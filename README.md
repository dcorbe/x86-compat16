# compat16

An experiment, not a library. It exists to falsify a specific claim:

> On x86-64, a 64-bit process can create a 16-bit protected-mode code segment
> and execute code in it, with no hypervisor and no mode switch on the kernel
> side, because long mode's *compatibility mode* selects 16-bit operation per
> code segment via `CS.L=0, CS.D=0`.

If that is true, this test suite passes. If the claim is wrong, or if the
kernel has quietly dropped support, the tests say exactly where it breaks.

## Why this is worth running rather than reading

The architectural claim is easy to state and easy to get subtly wrong. The
descriptor might be accepted but silently normalised to 32-bit. The far jump
might fault. The kernel might be built without `CONFIG_X86_16BIT`. None of
that is visible from the Intel SDM — only from the machine in front of you.

## Environment this was written against

    Linux 6.18.39-1-lts x86_64
    CONFIG_X86_16BIT=y
    CONFIG_X86_ESPFIX64=y

`CONFIG_X86_16BIT=n` is a legitimate and increasingly common hardening choice.
On such a kernel the first test fails at `modify_ldt`, which is itself a
result worth having.

## Running

    make test

## What each test establishes

1. **`kernel_accepts_a_16bit_code_descriptor`** — `modify_ldt(1, ...)` accepts a
   code descriptor with `seg_32bit = 0`. This is the gate; nothing later
   matters if it fails.

2. **D bit readback** *(planned)* — dumping the LDT shows the descriptor really
   has its default-operand-size bit clear, proving the kernel did not normalise
   the request into an ordinary 32-bit segment.

3. **Execution** *(planned)* — far-jump into the segment and run a stub whose
   *decoding* differs between 16- and 32-bit modes, so that a CPU not actually
   in 16-bit mode produces a different answer rather than the same one. The
   stub traps back out through a signal handler, which is also how the CPU's
   `CS` at fault time is captured.

4. **espfix64** *(stretch)* — take an interrupt on a 16-bit stack segment and
   see whether the upper 16 bits of `RSP` survive. This is the hazard that
   forced the espfix64 workaround into the kernel in 2014.

## Note on the execution test's design

Returning to 64-bit code from a 16-bit segment by far jump is awkward: the
return target is a 64-bit address that a 16-bit far jump cannot encode. The
probe sidesteps this by faulting deliberately and recovering through a signal
handler, which runs in 64-bit mode and `siglongjmp`s out. The signal frame is a
convenient bonus: it carries the register state at fault time, including `CS`.

## Finding: you cannot take a signal on a 64-bit stack from compatibility mode

This cost real debugging time and is the most interesting thing here.

The first working version of the probe died with an **unhandled `SIGSEGV`
despite having a `SIGSEGV` handler installed**, on a kernel with
`CONFIG_IA32_EMULATION=y`. `strace` showed the shape:

    --- SIGTRAP  {si_code=SI_KERNEL} ---     <- the int3 fired, so 16-bit
                                                code really did execute
    --- SIGSEGV  {si_code=SI_KERNEL} ---     <- frame setup failed
    --- SIGSEGV  {si_code=SI_KERNEL} ---     <- and failed again
    +++ killed by SIGSEGV +++

That doubled kernel-generated `SIGSEGV` is the signature of `force_sigsegv()`:
the kernel could not build a signal frame, tried to report *that* as a fault,
and could not build a frame for it either.

The cause is the frame's address. An ordinary x86-64 stack lives far above
4 GiB, and while the CPU is in compatibility mode the kernel cannot place a
frame there. Pointing the signal at a `MAP_32BIT` alternate stack — one
variable changed — makes delivery work. That is the evidence; the exact kernel
path enforcing it was not traced.

It is the same family of hazard as espfix64: a 64-bit stack pointer meeting a
stack discipline with only 32 bits to express it.

**Consequence for the design:** fault-and-recover-via-signal is a valid way
back out of 16-bit code, but *only* with a low alternate stack. Without one it
is not merely unreliable, it is fatal.
