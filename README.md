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

4. **`kernel_accepts_a_16bit_stack_descriptor`** — a writable 16-bit data
   descriptor, suitable for loading into `SS`. Note it reads back with type
   `0x3`, not the `0x2` the request implies: Linux sets the accessed bit itself
   so the LDT page can be mapped read-only.

5. **`rsp_survives_a_signal_taken_on_a_16bit_stack_segment`** — take a signal
   with a 16-bit `SS` loaded and see what happens to `RSP` across the
   `sigreturn`. This is a *characterisation* test: it records what the machine
   actually does and fires if that changes. The result contradicted the
   prediction; see below.

## Note on the execution test's design

Returning to 64-bit code from a 16-bit segment by far jump is awkward: the
return target is a 64-bit address that a 16-bit far jump cannot encode. The
probe sidesteps this by faulting deliberately and recovering through a signal
handler, which runs in 64-bit mode and `siglongjmp`s out. The signal frame is a
convenient bonus: it carries the register state at fault time, including `CS`.

## Result

All four tests pass on the environment above. A 64-bit process really does
create a 16-bit protected-mode code segment, far-jump into it, and execute
there, with the kernel in long mode the whole time and no hypervisor anywhere.

### The negative control

A test that always passes proves nothing, so the discriminator was checked by
flipping `seg_32bit` to 1 and re-running. The decode test failed exactly as
predicted:

    installed_descriptor_selects_16bit_compatibility_mode
        COMPAT16_DESC_D(raw): expected 0, got 1
    instructions_decode_with_16bit_default_operand_size
        trap.rax: expected 0xcafebabedead1234, got 0xcccc1234

`0xcccc1234` is the 32-bit reading of the probe: `mov eax, 0xCCCC1234`, having
eaten two of the `INT3` padding bytes as immediate data and zero-extended into
`RAX`, destroying the upper half. The `CS` test still passed, correctly — the
far jump still entered the LDT segment, it was simply a 32-bit one.

Worth making a permanent test rather than a one-off, which means threading the
operand size through `compat16_install_code_segment()`.

## Finding: the espfix64 hazard did not reproduce, and the prediction was wrong

The setup here is different from the tests above: `CS` stays **64-bit** and it
is `SS` that becomes a 16-bit LDT segment. Signal delivery therefore follows
the ordinary path. The moment of interest is `sigreturn`, which restores the
saved 16-bit `SS` and `IRET`s back to it.

**Predicted, before measuring:** `IRET` to a stack segment with `B = 0` reloads
only `SP`, so the low 16 bits of `RSP` survive and the upper bits arrive from
whatever the kernel was running on — a fixed espfix alias address with
espfix64, or the live kernel stack pointer without it.

**Measured:**

    rsp before      0x00007ffc3e70c900
    rsp after       0x00007ffc3e70c900
    ss saved        0x000f
    ss in handler   0x000f

`RSP` survives completely intact. No truncation, no leaked address. Two
secondary surprises: `SS` was **not** reset to a flat segment for the duration
of the handler — the handler ran with the 16-bit `SS` still loaded — and
`ss_saved` confirms the 16-bit selector really was live across the whole round
trip, so the test is not passing vacuously.

**Control:** re-running with the stack descriptor's `B` bit *set* (an ordinary
32-bit LDT stack segment) produces the same intact `RSP`. So in this
configuration the `B` bit makes no observable difference at all.

### What this does and does not establish

It establishes that a 64-bit process can take and return from a signal with a
16-bit `SS` loaded, and lose nothing.

It does **not** establish that the espfix64 path was exercised. Nothing here
observes the kernel taking that branch; the only evidence is that
`CONFIG_X86_ESPFIX64=y` and that `SS` was an LDT selector. A transparent
espfix64 and a never-taken espfix64 look identical from userspace.

### The most likely explanation, untested

`IRET`'s stack-pointer width follows the **operand size of the `IRET` itself**,
not the new `SS`. The kernel returns with `IRETQ`, and this return lands on a
64-bit `CS`, so a full 64-bit `RSP` is reloaded and the 16-bit `SS` never gets
a chance to matter. On that reading the hazard needs the return to land in
compatibility mode, with `CS` non-64-bit as well as `SS` 16-bit.

That is a hypothesis. It has not been tested, and it should not be repeated as
fact.

### Next experiment

Combine the two halves: 16-bit `CS` *and* 16-bit `SS`, then take a signal.
Harder than it sounds, because the compatibility-mode signal finding below
already shows delivery needs a `MAP_32BIT` alternate stack, and because
resuming in 16-bit code after `sigreturn` needs its own way back out to
64-bit — the probe above escapes by `siglongjmp`, which skips the `IRET` that
is the entire subject of the experiment.

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
