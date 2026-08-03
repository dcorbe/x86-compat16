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

2. **`installed_descriptor_selects_16bit_compatibility_mode`** — dumping the
   LDT shows the descriptor really has its default-operand-size bit clear,
   proving the kernel did not normalise the request into an ordinary 32-bit
   segment.

3. **`far_jump_enters_the_16bit_code_segment`** and
   **`instructions_decode_with_16bit_default_operand_size`** — far-jump into the
   segment and run a stub whose *decoding* differs between 16- and 32-bit modes,
   so that a CPU not actually in 16-bit mode produces a different answer rather
   than the same one. The stub traps back out through a signal handler, which is
   also how the CPU's `CS` at fault time is captured.

4. **`far_jump_returns_from_16bit_mode_without_taking_a_signal`**, with
   **`the_16bit_leg_of_the_round_trip_decoded_as_16bit_code`** and
   **`the_landing_pad_ran_in_64bit_mode`** either side of it — the whole
   excursion out to 16-bit code and back, by far jump in both directions, with
   the kernel never involved. Each end carries its own operand-size
   discriminator, because a round trip that never went anywhere would also take
   no signal.

5. **`rsp_arrives_at_the_landing_pad_truncated_to_32_bits`** and
   **`the_landing_pad_hands_back_an_intact_rsp`** — a *characterisation* pair.
   `RSP` does not survive the excursion; it comes back holding only its low 32
   bits, which was not predicted. The first test pins the exact shape of the
   damage, the second that the trampoline repairs it before any compiled code
   runs.

6. **`the_far_jump_return_costs_far_less_than_a_signal`** — what the two ways
   home actually cost, in nanoseconds, with setup hoisted out of the clock. The
   assertion is a loose floor; the numbers it prints are the point.

7. **`kernel_accepts_a_16bit_stack_descriptor`** — a writable 16-bit data
   descriptor, suitable for loading into `SS`. Note it reads back with type
   `0x3`, not the `0x2` the request implies: Linux sets the accessed bit itself
   so the LDT page can be mapped read-only.

8. **`rsp_survives_a_signal_taken_on_a_16bit_stack_segment`** — take a signal
   with a 16-bit `SS` loaded and see what happens to `RSP` across the
   `sigreturn`. This is a *characterisation* test: it records what the machine
   actually does and fires if that changes. The result contradicted the
   prediction; see below.

## Note on the execution test's design

The execution probe is deliberately one-way. Its return target is a 64-bit
address, which a bare 16-bit far jump cannot encode, so the probe faults on
purpose and recovers through a signal handler running in 64-bit mode, which
`siglongjmp`s out. The signal frame is a convenient bonus: it carries the
register state at fault time, including `CS`.

That is the probe's design, not a limit of the hardware. A 16-bit far jump
*can* be made to encode a 32-bit target, and the round trip below does exactly
that — no signal, no kernel. The one-way probe is kept as it is because a
deliberate fault is a cleaner way to capture `CS` mid-flight than anything the
round trip offers.

## Result

All tests pass on the environment above. A 64-bit process really does create a
16-bit protected-mode code segment, far-jump into it, and execute there, with
the kernel in long mode the whole time and no hypervisor anywhere.

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

## Finding: the round trip needs no signal, and costs three bytes of stack repair

The one-way probe leaves an obvious question hanging. A signal per transition is
tolerable for an experiment and ruinous for a host that has to service hundreds
of distinct API calls made from inside 16-bit code. So: can 16-bit code get back
to 64-bit mode on its own?

It can. The mechanism is one prefix byte.

In a 16-bit code segment, `EA` is `JMP ptr16:16` and its offset field is two
bytes wide — enough to reach anywhere inside a 64 KiB segment and nowhere else.
Prefixed with `0x66`, the same opcode becomes `JMP ptr16:32`: a 32-bit offset
and the selector alongside it, which between them can name any address below
4 GiB in any segment the LDT or GDT describes, including the flat 64-bit `CS`.
A 16-bit instruction thereby addresses a 4 GiB space. This is the manoeuvre
Windows uses to reach 64-bit code from WOW64, one segment size further down.

So the outbound jump lands on a stub in a `MAP_32BIT` page, and the stub is
assembled as 64-bit code. The CPU arrives there in 64-bit mode.

**Measured:**

    far_jump_returns_from_16bit_mode_without_taking_a_signal   PASS   signo == 0
    the_16bit_leg_of_the_round_trip_decoded_as_16bit_code      PASS
    the_landing_pad_ran_in_64bit_mode                          PASS

The middle test is the same operand-size discriminator the one-way probe uses,
so the 16-bit leg is known to have run *as 16-bit code*. The third is its mirror
image: the landing pad's first instruction is a `REX.W movabs` whose immediate
has `0x90909090` in its upper half, so if the CPU were somehow still in
compatibility mode those bytes would decode as a `DEC`, a 32-bit `MOV` and four
`NOP`s — a wrong answer rather than a crash. Arriving is not the same as
arriving in 64-bit mode, and both are checked.

### Only the trampoline is confined to the low 4 GiB

The return address does not have to be. It travels in `R11`, and the landing pad
leaves through `jmp *%r11` to a caller sitting far above 4 GiB. Compatibility
mode has no encoding that names `r8`–`r15`, and that inaccessibility is exactly
what keeps their contents safe across the excursion. Three registers are used
this way — `R11` the return address, `R14` a result slot, `R15` the saved stack
pointer — and all three survive intact.

### The prediction that was wrong: RSP is truncated

`SS` is never reloaded. The 16-bit leg pushes nothing. No instruction in the
excursion names the stack pointer. `RSP` should have been untouched.

    rsp before      0x00007ffc894c7500
    rsp at landing  0x00000000894c7500

It arrives holding the low 32 bits of what it left with, upper half zeroed.
Left alone, the process then dies the moment compiled code touches the stack —
which is what the first version of this test did, reporting `SIGSEGV` from a
round trip that had otherwise entirely succeeded.

That it is *exactly* a truncation is the useful part, and the test asserts the
relationship rather than merely printing it. A stack pointer mangled some other
way, or varying between runs, would mean the excursion could not be made
transparent at all. A clean truncation means the value is recoverable from a
register that did survive, so the landing pad restores it from `R15` — three
bytes, `4c 89 fc` — before any compiled code gets to run. Callers never see it.

Note the contrast: the same excursion that truncates `RSP` carries a 64-bit
return address through `R11` unharmed. This is specific to the stack pointer,
not a general narrowing of the register file. Why it happens has not been
traced; it is recorded here as measured behaviour.

### The window, and why the alternate stack is permanent

Between the outbound jump and that repair, `RSP` is unusable. A signal delivered
inside the window would have the kernel build a frame at a truncated address —
the same hazard, on a different edge, as the compatibility-mode signal finding
above.

The `MAP_32BIT` alternate stack installed for the recovery handlers closes it as
a side effect: `SA_ONSTACK` means the frame never goes near `RSP`. What looked
like scaffolding for a failing case turns out to be a permanent requirement of
the design.

### The negative control

Each new assertion was checked by mutation, and each failed in the right place:

| Mutation | Failures |
| --- | --- |
| `0x66` prefix → `NOP` | 5 of 5 round-trip tests |
| drop `mov %r15, %rsp` | no-signal, and intact-`RSP` |
| corrupt the landing immediate | 64-bit-decode only |

The first is the one that matters: strip the operand-size prefix and the whole
round trip collapses. The prefix is load-bearing, not decoration.

### Consequence for the design

Fault-and-recover-via-signal is no longer the only way out of 16-bit code, so
the per-call cost of a host API is not bounded below by signal delivery. What
that cost actually is, measured, is below.

## Finding: the far jump costs about 88 ns, the signal about 1765 ns

Both paths do the same work — far jump out, a few instructions in 16-bit mode,
control back in 64-bit code — and differ only in how they get home. Setup runs
once, outside the clock, after a thousand warmup excursions. 50,000 iterations
each.

    far jump           88.3 ns per round trip
    signal           1753.1 ns per round trip
    ratio              19.9x

Five consecutive runs gave 88.3 / 86.7 / 91.5 / 87.6 / 88.1 ns against
1753 / 1783 / 1765 / 1753 / 1766 ns. The ratio sat between 19.3x and 20.6x. This
is not a noisy measurement.

Two caveats, both erring in the honest direction. The far-jump figure includes
one ordinary function call and the trampoline's bookkeeping stores per
iteration, and the whole suite is built `-O0` on purpose, so the true transition
cost is somewhat *below* 88 ns. The signal figure includes `sigsetjmp` saving
the signal mask — a further syscall per iteration that a signal-based host could
shave off. It could not shave off the delivery itself, which is the bulk of it.

### What this means for a module host

At ~88 ns a transition, a module making 10,000 host calls a second spends under
0.1% of a core crossing between modes. The transition is not the thing to
optimise; it is comfortably below the noise floor of whatever the shim layer
does on the other side.

The signal path at ~1.8 µs is not catastrophic either — the same 10,000 calls
cost under 2% of a core — but it is 20x more for no benefit, and it scales
badly in exactly the wrong place: output-heavy paths, which are the common case
for a BBS module, are the ones making the most calls.

For scale, a bare `getpid()` on this machine — 50,000 calls, same warmup and
timing shape, measured as a one-off outside the suite — costs 177–208 ns. The
mode-transition round trip is **about half the price of the cheapest syscall
there is**.

That is worth sitting with. Crossing from 64-bit code into a 16-bit segment and
back is not an exotic expense to be engineered around; on this machine it is
cheaper than asking the kernel for the current process ID. Whatever ends up
limiting a module host, it will not be this.
