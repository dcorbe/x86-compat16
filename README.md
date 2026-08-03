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

8. **`sixteen_bit_code_runs_on_a_16bit_stack_segment`**, with
   **`the_stack16_leg_decoded_as_16bit_code`**,
   **`push_and_pop_round_trip_on_a_16bit_stack`** and
   **`a_far_call_and_ret_work_on_a_16bit_stack`** — the configuration real
   16-bit code actually runs in. Loads a 16-bit `SS` from inside 16-bit mode,
   pushes and pops, and far-calls a subroutine so that `CS:IP` goes on that
   stack and `RETF` brings it back.

9. **`a_far_call_leaves_a_usable_return_address_on_the_16bit_stack`** and
   **`sixteen_bit_code_resumes_at_a_recovered_cs_ip`** — leaving 16-bit code
   through a far call and getting back in where it left off, at an address the
   64-bit side recovers from the stack rather than being told.

10. **`a_signal_can_be_taken_and_resumed_from_16bit_code`** and
   **`sigreturn_restores_the_16bit_stack`** — the configuration espfix64 exists
   for: `CS` and `SS` both 16-bit when the signal lands. The handler *returns*
   rather than escaping, so that `sigreturn`'s `IRET` is the thing on trial.

11. **`without_an_alternate_stack_a_compatibility_mode_signal_is_fatal`** and
    **`an_alternate_stack_above_4gib_is_enough`** — the fix for
    compatibility-mode signal delivery, taken apart. Both run in a forked child,
    because what they measure is whether the process survives. They corrected a
    claim this file used to make; see below.

12. **`rsp_survives_a_signal_taken_on_a_16bit_stack_segment`** — take a signal
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

### The experiment that followed

Combine the two halves: 16-bit `CS` *and* 16-bit `SS`, then take a signal. Both
halves are now done and both work — see the last two findings in this file. The
hypothesis above, that the hazard needs the return to land in compatibility
mode, turns out to be testable and answered: it does land there, and `sigreturn`
handles it correctly.

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

Pointing the signal at a `MAP_32BIT` alternate stack makes delivery work.

### That fix changed two things at once, and this file blamed the wrong one

The sentence that used to sit here said the cause was the frame's *address* —
that an ordinary x86-64 stack lives above 4 GiB and the kernel cannot build a
frame there while the CPU is in compatibility mode. It called that "one variable
changed". It was two: the fix introduced an alternate stack **and** mapped it
low, and the low mapping was given the credit for both.

Separating them needs a third arm, and all three have to be able to end in the
process dying, so they run in a forked child. That is the only fork in this
suite; `harness.h` explains why there are otherwise none.

    none: exited 0 status 0 signal 11
    high: exited 1 status 0 signal 0
    low:  exited 1 status 0 signal 0

With no alternate stack the child is killed by `SIGSEGV`, which is the original
failure reproduced as a test rather than recalled as an anecdote. With an
alternate stack the child survives and the probe traps exactly as designed —
**whether or not that stack is below 4 GiB**.

So the rule is `SA_ONSTACK`. The address is incidental.

That reading also makes better mechanical sense. With an alternate stack the
kernel builds the frame at a place it already knows. Without one it has to
derive the address from `RSP`, and `RSP` in compatibility mode has been
truncated to 32 bits and re-based by whatever `SS` is loaded — so the address it
computes is not a stack at all. The trouble was never the height of the stack;
it was that the pointer to it had stopped meaning anything.

**Consequence for the design:** fault-and-recover-via-signal is a valid way back
out of 16-bit code, but *only* with `SA_ONSTACK`. Without it this is not merely
unreliable, it is fatal. Where that stack lives is a free choice.

## Finding: the round trip needs no signal, and three bytes of stack repair

The one-way probe leaves an obvious question hanging. A signal per transition is
tolerable when you cross once and ruinous when you cross constantly, which is
what any real use of 16-bit code does. So: can 16-bit code get back to 64-bit
mode on its own?

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

The alternate stack installed for the recovery handlers closes it as a side
effect: `SA_ONSTACK` means the frame never goes near `RSP`. What looked like
scaffolding for a failing case turns out to be a permanent requirement of the
design.

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
the cost of crossing is not bounded below by signal delivery. What that cost
actually is, measured, is below.

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
the signal mask — a further syscall per iteration that a signal-based
design could shave off. It could not shave off the delivery itself, which is
the bulk of it.

### What this means in practice

At ~88 ns a transition, code crossing 10,000 times a second spends under 0.1% of
a core in transit. Crossing is not the thing to optimise; it sits comfortably
below the noise floor of whatever work is being done on either side of it.

The signal path at ~1.8 µs is not catastrophic either — the same 10,000
crossings cost under 2% of a core — but it is 20x more for no benefit, and it
degrades exactly where you would least want it to, since the code that crosses
most often is the code that can least afford it.

For scale, a bare `getpid()` on this machine — 50,000 calls, same warmup and
timing shape, measured as a one-off outside the suite — costs 177–208 ns. The
mode-transition round trip is **about half the price of the cheapest syscall
there is**.

That is worth sitting with. Crossing from 64-bit code into a 16-bit segment and
back is not an exotic expense to be engineered around; on this machine it is
cheaper than asking the kernel for the current process ID. Whatever ends up
limiting a program built this way, it will not be this.

## Scope

This is a characterisation suite, and its scope is closed. It answers whether
the machine in front of you permits these transitions and what they cost. It is
not the execution layer of anything.

That distinction is deliberate rather than aspirational. The code here uses
file-scope statics throughout and is not reentrant; it is compiled `-O0` because
several tests depend on exact register contents across a mode transition, and
optimisation is free to keep those values somewhere the test cannot see. Both
choices are right for a test and wrong for a runtime. Anything wanting this
capability in earnest should be written against the *findings* below, not grown
from this code.

What the suite is good for is staying honest. Kernels change, hardening options
spread, and `CONFIG_X86_16BIT=n` is a legitimate and increasingly common build
choice. Run `make test` and the machine tells you where it stands.

## License

MIT. See [LICENSE](LICENSE).

## Finding: 16-bit code runs on a 16-bit stack, and nothing breaks

Every excursion above avoids the stack on purpose. That is what lets them keep
the flat 64-bit `SS` loaded throughout, and it is why the espfix64 hazard never
came up. It is also nothing like real 16-bit code, which does little else:
pushes arguments, makes far calls, keeps locals.

So this one loads a 16-bit `SS` from *inside* 16-bit mode and uses it properly:

```
mov   $0x1234, %ax        # the usual operand-size discriminator
mov   $SS, %bx
mov   %bx, %ss            # interrupt shadow covers the next instruction
mov   $0x1000, %sp
pushw $0xface
pop   %dx                 # DX == 0xface -> the stack works
lcall $CS, $sub           # CS:IP goes on the 16-bit stack
mov   %sp, %si            # SI == 0x1000 -> the stack is balanced
ljmpl $CS64, $landing     # home
sub:
mov   $0xbeef, %cx        # CX == 0xbeef -> the subroutine ran
lret
```

The `MOV SS` / `MOV SP` pairing is not stylistic. Loading `SS` inhibits
interrupts for exactly one instruction, and that instruction is the window in
which `SS` and `SP` disagree. Anything between them is a bug.

**It all works.** No signal, `DX` comes back `0xface`, `CX` comes back `0xbeef`,
`SI` comes back `0x1000`, and the caller's `SS` and `RSP` are both intact
afterwards. The far call and `RETF` — the mechanism every 16-bit inter-segment
call runs on — work fine on an LDT stack segment.

### The stack pointer you get back is a mongrel

    rsp at landing  0x000000000ccb1000
    ss at landing   0x000f

Read that value from the bottom up. The low 16 bits are `0x1000`, the `SP` the
16-bit code set. Bits 16–31 are left over from the caller's original `RSP`,
untouched because `MOV SP` writes 16 bits. The upper 32 are zero, from the
truncation the previous finding describes.

Three different provenances in one register. It is not a value anything should
try to reconstruct, which is the practical argument for keeping the original in
a register compatibility mode cannot reach and restoring from that. The landing
pad puts `SS` back from `R13` and `RSP` from `R15`, in that order, so `MOV SS`'s
interrupt shadow covers the instant when the two disagree.

### The negative control

| Mutation | Failures |
| --- | --- |
| never load the 16-bit `SS` | all four |
| change the pushed word | push/pop only |
| change the subroutine's marker | far call/ret only |
| drop the subroutine's `LRET` | all four |

The middle two are surgical, which is the useful evidence: those assertions are
reading the values they claim to read, not passing because the excursion
happened to complete.

### What this does and does not establish

It establishes that a 16-bit `SS` is usable as a stack, that far calls work on
it, and that a 64-bit caller gets its own stack back unharmed.

It does **not** establish anything about taking a signal in that state. This
excursion completes without the kernel ever being involved. A signal arriving
while 16-bit `CS` *and* 16-bit `SS` are both live — which is the configuration
the espfix64 finding never reached, and the one an asynchronous signal would
find in any long-running 16-bit code — remains untested.

## Finding: a signal from 16-bit code resumes cleanly, as predicted

The configuration every other experiment here stops short of, and the one
espfix64 exists for: `CS` **and** `SS` both 16-bit, a signal delivered, and
`sigreturn` `IRET`ing back into 16-bit mode.

The handler deliberately **returns** rather than escaping by `siglongjmp`. That
is the entire design. `siglongjmp` skips the `IRET`, which is the only
instruction under test — it is why the earlier probes could not answer this.

The stub pushes a word before trapping and pops it after:

```
mov   $0x1000, %sp
pushw $0xface
int3                      # signal delivered here
pop   %dx                 # only works if SS *and* SP came back
mov   %sp, %si
ljmpl $CS64, $landing
```

The pop reads through `SS` at `SP`, so recovering `0xface` is possible only if
the kernel restored both. Merely checking "did control return" would pass on a
flat `SS` and prove nothing.

### The prediction, written before measuring

`<asm/ucontext.h>` documents the machinery, including — pointedly — the DOSEMU
case of running in a segmented context. From it:

    UC_SIGCONTEXT_SS      set    this kernel saves SS and implements espfix
    UC_STRICT_RESTORE_SS  clear  it is only set for signals from 64-bit code

with `SS` restored regardless, because `sigreturn` restores it when the saved
selector is still valid, and ours is a live LDT entry.

### Measured

    cs in frame     0x0007
    ss in frame     0x000f
    rsp in frame    0x00000000ac1d0ffe
    uc_flags        0x3
    deliveries      1

`uc_flags = 0x3` is `UC_FP_XSTATE | UC_SIGCONTEXT_SS`, with
`UC_STRICT_RESTORE_SS` clear. Exactly as predicted, for exactly the documented
reason. `cs` and `ss` in the frame are the two LDT selectors, so the signal
really was taken in 16-bit code on the 16-bit stack; `rsp` ends `0x0ffe`, the
16-bit `SP` after the push, so the kernel recorded the segmented stack
pointer rather than a flat one. One delivery, no trap loop.

And the 16-bit code resumed: `DX` came back `0xface`, `SI` came back `0x1000`,
and the 64-bit caller's `SS` and `RSP` were both intact afterwards.

**This is the first prediction in this repo that was right.** The espfix64
prediction was wrong and the `RSP` prediction was wrong; both were guesses about
undocumented behaviour. This one came from a kernel header that describes the
contract, which is the difference.

### The negative control

| Mutation | Failures |
| --- | --- |
| remove the `INT3`, so no signal is taken | both |
| change the word pushed before the trap | the stack-restore test only |
| let the handler `siglongjmp` instead of returning | both |

The third is the one worth reading twice. Escaping by `siglongjmp` — what every
other probe here does — makes both tests fail, because it skips the `IRET`. That
is the mechanism, isolated.

### What this retires

Asynchronous signals arriving in 16-bit code are survivable. Delivery works with
the alternate stack, and resumption works because `sigreturn` restores a valid
16-bit `SS`.

Two caveats. The trap here is synchronous (`INT3`), so it arrives at a known
instruction boundary; a genuinely asynchronous signal arrives anywhere, and the
one place that matters is the handful of instructions where `SS` and `SP`
disagree, which `MOV SS`'s interrupt shadow already covers. And this says
nothing about a signal whose handler wants to *do* something in 16-bit context —
it only establishes that an interruption is transparent.

## Finding: 16-bit code can be resumed at an address it was never told

Every other excursion in this file enters 16-bit code at offset 0. That is fine
for a probe and useless for servicing a call made *from* 16-bit code, which has
to resume at an address nobody knew in advance.

The shape here mirrors a real import thunk:

```
        .code16
   0:   mov   $0x1234, %ax
        ... load the 16-bit SS, set SP ...
   b:   lcall $CS, $0x40         # into the thunk; pushes CS:IP
  10:   mov   $0xbeef, %cx       # <- THE RESUME POINT
  13:   mov   %sp, %si
  15:   ljmpl $CS64, $landing
```

The thunk does nothing but far-jump out to 64-bit mode. The 64-bit side is told
nothing about offset `0x10`: it reads the return `CS:IP` off the 16-bit stack,
where the far `CALL` left it, and jumps back to that.

**Measured:**

    saved cs:ip     0x0007:0x0010
    sp at thunk     0x0ffc

Both recovered, not supplied. `SP` is four below where it started — `CS` and
`IP`, one word each. Re-entry lands on `0x10`, `CX` comes back `0xbeef`, `SI`
comes back `0x1000` with the call frame gone, and the 64-bit caller's own `SS`
and `RSP` are untouched by either leg.

Re-entry needs no new instruction. It is the same indirect far jump used to
enter 16-bit mode anywhere else, with the offset taken from the stack instead of
fixed at zero.

### The one place this is easy to get wrong

`RSP` must be set to the **segment offset**, not a linear address. In 16-bit
mode only its low 16 bits are consulted, and the descriptor supplies the base.

Writing a linear address there is the obvious mistake, and it *sometimes works*
— exactly when the segment happens to start on a 64 KiB boundary, because only
then do the low 16 bits of `base + offset` equal `offset`. Six consecutive
`MAP_32BIT` mappings on this machine:

    0x40846000  low16=0x6000
    0x4197c000  low16=0xc000
    0x41985000  low16=0x5000
    0x41590000  low16=0x0000   <- would have worked
    0x40c39000  low16=0x9000
    0x40f28000  low16=0x8000

Page-aligned, essentially never 64 KiB-aligned. A stack pointer built that way
would come out wrong around fifteen times in sixteen, and right the other time,
which is a far worse failure than one that never works at all. Either use the
segment offset, as here, or allocate 16-bit stack segments 64 KiB aligned and
know that you are relying on it.

### The negative control

| Mutation | Failures |
| --- | --- |
| resume one byte past the saved `IP` | both |
| ignore the call frame when restoring `SP` | the resume test only |
| set `RSP` to a linear address | the resume test only |

The third is the mutation that matters: it is the plausible mistake, it fails
here, and the table above explains why it would not always fail elsewhere.
