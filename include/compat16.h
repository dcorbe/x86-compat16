/*
 * compat16.h - Creating and entering 16-bit protected-mode segments from a
 * 64-bit process on x86-64 Linux.
 *
 * Long mode selects the operand/address size of user code per code segment:
 *
 *     CS.L = 1, CS.D = 0   ->  64-bit mode
 *     CS.L = 0, CS.D = 1   ->  compatibility mode, 32-bit
 *     CS.L = 0, CS.D = 0   ->  compatibility mode, 16-bit   <- what we want
 *
 * The kernel stays in long mode throughout. Nothing here needs a hypervisor;
 * see README.md for where one does become necessary (real mode and v86).
 */
#ifndef COMPAT16_H
#define COMPAT16_H

#include <stddef.h>
#include <stdint.h>

/*
 * Install a 16-bit protected-mode code segment into this process's LDT.
 *
 *   entry   LDT slot to write. A process starts with an empty LDT, so low
 *           indices are free.
 *   base    Segment base address. MUST live below 4 GiB: a descriptor's base
 *           field is 32 bits wide and the kernel rejects anything larger.
 *           Map it with MAP_32BIT.
 *   length  Segment length in bytes. Capped by the caller; a 16-bit segment
 *           cannot usefully address beyond 64 KiB.
 *
 * Returns 0 on success. Returns -1 with errno set on failure; EINVAL from a
 * kernel built with CONFIG_X86_16BIT=n is the expected way for this to fail on
 * a hardened system.
 */
int compat16_install_code_segment(int entry, const void *base, size_t length);

/*
 * Read back the raw 8-byte segment descriptor sitting in LDT slot `entry`.
 *
 * Asking the kernel what it actually stored, rather than trusting what we
 * asked it to store, is the only way to catch a request that was accepted but
 * quietly normalised.
 *
 * Returns 0 on success and writes the descriptor to *out_raw. Returns -1 with
 * errno set on failure.
 */
int compat16_read_descriptor(int entry, uint64_t *out_raw);

/*
 * Field accessors for a raw descriptor, by bit position:
 *
 *   bit 53  L    long-mode (64-bit) code segment
 *   bit 54  D/B  default operand and address size, 1 = 32-bit, 0 = 16-bit
 *
 * 16-bit compatibility mode is exactly L = 0 together with D = 0. L = 1 with
 * D = 0 would be a 64-bit code segment, and the two are only one bit apart.
 */
#define COMPAT16_DESC_L(raw) ((unsigned)(((raw) >> 53) & 1u))
#define COMPAT16_DESC_D(raw) ((unsigned)(((raw) >> 54) & 1u))

/*
 * Segment type nibble, bits 40..43: accessed(40), writable(41),
 * expand-down(42), executable(43).
 *
 * Note the accessed bit is already set on readback. Linux sets it itself when
 * filling the descriptor rather than leaving it for the CPU to set on first
 * load, so that the LDT page can be mapped read-only. A writable expand-up
 * data segment therefore reads back as 0x3, not the 0x2 you would predict from
 * the request alone.
 */
#define COMPAT16_DESC_TYPE(raw) ((unsigned)(((raw) >> 40) & 0xfu))
#define COMPAT16_TYPE_DATA_RW_ACCESSED 0x3u

/*
 * Build the segment selector naming LDT slot `entry` at user privilege:
 * index in bits 3..15, TI = 1 selects the LDT rather than the GDT, RPL = 3.
 */
#define COMPAT16_SELECTOR(entry) ((uint16_t)(((unsigned)(entry) << 3) | 0x7u))

/*
 * Install a 16-bit writable data segment suitable for loading into SS.
 *
 * Same arguments and error convention as compat16_install_code_segment().
 * Clearing seg_32bit here clears the descriptor's B bit rather than its D bit;
 * the encoding is the same field, but for a stack segment it declares the
 * stack pointer to be SP rather than ESP. That is the bit the whole espfix64
 * problem hangs on.
 */
int compat16_install_stack_segment(int entry, const void *base, size_t length);

/* CPU state captured at the instant the 16-bit probe trapped. */
struct compat16_trap {
    uint64_t rax; /* RAX at fault time; proves how the probe was decoded */
    uint16_t cs;  /* CS at fault time; proves which segment was executing */
    int signo;    /* signal that ended the probe */
};

/*
 * Far-jump into the 16-bit code segment in LDT slot `entry` and run a short
 * probe there, recovering into *out when it traps.
 *
 * `segment_base` must be the same address the segment was installed over; the
 * probe's instruction bytes are written into it.
 *
 * There is no far jump back. A 16-bit far jump cannot encode a 64-bit return
 * target, so the probe deliberately traps instead and a signal handler running
 * in 64-bit mode recovers via siglongjmp. The signal frame is a useful bonus:
 * it carries the register state at fault time, including CS.
 *
 * Recovering this way requires an alternate signal stack below 4 GiB. That is
 * not a detail -- without it the process dies. See the comment in compat16.c.
 *
 * Returns 0 on success. Returns -1 on failure to set up, with errno set.
 */
int compat16_run_probe(int entry, void *segment_base, uint64_t seed,
                       struct compat16_trap *out);

/*
 * The value the landing pad's REX.W movabs leaves in R10 when it is decoded in
 * 64-bit mode.
 *
 * The immediate's upper half is deliberately 0x90909090. Should the CPU somehow
 * still be in compatibility mode when those bytes are reached, they decode
 * instead as a one-byte DEC, a 32-bit MOV, and four NOPs -- a different answer,
 * arrived at without faulting. A discriminator that crashes in the failing case
 * tells you far less than one that returns the wrong number.
 */
#define COMPAT16_LANDING_MARK 0x90909090abcdef01ull

/* What survives a 64 -> 16 -> 64 excursion made entirely by far jump. */
struct compat16_roundtrip {
    uint64_t rax;        /* RAX after the 16-bit leg; its decode evidence */
    uint64_t r10;        /* the landing pad's 64-bit decode evidence */
    uint64_t rsp_before; /* RSP before the outbound far jump */

    /*
     * RSP as it arrives at the landing pad, before the trampoline repairs it.
     * Measured, and not what was expected: it comes back holding only the low
     * 32 bits of the value it left with. See compat16.c.
     */
    uint64_t rsp_at_landing;

    uint64_t rsp_after; /* RSP once back in compiler-generated 64-bit code */
    uint16_t cs_before; /* the 64-bit CS we left from */
    uint16_t cs_after;  /* CS after the return; equality is the claim */
    int signo;          /* 0 when no signal was taken -- the whole point */
};

/*
 * Far-jump into the 16-bit code segment in LDT slot `entry`, run a short probe
 * there, and far-jump back into 64-bit mode without trapping.
 *
 * `segment_base` must be the same address the segment was installed over. It
 * receives both stubs: the 16-bit probe at offset 0 and, further up the same
 * page, a 64-bit landing pad. The landing pad is reached through the ordinary
 * flat 64-bit CS, so the outbound jump names it by its linear address rather
 * than by a segment offset -- which is why it, too, must live below 4 GiB.
 *
 * The return address itself is under no such limit. It travels in R11, which
 * compatibility mode cannot name and therefore cannot disturb, so the landing
 * pad can hand control back to a caller anywhere in the 64-bit address space.
 * Only the trampoline is confined to the low 4 GiB.
 *
 * SS is never touched and the 16-bit leg pushes nothing, so it needs no stack
 * of its own. RSP is a different matter: it does not survive the excursion
 * whole, and the landing pad puts it back from a copy kept in R15. `rsp_before`
 * and `rsp_at_landing` record the damage; `rsp_after` records the repair.
 *
 * Signal handlers are installed anyway, covering the case where the CPU or
 * kernel declines the transition. Reaching one means the claim is false, and
 * `signo` then reports which signal ended it rather than the binary dying.
 *
 * Returns 0 on success. Returns -1 on failure to set up, with errno set.
 */
int compat16_run_roundtrip(int entry, void *segment_base, uint64_t seed,
                           struct compat16_roundtrip *out);

/*
 * Time `iterations` complete far-jump excursions into 16-bit mode and back,
 * writing the total elapsed nanoseconds to *out_ns.
 *
 * Setup -- stub installation, alternate stack, signal handlers -- happens once,
 * outside the clock, so what is measured is the transition and nothing else. A
 * warmup pass runs first, also outside the clock.
 *
 * The figure includes the trampoline's bookkeeping stores and one ordinary
 * function call per iteration. Both are noise beside a mode transition, and
 * counting them errs in the honest direction.
 *
 * Returns 0 on success. Returns -1 with errno set on failure to set up, or
 * EIO if any excursion faulted, in which case the timing means nothing and is
 * not reported.
 */
int compat16_time_roundtrip(int entry, void *segment_base, uint64_t iterations,
                            uint64_t *out_ns);

/*
 * The same measurement for the other way home: far jump out, trap deliberately,
 * and let the signal handler recover by siglongjmp. Same setup-once discipline,
 * same units.
 *
 * Note this times the recovery path exactly as compat16_run_probe() implements
 * it, including sigsetjmp() saving the signal mask -- a further syscall per
 * iteration. A signal-based design could shave that off. It could not shave off
 * the signal delivery itself, which is the cost that matters.
 *
 * Returns 0 on success, -1 with errno set on failure.
 */
int compat16_time_signal_path(int entry, void *segment_base,
                              uint64_t iterations, uint64_t *out_ns);

/*
 * Values the 16-bit stack stub plants, so the tests can name them rather than
 * matching bare magic numbers against a byte array.
 */
#define COMPAT16_STACK16_PUSHED 0xfaceu     /* pushed, then popped into DX */
#define COMPAT16_STACK16_CALL_MARK 0xbeefu  /* set into CX by the subroutine */
#define COMPAT16_STACK16_INITIAL_SP 0x1000u /* SP on entry; top of segment */

/* What 16-bit code leaves behind after running on a 16-bit stack segment. */
struct compat16_stack16 {
    uint64_t rax; /* 0x1234 in AX: the operand-size discriminator */
    uint64_t rcx; /* COMPAT16_STACK16_CALL_MARK, if the subroutine ran */
    uint64_t rdx; /* what POP recovered */
    uint64_t rbp; /* SP at the end of the 16-bit leg; the balance check */

    uint64_t rsp_at_landing; /* RSP on arrival, before the trampoline repairs */
    uint64_t ss_at_landing;  /* SS on arrival: proves which stack was live */

    uint64_t rsp_before; /* the caller's RSP and SS, before and after, which */
    uint64_t rsp_after;  /* must match for the excursion to be usable at all */
    uint16_t ss_before;
    uint16_t ss_after;

    int signo; /* 0 when no signal was taken */
};

/*
 * Run 16-bit code on a 16-bit stack segment, and come back.
 *
 * Everything else here deliberately avoids the stack, which is what lets those
 * excursions keep the flat 64-bit SS loaded throughout. Real 16-bit code does
 * nothing else: it pushes arguments, makes far calls, and keeps locals. This is
 * the configuration that actually matters, and the one the espfix64 finding
 * never reached.
 *
 * The stub loads SS from inside 16-bit mode -- MOV SS is followed immediately
 * by the SP load, which the interrupt shadow makes atomic -- then pushes and
 * pops a word, and far-calls a subroutine in its own segment so that CS:IP goes
 * on the 16-bit stack and RETF brings it back. That last part is the mechanism
 * every 16-bit inter-segment call runs on.
 *
 *   code_entry, code_base    LDT slot and page of the 16-bit code segment
 *   stack_entry, stack_base  LDT slot and page of the 16-bit stack segment
 *
 * Both pages must be below 4 GiB, and both descriptors must already be
 * installed. The landing pad restores SS from R13 and RSP from R15 before
 * returning, in that order: MOV SS's interrupt shadow covers the instant when
 * the two disagree.
 *
 * Returns 0 on success. Returns -1 with errno set on failure to set up.
 */
int compat16_run_stack16(int code_entry, int stack_entry, void *code_base,
                         void *stack_base, struct compat16_stack16 *out);

/*
 * SP at the instant the 16-bit stub traps: 0x1000 less the word it pushed
 * first. The push happens before the trap on purpose, so that the pop after it
 * can only succeed if SS and SP both came back correctly.
 */
#define COMPAT16_SIGRET_SP_AT_TRAP 0x0ffeu

/* What a signal taken from inside 16-bit code, on a 16-bit stack, does. */
struct compat16_sigret {
    /* Recorded inside the handler, out of the signal frame. */
    uint16_t cs_in_frame;  /* proves the CPU was in the 16-bit code segment */
    uint16_t ss_in_frame;  /* proves the 16-bit stack was live */
    uint64_t rsp_in_frame; /* the stack pointer the kernel recorded */
    uint64_t uc_flags;     /* UC_SIGCONTEXT_SS / UC_STRICT_RESTORE_SS */
    int deliveries;        /* how many times the handler ran; 1 is correct */

    /* Recorded after the 16-bit code resumed and came home by far jump. */
    uint64_t rax; /* the operand-size discriminator */
    uint64_t rdx; /* the word popped AFTER the signal */
    uint64_t rsi; /* SP once the pop is done */

    uint64_t rsp_before;
    uint64_t rsp_after;
    uint16_t ss_before;
    uint16_t ss_after;

    int signo; /* non-zero only if the run had to be abandoned */
};

/*
 * Take a signal with 16-bit CS *and* 16-bit SS both live, and resume.
 *
 * This is the configuration every other experiment here stops short of, and
 * the one espfix64 exists for. The stub loads its 16-bit stack, pushes a word,
 * and executes INT3. The handler does NOT siglongjmp out -- it records the
 * frame and returns, because sigreturn's IRET back into 16-bit mode is the
 * entire subject. Escaping by siglongjmp would skip the only instruction that
 * matters.
 *
 * If the IRET works, the 16-bit code resumes at the instruction after the
 * INT3, pops the word it pushed before the signal, and far-jumps home. The
 * popped value is the evidence: it can only be right if the kernel restored
 * both the 16-bit SS and the 16-bit SP, because it is read through them.
 *
 * SIGSEGV and SIGILL are still caught and still escape by siglongjmp, so a
 * failed IRET reports a result rather than killing the process.
 *
 * Returns 0 on success. Returns -1 with errno set on failure to set up.
 */
int compat16_run_sigret(int code_entry, int stack_entry, void *code_base,
                        void *stack_base, struct compat16_sigret *out);

/*
 * Fixed offsets within the re-entry stub's code segment: where the thunk sits,
 * and the instruction the far CALL to it will return to. The second is what a
 * successful re-entry has to land on, and what the far CALL should have left
 * on the 16-bit stack.
 */
#define COMPAT16_REENTRY_THUNK_IP 0x0040u
#define COMPAT16_REENTRY_RESUME_IP 0x0010u

/* What a 64-bit caller can recover, and then resume, from a 16-bit far call. */
struct compat16_reentry {
    /* Read off the 16-bit stack after the outbound leg. */
    uint16_t saved_ip;    /* return offset the far CALL pushed */
    uint16_t saved_cs;    /* and the selector beside it */
    uint16_t sp_at_thunk; /* SP once the CALL had pushed both */

    /* Observed after 64-bit code re-entered at that saved CS:IP. */
    uint64_t rcx; /* the mark set at the resume point */
    uint64_t rsi; /* SP after resuming; the frame should be gone */

    uint64_t rsp_before;
    uint64_t rsp_after;
    uint16_t ss_before;
    uint16_t ss_after;

    int signo; /* non-zero only if the run had to be abandoned */
};

/*
 * Leave 16-bit code through a far call, then re-enter it where it left off.
 *
 * The last primitive a host needs, and the one every other excursion here
 * ducks: they all enter 16-bit code at a fixed offset. Servicing a call made
 * *from* 16-bit code means resuming it at an address nobody knew in advance.
 *
 * The shape mirrors what a real import thunk does:
 *
 *   1. 16-bit code far-CALLs a thunk, which puts CS:IP on the 16-bit stack.
 *   2. The thunk far-jumps out to 64-bit mode.
 *   3. The 64-bit side reads that CS:IP straight off the 16-bit stack -- it
 *      knows the segment's base and has SP from the landing pad.
 *   4. It re-enters 16-bit mode there, having put SS and SP back, with the
 *      call frame accounted for.
 *
 * Step 4 needs no new instruction: it is the same indirect far jump used to
 * enter 16-bit mode anywhere else, with the offset taken from the stack rather
 * than fixed at zero. What it does need is care with the stack pointer. SS is
 * loaded first and RSP immediately after, inside MOV SS's interrupt shadow, and
 * RSP is set to the *segment offset* rather than a linear address: in 16-bit
 * mode only its low 16 bits are consulted, and the base comes from the
 * descriptor. Setting a linear address there would work only when the segment
 * happens to be 64 KiB aligned.
 *
 * Returns 0 on success. Returns -1 with errno set on failure to set up.
 */
int compat16_run_reentry(int code_entry, int stack_entry, void *code_base,
                         void *stack_base, struct compat16_reentry *out);

/* What a signal taken with a 16-bit stack segment does to RSP. */
struct compat16_espfix {
    uint64_t rsp_before;    /* RSP in 64-bit mode, before the trap */
    uint64_t rsp_after;     /* RSP as sigreturn's IRET left it */
    uint16_t ss_saved;      /* SS the kernel recorded in the signal frame */
    uint16_t ss_in_handler; /* SS actually in effect inside the handler */
};

/*
 * Take a signal while SS names the 16-bit stack segment in LDT slot
 * `stack_entry`, and report what survives.
 *
 * CS stays 64-bit throughout, so signal delivery follows the ordinary path.
 * The interesting instant is the return: sigreturn restores the saved 16-bit
 * SS and IRETs to it.
 *
 * Measured result, which is NOT what was predicted: RSP survives completely
 * intact, and the kernel leaves the 16-bit SS loaded while the handler runs
 * rather than swapping in a flat one. README.md records the prediction, its
 * falsification, and what remains unexplained.
 *
 * Returns 0 on success, -1 with errno set on failure to set up.
 */
int compat16_probe_espfix(int stack_entry, struct compat16_espfix *out);

#endif /* COMPAT16_H */
