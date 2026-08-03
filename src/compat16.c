/*
 * compat16.c - see include/compat16.h
 */
#include <asm/ldt.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <time.h>
#include <unistd.h>

#include "compat16.h"

/* modify_ldt(2) function codes. */
#define LDT_READ 0
#define LDT_WRITE 1

/* struct user_desc .contents encoding. */
#define DESC_CONTENTS_DATA 0
#define DESC_CONTENTS_CODE 2

int compat16_install_code_segment(int entry, const void *base, size_t length)
{
    struct user_desc desc = {
        .entry_number = (unsigned int)entry,
        .base_addr = (unsigned int)(uintptr_t)base,
        .limit = (unsigned int)(length - 1),

        /*
         * The entire point of this project. seg_32bit is the descriptor's D
         * bit; clearing it makes the default operand and address size 16-bit.
         */
        .seg_32bit = 0,

        .contents = DESC_CONTENTS_CODE,
        .read_exec_only = 0, /* readable code segment */
        .limit_in_pages = 0, /* limit is in bytes */
        .seg_not_present = 0,
        .useable = 1,
    };

    if (syscall(SYS_modify_ldt, LDT_WRITE, &desc, sizeof(desc)) != 0)
        return -1;

    return 0;
}

int compat16_install_stack_segment(int entry, const void *base, size_t length)
{
    struct user_desc desc = {
        .entry_number = (unsigned int)entry,
        .base_addr = (unsigned int)(uintptr_t)base,
        .limit = (unsigned int)(length - 1),

        /*
         * For a stack segment this field is the B bit: cleared, it declares
         * the stack pointer to be SP rather than ESP.
         */
        .seg_32bit = 0,

        .contents = DESC_CONTENTS_DATA,
        .read_exec_only = 0, /* writable, which SS requires */
        .limit_in_pages = 0,
        .seg_not_present = 0,
        .useable = 1,
    };

    if (syscall(SYS_modify_ldt, LDT_WRITE, &desc, sizeof(desc)) != 0)
        return -1;

    return 0;
}

int compat16_read_descriptor(int entry, uint64_t *out_raw)
{
    if (entry < 0 || entry >= LDT_ENTRIES) {
        errno = EINVAL;
        return -1;
    }

    /*
     * modify_ldt(0, ...) dumps the LDT from slot 0, so reading slot N means
     * asking for N+1 descriptors and indexing the last one.
     */
    size_t needed = ((size_t)entry + 1) * sizeof(uint64_t);
    uint64_t *table = malloc(needed);
    if (table == NULL)
        return -1;

    long got = syscall(SYS_modify_ldt, LDT_READ, table, needed);
    if (got < 0 || (size_t)got < needed) {
        /*
         * A short read is not a syscall error: it means the process's LDT is
         * smaller than the slot asked for, so the descriptor does not exist.
         */
        if (got >= 0)
            errno = ENOENT;
        free(table);
        return -1;
    }

    *out_raw = table[entry];
    free(table);
    return 0;
}

/*
 * A far pointer in the m16:32 form that JMP FAR (FF /5) expects: a 32-bit
 * offset followed by a 16-bit selector, with no padding between them.
 */
struct far_ptr {
    uint32_t offset;
    uint16_t selector;
} __attribute__((packed));

/*
 * Signals the probe may end on. SIGTRAP is the designed exit. SIGSEGV and
 * SIGILL are caught so that a failed transition reports a result instead of
 * killing the test binary and taking the later tests with it.
 */
static const int PROBE_SIGNALS[] = {SIGTRAP, SIGSEGV, SIGILL};
#define PROBE_SIGNAL_COUNT (sizeof(PROBE_SIGNALS) / sizeof(PROBE_SIGNALS[0]))

/*
 * Recovery state. File-scope because a signal handler takes no context
 * argument, which also means the probe is not reentrant.
 */
static sigjmp_buf probe_recovery;
static volatile sig_atomic_t probe_signo;
static volatile uint16_t probe_cs;
static volatile uint64_t probe_rax;

/*
 * The probe body, written into the segment at offset 0.
 *
 *   B8 34 12   read as 16-bit: mov ax, 0x1234   (3 bytes, AX only)
 *              read as 32-bit: mov eax, imm32   (5 bytes, eats two INT3s
 *                                                and zero-extends into RAX)
 *   CC ...     INT3 padding. Deliberately long enough that the 32-bit
 *              misreading also lands on one, so a wrong-mode CPU reports a
 *              wrong value instead of running off into the page and dying
 *              somewhere unhelpful.
 */
static const unsigned char PROBE_CODE[] = {
    0xb8, 0x34, 0x12, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
};

static void probe_trap_handler(int signo, siginfo_t *info, void *ctx)
{
    const ucontext_t *uc = ctx;
    (void)info;

    probe_signo = signo;

    /*
     * On x86-64 the signal frame packs four segment registers into one
     * greg, with CS in the low 16 bits.
     */
    probe_cs = (uint16_t)(uc->uc_mcontext.gregs[REG_CSGSFS] & 0xffffu);
    probe_rax = (uint64_t)uc->uc_mcontext.gregs[REG_RAX];

    siglongjmp(probe_recovery, 1);
}

/*
 * Point signal delivery at an alternate stack below 4 GiB.
 *
 * The signal frame MUST live below 4 GiB, and this is not optional.
 *
 * Measured behaviour on Linux 6.18: when the trap is taken while the CPU is in
 * compatibility mode, the kernel cannot place a signal frame on the process's
 * ordinary stack, which on x86-64 sits far above 4 GiB. Frame setup fails, the
 * kernel calls force_sigsegv(), that delivery fails the same way, and the
 * process dies from an unhandled SIGSEGV -- with a SIGSEGV handler installed
 * and CONFIG_IA32_EMULATION=y.
 *
 * strace shows the shape of it plainly:
 *
 *     --- SIGTRAP  {si_code=SI_KERNEL} ---     <- our int3 fired
 *     --- SIGSEGV  {si_code=SI_KERNEL} ---     <- frame setup failed
 *     --- SIGSEGV  {si_code=SI_KERNEL} ---     <- and again
 *     +++ killed by SIGSEGV +++
 *
 * Redirecting the frame to a MAP_32BIT alternate stack fixes it, which is what
 * establishes the address range as the cause. That the frame must be
 * addressable within 32 bits is the observed rule; the precise kernel path that
 * enforces it has not been traced here.
 *
 * This is the same family of hazard as espfix64: a 64-bit stack pointer meeting
 * a stack discipline that only has 32 bits to say it in.
 *
 * Returns 0 on success, -1 with errno set on failure.
 */
static int probe_altstack_install(void)
{
    static char *altstack;

    if (altstack == NULL) {
        altstack = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
        if (altstack == MAP_FAILED) {
            altstack = NULL;
            return -1;
        }
    }

    stack_t alt = {.ss_sp = altstack, .ss_size = 65536, .ss_flags = 0};
    return sigaltstack(&alt, NULL);
}

/*
 * Install probe_trap_handler() over every signal a failed transition might
 * raise, saving the previous dispositions into `saved`.
 *
 * Returns 0 on success. On failure any handler already installed is put back,
 * so a partial install never leaks out of the call.
 */
static int probe_signals_install(struct sigaction *saved)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = probe_trap_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);

    for (size_t i = 0; i < PROBE_SIGNAL_COUNT; i++) {
        if (sigaction(PROBE_SIGNALS[i], &sa, &saved[i]) != 0) {
            while (i-- > 0)
                sigaction(PROBE_SIGNALS[i], &saved[i], NULL);
            return -1;
        }
    }

    return 0;
}

/* Put back what probe_signals_install() displaced. */
static void probe_signals_restore(const struct sigaction *saved)
{
    for (size_t i = 0; i < PROBE_SIGNAL_COUNT; i++)
        sigaction(PROBE_SIGNALS[i], &saved[i], NULL);
}

int compat16_run_probe(int entry, void *segment_base, uint64_t seed,
                       struct compat16_trap *out)
{
    /*
     * Saved handlers are static rather than automatic: an automatic object
     * written before sigsetjmp() and read after siglongjmp() has an
     * indeterminate value. The probe is single-threaded and non-reentrant
     * already, so file scope costs nothing here.
     */
    static struct sigaction saved[PROBE_SIGNAL_COUNT];

    memcpy(segment_base, PROBE_CODE, sizeof(PROBE_CODE));

    if (probe_altstack_install() != 0)
        return -1;
    if (probe_signals_install(saved) != 0)
        return -1;

    struct far_ptr target = {
        .offset = 0,
        .selector = COMPAT16_SELECTOR(entry),
    };

    if (sigsetjmp(probe_recovery, 1) == 0) {
        /*
         * The one-way door. A direct far jump (opcode EA) is invalid in
         * 64-bit mode, so the transition has to go through the indirect
         * memory form.
         */
        __asm__ __volatile__(
            /*
             * Seed RAX first: the whole point is what survives in the upper
             * bits. Naming rax as a clobber also stops the compiler handing
             * us rax as one of the input registers.
             */
            "movq %[seed], %%rax\n\t"
            "ljmpl *(%[target])"
            :
            : [seed] "r"(seed), [target] "r"(&target)
            : "rax", "memory");
    }

    probe_signals_restore(saved);

    out->cs = probe_cs;
    out->rax = probe_rax;
    out->signo = (int)probe_signo;
    return 0;
}

/*
 * Where the 64-bit landing pad sits inside the same page the 16-bit segment is
 * installed over. Far enough past the 16-bit stub to leave it obviously
 * separate, and still on the one page so a single MAP_32BIT mapping serves
 * both.
 *
 * That the two share a page is a convenience, not a requirement. The 16-bit
 * stub is reached at offset 0 of the LDT segment; the landing pad is reached at
 * its linear address through the flat 64-bit CS. They are addressed by entirely
 * different means and merely happen to be neighbours.
 */
#define ROUNDTRIP_LANDING_OFFSET 0x40

/*
 * The 16-bit leg.
 *
 *   b8 34 12            mov ax, 0x1234    the same operand-size discriminator
 *                                         the one-way probe uses
 *   66 ea off32 sel16   jmp far ptr16:32
 *
 * The 0x66 is the entire trick. Left off, EA in a 16-bit segment is
 * JMP ptr16:16 and the offset field is two bytes wide -- enough to reach
 * anywhere in a 64 KiB segment and nowhere else. The prefix widens the
 * immediate to a 32-bit offset, which can name any linear address below 4 GiB,
 * and the selector rides alongside it unchanged. A 16-bit instruction thus
 * addresses a 4 GiB space, which is what makes the return leg possible at all.
 *
 * The offset and selector are patched at run time: neither the address of the
 * landing pad nor the 64-bit CS selector is knowable when this array is
 * written.
 */
static unsigned char ROUNDTRIP_CODE16[] = {
    0xb8, 0x34, 0x12,             /* mov ax, 0x1234                  */
    0x66, 0xea,                   /* jmp far ptr16:32                */
    0x00, 0x00, 0x00, 0x00,       /*   offset   <- patched           */
    0x00, 0x00,                   /*   selector <- patched           */
};
#define ROUNDTRIP_CODE16_OFFSET_FIELD 5
#define ROUNDTRIP_CODE16_SELECTOR_FIELD 9

/*
 * The 64-bit landing pad.
 *
 *   49 ba 01 ef cd ab 90 90 90 90   movabs $0x90909090abcdef01, %r10
 *   49 89 26                        mov %rsp, (%r14)
 *   4c 89 fc                        mov %r15, %rsp
 *   41 ff e3                        jmp *%r11
 *
 * Every one of these needs a REX prefix, so none of them exists in
 * compatibility mode; see COMPAT16_LANDING_MARK in the header for what the
 * first decodes to if the CPU is not in the mode it should be in by now.
 *
 * Three 64-bit registers carry state across the excursion: R11 the return
 * address, R14 the address of the slot that records RSP on arrival, R15 the
 * saved stack pointer. Compatibility mode has no encoding that names r8-r15,
 * which is precisely why values left there are safe -- and, measured, they are:
 * R11 alone carries a return address far above 4 GiB and the jump through it
 * lands correctly.
 *
 * RSP enjoys no such protection, and this is the one prediction the round trip
 * got wrong. It arrives at the landing pad holding only its low 32 bits, its
 * upper half zeroed, even though SS was never reloaded and the 16-bit leg never
 * touched the stack. The general registers survive; the stack pointer does not.
 *
 * Two consequences, both of which matter more to a host than to this test:
 *
 *   1. The repair is three bytes and one spare register, done here before any
 *      compiled code gets a chance to run on a broken stack pointer. It is not
 *      a reason to abandon the technique.
 *
 *   2. Between the outbound jump and that repair there is a window in which
 *      RSP is unusable. A signal delivered inside it would have the kernel
 *      build a frame at a truncated address. The MAP_32BIT alternate stack
 *      installed for the recovery handlers closes this window as a side
 *      effect -- SA_ONSTACK means the frame never goes near RSP -- which makes
 *      the altstack a permanent requirement of the design rather than mere
 *      scaffolding for a failing case.
 */
static const unsigned char ROUNDTRIP_CODE64[] = {
    0x49, 0xba, 0x01, 0xef, 0xcd, 0xab, 0x90, 0x90, 0x90, 0x90,
    0x49, 0x89, 0x26,
    0x4c, 0x89, 0xfc,
    0x41, 0xff, 0xe3,
};

/*
 * Round-trip results. File scope for the same reason the saved handlers are:
 * a value written between sigsetjmp() and siglongjmp() only survives the jump
 * if it is not an automatic object.
 */
static uint64_t roundtrip_rax;
static uint64_t roundtrip_r10;
static uint64_t roundtrip_rsp_before;
static uint64_t roundtrip_rsp_at_landing;
static uint64_t roundtrip_rsp_after;
static uint16_t roundtrip_cs_after;

/*
 * One complete excursion: far jump out to the 16-bit stub, and back through the
 * landing pad. Results land in the roundtrip_* statics.
 *
 * Extracted so the probe and the timing loop run the identical instruction
 * sequence -- a benchmark measuring something subtly different from what the
 * tests verify would be worse than no benchmark.
 *
 * There is no sigsetjmp() here. A fault during the excursion longjmps to
 * whatever recovery point the caller established, abandoning this frame, which
 * is what should happen: a faulted transition invalidates the whole run.
 */
static void roundtrip_transition(const struct far_ptr *target, uint64_t seed)
{
    /*
     * Out and back, with no kernel involvement anywhere in between.
     *
     * The three registers the landing pad needs are loaded before the jump,
     * because after it there is no way to load them: compatibility mode cannot
     * name r8-r15, and that inaccessibility is exactly what keeps their
     * contents safe.
     *
     * R10 is zeroed rather than left alone so that a landing pad which never
     * ran reports zero instead of a stale value.
     */
    __asm__ __volatile__(
        "movq %%rsp, %[rsp_before]\n\t"
        "movq %[seed], %%rax\n\t"
        "xorl %%r10d, %%r10d\n\t"
        "leaq 1f(%%rip), %%r11\n\t"
        "movq %[landing_slot], %%r14\n\t"
        "movq %%rsp, %%r15\n\t"
        "ljmpl *(%[target])\n"
        "1:\n\t"
        "movq %%rsp, %[rsp_after]\n\t"
        "movq %%rax, %[rax]\n\t"
        "movq %%r10, %[r10]\n\t"
        "movw %%cs, %[cs_after]"
        : [rsp_before] "=m"(roundtrip_rsp_before),
          [rsp_after] "=m"(roundtrip_rsp_after), [rax] "=m"(roundtrip_rax),
          [r10] "=m"(roundtrip_r10), [cs_after] "=m"(roundtrip_cs_after)
        : [seed] "r"(seed), [target] "r"(target),
          [landing_slot] "r"(&roundtrip_rsp_at_landing)
        : "rax", "r10", "r11", "r14", "r15", "memory");
}

/*
 * Write both stubs into the page and patch the outbound far jump's target.
 *
 * Neither the landing pad's address nor the 64-bit CS selector is knowable
 * until run time, which is why ROUNDTRIP_CODE16 is not const.
 *
 * Returns the 64-bit CS selector on success, 0 on failure with errno set.
 */
static uint16_t roundtrip_stubs_install(void *segment_base)
{
    unsigned char *page = segment_base;
    unsigned char *landing = page + ROUNDTRIP_LANDING_OFFSET;

    /*
     * The outbound jump names the landing pad by a 32-bit offset, so a pad
     * above 4 GiB cannot be expressed. Refuse rather than silently truncate
     * into some unrelated mapping.
     */
    if ((uintptr_t)landing > UINT32_MAX) {
        errno = EFAULT;
        return 0;
    }

    /*
     * Ask the CPU which selector the 64-bit code segment is, rather than
     * assuming Linux's 0x33. The value has to be right for the jump to land,
     * and reading it costs one instruction.
     */
    uint16_t cs64;
    __asm__ __volatile__("movw %%cs, %0" : "=r"(cs64));

    uint32_t landing_linear = (uint32_t)(uintptr_t)landing;
    memcpy(ROUNDTRIP_CODE16 + ROUNDTRIP_CODE16_OFFSET_FIELD, &landing_linear,
           sizeof(landing_linear));
    memcpy(ROUNDTRIP_CODE16 + ROUNDTRIP_CODE16_SELECTOR_FIELD, &cs64,
           sizeof(cs64));
    memcpy(page, ROUNDTRIP_CODE16, sizeof(ROUNDTRIP_CODE16));
    memcpy(landing, ROUNDTRIP_CODE64, sizeof(ROUNDTRIP_CODE64));

    return cs64;
}

int compat16_run_roundtrip(int entry, void *segment_base, uint64_t seed,
                           struct compat16_roundtrip *out)
{
    static struct sigaction saved[PROBE_SIGNAL_COUNT];

    uint16_t cs64 = roundtrip_stubs_install(segment_base);
    if (cs64 == 0)
        return -1;

    if (probe_altstack_install() != 0)
        return -1;
    if (probe_signals_install(saved) != 0)
        return -1;

    probe_signo = 0;
    roundtrip_rax = 0;
    roundtrip_r10 = 0;
    roundtrip_rsp_before = 0;
    roundtrip_rsp_at_landing = 0;
    roundtrip_rsp_after = 0;
    roundtrip_cs_after = 0;

    struct far_ptr target = {
        .offset = 0,
        .selector = COMPAT16_SELECTOR(entry),
    };

    if (sigsetjmp(probe_recovery, 1) == 0)
        roundtrip_transition(&target, seed);

    probe_signals_restore(saved);

    out->rax = roundtrip_rax;
    out->r10 = roundtrip_r10;
    out->rsp_before = roundtrip_rsp_before;
    out->rsp_at_landing = roundtrip_rsp_at_landing;
    out->rsp_after = roundtrip_rsp_after;
    out->cs_before = cs64;
    out->cs_after = roundtrip_cs_after;
    out->signo = (int)probe_signo;
    return 0;
}

/*
 * Excursions run before the clock starts, to fault in the pages, load the
 * descriptor into the CPU's segment cache and settle the branch predictors.
 * The first transition is markedly more expensive than the rest, and timing it
 * would say more about cold caches than about the transition.
 */
#define COST_WARMUP 1000

static uint64_t monotonic_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int compat16_time_roundtrip(int entry, void *segment_base, uint64_t iterations,
                            uint64_t *out_ns)
{
    static struct sigaction saved[PROBE_SIGNAL_COUNT];

    if (roundtrip_stubs_install(segment_base) == 0)
        return -1;
    if (probe_altstack_install() != 0)
        return -1;
    if (probe_signals_install(saved) != 0)
        return -1;

    struct far_ptr target = {
        .offset = 0,
        .selector = COMPAT16_SELECTOR(entry),
    };

    /*
     * The recovery point exists only to catch a faulted excursion. Landing here
     * means the run is void: report the failure rather than a timing derived
     * from an unknown number of completed iterations.
     */
    if (sigsetjmp(probe_recovery, 1) != 0) {
        probe_signals_restore(saved);
        errno = EIO;
        return -1;
    }

    for (uint64_t i = 0; i < COST_WARMUP; i++)
        roundtrip_transition(&target, 0);

    uint64_t start = monotonic_ns();
    for (uint64_t i = 0; i < iterations; i++)
        roundtrip_transition(&target, 0);
    uint64_t elapsed = monotonic_ns() - start;

    probe_signals_restore(saved);

    *out_ns = elapsed;
    return 0;
}

/*
 * One excursion by the other route: far jump out, trap, and let the handler
 * recover.
 *
 * The sigsetjmp() sits inside this function rather than in the loop above it so
 * that recovery unwinds exactly one iteration. Put it outside and the handler's
 * siglongjmp would abandon the loop counter along with the frame.
 */
static void signal_transition(const struct far_ptr *target)
{
    if (sigsetjmp(probe_recovery, 1) == 0) {
        __asm__ __volatile__("ljmpl *(%[target])"
                             :
                             : [target] "r"(target)
                             : "memory");
    }
}

int compat16_time_signal_path(int entry, void *segment_base,
                              uint64_t iterations, uint64_t *out_ns)
{
    static struct sigaction saved[PROBE_SIGNAL_COUNT];

    memcpy(segment_base, PROBE_CODE, sizeof(PROBE_CODE));

    if (probe_altstack_install() != 0)
        return -1;
    if (probe_signals_install(saved) != 0)
        return -1;

    struct far_ptr target = {
        .offset = 0,
        .selector = COMPAT16_SELECTOR(entry),
    };

    for (uint64_t i = 0; i < COST_WARMUP; i++)
        signal_transition(&target);

    uint64_t start = monotonic_ns();
    for (uint64_t i = 0; i < iterations; i++)
        signal_transition(&target);
    uint64_t elapsed = monotonic_ns() - start;

    probe_signals_restore(saved);

    *out_ns = elapsed;
    return 0;
}

/*
 * espfix probe state. File scope is load-bearing, not stylistic: between the
 * IRET and the point where RSP is put back, there is no usable stack, so every
 * operand in that window has to be reachable RIP-relatively.
 */
static uint64_t espfix_rsp_before;
static uint64_t espfix_rsp_after;
static volatile uint16_t espfix_frame_ss;
static volatile uint16_t espfix_live_ss;

static void espfix_handler(int signo, siginfo_t *info, void *ctx)
{
    const ucontext_t *uc = ctx;
    uint16_t live;

    (void)signo;
    (void)info;

    /* Same packed greg as CS, but SS occupies the top 16 bits. */
    espfix_frame_ss = (uint16_t)(uc->uc_mcontext.gregs[REG_CSGSFS] >> 48);

    __asm__ __volatile__("movw %%ss, %0" : "=r"(live));
    espfix_live_ss = live;

    /*
     * Return normally. The return IS the experiment: sigreturn restores the
     * saved 16-bit SS and IRETs to it. Recovering by siglongjmp here, as the
     * other probe does, would skip the only instruction that matters.
     */
}

int compat16_probe_espfix(int stack_entry, struct compat16_espfix *out)
{
    struct sigaction sa, saved;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = espfix_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTRAP, &sa, &saved) != 0)
        return -1;

    uint16_t ss16 = COMPAT16_SELECTOR(stack_entry);
    uint16_t ss64;
    __asm__ __volatile__("movw %%ss, %0" : "=r"(ss64));

    /*
     * CS stays 64-bit for all of this, so the stack pointer in use is the full
     * RSP and SS.B is ignored while we run. It matters only to IRET.
     *
     * The three instructions after int3 are a hazard window: RSP is truncated
     * and any signal arriving before it is restored would push a frame at a
     * garbage address. All three are RIP-relative or register-only for that
     * reason, and the window is as short as it can be made.
     */
    __asm__ __volatile__("movq %%rsp, %[before]\n\t"
                         "movw %[ss16], %%ss\n\t"
                         "int3\n\t"
                         "movq %%rsp, %[after]\n\t"
                         "movw %[ss64], %%ss\n\t"
                         "movq %[before], %%rsp"
                         : [before] "=m"(espfix_rsp_before),
                           [after] "=m"(espfix_rsp_after)
                         : [ss16] "r"(ss16), [ss64] "r"(ss64)
                         : "memory");

    sigaction(SIGTRAP, &saved, NULL);

    out->rsp_before = espfix_rsp_before;
    out->rsp_after = espfix_rsp_after;
    out->ss_saved = espfix_frame_ss;
    out->ss_in_handler = espfix_live_ss;
    return 0;
}
