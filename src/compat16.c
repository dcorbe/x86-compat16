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
#include <stdio.h>
#include <sys/wait.h>
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
/* Seed for the forked probe. Its value does not matter, only that it runs. */
#define PROBE_CHILD_SEED 0x0123456789abcdefull

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
 * Arrange -- or deliberately fail to arrange -- an alternate signal stack.
 *
 * Taking a signal in compatibility mode without one is fatal. The kernel cannot
 * build a frame, calls force_sigsegv(), fails the same way again, and the
 * process dies with a SIGSEGV handler installed and CONFIG_IA32_EMULATION=y.
 * strace shows the shape of it plainly:
 *
 *     --- SIGTRAP  {si_code=SI_KERNEL} ---     <- our int3 fired
 *     --- SIGSEGV  {si_code=SI_KERNEL} ---     <- frame setup failed
 *     --- SIGSEGV  {si_code=SI_KERNEL} ---     <- and again
 *     +++ killed by SIGSEGV +++
 *
 * The three modes exist so that the fix can be taken apart. An earlier version
 * of this file changed two things at once -- it added an alternate stack AND
 * mapped it below 4 GiB -- and credited the low mapping. COMPAT16_ALTSTACK_HIGH
 * is what separates them.
 *
 * Returns 0 on success, -1 with errno set on failure.
 */
static int probe_altstack_install(enum compat16_altstack which)
{
    static char *low;
    static char *high;

    if (which == COMPAT16_ALTSTACK_NONE) {
        stack_t off = {.ss_sp = NULL, .ss_size = 0, .ss_flags = SS_DISABLE};
        return sigaltstack(&off, NULL);
    }

    char **slot = (which == COMPAT16_ALTSTACK_LOW) ? &low : &high;
    int extra = (which == COMPAT16_ALTSTACK_LOW) ? MAP_32BIT : 0;

    if (*slot == NULL) {
        char *p = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | extra, -1, 0);
        if (p == MAP_FAILED)
            return -1;
        *slot = p;
    }

    stack_t alt = {.ss_sp = *slot, .ss_size = 65536, .ss_flags = 0};
    return sigaltstack(&alt, NULL);
}

/* Where an installed alternate stack actually landed, for the tests to show. */
uintptr_t compat16_altstack_address(enum compat16_altstack which)
{
    stack_t current;

    (void)which;
    if (sigaltstack(NULL, &current) != 0)
        return 0;
    return (uintptr_t)current.ss_sp;
}

/*
 * Install probe_trap_handler() over every signal a failed transition might
 * raise, saving the previous dispositions into `saved`.
 *
 * Returns 0 on success. On failure any handler already installed is put back,
 * so a partial install never leaks out of the call.
 */
static int probe_signals_install_handler(struct sigaction *saved,
                                         void (*handler)(int, siginfo_t *,
                                                         void *))
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
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

/* The ordinary case: every probe signal escapes by siglongjmp. */
static int probe_signals_install(struct sigaction *saved)
{
    return probe_signals_install_handler(saved, probe_trap_handler);
}

/* Put back what probe_signals_install() displaced. */
static void probe_signals_restore(const struct sigaction *saved)
{
    for (size_t i = 0; i < PROBE_SIGNAL_COUNT; i++)
        sigaction(PROBE_SIGNALS[i], &saved[i], NULL);
}

static int run_probe_with(int entry, void *segment_base, uint64_t seed,
                          enum compat16_altstack altstack,
                          struct compat16_trap *out);

int compat16_run_probe(int entry, void *segment_base, uint64_t seed,
                       struct compat16_trap *out)
{
    return run_probe_with(entry, segment_base, seed, COMPAT16_ALTSTACK_LOW,
                          out);
}

static int run_probe_with(int entry, void *segment_base, uint64_t seed,
                          enum compat16_altstack altstack,
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

    if (probe_altstack_install(altstack) != 0)
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
 * Two consequences, both of which matter more in earnest than they do here:
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

    if (probe_altstack_install(COMPAT16_ALTSTACK_LOW) != 0)
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
    if (probe_altstack_install(COMPAT16_ALTSTACK_LOW) != 0)
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

    if (probe_altstack_install(COMPAT16_ALTSTACK_LOW) != 0)
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
 * The 16-bit stack stub, and where the 64-bit landing pad sits behind it.
 *
 * These bytes were produced by assembling the listing below with `as` and
 * lifting the encoding out of `objdump`, rather than by working out ModRM by
 * hand. At this length that is the difference between a stub that is right and
 * one that merely looks right.
 *
 *      .code16
 *   0: mov   $0x1234, %ax          b8 34 12    operand-size discriminator
 *   3: mov   $SS, %bx              bb ss ss    16-bit stack selector, patched
 *   6: mov   %bx, %ss              8e d3
 *   8: mov   $0x1000, %sp          bc 00 10
 *   b: pushw $0xface               68 ce fa
 *   e: pop   %dx                   5a
 *   f: lcall $CS, $0x1e            9a 1e 00 cs cs   selector patched
 *  14: mov   %sp, %si              89 e6       SP at the end; balance check
 *  16: ljmpl $CS64, $LANDING       66 ea <off32> <sel16>   both patched
 *  1e: mov   $0xbeef, %cx          b9 ef be    the subroutine
 *  21: lret                        cb
 *
 * MOV SS is immediately followed by the SP load. That ordering is not
 * stylistic: loading SS inhibits interrupts for exactly one instruction, which
 * is the window in which SS and SP disagree. Anything else between them is a
 * bug.
 *
 * The LCALL's offset (0x1e) needs no patching because the stub is installed at
 * offset 0 of its segment, so the subroutine's segment offset is its offset
 * within this array. The selector does need patching -- a segment does not know
 * its own selector.
 */
static unsigned char STACK16_CODE[] = {
    0xb8, 0x34, 0x12,                                /* mov  $0x1234, %ax  */
    0xbb, 0x00, 0x00,                                /* mov  $SS, %bx      */
    0x8e, 0xd3,                                      /* mov  %bx, %ss      */
    0xbc, 0x00, 0x10,                                /* mov  $0x1000, %sp  */
    0x68, 0xce, 0xfa,                                /* pushw $0xface      */
    0x5a,                                            /* pop  %dx           */
    0x9a, 0x1e, 0x00, 0x00, 0x00,                    /* lcall $CS, $0x1e   */
    0x89, 0xe6,                                      /* mov  %sp, %si      */
    0x66, 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* ljmpl $CS64, $pad  */
    0xb9, 0xef, 0xbe,                                /* mov  $0xbeef, %cx  */
    0xcb,                                            /* lret               */
};
#define STACK16_STACK_SELECTOR_FIELD 4
#define STACK16_CALL_SELECTOR_FIELD 18
#define STACK16_JMP_OFFSET_FIELD 24
#define STACK16_JMP_SELECTOR_FIELD 28

/*
 * The 64-bit landing pad for the stack excursion.
 *
 *      .code64
 *   0: movabs $MARK, %r10          49 ba 01 ef cd ab 90 90 90 90
 *  10: mov   %rax, (%r14)          49 89 06
 *  13: mov   %rcx, 0x08(%r14)      49 89 4e 08
 *  17: mov   %rdx, 0x10(%r14)      49 89 56 10
 *  1b: mov   %rsi, 0x18(%r14)      49 89 76 18
 *  1f: mov   %rsp, 0x20(%r14)      49 89 66 20
 *  23: mov   %ss,  0x28(%r14)      41 8c 56 28
 *  27: mov   %r13w, %ss            41 8e d5    restore the 64-bit SS
 *  2a: mov   %r15, %rsp            4c 89 fc    and RSP, in the shadow
 *  2d: jmp   *%r11                 41 ff e3
 *
 * The register spills happen while the 16-bit SS is still loaded, which is
 * fine: they address memory through DS, and in 64-bit mode SS's base is ignored
 * anyway. What they must not do is touch the stack, and they do not.
 *
 * SS is restored before RSP deliberately. MOV SS inhibits interrupts for one
 * instruction, so the pair executes with no window in which a signal could
 * arrive to find a 64-bit SS paired with a 16-bit stack pointer.
 */
static const unsigned char STACK16_LANDING[] = {
    0x49, 0xba, 0x01, 0xef, 0xcd, 0xab, 0x90, 0x90, 0x90, 0x90,
    0x49, 0x89, 0x06,
    0x49, 0x89, 0x4e, 0x08,
    0x49, 0x89, 0x56, 0x10,
    0x49, 0x89, 0x76, 0x18,
    0x49, 0x89, 0x66, 0x20,
    0x41, 0x8c, 0x56, 0x28,
    0x41, 0x8e, 0xd5,
    0x4c, 0x89, 0xfc,
    0x41, 0xff, 0xe3,
};

/*
 * Slots the landing pad spills into, in the order its stores expect. Indices
 * are byte offsets divided by eight; the pad hardcodes the byte offsets.
 */
enum {
    STACK16_SLOT_RAX = 0,
    STACK16_SLOT_RCX,
    STACK16_SLOT_RDX,
    STACK16_SLOT_RSI,
    STACK16_SLOT_RSP,
    STACK16_SLOT_SS,
    STACK16_SLOT_COUNT,
};

static uint64_t stack16_slots[STACK16_SLOT_COUNT];
static uint64_t stack16_rsp_before;
static uint64_t stack16_rsp_after;
static uint16_t stack16_ss_before;
static uint16_t stack16_ss_after;

int compat16_run_stack16(int code_entry, int stack_entry, void *code_base,
                         void *stack_base, struct compat16_stack16 *out)
{
    static struct sigaction saved[PROBE_SIGNAL_COUNT];

    (void)stack_base; /* named for symmetry; the descriptor already covers it */

    unsigned char *page = code_base;
    unsigned char *landing = page + ROUNDTRIP_LANDING_OFFSET;

    if ((uintptr_t)landing > UINT32_MAX) {
        errno = EFAULT;
        return -1;
    }

    uint16_t cs64;
    __asm__ __volatile__("movw %%cs, %0" : "=r"(cs64));

    uint16_t code_sel = COMPAT16_SELECTOR(code_entry);
    uint16_t stack_sel = COMPAT16_SELECTOR(stack_entry);
    uint32_t landing_linear = (uint32_t)(uintptr_t)landing;

    memcpy(STACK16_CODE + STACK16_STACK_SELECTOR_FIELD, &stack_sel,
           sizeof(stack_sel));
    memcpy(STACK16_CODE + STACK16_CALL_SELECTOR_FIELD, &code_sel,
           sizeof(code_sel));
    memcpy(STACK16_CODE + STACK16_JMP_OFFSET_FIELD, &landing_linear,
           sizeof(landing_linear));
    memcpy(STACK16_CODE + STACK16_JMP_SELECTOR_FIELD, &cs64, sizeof(cs64));

    memcpy(page, STACK16_CODE, sizeof(STACK16_CODE));
    memcpy(landing, STACK16_LANDING, sizeof(STACK16_LANDING));

    if (probe_altstack_install(COMPAT16_ALTSTACK_LOW) != 0)
        return -1;
    if (probe_signals_install(saved) != 0)
        return -1;

    probe_signo = 0;
    memset(stack16_slots, 0, sizeof(stack16_slots));
    stack16_rsp_before = 0;
    stack16_rsp_after = 0;
    stack16_ss_before = 0;
    stack16_ss_after = 0;

    struct far_ptr target = {
        .offset = 0,
        .selector = code_sel,
    };

    if (sigsetjmp(probe_recovery, 1) == 0) {
        /*
         * R13 carries the 64-bit SS the landing pad has to put back. It joins
         * R11, R14 and R15 in the set of registers compatibility mode cannot
         * name and therefore cannot disturb.
         */
        __asm__ __volatile__(
            "movq %%rsp, %[rsp_before]\n\t"
            "movw %%ss, %[ss_before]\n\t"
            "leaq 1f(%%rip), %%r11\n\t"
            "xorl %%r13d, %%r13d\n\t"
            "movw %%ss, %%r13w\n\t"
            "movq %[slots], %%r14\n\t"
            "movq %%rsp, %%r15\n\t"
            "ljmpl *(%[target])\n"
            "1:\n\t"
            "movq %%rsp, %[rsp_after]\n\t"
            "movw %%ss, %[ss_after]"
            : [rsp_before] "=m"(stack16_rsp_before),
              [rsp_after] "=m"(stack16_rsp_after),
              [ss_before] "=m"(stack16_ss_before),
              [ss_after] "=m"(stack16_ss_after)
            : [target] "r"(&target), [slots] "r"(stack16_slots)
            : "rax", "rcx", "rdx", "rsi", "r10", "r11", "r13", "r14", "r15",
              "memory");
    }

    probe_signals_restore(saved);

    out->rax = stack16_slots[STACK16_SLOT_RAX];
    out->rcx = stack16_slots[STACK16_SLOT_RCX];
    out->rdx = stack16_slots[STACK16_SLOT_RDX];
    out->rbp = stack16_slots[STACK16_SLOT_RSI];
    out->rsp_at_landing = stack16_slots[STACK16_SLOT_RSP];
    out->ss_at_landing = stack16_slots[STACK16_SLOT_SS];
    out->rsp_before = stack16_rsp_before;
    out->rsp_after = stack16_rsp_after;
    out->ss_before = stack16_ss_before;
    out->ss_after = stack16_ss_after;
    out->signo = (int)probe_signo;
    return 0;
}

/*
 * The stub that takes a signal from inside 16-bit mode.
 *
 *      .code16
 *   0: mov   $0x1234, %ax          b8 34 12
 *   3: mov   $SS, %bx              bb ss ss    patched
 *   6: mov   %bx, %ss              8e d3
 *   8: mov   $0x1000, %sp          bc 00 10
 *   b: pushw $0xface               68 ce fa    pushed BEFORE the trap
 *   e: int3                        cc          <- the signal
 *   f: pop   %dx                   5a          only works if SS and SP came back
 *  10: mov   %sp, %si              89 e6
 *  12: ljmpl $CS64, $LANDING       66 ea <off32> <sel16>   both patched
 *
 * The push before the trap and the pop after it are the whole design. The pop
 * reads through the 16-bit SS at the 16-bit SP, so recovering 0xface is only
 * possible if sigreturn restored both. A test that merely checked "did we get
 * back" would pass on a flat SS too, and prove nothing about espfix.
 */
static unsigned char SIGRET_CODE[] = {
    0xb8, 0x34, 0x12,                                /* mov  $0x1234, %ax  */
    0xbb, 0x00, 0x00,                                /* mov  $SS, %bx      */
    0x8e, 0xd3,                                      /* mov  %bx, %ss      */
    0xbc, 0x00, 0x10,                                /* mov  $0x1000, %sp  */
    0x68, 0xce, 0xfa,                                /* pushw $0xface      */
    0xcc,                                            /* int3               */
    0x5a,                                            /* pop  %dx           */
    0x89, 0xe6,                                      /* mov  %sp, %si      */
    0x66, 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* ljmpl $CS64, $pad  */
};
#define SIGRET_STACK_SELECTOR_FIELD 4
#define SIGRET_JMP_OFFSET_FIELD 20
#define SIGRET_JMP_SELECTOR_FIELD 24

/*
 * Ceiling on handler entries before the run is abandoned.
 *
 * If the IRET were to land back on the INT3 rather than past it, the handler
 * and the trap would take turns forever. One delivery is the correct answer;
 * anything above this means something is wrong in a way worth escaping from
 * rather than hanging on.
 */
#define SIGRET_MAX_DELIVERIES 4

static volatile sig_atomic_t sigret_deliveries;
static volatile uint16_t sigret_cs;
static volatile uint16_t sigret_ss;
static volatile uint64_t sigret_rsp;
static volatile uint64_t sigret_flags;

/*
 * Unlike probe_trap_handler(), this returns rather than escaping -- for
 * SIGTRAP, which is the designed trap. Returning is what puts sigreturn's IRET
 * on trial.
 *
 * SIGSEGV and SIGILL still escape, because reaching them means the IRET failed
 * and there is nothing left to measure.
 */
static void sigret_handler(int signo, siginfo_t *info, void *ctx)
{
    const ucontext_t *uc = ctx;
    (void)info;

    if (signo != SIGTRAP) {
        probe_signo = signo;
        siglongjmp(probe_recovery, 1);
    }

    sigret_deliveries++;

    /* CS sits in the low 16 bits of the packed greg, SS in the top. */
    sigret_cs = (uint16_t)(uc->uc_mcontext.gregs[REG_CSGSFS] & 0xffffu);
    sigret_ss = (uint16_t)(uc->uc_mcontext.gregs[REG_CSGSFS] >> 48);
    sigret_rsp = (uint64_t)uc->uc_mcontext.gregs[REG_RSP];
    sigret_flags = (uint64_t)uc->uc_flags;

    if (sigret_deliveries > SIGRET_MAX_DELIVERIES) {
        probe_signo = signo;
        siglongjmp(probe_recovery, 1);
    }
}

int compat16_run_sigret(int code_entry, int stack_entry, void *code_base,
                        void *stack_base, struct compat16_sigret *out)
{
    static struct sigaction saved[PROBE_SIGNAL_COUNT];

    (void)stack_base;

    unsigned char *page = code_base;
    unsigned char *landing = page + ROUNDTRIP_LANDING_OFFSET;

    if ((uintptr_t)landing > UINT32_MAX) {
        errno = EFAULT;
        return -1;
    }

    uint16_t cs64;
    __asm__ __volatile__("movw %%cs, %0" : "=r"(cs64));

    uint16_t code_sel = COMPAT16_SELECTOR(code_entry);
    uint16_t stack_sel = COMPAT16_SELECTOR(stack_entry);
    uint32_t landing_linear = (uint32_t)(uintptr_t)landing;

    memcpy(SIGRET_CODE + SIGRET_STACK_SELECTOR_FIELD, &stack_sel,
           sizeof(stack_sel));
    memcpy(SIGRET_CODE + SIGRET_JMP_OFFSET_FIELD, &landing_linear,
           sizeof(landing_linear));
    memcpy(SIGRET_CODE + SIGRET_JMP_SELECTOR_FIELD, &cs64, sizeof(cs64));

    memcpy(page, SIGRET_CODE, sizeof(SIGRET_CODE));
    memcpy(landing, STACK16_LANDING, sizeof(STACK16_LANDING));

    if (probe_altstack_install(COMPAT16_ALTSTACK_LOW) != 0)
        return -1;
    if (probe_signals_install_handler(saved, sigret_handler) != 0)
        return -1;

    probe_signo = 0;
    sigret_deliveries = 0;
    sigret_cs = 0;
    sigret_ss = 0;
    sigret_rsp = 0;
    sigret_flags = 0;
    memset(stack16_slots, 0, sizeof(stack16_slots));
    stack16_rsp_before = 0;
    stack16_rsp_after = 0;
    stack16_ss_before = 0;
    stack16_ss_after = 0;

    struct far_ptr target = {
        .offset = 0,
        .selector = code_sel,
    };

    if (sigsetjmp(probe_recovery, 1) == 0) {
        __asm__ __volatile__(
            "movq %%rsp, %[rsp_before]\n\t"
            "movw %%ss, %[ss_before]\n\t"
            "leaq 1f(%%rip), %%r11\n\t"
            "xorl %%r13d, %%r13d\n\t"
            "movw %%ss, %%r13w\n\t"
            "movq %[slots], %%r14\n\t"
            "movq %%rsp, %%r15\n\t"
            "ljmpl *(%[target])\n"
            "1:\n\t"
            "movq %%rsp, %[rsp_after]\n\t"
            "movw %%ss, %[ss_after]"
            : [rsp_before] "=m"(stack16_rsp_before),
              [rsp_after] "=m"(stack16_rsp_after),
              [ss_before] "=m"(stack16_ss_before),
              [ss_after] "=m"(stack16_ss_after)
            : [target] "r"(&target), [slots] "r"(stack16_slots)
            : "rax", "rcx", "rdx", "rsi", "r10", "r11", "r13", "r14", "r15",
              "memory");
    }

    probe_signals_restore(saved);

    out->cs_in_frame = sigret_cs;
    out->ss_in_frame = sigret_ss;
    out->rsp_in_frame = sigret_rsp;
    out->uc_flags = sigret_flags;
    out->deliveries = (int)sigret_deliveries;
    out->rax = stack16_slots[STACK16_SLOT_RAX];
    out->rdx = stack16_slots[STACK16_SLOT_RDX];
    out->rsi = stack16_slots[STACK16_SLOT_RSI];
    out->rsp_before = stack16_rsp_before;
    out->rsp_after = stack16_rsp_after;
    out->ss_before = stack16_ss_before;
    out->ss_after = stack16_ss_after;
    out->signo = (int)probe_signo;
    return 0;
}

/*
 * Layout of the re-entry experiment's code page. The thunk and the landing pad
 * are given room of their own rather than being packed, so that the offsets
 * baked into the stubs stay readable against a hex dump.
 */
#define REENTRY_THUNK_OFFSET 0x40
#define REENTRY_LANDING_OFFSET 0x80

/*
 * The 16-bit code that calls out and is later resumed.
 *
 *      .code16
 *   0: mov   $0x1234, %ax          b8 34 12
 *   3: mov   $SS, %bx              bb ss ss    patched
 *   6: mov   %bx, %ss              8e d3
 *   8: mov   $0x1000, %sp          bc 00 10
 *   b: lcall $CS, $0x40            9a 40 00 cs cs   selector patched
 *  10: mov   $0xbeef, %cx          b9 ef be    <- THE RESUME POINT
 *  13: mov   %sp, %si              89 e6
 *  15: ljmpl $CS64, $LANDING       66 ea <off32> <sel16>   both patched
 *
 * Offset 0x10 is the whole experiment. The far CALL at 0x0b pushes it, the
 * 64-bit side reads it back off the 16-bit stack, and re-entry has to land on
 * it. Nothing tells the 64-bit side what that offset is -- it recovers it.
 *
 * The CALL's own target offset (0x40) is fixed and needs no patching, since
 * the stub is installed at offset 0 of its segment. Its selector does.
 */
static unsigned char REENTRY_CODE[] = {
    0xb8, 0x34, 0x12,                                /* mov  $0x1234, %ax  */
    0xbb, 0x00, 0x00,                                /* mov  $SS, %bx      */
    0x8e, 0xd3,                                      /* mov  %bx, %ss      */
    0xbc, 0x00, 0x10,                                /* mov  $0x1000, %sp  */
    0x9a, 0x40, 0x00, 0x00, 0x00,                    /* lcall $CS, $0x40   */
    0xb9, 0xef, 0xbe,                                /* mov  $0xbeef, %cx  */
    0x89, 0xe6,                                      /* mov  %sp, %si      */
    0x66, 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* ljmpl $CS64, $pad  */
};
#define REENTRY_STACK_SELECTOR_FIELD 4
#define REENTRY_CALL_SELECTOR_FIELD 14
#define REENTRY_JMP_OFFSET_FIELD 23
#define REENTRY_JMP_SELECTOR_FIELD 27

/*
 * The thunk. All it does is leave, which is all a real import thunk does once
 * it has identified itself -- the work happens on the 64-bit side.
 *
 *   0: ljmpl $CS64, $LANDING       66 ea <off32> <sel16>
 */
static unsigned char REENTRY_THUNK[] = {
    0x66, 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
#define REENTRY_THUNK_OFFSET_FIELD 2
#define REENTRY_THUNK_SELECTOR_FIELD 6

int compat16_run_reentry(int code_entry, int stack_entry, void *code_base,
                         void *stack_base, struct compat16_reentry *out)
{
    static struct sigaction saved[PROBE_SIGNAL_COUNT];

    unsigned char *page = code_base;
    unsigned char *landing = page + REENTRY_LANDING_OFFSET;

    if ((uintptr_t)landing > UINT32_MAX) {
        errno = EFAULT;
        return -1;
    }

    uint16_t cs64;
    __asm__ __volatile__("movw %%cs, %0" : "=r"(cs64));

    uint16_t code_sel = COMPAT16_SELECTOR(code_entry);
    uint16_t stack_sel = COMPAT16_SELECTOR(stack_entry);
    uint32_t landing_linear = (uint32_t)(uintptr_t)landing;

    memcpy(REENTRY_CODE + REENTRY_STACK_SELECTOR_FIELD, &stack_sel,
           sizeof(stack_sel));
    memcpy(REENTRY_CODE + REENTRY_CALL_SELECTOR_FIELD, &code_sel,
           sizeof(code_sel));
    memcpy(REENTRY_CODE + REENTRY_JMP_OFFSET_FIELD, &landing_linear,
           sizeof(landing_linear));
    memcpy(REENTRY_CODE + REENTRY_JMP_SELECTOR_FIELD, &cs64, sizeof(cs64));
    memcpy(REENTRY_THUNK + REENTRY_THUNK_OFFSET_FIELD, &landing_linear,
           sizeof(landing_linear));
    memcpy(REENTRY_THUNK + REENTRY_THUNK_SELECTOR_FIELD, &cs64, sizeof(cs64));

    memcpy(page, REENTRY_CODE, sizeof(REENTRY_CODE));
    memcpy(page + REENTRY_THUNK_OFFSET, REENTRY_THUNK, sizeof(REENTRY_THUNK));
    memcpy(landing, STACK16_LANDING, sizeof(STACK16_LANDING));

    if (probe_altstack_install(COMPAT16_ALTSTACK_LOW) != 0)
        return -1;
    if (probe_signals_install(saved) != 0)
        return -1;

    probe_signo = 0;
    memset(stack16_slots, 0, sizeof(stack16_slots));
    stack16_rsp_before = 0;
    stack16_rsp_after = 0;
    stack16_ss_before = 0;
    stack16_ss_after = 0;

    struct far_ptr outbound = {
        .offset = 0,
        .selector = code_sel,
    };

    /* Leg one: in at offset 0, out through the thunk. */
    if (sigsetjmp(probe_recovery, 1) == 0) {
        __asm__ __volatile__(
            "movq %%rsp, %[rsp_before]\n\t"
            "movw %%ss, %[ss_before]\n\t"
            "leaq 1f(%%rip), %%r11\n\t"
            "xorl %%r13d, %%r13d\n\t"
            "movw %%ss, %%r13w\n\t"
            "movq %[slots], %%r14\n\t"
            "movq %%rsp, %%r15\n\t"
            "ljmpl *(%[target])\n"
            "1:"
            : [rsp_before] "=m"(stack16_rsp_before),
              [ss_before] "=m"(stack16_ss_before)
            : [target] "r"(&outbound), [slots] "r"(stack16_slots)
            : "rax", "rcx", "rdx", "rsi", "r10", "r11", "r13", "r14", "r15",
              "memory");
    }

    if (probe_signo != 0)
        goto done;

    /*
     * Recover the return address from the 16-bit stack.
     *
     * A 16-bit far CALL pushes CS first, then IP, so IP sits at the lower
     * address. SP came back in the landing pad's spill; the segment base is
     * `stack_base`, and the two together give a plain pointer.
     */
    uint16_t sp_at_thunk = (uint16_t)(stack16_slots[STACK16_SLOT_RSP] & 0xffffu);
    const unsigned char *frame = (const unsigned char *)stack_base + sp_at_thunk;

    uint16_t saved_ip, saved_cs;
    memcpy(&saved_ip, frame, sizeof(saved_ip));
    memcpy(&saved_cs, frame + sizeof(saved_ip), sizeof(saved_cs));

    out->sp_at_thunk = sp_at_thunk;
    out->saved_ip = saved_ip;
    out->saved_cs = saved_cs;

    struct far_ptr inbound = {
        .offset = saved_ip,
        .selector = saved_cs,
    };

    /*
     * Leg two: back in at the address the CALL left behind, with the call
     * frame accounted for -- SP moves up by the four bytes CS:IP occupied,
     * which is what the far RET this stands in for would have done.
     */
    uint64_t resume_sp = (uint64_t)sp_at_thunk + 4u;

    if (sigsetjmp(probe_recovery, 1) == 0) {
        __asm__ __volatile__(
            "leaq 1f(%%rip), %%r11\n\t"
            "xorl %%r13d, %%r13d\n\t"
            "movw %%ss, %%r13w\n\t"
            "movq %[slots], %%r14\n\t"
            "movq %%rsp, %%r15\n\t"

            /*
             * SS and the stack pointer, paired inside MOV SS's interrupt
             * shadow. RSP takes the segment offset, not a linear address:
             * 16-bit mode reads only its low 16 bits and adds the descriptor's
             * base itself.
             */
            "movw %[ss16], %%ss\n\t"
            "movq %[sp], %%rsp\n\t"

            "ljmpl *(%[target])\n"
            "1:\n\t"
            "movq %%rsp, %[rsp_after]\n\t"
            "movw %%ss, %[ss_after]"
            : [rsp_after] "=m"(stack16_rsp_after),
              [ss_after] "=m"(stack16_ss_after)
            : [target] "r"(&inbound), [slots] "r"(stack16_slots),
              [ss16] "r"(stack_sel), [sp] "r"(resume_sp)
            : "rax", "rcx", "rdx", "rsi", "r10", "r11", "r13", "r14", "r15",
              "memory");
    }

done:
    probe_signals_restore(saved);

    out->rcx = stack16_slots[STACK16_SLOT_RCX];
    out->rsi = stack16_slots[STACK16_SLOT_RSI];
    out->rsp_before = stack16_rsp_before;
    out->rsp_after = stack16_rsp_after;
    out->ss_before = stack16_ss_before;
    out->ss_after = stack16_ss_after;
    out->signo = (int)probe_signo;
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

/*
 * Run the one-way probe in a child process.
 *
 * The suite forks nowhere else, and harness.h explains why: a framework that
 * forked around every test would interfere with the very transitions under
 * test. This one is different, because the outcome being measured may be *the
 * death of the process*. Containing that in a child is the only way to report
 * it as a result rather than suffer it as one.
 *
 * The child exits 0 if the probe trapped as designed, 1 if it came back some
 * other way, and 2 if it could not be set up. _exit() rather than exit(), so
 * that no atexit handler or stdio buffer belonging to the parent runs twice.
 *
 * Returns 0 on success, -1 with errno set if the fork or the wait failed.
 */
int compat16_probe_in_child(int entry, void *segment_base,
                            enum compat16_altstack altstack,
                            struct compat16_child *out)
{
    fflush(NULL); /* nothing already buffered should be written twice */

    pid_t pid = fork();
    if (pid < 0)
        return -1;

    if (pid == 0) {
        struct compat16_trap trap = {0};
        if (run_probe_with(entry, segment_base, PROBE_CHILD_SEED, altstack,
                           &trap) != 0)
            _exit(2);
        _exit(trap.signo == SIGTRAP ? 0 : 1);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return -1;

    out->exited = WIFEXITED(status) ? 1 : 0;
    out->status = out->exited ? WEXITSTATUS(status) : 0;
    out->signo = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
    return 0;
}
