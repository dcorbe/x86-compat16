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
#include <unistd.h>

#include "compat16.h"

/* modify_ldt(2) function codes. */
#define LDT_READ 0
#define LDT_WRITE 1

/* struct user_desc .contents encoding. */
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

    /*
     * The signal frame MUST live below 4 GiB, and this is not optional.
     *
     * Measured behaviour on Linux 6.18: when the trap is taken while the CPU
     * is in compatibility mode, the kernel cannot place a signal frame on the
     * process's ordinary stack, which on x86-64 sits far above 4 GiB. Frame
     * setup fails, the kernel calls force_sigsegv(), that delivery fails the
     * same way, and the process dies from an unhandled SIGSEGV -- with a
     * SIGSEGV handler installed and CONFIG_IA32_EMULATION=y.
     *
     * strace shows the shape of it plainly:
     *
     *     --- SIGTRAP  {si_code=SI_KERNEL} ---     <- our int3 fired
     *     --- SIGSEGV  {si_code=SI_KERNEL} ---     <- frame setup failed
     *     --- SIGSEGV  {si_code=SI_KERNEL} ---     <- and again
     *     +++ killed by SIGSEGV +++
     *
     * Redirecting the frame to a MAP_32BIT alternate stack fixes it, which is
     * what establishes the address range as the cause. That the frame must be
     * addressable within 32 bits is the observed rule; the precise kernel path
     * that enforces it has not been traced here.
     *
     * This is the same family of hazard as espfix64: a 64-bit stack pointer
     * meeting a stack discipline that only has 32 bits to say it in.
     */
    static char *altstack;
    if (altstack == NULL) {
        altstack = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
        if (altstack == MAP_FAILED)
            return -1;
    }
    stack_t alt = {.ss_sp = altstack, .ss_size = 65536, .ss_flags = 0};
    if (sigaltstack(&alt, NULL) != 0)
        return -1;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = probe_trap_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);

    for (size_t i = 0; i < PROBE_SIGNAL_COUNT; i++) {
        if (sigaction(PROBE_SIGNALS[i], &sa, &saved[i]) != 0) {
            /* Undo the handlers already installed before giving up. */
            while (i-- > 0)
                sigaction(PROBE_SIGNALS[i], &saved[i], NULL);
            return -1;
        }
    }

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

    for (size_t i = 0; i < PROBE_SIGNAL_COUNT; i++)
        sigaction(PROBE_SIGNALS[i], &saved[i], NULL);

    out->cs = probe_cs;
    out->rax = probe_rax;
    out->signo = (int)probe_signo;
    return 0;
}
