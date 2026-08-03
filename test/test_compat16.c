/*
 * test_compat16.c - Does x86-64 Linux still let userspace create and enter a
 * 16-bit protected-mode code segment?
 *
 * See README.md for the claim under test.
 */
#include <sys/mman.h>

#include "compat16.h"
#include "harness.h"

/*
 * Which LDT slot to install into. Arbitrary; the process starts with an empty
 * LDT, so any low index is free. Named so the tests read clearly rather than
 * scattering a bare 0.
 */
#define TEST_LDT_ENTRY 0

/* A second slot, for the 16-bit stack segment the espfix64 probe loads. */
#define TEST_LDT_STACK_ENTRY 1

/*
 * Back the segment with one page. A 16-bit code segment cannot address more
 * than 64 KiB anyway, and the stub under test is a handful of bytes.
 */
#define SEGMENT_BYTES 4096

/*
 * RAX seed for the probe. Both halves carry distinctive bits so that a 32-bit
 * misdecode, which zero-extends into RAX, cannot be mistaken for success.
 */
#define PROBE_SEED 0xCAFEBABEDEAD0000ull

/* What a genuine 16-bit `mov ax, 0x1234` leaves behind: only AX changes. */
#define PROBE_SEED_RESULT_16BIT 0xCAFEBABEDEAD1234ull

/*
 * Allocate a page eligible to be a 16-bit segment base.
 *
 * MAP_32BIT is the point of this helper: a segment descriptor's base is a
 * 32-bit field, so the mapping must live below 4 GiB. A default mmap() on
 * x86-64 typically lands far above that and would silently truncate.
 *
 * Returns NULL on failure.
 */
static void *map_low_page(void)
{
    void *p = mmap(NULL, SEGMENT_BYTES, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

/*
 * The gate for every later experiment: if CONFIG_X86_16BIT is compiled out, or
 * a hardening patch rejects non-32-bit descriptors, this fails and nothing
 * downstream is worth attempting.
 */
TEST(kernel_accepts_a_16bit_code_descriptor)
{
    void *page = map_low_page();
    ASSERT_MSG(page != NULL, "could not map a page below 4 GiB");

    int rc = compat16_install_code_segment(TEST_LDT_ENTRY, page, SEGMENT_BYTES);

    ASSERT_EQ_INT(rc, 0);
}

/*
 * Acceptance is not agreement. The kernel could plausibly accept the request
 * and store an ordinary 32-bit descriptor, in which case every later test
 * would "pass" while measuring nothing. Read back what was actually stored.
 */
TEST(installed_descriptor_selects_16bit_compatibility_mode)
{
    void *page = map_low_page();
    ASSERT_MSG(page != NULL, "could not map a page below 4 GiB");
    ASSERT_EQ_INT(
        compat16_install_code_segment(TEST_LDT_ENTRY, page, SEGMENT_BYTES), 0);

    uint64_t raw = 0;
    ASSERT_EQ_INT(compat16_read_descriptor(TEST_LDT_ENTRY, &raw), 0);

    ASSERT_EQ_INT(COMPAT16_DESC_D(raw), 0);
    ASSERT_EQ_INT(COMPAT16_DESC_L(raw), 0);
}

/*
 * The descriptor existing proves nothing about whether the CPU will honour a
 * far jump to it from 64-bit mode. CS at fault time is the evidence: if it
 * carries our LDT selector, the processor really was executing inside the
 * 16-bit segment.
 */
TEST(far_jump_enters_the_16bit_code_segment)
{
    void *page = map_low_page();
    ASSERT_MSG(page != NULL, "could not map a page below 4 GiB");
    ASSERT_EQ_INT(
        compat16_install_code_segment(TEST_LDT_ENTRY, page, SEGMENT_BYTES), 0);

    struct compat16_trap trap = {0};
    ASSERT_EQ_INT(compat16_run_probe(TEST_LDT_ENTRY, page, PROBE_SEED, &trap),
                  0);

    ASSERT_EQ_INT(trap.cs, COMPAT16_SELECTOR(TEST_LDT_ENTRY));
}

/*
 * The one that actually settles it.
 *
 * Landing in the segment does not prove the CPU decoded 16-bit. The probe's
 * three bytes B8 34 12 decode differently depending on the D bit, and the two
 * readings disagree about how many bytes the instruction even is:
 *
 *   D = 0 (16-bit)   mov ax, 0x1234        3 bytes; writes AX only, so
 *                                          RAX[63:16] survives untouched
 *   D = 1 (32-bit)   mov eax, 0xCCCC1234   5 bytes; swallows two of the
 *                                          following INT3 bytes as immediate
 *                                          data, and zero-extends into RAX,
 *                                          destroying RAX[63:32]
 *
 * Seeding RAX with a value that has bits set in both halves makes the two
 * outcomes impossible to confuse. A CPU that quietly ran this as 32-bit code
 * cannot produce the expected answer by accident.
 */
TEST(instructions_decode_with_16bit_default_operand_size)
{
    void *page = map_low_page();
    ASSERT_MSG(page != NULL, "could not map a page below 4 GiB");
    ASSERT_EQ_INT(
        compat16_install_code_segment(TEST_LDT_ENTRY, page, SEGMENT_BYTES), 0);

    struct compat16_trap trap = {0};
    ASSERT_EQ_INT(compat16_run_probe(TEST_LDT_ENTRY, page, PROBE_SEED, &trap),
                  0);

    ASSERT_EQ_U64(trap.rax, PROBE_SEED_RESULT_16BIT);
}

/*
 * The far jump back.
 *
 * Everything above establishes a one-way door: enter 16-bit mode, trap, and let
 * a signal handler carry the process home. A signal per transition is fine for
 * an experiment and ruinous for a host that has to service hundreds of distinct
 * API calls made from inside 16-bit code.
 *
 * The claim under test is that no signal is needed, because a 16-bit far jump
 * carrying a 0x66 operand-size prefix takes a 32-bit offset, which is enough to
 * name any address below 4 GiB -- including a landing pad in a 64-bit code
 * segment. This is the same manoeuvre Windows uses to reach 64-bit code from
 * WOW64, one segment size further down.
 *
 * signo is the headline: 0 means the round trip completed without the kernel
 * ever being involved.
 */
TEST(far_jump_returns_from_16bit_mode_without_taking_a_signal)
{
    void *page = map_low_page();
    ASSERT_MSG(page != NULL, "could not map a page below 4 GiB");
    ASSERT_EQ_INT(
        compat16_install_code_segment(TEST_LDT_ENTRY, page, SEGMENT_BYTES), 0);

    struct compat16_roundtrip trip = {0};
    ASSERT_EQ_INT(
        compat16_run_roundtrip(TEST_LDT_ENTRY, page, PROBE_SEED, &trip), 0);

    ASSERT_MSG(trip.signo == 0, "expected no signal, got signal %d",
               trip.signo);
    ASSERT_EQ_INT(trip.cs_after, trip.cs_before);
}

/*
 * A round trip that never went anywhere would also take no signal. The 16-bit
 * leg has to be shown to have run, and to have run as 16-bit code: same
 * operand-size discriminator as the one-way probe, for the same reason.
 */
TEST(the_16bit_leg_of_the_round_trip_decoded_as_16bit_code)
{
    void *page = map_low_page();
    ASSERT_MSG(page != NULL, "could not map a page below 4 GiB");
    ASSERT_EQ_INT(
        compat16_install_code_segment(TEST_LDT_ENTRY, page, SEGMENT_BYTES), 0);

    struct compat16_roundtrip trip = {0};
    ASSERT_EQ_INT(
        compat16_run_roundtrip(TEST_LDT_ENTRY, page, PROBE_SEED, &trip), 0);

    ASSERT_EQ_U64(trip.rax, PROBE_SEED_RESULT_16BIT);
}

/*
 * And the far side has to be shown to be genuinely 64-bit, not merely
 * somewhere else. The landing pad's first instruction is a REX.W movabs whose
 * bytes stay decodable -- and produce a different answer -- if the CPU were
 * still in compatibility mode. Arriving is not the same as arriving in 64-bit
 * mode.
 */
TEST(the_landing_pad_ran_in_64bit_mode)
{
    void *page = map_low_page();
    ASSERT_MSG(page != NULL, "could not map a page below 4 GiB");
    ASSERT_EQ_INT(
        compat16_install_code_segment(TEST_LDT_ENTRY, page, SEGMENT_BYTES), 0);

    struct compat16_roundtrip trip = {0};
    ASSERT_EQ_INT(
        compat16_run_roundtrip(TEST_LDT_ENTRY, page, PROBE_SEED, &trip), 0);

    ASSERT_EQ_U64(trip.r10, COMPAT16_LANDING_MARK);
}

/*
 * The one the round trip got wrong, and the reason this file says
 * `rsp_at_landing` at all.
 *
 * The expectation was that RSP would be untouched. SS is never reloaded, the
 * 16-bit leg pushes nothing, and no instruction anywhere in the excursion names
 * the stack pointer. It is nonetheless truncated: what arrives at the landing
 * pad is the low 32 bits of what left, upper half zeroed.
 *
 * That it is *exactly* a truncation is the useful part, and worth asserting
 * rather than merely printing. A stack pointer that came back mangled in some
 * other way, or that varied between runs, would mean the excursion could not be
 * made transparent at all. A clean truncation means the original value is
 * recoverable from a register that did survive -- and this test fires if that
 * ever stops being true.
 *
 * Note the contrast with R11 in the test above: the same excursion that
 * truncates RSP carries a return address above 4 GiB through R11 intact. This
 * is specific to the stack pointer, not a general narrowing of the register
 * file.
 */
TEST(rsp_arrives_at_the_landing_pad_truncated_to_32_bits)
{
    void *page = map_low_page();
    ASSERT_MSG(page != NULL, "could not map a page below 4 GiB");
    ASSERT_EQ_INT(
        compat16_install_code_segment(TEST_LDT_ENTRY, page, SEGMENT_BYTES), 0);

    struct compat16_roundtrip trip = {0};
    ASSERT_EQ_INT(
        compat16_run_roundtrip(TEST_LDT_ENTRY, page, PROBE_SEED, &trip), 0);

    printf("        rsp before      %#018llx\n",
           (unsigned long long)trip.rsp_before);
    printf("        rsp at landing  %#018llx\n",
           (unsigned long long)trip.rsp_at_landing);

    /* The upper half is gone... */
    ASSERT_MSG(trip.rsp_before > UINT32_MAX,
               "rsp_before %#llx has nothing in its upper half to lose",
               (unsigned long long)trip.rsp_before);

    /* ...and the lower half is untouched. */
    ASSERT_EQ_U64(trip.rsp_at_landing, trip.rsp_before & 0xffffffffull);
}

/*
 * The excursion must still leave the caller's stack exactly as it found it: a
 * host transitioning on every API call cannot hand its callers a stack pointer
 * that drifts.
 *
 * Given the truncation above, this passes only because the landing pad puts RSP
 * back from R15 before returning. That is the point being recorded -- not that
 * the hardware preserves RSP, which it does not, but that three bytes in the
 * trampoline make the damage invisible to everything upstream.
 */
TEST(the_landing_pad_hands_back_an_intact_rsp)
{
    void *page = map_low_page();
    ASSERT_MSG(page != NULL, "could not map a page below 4 GiB");
    ASSERT_EQ_INT(
        compat16_install_code_segment(TEST_LDT_ENTRY, page, SEGMENT_BYTES), 0);

    struct compat16_roundtrip trip = {0};
    ASSERT_EQ_INT(
        compat16_run_roundtrip(TEST_LDT_ENTRY, page, PROBE_SEED, &trip), 0);

    ASSERT_EQ_U64(trip.rsp_after, trip.rsp_before);
}

/*
 * How many excursions to time. Large enough that the signal path's cost swamps
 * clock granularity, small enough that the suite still finishes promptly: the
 * signal path dominates the runtime of this whole file.
 */
#define COST_ITERATIONS 50000

/*
 * The measurement the far jump was built for.
 *
 * A host servicing a 16-bit module's API calls pays the transition cost twice
 * per call, on every call. The one-way probe's answer to "how do I get back"
 * was a deliberate fault and a signal; this asks what that answer costs, and
 * what the far jump costs instead.
 *
 * Both figures cover the same work -- far jump out, a few instructions in
 * 16-bit mode, and control back in 64-bit code -- differing only in the return
 * mechanism. The assertion is deliberately loose. The interesting output is the
 * two numbers; a floor of 5x only fails if something has changed so
 * fundamentally that the ratio no longer holds at all.
 */
TEST(the_far_jump_return_costs_far_less_than_a_signal)
{
    void *page = map_low_page();
    ASSERT_MSG(page != NULL, "could not map a page below 4 GiB");
    ASSERT_EQ_INT(
        compat16_install_code_segment(TEST_LDT_ENTRY, page, SEGMENT_BYTES), 0);

    uint64_t farjump_ns = 0;
    uint64_t signal_ns = 0;
    ASSERT_EQ_INT(compat16_time_roundtrip(TEST_LDT_ENTRY, page, COST_ITERATIONS,
                                          &farjump_ns),
                  0);
    ASSERT_EQ_INT(compat16_time_signal_path(TEST_LDT_ENTRY, page,
                                            COST_ITERATIONS, &signal_ns),
                  0);

    double far_each = (double)farjump_ns / COST_ITERATIONS;
    double signal_each = (double)signal_ns / COST_ITERATIONS;

    printf("        far jump      %9.1f ns per round trip\n", far_each);
    printf("        signal        %9.1f ns per round trip\n", signal_each);
    printf("        ratio         %9.1fx\n", signal_each / far_each);

    ASSERT_MSG(far_each > 0.0, "far jump measured at zero; clock resolution?");
    ASSERT_MSG(signal_each > far_each * 5.0,
               "expected the signal path to cost at least 5x more; "
               "got %.1f ns against %.1f ns",
               signal_each, far_each);
}

/*
 * The espfix64 hazard needs a 16-bit *stack* segment, which is a different
 * descriptor from the code one: writable data, and the cleared bit is B rather
 * than D. Gate the probe on the kernel accepting it.
 */
TEST(kernel_accepts_a_16bit_stack_descriptor)
{
    void *page = map_low_page();
    ASSERT_MSG(page != NULL, "could not map a page below 4 GiB");
    ASSERT_EQ_INT(compat16_install_stack_segment(TEST_LDT_STACK_ENTRY, page,
                                                 SEGMENT_BYTES),
                  0);

    uint64_t raw = 0;
    ASSERT_EQ_INT(compat16_read_descriptor(TEST_LDT_STACK_ENTRY, &raw), 0);

    ASSERT_EQ_INT(COMPAT16_DESC_D(raw), 0);
    ASSERT_EQ_INT(COMPAT16_DESC_TYPE(raw), COMPAT16_TYPE_DATA_RW_ACCESSED);
}

/*
 * Taking a signal on a 16-bit stack segment. This is a characterisation test:
 * it records measured behaviour, and it exists to fire if that behaviour ever
 * changes.
 *
 * The prediction going in was that RSP would come back truncated -- IRET to a
 * segment with B = 0 restoring only SP, upper bits supplied by espfix64. That
 * is wrong, at least in this configuration. RSP survives in full. The
 * prediction and what is still unexplained are written up in README.md.
 *
 * Asserting ss_saved matters as much as asserting RSP. Without it the test
 * would pass trivially if the kernel quietly reset SS to a flat segment,
 * measuring nothing.
 */
TEST(rsp_survives_a_signal_taken_on_a_16bit_stack_segment)
{
    void *page = map_low_page();
    ASSERT_MSG(page != NULL, "could not map a page below 4 GiB");
    ASSERT_EQ_INT(compat16_install_stack_segment(TEST_LDT_STACK_ENTRY, page,
                                                 SEGMENT_BYTES),
                  0);

    struct compat16_espfix fix = {0};
    ASSERT_EQ_INT(compat16_probe_espfix(TEST_LDT_STACK_ENTRY, &fix), 0);

    printf("        rsp before      %#018llx\n",
           (unsigned long long)fix.rsp_before);
    printf("        rsp after       %#018llx\n",
           (unsigned long long)fix.rsp_after);
    printf("        ss saved        %#06x\n", fix.ss_saved);
    printf("        ss in handler   %#06x\n", fix.ss_in_handler);

    /* The 16-bit stack segment really was in effect across the signal. */
    ASSERT_EQ_INT(fix.ss_saved, COMPAT16_SELECTOR(TEST_LDT_STACK_ENTRY));

    /* And RSP came back whole, upper bits and all. */
    ASSERT_EQ_U64(fix.rsp_after, fix.rsp_before);
}

int main(void)
{
    /*
     * Line buffering, so that partial results survive a crash. Earlier
     * versions of this suite died mid-run and took their own output with
     * them, which cost more time than it should have.
     */
    setvbuf(stdout, NULL, _IOLBF, 0);

    printf("compat16: 16-bit protected mode on x86-64\n");
    RUN_TEST(kernel_accepts_a_16bit_code_descriptor);
    RUN_TEST(installed_descriptor_selects_16bit_compatibility_mode);
    RUN_TEST(far_jump_enters_the_16bit_code_segment);
    RUN_TEST(instructions_decode_with_16bit_default_operand_size);
    RUN_TEST(far_jump_returns_from_16bit_mode_without_taking_a_signal);
    RUN_TEST(the_16bit_leg_of_the_round_trip_decoded_as_16bit_code);
    RUN_TEST(the_landing_pad_ran_in_64bit_mode);
    RUN_TEST(rsp_arrives_at_the_landing_pad_truncated_to_32_bits);
    RUN_TEST(the_landing_pad_hands_back_an_intact_rsp);
    RUN_TEST(the_far_jump_return_costs_far_less_than_a_signal);
    RUN_TEST(kernel_accepts_a_16bit_stack_descriptor);
    RUN_TEST(rsp_survives_a_signal_taken_on_a_16bit_stack_segment);
    return harness_report();
}
