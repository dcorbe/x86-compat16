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

int main(void)
{
    printf("compat16: 16-bit protected mode on x86-64\n");
    RUN_TEST(kernel_accepts_a_16bit_code_descriptor);
    RUN_TEST(installed_descriptor_selects_16bit_compatibility_mode);
    RUN_TEST(far_jump_enters_the_16bit_code_segment);
    RUN_TEST(instructions_decode_with_16bit_default_operand_size);
    RUN_TEST(kernel_accepts_a_16bit_stack_descriptor);
    return harness_report();
}
