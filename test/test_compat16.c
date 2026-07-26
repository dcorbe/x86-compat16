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

/*
 * Back the segment with one page. A 16-bit code segment cannot address more
 * than 64 KiB anyway, and the stub under test is a handful of bytes.
 */
#define SEGMENT_BYTES 4096

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

int main(void)
{
    printf("compat16: 16-bit protected mode on x86-64\n");
    RUN_TEST(kernel_accepts_a_16bit_code_descriptor);
    return harness_report();
}
