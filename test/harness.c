/*
 * harness.c - Storage and reporting for the minimal test harness.
 */
#include "harness.h"

int harness_current_failures;
int harness_total_failures;
int harness_tests_run;

int harness_report(void)
{
    printf("\n%d test(s) run, %d failed\n", harness_tests_run,
           harness_total_failures);
    return harness_total_failures == 0 ? 0 : 1;
}
