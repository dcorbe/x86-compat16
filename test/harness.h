/*
 * harness.h - Minimal assertion harness for the compat16 experiments.
 *
 * Deliberately dependency-free. These tests poke at CPU mode transitions and
 * signal handlers; the fewer moving parts sitting between an assertion and the
 * hardware, the easier a failure is to attribute. A framework that forks,
 * installs its own signal handlers, or rewrites the stack would actively
 * interfere with what is under test here.
 *
 * An assertion failure records the failure and returns from the enclosing test
 * function, so a test never continues past a broken precondition.
 */
#ifndef HARNESS_H
#define HARNESS_H

#include <stdio.h>

/* Failures recorded by the test currently executing. Reset by RUN_TEST. */
extern int harness_current_failures;

/* Totals across the whole run, reported by harness_report(). */
extern int harness_total_failures;
extern int harness_tests_run;

/* Declare a test. Tests take no arguments and report via the ASSERT macros. */
#define TEST(name) static void name(void)

/*
 * Run one test and print a PASS/FAIL line for it. Uses #fn as the display
 * name so the test's identifier is the thing reported, with no separate
 * string to drift out of sync.
 */
#define RUN_TEST(fn)                                                          \
    do {                                                                      \
        harness_current_failures = 0;                                         \
        harness_tests_run++;                                                  \
        fn();                                                                 \
        if (harness_current_failures == 0) {                                  \
            printf("  PASS  %s\n", #fn);                                      \
        } else {                                                              \
            printf("  FAIL  %s\n", #fn);                                      \
            harness_total_failures++;                                         \
        }                                                                     \
    } while (0)

/* Core assertion. Records the failure and abandons the current test. */
#define ASSERT_MSG(cond, fmt, ...)                                            \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "        %s:%d: " fmt "\n", __FILE__, __LINE__,   \
                    ##__VA_ARGS__);                                           \
            harness_current_failures++;                                       \
            return;                                                           \
        }                                                                     \
    } while (0)

/* Assert a condition holds, reporting the source text of the condition. */
#define ASSERT(cond) ASSERT_MSG((cond), "expected: %s", #cond)

/* Assert two integers are equal, reporting both values on mismatch. */
#define ASSERT_EQ_INT(actual, expected)                                       \
    do {                                                                      \
        long long a_ = (long long)(actual);                                   \
        long long e_ = (long long)(expected);                                 \
        ASSERT_MSG(a_ == e_, "%s: expected %lld, got %lld", #actual, e_, a_); \
    } while (0)

/*
 * Print the run summary. Returns a value suitable for main()'s exit status:
 * 0 when every test passed, 1 otherwise.
 */
int harness_report(void);

#endif /* HARNESS_H */
