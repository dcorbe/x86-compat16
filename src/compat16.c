/*
 * compat16.c - see include/compat16.h
 */
#include <asm/ldt.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>
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
