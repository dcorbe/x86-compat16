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

#endif /* COMPAT16_H */
