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
#include <stdint.h>

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

/*
 * Read back the raw 8-byte segment descriptor sitting in LDT slot `entry`.
 *
 * Asking the kernel what it actually stored, rather than trusting what we
 * asked it to store, is the only way to catch a request that was accepted but
 * quietly normalised.
 *
 * Returns 0 on success and writes the descriptor to *out_raw. Returns -1 with
 * errno set on failure.
 */
int compat16_read_descriptor(int entry, uint64_t *out_raw);

/*
 * Field accessors for a raw descriptor, by bit position:
 *
 *   bit 53  L    long-mode (64-bit) code segment
 *   bit 54  D/B  default operand and address size, 1 = 32-bit, 0 = 16-bit
 *
 * 16-bit compatibility mode is exactly L = 0 together with D = 0. L = 1 with
 * D = 0 would be a 64-bit code segment, and the two are only one bit apart.
 */
#define COMPAT16_DESC_L(raw) ((unsigned)(((raw) >> 53) & 1u))
#define COMPAT16_DESC_D(raw) ((unsigned)(((raw) >> 54) & 1u))

#endif /* COMPAT16_H */
