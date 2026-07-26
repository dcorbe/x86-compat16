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

/*
 * Segment type nibble, bits 40..43: accessed(40), writable(41),
 * expand-down(42), executable(43).
 *
 * Note the accessed bit is already set on readback. Linux sets it itself when
 * filling the descriptor rather than leaving it for the CPU to set on first
 * load, so that the LDT page can be mapped read-only. A writable expand-up
 * data segment therefore reads back as 0x3, not the 0x2 you would predict from
 * the request alone.
 */
#define COMPAT16_DESC_TYPE(raw) ((unsigned)(((raw) >> 40) & 0xfu))
#define COMPAT16_TYPE_DATA_RW_ACCESSED 0x3u

/*
 * Build the segment selector naming LDT slot `entry` at user privilege:
 * index in bits 3..15, TI = 1 selects the LDT rather than the GDT, RPL = 3.
 */
#define COMPAT16_SELECTOR(entry) ((uint16_t)(((unsigned)(entry) << 3) | 0x7u))

/*
 * Install a 16-bit writable data segment suitable for loading into SS.
 *
 * Same arguments and error convention as compat16_install_code_segment().
 * Clearing seg_32bit here clears the descriptor's B bit rather than its D bit;
 * the encoding is the same field, but for a stack segment it declares the
 * stack pointer to be SP rather than ESP. That is the bit the whole espfix64
 * problem hangs on.
 */
int compat16_install_stack_segment(int entry, const void *base, size_t length);

/* CPU state captured at the instant the 16-bit probe trapped. */
struct compat16_trap {
    uint64_t rax; /* RAX at fault time; proves how the probe was decoded */
    uint16_t cs;  /* CS at fault time; proves which segment was executing */
    int signo;    /* signal that ended the probe */
};

/*
 * Far-jump into the 16-bit code segment in LDT slot `entry` and run a short
 * probe there, recovering into *out when it traps.
 *
 * `segment_base` must be the same address the segment was installed over; the
 * probe's instruction bytes are written into it.
 *
 * There is no far jump back. A 16-bit far jump cannot encode a 64-bit return
 * target, so the probe deliberately traps instead and a signal handler running
 * in 64-bit mode recovers via siglongjmp. The signal frame is a useful bonus:
 * it carries the register state at fault time, including CS.
 *
 * Recovering this way requires an alternate signal stack below 4 GiB. That is
 * not a detail -- without it the process dies. See the comment in compat16.c.
 *
 * Returns 0 on success. Returns -1 on failure to set up, with errno set.
 */
int compat16_run_probe(int entry, void *segment_base, uint64_t seed,
                       struct compat16_trap *out);

#endif /* COMPAT16_H */
