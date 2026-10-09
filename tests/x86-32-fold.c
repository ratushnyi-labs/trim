/* Regression fixture: x86-32 dead-branch folding is paused (no libc).
 * Build: clang --target=i686-linux-gnu -nostdlib -static -O0
 *        -fno-pic -fuse-ld=lld; runs natively on an x86-64 kernel.
 *
 * The x86 decoders read 32-bit code in 64-bit mode, where the one-byte
 * inc/dec (0x40-0x4F) are REX prefixes. probe_inc_loop counts esi up
 * to 10 with `inc esi; cmp esi, 10; jne`: read in 64-bit mode, the inc
 * becomes a prefix of the cmp, esi stays 0, and the jne was folded as
 * always taken, so the loop exit was removed. Folding is paused on
 * x86-32 until its decoding is fixed and audited: trim must report no
 * dead branch here, and the trimmed binary must still exit with 0.
 *
 * The result is reported only through the exit status: an absolute
 * data address in moved code (`lea disp32`) also reads as RIP-relative
 * in 64-bit mode and is mis-patched, a separate decoding issue. */

/* Never called: dead-function removal stays on. It comes first, so the
 * probe and _start both move when it is removed. */
__attribute__((noinline, used))
static int dead_unused(int a) {
    return a * 3 + 1;
}

/* 100, plus 0..9 while esi counts to 10, plus the final 10: 155.
 * Kept above the 32-byte minimum the analysis looks at. */
__attribute__((noinline, used))
static int probe_inc_loop(void) {
    int r;
    __asm__ volatile(
        "mov $100, %0\n\t"
        "xor %%esi, %%esi\n"
        "1:\n\t"
        "add %%esi, %0\n\t"
        "inc %%esi\n\t"
        "cmp $10, %%esi\n\t"
        "jne 1b\n\t"
        "add %%esi, %0\n\t"
        : "=&r"(r) : : "esi", "cc");
    return r;
}

/* exit(0) when the probe returns 155, else exit(1). */
void _start(void) {
    int status = probe_inc_loop() == 155 ? 0 : 1;
    __asm__ volatile(
        "mov $1, %%eax\n"
        "int $0x80\n"
        :: "b"(status) : "eax");
}
