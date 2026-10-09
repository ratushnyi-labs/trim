/* Regression fixture: x86-32 dead code is zero-filled in place (no libc).
 * Build: clang --target=i686-linux-gnu -nostdlib -static -O0
 *        -fno-pic -fuse-ld=lld; runs natively on an x86-64 kernel.
 *
 * The x86 decoders read 32-bit code in 64-bit mode, where an absolute
 * [disp32] operand (ModRM mod=00 rm=101: `lea msg, %ecx`, 8d 0d disp32;
 * `mov magic, %edx`, 8b 15 disp32) is RIP-relative. Compacting .text
 * "corrected" those absolute data addresses by the code shift, so the
 * trimmed binary wrote and read the wrong bytes. Until x86-32 decoding
 * is fixed, trim zero-fills x86-32 dead code in place: nothing moves
 * and nothing is patched.
 *
 * _start writes msg and exits 0 only when the word read through the
 * absolute operand is MAGIC; the msg write goes through the other. */

#define MAGIC 0x7A11C0DE

__attribute__((used)) const char msg[] = "x86-32 absolute: ok\n";
__attribute__((used)) const unsigned magic = MAGIC;

/* Never called. It comes first, so _start moved when it was removed. */
__attribute__((noinline, used))
static int dead_unused(int a, int b) {
    int r = 0;
    for (int i = 0; i < a; i++) {
        r += b * i;
    }
    return r;
}

/* write(1, msg, sizeof msg - 1); exit(magic == MAGIC ? 0 : 1). */
void _start(void) {
    __asm__ volatile(
        "mov $4, %%eax\n\t"
        "mov $1, %%ebx\n\t"
        "lea msg, %%ecx\n\t"
        "mov %0, %%edx\n\t"
        "int $0x80\n\t"
        "mov magic, %%edx\n\t"
        "xor %%ebx, %%ebx\n\t"
        "cmp %1, %%edx\n\t"
        "setne %%bl\n\t"
        "mov $1, %%eax\n\t"
        "int $0x80\n\t"
        :: "i"(sizeof msg - 1), "i"(MAGIC)
        : "eax", "ebx", "ecx", "edx", "memory");
}
