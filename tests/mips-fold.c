/* Regression fixture: MIPS dead-branch folding is paused (no libc).
 * Build: clang --target=mips-linux-gnu -nostdlib -static -O0
 *        -fno-pic -fuse-ld=lld; run under qemu-mips.
 *
 * probe_lw sets $t0 to 0, overwrites it with `lw` (1 at run time) and
 * branches on it with `bnez`. The MIPS constant model ignored loads,
 * kept the stale 0 and folded the taken (live) path away. Folding is
 * paused on MIPS until its soundness audit lands: trim must report no
 * dead branch here, and the trimmed binary must print what the
 * original prints. The taken path is two instructions, above the
 * 8-byte minimum for a dead block on MIPS, and only `bnez` reaches it:
 * the other path leaves with `j` (`b` is `beq $0, $0`, which the CFG
 * treats as conditional, so it would also fall into the taken path). */

volatile int g_one = 1;

/* Return 1 when the branch on the loaded value is taken, as it is. */
__attribute__((noinline, used))
static int probe_lw(volatile int *p) {
    int r;
    __asm__ volatile(
        ".set push\n\t"
        ".set noreorder\n\t"
        "li %0, -2\n\t"
        "li $t0, 0\n\t"
        "lw $t0, 0(%1)\n\t"
        "nop\n\t"
        "bnez $t0, 1f\n\t"
        "nop\n\t"
        "li %0, -1\n\t"
        "j 2f\n\t"
        "nop\n"
        "1:\n\t"
        "li %0, 0\n\t"
        "addiu %0, %0, 1\n"
        "2:\n\t"
        ".set pop\n\t"
        : "=&r"(r) : "r"(p) : "t0", "memory");
    return r;
}

/* Never called: dead-function removal stays on. put and __start come
 * after it, so they move and every JAL to them (an absolute target)
 * must be re-pointed even though the JAL in __start moves as well. */
__attribute__((noinline, used))
static int dead_unused(int a) {
    return a * 3 + 1;
}

/* write(1, s, n) */
static void put(const char *s, int n) {
    register int v0 __asm__("$2") = 4004;
    register int a0 __asm__("$4") = 1;
    register const char *a1 __asm__("$5") = s;
    register int a2 __asm__("$6") = n;
    __asm__ volatile("syscall"
                     : "+r"(v0) : "r"(a0), "r"(a1), "r"(a2)
                     : "$3", "$7", "memory");
}

void __start(void) {
    put(probe_lw(&g_one) == 1 ? "probes: 1\n" : "probes: F\n", 10);
    __asm__ volatile(
        "li $v0, 4001\n"
        "li $a0, 0\n"
        "syscall\n"
    );
}
