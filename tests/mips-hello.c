/* Minimal test for MIPS cross-compiled ELF (no libc dependency).
 * Build: clang --target=mips-linux-gnu -nostdlib -static -fuse-ld=lld
 * Dead/live functions for trim detection tests. */

__attribute__((noinline, used))
static int dead_compute(int a, int b) {
    int result = 0;
    for (int i = 0; i < a; i++) {
        result += b * i;
    }
    return result;
}

__attribute__((noinline, used))
static int dead_factorial(int n) {
    if (n <= 1) return 1;
    return n * dead_factorial(n - 1);
}

__attribute__((noinline))
static int live_add(int a, int b) {
    return a + b;
}

__attribute__((noinline))
static int live_multiply(int a, int b) {
    return a * b;
}

void __start(void) {
    volatile int x = live_add(1, 2);
    volatile int y = live_multiply(x, 3);
    (void)x;
    (void)y;
#if defined(__mips__)
    __asm__ volatile(
        "li $v0, 4001\n"
        "li $a0, 0\n"
        "syscall\n"
    );
#endif
}
