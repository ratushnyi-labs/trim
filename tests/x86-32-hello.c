/* Minimal test for x86-32 cross-compiled ELF (no libc dependency).
 * Build: clang --target=i686-linux-gnu -nostdlib -static -fuse-ld=lld
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

void _start(void) {
    volatile int x = live_add(1, 2);
    volatile int y = live_multiply(x, 3);
    (void)x;
    (void)y;
    __asm__ volatile(
        "xor %%ebx, %%ebx\n"
        "mov $1, %%eax\n"
        "int $0x80\n"
        ::: "eax", "ebx"
    );
}
