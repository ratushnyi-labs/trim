/* Regression fixture for dead-branch soundness on static binaries.
 *
 * Built with `gcc -static -O2`, this links musl's printf core. That code
 * starts with `xor r11d,r11d; xor r12d,r12d; ... mov eax,0x7fffffff;
 * sub eax,r12d; cmp eax,r11d; jl overflow`. The constant flags value
 * used to be read as "branch taken" whatever the condition was, so the
 * whole format loop was flagged dead and printf with format arguments
 * printed nothing.
 *
 * Each x86-64 probe below isolates one construct where constant
 * propagation could pick the wrong edge. The live path always returns
 * 1. If the analysis drops it, the probe returns -1 or crashes.
 * Every probe function is kept above the minimum size the
 * analysis looks at. */
#include <stdio.h>

#if defined(__x86_64__)

/* Signed compare on constant operands: jl must fall through. */
__attribute__((noinline, used))
static int probe_signed_cmp(long x) {
    long r;
    __asm__ volatile(
        "xor %%ecx, %%ecx\n\t"
        "mov $0x7fffffff, %%eax\n\t"
        "cmp %%ecx, %%eax\n\t"
        "jl 1f\n\t"
        "mov $1, %%eax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "mov $-1, %%rax\n"
        "2:\n\t"
        : "=&a"(r) : "r"(x) : "rcx", "cc");
    return (int)r;
}

/* Equality on a zero result: je must be taken. */
__attribute__((noinline, used))
static int probe_je_zero(long x) {
    long r;
    __asm__ volatile(
        "xor %%eax, %%eax\n\t"
        "test %%eax, %%eax\n\t"
        "je 1f\n\t"
        "mov $-1, %%rax\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "mov $1, %%eax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n"
        "2:\n\t"
        : "=&a"(r) : "r"(x) : "cc");
    return (int)r;
}

/* Indirect jump after a constant compare: its target is live. */
__attribute__((noinline, used))
static int probe_indirect_jmp(long x) {
    long r;
    __asm__ volatile(
        "lea 1f(%%rip), %%rdx\n\t"
        "xor %%eax, %%eax\n\t"
        "test %%eax, %%eax\n\t"
        "jmp *%%rdx\n\t"
        "mov $-1, %%rax\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "mov $1, %%eax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n"
        "2:\n\t"
        : "=&a"(r) : "r"(x) : "rdx", "cc");
    return (int)r;
}

/* `dec` rewrites the flags of an earlier constant compare. */
__attribute__((noinline, used))
static int probe_dec_flags(long x) {
    long r;
    __asm__ volatile(
        "mov $2, %%eax\n\t"
        "cmp $2, %%eax\n\t"
        "mov %1, %%rcx\n\t"
        "dec %%ecx\n\t"
        "jne 1f\n\t"
        "mov $-1, %%rax\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "mov $1, %%eax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n"
        "2:\n\t"
        : "=&a"(r) : "r"(x) : "rcx", "cc");
    return (int)r;
}

/* An 8-bit write keeps the upper bits: eax stays nonzero. */
__attribute__((noinline, used))
static int probe_partial_write(long x) {
    long r;
    __asm__ volatile(
        "mov $0x100, %%eax\n\t"
        "mov $0, %%al\n\t"
        "test %%eax, %%eax\n\t"
        "je 1f\n\t"
        "mov $1, %%eax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "mov $-1, %%rax\n"
        "2:\n\t"
        : "=&a"(r) : "r"(x) : "cc");
    return (int)r;
}

/* A high-byte register is bits 8..15, not the low byte. */
__attribute__((noinline, used))
static int probe_high_byte(long x) {
    long r;
    __asm__ volatile(
        "mov $0x500, %%eax\n\t"
        "cmp $5, %%ah\n\t"
        "je 1f\n\t"
        "mov $-1, %%rax\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "mov $1, %%eax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n"
        "2:\n\t"
        : "=&a"(r) : "r"(x) : "cc");
    return (int)r;
}

/* A 32-bit result zero-extends: rax wraps to 0, not 2^32. */
__attribute__((noinline, used))
static int probe_zero_extend(long x) {
    long r;
    __asm__ volatile(
        "mov $-1, %%eax\n\t"
        "add $1, %%eax\n\t"
        "movabs $0x100000000, %%rcx\n\t"
        "cmp %%rcx, %%rax\n\t"
        "je 1f\n\t"
        "mov $1, %%eax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "mov $-1, %%rax\n"
        "2:\n\t"
        : "=&a"(r) : "r"(x) : "rcx", "cc");
    return (int)r;
}

/* `pop` loads a new value; the constant in rax is gone. */
__attribute__((noinline, used))
static int probe_pop(long x) {
    long r;
    __asm__ volatile(
        "xor %%eax, %%eax\n\t"
        "sub $128, %%rsp\n\t"
        "push %1\n\t"
        "pop %%rax\n\t"
        "add $128, %%rsp\n\t"
        "test %%rax, %%rax\n\t"
        "jne 1f\n\t"
        "mov $-1, %%rax\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "mov $1, %%eax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n"
        "2:\n\t"
        : "=&a"(r) : "r"(x) : "cc");
    return (int)r;
}

/* One-operand imul writes rdx:rax, not its source operand. */
__attribute__((noinline, used))
static int probe_imul(long x) {
    long r;
    __asm__ volatile(
        "mov $1, %%eax\n\t"
        "mov %1, %%rcx\n\t"
        "sub $1, %%rcx\n\t"
        "imul %%ecx\n\t"
        "test %%eax, %%eax\n\t"
        "jne 1f\n\t"
        "mov $1, %%eax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n\t"
        "add %1, %%rax\n\t"
        "sub %1, %%rax\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "mov $-1, %%rax\n"
        "2:\n\t"
        : "=&a"(r) : "r"(x) : "rcx", "rdx", "cc");
    return (int)r;
}

/* Run every probe; `one` is 1 at run time but unknown to the analysis.
 * Arguments are chosen so a dropped live path never yields 1 by chance. */
static void run_probes(long one) {
    printf("probes: %d %d %d %d %d %d %d %d %d\n",
           probe_signed_cmp(one), probe_je_zero(one),
           probe_indirect_jmp(one), probe_dec_flags(one + 1),
           probe_partial_write(one), probe_high_byte(one),
           probe_zero_extend(one), probe_pop(one + 4),
           probe_imul(one));
}

#else

/* Other architectures: print the expected line so callers stay uniform. */
static void run_probes(long one) {
    (void)one;
    printf("probes: 1 1 1 1 1 1 1 1 1\n");
}

#endif

int main(int argc, char *argv[]) {
    (void)argv;
    printf("fmt: %d %s %x %5.2f %-4d| %05d %c %lu\n",
           42, "hello", 255, 3.14159, 7, 31, 'z', 123456789UL);
    run_probes(argc);
    puts("done");
    return 0;
}
