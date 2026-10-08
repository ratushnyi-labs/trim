/* FDE function boundaries in a stripped x86-64 binary (gcc -O2).
 *
 * dead_fde_* are never called. Kept by `used` and emitted with FDEs,
 * they sit between live functions, and a stripped image has no symbol,
 * call target or pointer marking their start: inference alone merges
 * each into the live function before it. With .eh_frame FDEs as
 * function boundaries they must be found dead and removed. Each holds a
 * marker constant (0x5EAD100n) the test looks for in the file.
 *
 * The probe_* paths must stay live. Each isolates one way code is
 * entered that splitting at FDE boundaries could miss:
 *   ft    fall-through from one FDE into the next (no call or jump);
 *   gap   code past an FDE's end, entered by falling through;
 *   jt    a relative jump table whose cases are other FDEs;
 *   tail  a function entered only by a sibling-call jmp;
 *   fp    functions reached only through a pointer table in data;
 *   sort  a callback whose address is passed to qsort.
 */
#include <stdio.h>
#include <stdlib.h>

#define NOIPA __attribute__((noipa))
#define HIDDEN __attribute__((visibility("hidden")))

#define DEAD(name, k) \
    __attribute__((used, noipa)) static unsigned name(unsigned x) { \
        unsigned r = x; \
        for (unsigned i = 0; i < x; i++) \
            r = r * (k) + (r >> 7); \
        return r ^ (k); \
    }

NOIPA static int live_a(int x) { return x * 2 + 1; }
DEAD(dead_fde_1, 0x5EAD1001u)
NOIPA static int live_b(int x) { return x * x + 4; }
DEAD(dead_fde_2, 0x5EAD1002u)
DEAD(dead_fde_3, 0x5EAD1003u)
NOIPA static int live_c(int x) { return (x << 3) - 1; }

/* Entered only by the jmp of a sibling call from probe_tail. */
NOIPA static int probe_tail_target(int x) { return x * 7 + 3; }
NOIPA static int probe_tail(int x) { return probe_tail_target(x ^ 5); }
DEAD(dead_fde_4, 0x5EAD1004u)

/* Reached only through fp_table (data). */
NOIPA static int probe_fp_a(int x) { return x + 11; }
NOIPA static int probe_fp_b(int x) { return x + 13; }
static int (*const fp_table[])(int) = { probe_fp_a, probe_fp_b };

NOIPA static int probe_cmp(const void *a, const void *b) {
    return *(const int *)a - *(const int *)b;
}

HIDDEN int probe_ft_head(int x);
HIDDEN int probe_gap(int x);
HIDDEN int probe_jt(int i);

/* probe_ft_head: its FDE ends after one instruction and execution falls
 * into probe_ft_tail, a separate FDE nothing calls: (x + 1) * 3.
 * probe_gap: .cfi_endproc comes before its last instructions, which no
 * FDE covers: (x + 2) * 5.
 * probe_jt: dispatches through a relative table to jt_case0/jt_case1,
 * separate FDEs referenced only by the table: 70 + (i & 1). */
__asm__(
    ".text\n"
    ".p2align 4\n"
    ".globl probe_ft_head\n"
    ".hidden probe_ft_head\n"
    "probe_ft_head:\n"
    "    .cfi_startproc\n"
    "    leal 1(%rdi), %eax\n"
    "    .cfi_endproc\n"
    "probe_ft_tail:\n"
    "    .cfi_startproc\n"
    "    imull $3, %eax, %eax\n"
    "    ret\n"
    "    .cfi_endproc\n"
    ".p2align 4\n"
    ".globl probe_gap\n"
    ".hidden probe_gap\n"
    "probe_gap:\n"
    "    .cfi_startproc\n"
    "    leal 2(%rdi), %eax\n"
    "    .cfi_endproc\n"
    "    imull $5, %eax, %eax\n"
    "    ret\n"
    ".p2align 4\n"
    ".globl probe_jt\n"
    ".hidden probe_jt\n"
    "probe_jt:\n"
    "    .cfi_startproc\n"
    "    andl $1, %edi\n"
    "    leaq jt_table(%rip), %rcx\n"
    "    movslq (%rcx,%rdi,4), %rax\n"
    "    addq %rcx, %rax\n"
    "    jmp *%rax\n"
    "    .cfi_endproc\n"
    ".p2align 4\n"
    "jt_case0:\n"
    "    .cfi_startproc\n"
    "    movl $70, %eax\n"
    "    ret\n"
    "    .cfi_endproc\n"
    ".p2align 4\n"
    "jt_case1:\n"
    "    .cfi_startproc\n"
    "    movl $71, %eax\n"
    "    ret\n"
    "    .cfi_endproc\n"
    ".section .rodata\n"
    ".p2align 2\n"
    "jt_table:\n"
    "    .long jt_case0 - jt_table\n"
    "    .long jt_case1 - jt_table\n"
    ".text\n");

int main(int argc, char **argv) {
    (void)argv;
    int v[5] = { 5, 3, 9, 1, 7 };
    qsort(v, 5, sizeof v[0], probe_cmp);
    printf("live: %d %d %d\n", live_a(argc), live_b(argc), live_c(argc));
    printf("probes: ft=%d gap=%d jt=%d,%d tail=%d fp=%d sort=%d%d%d%d%d\n",
           probe_ft_head(argc), probe_gap(argc), probe_jt(0), probe_jt(1),
           probe_tail(argc), fp_table[argc & 1](argc),
           v[0], v[1], v[2], v[3], v[4]);
    return 0;
}
