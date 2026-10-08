/* Regression fixture for sound AArch64 dead-branch folding (no libc).
 * Build: clang --target=aarch64-linux-gnu -march=armv8.1-a -nostdlib
 *        -static -fno-pie -O2 -fuse-ld=lld; run under qemu-aarch64.
 *
 * Each `probe_*` sets a register or NZCV to a constant, overwrites it
 * with one instruction the constant model must not ignore, then
 * branches on the result. The taken edge is the live path and returns
 * 1. If the analysis keeps the stale constant, it folds the branch as
 * never taken, the live block is removed, and the probe returns -2.
 * The operands are runtime values (`one`, memory) so after the fix
 * none of these branches folds at all.
 *
 * Each `probe_dead_*` branches on a value that really is constant, so
 * its other path is provably dead and must still be removed.
 * Every probe is kept above the 32-byte minimum the analysis looks at. */

/* 64 KiB aligned below 4 GiB, so one MOVZ gives its exact address. */
long g_slots[4] __attribute__((aligned(65536)));
long g_word = 1;
long g_pair[2] = { 1, 1 };
volatile long g_one = 1;

/* Probe tail whose taken edge is live: start at -2, fall through to
 * -1, take the branch to 1. */
#define LIVE_IF_TAKEN(br) \
    br " 1f\n\t"          \
    "mov %0, #-1\n\t"     \
    "b 2f\n"              \
    "1:\n\t"              \
    "mov %0, #1\n"        \
    "2:\n\t"

/* Probe tail whose fall-through is live. */
#define LIVE_IF_NOT_TAKEN(br) \
    br " 1f\n\t"              \
    "mov %0, #1\n\t"          \
    "b 2f\n"                  \
    "1:\n\t"                  \
    "mov %0, #-1\n"           \
    "2:\n\t"

/* Return 1; called from probes to check that calls clobber x0. */
__attribute__((noinline, used))
long ret_one(void) {
    __asm__ volatile("" ::: "memory");
    return 1;
}

/* A load overwrites a constant. */
__attribute__((noinline, used))
static int probe_ldr(const long *p) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x9, #0\n\t"
        "ldr x9, [%1]\n\t"
        "cmp x9, #0\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(p) : "x9", "cc", "memory");
    return (int)r;
}

/* A pair load also writes its second register. */
__attribute__((noinline, used))
static int probe_ldp(const long *p) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x10, #0\n\t"
        "ldp x9, x10, [%1]\n\t"
        "cmp x10, #0\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(p) : "x9", "x10", "cc", "memory");
    return (int)r;
}

/* A post-index load writes back its base register. */
__attribute__((noinline, used))
static int probe_post_index(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "movz x10, #:abs_g1:g_slots\n\t"
        "ldr x9, [x10], #8\n\t"
        "movz x11, #:abs_g1:g_slots\n\t"
        "cmp x10, x11\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : : "x9", "x10", "x11", "cc", "memory");
    return (int)r;
}

/* A pre-index store writes back its base register. */
__attribute__((noinline, used))
static int probe_pre_index(long one) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "movz x10, #:abs_g1:g_slots\n\t"
        "add x10, x10, #16\n\t"
        "str %1, [x10, #-8]!\n\t"
        "movz x11, #:abs_g1:g_slots\n\t"
        "add x11, x11, #16\n\t"
        "cmp x10, x11\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(one) : "x10", "x11", "cc", "memory");
    return (int)r;
}

/* A store-exclusive writes its status register (0 or 1). */
__attribute__((noinline, used))
static int probe_stxr(long *p) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov w9, #5\n\t"
        "ldxr x10, [%1]\n\t"
        "stxr w9, x10, [%1]\n\t"
        "cmp w9, #5\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(p) : "x9", "x10", "cc", "memory");
    return (int)r;
}

/* An atomic add returns the old memory value in its Rt. */
__attribute__((noinline, used))
static int probe_ldadd(long *p) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x9, #0\n\t"
        "mov x10, #0\n\t"
        "ldadd x10, x9, [%1]\n\t"
        "cmp x9, #0\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(p) : "x9", "x10", "cc", "memory");
    return (int)r;
}

/* A failing compare-and-swap loads the memory value into Rs. */
__attribute__((noinline, used))
static int probe_cas(long *p) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x9, #0\n\t"
        "mov x10, #7\n\t"
        "cas x9, x10, [%1]\n\t"
        "cmp x9, #0\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(p) : "x9", "x10", "cc", "memory");
    return (int)r;
}

/* A shifted register operand: 1 + (1 << 1) is 3, not 2. */
__attribute__((noinline, used))
static int probe_shifted(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x10, #1\n\t"
        "mov x11, #1\n\t"
        "add x9, x10, x11, lsl #1\n\t"
        "cmp x9, #2\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : : "x9", "x10", "x11", "cc");
    return (int)r;
}

/* An extended register operand: uxtb(0x101) << 1 is 2, not 0x101. */
__attribute__((noinline, used))
static int probe_extended(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x10, #0\n\t"
        "mov x11, #0x101\n\t"
        "add x9, x10, w11, uxtb #1\n\t"
        "cmp x9, #0x101\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : : "x9", "x10", "x11", "cc");
    return (int)r;
}

/* TST with a bitmask immediate rewrites NZCV. */
__attribute__((noinline, used))
static int probe_tst_imm(long one) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x10, #0\n\t"
        "cmp x10, #0\n\t"
        "tst %1, #1\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(one) : "x10", "cc");
    return (int)r;
}

/* CCMP rewrites NZCV when its condition holds. */
__attribute__((noinline, used))
static int probe_ccmp(long one) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x10, #0\n\t"
        "cmp x10, #0\n\t"
        "ccmp %1, #0, #0, eq\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(one) : "x10", "cc");
    return (int)r;
}

/* FCMP rewrites NZCV. */
__attribute__((noinline, used))
static int probe_fcmp(long one) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x10, #0\n\t"
        "cmp x10, #0\n\t"
        "scvtf d0, %1\n\t"
        "fcmp d0, #0.0\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(one) : "x10", "v0", "cc");
    return (int)r;
}

/* ADCS rewrites NZCV (and its destination). */
__attribute__((noinline, used))
static int probe_adcs(long one) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x10, #0\n\t"
        "cmp x10, #0\n\t"
        "adcs x11, %1, xzr\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(one) : "x10", "x11", "cc");
    return (int)r;
}

/* MSR NZCV rewrites the flags directly. */
__attribute__((noinline, used))
static int probe_msr(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x10, #0\n\t"
        "cmp x10, #0\n\t"
        "msr nzcv, xzr\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : : "x10", "cc");
    return (int)r;
}

/* CSET (CSINC) overwrites a constant. */
__attribute__((noinline, used))
static int probe_cset(long one) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x9, #0\n\t"
        "cmp %1, #1\n\t"
        "cset x9, eq\n\t"
        "cmp x9, #0\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(one) : "x9", "cc");
    return (int)r;
}

/* A W-register write zero-extends: w9 = -1 is 0xffffffff, not -1. */
__attribute__((noinline, used))
static int probe_wzext(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov w9, #-1\n\t"
        "mov x10, #-1\n\t"
        "cmp x9, x10\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : : "x9", "x10", "cc");
    return (int)r;
}

/* ORR with a bitmask immediate overwrites a constant. */
__attribute__((noinline, used))
static int probe_orr_imm(long one) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x9, #0\n\t"
        "orr x9, %1, #0x5555555555555555\n\t"
        "cmp x9, #0\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(one) : "x9", "cc");
    return (int)r;
}

/* A bitfield move (LSL immediate) overwrites a constant. */
__attribute__((noinline, used))
static int probe_bitfield(long one) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x9, #0\n\t"
        "lsl x9, %1, #4\n\t"
        "cmp x9, #0\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(one) : "x9", "cc");
    return (int)r;
}

/* A multiply (MADD) overwrites a constant. */
__attribute__((noinline, used))
static int probe_mul(long one) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x9, #0\n\t"
        "mul x9, %1, %1\n\t"
        "cmp x9, #0\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(one) : "x9", "cc");
    return (int)r;
}

/* FMOV from a SIMD&FP register overwrites a constant. */
__attribute__((noinline, used))
static int probe_fmov(long one) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x9, #0\n\t"
        "scvtf d0, %1\n\t"
        "fmov x9, d0\n\t"
        "cmp x9, #0\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(one) : "x9", "v0", "cc");
    return (int)r;
}

/* UMOV from a vector lane overwrites a constant. */
__attribute__((noinline, used))
static int probe_umov(long one) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x9, #0\n\t"
        "dup v0.2d, %1\n\t"
        "umov x9, v0.d[1]\n\t"
        "cmp x9, #0\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(one) : "x9", "v0", "cc");
    return (int)r;
}

/* MRS overwrites a constant (NZCV after an equal compare is nonzero). */
__attribute__((noinline, used))
static int probe_mrs(long one) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x9, #0\n\t"
        "cmp %1, #1\n\t"
        "mrs x9, nzcv\n\t"
        "cmp x9, #0\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(one) : "x9", "cc");
    return (int)r;
}

/* MRS of RNDR (s3_3_c2_c4_0) writes x9 and NZCV: Z is clear when a
 * random number was returned, so the EQ left by the compare before it
 * must not decide the branch. */
__attribute__((noinline, used))
static int probe_mrs_rndr(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x10, #0\n\t"
        "cmp x10, #0\n\t"
        "mrs x9, s3_3_c2_c4_0\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : : "x9", "x10", "cc");
    return (int)r;
}

/* ADRP overwrites a constant with a page address. */
__attribute__((noinline, used))
static int probe_adrp(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x9, #0\n\t"
        "adrp x9, g_word\n\t"
        "cmp x9, #0\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : : "x9", "cc");
    return (int)r;
}

/* SVC returns its result in x0 (getpid is nonzero). */
__attribute__((noinline, used))
static int probe_svc(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x0, #0\n\t"
        "mov x8, #172\n\t"
        "svc #0\n\t"
        "cmp x0, #0\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : : "x0", "x8", "cc", "memory");
    return (int)r;
}

/* Registers a call may change (AAPCS64 caller-saved plus x30). */
#define CALL_CLOBBERS                                                 \
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",       \
    "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x30",    \
    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v16", "v17",     \
    "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26",    \
    "v27", "v28", "v29", "v30", "v31", "cc", "memory"

/* A direct call returns a new value in x0. */
__attribute__((noinline, used))
static int probe_bl(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x0, #0\n\t"
        "bl ret_one\n\t"
        "cmp x0, #0\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : : CALL_CLOBBERS);
    return (int)r;
}

/* An indirect call returns a new value in x0. */
__attribute__((noinline, used))
static int probe_blr(long (*fn)(void)) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x0, #0\n\t"
        "blr %1\n\t"
        "cmp x0, #0\n\t"
        LIVE_IF_TAKEN("b.ne")
        : "=&r"(r) : "r"(fn) : CALL_CLOBBERS);
    return (int)r;
}

/* Provably dead: 5 == 5, so B.EQ is always taken. */
__attribute__((noinline, used))
static int probe_dead_beq(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x9, #5\n\t"
        "cmp x9, #5\n\t"
        LIVE_IF_TAKEN("b.eq")
        : "=&r"(r) : : "x9", "cc");
    return (int)r;
}

/* Provably dead: CBNZ on zero is never taken. */
__attribute__((noinline, used))
static int probe_dead_cbnz(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x9, #0\n\t"
        "add x9, x9, #0\n\t"
        LIVE_IF_NOT_TAKEN("cbnz x9,")
        : "=&r"(r) : : "x9", "cc");
    return (int)r;
}

/* Provably dead: w9 of 2^32 is zero, so CBZ W is always taken. */
__attribute__((noinline, used))
static int probe_dead_cbz_w(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "movz x9, #1, lsl #32\n\t"
        "add x9, x9, #0\n\t"
        LIVE_IF_TAKEN("cbz w9,")
        : "=&r"(r) : : "x9", "cc");
    return (int)r;
}

/* Provably dead: bit 32 of 2^32 is set, so TBNZ is always taken. */
__attribute__((noinline, used))
static int probe_dead_tbnz(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "movz x9, #1, lsl #32\n\t"
        "add x9, x9, #0\n\t"
        LIVE_IF_TAKEN("tbnz x9, #32,")
        : "=&r"(r) : : "x9", "cc");
    return (int)r;
}

/* Provably dead: a 32-bit add wraps 0xffffffff + 1 to 0 and the write
 * zero-extends, so CBZ X is always taken. */
__attribute__((noinline, used))
static int probe_dead_wrap(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov w9, #-1\n\t"
        "add w9, w9, #1\n\t"
        LIVE_IF_TAKEN("cbz x9,")
        : "=&r"(r) : : "x9", "cc");
    return (int)r;
}

/* Provably dead: the bitmask immediate 0x8000000180000001 (MOV, i.e.
 * ORR from XZR; a 32-bit element replicated) has bit 32 set, so TBNZ
 * is always taken. */
__attribute__((noinline, used))
static int probe_dead_bitmask(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x9, #0x8000000180000001\n\t"
        "add x9, x9, #0\n\t"
        LIVE_IF_TAKEN("tbnz x9, #32,")
        : "=&r"(r) : : "x9", "cc");
    return (int)r;
}

/* Provably dead: MOVK keeps the other fields, so 1 with 0x8000 put in
 * bits 63:48 equals the bitmask immediate 0x8000000000000001. */
__attribute__((noinline, used))
static int probe_dead_movk(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x9, #1\n\t"
        "movk x9, #0x8000, lsl #48\n\t"
        "mov x10, #0x8000000000000001\n\t"
        "cmp x9, x10\n\t"
        LIVE_IF_TAKEN("b.eq")
        : "=&r"(r) : : "x9", "x10", "cc");
    return (int)r;
}

/* Provably dead: CMN adds, so -5 + 5 sets Z and B.EQ is always taken. */
__attribute__((noinline, used))
static int probe_dead_cmn(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "mov x9, #-5\n\t"
        "cmn x9, #5\n\t"
        LIVE_IF_TAKEN("b.eq")
        : "=&r"(r) : : "x9", "cc");
    return (int)r;
}

/* Provably dead: ANDS on W registers tests only the low 32 bits of
 * 2^32 against 0x80000000 (not sign-extended), so Z is set and B.EQ is
 * always taken. */
__attribute__((noinline, used))
static int probe_dead_ands_w(void) {
    long r;
    __asm__ volatile(
        "mov %0, #-2\n\t"
        "movz x10, #1, lsl #32\n\t"
        "ands w9, w10, #0x80000000\n\t"
        LIVE_IF_TAKEN("b.eq")
        : "=&r"(r) : : "x9", "x10", "cc");
    return (int)r;
}

/* Write a buffer to stdout. */
static void put(const char *s, long n) {
    register long x0 __asm__("x0") = 1;
    register const char *x1 __asm__("x1") = s;
    register long x2 __asm__("x2") = n;
    register long x8 __asm__("x8") = 64;
    __asm__ volatile("svc #0"
                     : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
}

/* Print " 1" for a probe that returned 1, " F" for anything else. */
__attribute__((noinline))
static void put_result(int r) {
    put(r == 1 ? " 1" : " F", 2);
}

/* Run every probe; `one` is 1 at run time but unknown to the analysis. */
void _start(void) {
    long one = g_one;
    put("probes:", 7);
    put_result(probe_ldr(&g_word));
    put_result(probe_ldp(g_pair));
    put_result(probe_post_index());
    put_result(probe_pre_index(one));
    put_result(probe_stxr(&g_word));
    put_result(probe_ldadd(&g_word));
    put_result(probe_cas(&g_word));
    put_result(probe_shifted());
    put_result(probe_extended());
    put_result(probe_tst_imm(one));
    put_result(probe_ccmp(one));
    put_result(probe_fcmp(one));
    put_result(probe_adcs(one));
    put_result(probe_msr());
    put_result(probe_cset(one));
    put_result(probe_wzext());
    put_result(probe_orr_imm(one));
    put_result(probe_bitfield(one));
    put_result(probe_mul(one));
    put_result(probe_fmov(one));
    put_result(probe_umov(one));
    put_result(probe_mrs(one));
    put_result(probe_mrs_rndr());
    put_result(probe_adrp());
    put_result(probe_svc());
    put_result(probe_bl());
    put_result(probe_blr(ret_one));
    put("\ndead:", 6);
    put_result(probe_dead_beq());
    put_result(probe_dead_cbnz());
    put_result(probe_dead_cbz_w());
    put_result(probe_dead_tbnz());
    put_result(probe_dead_wrap());
    put_result(probe_dead_bitmask());
    put_result(probe_dead_movk());
    put_result(probe_dead_cmn());
    put_result(probe_dead_ands_w());
    put("\n", 1);
    __asm__ volatile("mov x0, #0\n\tmov x8, #93\n\tsvc #0" ::: "memory");
    __builtin_unreachable();
}
