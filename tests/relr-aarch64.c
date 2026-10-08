/* RELR fixture: AArch64 static-pie without libc, under qemu-aarch64.
 * Build: clang --target=aarch64-linux-gnu -fPIE -static-pie -nostdlib
 *        -O1 -fuse-ld=lld
 *
 * A static-pie relocates itself: its start code applies DT_RELA and,
 * when that code knows it, DT_RELR (musl 1.2.4+, glibc 2.36+). This
 * start code applies both, so `trim --relr-static` may pack it and the
 * packed image must print exactly what the original prints. Without
 * --relr-static trim must refuse it: trim cannot tell which libc start
 * code a static-pie carries.
 *
 * Dense and sparse pointer tables need R_AARCH64_RELATIVE relocations;
 * each pointer is compared with an address formed PC-relatively. Before
 * `relocate` returns, nothing may read a pointer from memory: every
 * object is static or hidden, so its address is PC-relative. */

typedef unsigned long u64;

#define N 256
#define DT_NULL 0
#define DT_RELA 7
#define DT_RELASZ 8
#define DT_RELRSZ 35
#define DT_RELR 36
#define PT_DYNAMIC 2
#define R_AARCH64_RELATIVE 1027

static int vals[N];

#define R1(m, i) m(i)
#define R2(m, i) R1(m, i) R1(m, i + 1)
#define R4(m, i) R2(m, i) R2(m, i + 2)
#define R8(m, i) R4(m, i) R4(m, i + 4)
#define R16(m, i) R8(m, i) R8(m, i + 8)
#define R32(m, i) R16(m, i) R16(m, i + 16)
#define R64(m, i) R32(m, i) R32(m, i + 32)
#define R128(m, i) R64(m, i) R64(m, i + 64)
#define R256(m, i) R128(m, i) R128(m, i + 128)
#define PTR(i) &vals[i],

/* RELRO table (dense: bitmap words) and writable sparse pointers (more
 * than 63 words apart: address words). */
static int *const ptrs[N] = { R256(PTR, 0) };
struct sparse { int *p; long pad[71]; };
static struct sparse sparse[4] = {
    { &vals[0] }, { &vals[3] }, { &vals[6] }, { &vals[9] },
};

/* The ELF header and .dynamic, located PC-relatively by the linker. */
extern const char __ehdr_start[] __attribute__((visibility("hidden")));
extern u64 _DYNAMIC[] __attribute__((visibility("hidden")));

/* Load bias: where .dynamic is minus where PT_DYNAMIC says it is. */
static u64 load_bias(void) {
    const char *eh = __ehdr_start;
    u64 phoff = *(const u64 *)(eh + 32);
    unsigned short phnum = *(const unsigned short *)(eh + 56);
    for (unsigned i = 0; i < phnum; i++) {
        const unsigned *ph = (const unsigned *)(eh + phoff + 56 * i);
        if (ph[0] == PT_DYNAMIC)
            return (u64)_DYNAMIC - *(const u64 *)(ph + 4);
    }
    return 0;
}

/* Apply the RELATIVE relocations of DT_RELA. */
static void apply_rela(u64 bias, const u64 *r, u64 size) {
    for (const u64 *end = r + size / 8; r < end; r += 3)
        if ((r[1] & 0xffffffff) == R_AARCH64_RELATIVE)
            *(u64 *)(bias + r[0]) = bias + r[2];
}

/* Apply DT_RELR: an even word relocates the word it names, an odd one
 * is a bitmap over the 63 words after the last covered one. */
static void apply_relr(u64 bias, const u64 *r, u64 size) {
    u64 *where = 0;
    for (const u64 *end = r + size / 8; r < end; r++) {
        u64 e = *r;
        if ((e & 1) == 0) {
            where = (u64 *)(bias + e);
            *where++ += bias;
            continue;
        }
        u64 *w = where;
        for (e >>= 1; e; e >>= 1, w++)
            if (e & 1)
                *w += bias;
        where += 63;
    }
}

/* Apply this image's own relocations, as a static libc's start code. */
__attribute__((noinline)) static void relocate(void) {
    u64 bias = load_bias();
    u64 rela = 0, relasz = 0, relr = 0, relrsz = 0;
    for (const u64 *d = _DYNAMIC; d[0] != DT_NULL; d += 2) {
        if (d[0] == DT_RELA)
            rela = d[1];
        else if (d[0] == DT_RELASZ)
            relasz = d[1];
        else if (d[0] == DT_RELR)
            relr = d[1];
        else if (d[0] == DT_RELRSZ)
            relrsz = d[1];
    }
    if (rela)
        apply_rela(bias, (const u64 *)(bias + rela), relasz);
    if (relr)
        apply_relr(bias, (const u64 *)(bias + relr), relrsz);
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

/* Print `label`, then "<ok>/<total> ok" and a newline. */
__attribute__((noinline)) static void put_count(const char *label, long n,
                                                int ok, int total) {
    char buf[24];
    int len = 0;
    for (int v = ok, k = 1000; k; k /= 10)
        if (v >= k || k == 1 || len)
            buf[len++] = (char)('0' + v / k % 10);
    buf[len++] = '/';
    for (int v = total, k = 1000; k; k /= 10)
        if (v >= k || k == 1 || buf[len - 1] != '/')
            buf[len++] = (char)('0' + v / k % 10);
    put(label, n);
    put(buf, len);
    put(" ok\n", 4);
}

/* Relocate, check every pointer against its PC-relative address. */
void _start(void) {
    relocate();
    int ok_p = 0, ok_s = 0;
    for (int i = 0; i < N; i++)
        ok_p += ptrs[i] == &vals[i];
    for (int i = 0; i < 4; i++)
        ok_s += sparse[i].p == &vals[3 * i];
    put_count("ptrs: ", 6, ok_p, N);
    put_count("sparse: ", 8, ok_s, 4);
    if (ok_p == N && ok_s == 4)
        put("relr-a64: ok\n", 13);
    else
        put("relr-a64: FAIL\n", 15);
    __asm__ volatile("mov x0, #0\n\tmov x8, #93\n\tsvc #0" ::: "memory");
    __builtin_unreachable();
}
