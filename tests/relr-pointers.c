/* RELR fixture: thousands of RELATIVE relocations with a self-check.
 *
 * Built as a PIE (static or dynamic), every pointer below is a
 * R_*_RELATIVE dynamic relocation: dense runs (bitmap words), sparse
 * pointers more than 63 words apart (new address words), RELRO tables
 * (.data.rel.ro) and writable ones (.data). Each pointer is compared
 * with an address computed at run time (PC-relative, no relocation),
 * so a pointer left unrelocated or relocated twice is caught.
 *
 * -DWITH_UNALIGNED adds a pointer at an odd offset, which RELR cannot
 * encode: it must stay a RELA relocation.
 */
#include <stdio.h>

#define N 2048

static int vals[N];
static char text[N + 1];

/* Odd entries add one, even entries double. */
static int inc(int x) { return x + 1; }
static int dbl(int x) { return x * 2; }

#define R1(m, i) m(i)
#define R2(m, i) R1(m, i) R1(m, i + 1)
#define R4(m, i) R2(m, i) R2(m, i + 2)
#define R8(m, i) R4(m, i) R4(m, i + 4)
#define R16(m, i) R8(m, i) R8(m, i + 8)
#define R32(m, i) R16(m, i) R16(m, i + 16)
#define R64(m, i) R32(m, i) R32(m, i + 32)
#define R128(m, i) R64(m, i) R64(m, i + 64)
#define R256(m, i) R128(m, i) R128(m, i + 128)
#define R512(m, i) R256(m, i) R256(m, i + 256)
#define R1024(m, i) R512(m, i) R512(m, i + 512)
#define R2048(m, i) R1024(m, i) R1024(m, i + 1024)

#define PTR(i) &vals[i],
#define STR(i) &text[i],
#define FN(i) ((i) & 1) ? inc : dbl,

/* RELRO: const pointer tables land in .data.rel.ro. */
static int *const ptrs[N] = { R2048(PTR, 0) };
static int (*const fns[64])(int) = { R64(FN, 0) };

/* Writable: .data. */
static const char *strs[N] = { R2048(STR, 0) };

/* One pointer every 72 words: too far apart for one bitmap word. */
struct sparse { int *p; long pad[71]; };
static struct sparse sparse[8] = {
    { &vals[0] }, { &vals[3] }, { &vals[6] }, { &vals[9] },
    { &vals[12] }, { &vals[15] }, { &vals[18] }, { &vals[21] },
};

#ifdef WITH_UNALIGNED
struct __attribute__((packed)) odd { char c; int *p; };
static struct odd odd = { 'x', &vals[7] };
#endif

/* Count entries of `tab` that differ from `base + i`. */
static __attribute__((noinline)) int
check_ints(int *const *tab, int *base, int n)
{
    int bad = 0;
    for (int i = 0; i < n; i++)
        bad += tab[i] != base + i;
    return bad;
}

/* Count entries of `tab` that differ from `base + i`. */
static __attribute__((noinline)) int
check_chars(const char **tab, const char *base, int n)
{
    int bad = 0;
    for (int i = 0; i < n; i++)
        bad += tab[i] != base + i;
    return bad;
}

/* Count function table entries that compute the wrong value. */
static __attribute__((noinline)) int check_fns(void)
{
    int bad = 0;
    for (int i = 0; i < 64; i++)
        bad += fns[i](i) != ((i & 1) ? i + 1 : i * 2);
    return bad;
}

/* Count sparse pointers that differ from `vals + 3 * i`. */
static __attribute__((noinline)) int check_sparse(void)
{
    int bad = 0;
    for (int i = 0; i < 8; i++)
        bad += sparse[i].p != vals + 3 * i;
    return bad;
}

int main(void)
{
    int bad_p = check_ints(ptrs, vals, N);
    int bad_s = check_chars(strs, text, N);
    int bad_f = check_fns();
    int bad_x = check_sparse();
    int bad = bad_p + bad_s + bad_f + bad_x;
    printf("ptrs: %d/%d ok\n", N - bad_p, N);
    printf("strs: %d/%d ok\n", N - bad_s, N);
    printf("fns: %d/64 ok\n", 64 - bad_f);
    printf("sparse: %d/8 ok\n", 8 - bad_x);
#ifdef WITH_UNALIGNED
    int bad_o = odd.p != vals + 7;
    printf("unaligned: %s\n", bad_o ? "BAD" : "ok");
    bad += bad_o;
#endif
    printf("relr-fixture: %s\n", bad ? "FAIL" : "ok");
    return bad != 0;
}
