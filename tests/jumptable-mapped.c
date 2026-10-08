/* Regression fixture: x86-64 switch jump tables outside PIE ELF.
 *
 * trim read and rewrote relative jump-table entries at the table's
 * virtual address taken as a file offset. That holds only where vaddr
 * equals file offset (PIE ELF). A PE table sits at an RVA in .rdata
 * whose raw data lies elsewhere in the file; a Mach-O table sits at a
 * vmaddr above 4 GiB, past the end of the file. Such tables were
 * skipped, or the bytes at the wrong offset were rewritten.
 *
 * Built without libc (Mach-O links with -nostdlib, no SDK needed) and
 * stripped, so trim infers functions from call targets. The dead_*
 * functions call each other in pairs nothing live enters: each is a
 * call target, so each is inferred as a function, and the pairs are
 * dead. They precede the dispatcher with about 3 KB of code, under one
 * page, so no section after the code moves. In PE the table stays in
 * .rdata while the case targets move down, so every entry must change.
 * In Mach-O the table follows `dispatch` in __text and moves with its
 * targets, so every entry must stay as it is.
 *
 * `dispatch` is bounded (cases 0..11 plus default), so the dispatcher
 * compares the index with 11 and the table has exactly 12 entries. */

#define DEAD(name, next, c1, c2, c3) \
__attribute__((noinline, used)) \
static int name(int a, int b) { \
    int r = a * c1 + b; \
    r = r * c2 - a * c3; \
    r = (r ^ (r >> 3)) + c1 * b; \
    r = r * a - b * c2 + c3; \
    r = (r ^ (r >> 5)) + c1 * c2; \
    r = r + a * c3 - b * c1; \
    r = (r ^ (r >> 7)) * c2 + c3; \
    r = r * b - a * c3 + c1; \
    r = (r ^ (r >> 2)) + a * b; \
    r = r + b * c2 - a * c1 + c3; \
    if (r & 1) \
        r = r * 3 + next(b, r); \
    return r; \
}

/* Two dead functions that call each other. */
#define DEAD_PAIR(f, g, c1, c2, c3) \
static int g(int, int); \
DEAD(f, g, c1, c2, c3) \
DEAD(g, f, c2, c3, c1)

DEAD_PAIR(dead_f01, dead_f02, 7, 13, 31)
DEAD_PAIR(dead_f03, dead_f04, 3, 19, 41)
DEAD_PAIR(dead_f05, dead_f06, 5, 31, 47)
DEAD_PAIR(dead_f07, dead_f08, 43, 47, 59)
DEAD_PAIR(dead_f09, dead_f10, 67, 71, 73)
DEAD_PAIR(dead_f11, dead_f12, 97, 101, 103)
DEAD_PAIR(dead_f13, dead_f14, 127, 131, 137)
DEAD_PAIR(dead_f15, dead_f16, 157, 163, 167)

/* Live dispatcher: a dense, bounded switch -> base-relative jump table. */
__attribute__((noinline, used))
static int dispatch(int op, int acc) {
    switch (op) {
    case 0:  return acc + 3;
    case 1:  return acc ^ 7;
    case 2:  return acc + (acc << 1);
    case 3:  return acc - 5;
    case 4:  return acc * 3;
    case 5:  return acc + 11;
    case 6:  return acc ^ 0x2a;
    case 7:  return acc * 5 + 1;
    case 8:  return acc + 17;
    case 9:  return acc ^ 9;
    case 10: return acc * 7 - 3;
    case 11: return acc - 1;
    default: return acc;
    }
}

/* The exit status depends on every case: 37 when the table is intact. */
int main(void) {
    volatile int seed = 1;
    int acc = seed;
    for (int i = 0; i < 26; i++)
        acc = dispatch(i % 13, acc);
    return acc & 0x7f;
}
