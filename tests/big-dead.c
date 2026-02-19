/* Test binary with large dead code (>4K) to verify physical
 * file size reduction via page-aligned shrinking. */
#include <stdio.h>

/* Live code: called from main */
static int live_add(int a, int b) { return a + b; }
static int live_mul(int a, int b) { return a * b; }

int main(void) {
    printf("result: %d\n", live_add(2, 3) + live_mul(4, 5));
    return 0;
}

/* Macro to generate dead functions with distinct code.
 * Each function ~150-250 bytes at -O0 -fno-inline.
 * 30 functions x ~200 bytes = ~6000 bytes > 4096 (1 page). */
#define DEAD(name, c1, c2, c3) \
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
    return r; \
}

DEAD(dead_f01, 7, 13, 31)
DEAD(dead_f02, 11, 17, 37)
DEAD(dead_f03, 3, 19, 41)
DEAD(dead_f04, 23, 29, 43)
DEAD(dead_f05, 5, 31, 47)
DEAD(dead_f06, 37, 41, 53)
DEAD(dead_f07, 43, 47, 59)
DEAD(dead_f08, 53, 59, 61)
DEAD(dead_f09, 67, 71, 73)
DEAD(dead_f10, 79, 83, 89)
DEAD(dead_f11, 97, 101, 103)
DEAD(dead_f12, 107, 109, 113)
DEAD(dead_f13, 127, 131, 137)
DEAD(dead_f14, 139, 149, 151)
DEAD(dead_f15, 157, 163, 167)
DEAD(dead_f16, 173, 179, 181)
DEAD(dead_f17, 191, 193, 197)
DEAD(dead_f18, 199, 211, 223)
DEAD(dead_f19, 227, 229, 233)
DEAD(dead_f20, 239, 241, 251)
DEAD(dead_f21, 257, 263, 269)
DEAD(dead_f22, 271, 277, 281)
DEAD(dead_f23, 283, 293, 307)
DEAD(dead_f24, 311, 313, 317)
DEAD(dead_f25, 331, 337, 347)
DEAD(dead_f26, 349, 353, 359)
DEAD(dead_f27, 367, 373, 379)
DEAD(dead_f28, 383, 389, 397)
DEAD(dead_f29, 401, 409, 419)
DEAD(dead_f30, 421, 431, 433)
