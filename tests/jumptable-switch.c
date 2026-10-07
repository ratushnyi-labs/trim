/* Regression fixture for x86-64 switch jump-table base detection.
 *
 * Built at -O2: the dense `switch` compiles to a base-relative jump
 * table (`movsxd (%base,%idx,4); add %base; jmp`). Because the switch
 * sits in a loop, the compiler hoists the table-base `lea reg,[rip+T]`
 * out of the loop, so it lands far more than 6 instructions before the
 * `movsxd` that uses it. The old detector only scanned the 6 preceding
 * instructions and took the first RIP-relative operand, so it missed or
 * mislocated the base and left the table stale.
 *
 * Over 4K of uncalled (but `used`, so emitted) dead code precedes the
 * dispatcher, forcing both a per-interval and a page-aligned shift. The
 * switch targets in .text therefore move relative to the table base in
 * .rodata, so every live entry must be re-patched; a stale table sends
 * the indirect jump into the wrong code and corrupts the result. */
#include <stdio.h>

#define DEAD(name, c1, c2, c3) \
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

/* Live dispatcher: a loop around a dense switch -> hoisted table base. */
__attribute__((noinline, used))
static int dispatch_sum(int n, int seed) {
    int acc = seed;
    for (int i = 0; i < n; i++) {
        switch (i % 12) {
        case 0:  acc += 3;            break;
        case 1:  acc ^= 7;            break;
        case 2:  acc += acc << 1;     break;
        case 3:  acc -= 5;            break;
        case 4:  acc *= 3;            break;
        case 5:  acc += 11;           break;
        case 6:  acc ^= 0x2a;         break;
        case 7:  acc -= 2;            break;
        case 8:  acc += 17;           break;
        case 9:  acc ^= 9;            break;
        case 10: acc += 4;            break;
        case 11: acc -= 1;            break;
        }
    }
    return acc;
}

int main(void) {
    volatile int n = 500;
    volatile int seed = 1;
    printf("result: %d\n", dispatch_sum(n, seed));
    return 0;
}
