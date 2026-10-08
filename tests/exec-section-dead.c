/* Unstripped binary with dead functions OUTSIDE .text: a block of dead
 * code in the executable section `__managedcode` (no `__modules`, so trim
 * compacts instead of zero-filling a NativeAOT image) and one dead
 * function in the custom executable section `trimcode`. Together they
 * outweigh the dead code in .text by more than a page, so if they fed
 * the .text drain math the page-aligned drain would exceed the bytes
 * freed in .text: the old "slice index starts at X but ends at Y" panic.
 * They must be zero-filled in place while .text (>4K dead) is compacted,
 * and the live branch from `__managedcode` into .text re-patched.
 *
 * With -DWITH_MODULES the image has NativeAOT's `__modules` section, so
 * trim zero-fills in place and must treat every managed function as
 * live: `managed_hidden` is reached only through a 32-bit self-relative
 * pointer, the way NativeAOT reaches managed methods through dehydrated
 * MethodTables, which trim cannot see. */
#include <stdio.h>

#define BODY(c1, c2, c3) \
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
    return r;

/* Dead function in .text. */
#define DEAD(name, c1, c2, c3) \
static int name(int a, int b) { BODY(c1, c2, c3) }

/* Dead function in executable section `sec`; `used` keeps the compiler
 * from dropping it, `static` keeps it local (not an exported root). */
#define DEAD_IN(sec, name, c1, c2, c3) \
__attribute__((section(sec), used, noinline)) \
static int name(int a, int b) { BODY(c1, c2, c3) }

#define M(name, c1, c2, c3) DEAD_IN("__managedcode", name, c1, c2, c3)

DEAD(dead_t01, 7, 13, 31)
DEAD(dead_t02, 11, 17, 37)
DEAD(dead_t03, 3, 19, 41)
DEAD(dead_t04, 23, 29, 43)
DEAD(dead_t05, 5, 31, 47)
DEAD(dead_t06, 37, 41, 53)
DEAD(dead_t07, 43, 47, 59)
DEAD(dead_t08, 53, 59, 61)
DEAD(dead_t09, 67, 71, 73)
DEAD(dead_t10, 79, 83, 89)
DEAD(dead_t11, 97, 101, 103)
DEAD(dead_t12, 107, 109, 113)
DEAD(dead_t13, 127, 131, 137)
DEAD(dead_t14, 139, 149, 151)
DEAD(dead_t15, 157, 163, 167)
DEAD(dead_t16, 173, 179, 181)
DEAD(dead_t17, 191, 193, 197)
DEAD(dead_t18, 199, 211, 223)
DEAD(dead_t19, 227, 229, 233)
DEAD(dead_t20, 239, 241, 251)
DEAD(dead_t21, 257, 263, 269)
DEAD(dead_t22, 271, 277, 281)
DEAD(dead_t23, 283, 293, 307)
DEAD(dead_t24, 311, 313, 317)
DEAD(dead_t25, 331, 337, 347)
DEAD(dead_t26, 349, 353, 359)
DEAD(dead_t27, 367, 373, 379)
DEAD(dead_t28, 383, 389, 397)
DEAD(dead_t29, 401, 409, 419)
DEAD(dead_t30, 421, 431, 433)

/* Runtime helper in .text: referenced ONLY from the managed section. */
static __attribute__((noinline)) int rt_helper(int x) { return x * 5; }

/* Live "managed" code calling into .text. */
__attribute__((section("__managedcode"), noinline, used))
int managed_entry(int x) { return rt_helper(x) + 1; }

M(dead_m01, 7, 13, 31)
M(dead_m02, 11, 17, 37)
M(dead_m03, 3, 19, 41)
M(dead_m04, 23, 29, 43)
M(dead_m05, 5, 31, 47)
M(dead_m06, 37, 41, 53)
M(dead_m07, 43, 47, 59)
M(dead_m08, 53, 59, 61)
M(dead_m09, 67, 71, 73)
M(dead_m10, 79, 83, 89)
M(dead_m11, 97, 101, 103)
M(dead_m12, 107, 109, 113)
M(dead_m13, 127, 131, 137)
M(dead_m14, 139, 149, 151)
M(dead_m15, 157, 163, 167)
M(dead_m16, 173, 179, 181)
M(dead_m17, 191, 193, 197)
M(dead_m18, 199, 211, 223)
M(dead_m19, 227, 229, 233)
M(dead_m20, 239, 241, 251)
M(dead_m21, 257, 263, 269)
M(dead_m22, 271, 277, 281)
M(dead_m23, 283, 293, 307)
M(dead_m24, 311, 313, 317)
M(dead_m25, 331, 337, 347)
M(dead_m26, 349, 353, 359)
M(dead_m27, 367, 373, 379)
M(dead_m28, 383, 389, 397)
M(dead_m29, 401, 409, 419)
M(dead_m30, 421, 431, 433)
M(dead_m31, 439, 443, 449)
M(dead_m32, 457, 461, 463)
M(dead_m33, 467, 479, 487)
M(dead_m34, 491, 499, 503)
M(dead_m35, 509, 521, 523)
M(dead_m36, 541, 547, 557)
M(dead_m37, 563, 569, 571)
M(dead_m38, 577, 587, 593)
M(dead_m39, 599, 601, 607)
M(dead_m40, 613, 617, 619)
M(dead_m41, 631, 641, 643)
M(dead_m42, 647, 653, 659)
M(dead_m43, 661, 673, 677)
M(dead_m44, 683, 691, 701)
M(dead_m45, 709, 719, 727)
M(dead_m46, 733, 739, 743)
M(dead_m47, 751, 757, 761)
M(dead_m48, 769, 773, 787)
M(dead_m49, 797, 809, 811)
M(dead_m50, 821, 823, 827)
M(dead_m51, 829, 839, 853)
M(dead_m52, 857, 859, 863)
M(dead_m53, 877, 881, 883)
M(dead_m54, 887, 907, 911)
M(dead_m55, 919, 929, 937)
M(dead_m56, 941, 947, 953)
M(dead_m57, 967, 971, 977)
M(dead_m58, 983, 991, 997)
M(dead_m59, 1009, 1013, 1019)
M(dead_m60, 1021, 1031, 1033)

/* Dead function in a custom executable section with any other name. */
DEAD_IN("trimcode", dead_c01, 1039, 1049, 1051)

#ifdef WITH_MODULES
/* Helper in .text called only from the hidden managed function. */
static __attribute__((noinline)) int rt_hidden(int x) { return x + 100; }

/* Managed function no instruction or absolute pointer refers to. */
__attribute__((section("__managedcode"), noinline, used))
static int managed_hidden(int x) { return rt_hidden(x) * 2; }

__asm__(".section __modules,\"aw\"\n"
        ".balign 8\n"
        "hidden_rel: .long managed_hidden - .\n"
        ".long 0\n"
        ".previous\n");
extern const int hidden_rel;

/* Call `managed_hidden` through its self-relative pointer. */
static int call_hidden(int x) {
    const char *p = (const char *)&hidden_rel + hidden_rel;
    return ((int (*)(int))p)(x);
}
#endif

int main(void) {
    printf("result: %d\n", managed_entry(4));
#ifdef WITH_MODULES
    printf("hidden: %d\n", call_hidden(3));
#endif
    return 0;
}
