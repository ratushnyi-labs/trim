/* Test binary mimicking the .NET NativeAOT ELF layout: managed code lives
 * in executable sections `__managedcode` and `__unbox` (after .text) and
 * calls helpers in .text that nothing in .text references. Dead code
 * (>4K) placed before the helpers forces both per-interval and
 * page-aligned shifts, so branches from the managed sections into .text
 * must be treated as references AND re-patched after compaction. */
#include <stdio.h>

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

/* Runtime helpers in .text: referenced ONLY from the managed sections. */
static __attribute__((noinline)) int rt_helper(int x) { return x * 5; }
static __attribute__((noinline)) int rt_unbox(int x) { return x + 7; }

/* "Managed" code in NativeAOT's executable sections. */
__attribute__((section("__managedcode"), noinline, used))
int managed_entry(int x) { return rt_helper(x) + 1; }

__attribute__((section("__unbox"), noinline, used))
int unbox_stub(int x) { return rt_unbox(x); }

#ifdef WITH_MODULES
/* Variant with NativeAOT's `__modules` section, so trim detects a
 * NativeAOT image and zero-fills dead code in place. It holds a 32-bit
 * self-relative pointer from after .text to the ELF header (before
 * .text), like the ReadyToRun pointers trim cannot patch: it stays
 * valid only if nothing after .text moves. */
__asm__(".section __modules,\"aw\"\n"
        ".balign 8\n"
        "modules_rel: .long __ehdr_start - .\n"
        ".long 0\n"
        ".previous\n");
extern const int modules_rel;
extern const char __ehdr_start[];

/* Follow the self-relative pointer and check it still hits its target. */
static int modules_ok(void) {
    const char *target = (const char *)&modules_rel + modules_rel;
    return target == __ehdr_start;
}
#endif

int main(void) {
#ifdef WITH_MODULES
    printf("modules: %s\n", modules_ok() ? "ok" : "stale");
#endif
    printf("result: %d\n", managed_entry(4) + unbox_stub(3));
    return 0;
}
