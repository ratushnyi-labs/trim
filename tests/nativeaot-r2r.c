/* Test binary with a minimal .NET NativeAOT ReadyToRun header. __modules
 * points at an "RTR" header (version 16.0) whose section table names a
 * module initializer list (section 213) and an ExternalReferences table
 * (section 308). Each is an array of 32-bit self-relative pointers
 * (RELPTR32: target = location + value) to a static function nothing else
 * references. main() walks the header like the NativeAOT runtime and
 * calls through every RELPTR32, so both functions must stay live;
 * r2r_unused is referenced by nothing and stays dead.
 * Over 4 KB of dead code lies before both functions, so compacting .text
 * moves them by other amounts than the page-aligned drain moves the data
 * holding the RELPTR32s: those must be re-pointed for main() to reach
 * them.
 * -DR2R_MAJOR=N writes another header version, which trim must refuse
 * (every function then stays live). */
#include <stdio.h>

#ifndef R2R_MAJOR
#define R2R_MAJOR 16
#endif

#define STR2(x) #x
#define STR(x) STR2(x)

/* Dead code: referenced by nothing. */
#define DEAD(name, c1, c2, c3) \
static __attribute__((noinline, used)) int name(int a, int b) { \
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

DEAD(r2r_dead_01, 7, 13, 31)
DEAD(r2r_dead_02, 11, 17, 37)
DEAD(r2r_dead_03, 3, 19, 41)
DEAD(r2r_dead_04, 23, 29, 43)
DEAD(r2r_dead_05, 5, 31, 47)
DEAD(r2r_dead_06, 37, 41, 53)
DEAD(r2r_dead_07, 43, 47, 59)
DEAD(r2r_dead_08, 53, 59, 61)
DEAD(r2r_dead_09, 67, 71, 73)
DEAD(r2r_dead_10, 79, 83, 89)
DEAD(r2r_dead_11, 97, 101, 103)
DEAD(r2r_dead_12, 107, 109, 113)
DEAD(r2r_dead_13, 127, 131, 137)
DEAD(r2r_dead_14, 139, 149, 151)
DEAD(r2r_dead_15, 157, 163, 167)
DEAD(r2r_dead_16, 173, 179, 181)
DEAD(r2r_dead_17, 191, 193, 197)
DEAD(r2r_dead_18, 199, 211, 223)
DEAD(r2r_dead_19, 227, 229, 233)
DEAD(r2r_dead_20, 239, 241, 251)
DEAD(r2r_dead_21, 257, 263, 269)
DEAD(r2r_dead_22, 271, 277, 281)
DEAD(r2r_dead_23, 283, 293, 307)
DEAD(r2r_dead_24, 311, 313, 317)
DEAD(r2r_dead_25, 331, 337, 347)
DEAD(r2r_dead_26, 349, 353, 359)
DEAD(r2r_dead_27, 367, 373, 379)
DEAD(r2r_dead_28, 383, 389, 397)
DEAD(r2r_dead_29, 401, 409, 419)
DEAD(r2r_dead_30, 421, 431, 433)
DEAD(r2r_dead_31, 439, 443, 449)
DEAD(r2r_dead_32, 457, 461, 463)

/* Reached only through the ReadyToRun RELPTR32 arrays. */
static __attribute__((noinline, used)) int r2r_module_init(int x) {
    return x * 3 + 1;
}

static __attribute__((noinline, used)) int r2r_external_ref(int x) {
    return x * 7 - 2;
}

/* Referenced by nothing. */
static __attribute__((noinline, used)) int r2r_unused(int x) {
    return x ^ 0x5a5a;
}

/* NativeAOT managed code section: with __modules, a NativeAOT image. */
__attribute__((section("__managedcode"), noinline, used))
int managed_entry(int x) { return x + 1; }

__asm__(".section .data.r2r,\"aw\"\n"
        ".balign 8\n"
        "r2r_header:\n"
        ".long 0x00525452\n"                 /* signature "RTR" */
        ".short " STR(R2R_MAJOR) ", 0\n"     /* major, minor version */
        ".long 0\n"                          /* flags */
        ".short 2\n"                         /* section count */
        ".byte 24, 1\n"                      /* row size, row type */
        ".long 213, 1\n"                     /* module initializers */
        ".quad r2r_inits, r2r_inits_end\n"
        ".long 308, 1\n"                     /* ExternalReferences */
        ".quad r2r_ext, r2r_ext_end\n"
        "r2r_inits: .long r2r_module_init - .\n"
        "r2r_inits_end:\n"
        "r2r_ext: .long r2r_external_ref - .\n"
        "r2r_ext_end:\n"
        ".section __modules,\"aw\"\n"
        ".balign 8\n"
        "r2r_modules: .quad r2r_header\n"
        ".previous\n");

/* ModuleInfoRow: section id, flags, start, end. */
struct r2r_row {
    int id;
    int flags;
    const int *start;
    const int *end;
};

/* ReadyToRunHeader followed by its section table. */
struct r2r_header {
    unsigned sig;
    unsigned short major, minor;
    unsigned flags;
    unsigned short count;
    unsigned char row_size, row_type;
    struct r2r_row rows[];
};

extern const struct r2r_header *const r2r_modules[];

/* Follow a RELPTR32 like the runtime: target = location + value. */
static int (*relptr_fn(const int *p))(int) {
    return (int (*)(int))((const char *)p + *p);
}

int main(void) {
    const struct r2r_header *h = r2r_modules[0];
    int sum = 0;
    for (int i = 0; i < h->count; i++) {
        const struct r2r_row *r = &h->rows[i];
        for (const int *p = r->start; p < r->end; p++)
            sum += relptr_fn(p)(5);
    }
    printf("r2r: %d\n", sum + managed_entry(1));
    return 0;
}
