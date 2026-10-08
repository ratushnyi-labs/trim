/* Test binary with a minimal .NET NativeAOT ReadyToRun header. __modules
 * points at an "RTR" header (version 16.0) whose section table names a
 * module initializer list (section 213) and an ExternalReferences table
 * (section 308). Each is an array of 32-bit self-relative pointers
 * (RELPTR32: target = location + value) to a static function nothing else
 * references. main() walks the header like the NativeAOT runtime and
 * calls through every RELPTR32, so both functions must stay live;
 * r2r_unused is referenced by nothing and stays dead.
 * -DR2R_MAJOR=N writes another header version, which trim must refuse
 * (every function then stays live). */
#include <stdio.h>

#ifndef R2R_MAJOR
#define R2R_MAJOR 16
#endif

#define STR2(x) #x
#define STR(x) STR2(x)

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
