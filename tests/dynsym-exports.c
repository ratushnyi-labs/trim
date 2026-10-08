/* Shared library whose exports are reachable only through .dynsym:
 * dyn_ifunc is an IFUNC (STT_GNU_IFUNC) whose value is its resolver, and
 * dyn_notype is an untyped (STT_NOTYPE) assembly label in .text. Nothing
 * in the library calls them or takes their address, so once stripped
 * only their .dynsym st_value names them; a dynamic linker calls them
 * through it. The dead functions before them make trim compact .text and
 * move them. */

#define DEAD(name, c1, c2) \
static __attribute__((noinline, used)) int name(int a, int b) { \
    int r = a * c1 + b; \
    r = (r ^ (r >> 3)) * c2 - a; \
    r = (r ^ (r >> 5)) + c1 * b; \
    return r * a - b * c2; \
}

DEAD(dyn_dead_1, 7, 13)
DEAD(dyn_dead_2, 11, 17)
DEAD(dyn_dead_3, 19, 23)
DEAD(dyn_dead_4, 29, 31)

/* The implementation the IFUNC resolver selects. */
static __attribute__((noinline, used)) int ifunc_impl(int x) {
    return x * 3 + 1;
}

/* IFUNC resolver: returns the implementation to bind. */
static __attribute__((noinline, used)) void *ifunc_resolver(void) {
    return (void *)ifunc_impl;
}

__asm__(".globl dyn_ifunc\n"
        ".type dyn_ifunc, @gnu_indirect_function\n"
        ".set dyn_ifunc, ifunc_resolver\n"
        ".text\n"
        ".globl dyn_notype\n"
        "dyn_notype:\n"
        "    lea 41(%rdi), %eax\n"
        "    ret\n"
        ".previous\n");
