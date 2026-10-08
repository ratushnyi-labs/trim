/* Calls the .dynsym-only exports of tests/dynsym-exports.c the way a
 * dynamic linker binds them: through st_value. musl does not bind IFUNC
 * symbols, so the loader reads .dynsym from the library file, finds the
 * load base through dlsym on the untyped export, then calls the IFUNC
 * resolver and the implementation it returns. */
#include <dlfcn.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Read the whole file `path`; its length goes to `*len`. */
static unsigned char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    unsigned char *buf = n > 0 ? malloc((size_t)n) : NULL;
    if (buf && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    *len = n > 0 ? (size_t)n : 0;
    return buf;
}

/* Copy the .dynsym entry named `want` of ELF image `buf` to `*out`. */
static int find_dynsym(const unsigned char *buf, size_t len,
                       const char *want, Elf64_Sym *out) {
    const Elf64_Ehdr *eh = (const void *)buf;
    if (len < sizeof *eh ||
        eh->e_shoff + (size_t)eh->e_shnum * sizeof(Elf64_Shdr) > len)
        return 0;
    const Elf64_Shdr *sh = (const void *)(buf + eh->e_shoff);
    for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type != SHT_DYNSYM || sh[i].sh_link >= eh->e_shnum)
            continue;
        const Elf64_Sym *sym = (const void *)(buf + sh[i].sh_offset);
        const char *str = (const char *)(buf + sh[sh[i].sh_link].sh_offset);
        for (size_t k = 0; k < sh[i].sh_size / sizeof *sym; k++) {
            if (strcmp(str + sym[k].st_name, want) == 0) {
                *out = sym[k];
                return 1;
            }
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    size_t len = 0;
    unsigned char *buf = argc > 1 ? slurp(argv[1], &len) : NULL;
    void *h = buf ? dlopen(argv[1], RTLD_NOW) : NULL;
    if (!h) {
        printf("load failed: %s\n", buf ? dlerror() : "read");
        return 1;
    }
    Elf64_Sym fi, fn;
    if (!find_dynsym(buf, len, "dyn_ifunc", &fi) ||
        !find_dynsym(buf, len, "dyn_notype", &fn)) {
        printf("symbols missing\n");
        return 1;
    }
    printf("types: ifunc=%d notype=%d\n", ELF64_ST_TYPE(fi.st_info),
           ELF64_ST_TYPE(fn.st_info));
    int (*notype)(int) = (int (*)(int))dlsym(h, "dyn_notype");
    char *base = (char *)notype - fn.st_value;
    void *(*resolver)(void) = (void *(*)(void))(base + fi.st_value);
    int (*impl)(int) = (int (*)(int))resolver();
    printf("dynsym: ifunc=%d notype=%d\n", impl(5), notype(1));
    return 0;
}
