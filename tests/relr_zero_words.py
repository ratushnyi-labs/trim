#!/usr/bin/env python3
"""Zero the in-place words of R_X86_64_RELATIVE relocations to data.

RELA relocations carry explicit addends, so the loader never reads the
in-place word and the binary still runs (as lld leaves it by default).
RELR uses the in-place word as the addend: `trim --relr` must write the
addends back. Only words whose addend points into a non-executable
segment are zeroed: trim's dead-code analysis finds code pointers in
data by their in-place value. Usage: relr_zero_words.py FILE (in place).
"""
import struct
import sys

R_X86_64_RELATIVE = 8
SHT_RELA = 4
PT_LOAD = 1
PF_X = 1


def segment_of(phdrs, vaddr, in_memory=False):
    """The (offset, vaddr, flags) of the PT_LOAD holding `vaddr`'s word
    in its file-backed part (or anywhere in memory with `in_memory`)."""
    for p_type, p_flags, p_off, p_vaddr, p_filesz, p_memsz in phdrs:
        size = p_memsz if in_memory else p_filesz
        if p_type == PT_LOAD and p_vaddr <= vaddr < p_vaddr + size - 7:
            return p_off, p_vaddr, p_flags
    return None


def read_phdrs(data):
    """(type, flags, offset, vaddr, filesz, memsz) of each program header."""
    phoff, = struct.unpack_from('<Q', data, 32)
    phnum, = struct.unpack_from('<H', data, 56)
    out = []
    for i in range(phnum):
        fields = struct.unpack_from('<IIQQQQQ', data, phoff + i * 56)
        out.append(fields[:4] + fields[5:7])
    return out


def main(path):
    """Zero the data-pointing RELATIVE words of the ELF64 LE file `path`."""
    data = bytearray(open(path, 'rb').read())
    phdrs = read_phdrs(data)
    shoff, = struct.unpack_from('<Q', data, 40)
    shnum, = struct.unpack_from('<H', data, 60)
    zeroed = 0
    for i in range(shnum):
        sh_type, = struct.unpack_from('<I', data, shoff + i * 64 + 4)
        sh_off, sh_size = struct.unpack_from('<QQ', data, shoff + i * 64 + 24)
        if sh_type != SHT_RELA:
            continue
        for at in range(sh_off, sh_off + sh_size, 24):
            r_off, r_info, addend = struct.unpack_from('<QQq', data, at)
            where = segment_of(phdrs, r_off)
            target = segment_of(phdrs, addend, in_memory=True)
            if r_info != R_X86_64_RELATIVE or r_off % 8 or not where:
                continue
            if target is None or target[2] & PF_X:
                continue
            struct.pack_into('<Q', data, where[0] + r_off - where[1], 0)
            zeroed += 1
    open(path, 'wb').write(data)
    print('zeroed %d RELATIVE words' % zeroed)


if __name__ == '__main__':
    main(sys.argv[1])
