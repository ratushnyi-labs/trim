#!/usr/bin/env python3
"""Rewrite one .dynamic entry of a 64-bit little-endian ELF.

Crafts inputs `trim --relr` must refuse:
  retag OLD NEW  change the first entry tagged OLD to tag NEW
                 (e.g. 7 17: DT_RELA becomes DT_REL);
  grow TAG BY    add the value of the first BY entry to the first TAG
                 entry (e.g. 8 2: DT_RELASZ += DT_PLTRELSZ, so the PLT
                 relocations lie inside the DT_RELA table).
A trailing `noshdr` also drops the section header table from the ELF
header (e_shoff, e_shnum, e_shstrndx = 0), as sstrip leaves a binary,
so no section header can contradict the new tags.
Usage: elf_dyn_tag.py IN OUT (retag|grow) A B [noshdr]
"""
import struct
import sys

PT_DYNAMIC = 2


def dynamic_entries(data):
    """File offsets of the .dynamic entries before DT_NULL."""
    phoff, = struct.unpack_from('<Q', data, 32)
    phnum, = struct.unpack_from('<H', data, 56)
    for i in range(phnum):
        p_type, _, p_off, _, _, p_filesz = struct.unpack_from(
            '<IIQQQQ', data, phoff + i * 56)
        if p_type != PT_DYNAMIC:
            continue
        at = []
        for e in range(p_off, p_off + p_filesz, 16):
            tag, = struct.unpack_from('<Q', data, e)
            if tag == 0:
                break
            at.append(e)
        return at
    sys.exit('no PT_DYNAMIC')


def first(data, entries, tag):
    """Offset of the first entry tagged `tag`."""
    for e in entries:
        if struct.unpack_from('<Q', data, e)[0] == tag:
            return e
    sys.exit('no dynamic tag %d' % tag)


def main(src, dst, mode, a, b, noshdr):
    """Apply `mode` with tags `a` and `b` to `src`, writing `dst`."""
    data = bytearray(open(src, 'rb').read())
    if noshdr:
        struct.pack_into('<Q', data, 40, 0)
        struct.pack_into('<HH', data, 60, 0, 0)
    entries = dynamic_entries(data)
    at = first(data, entries, a)
    if mode == 'retag':
        struct.pack_into('<Q', data, at, b)
    elif mode == 'grow':
        by, = struct.unpack_from('<Q', data, first(data, entries, b) + 8)
        val, = struct.unpack_from('<Q', data, at + 8)
        struct.pack_into('<Q', data, at + 8, val + by)
    else:
        sys.exit(__doc__)
    open(dst, 'wb').write(data)


if __name__ == '__main__':
    if len(sys.argv) not in (6, 7) or sys.argv[6:] not in ([], ['noshdr']):
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2], sys.argv[3],
         int(sys.argv[4], 0), int(sys.argv[5], 0), len(sys.argv) == 7)
