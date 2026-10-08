#!/usr/bin/env python3
"""Craft an ELF whose named sections start past the end of the file.

A truncated or crafted file can name a code section whose sh_offset
lies beyond EOF while the headers still parse. trim decodes .init,
.fini, .plt* and NativeAOT code sections besides .text: none of them
may make it index outside the file. The section header table stays
where it is; only each named section's sh_offset changes, to the file
size plus 0x10000. Handles 32- and 64-bit little-endian ELF.
Usage: elf_past_eof.py IN OUT SECTION [SECTION...]
"""
import struct
import sys


def layout(data):
    """(shoff, shentsize, shnum, shstrndx, offset field, offset format)."""
    if data[:4] != b'\x7fELF' or data[5] != 1:
        sys.exit('not a little-endian ELF')
    if data[4] == 2:
        shoff, = struct.unpack_from('<Q', data, 40)
        shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 58)
        return shoff, shentsize, shnum, shstrndx, 24, '<Q'
    shoff, = struct.unpack_from('<I', data, 32)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 46)
    return shoff, shentsize, shnum, shstrndx, 16, '<I'


def section_names(data, shoff, shentsize, shnum, shstrndx, off_at, fmt):
    """Map section name -> file offset of its section header entry."""
    at = shoff + shstrndx * shentsize
    str_off, = struct.unpack_from(fmt, data, at + off_at)
    names = {}
    for i in range(shnum):
        hdr = shoff + i * shentsize
        name, = struct.unpack_from('<I', data, hdr)
        end = data.index(b'\0', str_off + name)
        names[data[str_off + name:end].decode()] = hdr
    return names


def main(src, dst, wanted):
    """Write `src` to `dst` with each `wanted` section moved past EOF."""
    data = bytearray(open(src, 'rb').read())
    shoff, entsize, shnum, strndx, off_at, fmt = layout(data)
    names = section_names(data, shoff, entsize, shnum, strndx, off_at, fmt)
    past = len(data) + 0x10000
    for name in wanted:
        if name not in names:
            sys.exit('no section %s' % name)
        struct.pack_into(fmt, data, names[name] + off_at, past)
    open(dst, 'wb').write(data)
    print('%s: %s now at %#x (file is %#x bytes)'
          % (dst, ' '.join(wanted), past, len(data)))


if __name__ == '__main__':
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2], sys.argv[3:])
