#!/usr/bin/env python3
"""Check that a trimmed x86-64 PE or Mach-O keeps a switch jump table.

Finds the dispatch `cmp $BOUND; ja; ...; lea T(%rip),%b; movslq
(%b,%i,4),%e` whose bound is COUNT - 1 (exactly one per file) in the
original and in the trimmed file, reads the COUNT relative entries of
each table through the file's own section headers, and requires every
trimmed entry to reach the same code as the original one: the first
SIG bytes at both case targets must match (so the case code must not
start with a PC-relative operand, whose bytes legitimately change).
Prints one line per entry and a summary; exits 1 on any mismatch.
Usage: jumptable_targets.py ORIG TRIMMED COUNT
"""
import re
import struct
import subprocess
import sys

SIG = 4
LEA = re.compile(r'^\s*([0-9a-f]+):\s+leaq\s+-?0x[0-9a-f]+\(%rip\),'
                 r'\s+%(\w+)\s+#+\s*0x([0-9a-f]+)')
MOVSLQ = re.compile(r'movslq\s+\(%(\w+),%\w+,4\),')
CMP = re.compile(r'cmp[lq]\s+\$0x([0-9a-f]+),')


def pe_sections(data):
    """(va, size, offset) of each PE section, va including ImageBase."""
    pe, = struct.unpack_from('<I', data, 0x3C)
    nsec, = struct.unpack_from('<H', data, pe + 6)
    optsz, = struct.unpack_from('<H', data, pe + 20)
    image_base, = struct.unpack_from('<Q', data, pe + 24 + 24)
    out = []
    for i in range(nsec):
        at = pe + 24 + optsz + i * 40
        vsize, rva, rsize, roff = struct.unpack_from('<IIII', data, at + 8)
        out.append((image_base + rva, min(vsize, rsize), roff))
    return out


def macho_sections(data):
    """(addr, size, offset) of each section of a 64-bit Mach-O."""
    ncmds, = struct.unpack_from('<I', data, 16)
    at, out = 32, []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, at)
        if cmd == 0x19:
            nsects, = struct.unpack_from('<I', data, at + 64)
            for k in range(nsects):
                s = at + 72 + k * 80
                addr, ssize, off = struct.unpack_from('<QQI', data, s + 32)
                out.append((addr, ssize, off))
        at += size
    return out


def file_offset(sections, va, width):
    """File offset of `width` bytes at `va`, or None if not file-backed."""
    for base, size, off in sections:
        if base <= va and va + width <= base + size:
            return off + va - base
    return None


def table_base(path, count):
    """Vaddr of the one table whose dispatch bound is `count` - 1."""
    asm = subprocess.run(
        ['llvm-objdump', '-d', '--no-show-raw-insn', path],
        capture_output=True, text=True, check=True).stdout.splitlines()
    bases = set()
    for k, line in enumerate(asm):
        m = LEA.match(line)
        if not m:
            continue
        near = asm[max(0, k - 4):k]
        bound = [int(c.group(1), 16) for c in map(CMP.search, near) if c]
        uses = [MOVSLQ.search(x) for x in asm[k + 1:k + 4]]
        if count - 1 in bound and any(u and u.group(1) == m.group(2)
                                      for u in uses):
            bases.add(int(m.group(3), 16))
    if len(bases) != 1:
        sys.exit(f'{path}: {len(bases)} dispatches with bound {count - 1}')
    return bases.pop()


def load(path, count):
    """(data, sections, table vaddr, entries) of `path`."""
    data = open(path, 'rb').read()
    secs = pe_sections(data) if data[:2] == b'MZ' else macho_sections(data)
    base = table_base(path, count)
    off = file_offset(secs, base, 4 * count)
    if off is None:
        sys.exit(f'{path}: table at {base:#x} is not file-backed')
    entries = struct.unpack_from(f'<{count}i', data, off)
    return data, secs, base, entries


def code_at(data, secs, va):
    """The SIG bytes of code at `va`, or None."""
    off = file_offset(secs, va, SIG)
    return None if off is None else data[off:off + SIG]


def main(orig, trimmed, count):
    """Compare each case target of the two tables; exit 1 on mismatch."""
    a, a_secs, a_base, a_ent = load(orig, count)
    b, b_secs, b_base, b_ent = load(trimmed, count)
    print(f'table {a_base:#x} -> {b_base:#x}')
    bad = changed = 0
    for i, (ea, eb) in enumerate(zip(a_ent, b_ent)):
        ok = code_at(a, a_secs, a_base + ea) == code_at(b, b_secs, b_base + eb)
        bad += not ok
        changed += ea != eb
        print(f'  [{i:2}] {ea:#x} -> {eb:#x}: target '
              f'{a_base + ea:#x} -> {b_base + eb:#x} '
              f'{"same code" if ok else "WRONG CODE"}')
    print(f'{count - bad}/{count} entries reach their case code '
          f'({changed} rewritten)')
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]))
