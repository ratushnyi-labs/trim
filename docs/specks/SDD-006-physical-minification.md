# SDD-006 — Physical Binary Minification with Address Recalculation

**Impacted UCs:** UC-001, UC-002
**Impacted BR/WF:** BR-001, WF-001

## Scope / Non-goals

**Scope:**
- Physically shrink ELF binaries by removing dead .text bytes and shifting all subsequent content
- Update ALL ELF metadata: section headers, program headers, symbol tables, .dynamic entries
- Unified shift function that handles within-.text and post-.text address translation
- Truncate file to final smaller size

**Non-goals:**
- .eh_frame / DWARF CFI patching (stack unwinding may break for shifted functions)
- 32-bit ELF support (focus on Elf64)
- PE/COFF or Mach-O physical minification (ELF only)

## Acceptance Criteria

- AC-1: Patched ELF dynamic binary is measurably smaller than original (file size reduced)
- AC-2: Patched binary executes correctly and produces expected output
- AC-3: Patched static binary executes correctly
- AC-4: Patched shared library (.so) loads and functions correctly
- AC-5: Symbol tables (nm output) show correct shifted addresses after patching
- AC-6: Section and program headers reflect new sizes and offsets
- AC-7: .dynamic entries point to correct shifted addresses
- AC-8: Stripped binaries (no .symtab) still work correctly after patching
- AC-9: All existing tests continue to pass
- AC-10: Dead intervals absorb adjacent NOP/INT3 alignment padding (defragmentation)

## Security Acceptance Criteria (mandatory)

- SEC-1: Corrupted/malformed ELF files do not cause crashes or buffer overflows
- SEC-2: Symlink escape protection remains functional after changes
- SEC-3: Path traversal protection remains functional after changes

## Failure Modes / Error Mapping

- If .text section not found: fall back to zero-fill (existing behavior)
- If no dead intervals found: no-op, return 0 saved bytes
- If ELF header missing/corrupt: skip patching gracefully

## Test Matrix (mandatory)

| AC    | Integration |
|-------|-------------|
| AC-1  | file-size-reduction assertion in test.sh |
| AC-2  | patched binary executes + output check |
| AC-3  | static patched binary executes |
| AC-4  | .so detection + export preservation |
| AC-5  | nm address check on patched binary |
| AC-6  | covered by AC-2 (binary loads = headers correct) |
| AC-7  | covered by AC-2/AC-4 (dynamic linking works) |
| AC-8  | stripped binary execute tests |
| AC-9  | all existing 40 tests pass |
| AC-10 | defrag absorbs padding, patched binaries still execute |
| SEC-1 | corrupted file test |
| SEC-2 | symlink test |
| SEC-3 | path traversal test |
