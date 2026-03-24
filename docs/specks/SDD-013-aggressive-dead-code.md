# SDD-013 -- Aggressive Dead Code Scanning & Unified Compaction

**Impacted UCs:** UC-001, UC-002, UC-003, UC-004
**Impacted BR/WF:** BR-003, BR-007, BR-008 (new), BR-009 (new), WF-001

## Scope / Non-goals

**Scope:**
- Phase 1: Extend SCCP constant propagation to all native architectures
  (AArch64, ARM32, RISC-V, MIPS, s390x, LoongArch64)
- Phase 2: Extend ELF compaction to all architectures (remove x86 guard)
- Phase 3: PE compaction with full metadata patching
- Phase 4: Mach-O compaction with full metadata patching
- Phase 5: Wasm & .NET IL dead branch detection
- Phase 6: Documentation, spec, and test updates

**Non-goals:**
- Profile-guided optimization (PGO)
- Inter-procedural constant propagation
- Source-level or IR-level analysis
- Fat/universal Mach-O binary support (single-arch only)

## Acceptance Criteria

### Phase 1: SCCP Multi-Architecture

- AC-1: `sccp_dead_blocks()` produces results for all native architectures,
  not just x86-64/x86-32
- AC-2: Each architecture maps GPRs to abstract RegId 0-15, FLAGS=16
- AC-3: Unknown or complex instructions produce Clobber effects (conservative)
- AC-4: Caller-saved register sets follow each architecture's standard ABI
- AC-5: All existing x86 SCCP tests pass unchanged
- AC-6: No false positives on any architecture

### Phase 2: ELF All-Architecture Compaction

- AC-7: ELF binaries for AArch64, ARM32, RISC-V, MIPS, s390x, LoongArch64
  are physically compacted (not just zero-filled)
- AC-8: Per-arch branch offset patching correctly recalculates offsets
- AC-9: Big-endian ELF metadata patching works for s390x and MIPS BE
- AC-10: All existing ELF tests pass unchanged

### Phase 3: PE Compaction

- AC-11: PE .text section is physically compacted
- AC-12: PE relocations (.reloc), exports (EAT), imports (IAT/ILT),
  exception tables (.pdata), and headers are correctly patched
- AC-13: PE format validation passes after compaction

### Phase 4: Mach-O Compaction

- AC-14: Mach-O __text section is physically compacted
- AC-15: Load commands, symbol tables, stubs, GOT entries, rebase info,
  and function starts are correctly patched
- AC-16: Mach-O format validation passes after compaction

### Phase 5: Wasm & .NET Dead Branch Detection

- AC-17: Wasm dead branches detected (unreachable opcode, constant if,
  unconditional br)
- AC-18: .NET IL dead branches detected (throw, unconditional br,
  constant branch patterns)
- AC-19: Dead branches reported in analysis output alongside dead functions

## Security Acceptance Criteria (mandatory)

- SEC-1: Crafted binaries with unusual instruction encodings do not cause
  panics in arch effect extractors
- SEC-2: Big-endian binaries with corrupted headers do not cause buffer
  overflows in endian-aware metadata patching
- SEC-3: PE/Mach-O binaries with malformed relocation/rebase data do not
  crash the patcher (skip compaction, fall back to zero-fill)
- SEC-4: Wasm modules with deeply nested block structures do not cause
  stack overflow in branch analysis

## Failure Modes / Error Mapping

| Input | Behavior |
|-------|----------|
| Unrecognized instruction in arch effects | Clobber all written registers (conservative) |
| Branch offset overflow after compaction | Skip compaction for that function, zero-fill instead |
| PE relocation parsing failure | Fall back to zero-fill for entire binary |
| Mach-O rebase info parsing failure | Fall back to zero-fill for entire binary |
| Big-endian ELF with unknown EI_DATA | Fall back to little-endian (existing behavior) |

## Test Matrix (mandatory)

| AC     | Docker Test |
|--------|-------------|
| AC-1   | SCCP detection tests per architecture |
| AC-2   | Register mapping correctness tests |
| AC-3   | Unknown instruction conservative handling tests |
| AC-4   | Caller-saved register tests |
| AC-5   | Existing x86 SCCP regression tests |
| AC-6   | False positive tests per architecture |
| AC-7   | ELF compaction size reduction per architecture |
| AC-8   | Branch offset patching per architecture |
| AC-9   | Big-endian ELF compaction tests |
| AC-10  | Existing ELF regression tests |
| AC-11  | PE compaction size reduction tests |
| AC-12  | PE metadata correctness tests |
| AC-13  | PE format validation tests |
| AC-14  | Mach-O compaction size reduction tests |
| AC-15  | Mach-O metadata correctness tests |
| AC-16  | Mach-O format validation tests |
| AC-17  | Wasm dead branch detection tests |
| AC-18  | .NET IL dead branch detection tests |
| AC-19  | Combined reporting tests |
| SEC-1  | Malformed instruction tests |
| SEC-2  | Corrupted big-endian header tests |
| SEC-3  | Malformed PE/Mach-O relocation tests |
| SEC-4  | Deeply nested Wasm block tests |

## Dependencies

No new crate dependencies. All architecture effect extractors are implemented
in pure Rust using raw byte decoding (same approach as existing arch decoders).

## Verification

After each phase:
```bash
docker compose run --build --rm test
```
