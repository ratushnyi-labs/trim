# SDD-010 -- Multi-Architecture & Multi-Format Support

**Impacted UCs:** UC-001, UC-002, UC-003, UC-004
**Impacted BR/WF:** BR-002, BR-003, WF-001

## Scope / Non-goals

**Scope (all phases completed):**
- Refactor codebase to abstract arch/format layers (Phase 1: done)
- Add ARM (AArch64 + ARM32) disassembly support (Phase 2: done)
- Add PE/COFF analysis and patching (Phase 3: done)
- Add Mach-O analysis and patching (Phase 4: done)
- Add .NET IL metadata trimming (Phase 5: done)

**Non-goals:**
- RISC-V, MIPS, or other architectures
- WebAssembly analysis (already unsupported, stays unsupported)
- Dynamic analysis or runtime instrumentation

## Acceptance Criteria

- AC-1: Phase 1 refactoring produces identical behavior; all 40+ existing
  tests pass without modification
- AC-2: ARM ELF binaries (AArch64, ARM32) have dead code detected via
  structural validation
- AC-3: PE/COFF binaries have dead code detected; patched PE retains
  valid structure
- AC-4: Mach-O binaries have dead code detected; patched Mach-O retains
  valid structure (code signature stripped)
- AC-5: .NET managed assemblies have dead IL methods detected and zeroed
- AC-6: .NET Native AOT binaries handled by PE/ELF pipeline (no extra work)
- AC-7: Format auto-detection works for ELF, PE, Mach-O, .NET
- AC-8: All new code is pure Rust (no C dependencies)
- AC-9: No new dependencies with GPL-incompatible licenses
- AC-10: --help output lists all supported formats

## Security Acceptance Criteria (mandatory)

- SEC-1: Malformed/truncated PE, Mach-O, .NET binaries handled gracefully
  (no panics, no buffer overflows)
- SEC-2: Crafted binaries with overlapping sections or invalid offsets do
  not cause out-of-bounds access
- SEC-3: .NET metadata parser rejects invalid table indices and heap
  offsets without panic
- SEC-4: Fat Mach-O with conflicting slice offsets rejected gracefully

## Failure Modes / Error Mapping

| Input | Behavior |
|-------|----------|
| Unknown format | "skipped: unsupported format" |
| Unsupported arch in known format | "skipped: unsupported architecture" |
| Truncated PE/Mach-O headers | "skipped: no functions detected" |
| .NET with missing CLI header | Falls through to PE pipeline |
| Corrupted .NET metadata | "skipped: no functions detected" |

## Test Matrix (mandatory)

| AC    | Unit | Integration | Docker Test |
|-------|------|-------------|-------------|
| AC-1  | N/A  | N/A         | All existing tests pass |
| AC-2  | N/A  | N/A         | ARM ELF structural tests |
| AC-3  | N/A  | N/A         | PE detection + structure tests |
| AC-4  | N/A  | N/A         | Mach-O detection + structure tests |
| AC-5  | N/A  | N/A         | .NET trimming tests |
| AC-7  | N/A  | N/A         | Format detection tests |
| SEC-1 | N/A  | N/A         | Corrupted PE/Mach-O tests |
| SEC-2 | N/A  | N/A         | Overlapping section tests |
