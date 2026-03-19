# SDD-012 — Multi-Architecture Expansion

**Impacted UCs:** UC-001, UC-002, UC-003, UC-004
**Impacted BR/WF:** BR-003 / WF-001

## Scope / Non-goals

**Scope:**

- Add RISC-V (RV32/RV64), MIPS (32/64), s390x, LoongArch64 instruction
  decoders for dead code analysis
- Add WebAssembly function-level dead code analysis using `wasmparser`
- Add ELF e_machine detection for all new architectures
- Add QEMU-based execution tests for cross-compiled binaries
- Update Format enum with Wasm variant

**Non-goals:**

- PE/Mach-O support for new CPU architectures (no Windows/macOS targets)
- SCCP analysis for non-x86 architectures (remains x86-only)
- Wasm compaction (function indices must remain stable)
- MIPS16/microMIPS compressed instruction support
- RISC-V extensions beyond RV32GC/RV64GC compressed (C)

## Acceptance Criteria

- AC-1: RISC-V 64 dead code detection identifies dead_compute and
  dead_factorial in cross-compiled nostdlib ELF binary
- AC-2: RISC-V 64 patched binary executes correctly via QEMU
- AC-3: MIPS big-endian dead code detection identifies dead functions
- AC-4: MIPS patched binary executes correctly via QEMU
- AC-5: s390x dead code detection identifies dead functions
- AC-6: s390x patched binary executes correctly via QEMU
- AC-7: LoongArch64 dead code detection identifies dead functions
- AC-8: LoongArch64 patched binary executes correctly via QEMU
- AC-9: WebAssembly dead function detection identifies dead_factorial
  and dead_heavy in lib.wasm
- AC-10: Live functions (exported) are not flagged as dead for any arch
- AC-11: All existing 127 tests continue to pass
- AC-12: Format::Wasm detected from \0asm magic bytes

## Security Acceptance Criteria (mandatory)

- SEC-1: Malformed ELF with invalid e_machine values does not crash
  (falls back to X86_64 default)
- SEC-2: Truncated Wasm files do not cause panics (graceful error)
- SEC-3: Cross-compiled binaries with corrupt instruction streams do
  not cause unbounded memory allocation

## Failure Modes / Error Mapping

| Condition | Behavior |
|-----------|----------|
| Unknown e_machine | Falls back to X86_64 (existing behavior) |
| Invalid Wasm magic | Not detected as Wasm, skipped |
| Truncated code section | Decoder stops at available bytes |
| QEMU not available | Test skipped (build-time only) |

## Test Matrix (mandatory)

| AC     | Unit | Integration | Curl Dev | Prod |
|--------|------|-------------|----------|------|
| AC-1   | N/A  | ✅           | N/A      | N/A  |
| AC-2   | N/A  | ✅           | N/A      | N/A  |
| AC-3   | N/A  | ✅           | N/A      | N/A  |
| AC-4   | N/A  | ✅           | N/A      | N/A  |
| AC-5   | N/A  | ✅           | N/A      | N/A  |
| AC-6   | N/A  | ✅           | N/A      | N/A  |
| AC-7   | N/A  | ✅           | N/A      | N/A  |
| AC-8   | N/A  | ✅           | N/A      | N/A  |
| AC-9   | N/A  | ✅           | N/A      | N/A  |
| AC-10  | N/A  | ✅           | N/A      | N/A  |
| AC-11  | N/A  | ✅           | N/A      | N/A  |
| AC-12  | N/A  | ✅           | N/A      | N/A  |
| SEC-1  | N/A  | ✅           | N/A      | N/A  |
| SEC-2  | N/A  | ✅           | N/A      | N/A  |
| SEC-3  | N/A  | ✅           | N/A      | N/A  |

Notes:

- This is a CLI tool with no API or UI — integration tests via
  Docker shell script cover all acceptance criteria.
- "✅" means meaningful assertions in test.sh.
- Security criteria tested via corrupted input handling tests.
