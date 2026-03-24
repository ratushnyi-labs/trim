# SDD-015 -- Dead Branch Physical Compaction for Bytecode Formats

**Impacted UCs:** UC-001, UC-002, UC-003, UC-004
**Impacted BR/WF:** BR-009, BR-010, WF-001

## Scope / Non-goals

**Scope:**
- Phase 1: Wasm dead branch physical compaction (excise dead blocks
  from live function bodies, rebuild Code section)
- Phase 2: .NET IL dead branch physical compaction (patch branch
  offsets, excise dead blocks, update method headers)
- Phase 3: Java dead branch physical compaction (patch branch offsets,
  excise dead blocks, rebuild method_info bytes)

**Non-goals:**
- .NET exception handler offset patching (bail out to nop-fill)
- Java StackMapTable delta patching (bail out to nop-fill)
- Java tableswitch/lookupswitch alignment patching (bail out to nop-fill)
- Java exception_table offset patching (bail out to nop-fill)

## Acceptance Criteria

- AC-1: Wasm files with dead branches physically shrink
- AC-2: .NET assemblies with dead branches in simple methods (no
  exception handlers) physically shrink
- AC-3: Java .class files with dead branches in simple methods (no
  exception handlers, no switches, no StackMapTable) physically shrink
- AC-4: Branch offsets in .NET and Java are correctly repatched after
  dead byte removal
- AC-5: Methods with complex attributes fall back to nop-fill safely
- AC-6: All existing tests continue to pass (no regressions)

## Security Acceptance Criteria

- SEC-1: Malformed branch offsets after compaction do not cause panics
- SEC-2: Methods with exception handlers are never compacted (bail out)

## Key Files

| File | Change |
|------|--------|
| `src/format/wasm/mod.rs` | excise_ranges, build_block_ranges, modified rebuild_code_section |
| `src/format/dotnet/il.rs` | compact_il_dead_blocks, patch_il_branches, il_shift |
| `src/format/java/bytecode.rs` | compact_method_code, patch_java_branches, java_shift |
| `src/format/java/classfile.rs` | Extended MethodInfo with code_attr_offset, exception_table_len |
| `src/format/java/mod.rs` | Wire compaction into reassemble_java |
| `tests/gen_java.py` | Added liveBranch method with dead branch |
| `tests/test.sh` | Strict shrink assertion for Wasm |

## Verification

```bash
docker compose run --build --rm test
```
