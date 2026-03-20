# SDD-014 -- Wasm/.NET Physical Compaction & Java .class File Support

**Impacted UCs:** UC-001, UC-002, UC-003, UC-004
**Impacted BR/WF:** BR-002, BR-003, BR-009, BR-010 (new), WF-001

## Scope / Non-goals

**Scope:**
- Phase 1: Wasm physical compaction — rebuild Code section with minimal
  dead function bodies instead of nop-filling
- Phase 2: .NET physical compaction — wire dead method bodies into the
  existing PE compaction pipeline (defrag_intervals + compact_text)
- Phase 3: Java .class file support — new format module with class file
  parser, bytecode call graph, dead method removal, dead branch detection
- Phase 4: Tests for all three formats
- Phase 5: Documentation and spec updates

**Non-goals:**
- JAR file support (only single .class files)
- Wasm dead branch physical removal (would require branch target rewriting)
- .NET dead branch physical removal (IL branch offsets would break)
- Java annotation or attribute stripping

## Acceptance Criteria

### Phase 1: Wasm Physical Compaction

- AC-1: `rebuild_code_section()` replaces dead function bodies with minimal
  3-byte stubs (0 locals + unreachable + end) while preserving function
  indices
- AC-2: Module is reconstructed from `[before_code][new_code][after_code]`
  with correct LEB128 section size encoding
- AC-3: Dead functions with already-minimal bodies (body_size <= 3) are
  copied as-is to avoid file growth
- AC-4: Patched Wasm module is valid (file magic preserved, no size growth)

### Phase 2: .NET Physical Compaction

- AC-5: Dead method bodies are converted to dead intervals and compacted
  via `compact_text()` + `defrag_intervals()`
- AC-6: MethodDef RVAs in metadata tables are patched after compaction
- AC-7: CLI header RVAs (metadata, resources, strong_name) are patched
- AC-8: PE section headers, entry point, and other PE metadata are patched

### Phase 3: Java .class File Support

- AC-9: Java .class files (magic 0xCAFEBABE) are auto-detected
- AC-10: Constant pool parser handles all tag types (Utf8, Integer, Float,
  Long, Double, Class, String, Fieldref, Methodref, InterfaceMethodref,
  NameAndType, MethodHandle, MethodType, InvokeDynamic)
- AC-11: Call graph built from invoke* bytecodes (invokevirtual,
  invokespecial, invokestatic, invokeinterface)
- AC-12: BFS reachability from roots (main, `<init>`, `<clinit>`,
  public/protected methods) identifies dead private methods
- AC-13: Dead methods physically removed from .class file by rebuilding
  methods table and updating methods_count
- AC-14: Dead branches detected within live methods (code after terminators
  until next branch target)
- AC-15: Patched .class file retains CAFEBABE magic and is valid

### Phase 4: Tests

- AC-16: Wasm patching test verifies no file size growth
- AC-17: Java tests verify dead method detection (deadMethod1, deadMethod2)
- AC-18: Java tests verify live method preservation (main, liveHelper,
  `<init>`)
- AC-19: Java patching test verifies file physically shrinks

## Security Acceptance Criteria (mandatory)

- SEC-1: Malformed .class files with truncated constant pools do not
  cause panics (return None from parser)
- SEC-2: Java bytecodes with invalid opcode lengths do not cause buffer
  overflows (opcode_length defaults to 1 for unknown opcodes)
- SEC-3: Wasm modules with zero-length Code sections do not crash the
  compactor
- SEC-4: .NET assemblies with missing MethodDef tables skip compaction
  gracefully

## Failure Modes / Error Mapping

| Input | Behavior |
|-------|----------|
| .class with no methods | Return empty analysis (no dead code) |
| .class with truncated constant pool | Skip file (no functions detected) |
| Wasm with no Code section | Skip compaction, return zeros |
| .NET with no MethodDef table | Skip RVA patching |
| Dead function body already minimal | Copy original entry (no growth) |

## Test Matrix (mandatory)

| AC     | Docker Test |
|--------|-------------|
| AC-1   | Wasm dead function body replacement test |
| AC-2   | Wasm module reconstruction test |
| AC-3   | Wasm minimal body preservation test |
| AC-4   | Wasm valid module after patching |
| AC-5   | .NET dead method compaction test |
| AC-6   | .NET MethodDef RVA patching test |
| AC-7   | .NET CLI header patching test |
| AC-8   | .NET PE metadata patching test |
| AC-9   | Java format detection test |
| AC-10  | Java constant pool parsing test |
| AC-11  | Java call graph construction test |
| AC-12  | Java dead method detection test |
| AC-13  | Java physical method removal test |
| AC-14  | Java dead branch detection test |
| AC-15  | Java valid .class after patching |
| AC-16  | Wasm no-growth assertion |
| AC-17  | Java deadMethod1/deadMethod2 detection |
| AC-18  | Java main/liveHelper/<init> preservation |
| AC-19  | Java file shrink assertion |
| SEC-1  | Malformed .class input test |
| SEC-2  | Invalid bytecode length test |
| SEC-3  | Zero-length Wasm Code section test |
| SEC-4  | Missing .NET MethodDef table test |

## Dependencies

No new crate dependencies. Java class file parser, bytecode analyzer, and
Wasm Code section rebuilder are implemented in pure Rust.

## Key Files

| File | Change |
|------|--------|
| `src/format/wasm/mod.rs` | write_leb128_u32, rebuild_code_section, parse_code_section_bounds |
| `src/format/dotnet/mod.rs` | Wire dead intervals into PE compact pipeline |
| `src/format/dotnet/patch.rs` | patch_method_rvas, patch_cli_rvas |
| `src/format/dotnet/tables.rs` | method_def_table_info |
| `src/format/java/mod.rs` (new) | analyze_java, reassemble_java, find_java_dead_blocks |
| `src/format/java/classfile.rs` (new) | Class file parser (constant pool, methods) |
| `src/format/java/bytecode.rs` (new) | Call graph builder, dead branch scanner |
| `src/format/mod.rs` | Java variant in Format enum + detection |
| `src/lib.rs` | Java dispatch in analyze/reassemble/find_dead_blocks |
| `tests/gen_java.py` (new) | Generate test .class file with dead methods |
| `tests/test.sh` | Wasm compaction + Java detection/patching tests |

## Verification

After each phase:
```bash
docker compose run --build --rm test
```
