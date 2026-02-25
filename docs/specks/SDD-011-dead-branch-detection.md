# SDD-011 -- Dead Branch Detection & Shrinking

**Impacted UCs:** UC-001, UC-002, UC-003, UC-004
**Impacted BR/WF:** BR-002, BR-003, BR-005, BR-007 (new), WF-001

## Scope / Non-goals

**Scope:**
- Phase A: CFG construction + unreachable block detection + zero-fill
- Phase B: Intra-function compaction with tail reclamation
- Phase C: SSA construction + constant propagation for provable dead branches

**Non-goals:**
- Profile-guided optimization (PGO) or runtime instrumentation
- Inter-procedural constant propagation (callee value range narrowing)
- Speculative devirtualization
- Source-level or IR-level analysis (xstrip works on binaries only)
- .NET IL branch elimination (CIL has no fixed layout; JIT handles this)

## Acceptance Criteria

### Phase A: CFG + Unreachable Blocks

- AC-1: Each function's disassembled instructions are split into basic
  blocks at branch targets and branch sources
- AC-2: CFG edges (fall-through, conditional, unconditional, indirect via
  jump tables) are correctly identified for x86-64, x86-32, AArch64, ARM32
- AC-3: Post-noreturn dead code (code after calls to functions like `exit`,
  `abort`, `__stack_chk_fail`) is identified as dead blocks
- AC-4: Code after unconditional jumps with no incoming edges is identified
  as dead blocks
- AC-5: Dead blocks within live functions are zero-filled (INT3/0xCC for
  x86, BRK #0/0x00 for ARM)
- AC-6: `--dry-run` reports dead branches with block addresses and sizes
- AC-7: All existing dead function tests still pass unchanged
- AC-8: No false positives — live blocks are never marked dead

### Phase B: Intra-Function Compaction

- AC-9: Dead blocks within a function are physically removed; live blocks
  shift down to fill gaps
- AC-10: All intra-function branch offsets crossing a removed region are
  correctly patched (x86 rel8/rel32, ARM B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ)
- AC-11: Branch range overflow (e.g., rel8 out of range after compaction)
  is handled by widening the branch instruction
- AC-12: Freed tail bytes at end of each compacted function are reclaimed
  by existing dead function compaction pipeline
- AC-13: Jump table entries pointing into the compacted function are
  updated
- AC-14: Exception handling tables (.eh_frame for ELF, .pdata/.xdata for
  PE, __unwind_info for Mach-O) are updated
- AC-15: All formats (ELF, PE, Mach-O) support intra-function compaction

### Phase C: Data-Flow Provable Dead Branches

- AC-16: SSA form is constructed from disassembled instructions within each
  function (register-based, intra-procedural)
- AC-17: Dominance tree and dominance frontiers are computed correctly
- AC-18: Phi-nodes are inserted at dominance frontiers for each register
  definition
- AC-19: Conditional Constant Propagation (Wegman-Zadeck) resolves
  constant conditions and marks infeasible edges
- AC-20: Value range analysis narrows integer ranges through comparisons,
  arithmetic, and phi-nodes
- AC-21: Data-flow proven dead branches are eliminated (dead edges removed,
  blocks with no live predecessors marked dead)
- AC-22: Conservative handling of memory: all memory assumed clobbered at
  call sites (no alias analysis)
- AC-23: Conservative handling of indirect branches: if target cannot be
  resolved, all successors assumed live
- AC-24: Combined with Phase A/B, provable dead blocks are compacted out

## Security Acceptance Criteria (mandatory)

- SEC-1: Crafted binaries with overlapping basic blocks (e.g., jump into
  middle of instruction) do not cause panics or incorrect analysis
- SEC-2: Functions with intentionally obfuscated CFGs (opaque predicates,
  overlapping code) are handled conservatively (no false dead marking)
- SEC-3: Binaries with extremely large functions (>100KB) do not cause
  excessive memory usage or stack overflow in SSA/dominance computation
- SEC-4: Jump tables with out-of-bounds entries do not cause buffer
  overflows during CFG construction
- SEC-5: Corrupted exception handling tables do not crash the patcher

## Failure Modes / Error Mapping

| Input | Behavior |
|-------|----------|
| Function with unresolvable indirect jumps | All blocks reachable from indirect jump assumed live |
| Jump table with unparseable entries | Entire function treated as fully live |
| SSA construction fails (too complex) | Fall back to Phase A (CFG-only) analysis |
| Branch widening causes cascade | Iteratively re-resolve until stable or abort compaction for that function |
| Exception table parsing fails | Skip compaction for that function (zero-fill only) |

## Test Matrix (mandatory)

| AC     | Unit | Integration | Docker Test |
|--------|------|-------------|-------------|
| AC-1   | N/A  | N/A         | CFG construction tests |
| AC-2   | N/A  | N/A         | CFG edge accuracy tests |
| AC-3   | N/A  | N/A         | Post-noreturn dead block tests |
| AC-4   | N/A  | N/A         | Post-unconditional-jump tests |
| AC-5   | N/A  | N/A         | Zero-fill verification tests |
| AC-6   | N/A  | N/A         | Dry-run output format tests |
| AC-7   | N/A  | N/A         | All existing tests pass |
| AC-8   | N/A  | N/A         | No false positive tests |
| AC-9   | N/A  | N/A         | Compaction byte removal tests |
| AC-10  | N/A  | N/A         | Branch offset patching tests |
| AC-11  | N/A  | N/A         | Branch widening tests |
| AC-12  | N/A  | N/A         | Tail reclamation + size reduction tests |
| AC-13  | N/A  | N/A         | Jump table update tests |
| AC-14  | N/A  | N/A         | Exception table update tests |
| AC-15  | N/A  | N/A         | Multi-format compaction tests |
| AC-16  | N/A  | N/A         | SSA construction tests |
| AC-17  | N/A  | N/A         | Dominance tree tests |
| AC-18  | N/A  | N/A         | Phi-node insertion tests |
| AC-19  | N/A  | N/A         | Constant propagation tests |
| AC-20  | N/A  | N/A         | Value range analysis tests |
| AC-21  | N/A  | N/A         | Provable dead branch tests |
| AC-22  | N/A  | N/A         | Conservative memory tests |
| AC-23  | N/A  | N/A         | Indirect branch conservative tests |
| AC-24  | N/A  | N/A         | Combined dead branch + compaction tests |
| SEC-1  | N/A  | N/A         | Overlapping block tests |
| SEC-2  | N/A  | N/A         | Obfuscated CFG tests |
| SEC-3  | N/A  | N/A         | Large function memory tests |
| SEC-4  | N/A  | N/A         | Jump table bounds tests |
| SEC-5  | N/A  | N/A         | Corrupted exception table tests |

## Phase A: CFG + Unreachable Block Detection + Zero-Fill

### Estimated: ~2500 lines new code

### Step A.1: Basic block splitting (`src/analysis/cfg.rs`)
- Split decoded instructions into basic blocks
- Block boundary = branch target address OR instruction after a branch
- Each block: start address, end address, list of instruction indices
- ~200 lines

### Step A.2: CFG edge construction (`src/analysis/cfg.rs`)
- For each block's terminator instruction:
  - Unconditional jump: single edge to target block
  - Conditional branch: two edges (taken + fall-through)
  - Call: fall-through edge (call does not split blocks)
  - Return/HLT/UD2: no outgoing edges
  - Indirect jump: try to resolve via jump table, else mark as unresolved
- ~300 lines

### Step A.3: Jump table resolution (`src/analysis/cfg.rs`)
- x86: detect `jmp [reg*scale + base]` patterns, read table entries
  from .rodata
- ARM: detect `TBB`/`TBH`/`ADR+LDR+BR` patterns
- Already partially exists in `arch/x86_patch.rs` jump table code
- ~200 lines

### Step A.4: Noreturn function identification (`src/analysis/noreturn.rs`)
- Build list of known noreturn functions: `exit`, `_exit`, `abort`,
  `__stack_chk_fail`, `__assert_fail`, `longjmp`, `__cxa_throw`,
  `pthread_exit`, `ExitProcess`, `TerminateProcess`
- Mark calls to these as terminal (no fall-through edge)
- ~100 lines

### Step A.5: Unreachable block detection (`src/analysis/cfg.rs`)
- Entry block = block containing function entry point
- BFS/DFS from entry block following CFG edges
- Blocks not reached = dead blocks
- ~100 lines

### Step A.6: Dead block zero-filling (`src/patch/zerofill.rs`)
- Extend existing zero-fill to accept block-level dead regions
  (not just whole functions)
- x86: fill with INT3 (0xCC)
- ARM: fill with 0x00 (UDF) or BRK
- ~100 lines

### Step A.7: Reporting (`src/lib.rs`)
- Extend analysis report to include dead blocks within live functions
- Format: `  dead branch: 24 bytes @ 0x1234 (in function_name)`
- ~100 lines

### Step A.8: Test infrastructure
- New test C files with provable dead branches:
  - `tests/dead-branch.c`: functions with `if (0)` blocks, post-exit
    code, unreachable switch cases
  - `tests/noreturn-dead.c`: code after `exit()` calls
- ~200 lines test code

### Step A.9: Integration
- Wire CFG analysis into existing `analyze()` pipeline
- Dead blocks reported alongside dead functions
- Zero-fill applied to dead blocks during patching
- All existing tests must still pass
- ~200 lines

**Verification:** `docker compose run --build --rm test` — all existing
tests pass + new dead branch tests pass.

## Phase B: Intra-Function Compaction

### Estimated: ~2000 lines new code

### Step B.1: Block reordering engine (`src/patch/block_compact.rs`)
- Given a function's CFG with dead blocks identified:
  - Collect live blocks in original order
  - Calculate byte offsets after removing dead blocks
  - Build shift map: for each original offset, compute new offset
- ~300 lines

### Step B.2: Branch offset patching (`src/patch/block_compact.rs`)
- x86: patch rel8/rel32 in JMP, Jcc, CALL instructions
  - If rel8 overflows after shift: widen to rel32 (2-byte -> 6-byte)
  - Widening may cascade — iterate until stable
- ARM: patch B/BL (26-bit), B.cond (19-bit), CBZ/CBNZ (19-bit),
  TBZ/TBNZ (14-bit)
  - If offset overflows: emit trampoline (veneer) at function tail
- ~500 lines

### Step B.3: Jump table patching (`src/patch/block_compact.rs`)
- Update relative offsets in jump table entries
- x86: 32-bit relative entries in .rodata
- ARM: TBB (8-bit) / TBH (16-bit) entries
- ~200 lines

### Step B.4: Exception table patching
- ELF `.eh_frame`: update FDE pc ranges, adjust CFA instructions
  (`src/format/elf/patch.rs`)
- PE `.pdata`: update RUNTIME_FUNCTION begin/end addresses
  (`src/format/pe/patch.rs`)
- Mach-O `__unwind_info`: update function offsets
  (`src/format/macho/patch.rs`)
- ~500 lines across formats

### Step B.5: Tail reclamation
- After intra-function compaction, freed bytes at function tail are
  contiguous dead space
- Feed these into existing dead function compaction pipeline
  (`patch/compact.rs`)
- ~100 lines

### Step B.6: Integration + testing
- Wire block compaction into `reassemble()` pipeline
- Test with binaries containing dead branches + verify:
  - Patched binary executes correctly
  - File size reduced
  - All branch targets valid
- ~400 lines test code

**Verification:** `docker compose run --build --rm test` — all tests pass
+ compacted binaries execute correctly.

## Phase C: SSA + Constant Propagation

### Estimated: ~3000 lines new code

### Step C.1: Register def-use tracking (`src/analysis/regstate.rs`)
- For each instruction, identify:
  - Registers defined (written)
  - Registers used (read)
- x86: use iced-x86 operand info
- ARM: use yaxpeax-arm operand info
- ~300 lines

### Step C.2: Dominance tree (`src/analysis/dominance.rs`)
- Lengauer-Tarjan algorithm for immediate dominators
- Dominance frontier computation
- ~300 lines

### Step C.3: SSA construction (`src/analysis/ssa.rs`)
- Insert phi-nodes at dominance frontiers for each register definition
- Rename registers to SSA versions (v0, v1, v2, ...)
- Represent SSA values as a graph: each value has a definition point
  and a list of uses
- ~500 lines

### Step C.4: Lattice + abstract values (`src/analysis/lattice.rs`)
- Value lattice: Bottom (unreachable) -> Constant(i64) -> Range(lo,hi)
  -> Top (unknown)
- Meet operation for phi-nodes
- Transfer functions for arithmetic (add, sub, mul, and, or, shift)
- Transfer functions for comparisons (produces constraint on operands)
- ~400 lines

### Step C.5: Sparse Conditional Constant Propagation
(`src/analysis/sccp.rs`)
- Wegman-Zadeck SCCP algorithm:
  - Maintain SSA edge worklist + CFG edge worklist
  - Initialize all values as Bottom, all edges as not-executable
  - Process worklists until fixpoint
  - Conditional branches with constant condition: mark only taken edge
  - Phi-nodes: meet over executable incoming edges only
- ~400 lines

### Step C.6: Value range narrowing (`src/analysis/sccp.rs`)
- Extend lattice with integer ranges
- At conditional branches (`cmp + jcc`), narrow operand ranges on
  the taken edge
- Example: `if (x > 5)` -> on taken edge, x has range [6, MAX]
- ~300 lines

### Step C.7: Dead edge elimination (`src/analysis/sccp.rs`)
- After SCCP fixpoint: edges still marked not-executable are dead
- Remove dead edges from CFG
- Blocks with no executable incoming edges are dead blocks
- Feed dead blocks into Phase A/B pipeline
- ~200 lines

### Step C.8: Conservative guards
- At call instructions: set all caller-saved registers to Top
  (unknown)
- At indirect memory loads: set result to Top
- At indirect branches: mark all successors as executable
- At unrecognized instructions: set all potentially-affected
  registers to Top
- ~200 lines

### Step C.9: Integration + testing
- Wire SCCP into analysis pipeline (after CFG, before dead block
  marking)
- Test C files:
  - `tests/const-branch.c`: branches on compile-time constants that
    the compiler didn't eliminate (e.g., via volatile or external linkage)
  - `tests/range-branch.c`: branches provable dead via range analysis
  - `tests/noreturn-prop.c`: noreturn propagation through call chains
- Verify: no false positives, correct dead blocks identified
- ~400 lines test code

**Verification:** `docker compose run --build --rm test` — all tests pass
+ data-flow dead branches detected and removed.

## Implementation Order

Execute phases sequentially: A -> B -> C. Each phase ends with all tests
passing.

Phase A is independently valuable (catches post-noreturn and unreachable
code without data-flow analysis). Phase B adds size reduction. Phase C
adds the most sophisticated analysis.

## Key Risk Mitigations

| Risk | Mitigation |
|------|------------|
| False positives in CFG | Conservative: unresolved edges assumed live |
| Branch widening cascade | Iterative fixpoint with bounded iterations |
| Exception table complexity | Skip compaction for functions with unparseable unwind info |
| SSA correctness | Extensive test suite with hand-verified expected results |
| Performance on large binaries | Limit SSA/SCCP to functions under 10K instructions |
| ARM interworking complexity | Conservative: skip compaction for mixed ARM/Thumb functions initially |

## Files Created/Modified Per Phase Summary

| Phase | Key new files | Key modified files |
|-------|--------------|-------------------|
| A | `analysis/cfg.rs`, `analysis/noreturn.rs`, `tests/dead-branch.c`, `tests/noreturn-dead.c` | `analysis/mod.rs`, `lib.rs`, `patch/zerofill.rs`, `tests/test.sh` |
| B | `patch/block_compact.rs` | `format/elf/patch.rs`, `format/pe/patch.rs`, `format/macho/patch.rs`, `patch/compact.rs`, `tests/test.sh` |
| C | `analysis/regstate.rs`, `analysis/dominance.rs`, `analysis/ssa.rs`, `analysis/lattice.rs`, `analysis/sccp.rs`, `tests/const-branch.c`, `tests/range-branch.c` | `analysis/cfg.rs`, `lib.rs`, `tests/test.sh` |

## Dependencies

No new crate dependencies required. All algorithms implemented in pure
Rust using existing disassembly crates (iced-x86, yaxpeax-arm).

## Verification (end-to-end)

After each phase:
```bash
docker compose run --build --rm test
```

After all phases:
```bash
docker build -t xstrip . && docker run --rm xstrip --help
```

Update docs: `docs/spec.md` (BR-007), `docs/development-manual.md`,
`docs/installation-manual.md`.
