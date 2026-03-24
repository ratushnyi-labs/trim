# SDD-008 — Stream/Pipe CLI Mode

**Impacted UCs:** UC-001, UC-002, UC-003, UC-004 (new)
**Impacted BR/WF:** BR-001, BR-005, WF-001

## Scope

- Default mode changes from in-place modification to stream (input → output)
- In-place modification requires explicit `--in-place` / `-i` flag
- Support pipe mode: stdin (`-`) → stdout
- All diagnostic output goes to stderr; binary output to stdout or named file

## Non-goals

- No changes to analysis or patching logic
- No new binary format support
- No changes to Docker image structure

## Acceptance Criteria

- AC-1: `trim INPUT OUTPUT` reads INPUT, writes patched binary to OUTPUT
- AC-2: `trim INPUT` reads INPUT, writes patched binary to stdout
- AC-3: `trim -` reads stdin, writes patched binary to stdout
- AC-4: `trim -i FILE [FILE...]` modifies files in-place (old default)
- AC-5: `trim --dry-run INPUT` analyzes only, reports to stderr, exit 0
- AC-6: `trim --dry-run -` reads stdin, analyzes only, reports to stderr
- AC-7: All diagnostic output (analysis reports, errors) goes to stderr
- AC-8: Binary output is clean (no text mixed in)
- AC-9: `trim.sh` wrapper passes `--in-place` automatically

## Security Acceptance Criteria (mandatory)

- SEC-1: Path traversal via INPUT/OUTPUT paths rejected (existing behavior)
- SEC-2: Symlink escape via `--in-place` target rejected (existing behavior)
- SEC-3: Corrupted/malformed binary on stdin does not crash (graceful error)
- SEC-4: No unbounded memory allocation on oversized stdin input (limited by
  available memory, no amplification)

## Failure Modes / Error Mapping

| Condition                       | Output (stderr)                        | Exit |
|---------------------------------|----------------------------------------|------|
| No arguments                    | Usage message                          | 1    |
| `--in-place` with no files      | "Error: --in-place requires files"     | 1    |
| Input file not found            | "Error: '<path>' not found"            | 1    |
| In-place file not writable      | "Error: '<path>' is not writable"      | 1    |
| Symlink outside /work (in-place)| "Error: symlink outside /work"         | 1    |
| No functions detected           | "skipped: no functions detected"       | 0    |
| No dead code found              | "no dead code found"                   | 0    |
| Output file write failure       | "Error: cannot write '<path>'"         | 1    |

## Test Matrix (mandatory)

| AC    | Integration |
|-------|-------------|
| AC-1  | ✅           |
| AC-2  | ✅           |
| AC-3  | ✅           |
| AC-4  | ✅           |
| AC-5  | ✅           |
| AC-6  | ✅           |
| AC-7  | ✅           |
| AC-8  | ✅           |
| AC-9  | ✅           |
| SEC-1 | ✅           |
| SEC-2 | ✅           |
| SEC-3 | ✅           |
| SEC-4 | ✅           |

Notes:
- All tests run inside Docker containers (test.sh)
- Security tests labeled `[SEC]` in test output
- No unit tests (Rust binary, integration-only testing via shell)
