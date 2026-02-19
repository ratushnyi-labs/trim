# SDD-005 -- xstrip Docker Image for Cross-Format Executable Stripping

**Impacted UCs:** UC-001, UC-002, UC-003
**Impacted BR/WF:** BR-001 through BR-006, WF-001

## Scope / Non-goals

**Scope:**

- Build a Docker image that strips debug symbols from any mounted executable
- Support ELF, PE/COFF, Mach-O, and Wasm formats via `llvm-strip`
- Multi-stage Dockerfile (Alpine) following rules.md container image policy
- Entrypoint script with format auto-detection and size reporting
- docker-compose.yml for easy usage
- Non-root container execution
- Zscaler TLS proxy support (corporate environment)
- Test infrastructure verifying ELF and PE stripping
- Full documentation (spec, dev manual, install manual, config manual)

**Non-goals:**

- GUI or web UI
- API server
- Modifying executable behavior (only stripping metadata)
- Building executables (only stripping pre-built ones)
- macOS Mach-O test binaries (no cross-compiler readily available; format
  support verified by llvm-strip's built-in capability)

## Acceptance Criteria

- AC-1: Docker image builds successfully with `docker compose build`
- AC-2: Stripping a Linux ELF binary reduces its size and produces valid output
- AC-3: Stripping a Windows PE binary reduces its size and produces valid output
- AC-4: Missing file argument prints usage and exits 1
- AC-5: Non-existent file prints error and exits 1
- AC-6: Non-writable file prints error and exits 1
- AC-7: Multiple files can be stripped in a single invocation
- AC-8: `--strip-debug` flag keeps dynamic symbols (strips only debug info)
- AC-9: Container runs as non-root user
- AC-10: Image uses multi-stage build with Alpine base

## Security Acceptance Criteria (mandatory)

- SEC-1: Path traversal filenames are handled safely (llvm-strip operates
  on the exact path given; no path interpretation in entrypoint)
- SEC-2: Symlinks pointing outside the work directory are rejected
- SEC-3: Corrupted/non-executable files produce a clear error, not a crash
- SEC-4: No temp files are written during stripping
- SEC-5: Container runs as non-root; cannot escalate privileges

## Failure Modes / Error Mapping

| Failure | Error Message | Exit Code |
|---------|---------------|-----------|
| No arguments | Usage message | 1 |
| File not found | "Error: '<path>' not found or not a regular file" | 1 |
| File not writable | "Error: '<path>' is not writable" | 1 |
| Unsupported format | "Error: failed to strip '<path>' (unsupported format or corrupted)" | 1 |
| Symlink outside /work | "Error: '<path>' is a symlink outside the work directory" | 1 |

## Test Matrix (mandatory)

| AC    | Unit | Integration | Curl Dev | Base UI | UI | Curl Prod API | Prod Fullstack |
|-------|------|-------------|----------|---------|----|---------------|----------------|
| AC-1  | --   | Y           | --       | --      | -- | --            | --             |
| AC-2  | --   | Y           | --       | --      | -- | --            | --             |
| AC-3  | --   | Y           | --       | --      | -- | --            | --             |
| AC-4  | --   | Y           | --       | --      | -- | --            | --             |
| AC-5  | --   | Y           | --       | --      | -- | --            | --             |
| AC-6  | --   | Y           | --       | --      | -- | --            | --             |
| AC-7  | --   | Y           | --       | --      | -- | --            | --             |
| AC-8  | --   | Y           | --       | --      | -- | --            | --             |
| SEC-1 | --   | Y           | --       | --      | -- | --            | --             |
| SEC-2 | --   | Y           | --       | --      | -- | --            | --             |
| SEC-3 | --   | Y           | --       | --      | -- | --            | --             |

Notes:

- Unit tests marked `--` (shell script entrypoint; tested via integration).
- Curl/UI/Prod stages marked `--` (not applicable: CLI tool, no API or UI).
- Integration tests run inside Docker containers, building test executables
  and verifying stripping behavior.
- `SEC-*` tests run within integration stage alongside functional tests.
