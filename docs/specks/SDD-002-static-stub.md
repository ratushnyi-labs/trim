# SDD-002 -- Static Stub with Cross-Platform In-Memory Execution

**Impacted UCs:** UC-002, UC-003
**Impacted BR/WF:** BR-006, BR-007, BR-009, WF-002

## Scope / Non-goals

**Scope:**

- Static linking for all stub binaries (Linux=musl, Windows=crt-static, macOS=system)
- In-memory PE loading on Windows (VirtualAlloc, import resolution, relocation fixing)
- In-memory Mach-O loading on macOS (NSCreateObjectFileImageFromMemory)
- Remove temp file fallback from all platforms
- Update Linux memfd path to remove temp file fallback
- Update Dockerfile to build stub with musl target
- Update CI/release workflows for static stub builds
- Update documentation for new platform execution strategies

**Non-goals:**

- Changing the packer binary or SFX format
- Changing the compression algorithm
- Adding new CLI options
- Supporting 32-bit targets
- ARM64 Windows PE loading (ARM64 PE has identical format; loader works unchanged)

## Acceptance Criteria

- AC-1: Linux stub is statically linked via musl and uses memfd_create without fallback
- AC-2: Windows stub loads PE payload in-process via VirtualAlloc/import resolution (no temp file)
- AC-3: macOS stub loads Mach-O payload via NSCreateObjectFileImageFromMemory (no temp file)
- AC-4: No temp file code remains in the stub
- AC-5: PE parser logic is testable on all platforms (cross-platform unit tests)
- AC-6: Mach-O header patching logic is testable on all platforms (cross-platform unit tests)
- AC-7: Docker test suite passes (fmt, clippy, coverage 100%, audit)
- AC-8: Docker build produces a statically linked musl stub
- AC-9: CI builds pass on all 7 targets

## Security Acceptance Criteria (mandatory)

- SEC-1: PE parser rejects malformed/truncated PE headers with an error (no panic, no out-of-bounds)
- SEC-2: PE parser rejects PE files with section counts or sizes that would exceed available memory
- SEC-3: Mach-O header patching validates magic bytes before patching (rejects non-Mach-O data)
- SEC-4: Import resolution failure (missing DLL/function) returns a clear error, does not crash
- SEC-5: Oversized or zero-length payloads are rejected gracefully
- SEC-6: No memory leaks -- VirtualAlloc memory is properly freed on error paths (Windows)

## Failure Modes / Error Mapping

| Failure | Platform | Error Message |
|---------|----------|---------------|
| Invalid PE signature | Windows | "Invalid PE signature" |
| PE section out of bounds | Windows | "PE section exceeds image size" |
| DLL load failure | Windows | "Failed to load DLL: {name}" |
| Import resolution failure | Windows | "Failed to resolve import: {dll}!{func}" |
| Invalid Mach-O magic | macOS | "Invalid Mach-O magic" |
| NSCreateObjectFileImageFromMemory failure | macOS | "Failed to create object file image" |
| NSLinkModule failure | macOS | "Failed to link module" |
| Symbol lookup failure | macOS | "Failed to find _main symbol" |
| memfd_create failure | Linux | "memfd_create failed: {os_error}" |

## Test Matrix (mandatory)

| AC    | Unit | Integration | Curl Dev | Base UI | UI | Curl Prod API | Prod Fullstack |
|-------|------|-------------|----------|---------|----|---------------|----------------|
| AC-1  | --   | --          | --       | --      | -- | --            | --             |
| AC-2  | --   | --          | --       | --      | -- | --            | --             |
| AC-3  | --   | --          | --       | --      | -- | --            | --             |
| AC-4  | --   | --          | --       | --      | -- | --            | --             |
| AC-5  | Y    | --          | --       | --      | -- | --            | --             |
| AC-6  | Y    | --          | --       | --      | -- | --            | --             |
| AC-7  | Y    | Y           | --       | --      | -- | --            | --             |
| AC-8  | --   | --          | --       | --      | -- | --            | --             |
| AC-9  | --   | --          | --       | --      | -- | --            | --             |
| SEC-1 | Y    | --          | --       | --      | -- | --            | --             |
| SEC-2 | Y    | --          | --       | --      | -- | --            | --             |
| SEC-3 | Y    | --          | --       | --      | -- | --            | --             |
| SEC-4 | Y    | --          | --       | --      | -- | --            | --             |
| SEC-5 | Y    | --          | --       | --      | -- | --            | --             |
| SEC-6 | Y    | --          | --       | --      | -- | --            | --             |

Notes:

- Curl/UI/Prod stages marked `--` (not applicable: CLI tool with no API or UI).
- AC-1/AC-2/AC-3/AC-4/AC-8/AC-9 verified via CI builds and Docker build, not unit tests.
- PE parser and Mach-O header patch tests run on ALL platforms (pure byte manipulation).
- PE loader integration tests run only on Windows CI runners.
- Mach-O loader integration tests run only on macOS CI runners.
- `SEC-*` tests run within unit stage alongside functional tests.
