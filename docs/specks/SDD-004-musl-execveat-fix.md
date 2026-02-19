# SDD-004 — Fix musl payload/stub compatibility via execveat

**Impacted UCs:** UC-002
**Impacted BR/WF:** BR-006, BR-010, BR-013, WF-002

## Problem

UPX-compressed musl-linked stubs fail to start on Linux. UPX uses in-process
decompression (mmap MAP_FIXED + jump to entry point), which preserves the
kernel's original auxiliary vector (auxv). The auxv contains AT_BASE set by the
kernel for the UPX wrapper binary. Musl's `__libc_start_main` checks AT_BASE:
if non-zero, musl assumes it is running as a dynamic linker and tries to open
`/lib/ld-musl-x86_64.so.1`. This file does not exist on most systems, causing
exit code 127.

glibc is unaffected because its static startup path does not use AT_BASE to
determine its role. The bug is in the interaction between UPX and musl, not in
musl itself — musl's behavior is correct per the ELF spec.

## Scope

- Replace the Linux stub's `Command`-based fork+exec (via `/proc/self/fd/`)
  with a direct `execveat(fd, "", argv, envp, AT_EMPTY_PATH)` syscall
- Skip UPX compression for `*-linux-musl` stub targets in the build pipeline
- Add `-C target-feature=+crt-static` for `*-linux-musl` stub builds (zig's
  musl toolchain links dynamically by default, producing PIE binaries that
  depend on `/lib/ld-musl-x86_64.so.1`)

## Non-goals

- Changing Windows or macOS execution strategies
- Replacing UPX for non-musl Linux targets (glibc stubs work with UPX)
- Changing the SFX binary format or trailer structure

## Acceptance Criteria

- AC-1: Linux stub uses `execveat` syscall with `AT_EMPTY_PATH` to execute
  the payload from a memfd, replacing the current process entirely (no fork)
- AC-2: `memfd_create` with `MFD_CLOEXEC` is retained for zero-disk-write
  guarantee and fd cleanup
- AC-3: argv[0] is set to the SFX executable path (preserving BR-009)
- AC-4: All CLI arguments are forwarded to the payload (preserving BR-008)
- AC-5: UPX compression is skipped for `*-linux-musl` stub targets in the
  build script
- AC-6: UPX compression remains enabled for all other targets where supported
- AC-7: Musl stubs are built with `-C target-feature=+crt-static` to force
  static linking regardless of the cross-linker (zig or native musl-gcc)

## Security Acceptance Criteria (mandatory)

- SEC-1: No file descriptor leaks — memfd is MFD_CLOEXEC and closed on exec
- SEC-2: Execute permission is set via fchmod before execveat (no
  world-readable memfd)
- SEC-3: No temp files written to disk at any point in the execution path
- SEC-4: Environment is passed through unmodified via POSIX `environ` pointer

## Failure Modes / Error Mapping

| Condition                  | Behavior                         |
|----------------------------|----------------------------------|
| memfd_create fails         | Print "SFX stub error", exit 1   |
| write to memfd fails       | Print "SFX stub error", exit 1   |
| fchmod fails               | Print "SFX stub error", exit 1   |
| execveat fails             | Print "SFX stub error", exit 1   |
| argv contains null bytes   | Print "SFX stub error", exit 1   |

## Test Matrix (mandatory)

| AC    | Unit | Integration | Curl Dev | Base UI | UI | Curl Prod API | Prod Fullstack |
|-------|------|-------------|----------|---------|----|---------------|----------------|
| AC-1  | N/A  | N/A         | N/A      | N/A     | N/A| N/A           | N/A            |
| AC-2  | N/A  | N/A         | N/A      | N/A     | N/A| N/A           | N/A            |
| AC-3  | N/A  | N/A         | N/A      | N/A     | N/A| N/A           | N/A            |
| AC-4  | N/A  | N/A         | N/A      | N/A     | N/A| N/A           | N/A            |
| AC-5  | N/A  | N/A         | N/A      | N/A     | N/A| N/A           | N/A            |
| AC-6  | N/A  | N/A         | N/A      | N/A     | N/A| N/A           | N/A            |
| SEC-1 | N/A  | N/A         | N/A      | N/A     | N/A| N/A           | N/A            |
| SEC-2 | N/A  | N/A         | N/A      | N/A     | N/A| N/A           | N/A            |

Notes:
- Stub execution is tested via the Docker cross-build pipeline (CI build job)
  which produces SFX binaries for all 9 targets. The changes are in the stub
  binary (platform-specific runtime code) and build script — not in library
  functions testable via unit/integration tests.
- Existing integration tests (trailer parsing, compression roundtrip, SFX
  format assembly) remain passing and unchanged.
