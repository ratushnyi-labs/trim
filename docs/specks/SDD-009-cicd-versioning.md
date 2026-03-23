# SDD-009 — CI/CD Pipeline + Versioning + Author/License Info

**Impacted UCs:** UC-001, UC-002, UC-003, UC-004
**Impacted BR/WF:** WF-001

## Scope

- Add `--version` / `-v` flag: prints `trim <version>` to stdout, exit 0
- Add `--license` / `-l` flag: prints MIT license to stdout, exit 0
- Show version, author, and legal disclaimer in `--help` output
- Embed version at compile time via `TRIM_VERSION` env var (fallback to
  `CARGO_PKG_VERSION`)
- Create MIT LICENSE file
- Add GitHub CI workflow (test via Docker, native cargo build on push/PR)
- Add GitHub release workflow (test via Docker, native cargo-zigbuild
  cross-compilation for amd64+arm64 on tag push)
- Pass `TRIM_VERSION` build arg through Dockerfile and dist.sh
- Stream mode output file is automatically executable (chmod +x)

## Non-goals

- No changes to analysis or patching logic
- No new binary format support
- No changes to Docker image base or runtime structure

## Acceptance Criteria

- AC-1: `trim --version` prints `trim <version>` to stdout, exit 0
- AC-2: `trim -v` behaves identically to `--version`
- AC-3: `trim --license` prints MIT license text to stdout, exit 0
- AC-4: `trim -l` behaves identically to `--license`
- AC-5: `trim --help` shows version in header, author line, legal disclaimer
- AC-6: Version defaults to Cargo.toml version when `TRIM_VERSION` is unset
- AC-7: Version uses `TRIM_VERSION` env var when set at compile time
- AC-8: CI workflow runs tests and builds on push to main and PRs
- AC-9: Release workflow builds and publishes binaries on tag push
- AC-10: `dist.sh` passes `TRIM_VERSION` build arg to Docker
- AC-11: LICENSE file exists at repo root with MIT text
- AC-12: Stream mode output file has executable permission set

## Security Acceptance Criteria (mandatory)

- SEC-1: No secrets or tokens hardcoded in CI workflows (uses GitHub
  defaults only)
- SEC-2: Version string is compile-time constant; no runtime file reads
  or network calls for version info
- SEC-3: License text is embedded at compile time; no runtime file reads

## Failure Modes / Error Mapping

| Condition             | Output (stderr/stdout)      | Exit |
|-----------------------|-----------------------------|------|
| `--version`           | stdout: `trim <ver>`      | 0    |
| `-v`                  | stdout: `trim <ver>`      | 0    |
| `--license`           | stdout: MIT license text    | 0    |
| `-l`                  | stdout: MIT license text    | 0    |

## Test Matrix (mandatory)

| AC     | Integration |
|--------|-------------|
| AC-1   | ✅           |
| AC-2   | ✅           |
| AC-3   | ✅           |
| AC-4   | ✅           |
| AC-5   | ✅           |
| AC-6   | ✅           |
| AC-7   | ⬜           |
| AC-8   | ⬜           |
| AC-9   | ⬜           |
| AC-10  | ⬜           |
| AC-11  | ✅           |
| AC-12  | ✅           |
| SEC-1  | ⬜           |
| SEC-2  | ✅           |
| SEC-3  | ✅           |

Notes:
- AC-7 through AC-10: CI/CD pipeline behavior verified by GitHub Actions,
  not by local integration tests
- SEC-1: Verified by code review of workflow YAML files
- All local tests run inside Docker containers (test.sh)
