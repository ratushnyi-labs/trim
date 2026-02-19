# SDD-001 -- Compliance Gap Remediation

**Impacted UCs:** UC-001, UC-002, UC-003
**Impacted BR/WF:** BR-001 through BR-009, WF-001, WF-002

## Scope / Non-goals

**Scope:**

- Reconstruct `docs/spec.md` from codebase (per rules.md section 4.1)
- Create mandatory documentation (development, installation, configuration manuals)
- Refactor library for testability (extract compress/decompress to library modules)
- Add unit tests with 100% coverage (lines, branches, functions)
- Add integration tests with 100% coverage
- Add security/adversarial tests labeled with `[SEC]`
- Update CI pipeline with quality, test, and audit stages
- Create this Speck file

**Non-goals:**

- Docker container test infrastructure (N/A: CLI tool, not client-server)
- UI testing, curl testing (N/A: no API, no UI)
- Behavioral changes to xsfx
- Dependency version upgrades (current versions are appropriate)

## Acceptance Criteria

- AC-1: `docs/spec.md` exists and follows rules.md template with UCs, BRs, WFs
- AC-2: `docs/development-manual.md` exists
- AC-3: `docs/installation-manual.md` exists
- AC-4: `docs/configuration-manual.md` exists
- AC-5: Unit tests pass with 100% line/function coverage of library code
- AC-6: Integration tests pass covering full SFX round-trip
- AC-7: CI includes quality (clippy + fmt), test, and audit stages
- AC-8: Security tests labeled with `[SEC]` prefix in test names
- AC-9: No behavioral changes to xsfx

## Security Acceptance Criteria (mandatory)

- SEC-1: Malformed trailer data handled gracefully (no panic, error returned)
- SEC-2: Corrupted compressed data handled gracefully (error returned)
- SEC-3: Truncated input handled gracefully (error returned)
- SEC-4: Boundary values (zero, max u64) handled without overflow or panic

## Failure Modes / Error Mapping

N/A -- documentation and testing task, no new runtime behavior introduced.

## Test Matrix (mandatory)

| AC    | Unit | Integration | Curl Dev | Base UI | UI | Curl Prod API | Prod Fullstack |
|-------|------|-------------|----------|---------|----|---------------|----------------|
| AC-5  | Y    | --          | --       | --      | -- | --            | --             |
| AC-6  | --   | Y           | --       | --      | -- | --            | --             |
| SEC-1 | Y    | Y           | --       | --      | -- | --            | --             |
| SEC-2 | Y    | Y           | --       | --      | -- | --            | --             |
| SEC-3 | Y    | Y           | --       | --      | -- | --            | --             |
| SEC-4 | Y    | Y           | --       | --      | -- | --            | --             |

Notes:

- Curl/UI/Prod stages marked `--` (not applicable: CLI tool with no API or UI).
- Every AC has positive + negative test cases.
- `SEC-*` tests run within unit and integration stages (not isolated).
