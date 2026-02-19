# SDD-007 — Multi-arch Static Binary Distribution (x86_64 + aarch64)

**Impacted UCs:** UC-001, UC-002, UC-003
**Impacted BR/WF:** BR-006 / WF-001

## Scope / Non-goals

**Scope:**
- Cross-compile xstrip for both x86_64 and aarch64 Linux using Docker `xx`
- Add an `export` stage to Dockerfile for `--output type=local` binary extraction
- Create `dist.sh` script to produce both platform binaries in `dist/`
- Update Dockerfile.test builder to use `xx` (test runtime unchanged)

**Non-goals:**
- macOS or Windows native binaries (Linux-only)
- QEMU emulation (cross-compilation only, no emulated builds)
- Changing `.cargo/config.toml` (kept for local development)
- Changing `docker-compose.yml` (builds for native platform by default)
- Multi-arch Docker image (manifest list / `docker buildx --push`)

## Acceptance Criteria

- AC-1: `docker compose run --rm test` passes all existing tests
- AC-2: `docker buildx build --platform linux/amd64` succeeds
- AC-3: `docker buildx build --platform linux/arm64` succeeds
- AC-4: `dist.sh` produces `dist/xstrip-linux-amd64.tar.gz` (ELF x86-64, static)
- AC-5: `dist.sh` produces `dist/xstrip-linux-arm64.tar.gz` (ELF aarch64, static)
- AC-6: `.cargo/` directory is NOT copied into the Docker builder
- AC-7: Runtime stage unchanged (scratch, non-root uid 10000, healthcheck)

## Security Acceptance Criteria (mandatory)

- SEC-1: Build does not download unsigned/unverified toolchains (xx uses apk packages)
- SEC-2: Production image remains scratch-based with non-root user
- SEC-3: No new network-facing surface introduced (CLI tool, no listeners)

## Failure Modes / Error Mapping

- If `xx-cargo` fails for a target: build fails with clear error from cargo
- If target musl-dev not available: `xx-apk` fails early with package-not-found
- If buildx not available: `dist.sh` exits with clear error message

## Test Matrix (mandatory)

| AC    | Integration |
|-------|-------------|
| AC-1  | `docker compose run --rm test` (all 70 tests) |
| AC-2  | `docker buildx build --platform linux/amd64` |
| AC-3  | `docker buildx build --platform linux/arm64` |
| AC-4  | `dist/xstrip-linux-amd64.tar.gz` contains ELF x86-64 static |
| AC-5  | `dist/xstrip-linux-arm64.tar.gz` contains ELF aarch64 static |
| AC-6  | Dockerfile inspection (no COPY .cargo) |
| AC-7  | Dockerfile inspection (scratch, USER 10000, HEALTHCHECK) |
| SEC-1 | xx uses distro packages only |
| SEC-2 | Dockerfile inspection |
| SEC-3 | No EXPOSE, no listener code |
