# SDD-003 -- Stub Minification & Ultra Compression

**Impacted UCs:** UC-001, UC-002
**Impacted BR/WF:** BR-013, BR-014

## Scope / Non-goals

**Scope:**

- Minimize stub binary size to < 100 KB across all platforms
- Use nightly Rust with `-Z build-std` and `panic=immediate-abort` to rebuild std optimized for size
- Eliminate formatting machinery (`eprintln!`, `format!`) from stub code paths
- Apply UPX post-build compression (multistage: tiny UPX decompressor + LZMA-compressed stub)
- Upgrade payload compression to LZMA2 ultra: extreme preset 9, x86 BCJ filter, 64 MiB dictionary, BinaryTree4 match finder, nice_len=273
- Update Dockerfile, CI, and release workflows for nightly stub builds + UPX

**Non-goals:**

- Rewriting the stub as `#![no_std]` (excessive complexity for marginal gains beyond UPX)
- Changing the SFX binary format or trailer structure
- Multi-threaded compression (single-threaded is sufficient for packing)

## Acceptance Criteria

- AC-1: Windows x64 stub < 100 KB after UPX compression
- AC-2: Linux x64 musl stub < 100 KB after UPX compression
- AC-3: Stub builds use nightly Rust with `-Z build-std=std,panic_abort` and `-Cpanic=immediate-abort`
- AC-4: UPX `--best --lzma` applied as post-build step in Dockerfile, CI, and release workflows
- AC-5: Native compression (`native-compress` feature) uses LZMA2 extreme preset with x86 BCJ filter
- AC-6: All existing tests pass (Docker test suite: fmt, clippy, coverage 100%, audit)
- AC-7: Decompression of ultra-compressed payloads works with the pure-Rust lzma-rs stub decoder

## Security Acceptance Criteria (mandatory)

- SEC-1: UPX compression does not alter stub execution behavior (functional equivalence)
- SEC-2: Ultra-compressed payloads decompress identically to original input (no data corruption)
- SEC-3: Dictionary size is capped at input size (no excessive memory allocation for small payloads)

## Failure Modes / Error Mapping

| Failure | Context | Resolution |
|---------|---------|------------|
| UPX not available | CI build | Install step fetches UPX; fails fast if download fails |
| Nightly compiler unavailable | CI build | Explicit `dtolnay/rust-toolchain@nightly` step |
| Ultra compression OOM | Large payloads with 64 MiB dict | Dict size capped to min(64 MiB, input.next_power_of_two()) |

## Test Matrix (mandatory)

| AC    | Unit | Integration | Curl Dev | Base UI | UI | Curl Prod API | Prod Fullstack |
|-------|------|-------------|----------|---------|----|---------------|----------------|
| AC-1  | --   | --          | --       | --      | -- | --            | --             |
| AC-2  | --   | --          | --       | --      | -- | --            | --             |
| AC-3  | --   | --          | --       | --      | -- | --            | --             |
| AC-4  | --   | --          | --       | --      | -- | --            | --             |
| AC-5  | Y    | --          | --       | --      | -- | --            | --             |
| AC-6  | Y    | Y           | --       | --      | -- | --            | --             |
| AC-7  | Y    | --          | --       | --      | -- | --            | --             |
| SEC-1 | --   | --          | --       | --      | -- | --            | --             |
| SEC-2 | Y    | --          | --       | --      | -- | --            | --             |
| SEC-3 | Y    | --          | --       | --      | -- | --            | --             |

Notes:

- AC-1/AC-2/AC-3/AC-4 verified via CI builds and size reporting, not unit tests.
- SEC-1 verified by functional testing of UPX-compressed stubs in CI.
- Existing roundtrip tests cover SEC-2 (compress with ultra → decompress with lzma-rs).
- Ultra compression only active with `native-compress` feature; pure-Rust fallback unchanged.
