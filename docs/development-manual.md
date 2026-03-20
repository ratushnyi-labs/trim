# Development Manual

## Prerequisites

- Docker Engine 20.10+ or Docker Desktop (required for building and testing)
- Docker Compose V2 (included with Docker Desktop)
- Docker Buildx (included with Docker Desktop; required for `dist.sh`)
- No other host dependencies are needed

## Repository Structure

```text
Cargo.toml          Rust project manifest (dependencies, release profile)
Cargo.lock          Dependency lock file (reproducible builds)
src/                Rust source code
  main.rs           CLI entry point
  lib.rs            Core analysis and patching logic (format dispatch)
  arch/             Architecture-specific decoders
    x86.rs          x86-64/x86-32 decoder (iced-x86)
    x86_patch.rs    x86 padding/patching
    aarch64.rs      AArch64 decoder (custom)
    aarch64_patch.rs AArch64 padding
    arm32.rs        ARM32 decoder (custom)
    arm32_patch.rs  ARM32 padding
    riscv.rs        RISC-V RV32/RV64+C decoder (custom)
    riscv_patch.rs  RISC-V padding
    mips.rs         MIPS32/64 decoder (custom)
    mips_patch.rs   MIPS padding
    s390x.rs        s390x decoder (custom, variable-length)
    s390x_patch.rs  s390x padding
    loongarch.rs    LoongArch64 decoder (custom)
    loongarch_patch.rs LoongArch padding
  format/           Format-specific modules
    elf/            ELF analysis, sections, symbols, patching
    pe/             PE/COFF analysis, sections, symbols
    macho/          Mach-O analysis, sections, symbols
    dotnet/         .NET IL metadata parsing, call graph, patching
    wasm/           WebAssembly function-level analysis (wasmparser)
    java/           Java .class file parser, bytecode call graph
  analysis/         Format-agnostic reachability analysis
  decode/           Instruction decoding, call graph, function inference
  patch/            Shared patching utilities (zero-fill, compact, relocs)
Dockerfile          Multi-arch production image (xx + scratch)
Dockerfile.test     Multi-arch test image (xx + Alpine runtime)
docker-compose.yml  Services: strip (production), test (testing)
dist.sh             Build static binaries for amd64 + arm64
xstrip.sh           Host-side wrapper (builds image, runs container)
.cargo/config.toml  Local cargo config (x86_64-musl target, not used in Docker)
.dockerignore       Files excluded from Docker build context
.gitignore          Git ignore rules
.env                Environment configuration (minimal for CLI tool)
zscaler.crt         Corporate TLS proxy CA certificate
tests/
  test.sh           Integration test suite (shell-based)
  hello.c           Test program with dead functions
  lib.c             Shared library test with dead internals
  arm-hello.c       ARM nostdlib test program (AArch64/ARM32)
  riscv-hello.c     RISC-V nostdlib test program (RV64GC)
  mips-hello.c      MIPS nostdlib test program (big-endian)
  s390x-hello.c     s390x nostdlib test program
  loongarch-hello.c LoongArch64 nostdlib test program
  tail-dead.c       Test for tail-position dead code removal
  big-dead.c        Test for large dead code physical shrinking
  dead-branch.c     Dead branch after noreturn call (exit)
  combined-dead.c   Combined dead functions + dead branches
  gen_dotnet.py     Generator for minimal .NET test assembly
  gen_java.py       Generator for minimal Java .class test file
docs/
  spec.md           Business specification
  rules.md          Development rules
  specks/           Speck-driven development task files
  development-manual.md   This file
  installation-manual.md  Installation instructions
  configuration-manual.md Configuration reference
```

## Building

### Build the production image (native platform)

```bash
docker compose build strip
```

### Build the test image

```bash
docker compose build test
```

### Cross-compile for a specific platform

```bash
docker buildx build --platform linux/arm64 .
```

### Build distributable binaries for both architectures

```bash
sh dist.sh
```

This produces `dist/xstrip-linux-amd64.tar.gz` and `dist/xstrip-linux-arm64.tar.gz`
(archives containing static musl binaries with executable permissions).

## Multi-arch Build System

The Dockerfiles use [tonistiigi/xx](https://github.com/tonistiigi/xx)
for cross-compilation:

- Builder runs natively on the host architecture (`$BUILDPLATFORM`)
- `xx-cargo` cross-compiles Rust to the target via musl cross-toolchain
- `xx-verify` validates the binary matches `$TARGETPLATFORM`
- No QEMU emulation needed — native compilation speed

Supported targets:

| Platform       | Rust Target                    |
|----------------|--------------------------------|
| `linux/amd64`  | `x86_64-unknown-linux-musl`    |
| `linux/arm64`  | `aarch64-unknown-linux-musl`   |

Binary stripping is handled by `strip = true` in `Cargo.toml`'s
`[profile.release]`, which uses Rust's bundled LLVM strip.

**Note:** `.cargo/config.toml` sets a hardcoded x86_64 target for local
`cargo build`. It is excluded from the Docker build context via
`.dockerignore` so it does not conflict with `xx-cargo`.

## Testing (Docker -- primary method)

All tests run inside Docker containers.

### Run the full test suite

```bash
docker compose run --build --rm test
```

This executes the integration tests that:

1. Compile test executables with dead code (ELF dynamic, static, shared library)
2. Cross-compile PE (Windows) EXE and DLL test binaries
3. Cross-compile Mach-O object files (arm64-apple-macosx)
4. Cross-compile AArch64, ARM32, RISC-V, MIPS, s390x, and LoongArch64 ELF binaries
5. Generate .NET managed assembly test fixture
6. Generate Java .class file test fixture (gen_java.py)
7. Verify dead code detection across all formats (no false positives)
8. Verify in-place patched binaries execute correctly with expected output
9. Verify physical file size reduction for large dead code (x86 ELF)
10. Verify already-stripped binaries are handled correctly
11. Test error handling (missing files, non-writable, no args)
12. Test security scenarios (path traversal, symlinks, corrupted files)
13. Verify stream mode (input → output file, input → stdout)
14. Verify pipe mode (stdin → stdout)
15. Verify dry-run over pipe (stdin analysis)

### Test program design

Test C files contain intentional dead code patterns:

- `hello.c` — dead functions with computation, string returns, table
  lookups, buffer fills; live functions called from `main`
- `lib.c` — shared library with dead internal functions; exported
  functions must be preserved (also used for PE DLL and Mach-O object)
- `arm-hello.c` — minimal nostdlib program with dead functions; uses
  inline asm for syscall exit (AArch64/ARM32/x86-64)
- `tail-dead.c` — dead functions at end of .text section
- `big-dead.c` — 30 large dead functions (>7KB) to test physical shrinking
- `gen_dotnet.py` — generates minimal .NET PE assembly with Main,
  LiveHelper (live), DeadMethod1, DeadMethod2 (dead)
- `gen_java.py` — generates minimal Java .class file (version 52/Java 8)
  with `<init>`, main, liveHelper (live), deadMethod1, deadMethod2 (dead);
  call graph uses invokestatic for liveHelper, invokespecial for super init

## Quick manual test

```bash
# Analyze dead code without modifying
docker run --rm -v /path/to/binary:/work/binary xstrip-strip \
    --dry-run /work/binary

# Remove dead code (in-place)
docker run --rm -v /path/to/binary:/work/binary xstrip-strip \
    --in-place /work/binary

# Stream mode via pipe (stdin → stdout)
docker run --rm -i xstrip-strip - < /path/to/binary > /path/to/output
```
