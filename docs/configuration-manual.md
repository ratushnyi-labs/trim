# Configuration Manual

## Runtime Configuration

xstrip is configured entirely via CLI arguments. There are no environment
variables, config files, or runtime settings.

### CLI Options

| Option              | Description                                  |
|---------------------|----------------------------------------------|
| `--in-place`, `-i`  | Modify files in-place (multiple files allowed) |
| `--dry-run`         | Report dead code without producing output    |
| `--version`, `-v`   | Show version                                 |
| `--license`, `-l`   | Show MIT license                             |
| `--help`, `-h`      | Show usage message                           |

### Arguments

Without `--in-place`: first positional argument is the input file (or `-`
for stdin), optional second argument is the output file. If no output file
is given, patched binary is written to stdout.

With `--in-place`: all positional arguments are treated as file paths to
modify in-place. At least one file path is required.

### Output Streams

All diagnostic output (analysis reports, errors) goes to stderr.
Binary output goes to stdout or the named output file.

## Docker Image Details

### Base Images

| Stage   | Image                          | Version | Justification                     |
|---------|--------------------------------|---------|-----------------------------------|
| xx      | `tonistiigi/xx`                | 1.9.0   | Cross-compilation helper          |
| builder | `rust:1.93-alpine3.23`         | 1.93    | Rust compiler on musl             |
| export  | `scratch`                      | —       | Binary extraction stage           |
| runtime | `scratch`                      | —       | Minimal: static binary only       |

The production image is `scratch` (empty) because xstrip is a fully
static musl binary with zero runtime dependencies. This is the highest
priority per §8.3 (smaller than distroless).

### Build Dependencies (builder stage only)

| Package    | Purpose                                      |
|------------|----------------------------------------------|
| clang      | C/C++ compiler used by xx as cross-linker    |
| lld        | LLVM linker for cross-compilation            |
| file       | Binary format detection for `xx-verify`      |
| musl-dev   | Target platform musl headers (via `xx-apk`)  |

### Runtime Dependencies

None. The binary is statically linked against musl libc.

### Image Size

| Image   | Size   |
|---------|--------|
| runtime | ~2 MiB |

### Container User

The container runs as uid 10000 (non-root). When mounting files from the
host via Docker, ensure the file is writable by the container user.
Use `--user $(id -u):$(id -g)` to match the host user identity.

### Health Check

The image defines a HEALTHCHECK that runs `xstrip --help`. This is
primarily for orchestration systems that monitor container health.

## Multi-arch Support

The Dockerfiles use `tonistiigi/xx` for cross-compilation. The builder
always runs on the host's native architecture (`$BUILDPLATFORM`) and
cross-compiles to the target (`$TARGETPLATFORM`).

| Target Platform | Rust Target                    | Archive                         |
|-----------------|--------------------------------|---------------------------------|
| `linux/amd64`   | `x86_64-unknown-linux-musl`    | `xstrip-linux-amd64.tar.gz`   |
| `linux/arm64`   | `aarch64-unknown-linux-musl`   | `xstrip-linux-arm64.tar.gz`   |

Binary stripping is handled by Cargo's `strip = true` in `[profile.release]`,
which uses Rust's bundled LLVM strip. No external `strip` binary is needed.

## Cargo Release Profile

```toml
[profile.release]
opt-level = "z"      # Optimize for size
lto = true           # Link-time optimization (full)
strip = true         # Strip debug symbols via LLVM
panic = "abort"      # No unwinding overhead
codegen-units = 1    # Single codegen unit for best optimization
```

## TLS Proxy Support

For corporate environments with TLS-intercepting proxies (e.g., Zscaler),
the `zscaler.crt` certificate is baked into the builder image at build
time and appended to the system CA bundle. This allows crate downloads
and `apk` package installation during the Docker build.

To use a different CA certificate, replace `zscaler.crt` before building.

## Test Configuration

The test image (`Dockerfile.test`) uses the same `xx`-based builder as
production. The test runtime stage is Alpine 3.23 with additional packages:

| Package         | Purpose                              |
|-----------------|--------------------------------------|
| gcc             | Compile ELF test binaries            |
| musl-dev        | C library headers for gcc            |
| clang19         | Cross-compile PE, Wasm, Mach-O tests |
| lld19           | LLVM linker for clang19              |
| llvm19          | llvm-strip for pre-stripped tests    |
| mingw-w64-gcc   | Cross-compile Windows PE binaries    |
| file            | Detect binary format in tests        |
