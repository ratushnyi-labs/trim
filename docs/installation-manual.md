# Installation Manual

## Prerequisites

- Docker Engine 20.10+ or Docker Desktop
- Docker Compose V2
- Docker Buildx (for multi-arch builds / `dist.sh`)

## Option 1: Pre-built Static Binary

If distributable binaries have been built with `dist.sh`:

```bash
# Extract the binary for your architecture
tar -xzf dist/xstrip-linux-amd64.tar.gz -C /usr/local/bin/   # x86_64
tar -xzf dist/xstrip-linux-arm64.tar.gz -C /usr/local/bin/   # aarch64
```

These are fully static musl binaries with zero runtime dependencies.
They run on any Linux distribution.

### Build distributable binaries

```bash
sh dist.sh
```

Produces `dist/xstrip-linux-amd64.tar.gz` and `dist/xstrip-linux-arm64.tar.gz`.
Each archive contains a single `xstrip` binary with executable permissions.

## Option 2: Docker Image

### Build the image

```bash
git clone <repo-url>
cd xstrip
docker compose build strip
```

### Build for a specific platform

```bash
docker buildx build --platform linux/arm64 -t xstrip .
```

## Usage

### Analyze dead code (read-only, report to stderr)

```bash
xstrip --dry-run /path/to/binary
```

### Stream: write patched binary to output file

```bash
xstrip /path/to/binary /path/to/output
```

### Stream: write patched binary to stdout

```bash
xstrip /path/to/binary > /path/to/output
```

### Pipe: read stdin, write to stdout

```bash
cat /path/to/binary | xstrip - > /path/to/output
```

### In-place modification

```bash
xstrip -i /path/to/binary
xstrip -i /path/to/app1 /path/to/app2
```

### Via Docker

```bash
docker run --rm -v $(pwd)/myapp:/work/myapp xstrip-strip -i /work/myapp
docker run --rm -v $(pwd)/myapp:/work/myapp xstrip-strip \
    --dry-run /work/myapp
docker run --rm -i xstrip-strip - < myapp > myapp.patched
```

### Via docker compose

```bash
# Place files in ./work/ directory
docker compose run --rm strip -i /work/myapp
```

## Supported Formats

| Format      | Analyze | Patch | Architectures       | Notes                          |
|-------------|---------|-------|----------------------|--------------------------------|
| ELF         | Yes     | Yes   | x86-64, x86-32, AArch64, ARM32, RISC-V, MIPS, s390x, LoongArch64 | Physical compaction + offset patching |
| PE/COFF     | Yes     | Yes   | x86-64, x86-32, AArch64, ARM32 | Physical compaction + metadata patching |
| Mach-O      | Yes     | Yes   | x86-64, AArch64, ARM32 | Physical compaction + load command patching |
| .NET        | Yes     | Yes   | IL (arch-independent) | IL dead method compaction via PE pipeline |
| WebAssembly | Yes     | Yes   | Wasm                 | Code section rebuild, function-level analysis |
| Java .class | Yes     | Yes   | JVM bytecode         | Dead method removal, bytecode call graph |

## Output

Analysis mode reports dead functions found:

```text
analyzing: /work/myapp (20528 bytes)
  found 5 dead functions (230 bytes):
    dead_compute: 53 bytes @ 0x1195
    dead_factorial: 43 bytes @ 0x11d7
    ...
```

Patch mode removes dead code and reports freed bytes:

```text
  reassembled: 5 dead functions removed, 230 bytes freed
```

## Exit Codes

| Code | Meaning                            |
|------|------------------------------------|
| 0    | All files processed successfully   |
| 1    | One or more files failed or errors |

## Architectures

| Platform       | Archive                         | Target Triple                  |
|----------------|---------------------------------|--------------------------------|
| `linux/amd64`  | `xstrip-linux-amd64.tar.gz`    | `x86_64-unknown-linux-musl`    |
| `linux/arm64`  | `xstrip-linux-arm64.tar.gz`    | `aarch64-unknown-linux-musl`   |

## Troubleshooting

- **"Permission denied":** The file must be writable. On Linux with Docker,
  match the container user uid with `--user $(id -u):$(id -g)`.
- **"not found":** The file path does not exist or is not a regular file.
- **"not writable":** The file is read-only; `chmod u+w` to fix.
- **"skipped":** The file is not a recognized binary format (ELF, PE,
  Mach-O, .NET, Wasm, Java .class) or has no functions to analyze.

## Reverse Proxy Support

N/A -- xstrip is a CLI tool, not a network service. No proxy configuration
is needed.
