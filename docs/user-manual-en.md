# trim — User Manual

> **trim** — Target-agnostic Removal of Inert Metadata

## Prerequisites

- Docker Engine 20.10+ or Docker Desktop
- Docker Compose V2
- Docker Buildx (for multi-arch builds / `dist.sh`)

## Installation

### Option 1: Pre-built Static Binary

If distributable binaries have been built with `dist.sh`:

```bash
# Extract the binary for your architecture
tar -xzf dist/trim-linux-amd64.tar.gz -C /usr/local/bin/   # x86_64
tar -xzf dist/trim-linux-arm64.tar.gz -C /usr/local/bin/   # aarch64
```

These are fully static musl binaries with zero runtime dependencies.
They run on any Linux distribution.

### Option 2: Docker Image

```bash
git clone <repo-url>
cd trim
docker compose build strip
```

Build for a specific platform:

```bash
docker buildx build --platform linux/arm64 -t trim .
```

## Usage

### Analyze dead code (read-only)

```bash
trim --dry-run /path/to/binary
```

### Write patched binary to output file

```bash
trim /path/to/binary /path/to/output
```

### Write patched binary to stdout

```bash
trim /path/to/binary > /path/to/output
```

### Pipe: read stdin, write to stdout

```bash
cat /path/to/binary | trim - > /path/to/output
```

### In-place modification

```bash
trim -i /path/to/binary
trim -i /path/to/app1 /path/to/app2
```

### Via Docker

```bash
docker run --rm -v $(pwd)/myapp:/work/myapp trim-strip -i /work/myapp
docker run --rm -v $(pwd)/myapp:/work/myapp trim-strip --dry-run /work/myapp
docker run --rm -i trim-strip - < myapp > myapp.patched
```

### Via docker compose

```bash
docker compose run --rm strip -i /work/myapp
```

## Supported Formats

| Format | Analyze | Compact | Architectures | Notes |
|--------|---------|---------|---------------|-------|
| ELF | Yes | Yes | x86-64, x86-32, AArch64, ARM32, RISC-V, MIPS, s390x, LoongArch64 | Physical compaction + offset patching |
| PE/COFF | Yes | Yes | x86-64, x86-32, AArch64, ARM32 | Physical compaction + metadata patching |
| Mach-O | Yes | Yes | x86-64, AArch64, ARM32 | Physical compaction + load command patching |
| .NET | Yes | Yes | IL (arch-independent) | Dead method compaction via PE pipeline |
| WebAssembly | Yes | Yes | Wasm | Code section rebuild |
| Java .class | Yes | Yes | JVM bytecode | Dead method removal |

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

| Code | Meaning |
|------|---------|
| 0 | All files processed successfully |
| 1 | One or more files failed or errors |

## Distribution

| Platform | Archive | Target |
|----------|---------|--------|
| `linux/amd64` | `trim-linux-amd64.tar.gz` | `x86_64-unknown-linux-musl` |
| `linux/arm64` | `trim-linux-arm64.tar.gz` | `aarch64-unknown-linux-musl` |

## Troubleshooting

- **"Permission denied":** The file must be writable. With Docker,
  match the container user uid with `--user $(id -u):$(id -g)`.
- **"not found":** The file path does not exist or is not a regular file.
- **"not writable":** The file is read-only; `chmod u+w` to fix.
- **"skipped":** The file is not a recognized binary format or has no
  functions to analyze.
