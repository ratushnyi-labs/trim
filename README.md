# xstrip

Dead code analyzer and remover for compiled binaries.

xstrip finds unreachable functions and dead branches in compiled binaries
using address-based call graph analysis, patches them with zero-fills, and
for x86 ELF physically shrinks the binary. Supports ELF, PE/COFF, Mach-O,
.NET assemblies, and WebAssembly across 8+ architectures. It works directly
on the binary — no source code or recompilation needed.

## Quick Start

```bash
# Analyze without modifying (report to stderr)
xstrip --dry-run /path/to/binary

# Stream: write patched binary to output file
xstrip /path/to/binary /path/to/output

# Stream: write patched binary to stdout
xstrip /path/to/binary > /path/to/output

# Pipe: read stdin, write patched binary to stdout
cat /path/to/binary | xstrip - > /path/to/output

# In-place modification (single or multiple files)
xstrip -i /path/to/binary
xstrip -i app server.so lib.a
```

### Via Docker

```bash
docker compose build strip
docker run --rm -v $(pwd)/myapp:/work/myapp xstrip-strip --dry-run /work/myapp
docker run --rm -v $(pwd)/myapp:/work/myapp xstrip-strip -i /work/myapp
docker run --rm -i xstrip-strip - < myapp > myapp.patched
```

### Via host wrapper

```bash
# Auto-builds the Docker image on first run (always in-place)
./xstrip.sh --dry-run /path/to/binary
./xstrip.sh /path/to/binary
```

## How It Works

1. Auto-detects binary format from magic bytes (ELF, PE/COFF, Mach-O, .NET, WebAssembly)
2. Parses headers, symbol tables, and section metadata
3. Decodes instructions for the target architecture (x86-64, x86-32, AArch64, ARM32, RISC-V, MIPS, s390x, LoongArch64) or IL opcodes (.NET) or Wasm function bodies
4. Builds an address-based call graph from branch/call targets and cross-references
5. BFS reachability from roots (entry point, global symbols, data-section references)
6. Detects dead branches within live functions via CFG analysis, intra-function compaction, and SSA-based constant propagation
7. Patches unreachable code with zero-fills (x86 ELF also physically shrinks the binary)

Works on stripped binaries (no `.symtab`), statically linked binaries, shared
libraries, Windows PE executables/DLLs, Mach-O objects, .NET assemblies, and
WebAssembly modules. No source code or recompilation needed.

## Example Output

```
analyzing: /work/hello (26840 bytes)
  found 30 dead functions (7570 bytes):
    dead_f01: 281 bytes @ 0x11f9
    dead_f03: 270 bytes @ 0x1414
    ...
  reassembled: 30 dead functions removed, 7570 bytes freed
Size: 26840 -> 22744 bytes
```

## Supported Formats

| Format | Analyze | Patch | Architectures | Notes |
|--------|---------|-------|---------------|-------|
| ELF | Yes | Yes | x86-64, x86-32, AArch64, ARM32, RISC-V, MIPS, s390x, LoongArch64 | Compact+shrink for x86, zero-fill for others |
| PE/COFF | Yes | Yes | x86-64, x86-32, AArch64, ARM32 | Zero-fill patching |
| Mach-O | Yes | Yes | x86-64, AArch64, ARM32 | Zero-fill patching |
| .NET | Yes | Yes | IL (arch-independent) | IL-level dead method detection |
| WebAssembly | Yes | Yes | Wasm | Function-level call graph analysis |

## Options

```
Usage: xstrip [OPTIONS] <INPUT> [OUTPUT]

Modes:
  xstrip INPUT OUTPUT       Write patched binary to OUTPUT
  xstrip INPUT              Write patched binary to stdout
  xstrip -                  Read stdin, write to stdout
  xstrip -i FILE [FILE...]  Modify files in-place
  xstrip --dry-run INPUT    Analyze only, report to stderr

Options:
  --in-place, -i   Modify files in-place
  --dry-run        Report dead code without producing output
  --version, -v    Show version
  --license, -l    Show license
  --help, -h       Show this help message
```

All diagnostic output goes to stderr. Binary output goes to stdout or
the named output file.

## Distribution

Static musl binaries with zero runtime dependencies:

| Platform | Archive | Target |
|----------|---------|--------|
| Linux x86_64 | `xstrip-linux-amd64.tar.gz` | `x86_64-unknown-linux-musl` |
| Linux aarch64 | `xstrip-linux-arm64.tar.gz` | `aarch64-unknown-linux-musl` |

Each archive contains a single `xstrip` binary with executable permissions.

```bash
sh dist.sh          # builds both to dist/
ls -lh dist/        # confirm archives
```

Docker image is `scratch`-based (~2 MiB), non-root (uid 10000).

## Building

Requires Docker with Compose V2 and Buildx:

```bash
docker compose build strip    # production image (native arch)
docker compose run --rm test  # run test suite (171 tests)
sh dist.sh                    # static binaries for amd64 + arm64
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All files processed successfully |
| 1 | One or more files failed or no arguments given |

## Documentation

- [Specification](docs/spec.md)
- [Installation Manual](docs/installation-manual.md)
- [Development Manual](docs/development-manual.md)
- [Configuration Manual](docs/configuration-manual.md)
