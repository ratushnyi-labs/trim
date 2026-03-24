<p align="center">
  <img src="assets/logo.png" alt="trim logo" width="200">
</p>

<h1 align="center">trim</h1>
<p align="center"><strong>Target-agnostic Removal of Inert Metadata</strong></p>

<p align="center">
Dead code analyzer and remover for compiled binaries.<br>
Supports ELF, PE/COFF, Mach-O, .NET, WebAssembly, and Java&nbsp;.class across 8+ architectures.<br>
Physically shrinks binaries &mdash; no source code or recompilation needed.
</p>

---

## Documentation

| | Language | Manual |
|---|----------|--------|
| :gb: | English | [User Manual](docs/user-manual-en.md) |
| :fr: | Français | [Manuel utilisateur](docs/user-manual-fr.md) |
| :ukraine: | Українська | [Посібник користувача](docs/user-manual-ua.md) |
| :es: | Español | [Manual de usuario](docs/user-manual-es.md) |
| :portugal: | Português | [Manual do utilizador](docs/user-manual-pt.md) |
| :it: | Italiano | [Manuale utente](docs/user-manual-it.md) |

Developer docs: [Specification](docs/spec.md) · [Development](docs/development-manual.md) · [Configuration](docs/configuration-manual.md)

---

## Quick Start

```bash
# Analyze without modifying (report to stderr)
trim --dry-run /path/to/binary

# Stream: write patched binary to output file
trim /path/to/binary /path/to/output

# Stream: write patched binary to stdout
trim /path/to/binary > /path/to/output

# Pipe: read stdin, write patched binary to stdout
cat /path/to/binary | trim - > /path/to/output

# In-place modification (single or multiple files)
trim -i /path/to/binary
trim -i app server.so lib.a
```

### Via Docker

```bash
docker compose build strip
docker run --rm -v $(pwd)/myapp:/work/myapp trim-strip --dry-run /work/myapp
docker run --rm -v $(pwd)/myapp:/work/myapp trim-strip -i /work/myapp
docker run --rm -i trim-strip - < myapp > myapp.patched
```

## How It Works

1. Auto-detects binary format from magic bytes (ELF, PE/COFF, Mach-O, .NET, WebAssembly, Java .class)
2. Parses headers, symbol tables, and section metadata
3. Decodes instructions for the target architecture or bytecode format
4. Builds a call graph from branch/call targets, IL opcodes, or JVM invoke instructions
5. BFS reachability from roots (entry point, global symbols, data-section references)
6. Detects dead branches within live functions via CFG analysis and SSA-based constant propagation
7. Physically compacts dead code: removes dead regions, patches offsets, and updates format metadata

Works on stripped binaries, statically linked binaries, shared libraries, Windows PE
executables/DLLs, Mach-O objects, .NET assemblies, WebAssembly modules, and Java .class files.

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

| Format | Analyze | Compact | Architectures | Notes |
|--------|---------|---------|---------------|-------|
| ELF | Yes | Yes | x86-64, x86-32, AArch64, ARM32, RISC-V, MIPS, s390x, LoongArch64 | Dead regions removed, offsets patched |
| PE/COFF | Yes | Yes | x86-64, x86-32, AArch64, ARM32 | Dead regions removed, metadata patched |
| Mach-O | Yes | Yes | x86-64, AArch64, ARM32 | Dead regions removed, load commands patched |
| .NET | Yes | Yes | IL (arch-independent) | Dead methods compacted via PE pipeline |
| WebAssembly | Yes | Yes | Wasm | Code section rebuilt with minimal stubs |
| Java .class | Yes | Yes | JVM bytecode | Dead methods physically removed |

## Options

```
Usage: trim [OPTIONS] <INPUT> [OUTPUT]

Modes:
  trim INPUT OUTPUT       Write patched binary to OUTPUT
  trim INPUT              Write patched binary to stdout
  trim -                  Read stdin, write to stdout
  trim -i FILE [FILE...]  Modify files in-place
  trim --dry-run INPUT    Analyze only, report to stderr

Options:
  --in-place, -i   Modify files in-place
  --dry-run        Report dead code without producing output
  --version, -v    Show version
  --license, -l    Show license
  --help, -h       Show this help message
```

All diagnostic output goes to stderr. Binary output goes to stdout or the named output file.

## Distribution

Static musl binaries with zero runtime dependencies:

| Platform | Archive | Target |
|----------|---------|--------|
| Linux x86_64 | `trim-linux-amd64.tar.gz` | `x86_64-unknown-linux-musl` |
| Linux aarch64 | `trim-linux-arm64.tar.gz` | `aarch64-unknown-linux-musl` |

Each archive contains a single `trim` binary with executable permissions.

```bash
sh dist.sh          # builds both to dist/
ls -lh dist/        # confirm archives
```

Docker image is `scratch`-based (~2 MiB), non-root (uid 10000).

## Building

Requires Docker with Compose V2 and Buildx:

```bash
docker compose build strip    # production image (native arch)
docker compose run --rm test  # run test suite
sh dist.sh                    # static binaries for amd64 + arm64
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All files processed successfully |
| 1 | One or more files failed or no arguments given |
