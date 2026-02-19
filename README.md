# xstrip

Dead code analyzer and remover for ELF binaries.

xstrip finds unreachable functions in compiled binaries using address-based
call graph analysis, patches them with INT3 (`0xCC`) fills, and physically
shrinks the binary. It works directly on the binary — no source code or
recompilation needed.

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

1. Parses ELF headers and symbol tables (static + dynamic)
2. Disassembles `.text` with a full x86-64 decoder ([iced-x86](https://github.com/icedland/iced))
3. Builds an address-based call graph from branch/call targets and RIP-relative references
4. BFS reachability from roots (entry point, global symbols, data-section references)
5. Patches unreachable functions with `0xCC` (INT3)
6. Physically shrinks the binary by removing dead code bytes and updating all ELF metadata

Works on stripped binaries (no `.symtab`), statically linked binaries, and
shared libraries. Compilers already eliminate dead branches within functions
at `-O1`+; xstrip catches whole **functions** that the linker pulled in but
nothing calls.

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

| Format | Analyze | Patch | Notes |
|--------|---------|-------|-------|
| ELF executables | Yes | Yes | Dynamic and static linking |
| ELF shared libraries (.so) | Yes | Yes | Exports preserved |
| ELF stripped binaries | Yes | Yes | Function boundaries inferred |
| PE/COFF | — | — | Planned |
| Mach-O | — | — | Planned |

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
docker compose run --rm test  # run test suite (70 tests)
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
