# Contributing to trim

Thank you for your interest in contributing to trim.

## Code Quality Standards

All contributions must meet these standards. PRs that don't comply will be requested to fix before merge.

### Safety First

trim processes untrusted binary files. Every code path that reads from binary data must be defensive:

- **Bounds check all reads.** Every `read_u16()`, `read_u32()`, slice access from parsed offsets must check `offset + size <= data.len()` before accessing. Return `0`, `None`, or a safe default on out-of-bounds — never panic.
- **No `unwrap()` / `expect()` on binary data.** Use `?`, `.unwrap_or()`, or `.get()` instead. The only acceptable `unwrap()` is on infallible operations (e.g., `try_into()` on a known-size slice).
- **Checked arithmetic.** Use `saturating_add()`, `saturating_mul()`, or `checked_*()` for any offset/size computation derived from binary data. A crafted binary with `count = 0xFFFFFFFF` must not cause integer overflow.
- **No full-file clones.** Never `data.to_vec()` or `data.clone()` on the entire input. Clone only the minimal slice needed (e.g., a single function's bytecode).
- **Validate before patching.** Before writing patched bytes back, verify the target offset and size are within bounds. A compaction bug must not corrupt data beyond the dead region.

### Code Style

- **Max line width:** 120 characters
- **No dead code:** No unused functions, no `TODO` comments, no commented-out logic
- **Doc comments:** Public functions must have `///` doc comments explaining purpose and return value
- **Naming:** Follow Rust conventions. Snake_case for functions/variables, CamelCase for types, SCREAMING_SNAKE for constants
- **Error handling:** Functions that can fail return `Option<T>` or use `anyhow::Result`. No silent failures — log to stderr or propagate

### Architecture Rules

- **Format modules are self-contained.** Each format (`src/format/{elf,pe,macho,dotnet,wasm,java}/`) owns its analysis and compaction. Shared utilities live in `src/patch/` or `src/analysis/`.
- **No cross-format imports.** `format::elf` must not import from `format::pe`. Shared types go in `src/types.rs`.
- **Conservative analysis.** When in doubt, keep code alive. A false negative (missed dead code) is acceptable; a false positive (removing live code) is a critical bug.
- **Bail-out on complexity.** If a method has exception handlers, switch tables, or metadata that would break after compaction — bail out to nop-fill. Don't attempt unsafe transformations.

### Testing Requirements

- **All tests must pass:** `docker compose run --build --rm test` — zero failures
- **New features need tests:** Add assertions in `tests/test.sh` for any new detection or compaction behavior
- **Negative tests:** Malformed/truncated inputs must not crash — add a test case
- **No test modifications** without justification. Adding tests is always OK; changing existing assertions requires explanation

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add RISC-V compressed instruction support
fix: bounds check on Java constant pool read
docs: update supported formats table
ci: add macOS arm64 build target
test: add truncated Wasm negative test
refactor: extract PE section parser to shared module
```

### PR Process

1. Fork and create a feature branch (`feat/description` or `fix/description`)
2. Make changes following the standards above
3. Run `docker compose run --build --rm test` — all tests must pass
4. Open a PR using the template
5. One approval required for merge
6. Squash merge to `main`

## Supported Formats Reference

When adding or modifying format support, reference these:

| Format | Module | Magic | Spec |
|--------|--------|-------|------|
| ELF | `src/format/elf/` | `\x7fELF` | [System V ABI](https://refspecs.linuxfoundation.org/elf/elf.pdf) |
| PE/COFF | `src/format/pe/` | `MZ` | [Microsoft PE/COFF Spec](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) |
| Mach-O | `src/format/macho/` | `0xFEEDFACE/F` | [Mach-O Reference](https://github.com/nicowilliams/inmern.github.io/blob/master/docs/MachORuntime.pdf) |
| .NET | `src/format/dotnet/` | `MZ` + CLI header | [ECMA-335](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/) |
| WebAssembly | `src/format/wasm/` | `\x00asm` | [Wasm Spec](https://webassembly.github.io/spec/) |
| Java .class | `src/format/java/` | `0xCAFEBABE` | [JVM Spec Ch.4](https://docs.oracle.com/javase/specs/jvms/se21/html/jvms-4.html) |

## Getting Help

- Open an issue for questions
- Check [user manuals](https://github.com/ratushnyi-labs/trim#documentation) (6 languages)
- Read [docs/development-manual.md](docs/development-manual.md) for build/test instructions
