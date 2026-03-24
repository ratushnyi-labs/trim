# TASK-014 -- Wasm/.NET Physical Compaction & Java .class File Support

**Status:** DONE
**Created:** 2026-03-20  **Updated:** 2026-03-20

## Raw Request
> the core idea to shrink the file by eliminating the dead code. so file
> shrinking is the goal. and add java

## Refined Description
**Scope:** Physical file compaction for Wasm and .NET formats (previously
only nop-filled), plus new Java .class file format support with dead
method removal.

**Non-goals:** JAR support, Wasm dead branch physical removal, .NET dead
branch physical removal, Java annotation stripping.

**Impacted UCs:** UC-001, UC-002, UC-003, UC-004
**Impacted BR/WF:** BR-002, BR-003, BR-009, BR-010 (new), WF-001
**Dependencies:** SDD-013 (dead code scanning foundation)
**Risks / Open Questions:** None remaining.

## Estimation
**Level:** LOW
**Justification:** Well-scoped across three phases, each self-contained.
Wasm ~120 lines, .NET ~150 lines, Java ~600 lines new module. All builds
on existing infrastructure.

## Speck Reference
docs/specks/SDD-014-wasm-dotnet-compaction-java.md
