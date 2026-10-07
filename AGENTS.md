<!-- agent-rules:begin -->
# Agent Rules Reference

This repository is governed by the CodexOfLaws lawbook, served by the LeaseVibe MCP.

Default User Mode: GUIDED

Adoption pin (canonical here, mirrored in `CLAUDE.md`; change a field only through a recorded re-bind, §6.6.3.2 / §602.1.10):

<!-- adoption-authorization: rules_backend_mode=file->mcp ref=user-authorization -->

```yaml
adoption-pin:
  governed: true
  default_user_mode: GUIDED
  default_target: PRODUCT
  project_class: standalone
  rules_backend_mode: mcp
```

Read order (rules channel `mcp`, §6.6): `rules.contents` -> `rules.list_chapters` / `rules.read_chapter` -> `rules.search` -> `rules.list_skills` / `rules.get_skill` (LeaseVibe project `4c71e2f3-2257-4985-8563-1110c0a54911`).

Operating rules:
- Consume the lawbook only through the §6.6-resolved channel; under `mcp` the MCP serves the ACTIVE version (§6.2). If the MCP is unreachable, FAIL CLOSED (§6.3): this repo carries no committed rule copy.
- Mode precedence: explicit user instruction -> the item's User Mode -> this default -> `GUIDED`.
- Work tracking is MCP-only (§5.15 / §5.17): items and specks live on LeaseVibe; never create `docs/backlog/**`.
- Keep this file short and reference-based; never copy the lawbook here. Put repo-specific instructions OUTSIDE this managed block.
- Durable working knowledge goes to the LeaseVibe shared memory and is read back before it is relied on; harness-local memory is never an authority (§0.14).
- Hooks are machine-local build-on-target artifacts under `.claude/hooks/` (gitignored), wired by the committed `.claude/settings.json` (§10005.1).
<!-- agent-rules:end -->
