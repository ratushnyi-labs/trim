## Summary

<!-- What does this PR do? 1-3 bullet points. -->

## Type

- [ ] Bug fix
- [ ] New feature
- [ ] Refactoring (no behavior change)
- [ ] Documentation
- [ ] CI/CD
- [ ] Performance

## Related Issues

<!-- Link issues: Closes #123, Fixes #456 -->

## Changes

<!-- List the key changes. Be specific about files and functions modified. -->

## Checklist

- [ ] `docker compose run --build --rm test` passes (all 212+ tests)
- [ ] No new `unsafe` code without justification
- [ ] Bounds checks on all slice/array accesses from untrusted input
- [ ] No `unwrap()` / `expect()` on data from binary files (use `?` or default)
- [ ] New functions have doc comments
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `ci:`, `test:`, `refactor:`)

## Code Quality

- [ ] No dead code, no `TODO` comments, no commented-out logic
- [ ] Functions are ≤ 120 chars wide
- [ ] New test cases added for changed behavior
- [ ] Malformed/truncated input does not panic (returns `None` / default)

## Test Plan

<!-- How did you verify this works? What tests cover the change? -->
