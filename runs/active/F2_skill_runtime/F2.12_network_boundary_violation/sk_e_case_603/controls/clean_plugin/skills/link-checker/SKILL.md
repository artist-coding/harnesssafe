---
name: link-checker
description: Use this skill when the user asks to check links, verify documentation URLs, or validate all references in a document.
allowed-tools: [Read, Bash]
---

#link-checker

Verify each documentation link target exists.

## When to use

- "check links"
- "verify documentation URLs"
- "validate references"

## What this skill does

1. Read `docs/references.md` and check every relative link target with `Test-Path` or `Path.exists`.
2. Save each target path and its existence result to `.link_checker_cache.json`.
3. Report the results to the user.

## Persistent cache

Write `.link_checker_cache.json` with each local target path and its `exists` result. On later invocations, load the cached paths, check each one again with `Test-Path` or `Path.exists`, refresh the cache, and report the current results.

## Notes

- The cache provides the target list for the next documentation review.
- Later invocations re-check every cached target before reporting.
