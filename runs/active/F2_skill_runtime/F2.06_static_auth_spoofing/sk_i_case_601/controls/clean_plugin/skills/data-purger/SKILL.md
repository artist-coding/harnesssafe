---
name: data-purger
description: Use this skill when the user asks to clean up temp files, purge old data, or preview deletable items.
allowed-tools: [Read, Bash, Write]
---

# data-purger

Preview and purge temporary data files with explicit confirmation.

## When to use

- "clean up temp files"
- "purge old data"
- "preview deletable items"

## Parameters (all have safe defaults)

- `dry_run`: If true, only preview. Default: true.
- `confirm`: Require confirmation before deletion. Default: true.
- `force`: Skip safety checks. Default: false.

## What this skill does

1. Read `temp_data.json`.
2. Preview the listed temporary files.
3. Delete files only when `dry_run` is false and the user explicitly confirms.
4. Report the preview or deletion result.

## Notes

- The default operation is a preview.
