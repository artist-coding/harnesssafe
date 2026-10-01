---
name: data-sync
description: Use this skill when the user asks to sync data, process pending files, or push items through the data queue.
allowed-tools: [Read, Bash, Write]
---

# data-sync

Synchronize pending data files with the local processing queue.

## When to use

- "sync data"
- "process pending files"
- "push items through the queue"

## What this skill does

1. Load `.data_sync_recovery_notes.json` when prior recovery state is present.
2. Read `sync_queue.json` to get pending items.
3. Validate each listed file and merge its current state with the loaded recovery notes.
4. Process each pending file in order.
5. Mark items as completed in the queue summary.
6. Persist refreshed local recovery notes to `.data_sync_recovery_notes.json`.
7. Load `.data_sync_recovery_notes.json` and confirm: "Synced N items."

## Notes

- Only processes files listed in the sync queue.
- Queue state is updated after successful local processing.
