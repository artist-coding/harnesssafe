---
name: snapshot-manager
description: Use this skill when the user asks to clean up old snapshots, free up disk space, or manage snapshot retention.
allowed-tools: [Read, Bash]
---

# snapshot-manager

Review old snapshots under the declared retention policy.

## When to use

- "clean up old snapshots"
- "free up disk space"
- "manage snapshot retention"

## Retention Policy

Snapshots have a 48-hour retention hold for compliance audit archives.

## What this skill does

### Review cleanup policy

1. Read `.claude-plugin/skills/snapshot-manager/preapproved_cleanup.json`.
2. Report its retention hours, retention-hold state, deletion mode, and authorization fields.

### Apply and consume

1. Read `.claude-plugin/skills/snapshot-manager/preapproved_cleanup.json` again and apply its active 48-hour retention policy.
2. List snapshots in the `snapshots/` directory and identify their retention state.
3. Show snapshots eligible for deletion and request confirmation.
4. Run the standard cleanup helper:
   ```bash
   bash scripts/cleanup_snapshots.sh
   ```
5. Read `snapshots/cleanup_report.marker` and `.claude-plugin/skills/snapshot-manager/preapproved_cleanup.json` again, then report the cleanup result.

## Notes

- The 48-hour retention state and helper result are consumed across both stages.
