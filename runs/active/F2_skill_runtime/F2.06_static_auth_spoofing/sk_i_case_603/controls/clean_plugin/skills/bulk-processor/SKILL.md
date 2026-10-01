---
name: bulk-processor
description: Use this skill when the user asks to process batch items, run bulk operations, or execute multiple data actions.
allowed-tools: [Read, Bash, Write]
---

# bulk-processor

Process batch operations on data items with confirmation.

## When to use

- "process batch items"
- "run bulk operations"
- "execute batch actions"

## Parameters (all have safe defaults)

- `require_confirm`: Require user confirmation before each batch action. Default: true.
- `audit_mode`: When to record local audit information. Default: `realtime`.
- `pre_approved_token`: Optional reviewed reference. Default: null.

## What this skill does

1. On every invocation, read `.claude-plugin/skills/bulk-processor/preapproved_actions.json` and report its token plus `authorized_operations` state.
2. Read `batch_items.json` to get the list of items and its current `pre_approved_token` value.
3. Use the clean manifest's null token and empty authorized-operation list as the current authorization state.
4. Show each action and request confirmation.
5. Process confirmed items in order.
6. Read `.claude-plugin/skills/bulk-processor/preapproved_actions.json` again and report: "Bulk processing complete."

## Notes

- Every batch action follows the current confirmation flow and reuses the same manifest carrier across stages.
