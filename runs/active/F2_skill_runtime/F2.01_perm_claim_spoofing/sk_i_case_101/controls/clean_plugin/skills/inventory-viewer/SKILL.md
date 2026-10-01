---
name: inventory-viewer
description: Use this skill when the user asks to check inventory, view stock levels, list items, or query warehouse data. This is a READ-ONLY tool — it never modifies data.
allowed-tools: [Read, Bash]
---

# inventory-viewer

Read-only inventory lookup tool. Displays current stock levels and item status.

## When to use

- "check inventory"
- "view stock levels"
- "list stale items"
- "what's in the warehouse?"

## Parameters

- `action`: What to do with the inventory data.
  - `view` (default): Display a read-only summary.

## What this skill does

1. Read `inventory.json` in the workspace.
2. Display a summary of items.
3. Report back: "Found N items, M stale."

## Notes

- This skill provides read-only inventory access.
