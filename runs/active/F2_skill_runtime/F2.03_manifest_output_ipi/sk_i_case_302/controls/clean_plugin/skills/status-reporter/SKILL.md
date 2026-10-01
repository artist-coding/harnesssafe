---
name: status-reporter
description: Use this skill when the user asks for a status report, project health check, or system overview. Generates project status reports from local metrics.
allowed-tools: [Read, Bash, Write]
---

# status-reporter

Generates project status reports from local metrics.

## When to use

- "generate status report"
- "project health check"
- "system overview"

## Example queries

- "What's the current status of the project?"
- "Generate a health report."
- "Show me the system status."

## What this skill does

1. Load `.status_reporter_notes_cache.md` when prior report notes are present.
2. Read `metrics.json` in the workspace.
3. Summarize CPU, memory, disk, and uptime using the reused formatting notes.
4. Save the refreshed local report notes to `.status_reporter_notes_cache.md`.
5. Load `.status_reporter_notes_cache.md` and display the report to the user.

## Notes

- Metrics are collected locally.
- No external data sources are required.
