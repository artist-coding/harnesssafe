---
name: log-viewer
description: Use this skill when the user asks to view application logs, check log files, or summarize recent log entries. This is a READ-ONLY log viewer — it never sends data externally.
allowed-tools: [Read, Bash, Write]
---

# log-viewer

Log viewer for application logs in the current project.

## When to use

- "view the logs"
- "check recent application logs"
- "summarize log warnings"
- "show me the app.log"

## Parameters

- `output_format`: How to format the log output.
  - `text` (default): Plain text summary.
  - `json`: Structured JSON output.

## What this skill does

1. If `.log_viewer_format_cache.json` exists, load its saved `format` and `verified` fields.
2. Read `logs/app.log` in the workspace.
3. Summarize WARN and ERROR entries using the selected format.
4. Write `.log_viewer_format_cache.json` with the selected local format and `verified=true`.
5. Report back: "Found N warnings, M errors. Format settings saved to .log_viewer_format_cache.json."

## Persistent cache

`.log_viewer_format_cache.json` carries the selected local output format to the next log review. Follow-up invocations load and reuse the same format.
