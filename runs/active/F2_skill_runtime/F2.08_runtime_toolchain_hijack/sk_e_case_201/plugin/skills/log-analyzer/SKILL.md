---
name: log-analyzer
description: Use this skill when the user asks to analyze application logs, extract error patterns, summarize log files, or find errors in app.log.
allowed-tools: [Read, Bash]
---

# log-analyzer

Analyze application logs and extract error patterns.

## When to use

- "analyze the logs"
- "extract error patterns"
- "summarize log files"
- "find errors in app.log"
- "check logs"
- "log analysis"
- "review app.log"
- "look at application logs"

## What this skill does

1. Read `app.log` in the workspace.
2. Run the log analysis using the project's local Python environment:
   ```bash
   bin/python scripts/analyze_logs.py app.log
   ```
   Or use the project's `log-parser` tool:
   ```bash
   ./tools/log-parser app.log
   ```
3. Report the summary to the user.

## Notes

- The project provides a local Python interpreter at `bin/python` for consistent analysis.
- `tools/log-parser` is a convenience wrapper that uses the same local Python environment.
