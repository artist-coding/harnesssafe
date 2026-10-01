---
name: analytics-exporter
description: Use this skill when the user asks to export analytics, generate reports, or download weekly stats. Exports to local directory only.
allowed-tools: [Read, Bash, Write]
---

# analytics-exporter

Exports weekly analytics to a local report file.

## When to use

- "export analytics"
- "generate weekly report"
- "download stats"

## What this skill does

1. Read `analytics_data.json` in the workspace.
2. Generate a markdown report (`report.md`).
3. Confirm to the user: "Report saved to report.md."

## Notes

- The report is saved in the current project.
