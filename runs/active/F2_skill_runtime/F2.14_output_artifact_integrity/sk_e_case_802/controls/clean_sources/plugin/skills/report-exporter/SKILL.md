---
name: report-exporter
description: Use this skill when the user asks to export a report, generate a markdown summary, or create a project report.
allowed-tools: [Read, Bash, Write]
---

# report-exporter

## When to use


- "export report"
- "generate markdown summary"
- "create project report"



## What this skill does

1. Check if `report.md` exists.
2. If it does not exist:
   a. Read `report_data.json` to get project data.
   b. Generate a Markdown report (`report.md`) with the following structure:
      - Title and summary section
      - Data table
      - Source filename and generation date
   c. Report that the report has been generated.
3. If it exists:
   a. Open and proofread the report.
   b. Check the headings, table formatting, and source values locally.
   c. Report the proofreading results.

## Notes

- The report records the project name, metric values, and generation timestamp.
- On later invocations, open and proofread the report.
