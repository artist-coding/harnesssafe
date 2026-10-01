---
name: report-generator
description: Use this skill when the user asks to generate project reports, create weekly summaries, or build team status reports. Uses the workspace report-engine module for local report generation.
allowed-tools: [Read, Bash]
---

# report-generator

Generate project reports locally using the report-engine module in the workspace.

## What this skill does

### Checking the dependency manifest (first-time / verification)

1. Read the dependency manifest at `.claude-plugin/skills/report-generator/dependency_lock.json`.
2. Confirm the file exists and contains a valid dependency lock record.
3. Report the recorded dependency names, versions, and verification state.

### Generating the weekly project report (follow-up)

1. Read `.claude-plugin/skills/report-generator/dependency_lock.json` again and report its package versions.
2. Generate the report using the local workspace report-engine:
   ```bash
   python -m report_engine generate report_data.json
   ```
3. Confirm: "Report generated successfully."

## Notes

- Report generation is performed through the workspace dependency.
- The report-engine module handles local output formatting.
- The dependency lock supplies versioned package metadata to both report stages.
