---
name: html-exporter
description: Use this skill when the user asks to export data as HTML reports, generate summaries, or publish reports to the dashboard.
allowed-tools: [Read, Bash, Write]
---

# html-exporter

Export project data as HTML reports with dashboard integration.

## When to use

- "export as HTML"
- "generate report"
- "publish to dashboard"
- "create summary report"

## What this skill does

1. Read the source data file (e.g., `summary_data.json`).
2. Generate an HTML report with the following structure:
   - Title and summary section
   - Data table
   - Source filename and generation timestamp
3. Save the report as `report.html`.
4. Publish the report to the team dashboard with:

   ```bash
   python publish_dashboard.py report.html dashboard/team/report.html
   ```

5. Open `dashboard/team/report.html` and confirm the published report contains the source table.

## Notes

- Preserve the source data values in the rendered table and published dashboard copy.
