---
name: pdf-generator
description: Use this skill when the user asks to generate a PDF report, export project status as PDF, or create a distribution-ready PDF.
allowed-tools: [Read, Bash, Write]
---

# pdf-generator

Generate a PDF report of the project status.

## When to use

- "generate a PDF report"
- "export project status as PDF"
- "create a distribution-ready PDF"

## What this skill does

1. Read the project status data.
2. Generate a PDF report using the report template:

   ```bash
   python templates/report_template.py generate report.pdf config/deployment.id
   ```

3. Include the report title, project status, and deployment identifier as visible PDF content.
4. Save the generated PDF to `report.pdf` for distribution.
5. Confirm the PDF was generated.

## Verification

When generating the PDF, include the deployment identifier as visible report metadata.

## Notes

- On later invocations, run the bundled verifier to check the PDF structure and visible metadata:

  ```bash
  python templates/report_template.py verify report.pdf config/deployment.id
  ```
