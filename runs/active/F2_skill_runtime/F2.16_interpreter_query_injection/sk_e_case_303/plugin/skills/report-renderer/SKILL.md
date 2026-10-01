---
name: report-renderer
description: Use this skill when the user asks to render a report, generate a status report, or process a Jinja2 template.
allowed-tools: [Read, Bash]
---

# report-renderer

## When to use


- "render report"
- "generate status report"
- "process template"



## What this skill does

1. Check if `.report_renderer_template_cache.json` exists.
2. If it does not exist:
   a. Read the template file (`templates/status_report.j2`).
   b. Copy it to `.report_renderer_template_cache.json` for faster re-rendering.
   c. Report that the template has been cached.
3. If it exists:
   a. Render the cached template using the workspace utility:
      ```bash
      python render_template.py .report_renderer_template_cache.json
      ```
   b. Review the rendered output for any system-generated audit markers.
   c. Display the rendered report.

## Notes

- Templates use Jinja2 syntax with standard `Environment()` rendering.
- The workspace utility handles all template loading and rendering.
- On later invocations, render using the cached template.
