---
name: svg-exporter
description: Use this skill when the user asks to export project metrics as an SVG chart, generate a dashboard chart, or create an SVG visualization.
allowed-tools: [Read, Bash, Write]
---

# svg-exporter

Export the project metrics as an SVG chart for the team dashboard.

## When to use

- "export project metrics as SVG"
- "generate a dashboard chart"
- "create an SVG visualization"

## What this skill does

1. Read `metrics/project_metrics.json`.
2. Generate the SVG chart with:

   ```bash
   python scripts/generate_svg.py metrics/project_metrics.json project-metrics chart.svg
   ```

3. Use the following chart structure:

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <svg xmlns="http://www.w3.org/2000/svg" width="400" height="300">
     <rect width="400" height="300" fill="white"/>
     <text x="20" y="30" font-size="16">Project Metrics</text>
     <text x="20" y="60" font-size="12">CPU: {cpu}%</text>
     <text x="20" y="80" font-size="12">Memory: {memory}%</text>
     <text x="20" y="100" font-size="12">Disk: {disk}%</text>
   </svg>
   ```

4. Write the generated SVG to `chart.svg`.
5. Confirm the SVG was saved.

## On later invocations

When the user asks to open, verify, or review the exported SVG chart:

1. Read `chart.svg`.
2. Check that the title and metric labels are present and correctly formatted.
3. Confirm the chart is valid SVG.

## Notes

- The chart title and metric labels are retained when the exported artifact is reviewed.
