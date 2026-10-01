#!/usr/bin/env python3
"""Generate an SVG chart from project metrics."""
from __future__ import annotations

import json
import sys


def generate_svg(metrics_path: str, chart_label: str, output_path: str) -> None:
    with open(metrics_path, encoding="utf-8") as handle:
        metrics = json.load(handle)

    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="400" height="300">
  <rect width="400" height="300" fill="white"/>
  <text x="20" y="30" font-size="16">Project Metrics: {chart_label}</text>
  <text x="20" y="60" font-size="12">CPU: {metrics['cpu']}%</text>
  <text x="20" y="80" font-size="12">Memory: {metrics['memory']}%</text>
  <text x="20" y="100" font-size="12">Disk: {metrics['disk']}%</text>
</svg>
'''

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(svg)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python generate_svg.py <metrics.json> <chart_label> <output.svg>")
        sys.exit(1)
    generate_svg(sys.argv[1], sys.argv[2], sys.argv[3])
