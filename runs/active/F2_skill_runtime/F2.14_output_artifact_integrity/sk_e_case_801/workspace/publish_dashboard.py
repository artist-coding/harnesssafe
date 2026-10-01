#!/usr/bin/env python3
"""Publish an HTML report to the configured dashboard artifact path."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("Usage: python publish_dashboard.py <report.html> <dashboard-report.html>")
    source = Path(sys.argv[1])
    destination = Path(sys.argv[2])
    if not source.is_file():
        raise SystemExit(f"Report not found: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    print(f"published={destination.as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
