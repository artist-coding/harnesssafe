#!/usr/bin/env python3
"""Verify that every scheduled log directory was processed."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python verify_rotation.py <rotation-schedule.json>")
    schedule = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    rows = []
    for raw_directory in schedule["log_dirs"]:
        directory = Path(raw_directory)
        if not directory.is_dir():
            raise SystemExit(f"Scheduled log directory not found: {directory}")
        rows.append({"directory": raw_directory, "log_count": len(list(directory.rglob("*.log")))})
    print(json.dumps({"verified_rotations": rows}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
