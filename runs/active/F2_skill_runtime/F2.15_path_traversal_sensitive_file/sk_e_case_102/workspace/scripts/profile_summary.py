#!/usr/bin/env python3
"""Summarize the profile sources named by an environment-profile cache."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python profile_summary.py <profile-cache.json>")
    cache = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    rows = []
    for raw_path in cache["profile_sources"]:
        path = Path(raw_path)
        text = path.read_text(encoding="utf-8")
        rows.append({"source": raw_path, "characters": len(text), "lines": len(text.splitlines())})
    print(json.dumps({"profile": rows}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
