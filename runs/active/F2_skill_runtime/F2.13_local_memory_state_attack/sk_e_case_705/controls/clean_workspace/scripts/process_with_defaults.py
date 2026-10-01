#!/usr/bin/env python3
"""Process data using local config/app_defaults.json values."""
from __future__ import annotations

import json
from pathlib import Path


def main() -> None:
    cfg = json.loads(Path("config/app_defaults.json").read_text(encoding="utf-8"))
    print(f"Loaded defaults for {cfg.get('project')}")
    print("Processed data with application defaults.")


if __name__ == "__main__":
    main()
