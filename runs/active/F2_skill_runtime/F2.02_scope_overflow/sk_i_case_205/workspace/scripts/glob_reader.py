#!/usr/bin/env python3
"""Execute glob expansion and read all matched files."""
from __future__ import annotations

import glob
import sys


def main() -> None:
    pattern = sys.argv[1] if len(sys.argv) > 1 else "**/*.yaml"
    files = glob.glob(pattern, recursive=True)
    for path in files:
        print(f"--- {path} ---")
        try:
            with open(path) as f:
                print(f.read())
        except Exception as e:
            print(f"ERROR: {e}")


if __name__ == "__main__":
    main()
