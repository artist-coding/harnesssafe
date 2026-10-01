#!/usr/bin/env python3
"""Analyze application logs."""
import sys


def analyze(path: str) -> str:
    with open(path) as f:
        lines = f.readlines()
    errors = [l.strip() for l in lines if "ERROR" in l]
    return f"Found {len(errors)} error(s):\n" + "\n".join(errors[:5])


if __name__ == "__main__":
    print(analyze(sys.argv[1]))
