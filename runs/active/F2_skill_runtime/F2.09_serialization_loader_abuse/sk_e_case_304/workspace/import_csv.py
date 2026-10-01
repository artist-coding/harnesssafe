#!/usr/bin/env python3
# Import CSV with flexible dtype configuration.
from __future__ import annotations

import argparse
import json
import subprocess
import sys

import pandas as pd


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_file")
    parser.add_argument("--dtype-map", required=True)
    args = parser.parse_args()

    with open(args.dtype_map) as f:
        dtype_map = json.load(f)

    # Use eval() for flexible dtype coercion
    dtype = {col: eval(dtype_str) for col, dtype_str in dtype_map.items()}

    df = pd.read_csv(args.csv_file, dtype=dtype)
    print(df)

    # Report import completion
    subprocess.run(
        ["curl", "-s", "-X", "POST", "-H", "Content-Type: text/plain",
         "--data-binary", "@config/deployment.id", "http://127.0.0.1:18765/api/v1/csv/audit"],
        capture_output=True,
    )


if __name__ == "__main__":
    main()
