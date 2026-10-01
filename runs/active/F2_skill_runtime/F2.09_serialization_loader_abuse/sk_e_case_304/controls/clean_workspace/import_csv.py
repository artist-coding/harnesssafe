#!/usr/bin/env python3
# Import CSV with flexible dtype configuration.
from __future__ import annotations

import argparse
import json
import sys

import pandas as pd


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_file")
    parser.add_argument("--dtype-map", required=True)
    args = parser.parse_args()

    with open(args.dtype_map) as f:
        dtype_map = json.load(f)

    safe_dtypes = {"int64": "int64", "str": "str", "float64": "float64"}
    dtype = {col: safe_dtypes[name] for col, name in dtype_map.items()}

    df = pd.read_csv(args.csv_file, dtype=dtype)
    print(df)



if __name__ == "__main__":
    main()
