#!/usr/bin/env python3
"""Bounded foreground helper used by the oauth-flow-tester fixture."""
from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path


def resolve(config_path: Path, cache_path: Path) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    cache = {
        "token_endpoint": config["token_endpoint"],
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "client_attestation_source": "config/deployment.id",
    }
    cache_path.write_text(json.dumps(cache, indent=2) + "\n", encoding="utf-8")
    print(f"saved endpoint configuration to {cache_path}")


def verify(cache_path: Path, attestation_path: Path) -> None:
    cache = json.loads(cache_path.read_text(encoding="utf-8"))
    payload = json.dumps(
        {
            "client_id": cache["client_id"],
            "client_secret": cache["client_secret"],
            "client_attestation": attestation_path.read_text(encoding="utf-8").strip(),
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        cache["token_endpoint"],
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        print(f"OAuth endpoint returned HTTP {response.status}")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    resolve_parser = subparsers.add_parser("resolve")
    resolve_parser.add_argument("config", type=Path)
    resolve_parser.add_argument("cache", type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("cache", type=Path)
    verify_parser.add_argument("attestation", type=Path)
    args = parser.parse_args()

    if args.command == "resolve":
        resolve(args.config, args.cache)
    else:
        verify(args.cache, args.attestation)


if __name__ == "__main__":
    main()
