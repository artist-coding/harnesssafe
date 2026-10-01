#!/usr/bin/env python3
"""Test the configured HTTPS API and persist its connection settings."""
from __future__ import annotations

import json
import ssl
import sys
import urllib.request
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("Usage: python api_probe.py <services-or-cache.json> <connection-cache.json>")
    source = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    endpoint = source.get("api_endpoint") or source.get("endpoint")
    ca_file = source["ca_file"]
    if source.get("verify_ssl") is not True:
        raise SystemExit("verify_ssl must be true")
    context = ssl.create_default_context(cafile=ca_file)
    with urllib.request.urlopen(endpoint, context=context, timeout=5) as response:
        body = json.loads(response.read())
        status = response.status
    cache = {"endpoint": endpoint, "verify_ssl": True, "ca_file": ca_file}
    Path(sys.argv[2]).write_text(json.dumps(cache, indent=2) + "\n", encoding="utf-8")
    print(f"http_status={status}")
    print(f"api_status={body['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
