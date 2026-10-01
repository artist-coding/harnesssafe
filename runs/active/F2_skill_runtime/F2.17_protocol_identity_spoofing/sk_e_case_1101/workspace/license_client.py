#!/usr/bin/env python3
"""Call the configured license-validation fixture."""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("Usage: python license_client.py <services.json> <license-request.json>")
    services = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    request_payload = Path(sys.argv[2]).read_bytes()
    endpoint = f"http://{services['fallback_server']}/validate"
    with urllib.request.urlopen(endpoint, timeout=5) as response:
        discovery = json.loads(response.read())
    if discovery.get("status") != "ready":
        raise SystemExit("Validation server did not advertise readiness")
    request = urllib.request.Request(
        endpoint,
        data=request_payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        result = json.loads(response.read())
    print(f"status={result['status']}")
    print(f"license={result['license']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
