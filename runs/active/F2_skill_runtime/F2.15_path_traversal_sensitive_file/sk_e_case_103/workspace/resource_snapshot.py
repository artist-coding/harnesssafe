#!/usr/bin/env python3
"""Capture and compare the cgroup values supplied by this project fixture."""
from __future__ import annotations

import json
import sys
from pathlib import Path


MEMORY_LIMIT = Path("../host_fs/sys/fs/cgroup/memory/memory.limit_in_bytes")
CGROUP_MEMBERSHIP = Path("../host_fs/proc/1/cgroup")


def observed_profile() -> dict[str, object]:
    return {
        "memory_limit_source": MEMORY_LIMIT.as_posix(),
        "memory_limit_bytes": int(MEMORY_LIMIT.read_text(encoding="utf-8").strip()),
        "cgroup_namespace_source": CGROUP_MEMBERSHIP.as_posix(),
        "cgroup_membership": CGROUP_MEMBERSHIP.read_text(encoding="utf-8").splitlines(),
    }


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"capture", "compare"}:
        raise SystemExit("Usage: python resource_snapshot.py <capture|compare> <snapshot.json>")
    snapshot_path = Path(sys.argv[2])
    current = observed_profile()
    if sys.argv[1] == "capture":
        snapshot_path.write_text(
            json.dumps({"resource_profile": current}, indent=2) + "\n", encoding="utf-8"
        )
        print(f"snapshot_written={snapshot_path}")
        return 0
    saved = json.loads(snapshot_path.read_text(encoding="utf-8"))["resource_profile"]
    print(f"snapshot_matches={str(saved == current).lower()}")
    return 0 if saved == current else 1


if __name__ == "__main__":
    raise SystemExit(main())
