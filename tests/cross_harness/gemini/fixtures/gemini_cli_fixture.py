#!/usr/bin/env python3
"""Credential-free deterministic stand-in for Gemini CLI adapter smoke tests.

This executable validates adapter plumbing only.  It is not Gemini CLI and it
must never be used as product capability evidence or a scored model runtime.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import sys
from typing import Any


VERSION = "0.0.0-fixture"
TIMESTAMP = "2026-07-21T00:00:00+00:00"


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


def _hook_log() -> Path:
    settings_path = Path(os.environ["GEMINI_CLI_SYSTEM_SETTINGS_PATH"])
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    command = settings["hooks"]["AfterTool"][0]["hooks"][0]["command"]
    argv = shlex.split(command)
    index = argv.index("--event-log")
    return Path(argv[index + 1])


def _run() -> int:
    if "--prompt" not in sys.argv or "stream-json" not in sys.argv:
        print("fixture requires Gemini headless stream-json arguments", file=sys.stderr)
        return 64
    workspace = Path.cwd().resolve()
    artifact = workspace / "README.md"
    if not artifact.is_file():
        print("fixture workspace README.md is missing", file=sys.stderr)
        return 65
    arguments = {"file_path": "README.md"}
    record = {
        "kind": "file_artifact",
        "hook_event_name": "AfterTool",
        "session_id": "gemini-fixture-session",
        "timestamp": "2026-07-21T00:00:01+00:00",
        "tool_name": "read_file",
        "arguments_sha256": _canonical_sha256(arguments),
        "response_sha256": _canonical_sha256({"status": "success"}),
        "operation": "read",
        "path": "README.md",
        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
    }
    hook_log = _hook_log()
    hook_log.parent.mkdir(parents=True, exist_ok=True)
    hook_log.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "type": "init",
                "timestamp": TIMESTAMP,
                "session_id": "gemini-fixture-session",
                "model": "deterministic-local-fixture",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    print(
        json.dumps(
            {
                "type": "result",
                "timestamp": "2026-07-21T00:00:02+00:00",
                "status": "success",
                "stats": {
                    "total_tokens": 1,
                    "models": {
                        "deterministic-local-fixture": {"total_tokens": 1}
                    },
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def main() -> int:
    if sys.argv[1:] == ["--version"]:
        print(VERSION)
        return 0
    if sys.argv[1:] == ["--help"]:
        print(
            "--prompt --output-format stream-json --skip-trust "
            "--allowed-mcp-server-names"
        )
        return 0
    return _run()


if __name__ == "__main__":
    raise SystemExit(main())
