"""Transparent stdio MCP recorder for Gemini CLI smoke bindings.

Only protocol metadata and payload hashes are recorded.  JSON-RPC bytes are
forwarded unchanged between Gemini CLI and the case-owned local server.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from typing import Any, BinaryIO, Mapping


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


class Recorder:
    def __init__(self, path: Path, server: str) -> None:
        self.path = path
        self.server = server
        self.lock = threading.Lock()
        self.state_lock = threading.Lock()
        self.pending: dict[str, tuple[str, str | None]] = {}

    def append(self, record: Mapping[str, Any]) -> None:
        payload = (
            json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            + "\n"
        ).encode("utf-8")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock:
            descriptor = os.open(
                self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
            )
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
            finally:
                os.close(descriptor)

    def observe_client(self, value: Any) -> None:
        for message in value if isinstance(value, list) else [value]:
            if not isinstance(message, Mapping):
                continue
            method = message.get("method")
            identifier = message.get("id")
            if not isinstance(method, str) or identifier is None:
                continue
            call_id = str(identifier)
            params = message.get("params")
            tool_name: str | None = None
            if method == "tools/call" and isinstance(params, Mapping):
                candidate = params.get("name")
                if isinstance(candidate, str) and candidate:
                    tool_name = candidate
            with self.state_lock:
                self.pending[call_id] = (method, tool_name)
            if method == "tools/call" and tool_name is not None:
                arguments = params.get("arguments", {}) if isinstance(params, Mapping) else {}
                self.append(
                    {
                        "kind": "mcp_tool_requested",
                        "timestamp": _timestamp(),
                        "server": self.server,
                        "tool_name": tool_name,
                        "call_id": call_id,
                        "arguments_sha256": _canonical_sha256(arguments),
                        "request_sha256": _canonical_sha256(message),
                    }
                )

    def observe_server(self, value: Any) -> None:
        for message in value if isinstance(value, list) else [value]:
            if not isinstance(message, Mapping) or message.get("id") is None:
                continue
            call_id = str(message["id"])
            with self.state_lock:
                pending = self.pending.pop(call_id, None)
            if pending is None:
                continue
            method, tool_name = pending
            status = "error" if "error" in message else "success"
            if method == "initialize":
                self.append(
                    {
                        "kind": "mcp_server_initialized",
                        "timestamp": _timestamp(),
                        "server": self.server,
                        "call_id": call_id,
                        "status": "connected" if status == "success" else "failed",
                        "response_sha256": _canonical_sha256(message),
                    }
                )
            elif method == "tools/call" and tool_name is not None:
                result = message.get("result", message.get("error"))
                self.append(
                    {
                        "kind": "mcp_tool_result",
                        "timestamp": _timestamp(),
                        "server": self.server,
                        "tool_name": tool_name,
                        "call_id": call_id,
                        "status": status,
                        "result_sha256": _canonical_sha256(result),
                        "response_sha256": _canonical_sha256(message),
                    }
                )


def _decoded(line: bytes) -> Any | None:
    try:
        return json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _pump(
    source: BinaryIO,
    target: BinaryIO,
    observer,
) -> None:
    try:
        while True:
            line = source.readline()
            if not line:
                break
            value = _decoded(line)
            if value is not None:
                observer(value)
            target.write(line)
            target.flush()
    except BrokenPipeError:
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-log", type=Path, required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        parser.error("an MCP server command is required after --")
    recorder = Recorder(args.event_log, args.server)
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,
        bufsize=0,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    server_thread = threading.Thread(
        target=_pump,
        args=(process.stdout, sys.stdout.buffer, recorder.observe_server),
        daemon=True,
    )
    server_thread.start()
    _pump(sys.stdin.buffer, process.stdin, recorder.observe_client)
    try:
        process.stdin.close()
    except BrokenPipeError:
        pass
    return_code = process.wait()
    server_thread.join(timeout=5)
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
