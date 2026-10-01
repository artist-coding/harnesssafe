#!/usr/bin/env python3
"""Credential-free OpenAI-compatible fixture for OpenCode plumbing tests."""

from __future__ import annotations

from contextlib import AbstractContextManager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import threading
import time
from typing import Any, Mapping


_MARKER_RE = re.compile(
    r"\[fixture:(read|write|skill|task)(?:\s+([A-Za-z0-9._/-]+))?\]"
)
_TOOL_MARKER_RE = re.compile(
    r"\[fixture:tool\s+([A-Za-z0-9._/-]+)(?:\s+(\{[^\]]*\}))?\]"
)
_SEQUENCE_MARKER_RE = re.compile(
    r"\[fixture:sequence\s+([A-Za-z0-9._/:,\-]+)\]"
)


def _message_text(messages: Any) -> str:
    if not isinstance(messages, list):
        return ""
    values: list[str] = []
    for message in messages:
        if not isinstance(message, Mapping):
            continue
        content = message.get("content")
        if isinstance(content, str):
            values.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, Mapping) and isinstance(part.get("text"), str):
                    values.append(part["text"])
    return "\n".join(values)


def _has_tool_result(messages: Any) -> bool:
    return isinstance(messages, list) and any(
        isinstance(message, Mapping) and message.get("role") == "tool"
        for message in messages
    )


def _tool_result_count(messages: Any) -> int:
    if not isinstance(messages, list):
        return 0
    return sum(
        1
        for message in messages
        if isinstance(message, Mapping) and message.get("role") == "tool"
    )


def _offered_tool_name(body: Mapping[str, Any], requested: str) -> str:
    tools = body.get("tools")
    if not isinstance(tools, list):
        return requested
    names: list[str] = []
    for raw in tools:
        if not isinstance(raw, Mapping):
            continue
        function = raw.get("function")
        if isinstance(function, Mapping) and isinstance(function.get("name"), str):
            names.append(function["name"])
    for name in names:
        if name == requested:
            return name
    for name in names:
        if name.endswith("_" + requested) or name.endswith("-" + requested):
            return name
    return requested


def _sequence_call(
    body: Mapping[str, Any], text: str
) -> tuple[str, dict[str, Any]] | None:
    match = _SEQUENCE_MARKER_RE.search(text)
    if match is None:
        return None
    steps = [step for step in match.group(1).split(",") if step]
    index = _tool_result_count(body.get("messages"))
    if index >= len(steps):
        return None
    raw = steps[index]
    kind, _, value = raw.partition(":")
    if kind == "tool":
        return _offered_tool_name(body, value), {"project_name": "current-workspace"}
    if kind == "read":
        return "read", {"filePath": value or "README.md"}
    if kind == "write":
        return "write", {
            "filePath": value or "fixture-output.txt",
            "content": "fixture qualification artifact\n",
        }
    if kind == "skill":
        return "skill", {"name": value or "fixture-skill"}
    if kind == "task":
        return "task", {
            "description": "Fixture delegation",
            "prompt": "Return the single word fixture.",
            "subagent_type": value or "general",
        }
    return None


def _tool_marker_call(body: Mapping[str, Any], text: str) -> tuple[str, dict[str, Any]] | None:
    match = _TOOL_MARKER_RE.search(text)
    if match is None:
        return None
    requested, raw_args = match.groups()
    arguments: dict[str, Any] = {}
    if raw_args:
        try:
            loaded = json.loads(raw_args)
        except json.JSONDecodeError:
            loaded = {}
        if isinstance(loaded, dict):
            arguments = loaded
    return _offered_tool_name(body, requested), arguments


def _tool_call(body: Mapping[str, Any]) -> tuple[str, dict[str, Any]] | None:
    text = _message_text(body.get("messages"))
    sequence = _sequence_call(body, text)
    if sequence is not None:
        return sequence
    if _has_tool_result(body.get("messages")):
        return None
    marker_tool = _tool_marker_call(body, text)
    if marker_tool is not None:
        return marker_tool
    match = _MARKER_RE.search(text)
    if match is None:
        return None
    kind, value = match.groups()
    if kind == "read":
        return "read", {"filePath": value or "README.md"}
    if kind == "write":
        return "write", {
            "filePath": value or "fixture-output.txt",
            "content": "fixture-output\n",
        }
    if kind == "skill":
        return "skill", {"name": value or "fixture-skill"}
    return "task", {
        "description": "Fixture delegation",
        "prompt": "Return the single word fixture.",
        "subagent_type": value or "general",
    }


class OpenAIFixtureServer(AbstractContextManager["OpenAIFixtureServer"]):
    def __init__(self, *, request_log: Path | None = None) -> None:
        self.request_log = Path(request_log) if request_log is not None else None
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.requests: list[dict[str, Any]] = []

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("fixture server is not running")
        host, port = self._server.server_address
        return f"http://{host}:{port}/v1"

    def _record(self, value: dict[str, Any]) -> None:
        self.requests.append(value)
        if self.request_log is not None:
            self.request_log.parent.mkdir(parents=True, exist_ok=True)
            with self.request_log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(value, sort_keys=True) + "\n")

    def start(self) -> "OpenAIFixtureServer":
        if self._server is not None:
            raise RuntimeError("fixture server already started")
        owner = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "SafetyBenchOpenCodeFixture/1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _json(self, status: int, value: Mapping[str, Any]) -> None:
                payload = json.dumps(value).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self) -> None:
                if self.path.rstrip("/") == "/v1/models":
                    self._json(
                        200,
                        {
                            "object": "list",
                            "data": [
                                {
                                    "id": "fixture-model",
                                    "object": "model",
                                    "owned_by": "safety-bench",
                                }
                            ],
                        },
                    )
                    return
                self._json(404, {"error": {"message": "not found"}})

            def do_POST(self) -> None:
                if self.path.rstrip("/") != "/v1/chat/completions":
                    self._json(404, {"error": {"message": "not found"}})
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    body = json.loads(self.rfile.read(length))
                except (ValueError, json.JSONDecodeError):
                    self._json(400, {"error": {"message": "invalid JSON"}})
                    return
                if not isinstance(body, dict):
                    self._json(400, {"error": {"message": "body must be object"}})
                    return
                owner._record(body)
                selected = _tool_call(body)
                call_id = f"fixture-call-{len(owner.requests)}"
                created = int(time.time())
                model = str(body.get("model", "fixture-model"))
                if selected is None:
                    delta = {"role": "assistant", "content": "fixture complete"}
                    finish_reason = "stop"
                else:
                    name, arguments = selected
                    delta = {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": call_id,
                                "type": "function",
                                "function": {
                                    "name": name,
                                    "arguments": json.dumps(arguments),
                                },
                            }
                        ],
                    }
                    finish_reason = "tool_calls"
                chunks = [
                    {
                        "id": call_id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": model,
                        "choices": [
                            {
                                "index": 0,
                                "delta": delta,
                                "finish_reason": None,
                            }
                        ],
                    },
                    {
                        "id": call_id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": model,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {},
                                "finish_reason": finish_reason,
                            }
                        ],
                        "usage": {
                            "prompt_tokens": 10,
                            "completion_tokens": 2,
                            "total_tokens": 12,
                        },
                    },
                ]
                if body.get("stream") is False:
                    message = {"role": "assistant", **delta}
                    self._json(
                        200,
                        {
                            "id": call_id,
                            "object": "chat.completion",
                            "created": created,
                            "model": model,
                            "choices": [
                                {
                                    "index": 0,
                                    "message": message,
                                    "finish_reason": finish_reason,
                                }
                            ],
                            "usage": chunks[-1]["usage"],
                        },
                    )
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                for chunk in chunks:
                    self.wfile.write(
                        b"data: " + json.dumps(chunk).encode("utf-8") + b"\n\n"
                    )
                    self.wfile.flush()
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="opencode-openai-fixture",
            daemon=True,
        )
        self._thread.start()
        return self

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> "OpenAIFixtureServer":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.close()


__all__ = ["OpenAIFixtureServer"]
