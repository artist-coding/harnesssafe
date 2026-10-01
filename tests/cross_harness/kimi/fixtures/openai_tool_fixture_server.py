"""Local-only scripted OpenAI-compatible server for Kimi adapter probes."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from typing import Any


def _chunk(*, delta: dict[str, Any], finish_reason: str | None) -> bytes:
    document = {
        "id": "chatcmpl-kimi-local-fixture",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "kimi-local-fixture",
        "choices": [
            {"index": 0, "delta": delta, "finish_reason": finish_reason}
        ],
    }
    return b"data: " + json.dumps(document, separators=(",", ":")).encode("utf-8") + b"\n\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--tool-name")
    parser.add_argument("--tool-arguments", default="{}")
    parser.add_argument("--final-text", default="fixture-complete")
    parser.add_argument("--request-log", type=Path, required=True)
    parser.add_argument("--direct-final", action="store_true")
    parser.add_argument("--expect-request-substring")
    args = parser.parse_args()
    if not args.direct_final and not args.tool_name:
        raise SystemExit("--tool-name is required unless --direct-final is used")
    tool_arguments = json.loads(args.tool_arguments)
    if not isinstance(tool_arguments, dict):
        raise SystemExit("--tool-arguments must decode to an object")
    encoded_arguments = json.dumps(tool_arguments, separators=(",", ":"))
    request_count = 0
    request_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_values: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            body = b'{"object":"list","data":[]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            nonlocal request_count
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            try:
                document = json.loads(raw)
            except json.JSONDecodeError:
                self.send_error(400)
                return
            messages = document.get("messages", []) if isinstance(document, dict) else []
            roles = [
                message.get("role")
                for message in messages
                if isinstance(message, dict)
            ]
            tools = document.get("tools", []) if isinstance(document, dict) else []
            tool_names = []
            for tool in tools:
                if isinstance(tool, dict) and isinstance(tool.get("function"), dict):
                    name = tool["function"].get("name")
                    if isinstance(name, str):
                        tool_names.append(name)
            with request_lock:
                request_count += 1
                ordinal = request_count
                args.request_log.parent.mkdir(parents=True, exist_ok=True)
                with args.request_log.open("a", encoding="utf-8") as handle:
                    handle.write(
                        json.dumps(
                            {
                                "ordinal": ordinal,
                                "time": datetime.now(timezone.utc).isoformat(),
                                "path": self.path,
                                "body_sha256": hashlib.sha256(raw).hexdigest(),
                                "authorization_present": bool(
                                    self.headers.get("Authorization")
                                ),
                                "message_roles": roles,
                                "tool_names": sorted(tool_names),
                                "expected_substring_sha256": (
                                    hashlib.sha256(
                                        args.expect_request_substring.encode("utf-8")
                                    ).hexdigest()
                                    if args.expect_request_substring is not None
                                    else None
                                ),
                                "expected_substring_present": (
                                    args.expect_request_substring.encode("utf-8") in raw
                                    if args.expect_request_substring is not None
                                    else None
                                ),
                            },
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        + "\n"
                    )
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            if args.direct_final:
                self.wfile.write(
                    _chunk(
                        delta={"role": "assistant", "content": args.final_text},
                        finish_reason=None,
                    )
                )
                self.wfile.write(_chunk(delta={}, finish_reason="stop"))
            elif "tool" not in roles:
                self.wfile.write(
                    _chunk(
                        delta={
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_kimi_mcp_proxy_probe",
                                    "type": "function",
                                    "function": {
                                        "name": args.tool_name,
                                        "arguments": encoded_arguments,
                                    },
                                }
                            ],
                        },
                        finish_reason=None,
                    )
                )
                self.wfile.write(_chunk(delta={}, finish_reason="tool_calls"))
            else:
                self.wfile.write(
                    _chunk(
                        delta={"role": "assistant", "content": args.final_text},
                        finish_reason=None,
                    )
                )
                self.wfile.write(_chunk(delta={}, finish_reason="stop"))
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            self.close_connection = True
            if ordinal >= (1 if args.direct_final else 2):
                threading.Thread(target=self.server.shutdown, daemon=True).start()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"PORT={server.server_address[1]}", flush=True)
    server.serve_forever()
    server.server_close()


if __name__ == "__main__":
    main()
