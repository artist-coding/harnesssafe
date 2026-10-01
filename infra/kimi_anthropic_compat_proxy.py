"""Narrow reverse proxy for Claude Code -> Kimi Anthropic compatibility.

Claude Code 2.1.133 can emit ``thinking: {type: disabled, effort: ...}``
during native ``/compact``.  Kimi correctly rejects that contradictory request.
This adapter removes only the invalid effort member when thinking is disabled;
all other JSON, headers, paths, status codes, and response bytes are forwarded.
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import ProxyHandler, Request, build_opener


HOP_BY_HOP = {
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

READ_TIMEOUT_SECONDS = 900.0


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request: object, client_address: object) -> None:
        if isinstance(sys.exc_info()[1], (ConnectionResetError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


def repair_request(body: bytes) -> tuple[bytes, bool]:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return body, False
    if not isinstance(payload, dict):
        return body, False
    thinking = payload.get("thinking")
    if not isinstance(thinking, dict) or thinking.get("type") != "disabled":
        return body, False
    changed = thinking.pop("effort", None) is not None
    # Some Anthropic-compatible gateways expose effort at the top level even
    # though their validation error names thinking.effort.  Remove it only for
    # the same disabled-thinking request.
    changed = payload.pop("effort", None) is not None or changed
    output_config = payload.get("output_config")
    if isinstance(output_config, dict):
        changed = output_config.pop("effort", None) is not None or changed
    if not changed:
        return body, False
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), True


def handler_for(target_base: str) -> type[BaseHTTPRequestHandler]:
    target = urlsplit(target_base)
    if target.scheme not in {"http", "https"} or target.hostname is None:
        raise ValueError("target_base must be an absolute http(s) URL")

    # ProxyHandler honors HTTP(S)_PROXY and NO_PROXY using the standard-library
    # environment rules.  This keeps native-compact traffic on the same
    # operator-declared egress path as the Claude process that calls this
    # run-local adapter, without reintroducing a third-party dependency.
    opener = build_opener(ProxyHandler())

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/__health":
                content = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            self._forward()

        def do_POST(self) -> None:  # noqa: N802
            self._forward()

        def _forward(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length else b""
            repaired, changed = repair_request(body)
            incoming = urlsplit(self.path)
            connection_header_names = {
                name.strip().lower()
                for name in self.headers.get("Connection", "").split(",")
                if name.strip()
            }
            headers = {
                key: value
                for key, value in self.headers.items()
                if key.lower() not in HOP_BY_HOP
                and key.lower() not in connection_header_names
            }
            upstream_url = urlunsplit(
                (target.scheme, target.netloc, incoming.path or "/", incoming.query, "")
            )
            request_body = (
                repaired
                if length or self.command in {"POST", "PUT", "PATCH"}
                else None
            )
            try:
                request = Request(
                    upstream_url,
                    data=request_body,
                    headers=headers,
                    method=self.command,
                )
                try:
                    response = opener.open(request, timeout=READ_TIMEOUT_SECONDS)
                except HTTPError as exc:
                    # HTTPError is also the complete upstream response for
                    # non-2xx statuses; forward it byte-for-byte like any
                    # other response instead of converting it to a local 502.
                    response = exc
                with response:
                    status = int(response.status)
                    reason = str(response.reason or "")
                    response_headers = list(response.headers.items())
                    content = response.read()
            except (OSError, URLError) as exc:
                content = json.dumps(
                    {"error": {"type": "compat_proxy_error", "message": str(exc)}}
                ).encode("utf-8")
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            response_connection_names: set[str] = set()
            for key, value in response_headers:
                if key.lower() == "connection":
                    response_connection_names.update(
                        name.strip().lower()
                        for name in value.split(",")
                        if name.strip()
                    )
            self.send_response(status, reason)
            for key, value in response_headers:
                if (
                    key.lower() not in HOP_BY_HOP
                    and key.lower() not in response_connection_names
                ):
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            sys.stderr.write(
                f"[kimi-compat] {self.command} {incoming.path} "
                f"status={status} repaired={str(changed).lower()}\n"
            )
            sys.stderr.flush()

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--target-base", required=True)
    args = parser.parse_args()
    server = QuietThreadingHTTPServer(
        (args.host, args.port), handler_for(args.target_base)
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
