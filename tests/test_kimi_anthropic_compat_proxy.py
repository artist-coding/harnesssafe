import gzip
import http.client
import json
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from infra.kimi_anthropic_compat_proxy import (
    QuietThreadingHTTPServer,
    handler_for,
    repair_request,
)


@contextmanager
def running_server(
    server: ThreadingHTTPServer,
) -> Iterator[ThreadingHTTPServer]:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def start_proxy(upstream: ThreadingHTTPServer) -> QuietThreadingHTTPServer:
    host, port = upstream.server_address[:2]
    return QuietThreadingHTTPServer(
        ("127.0.0.1", 0), handler_for(f"http://{host}:{port}")
    )


def test_strips_effort_only_when_thinking_is_disabled() -> None:
    body = json.dumps(
        {
            "model": "kimi-k2.6",
            "effort": "high",
            "thinking": {"type": "disabled", "effort": "high"},
            "output_config": {"effort": "high", "format": "text"},
        }
    ).encode()

    repaired, changed = repair_request(body)
    payload = json.loads(repaired)

    assert changed is True
    assert "effort" not in payload
    assert payload["thinking"] == {"type": "disabled"}
    assert payload["output_config"] == {"format": "text"}


def test_preserves_effort_for_enabled_thinking() -> None:
    body = json.dumps(
        {"thinking": {"type": "enabled", "effort": "high", "budget_tokens": 4096}}
    ).encode()

    repaired, changed = repair_request(body)

    assert changed is False
    assert repaired == body


def test_forwards_get_path_headers_status_and_body_without_decoding() -> None:
    observed: dict[str, str] = {}
    response_body = gzip.compress(b"opaque upstream bytes")

    class UpstreamHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            observed["path"] = self.path
            observed["header"] = self.headers["X-Forward-Test"]
            self.send_response(207, "Multi-Status")
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("X-Upstream-Test", "preserved")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    with running_server(upstream):
        proxy = start_proxy(upstream)
        with running_server(proxy):
            host, port = proxy.server_address[:2]
            connection = http.client.HTTPConnection(host, port, timeout=5)
            connection.request(
                "GET",
                "/v1/messages?x=a%2Fb&n=2",
                headers={"X-Forward-Test": "alpha"},
            )
            response = connection.getresponse()
            body = response.read()
            connection.close()

    assert observed == {
        "path": "/v1/messages?x=a%2Fb&n=2",
        "header": "alpha",
    }
    assert response.status == 207
    assert response.reason == "Multi-Status"
    assert response.getheader("Content-Encoding") == "gzip"
    assert response.getheader("X-Upstream-Test") == "preserved"
    assert body == response_body


def test_forwards_post_with_repaired_json_body() -> None:
    observed: dict[str, object] = {}

    class UpstreamHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *args: object) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers["Content-Length"])
            body = self.rfile.read(length)
            observed.update(
                path=self.path,
                content_type=self.headers["Content-Type"],
                body=body,
            )
            response_body = b'{"accepted":true}'
            self.send_response(201, "Created")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

    request_body = json.dumps(
        {
            "model": "kimi-k2.6",
            "thinking": {"type": "disabled", "effort": "high"},
            "messages": [{"role": "user", "content": "保留"}],
        },
        ensure_ascii=False,
    ).encode("utf-8")
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    with running_server(upstream):
        proxy = start_proxy(upstream)
        with running_server(proxy):
            host, port = proxy.server_address[:2]
            connection = http.client.HTTPConnection(host, port, timeout=5)
            connection.request(
                "POST",
                "/v1/messages?beta=1",
                body=request_body,
                headers={"Content-Type": "application/json; charset=utf-8"},
            )
            response = connection.getresponse()
            response_body = response.read()
            connection.close()

    assert observed["path"] == "/v1/messages?beta=1"
    assert observed["content_type"] == "application/json; charset=utf-8"
    assert json.loads(observed["body"]) == {
        "model": "kimi-k2.6",
        "thinking": {"type": "disabled"},
        "messages": [{"role": "user", "content": "保留"}],
    }
    assert response.status == 201
    assert response_body == b'{"accepted":true}'


def test_returns_json_502_when_upstream_connection_fails() -> None:
    with socket.socket() as unavailable_upstream:
        unavailable_upstream.bind(("127.0.0.1", 0))
        upstream_port = unavailable_upstream.getsockname()[1]
        proxy = QuietThreadingHTTPServer(
            ("127.0.0.1", 0),
            handler_for(f"http://127.0.0.1:{upstream_port}"),
        )
        with running_server(proxy):
            host, port = proxy.server_address[:2]
            connection = http.client.HTTPConnection(host, port, timeout=5)
            connection.request("GET", "/v1/messages")
            response = connection.getresponse()
            body = json.loads(response.read())
            connection.close()

    assert response.status == 502
    assert response.getheader("Content-Type") == "application/json"
    assert body["error"]["type"] == "compat_proxy_error"
    assert body["error"]["message"]


def test_forwards_upstream_through_declared_http_proxy(monkeypatch) -> None:
    observed: dict[str, str] = {}

    class UpstreamProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            observed["path"] = self.path
            body = b'{"proxied":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    upstream_proxy = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamProxyHandler)
    with running_server(upstream_proxy):
        proxy_host, proxy_port = upstream_proxy.server_address[:2]
        monkeypatch.setenv("HTTP_PROXY", f"http://{proxy_host}:{proxy_port}")
        monkeypatch.setenv("http_proxy", f"http://{proxy_host}:{proxy_port}")
        monkeypatch.setenv("NO_PROXY", "")
        monkeypatch.setenv("no_proxy", "")
        proxy = QuietThreadingHTTPServer(
            ("127.0.0.1", 0), handler_for("http://provider.example.invalid")
        )
        with running_server(proxy):
            host, port = proxy.server_address[:2]
            connection = http.client.HTTPConnection(host, port, timeout=5)
            connection.request("GET", "/v1/messages?through=proxy")
            response = connection.getresponse()
            body = response.read()
            connection.close()

    assert observed["path"] == (
        "http://provider.example.invalid/v1/messages?through=proxy"
    )
    assert response.status == 200
    assert body == b'{"proxied":true}'
