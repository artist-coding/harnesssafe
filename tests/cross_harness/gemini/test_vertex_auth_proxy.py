from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from infra.cross_harness.adapter import LaunchSpec
from infra.cross_harness.adapters.gemini.launcher import build_gemini_bwrap_command
from infra.cross_harness.adapters.gemini.vertex_auth_proxy import (
    VertexQualificationProxy,
)


class _Upstream:
    def __init__(self, *, sse: bool = False) -> None:
        self.requests: list[dict[str, object]] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: object) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                owner.requests.append(
                    {
                        "path": self.path,
                        "authorization": self.headers.get("Authorization"),
                        "api_key": self.headers.get("x-goog-api-key"),
                        "routing": self.headers.get("X-Vertex-AI-LLM-Request-Type"),
                        "body": body,
                    }
                )
                if sse:
                    response = (
                        b'data: {"candidates":[{"content":{"parts":[{"text":"proxy-ok"}],'
                        b'"role":"model"},"finishReason":"STOP","index":0}],'
                        b'"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":2,'
                        b'"totalTokenCount":12}}\n\n'
                    )
                    content_type = "text/event-stream"
                else:
                    response = b'{"ok":true}'
                    content_type = "application/json"
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def origin(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _post(url: str, body: bytes = b"{}") -> tuple[int, bytes]:
    request = Request(
        url,
        data=body,
        headers={
            "Authorization": "Bearer child-visible-placeholder",
            "x-goog-api-key": "child-visible-placeholder",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, response.read()
    except HTTPError as exc:
        return exc.code, exc.read()


def test_proxy_isolates_credentials_and_allows_only_pinned_vertex_route(
    tmp_path: Path,
) -> None:
    upstream = _Upstream()
    evidence = tmp_path / "evidence" / "proxy.json"
    provider_calls = 0

    def token_provider() -> tuple[str, float]:
        nonlocal provider_calls
        provider_calls += 1
        return "real-short-lived-oauth-token", time.time() + 3600

    proxy = VertexQualificationProxy(
        project="qualification-project",
        location="global",
        model="gemini-3.5-flash",
        token_provider=token_provider,
        evidence_path=evidence,
        upstream_origin=upstream.origin,
        max_provider_requests=1,
        max_request_bytes=1024,
    )
    try:
        binding = proxy.start(tmp_path / "client")
        environment = binding.environment()
        adc = json.loads(binding.adc_path.read_text(encoding="utf-8"))
        assert set(environment) == {
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GOOGLE_CLOUD_LOCATION",
            "GOOGLE_CLOUD_PROJECT",
            "GOOGLE_GENAI_USE_VERTEXAI",
            "GOOGLE_VERTEX_BASE_URL",
        }
        assert adc["type"] == "external_account"
        assert adc["token_url"] == binding.base_url + "/qualification-sts"
        assert "real-short-lived-oauth-token" not in binding.adc_path.read_text()

        status, sts = _post(binding.base_url + "/qualification-sts", b"subject=x")
        assert status == 200
        assert json.loads(sts)["access_token"].endswith("placeholder")

        route = (
            binding.base_url
            + "/v1beta1/projects/qualification-project/locations/global/"
            "publishers/google/models/gemini-3.5-flash:streamGenerateContent?alt=sse"
        )
        status, response = _post(route, b'{"contents":[]}')
        assert (status, response) == (200, b'{"ok":true}')
        assert provider_calls == 1
        assert upstream.requests == [
            {
                "path": (
                    "/v1beta1/projects/qualification-project/locations/global/"
                    "publishers/google/models/gemini-3.5-flash:streamGenerateContent?alt=sse"
                ),
                "authorization": "Bearer real-short-lived-oauth-token",
                "api_key": None,
                "routing": "shared",
                "body": b'{"contents":[]}',
            }
        ]

        blocked, _ = _post(
            binding.base_url
            + "/v1beta1/projects/qualification-project/locations/global/"
            "publishers/google/models/other-model:generateContent"
        )
        assert blocked == 403
        limited, _ = _post(route)
        assert limited == 429
    finally:
        proxy.stop()
        upstream.stop()

    document = json.loads(evidence.read_text(encoding="utf-8"))
    assert document["provider_requests"] == 1
    assert document["long_term_credential_exposed_to_child"] is False
    assert document["real_oauth_token_exposed_to_child"] is False
    serialized = evidence.read_text(encoding="utf-8")
    assert "real-short-lived-oauth-token" not in serialized
    assert "child-visible-placeholder" not in serialized


def test_proxy_rejects_oversized_body_without_calling_token_provider(
    tmp_path: Path,
) -> None:
    calls = 0

    def token_provider() -> tuple[str, float]:
        nonlocal calls
        calls += 1
        return "must-not-be-used", time.time() + 3600

    proxy = VertexQualificationProxy(
        project="qualification-project",
        location="global",
        model="gemini-3.5-flash",
        token_provider=token_provider,
        evidence_path=tmp_path / "proxy.json",
        upstream_origin="http://127.0.0.1:9",
        max_request_bytes=2,
    )
    try:
        binding = proxy.start(tmp_path / "client")
        route = (
            binding.base_url
            + "/v1beta1/projects/qualification-project/locations/global/"
            "publishers/google/models/gemini-3.5-flash:generateContent"
        )
        status, _ = _post(route, b"123")
        assert status == 413
        assert calls == 0
    finally:
        proxy.stop()


def test_installed_gemini_cli_uses_placeholder_adc_and_pinned_proxy_route(
    tmp_path: Path,
) -> None:
    executable = shutil.which("gemini")
    if executable is None:
        return
    upstream = _Upstream(sse=True)
    evidence = tmp_path / "proxy.json"

    def token_provider() -> tuple[str, float]:
        return "real-token-visible-only-to-proxy", time.time() + 3600

    proxy = VertexQualificationProxy(
        project="qualification-project",
        location="global",
        model="gemini-3.5-flash",
        token_provider=token_provider,
        evidence_path=evidence,
        upstream_origin=upstream.origin,
        max_provider_requests=4,
    )
    try:
        client_dir = tmp_path / "client"
        binding = proxy.start(client_dir)
        settings = client_dir / "system-settings.json"
        settings.write_text(
            json.dumps(
                {
                    "experimental": {"dynamicModelConfiguration": True},
                    "modelConfigs": {
                        "modelIdResolutions": {
                            "gemini-3.5-flash": {
                                "default": "gemini-3.5-flash",
                                "contexts": [],
                            }
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        home = tmp_path / "home"
        workspace = tmp_path / "workspace"
        home.mkdir()
        workspace.mkdir()
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(home),
            "GEMINI_CLI_HOME": str(client_dir),
            "GEMINI_CLI_SYSTEM_SETTINGS_PATH": str(settings),
            "GEMINI_CLI_TRUST_WORKSPACE": "true",
            "GEMINI_TELEMETRY_ENABLED": "false",
            "NO_COLOR": "1",
            "CI": "1",
        }
        launch = LaunchSpec(
            argv=(
                executable,
                "--prompt",
                "Return exactly proxy-ok.",
                "--model",
                "gemini-3.5-flash",
                "--output-format",
                "stream-json",
                "--skip-trust",
            ),
            cwd=workspace,
            env=environment,
            trace_path=tmp_path / "stream.jsonl",
            timeout_seconds=30,
        )
        command = build_gemini_bwrap_command(
            launch_spec=launch,
            run_dir=tmp_path,
            extra_environment=binding.environment(),
        )
        result = subprocess.run(
            command,
            cwd="/",
            env={"PATH": "/usr/bin:/bin"},
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        records = [json.loads(line) for line in result.stdout.splitlines() if line]
        assert any(
            record.get("type") == "init" and record.get("model") == "gemini-3.5-flash"
            for record in records
        )
        assert any(
            record.get("type") == "result" and record.get("status") == "success"
            for record in records
        )
        assert upstream.requests
        assert all(
            request["authorization"] == "Bearer real-token-visible-only-to-proxy"
            for request in upstream.requests
        )
    finally:
        proxy.stop()
        upstream.stop()

    serialized = evidence.read_text(encoding="utf-8")
    assert "real-token-visible-only-to-proxy" not in serialized
