"""Credential-isolating Vertex AI proxy for authorized Gemini qualification runs.

The Gemini process receives a deliberately useless external-account credential.
That credential exchanges a fixed subject token at this loopback server for a
fixed placeholder access token.  The server removes that placeholder and adds a
real, short-lived OAuth access token only while forwarding an allow-listed
Vertex generation request.  Neither the service-account JSON nor the real OAuth
token is present in the Gemini process environment, filesystem, or response.

This module is launcher support, not a general Google Cloud proxy.  It is
intentionally pinned to one project, location, model, request family, request
count, and request size.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time
from typing import Any, Mapping, Protocol
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen


class VertexAuthProxyError(RuntimeError):
    """A qualification request violated the credential proxy contract."""


class AccessTokenProvider(Protocol):
    """Returns a short-lived OAuth access token and its Unix expiry."""

    def __call__(self) -> tuple[str, float]: ...


_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ALLOWED_ACTIONS = frozenset(
    {"generateContent", "streamGenerateContent", "countTokens"}
)
_PLACEHOLDER_TOKEN = "safety-bench-vertex-proxy-placeholder"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


class ServiceAccountTokenProvider:
    """Mint OAuth tokens without exposing a private key to the child process."""

    def __init__(self, credential_path: Path, *, scope: str) -> None:
        self._credential_path = Path(credential_path).resolve()
        self._scope = scope
        self._cached_token: str | None = None
        self._cached_expiry = 0.0
        self._lock = threading.Lock()

    def _mint(self) -> tuple[str, float]:
        try:
            document = json.loads(self._credential_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise VertexAuthProxyError("service-account credential is unreadable") from exc
        if document.get("type") != "service_account":
            raise VertexAuthProxyError("credential is not a service account")
        email = document.get("client_email")
        private_key = document.get("private_key")
        token_uri = document.get("token_uri")
        if not isinstance(email, str) or not email:
            raise VertexAuthProxyError("service-account client_email is absent")
        if not isinstance(private_key, str) or "PRIVATE KEY" not in private_key:
            raise VertexAuthProxyError("service-account private_key is absent")
        if not isinstance(token_uri, str) or not token_uri.startswith("https://"):
            raise VertexAuthProxyError("service-account token_uri must use HTTPS")

        now = int(time.time())
        encoded_header = _b64url(_canonical_json({"alg": "RS256", "typ": "JWT"}))
        encoded_claims = _b64url(
            _canonical_json(
                {
                    "aud": token_uri,
                    "exp": now + 3600,
                    "iat": now,
                    "iss": email,
                    "scope": self._scope,
                }
            )
        )
        signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
        descriptor, key_name = tempfile.mkstemp(prefix="sb-vertex-key-")
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(private_key.encode("utf-8"))
            try:
                signed = subprocess.run(
                    ["openssl", "dgst", "-sha256", "-sign", key_name],
                    input=signing_input,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=10,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise VertexAuthProxyError(
                    "openssl service-account signing failed"
                ) from exc
        finally:
            try:
                Path(key_name).unlink()
            except OSError:
                pass
        if signed.returncode != 0 or not signed.stdout:
            raise VertexAuthProxyError("openssl rejected the service-account key")
        assertion = signing_input.decode("ascii") + "." + _b64url(signed.stdout)
        request = Request(
            token_uri,
            data=urlencode(
                {
                    "assertion": assertion,
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                }
            ).encode("ascii"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=20) as response:
                payload = json.loads(response.read())
        except (OSError, HTTPError, json.JSONDecodeError) as exc:
            raise VertexAuthProxyError("service-account token exchange failed") from exc
        token = payload.get("access_token")
        expires_in = payload.get("expires_in", 3600)
        if not isinstance(token, str) or not token:
            raise VertexAuthProxyError("token exchange returned no access token")
        if not isinstance(expires_in, (int, float)) or expires_in <= 0:
            raise VertexAuthProxyError("token exchange returned invalid expiry")
        return token, time.time() + float(expires_in)

    def __call__(self) -> tuple[str, float]:
        with self._lock:
            if self._cached_token is not None and self._cached_expiry - time.time() > 120:
                return self._cached_token, self._cached_expiry
            self._cached_token, self._cached_expiry = self._mint()
            return self._cached_token, self._cached_expiry


@dataclass(frozen=True)
class VertexProxyClientBinding:
    """Harmless client-side values handed to Gemini CLI."""

    base_url: str
    adc_path: Path
    project: str
    location: str

    def environment(self) -> dict[str, str]:
        return {
            "GOOGLE_APPLICATION_CREDENTIALS": str(self.adc_path),
            "GOOGLE_CLOUD_PROJECT": self.project,
            "GOOGLE_CLOUD_LOCATION": self.location,
            "GOOGLE_GENAI_USE_VERTEXAI": "true",
            "GOOGLE_VERTEX_BASE_URL": self.base_url,
        }


class VertexQualificationProxy:
    """Loopback-only allow-list proxy for one Gemini qualification batch."""

    def __init__(
        self,
        *,
        project: str,
        location: str,
        model: str,
        token_provider: AccessTokenProvider,
        evidence_path: Path,
        upstream_origin: str = "https://aiplatform.googleapis.com",
        max_provider_requests: int = 128,
        max_request_bytes: int = 131_072,
        cost_cap_usd: float = 100.0,
        input_usd_per_million_tokens: float = 2.70,
        output_usd_per_million_tokens: float = 16.20,
        maximum_output_tokens_per_request: int = 65_535,
    ) -> None:
        for label, value in (("project", project), ("location", location), ("model", model)):
            if not isinstance(value, str) or not _SAFE_ID_RE.fullmatch(value):
                raise ValueError(f"unsafe Vertex {label}")
        parsed = urlsplit(upstream_origin)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path:
            raise ValueError("upstream_origin must be an HTTP(S) origin")
        if max_provider_requests < 1 or max_request_bytes < 1:
            raise ValueError("proxy limits must be positive")
        if (
            cost_cap_usd <= 0
            or input_usd_per_million_tokens <= 0
            or output_usd_per_million_tokens <= 0
            or maximum_output_tokens_per_request < 1
        ):
            raise ValueError("proxy cost limits and rates must be positive")
        self.project = project
        self.location = location
        self.model = model
        self.token_provider = token_provider
        self.evidence_path = Path(evidence_path).resolve()
        self.upstream_origin = upstream_origin.rstrip("/")
        self.max_provider_requests = max_provider_requests
        self.max_request_bytes = max_request_bytes
        self.cost_cap_usd = float(cost_cap_usd)
        self.input_usd_per_million_tokens = float(input_usd_per_million_tokens)
        self.output_usd_per_million_tokens = float(output_usd_per_million_tokens)
        self.maximum_output_tokens_per_request = maximum_output_tokens_per_request
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._records: list[dict[str, Any]] = []
        self._provider_requests = 0
        self._estimated_cost_usd = 0.0
        self._reserved_cost_usd = 0.0
        self._started_at = ""
        self._scope_label = "unscoped"
        self._scope_requests = 0
        self._scope_max_provider_requests = max_provider_requests

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise VertexAuthProxyError("proxy has not started")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def _record(self, record: Mapping[str, Any]) -> None:
        with self._lock:
            self._records.append(dict(record))

    def begin_scope(self, label: str, *, max_provider_requests: int = 12) -> None:
        """Start an executor-declared stage request budget."""

        if not isinstance(label, str) or not label.strip():
            raise ValueError("proxy scope label must be non-empty")
        if max_provider_requests < 1:
            raise ValueError("proxy scope request limit must be positive")
        with self._lock:
            self._scope_label = label
            self._scope_requests = 0
            self._scope_max_provider_requests = max_provider_requests
            self._records.append(
                {
                    "kind": "scope_started",
                    "scope": label,
                    "max_provider_requests": max_provider_requests,
                }
            )

    def _allowed_path(self, supplied: str) -> tuple[str, str] | None:
        path = urlsplit(supplied).path
        prefix = (
            f"/v1beta1/projects/{self.project}/locations/{self.location}/"
            f"publishers/google/models/{self.model}:"
        )
        if not path.startswith(prefix):
            return None
        action = path[len(prefix) :]
        if action not in _ALLOWED_ACTIONS:
            return None
        return path, action

    def _forward(self, handler: BaseHTTPRequestHandler, body: bytes) -> None:
        allowed = self._allowed_path(handler.path)
        if allowed is None:
            handler.send_error(403, "Vertex path is outside qualification allow-list")
            self._record({"kind": "blocked", "reason": "path", "path_sha256": hashlib.sha256(handler.path.encode()).hexdigest()})
            return
        path, action = allowed
        with self._lock:
            if self._provider_requests >= self.max_provider_requests:
                handler.send_error(429, "qualification provider-request limit reached")
                self._records.append({"kind": "blocked", "reason": "request_limit"})
                return
            if self._scope_requests >= self._scope_max_provider_requests:
                handler.send_error(429, "qualification stage request limit reached")
                self._records.append(
                    {
                        "kind": "blocked",
                        "reason": "scope_request_limit",
                        "scope": self._scope_label,
                    }
                )
                return
            # One byte per input token is deliberately much more conservative
            # than normal text tokenization. Reserving a model's documented
            # maximum output makes the cap fail closed before each request.
            worst_request_cost = (
                len(body) * self.input_usd_per_million_tokens
                + self.maximum_output_tokens_per_request
                * self.output_usd_per_million_tokens
            ) / 1_000_000
            if (
                self._estimated_cost_usd
                + self._reserved_cost_usd
                + worst_request_cost
                > self.cost_cap_usd
            ):
                handler.send_error(429, "qualification cost cap reached")
                self._records.append(
                    {
                        "kind": "blocked",
                        "reason": "cost_cap",
                        "observed_estimated_cost_usd": round(
                            self._estimated_cost_usd, 8
                        ),
                        "reserved_request_cost_usd": round(worst_request_cost, 8),
                    }
                )
                return
            self._provider_requests += 1
            self._scope_requests += 1
            self._reserved_cost_usd += worst_request_cost
            ordinal = self._provider_requests
            scope = self._scope_label
            scope_ordinal = self._scope_requests
        try:
            token, expiry = self.token_provider()
        except Exception:
            with self._lock:
                self._reserved_cost_usd -= worst_request_cost
            handler.send_error(502, "qualification OAuth token unavailable")
            self._record(
                {
                    "kind": "blocked",
                    "reason": "oauth_token_unavailable",
                    "scope": scope,
                }
            )
            return
        query = urlsplit(handler.path).query
        target = self.upstream_origin + path + ("?" + query if query else "")
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": handler.headers.get("Content-Type", "application/json"),
            "Accept": handler.headers.get("Accept", "*/*"),
            "X-Vertex-AI-LLM-Request-Type": "shared",
        }
        request = Request(target, data=body, headers=headers, method="POST")
        status = 502
        response_body = b""
        response_headers: Mapping[str, str] = {}
        try:
            with urlopen(request, timeout=180) as response:
                status = response.status
                response_body = response.read()
                response_headers = response.headers
        except HTTPError as exc:
            status = exc.code
            response_body = exc.read()
            response_headers = exc.headers
        except OSError:
            response_body = b'{"error":{"message":"qualification upstream unavailable"}}'
        handler.send_response(status)
        for name in ("Content-Type", "Cache-Control"):
            value = response_headers.get(name)
            if value:
                handler.send_header(name, value)
        handler.send_header("Content-Length", str(len(response_body)))
        handler.end_headers()
        handler.wfile.write(response_body)
        prompt_tokens, output_tokens = self._usage_tokens(response_body)
        request_cost = (
            prompt_tokens * self.input_usd_per_million_tokens
            + output_tokens * self.output_usd_per_million_tokens
        ) / 1_000_000
        usage_missing = status == 200 and prompt_tokens == 0 and output_tokens == 0
        if usage_missing:
            request_cost = worst_request_cost
        with self._lock:
            self._reserved_cost_usd -= worst_request_cost
            self._estimated_cost_usd += request_cost
            cumulative_cost = self._estimated_cost_usd
        self._record(
            {
                "kind": "provider_request",
                "ordinal": ordinal,
                "scope": scope,
                "scope_ordinal": scope_ordinal,
                "action": action,
                "request_sha256": hashlib.sha256(body).hexdigest(),
                "request_bytes": len(body),
                "response_sha256": hashlib.sha256(response_body).hexdigest(),
                "response_bytes": len(response_body),
                "status": status,
                "usage": {
                    "prompt_tokens": prompt_tokens,
                    "output_and_reasoning_tokens": output_tokens,
                    "usage_metadata_missing": usage_missing,
                    "estimated_cost_usd": round(request_cost, 8),
                    "cumulative_estimated_cost_usd": round(cumulative_cost, 8),
                },
                "oauth_expires_at": datetime.fromtimestamp(
                    expiry, tz=timezone.utc
                ).isoformat(),
            }
        )

    @staticmethod
    def _usage_tokens(response_body: bytes) -> tuple[int, int]:
        documents: list[Mapping[str, Any]] = []
        decoded = response_body.decode("utf-8", errors="replace")
        try:
            direct = json.loads(decoded)
            if isinstance(direct, Mapping):
                documents.append(direct)
        except json.JSONDecodeError:
            for line in decoded.splitlines():
                if not line.startswith("data:"):
                    continue
                try:
                    value = json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue
                if isinstance(value, Mapping):
                    documents.append(value)
        prompt = 0
        output = 0
        for document in documents:
            usage = document.get("usageMetadata")
            if not isinstance(usage, Mapping):
                continue
            raw_prompt = usage.get("promptTokenCount", 0)
            raw_candidates = usage.get("candidatesTokenCount", 0)
            raw_thoughts = usage.get("thoughtsTokenCount", 0)
            raw_total = usage.get("totalTokenCount", 0)
            values = (raw_prompt, raw_candidates, raw_thoughts, raw_total)
            if any(
                not isinstance(value, int) or isinstance(value, bool) or value < 0
                for value in values
            ):
                continue
            prompt = max(prompt, raw_prompt)
            output = max(
                output,
                raw_candidates + raw_thoughts,
                max(0, raw_total - raw_prompt),
            )
        return prompt, output

    def start(self, client_dir: Path) -> VertexProxyClientBinding:
        if self._server is not None:
            raise VertexAuthProxyError("proxy already started")
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "SafetyBenchVertexProxy/1"

            def log_message(self, _format: str, *_args: Any) -> None:
                return

            def do_GET(self) -> None:  # noqa: N802
                self.send_error(405, "GET is not allowed")

            def do_POST(self) -> None:  # noqa: N802
                raw_length = self.headers.get("Content-Length")
                try:
                    length = int(raw_length or "0")
                except ValueError:
                    self.send_error(400, "invalid Content-Length")
                    return
                if length < 1 or length > proxy.max_request_bytes:
                    self.send_error(413, "qualification request body outside limit")
                    proxy._record({"kind": "blocked", "reason": "request_size", "bytes": length})
                    return
                body = self.rfile.read(length)
                if urlsplit(self.path).path == "/qualification-sts":
                    response = json.dumps(
                        {
                            "access_token": _PLACEHOLDER_TOKEN,
                            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                            "token_type": "Bearer",
                            "expires_in": 3600,
                        },
                        separators=(",", ":"),
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(response)))
                    self.end_headers()
                    self.wfile.write(response)
                    proxy._record({"kind": "placeholder_token_exchange"})
                    return
                proxy._forward(self, body)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="safety-bench-vertex-qualification-proxy",
            daemon=True,
        )
        self._started_at = datetime.now(timezone.utc).isoformat()
        self._thread.start()
        client_dir = Path(client_dir).resolve()
        client_dir.mkdir(parents=True, exist_ok=True)
        subject_path = client_dir / "qualification-subject.txt"
        adc_path = client_dir / "qualification-external-account.json"
        subject_path.write_text("qualification-placeholder-subject\n", encoding="utf-8")
        adc = {
            "type": "external_account",
            "audience": "//iam.googleapis.com/projects/0/locations/global/workloadIdentityPools/qualification/providers/loopback",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": self.base_url + "/qualification-sts",
            "credential_source": {"file": str(subject_path), "format": {"type": "text"}},
        }
        adc_path.write_text(
            json.dumps(adc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return VertexProxyClientBinding(
            base_url=self.base_url,
            adc_path=adc_path,
            project=self.project,
            location=self.location,
        )

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        evidence = {
            "schema_name": "safety_bench_gemini_vertex_proxy_evidence",
            "schema_version": 1,
            "started_at": self._started_at,
            "stopped_at": datetime.now(timezone.utc).isoformat(),
            "route": {
                "project_sha256": hashlib.sha256(self.project.encode()).hexdigest(),
                "location": self.location,
                "model": self.model,
                "allowed_actions": sorted(_ALLOWED_ACTIONS),
                "upstream_origin": self.upstream_origin,
            },
            "limits": {
                "max_provider_requests": self.max_provider_requests,
                "max_request_bytes": self.max_request_bytes,
                "cost_cap_usd": self.cost_cap_usd,
                "input_usd_per_million_tokens": self.input_usd_per_million_tokens,
                "output_usd_per_million_tokens": self.output_usd_per_million_tokens,
                "maximum_output_tokens_per_request": self.maximum_output_tokens_per_request,
            },
            "provider_requests": self._provider_requests,
            "estimated_cost_usd": round(self._estimated_cost_usd, 8),
            "records": self._records,
            "long_term_credential_exposed_to_child": False,
            "real_oauth_token_exposed_to_child": False,
        }
        self.evidence_path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_path.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self._server = None
        self._thread = None

    def __enter__(self) -> "VertexQualificationProxy":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()


__all__ = [
    "ServiceAccountTokenProvider",
    "VertexAuthProxyError",
    "VertexProxyClientBinding",
    "VertexQualificationProxy",
]
