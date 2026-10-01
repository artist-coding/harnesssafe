"""OpenAI-compatible chat-completions proxy for Gemini CLI runs.

Gemini CLI 0.51.0 speaks the Gemini/Vertex ``generateContent`` wire shape.
Some deployments expose the requested Gemini model through an OpenAI-compatible
``/v1/chat/completions`` endpoint instead.  This proxy keeps the Gemini child
process on the existing run-local Vertex-shaped loopback route and translates
requests/responses at the boundary.

The upstream API key is held only by this parent-side proxy.  It is never placed
in the child environment, run-local ADC file, Gemini settings, traces, or
machine-readable evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import threading
from typing import Any, Mapping
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class OpenAICompatProxyError(RuntimeError):
    """The OpenAI-compatible proxy rejected or failed a request."""


_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ALLOWED_ACTIONS = frozenset(
    {"generateContent", "streamGenerateContent", "countTokens"}
)
_PLACEHOLDER_TOKEN = "safety-bench-openai-compat-placeholder"


@dataclass(frozen=True)
class OpenAICompatProxyClientBinding:
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


def _json_response(handler: BaseHTTPRequestHandler, status: int, value: Mapping[str, Any]) -> None:
    body = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _sse_response(handler: BaseHTTPRequestHandler, status: int, value: Mapping[str, Any]) -> None:
    payload = (
        "data: "
        + json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        + "\n\n"
    ).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/event-stream")
    handler.send_header("Cache-Control", "no-cache")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def _parts_text(parts: Any, label: str) -> str:
    if not isinstance(parts, list):
        raise OpenAICompatProxyError(f"{label} parts must be an array")
    chunks: list[str] = []
    for part in parts:
        if not isinstance(part, Mapping):
            raise OpenAICompatProxyError(f"{label} part must be an object")
        if "text" in part:
            text = part["text"]
            if not isinstance(text, str):
                raise OpenAICompatProxyError(f"{label} text part must be a string")
            chunks.append(text)
            continue
        if "functionCall" in part or "functionResponse" in part:
            continue
        raise OpenAICompatProxyError(
            f"{label} contains a non-text/non-function part unsupported by chat/completions"
        )
    return "\n".join(chunk for chunk in chunks if chunk)


def _tool_call_id(name: str, ordinal: int, payload: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(
        json.dumps(
            {"name": name, "ordinal": ordinal, "payload": payload},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()[:24]
    return f"call_{digest}"


def _normalize_gemini_cli_tool_args(
    name: str, args: Mapping[str, Any]
) -> dict[str, Any]:
    normalized = dict(args)
    if name in {"read_file", "write_file", "replace"} and "file_path" not in normalized:
        path = normalized.pop("path", None)
        if isinstance(path, str) and path:
            normalized["file_path"] = path
    if name == "list_directory":
        path = normalized.pop("path", None)
        if "dir_path" not in normalized and isinstance(path, str) and path:
            normalized["dir_path"] = path
        if "dir_path" not in normalized:
            normalized["dir_path"] = "."
    return normalized


def _gemini_tools_to_openai(raw_tools: Any) -> list[dict[str, Any]]:
    if raw_tools is None:
        return []
    if not isinstance(raw_tools, list):
        raise OpenAICompatProxyError("Gemini tools must be an array")
    tools: list[dict[str, Any]] = []
    for tool in raw_tools:
        if not isinstance(tool, Mapping):
            raise OpenAICompatProxyError("Gemini tool declaration must be an object")
        declarations = tool.get("functionDeclarations", [])
        if not isinstance(declarations, list):
            raise OpenAICompatProxyError("functionDeclarations must be an array")
        for declaration in declarations:
            if not isinstance(declaration, Mapping):
                raise OpenAICompatProxyError("function declaration must be an object")
            name = declaration.get("name")
            if not isinstance(name, str) or not name:
                raise OpenAICompatProxyError("function declaration lacks name")
            function: dict[str, Any] = {"name": name}
            description = declaration.get("description")
            if isinstance(description, str):
                function["description"] = description
            parameters = declaration.get("parameters")
            if isinstance(parameters, Mapping):
                function["parameters"] = dict(parameters)
            tools.append({"type": "function", "function": function})
    return tools


def gemini_generate_to_chat_completion(
    body: Mapping[str, Any], *, model: str
) -> dict[str, Any]:
    messages: list[dict[str, Any]] = []
    pending_tool_ids: dict[str, list[str]] = {}
    tool_ordinal = 0

    system = body.get("systemInstruction")
    if isinstance(system, Mapping):
        text = _parts_text(system.get("parts", []), "systemInstruction")
        if text:
            messages.append({"role": "system", "content": text})

    contents = body.get("contents", [])
    if not isinstance(contents, list) or not contents:
        raise OpenAICompatProxyError("Gemini request contains no contents")
    for content in contents:
        if not isinstance(content, Mapping):
            raise OpenAICompatProxyError("Gemini content item must be an object")
        role = content.get("role")
        parts = content.get("parts", [])
        if role == "model":
            text = _parts_text(parts, "model content")
            tool_calls: list[dict[str, Any]] = []
            for part in parts:
                if not isinstance(part, Mapping) or "functionCall" not in part:
                    continue
                call = part["functionCall"]
                if not isinstance(call, Mapping):
                    raise OpenAICompatProxyError("functionCall must be an object")
                name = call.get("name")
                args = call.get("args", {})
                if not isinstance(name, str) or not name:
                    raise OpenAICompatProxyError("functionCall lacks name")
                if not isinstance(args, Mapping):
                    raise OpenAICompatProxyError("functionCall args must be an object")
                tool_ordinal += 1
                call_id = _tool_call_id(name, tool_ordinal, args)
                pending_tool_ids.setdefault(name, []).append(call_id)
                tool_calls.append(
                    {
                        "id": call_id,
                        "type": "function",
                        "function": {
                            "name": name,
                            "arguments": json.dumps(
                                args,
                                sort_keys=True,
                                separators=(",", ":"),
                                ensure_ascii=False,
                            ),
                        },
                    }
                )
            message: dict[str, Any] = {"role": "assistant", "content": text or None}
            if tool_calls:
                message["tool_calls"] = tool_calls
            messages.append(message)
            continue

        # Gemini function responses usually arrive in user-role contents.
        function_response_parts = [
            part
            for part in parts
            if isinstance(part, Mapping) and "functionResponse" in part
        ]
        text = _parts_text(parts, "user content")
        if text:
            messages.append({"role": "user", "content": text})
        for part in function_response_parts:
            response = part["functionResponse"]
            if not isinstance(response, Mapping):
                raise OpenAICompatProxyError("functionResponse must be an object")
            name = response.get("name")
            payload = response.get("response", {})
            if not isinstance(name, str) or not name:
                raise OpenAICompatProxyError("functionResponse lacks name")
            call_ids = pending_tool_ids.get(name) or []
            call_id = call_ids.pop(0) if call_ids else _tool_call_id(name, 0, response)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call_id,
                    "name": name,
                    "content": json.dumps(
                        payload,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ),
                }
            )

    request: dict[str, Any] = {"model": model, "messages": messages, "stream": False}
    tools = _gemini_tools_to_openai(body.get("tools"))
    if tools:
        request["tools"] = tools
        request["tool_choice"] = "auto"
    generation_config = body.get("generationConfig")
    if isinstance(generation_config, Mapping):
        mapping = {
            "temperature": "temperature",
            "topP": "top_p",
            "maxOutputTokens": "max_tokens",
        }
        for source, target in mapping.items():
            value = generation_config.get(source)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                request[target] = value
    return request


def chat_completion_to_gemini_response(body: Mapping[str, Any]) -> dict[str, Any]:
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        raise OpenAICompatProxyError("chat completion response contains no choices")
    first = choices[0]
    if not isinstance(first, Mapping):
        raise OpenAICompatProxyError("chat completion choice must be an object")
    message = first.get("message")
    if not isinstance(message, Mapping):
        raise OpenAICompatProxyError("chat completion choice lacks message")
    parts: list[dict[str, Any]] = []
    content = message.get("content")
    if isinstance(content, str) and content.strip():
        parts.append({"text": content})
    tool_calls = message.get("tool_calls", [])
    if tool_calls is None:
        tool_calls = []
    if not tool_calls and isinstance(message.get("function_call"), Mapping):
        tool_calls = [{"function": message["function_call"]}]
    if not isinstance(tool_calls, list):
        raise OpenAICompatProxyError("chat completion tool_calls must be an array")
    for tool_call in tool_calls:
        if not isinstance(tool_call, Mapping):
            raise OpenAICompatProxyError("tool_call must be an object")
        function = tool_call.get("function")
        if not isinstance(function, Mapping):
            continue
        name = function.get("name")
        raw_args = function.get("arguments", "{}")
        if not isinstance(name, str) or not name:
            raise OpenAICompatProxyError("tool_call function lacks name")
        if not isinstance(raw_args, str):
            raw_args = "{}"
        try:
            args = json.loads(raw_args) if raw_args else {}
        except json.JSONDecodeError:
            args = {"_raw_arguments": raw_args}
        if not isinstance(args, Mapping):
            args = {"_raw_arguments": raw_args}
        args = _normalize_gemini_cli_tool_args(name, args)
        parts.append({"functionCall": {"name": name, "args": dict(args)}})
    if not parts:
        parts.append({"text": "Done."})

    usage = body.get("usage", {})
    prompt_tokens = usage.get("prompt_tokens", 0) if isinstance(usage, Mapping) else 0
    completion_tokens = (
        usage.get("completion_tokens", 0) if isinstance(usage, Mapping) else 0
    )
    total_tokens = usage.get("total_tokens", 0) if isinstance(usage, Mapping) else 0
    usage_metadata = {
        "promptTokenCount": prompt_tokens if isinstance(prompt_tokens, int) else 0,
        "candidatesTokenCount": (
            completion_tokens if isinstance(completion_tokens, int) else 0
        ),
        "totalTokenCount": total_tokens if isinstance(total_tokens, int) else 0,
    }
    finish_reason = first.get("finish_reason")
    mapped_finish = "STOP" if finish_reason in {None, "stop", "tool_calls"} else "OTHER"
    return {
        "candidates": [
            {
                "content": {"role": "model", "parts": parts},
                "finishReason": mapped_finish,
            }
        ],
        "usageMetadata": usage_metadata,
    }


def _usage_tokens_from_chat(body: Mapping[str, Any]) -> tuple[int, int]:
    usage = body.get("usage")
    if not isinstance(usage, Mapping):
        return 0, 0
    prompt = usage.get("prompt_tokens", 0)
    completion = usage.get("completion_tokens", 0)
    return (
        prompt if isinstance(prompt, int) and prompt >= 0 else 0,
        completion if isinstance(completion, int) and completion >= 0 else 0,
    )


class OpenAICompatibleVertexProxy:
    """Loopback Vertex-shaped proxy backed by chat/completions."""

    def __init__(
        self,
        *,
        project: str,
        location: str,
        model: str,
        api_base_url: str,
        api_key: str,
        evidence_path: Path,
        max_provider_requests: int = 20_000,
        max_request_bytes: int = 1_000_000,
        timeout_seconds: int = 180,
    ) -> None:
        for label, value in (("project", project), ("location", location), ("model", model)):
            if not isinstance(value, str) or not _SAFE_ID_RE.fullmatch(value):
                raise ValueError(f"unsafe proxy {label}")
        parsed = urlsplit(api_base_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("api_base_url must be an HTTPS URL")
        if not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("api_key must be non-empty")
        if max_provider_requests < 1 or max_request_bytes < 1 or timeout_seconds < 1:
            raise ValueError("proxy limits must be positive")
        self.project = project
        self.location = location
        self.model = model
        self.api_base_url = api_base_url.rstrip("/")
        self.api_key = api_key
        self.evidence_path = Path(evidence_path).resolve()
        self.max_provider_requests = max_provider_requests
        self.max_request_bytes = max_request_bytes
        self.timeout_seconds = timeout_seconds
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._records: list[dict[str, Any]] = []
        self._provider_requests = 0
        self._started_at = ""
        self._scope_label = "unscoped"
        self._scope_requests = 0
        self._scope_max_provider_requests = max_provider_requests
        self._prompt_tokens = 0
        self._completion_tokens = 0

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise OpenAICompatProxyError("proxy has not started")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def _record(self, record: Mapping[str, Any]) -> None:
        with self._lock:
            self._records.append(dict(record))

    def begin_scope(self, label: str, *, max_provider_requests: int = 12) -> None:
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

    def _forward_chat(self, handler: BaseHTTPRequestHandler, body: bytes, *, stream: bool) -> None:
        try:
            gemini_body = json.loads(body.decode("utf-8"))
            if not isinstance(gemini_body, Mapping):
                raise OpenAICompatProxyError("Gemini request body must be an object")
            chat_request = gemini_generate_to_chat_completion(
                gemini_body, model=self.model
            )
        except (json.JSONDecodeError, OpenAICompatProxyError) as exc:
            _json_response(handler, 400, {"error": {"message": str(exc)}})
            self._record({"kind": "blocked", "reason": "translation", "message": str(exc)})
            return

        request_body = json.dumps(
            chat_request, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        with self._lock:
            if self._provider_requests >= self.max_provider_requests:
                _json_response(handler, 429, {"error": {"message": "provider request limit reached"}})
                self._records.append({"kind": "blocked", "reason": "request_limit"})
                return
            if self._scope_requests >= self._scope_max_provider_requests:
                _json_response(handler, 429, {"error": {"message": "stage request limit reached"}})
                self._records.append(
                    {
                        "kind": "blocked",
                        "reason": "scope_request_limit",
                        "scope": self._scope_label,
                    }
                )
                return
            self._provider_requests += 1
            self._scope_requests += 1
            ordinal = self._provider_requests
            scope = self._scope_label
            scope_ordinal = self._scope_requests

        request = Request(
            self.api_base_url + "/chat/completions",
            data=request_body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        status = 502
        response_body = b""
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                status = response.status
                response_body = response.read()
        except HTTPError as exc:
            status = exc.code
            response_body = exc.read()
        except OSError:
            response_body = b'{"error":{"message":"chat-completions upstream unavailable"}}'

        try:
            decoded = json.loads(response_body.decode("utf-8", errors="replace"))
            if not isinstance(decoded, Mapping):
                raise OpenAICompatProxyError("chat completion response is not an object")
            if status == 200:
                vertex_response = chat_completion_to_gemini_response(decoded)
            else:
                vertex_response = {"error": decoded.get("error", decoded)}
        except (json.JSONDecodeError, OpenAICompatProxyError) as exc:
            status = 502
            vertex_response = {"error": {"message": str(exc)}}
            decoded = {}

        prompt_tokens, completion_tokens = (
            _usage_tokens_from_chat(decoded) if isinstance(decoded, Mapping) else (0, 0)
        )
        with self._lock:
            self._prompt_tokens += prompt_tokens
            self._completion_tokens += completion_tokens
        self._record(
            {
                "kind": "provider_request",
                "ordinal": ordinal,
                "scope": scope,
                "scope_ordinal": scope_ordinal,
                "action": "streamGenerateContent" if stream else "generateContent",
                "request_sha256": hashlib.sha256(body).hexdigest(),
                "translated_request_sha256": hashlib.sha256(request_body).hexdigest(),
                "request_bytes": len(body),
                "translated_request_bytes": len(request_body),
                "response_sha256": hashlib.sha256(response_body).hexdigest(),
                "status": status,
                "usage": {
                    "prompt_tokens": prompt_tokens,
                    "output_tokens": completion_tokens,
                },
            }
        )
        if stream:
            _sse_response(handler, status, vertex_response)
        else:
            _json_response(handler, status, vertex_response)

    def start(self, client_dir: Path) -> OpenAICompatProxyClientBinding:
        if self._server is not None:
            raise OpenAICompatProxyError("proxy already started")
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "SafetyBenchOpenAICompatProxy/1"

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
                    self.send_error(413, "request body outside limit")
                    proxy._record({"kind": "blocked", "reason": "request_size", "bytes": length})
                    return
                body = self.rfile.read(length)
                if urlsplit(self.path).path == "/qualification-sts":
                    response = {
                        "access_token": _PLACEHOLDER_TOKEN,
                        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }
                    _json_response(self, 200, response)
                    proxy._record({"kind": "placeholder_token_exchange"})
                    return
                allowed = proxy._allowed_path(self.path)
                if allowed is None:
                    self.send_error(403, "path is outside OpenAI-compatible allow-list")
                    proxy._record(
                        {
                            "kind": "blocked",
                            "reason": "path",
                            "path_sha256": hashlib.sha256(self.path.encode()).hexdigest(),
                        }
                    )
                    return
                _path, action = allowed
                if action == "countTokens":
                    approx = max(1, len(body) // 4)
                    _json_response(self, 200, {"totalTokens": approx})
                    proxy._record(
                        {
                            "kind": "count_tokens_estimate",
                            "request_sha256": hashlib.sha256(body).hexdigest(),
                            "totalTokens": approx,
                        }
                    )
                    return
                proxy._forward_chat(
                    self,
                    body,
                    stream=action == "streamGenerateContent",
                )

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="safety-bench-openai-compatible-proxy",
            daemon=True,
        )
        self._started_at = datetime.now(timezone.utc).isoformat()
        self._thread.start()
        client_dir = Path(client_dir).resolve()
        client_dir.mkdir(parents=True, exist_ok=True)
        subject_path = client_dir / "openai-compat-subject.txt"
        adc_path = client_dir / "openai-compat-external-account.json"
        subject_path.write_text("openai-compatible-placeholder-subject\n", encoding="utf-8")
        adc = {
            "type": "external_account",
            "audience": "//iam.googleapis.com/projects/0/locations/global/workloadIdentityPools/openai-compatible/providers/loopback",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": self.base_url + "/qualification-sts",
            "credential_source": {"file": str(subject_path), "format": {"type": "text"}},
        }
        adc_path.write_text(
            json.dumps(adc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return OpenAICompatProxyClientBinding(
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
            "schema_name": "safety_bench_gemini_openai_compat_proxy_evidence",
            "schema_version": 1,
            "started_at": self._started_at,
            "stopped_at": datetime.now(timezone.utc).isoformat(),
            "route": {
                "provider_kind": "openai_compatible_chat_completions",
                "api_base_url": self.api_base_url,
                "model": self.model,
                "vertex_shim": {"project": self.project, "location": self.location},
                "allowed_vertex_actions": sorted(_ALLOWED_ACTIONS),
                "api_key_sha256": hashlib.sha256(self.api_key.encode()).hexdigest(),
                "credential_value_recorded": False,
            },
            "limits": {
                "max_provider_requests": self.max_provider_requests,
                "max_request_bytes": self.max_request_bytes,
                "timeout_seconds": self.timeout_seconds,
            },
            "provider_requests": self._provider_requests,
            "estimated_cost_usd": None,
            "usage": {
                "prompt_tokens": self._prompt_tokens,
                "output_tokens": self._completion_tokens,
            },
            "records": self._records,
            "upstream_api_key_exposed_to_child": False,
        }
        self.evidence_path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_path.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self._server = None
        self._thread = None

    def __enter__(self) -> "OpenAICompatibleVertexProxy":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()


__all__ = [
    "OpenAICompatProxyClientBinding",
    "OpenAICompatProxyError",
    "OpenAICompatibleVertexProxy",
    "chat_completion_to_gemini_response",
    "gemini_generate_to_chat_completion",
]
