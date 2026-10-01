"""Fail-closed, design-time probing of case-local MCP stdio interfaces.

The probe intentionally supports only repository-owned Python fixtures.  It
does not execute the command recorded in an MCP config: after validating that
the command denotes Python and that its first argument resolves to a case-local
``.py`` file, it launches that file with the *current* Python interpreter.

Only interface-discovery methods are sent.  Tool calls, resource reads, and
prompt expansion are deliberately outside this module's scope.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
PROTOCOL_VERSION = "2024-11-05"
MAX_CAPTURE_BYTES = 4 * 1024 * 1024
_PYTHON_COMMAND_NAMES = {"python", "python.exe", "python3", "python3.exe", "py", "py.exe"}
_METHODS = ("initialize", "tools/list", "resources/list", "prompts/list")


class ProbeError(RuntimeError):
    """Raised when an MCP interface cannot be verified safely and completely."""


@dataclass(frozen=True)
class ServerSpec:
    """A validated command for one case-local Python MCP server."""

    name: str
    script: Path
    args: tuple[str, ...]
    cwd: Path


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _resolve_file_within(path: Path, root: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ProbeError(f"{label} does not resolve to an existing file: {path}") from exc
    if not resolved.is_file():
        raise ProbeError(f"{label} is not a file: {resolved}")
    if not _is_within(resolved, root):
        raise ProbeError(f"{label} escapes the allowed root {root}: {resolved}")
    return resolved


def _python_command_is_allowed(command: str) -> bool:
    if not command or command != command.strip():
        return False
    command_path = Path(command)
    if command_path.name.lower() not in _PYTHON_COMMAND_NAMES:
        return False
    if command_path.is_absolute():
        try:
            return command_path.resolve(strict=True) == Path(sys.executable).resolve(strict=True)
        except (OSError, RuntimeError):
            return False
    # A bare command name is treated only as a declaration of intent.  The
    # process below always uses sys.executable and never searches PATH.
    return len(command_path.parts) == 1


def replace_mode_argument(args: Sequence[str], clean_mode: str) -> tuple[str, ...]:
    """Return ``args`` with its single ``--mode VALUE`` replaced.

    Missing, repeated, valueless, or option-looking mode values are rejected so
    a requested clean probe can never silently exercise the attack mode.
    """

    if not isinstance(clean_mode, str) or not clean_mode or clean_mode != clean_mode.strip():
        raise ProbeError("clean_mode must be a non-empty string without surrounding whitespace")
    positions = [index for index, value in enumerate(args) if value == "--mode"]
    if len(positions) != 1:
        raise ProbeError(f"mode override requires exactly one --mode argument, found {len(positions)}")
    index = positions[0]
    if index + 1 >= len(args) or not args[index + 1] or args[index + 1].startswith("-"):
        raise ProbeError("--mode must have one explicit value")
    replaced = list(args)
    replaced[index + 1] = clean_mode
    return tuple(replaced)


def _resolve_server_script(case_root: Path, config_dir: Path, raw_script: str) -> Path:
    if not raw_script.lower().endswith(".py"):
        raise ProbeError("the first server argument must name a .py file")

    requested = Path(raw_script)
    if requested.is_absolute():
        candidates = [requested]
    else:
        # MCP clients in this repository run with the case workspace as cwd,
        # while hand-authored configs sometimes use config-relative paths.
        # Accept either interpretation only when it resolves unambiguously.
        candidates = [config_dir / requested, case_root / requested]
        workspace = case_root / "workspace"
        if workspace.is_dir():
            candidates.append(workspace / requested)

    resolved: list[Path] = []
    for candidate in candidates:
        try:
            path = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if path.is_file() and path.suffix.lower() == ".py" and path not in resolved:
            resolved.append(path)

    if not resolved:
        raise ProbeError(f"server script does not resolve to an existing .py file: {raw_script}")
    if len(resolved) != 1:
        rendered = ", ".join(str(path) for path in resolved)
        raise ProbeError(f"server script path is ambiguous: {raw_script} -> {rendered}")
    script = resolved[0]
    if not _is_within(script, case_root):
        raise ProbeError(f"server script is not case-local: {script}")
    if not _is_within(script, REPO_ROOT.resolve()):
        raise ProbeError(f"server script is outside the repository: {script}")
    return script


def _mode_for_server(clean_mode: str | Mapping[str, str] | None, server_name: str) -> str | None:
    if clean_mode is None:
        return None
    if isinstance(clean_mode, str):
        return clean_mode
    if not isinstance(clean_mode, Mapping):
        raise ProbeError("clean_mode must be a string, a server-name mapping, or None")
    value = clean_mode.get(server_name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ProbeError(f"clean mode for server {server_name!r} must be a string")
    return value


def load_server_specs(
    case_root: str | Path,
    config_path: str | Path,
    *,
    clean_mode: str | Mapping[str, str] | None = None,
) -> tuple[ServerSpec, ...]:
    """Parse an MCP config into validated, deterministic server specs."""

    try:
        root = Path(case_root).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ProbeError(f"case_root does not exist: {case_root}") from exc
    if not root.is_dir():
        raise ProbeError(f"case_root is not a directory: {root}")
    if not _is_within(root, REPO_ROOT.resolve()):
        raise ProbeError(f"case_root is outside the repository: {root}")

    raw_config = Path(config_path)
    if raw_config.is_absolute():
        config_candidates = [raw_config]
    else:
        # Accept both the natural case-relative spelling (``mcp.json``) and a
        # repository-relative Path that a manifest walker may already have
        # constructed (``runs/active/.../mcp.json``).
        config_candidates = [root / raw_config, REPO_ROOT / raw_config]
    resolved_configs: list[Path] = []
    for candidate in config_candidates:
        try:
            resolved_candidate = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if (
            resolved_candidate.is_file()
            and _is_within(resolved_candidate, root)
            and resolved_candidate not in resolved_configs
        ):
            resolved_configs.append(resolved_candidate)
    if not resolved_configs:
        raise ProbeError(f"MCP config does not resolve to a case-local file: {config_path}")
    if len(resolved_configs) != 1:
        raise ProbeError(f"MCP config path is ambiguous: {config_path}")
    config = resolved_configs[0]
    try:
        document = json.loads(config.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProbeError(f"MCP config is not valid UTF-8 JSON: {config}") from exc
    if not isinstance(document, dict):
        raise ProbeError("MCP config root must be an object")
    servers = document.get("mcpServers")
    if not isinstance(servers, dict) or not servers:
        raise ProbeError("MCP config must contain a non-empty mcpServers object")

    if isinstance(clean_mode, Mapping):
        unknown = sorted(set(clean_mode) - set(servers))
        if unknown:
            raise ProbeError(f"clean_mode names unknown MCP servers: {unknown}")

    cwd = root / "workspace" if (root / "workspace").is_dir() else root
    specs: list[ServerSpec] = []
    for server_name in sorted(servers):
        if not isinstance(server_name, str) or not server_name:
            raise ProbeError("MCP server names must be non-empty strings")
        definition = servers[server_name]
        if not isinstance(definition, dict):
            raise ProbeError(f"MCP server {server_name!r} definition must be an object")
        if definition.get("env") is not None or definition.get("cwd") is not None:
            raise ProbeError(f"MCP server {server_name!r} may not override env or cwd during probing")
        command = definition.get("command")
        if not isinstance(command, str) or not _python_command_is_allowed(command):
            raise ProbeError(f"MCP server {server_name!r} command is not an allowed Python command")
        raw_args = definition.get("args")
        if not isinstance(raw_args, list) or not raw_args:
            raise ProbeError(f"MCP server {server_name!r} args must be a non-empty list")
        if any(not isinstance(value, str) for value in raw_args):
            raise ProbeError(f"MCP server {server_name!r} args must contain only strings")
        script = _resolve_server_script(root, config.parent, raw_args[0])
        args = tuple(raw_args[1:])
        override = _mode_for_server(clean_mode, server_name)
        if override is not None:
            args = replace_mode_argument(args, override)
        specs.append(ServerSpec(name=server_name, script=script, args=args, cwd=cwd))
    return tuple(specs)


def _probe_environment() -> dict[str, str]:
    # Do not leak credentials or project-specific environment variables into a
    # design-time fixture.  Python on Windows needs SystemRoot to initialize.
    allowed = ("SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR")
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
        }
    )
    return environment


def _request_bytes() -> bytes:
    requests: list[dict[str, Any]] = [
        {
            "jsonrpc": "2.0",
            "id": "initialize",
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "safety-bench-interface-probe", "version": "1.0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
    ]
    requests.extend(
        {"jsonrpc": "2.0", "id": method, "method": method, "params": {}}
        for method in _METHODS[1:]
    )
    return b"".join(
        json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        for request in requests
    )


def _parse_messages(raw: bytes) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    offset = 0
    length = len(raw)
    while offset < length:
        while offset < length and raw[offset : offset + 1] in {b"\r", b"\n"}:
            offset += 1
        if offset >= length:
            break
        if raw[offset : offset + 15].lower() == b"content-length:":
            header_end = raw.find(b"\r\n\r\n", offset)
            separator_length = 4
            if header_end < 0:
                header_end = raw.find(b"\n\n", offset)
                separator_length = 2
            if header_end < 0:
                raise ProbeError("MCP response has an incomplete Content-Length header")
            headers = raw[offset:header_end].replace(b"\r\n", b"\n").split(b"\n")
            content_lengths: list[int] = []
            for header in headers:
                name, separator, value = header.partition(b":")
                if not separator:
                    raise ProbeError("MCP response contains a malformed header")
                if name.strip().lower() == b"content-length":
                    try:
                        content_lengths.append(int(value.strip()))
                    except ValueError as exc:
                        raise ProbeError("MCP response has an invalid Content-Length") from exc
            if len(content_lengths) != 1 or content_lengths[0] < 0:
                raise ProbeError("MCP response must have exactly one valid Content-Length")
            body_start = header_end + separator_length
            body_end = body_start + content_lengths[0]
            if body_end > length:
                raise ProbeError("MCP response body is shorter than Content-Length")
            payload = raw[body_start:body_end]
            offset = body_end
        else:
            line_end = raw.find(b"\n", offset)
            if line_end < 0:
                line_end = length
            payload = raw[offset:line_end].rstrip(b"\r")
            offset = line_end + 1
        try:
            message = json.loads(payload.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ProbeError("MCP stdout contains a malformed JSON-RPC message") from exc
        if not isinstance(message, dict):
            raise ProbeError("MCP JSON-RPC responses must be objects")
        messages.append(message)
    return messages


def _normalize_json(value: Any, *, collection_key: str | None = None) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ProbeError("MCP response contains a non-finite number")
        return value
    if isinstance(value, dict):
        return {key: _normalize_json(value[key], collection_key=key) for key in sorted(value)}
    if isinstance(value, list):
        normalized = [_normalize_json(item) for item in value]
        if collection_key in {"tools", "resources", "prompts"}:
            def sort_key(item: Any) -> tuple[str, str]:
                if isinstance(item, dict):
                    identity = item.get("name") or item.get("uri") or ""
                else:
                    identity = ""
                return str(identity), canonical_json(item)

            normalized.sort(key=sort_key)
        elif collection_key == "required" and all(isinstance(item, str) for item in normalized):
            normalized.sort()
        return normalized
    raise ProbeError(f"MCP response contains a non-JSON value: {type(value).__name__}")


def _probe_server(spec: ServerSpec, timeout_seconds: float) -> dict[str, Any]:
    command = [sys.executable, "-I", str(spec.script), *spec.args]
    creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        process = subprocess.Popen(
            command,
            cwd=str(spec.cwd),
            env=_probe_environment(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creation_flags,
        )
    except OSError as exc:
        raise ProbeError(f"failed to launch MCP server {spec.name!r}: {exc}") from exc
    try:
        stdout, stderr = process.communicate(_request_bytes(), timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        stdout, stderr = process.communicate()
        raise ProbeError(f"MCP server {spec.name!r} timed out after {timeout_seconds:g}s") from exc
    if len(stdout) > MAX_CAPTURE_BYTES or len(stderr) > MAX_CAPTURE_BYTES:
        raise ProbeError(f"MCP server {spec.name!r} exceeded the probe output limit")
    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip()
        if len(detail) > 500:
            detail = detail[:500] + "..."
        suffix = f": {detail}" if detail else ""
        raise ProbeError(f"MCP server {spec.name!r} exited with code {process.returncode}{suffix}")

    responses = _parse_messages(stdout)
    by_id: dict[str, dict[str, Any]] = {}
    for response in responses:
        response_id = response.get("id")
        if response_id not in _METHODS:
            raise ProbeError(f"MCP server {spec.name!r} returned an unexpected response id: {response_id!r}")
        if response_id in by_id:
            raise ProbeError(f"MCP server {spec.name!r} returned duplicate response id {response_id!r}")
        if response.get("jsonrpc") != "2.0":
            raise ProbeError(f"MCP server {spec.name!r} returned an invalid JSON-RPC version")
        if "error" in response:
            raise ProbeError(
                f"MCP server {spec.name!r} returned an error for {response_id}: "
                f"{canonical_json(response['error'])}"
            )
        if "result" not in response or not isinstance(response["result"], dict):
            raise ProbeError(f"MCP server {spec.name!r} returned no object result for {response_id}")
        by_id[response_id] = response
    missing = [method for method in _METHODS if method not in by_id]
    if missing:
        raise ProbeError(f"MCP server {spec.name!r} omitted probe responses: {missing}")

    return {method: _normalize_json(by_id[method]["result"]) for method in _METHODS}


def probe_mcp_interface(
    case_root: str | Path,
    config_path: str | Path,
    *,
    clean_mode: str | Mapping[str, str] | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """Return a canonicalizable snapshot of all interfaces in an MCP config.

    The returned shape is exactly ``{"servers": {name: {method: result}}}``,
    with all four discovery methods present for every server.  Any partial or
    error response raises :class:`ProbeError`.
    """

    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise ProbeError("timeout_seconds must be a positive finite number")
    timeout = float(timeout_seconds)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ProbeError("timeout_seconds must be a positive finite number")
    specs = load_server_specs(case_root, config_path, clean_mode=clean_mode)
    return {"servers": {spec.name: _probe_server(spec, timeout) for spec in specs}}


def canonical_json(value: Any) -> str:
    """Serialize JSON data deterministically, rejecting NaN and infinities."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ProbeError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: Any) -> str:
    """Return the lowercase SHA-256 of :func:`canonical_json` UTF-8 bytes."""

    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def json_pointer_diff(left: Any, right: Any) -> list[dict[str, Any]]:
    """Return deterministic leaf/subtree differences using RFC 6901 pointers.

    Dictionary additions/removals and list additions/removals are reported at
    the exact new/old member pointer.  Scalar or type changes use ``changed``.
    The root pointer is the RFC 6901 empty string.
    """

    differences: list[dict[str, Any]] = []

    def visit(old: Any, new: Any, pointer: str) -> None:
        if isinstance(old, dict) and isinstance(new, dict):
            old_keys = set(old)
            new_keys = set(new)
            for key in sorted(old_keys - new_keys):
                child = pointer + "/" + _pointer_token(str(key))
                differences.append({"pointer": child, "kind": "removed", "left": old[key]})
            for key in sorted(new_keys - old_keys):
                child = pointer + "/" + _pointer_token(str(key))
                differences.append({"pointer": child, "kind": "added", "right": new[key]})
            for key in sorted(old_keys & new_keys):
                visit(old[key], new[key], pointer + "/" + _pointer_token(str(key)))
            return
        if isinstance(old, list) and isinstance(new, list):
            common = min(len(old), len(new))
            for index in range(common):
                visit(old[index], new[index], pointer + "/" + str(index))
            for index in range(common, len(old)):
                differences.append(
                    {"pointer": pointer + "/" + str(index), "kind": "removed", "left": old[index]}
                )
            for index in range(common, len(new)):
                differences.append(
                    {"pointer": pointer + "/" + str(index), "kind": "added", "right": new[index]}
                )
            return
        if type(old) is not type(new) or old != new:
            differences.append({"pointer": pointer, "kind": "changed", "left": old, "right": new})

    visit(left, right, "")
    return differences


__all__ = [
    "ProbeError",
    "ServerSpec",
    "canonical_json",
    "canonical_sha256",
    "json_pointer_diff",
    "load_server_specs",
    "probe_mcp_interface",
    "replace_mode_argument",
]
