"""Strict Kimi Code 0.26.x trace normalization to Event IR v1."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import TYPE_CHECKING, Any, Mapping

from ...adapter import HarnessIdentity, MaterializedBinding
from ...contract import validate_event_document
from .bench_materializer import load_bench_materialization_manifest
from .disposition import KimiModelProtocolIncompleteError
from .materializer import (
    load_materialization_manifest,
    sha256_bytes,
    sha256_file,
    validate_manifest_against_binding,
)
from .mcp_stdio_proxy import (
    KimiMcpProxyError,
    ProxyPaths,
    validate_health_evidence,
)

if TYPE_CHECKING:
    from .executor import NormalizationRequest, StageCapture


class KimiTraceNormalizationError(ValueError):
    """Raised when raw Kimi evidence cannot be normalized without inference."""


@dataclass(frozen=True)
class KimiObservedTraceSource:
    """One hash-pinned run-local source consumed by the strict parser."""

    path: Path
    sha256: str
    mode: str = "all"


@dataclass(frozen=True)
class KimiObservedTraceContext:
    """Trusted execution context for runner-owned multi-source normalization."""

    run_id: str
    case_id: str
    run_dir: Path
    workspace: Path
    stage: Mapping[str, Any]
    expected_event_types: tuple[str, ...]
    sources: tuple[KimiObservedTraceSource, ...]


_KIMI_0_26_0_BINARY_SHA256 = (
    "bc310a7d2f0c3c2cb1367fa7b2092375351efff51c6d4a358b8681b4a01fb7b0"
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise KimiTraceNormalizationError(f"{label} must be an object")
    return value


def _timestamp(value: Any) -> tuple[str, str]:
    if value is None:
        raise KimiTraceNormalizationError(
            "raw event timestamp is absent; trace file mtime is not event evidence"
        )
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = float(value) / 1000 if value > 100_000_000_000 else float(value)
        try:
            parsed = datetime.fromtimestamp(seconds, timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise KimiTraceNormalizationError(f"invalid epoch timestamp: {value!r}") from exc
        return parsed.isoformat(), "raw_epoch"
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise KimiTraceNormalizationError(f"invalid raw timestamp: {value!r}") from exc
        if parsed.tzinfo is None:
            raise KimiTraceNormalizationError("raw timestamp must include a timezone")
        return parsed.isoformat(), "raw_rfc3339"
    raise KimiTraceNormalizationError("raw timestamp must be epoch numeric or RFC3339")


def _timestamp_datetime(value: Any) -> datetime:
    normalized, _ = _timestamp(value)
    return datetime.fromisoformat(normalized).astimezone(timezone.utc)


def _payload_sha256(value: Any) -> str:
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            content = value.encode("utf-8")
        else:
            content = json.dumps(
                parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
    else:
        content = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    return sha256_bytes(content)


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        char not in "0123456789abcdef" for char in value
    ):
        raise KimiTraceNormalizationError(f"{label} SHA-256 is invalid")
    return value


def _positive_line(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise KimiTraceNormalizationError(f"{label} must be a positive line number")
    return value


def _run_local_observed_file(
    *, raw_path: Any, raw_sha256: Any, run_dir: Path, label: str
) -> tuple[Path, str]:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise KimiTraceNormalizationError(f"{label} path must be non-empty")
    supplied = Path(raw_path).absolute()
    if supplied.is_symlink():
        raise KimiTraceNormalizationError(f"{label} must not be a symlink")
    try:
        supplied_relative = supplied.relative_to(run_dir)
    except ValueError as exc:
        raise KimiTraceNormalizationError(f"{label} escapes the Kimi run") from exc
    cursor = run_dir
    for component in supplied_relative.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise KimiTraceNormalizationError(
                f"{label} traverses a symlink inside the Kimi run"
            )
    resolved = supplied.resolve()
    try:
        resolved.relative_to(run_dir)
    except ValueError as exc:
        raise KimiTraceNormalizationError(f"{label} escapes the Kimi run") from exc
    if not resolved.is_file():
        raise KimiTraceNormalizationError(f"{label} does not exist")
    expected = _sha256(raw_sha256, label)
    observed = sha256_bytes(resolved.read_bytes())
    if observed != expected:
        raise KimiTraceNormalizationError(f"{label} SHA-256 does not match bytes")
    return resolved, observed


def _jsonl_record(path: Path, line_number: Any, label: str) -> Mapping[str, Any]:
    line = _positive_line(line_number, f"{label} line")
    try:
        raw = path.read_text(encoding="utf-8").splitlines()[line - 1]
    except IndexError as exc:
        raise KimiTraceNormalizationError(f"{label} line is outside the source trace") from exc
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise KimiTraceNormalizationError(f"{label} source line is malformed JSON") from exc
    return _mapping(decoded, f"{label} source record")


def _wire_success_omission_is_validated(identity: HarnessIdentity) -> bool:
    return (
        identity.version == "0.26.0"
        and identity.feature_flags.get("binary_sha256")
        == _KIMI_0_26_0_BINARY_SHA256
    )


def _observation_file(
    reference: Any, *, run_dir: Path, label: str
) -> tuple[Path, str, Mapping[str, Any]]:
    document = _mapping(reference, f"{label} reference")
    path, digest = _run_local_observed_file(
        raw_path=document.get("path"),
        raw_sha256=document.get("sha256"),
        run_dir=run_dir,
        label=label,
    )
    return path, digest, document


def _session_id(value: Any, label: str = "session_id") -> str:
    if not isinstance(value, str) or not value.startswith("session_"):
        raise KimiTraceNormalizationError(
            f"{label} must be a non-empty native Kimi session id"
        )
    return value


def _state_agent(
    state: Mapping[str, Any], agent_id: str, *, expected_type: str
) -> Mapping[str, Any]:
    agents = _mapping(state.get("agents"), "native session state agents")
    agent = _mapping(agents.get(agent_id), f"native agent state {agent_id}")
    if agent.get("type") != expected_type:
        raise KimiTraceNormalizationError(
            f"native agent {agent_id!r} type is not {expected_type!r}"
        )
    return agent


def _prompt_lists_skill(system_prompt: str, *, skill_name: str, skill_path: Path) -> bool:
    """Match one native Kimi skill-list entry without copying prompt text."""

    lines = system_prompt.splitlines()
    header = re.compile(rf"^- {re.escape(skill_name)}(?:\s*:|\s*$)")
    expected_path = f"  Path: {skill_path}"
    matching_entries = 0
    for index, line in enumerate(lines):
        if header.match(line) is None:
            continue
        for candidate in lines[index + 1 :]:
            if candidate.startswith("- ") or candidate.startswith("### "):
                break
            if candidate == expected_path:
                matching_entries += 1
                break
    return matching_entries == 1


def _event_id(run_id: str, stage_index: int, sequence: int) -> str:
    identity = f"{run_id}:{stage_index}:{sequence}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
    return f"kimi:{stage_index}:{sequence}:{digest}"


def _stage_for_record(
    record: Mapping[str, Any], default_stage: Mapping[str, Any]
) -> dict[str, Any]:
    raw = record.get("_stage")
    if raw is None:
        return {"name": default_stage["name"], "index": default_stage["index"]}
    stage = _mapping(raw, "raw _stage")
    name = stage.get("name")
    index = stage.get("index")
    if not isinstance(name, str) or not name.strip():
        raise KimiTraceNormalizationError("raw stage name must be non-empty")
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise KimiTraceNormalizationError("raw stage index must be non-negative")
    if name != default_stage["name"] or index != default_stage["index"]:
        raise KimiTraceNormalizationError(
            "raw stage does not match the run-local trace stage"
        )
    return {"name": name, "index": index}


def _workspace_artifact_path(raw_path: Any, workspace: Path) -> tuple[str, Path]:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise KimiTraceNormalizationError("file tool path must be non-empty")
    candidate = Path(raw_path)
    supplied = candidate if candidate.is_absolute() else workspace / candidate
    supplied = supplied.absolute()
    if supplied.is_symlink():
        raise KimiTraceNormalizationError("file event path must not be a symlink")
    workspace_root = workspace.resolve()
    try:
        supplied_relative = supplied.relative_to(workspace_root)
    except ValueError as exc:
        raise KimiTraceNormalizationError(
            f"file event path escapes the Kimi workspace: {raw_path!r}"
        ) from exc
    cursor = workspace_root
    for component in supplied_relative.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise KimiTraceNormalizationError(
                "file event path traverses a workspace symlink"
            )
    resolved = supplied.resolve()
    try:
        relative = resolved.relative_to(workspace_root)
    except ValueError as exc:
        raise KimiTraceNormalizationError(
            f"file event path escapes the Kimi workspace: {raw_path!r}"
        ) from exc
    if not relative.parts:
        raise KimiTraceNormalizationError("file event path names the workspace root")
    return relative.as_posix(), resolved


def _optional_workspace_read_path(
    raw_path: Any,
    workspace: Path,
    *,
    required: bool,
) -> tuple[str, Path] | None:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise KimiTraceNormalizationError("file tool path must be non-empty")
    candidate = Path(raw_path)
    supplied = candidate if candidate.is_absolute() else workspace / candidate
    supplied = Path(os.path.abspath(supplied))
    if supplied.is_symlink():
        raise KimiTraceNormalizationError("file event path must not be a symlink")
    try:
        supplied.relative_to(workspace.resolve())
    except ValueError:
        if not required:
            return None
    return _workspace_artifact_path(raw_path, workspace)


def _tool_call_parts(raw: Mapping[str, Any]) -> tuple[str, str, Any]:
    call_id = raw.get("id", raw.get("toolCallId"))
    function = raw.get("function")
    if isinstance(function, Mapping):
        name = function.get("name")
        args = function.get("arguments", {})
    else:
        name = raw.get("name")
        args = raw.get("args", raw.get("arguments", {}))
    if not isinstance(call_id, str) or not call_id:
        raise KimiTraceNormalizationError("tool call is missing id/toolCallId")
    if not isinstance(name, str) or not name:
        raise KimiTraceNormalizationError("tool call is missing name")
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError as exc:
            raise KimiTraceNormalizationError(
                f"tool call {call_id!r} arguments are malformed JSON"
            ) from exc
    if not isinstance(args, Mapping):
        raise KimiTraceNormalizationError("tool call arguments must be an object")
    return call_id, name, args


def _mcp_name(name: str) -> tuple[str, str] | None:
    if not name.startswith("mcp__"):
        return None
    remainder = name[len("mcp__") :]
    server, separator, tool = remainder.partition("__")
    if not separator or not server or not tool:
        raise KimiTraceNormalizationError(f"malformed Kimi MCP tool name: {name!r}")
    return server, tool


def _tool_result_parts(
    record: Mapping[str, Any], *, allow_wire_success_omission: bool
) -> tuple[str, Any, bool]:
    if record.get("role") == "tool":
        if not isinstance(record.get("is_error"), bool):
            raise KimiTraceNormalizationError(
                "Kimi stdout tool results omit success/error state; use a directly "
                "observed wire result instead"
            )
        call_id = record.get("tool_call_id")
        output = record.get("content")
        is_error = record["is_error"]
    else:
        event = _mapping(record.get("event"), "wire tool result event")
        call_id = event.get("toolCallId")
        result = _mapping(event.get("result"), "wire tool result")
        output = result.get("output")
        raw_is_error = result.get("isError")
        # Kimi 0.26 normalizeToolResult deliberately omits isError for a
        # successful result and writes true for an error. Absence is therefore
        # the version-scoped success representation, while any non-boolean
        # present value is malformed evidence.
        if raw_is_error is None and not allow_wire_success_omission:
            raise KimiTraceNormalizationError(
                "wire tool result omitted isError for an unvalidated Kimi version"
            )
        if raw_is_error is not None and not isinstance(raw_is_error, bool):
            raise KimiTraceNormalizationError(
                "wire tool result isError must be boolean when present"
            )
        is_error = raw_is_error is True
    if not isinstance(call_id, str) or not call_id:
        raise KimiTraceNormalizationError("tool result is missing correlation id")
    return call_id, output, is_error


def normalize_kimi_trace(
    *,
    identity: HarnessIdentity,
    raw_trace_path: Path,
    stage_index: int,
    materialized: MaterializedBinding | None = None,
    trusted_binding_document: Mapping[str, Any] | None = None,
    trusted_manifest_document: Mapping[str, Any] | None = None,
    observed_context: KimiObservedTraceContext | None = None,
) -> list[Mapping[str, Any]]:
    """Normalize directly observable Kimi tool and adapter evidence.

    Supported inputs are Kimi stdout stream-json messages, Kimi persisted
    `context.append_loop_event` wire records, and narrowly defined adapter
    observations that bind a successful file tool call or a handoff to an
    exact SHA-256. Lifecycle events absent from these sources are not inferred.
    """

    if identity.harness_id != "kimi":
        raise KimiTraceNormalizationError("identity is not Kimi")
    if observed_context is None:
        if (
            materialized is None
            or trusted_binding_document is None
            or trusted_manifest_document is None
        ):
            raise KimiTraceNormalizationError(
                "materialized normalization requires trusted binding and manifest snapshots"
            )
        manifest = load_materialization_manifest(materialized)
        if manifest != trusted_manifest_document:
            raise KimiTraceNormalizationError(
                "materialization manifest drifted from the adapter-owned snapshot"
            )
        validate_manifest_against_binding(manifest, trusted_binding_document)
        run_dir = materialized.run_dir.resolve()
        stages = {stage["index"]: stage for stage in manifest["stages"]}
        if stage_index not in stages:
            raise KimiTraceNormalizationError(
                f"unknown materialized stage: {stage_index}"
            )
        default_stage = stages[stage_index]
        workspace = Path(manifest["materialized"]["workspace_dir"])
        case_id = materialized.case_id
        supplied_trace = Path(raw_trace_path).absolute()
        expected_primary = Path(default_stage["trace_path"]).absolute()
        source_specs = (
            KimiObservedTraceSource(
                path=expected_primary,
                sha256=(
                    hashlib.sha256(expected_primary.read_bytes()).hexdigest()
                    if expected_primary.is_file() and not expected_primary.is_symlink()
                    else "0" * 64
                ),
            ),
        )
    else:
        if any(
            value is not None
            for value in (
                materialized,
                trusted_binding_document,
                trusted_manifest_document,
            )
        ):
            raise KimiTraceNormalizationError(
                "observed trace context cannot be mixed with materialization snapshots"
            )
        if (
            not isinstance(observed_context.run_id, str)
            or not observed_context.run_id
            or not isinstance(observed_context.case_id, str)
            or not observed_context.case_id
            or not observed_context.sources
        ):
            raise KimiTraceNormalizationError(
                "observed trace context identity or sources are incomplete"
            )
        run_dir = Path(observed_context.run_dir).resolve(strict=True)
        workspace = Path(observed_context.workspace).resolve(strict=True)
        try:
            workspace.relative_to(run_dir)
        except ValueError as exc:
            raise KimiTraceNormalizationError(
                "observed workspace must be inside the Kimi run"
            ) from exc
        default_stage = dict(
            _mapping(observed_context.stage, "observed trace stage")
        )
        if default_stage.get("index") != stage_index:
            raise KimiTraceNormalizationError(
                "observed trace stage index differs from the requested stage"
            )
        if not isinstance(default_stage.get("name"), str) or not default_stage["name"]:
            raise KimiTraceNormalizationError("observed trace stage name is invalid")
        stages = {stage_index: default_stage}
        manifest = {
            "run_id": observed_context.run_id,
            "expected_event_types": list(observed_context.expected_event_types),
        }
        case_id = observed_context.case_id
        supplied_trace = Path(raw_trace_path).absolute()
        source_specs = observed_context.sources

    if supplied_trace.is_symlink():
        raise KimiTraceNormalizationError("raw trace must not be a symlink")
    trace_path = supplied_trace.resolve()
    expected_trace = Path(source_specs[0].path).absolute().resolve()
    if trace_path != expected_trace:
        raise KimiTraceNormalizationError(
            "raw trace path does not match the exact materialized stage trace"
        )

    raw_records: list[tuple[int, Mapping[str, Any]]] = []
    record_sources: dict[int, Path] = {}
    source_modes: dict[Path, str] = {}
    source_hashes: dict[Path, str] = {}
    source_line_counts: dict[Path, int] = {}
    for source in source_specs:
        if source.mode not in {"all", "session_meta", "adapter"}:
            raise KimiTraceNormalizationError(
                f"unknown observed trace source mode: {source.mode!r}"
            )
        _sha256(source.sha256, "observed trace source")
        supplied_source = Path(source.path).absolute()
        if supplied_source.is_symlink():
            raise KimiTraceNormalizationError("raw trace source must not be a symlink")
        source_path = supplied_source.resolve()
        if source_path in source_modes:
            raise KimiTraceNormalizationError(
                "observed trace source path is duplicated"
            )
        source_modes[source_path] = source.mode
        try:
            source_path.relative_to(run_dir)
        except ValueError as exc:
            raise KimiTraceNormalizationError(
                "raw trace source must be inside this Kimi run"
            ) from exc
        if (
            "kimi" not in source_path.as_posix().lower()
            or manifest["run_id"] not in source_path.as_posix()
        ):
            raise KimiTraceNormalizationError(
                "raw trace source path lacks kimi/run_id ownership"
            )
        if not source_path.is_file():
            raise KimiTraceNormalizationError(
                f"raw trace source does not exist: {source_path}"
            )
        raw_bytes = source_path.read_bytes()
        if hashlib.sha256(raw_bytes).hexdigest() != source.sha256:
            raise KimiTraceNormalizationError("raw trace source SHA-256 drifted")
        try:
            raw_lines = raw_bytes.decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise KimiTraceNormalizationError(
                f"raw trace source is not UTF-8: {source_path}"
            ) from exc
        source_hashes[source_path] = source.sha256
        source_line_counts[source_path] = len(raw_lines)
        for line_number, raw_line in enumerate(raw_lines, start=1):
            if not raw_line.strip():
                continue
            try:
                decoded = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise KimiTraceNormalizationError(
                    f"malformed JSON at {source_path}:{line_number}: {exc.msg}"
                ) from exc
            if not isinstance(decoded, Mapping):
                raise KimiTraceNormalizationError(
                    f"trace line {line_number} must be a JSON object"
                )
            if source.mode == "session_meta" and not (
                decoded.get("role") == "meta"
                and decoded.get("type") == "session.resume_hint"
            ):
                continue
            if source.mode == "adapter" and not (
                isinstance(decoded.get("type"), str)
                and str(decoded["type"]).startswith("adapter.")
            ):
                raise KimiTraceNormalizationError(
                    "adapter observation trace contains a non-adapter record"
                )
            raw_records.append((line_number, decoded))
            record_sources[id(decoded)] = source_path

    pending: dict[str, dict[str, Any]] = {}
    completed_reads: dict[str, dict[str, Any]] = {}
    observed_read_hashes: dict[str, tuple[str, str]] = {}
    completed_writes: dict[str, dict[str, Any]] = {}
    completed_tools: list[dict[str, Any]] = []
    pending_skill_activations: dict[str, dict[str, Any]] = {}
    skill_prompt_snapshots: list[dict[str, Any]] = []
    seen_call_ids: set[str] = set()
    started_session_ids: set[str] = set()
    events: list[dict[str, Any]] = []

    def emit(
        *,
        event_type: str,
        line: int,
        raw_event_type: str,
        record: Mapping[str, Any],
        attributes: Mapping[str, Any] | None = None,
        tool: Mapping[str, Any] | None = None,
        artifact: Mapping[str, Any] | None = None,
        source_path: Path | None = None,
        session_id: str | None = None,
        agent_id: str | None = None,
        parent_agent_id: str | None = None,
    ) -> None:
        stage = _stage_for_record(record, default_stage)
        timestamp, provenance = _timestamp(
            record.get("time", record.get("timestamp"))
        )
        sequence = len(events)
        event: dict[str, Any] = {
            "schema_name": "safety_bench_cross_harness_event",
            "schema_version": 1,
            "event_id": _event_id(manifest["run_id"], stage["index"], sequence),
            "event_type": event_type,
            "run_id": manifest["run_id"],
            "case_id": case_id,
            "harness": {
                "id": "kimi",
                "version": identity.version,
                "feature_flags": dict(identity.feature_flags),
            },
            "stage": stage,
            "sequence": sequence,
            "timestamp": timestamp,
            "source": {
                "trace_path": str(
                    source_path or record_sources.get(id(record), trace_path)
                ),
                "line": line,
                "raw_event_type": raw_event_type,
            },
            "attributes": {
                "timestamp_provenance": provenance,
                **dict(attributes or {}),
            },
        }
        if tool is not None:
            event["tool"] = dict(tool)
        if artifact is not None:
            event["artifact"] = dict(artifact)
        if session_id is not None:
            event["session_id"] = session_id
        if agent_id is not None:
            event["agent_id"] = agent_id
        if parent_agent_id is not None:
            event["parent_agent_id"] = parent_agent_id
        validate_event_document(event)
        events.append(event)

    for line_number, record in raw_records:
        record_type = record.get("type")
        role = record.get("role")

        if record_type == "config.update" and "systemPrompt" in record:
            system_prompt = record.get("systemPrompt")
            if not isinstance(system_prompt, str) or not system_prompt:
                raise KimiTraceNormalizationError(
                    "native config.update systemPrompt must be non-empty"
                )
            skill_prompt_snapshots.append(
                {
                    "line": line_number,
                    "record": record,
                    "system_prompt": system_prompt,
                    "sha256": sha256_bytes(system_prompt.encode("utf-8")),
                }
            )

        calls: list[Mapping[str, Any]] = []
        raw_event_type = ""
        if record_type == "context.append_loop_event":
            raw_event = _mapping(record.get("event"), "wire loop event")
            if raw_event.get("type") == "tool.call":
                calls = [raw_event]
                raw_event_type = "context.append_loop_event:tool.call"
        elif role == "assistant" and record.get("tool_calls") is not None:
            raw_calls = record.get("tool_calls")
            if not isinstance(raw_calls, list):
                raise KimiTraceNormalizationError("assistant tool_calls must be an array")
            calls = [_mapping(call, "assistant tool call") for call in raw_calls]
            raw_event_type = "assistant.tool_calls"

        for raw_call in calls:
            call_id, name, args = _tool_call_parts(raw_call)
            if call_id in seen_call_ids:
                raise KimiTraceNormalizationError(f"duplicate tool call id: {call_id}")
            seen_call_ids.add(call_id)
            pending[call_id] = {
                "name": name,
                "args": dict(args),
                "line": line_number,
                "record": record,
                "source": record_sources.get(id(record), trace_path),
            }
            mcp = _mcp_name(name)
            if mcp is not None:
                server, tool_name = mcp
                emit(
                    event_type="mcp.tool_requested",
                    line=line_number,
                    raw_event_type=raw_event_type,
                    record=record,
                    tool={
                        "server": server,
                        "name": tool_name,
                        "call_id": call_id,
                        "arguments_sha256": _payload_sha256(args),
                    },
                )

        if record_type == "context.append_message":
            message = _mapping(record.get("message"), "wire appended message")
            origin_raw = message.get("origin")
            if origin_raw is not None:
                origin = _mapping(origin_raw, "wire message origin")
                if origin.get("kind") == "skill_activation":
                    activation_id = origin.get("activationId")
                    skill_name = origin.get("skillName")
                    skill_path_raw = origin.get("skillPath")
                    skill_type = origin.get("skillType")
                    skill_source = origin.get("skillSource")
                    trigger = origin.get("trigger")
                    for value, label in (
                        (activation_id, "skill activation id"),
                        (skill_name, "skill name"),
                        (skill_path_raw, "skill path"),
                        (skill_type, "skill type"),
                        (skill_source, "skill source"),
                    ):
                        if not isinstance(value, str) or not value.strip():
                            raise KimiTraceNormalizationError(
                                f"{label} must be non-empty"
                            )
                    if trigger != "model-tool":
                        raise KimiTraceNormalizationError(
                            "skill activation trigger must be model-tool"
                        )
                    candidates = [
                        call_id
                        for call_id, request in pending.items()
                        if request["name"] == "Skill"
                        and request["args"].get("skill") == skill_name
                        and call_id not in pending_skill_activations
                    ]
                    if len(candidates) != 1:
                        raise KimiTraceNormalizationError(
                            "skill activation lacks one correlated pending Skill call"
                        )
                    skill_root = Path(default_stage["skills_dir"]).resolve()
                    supplied_skill_path = Path(str(skill_path_raw)).absolute()
                    if supplied_skill_path.is_symlink():
                        raise KimiTraceNormalizationError(
                            "skill activation path must not be a symlink"
                        )
                    try:
                        supplied_skill_relative = supplied_skill_path.relative_to(
                            skill_root
                        )
                    except ValueError as exc:
                        raise KimiTraceNormalizationError(
                            "skill activation path escapes the stage skills_dir"
                        ) from exc
                    skill_cursor = skill_root
                    for component in supplied_skill_relative.parts:
                        skill_cursor = skill_cursor / component
                        if skill_cursor.is_symlink():
                            raise KimiTraceNormalizationError(
                                "skill activation path traverses a symlink"
                            )
                    skill_path = supplied_skill_path.resolve()
                    try:
                        relative_skill = skill_path.relative_to(skill_root)
                    except ValueError as exc:
                        raise KimiTraceNormalizationError(
                            "skill activation path escapes the stage skills_dir"
                        ) from exc
                    if not skill_path.is_file():
                        raise KimiTraceNormalizationError(
                            "skill activation path is not a regular run-local file"
                        )
                    discovery_candidates = [
                        snapshot
                        for snapshot in skill_prompt_snapshots
                        if snapshot["line"] < line_number
                        and _prompt_lists_skill(
                            snapshot["system_prompt"],
                            skill_name=str(skill_name),
                            skill_path=skill_path,
                        )
                    ]
                    if len(discovery_candidates) != 1:
                        raise KimiTraceNormalizationError(
                            "skill activation lacks one prior native skill-list entry"
                        )
                    activation = {
                        "record": record,
                        "line": line_number,
                        "activation_id": activation_id,
                        "skill_name": skill_name,
                        "skill_type": skill_type,
                        "skill_source": skill_source,
                        "trigger": trigger,
                        "path": relative_skill.as_posix(),
                        "sha256": sha256_bytes(skill_path.read_bytes()),
                        "discovery": discovery_candidates[0],
                    }
                    pending_skill_activations[candidates[0]] = activation
                    discovery = activation["discovery"]
                    emit(
                        event_type="skill.discovered",
                        line=discovery["line"],
                        raw_event_type="config.update:systemPrompt:skill_listing",
                        record=discovery["record"],
                        attributes={
                            "skill_name": activation["skill_name"],
                            "skill_path": activation["path"],
                            "skill_sha256": activation["sha256"],
                            "system_prompt_sha256": discovery["sha256"],
                            "discovery_observer": "native_skill_listing",
                        },
                    )
                    emit(
                        event_type="skill.activated",
                        line=activation["line"],
                        raw_event_type="context.append_message:skill_activation",
                        record=activation["record"],
                        attributes={
                            "activation_id": activation["activation_id"],
                            "origin_tool_call_id": candidates[0],
                            "skill_name": activation["skill_name"],
                            "skill_type": activation["skill_type"],
                            "skill_source": activation["skill_source"],
                            "trigger": activation["trigger"],
                            "skill_path": activation["path"],
                            "skill_sha256": activation["sha256"],
                        },
                    )

        is_result = role == "tool"
        if record_type == "context.append_loop_event":
            raw_event = _mapping(record.get("event"), "wire loop event")
            is_result = raw_event.get("type") == "tool.result"
        if is_result:
            call_id, output, is_error = _tool_result_parts(
                record,
                allow_wire_success_omission=_wire_success_omission_is_validated(identity),
            )
            request = pending.pop(call_id, None)
            if request is None:
                raise KimiTraceNormalizationError(
                    f"tool result {call_id!r} has no unique request"
                )
            name = request["name"]
            result_source = record_sources.get(id(record), trace_path)
            completed_tools.append(
                {
                    "call_id": call_id,
                    "name": name,
                    "args": dict(request["args"]),
                    "call_line": request["line"],
                    "call_source": request["source"],
                    "result_line": line_number,
                    "result_source": result_source,
                    "is_error": is_error,
                }
            )
            mcp = _mcp_name(name)
            result_raw_type = (
                "tool.result"
                if role == "tool"
                else "context.append_loop_event:tool.result"
            )
            if mcp is not None:
                server, tool_name = mcp
                emit(
                    event_type="mcp.tool_result",
                    line=line_number,
                    raw_event_type=result_raw_type,
                    record=record,
                    tool={
                        "server": server,
                        "name": tool_name,
                        "call_id": call_id,
                        "result_sha256": _payload_sha256(output),
                        "status": "error" if is_error else "success",
                    },
                )
            elif name == "Skill":
                activation = pending_skill_activations.pop(call_id, None)
                if activation is None:
                    if not is_error:
                        raise KimiTraceNormalizationError(
                            "successful Skill result lacks native activation evidence"
                        )
                elif is_error:
                    raise KimiTraceNormalizationError(
                        "native skill activation was followed by an error result"
                    )
            elif name == "Write" and not is_error:
                args = request["args"]
                mode = args.get("mode", "overwrite")
                if mode == "overwrite" and isinstance(args.get("content"), str):
                    relative, resolved = _workspace_artifact_path(
                        args.get("path"), workspace
                    )
                    digest = sha256_bytes(args["content"].encode("utf-8"))
                    completed_writes[relative] = {
                        "path": relative,
                        "resolved": resolved,
                        "expected_sha256": digest,
                        "line": line_number,
                        "record": record,
                        "raw_event_type": result_raw_type,
                        "call_id": call_id,
                        "tool_name": name,
                        "order": len(completed_tools),
                        "result_source": result_source,
                    }
            elif name == "Edit" and not is_error:
                relative, resolved = _workspace_artifact_path(
                    request["args"].get("path"), workspace
                )
                completed_writes[relative] = {
                    "path": relative,
                    "resolved": resolved,
                    "expected_sha256": None,
                    "line": line_number,
                    "record": record,
                    "raw_event_type": result_raw_type,
                    "call_id": call_id,
                    "tool_name": name,
                    "order": len(completed_tools),
                    "result_source": result_source,
                }
            elif name == "Read" and not is_error:
                read_path = _optional_workspace_read_path(
                    request["args"].get("path"),
                    workspace,
                    required=(
                        "file.read" in set(manifest["expected_event_types"])
                    ),
                )
                if read_path is None:
                    continue
                relative, resolved = read_path
                completed_reads[call_id] = {
                    "path": relative,
                    "resolved": str(resolved),
                    "call_line": request["line"],
                    "result_line": line_number,
                    "result_source": result_source,
                    "result_source_sha256": source_hashes.get(result_source),
                    "result_source_line_count": source_line_counts.get(result_source),
                    "result_timestamp": _timestamp(
                        record.get("time", record.get("timestamp"))
                    )[0],
                }

        if record_type == "mcp.server.status":
            raw_server = _mapping(record.get("server"), "Kimi MCP status server")
            server = raw_server.get("name")
            status = raw_server.get("status")
            if not isinstance(server, str) or not server:
                raise KimiTraceNormalizationError("MCP status is missing server name")
            if status not in {"connected", "failed"}:
                raise KimiTraceNormalizationError("MCP status must be connected or failed")
            if status == "failed":
                raise KimiTraceNormalizationError(
                    f"MCP server {server!r} failed the conformance health precondition"
                )
            emit(
                event_type="mcp.server_initialized",
                line=line_number,
                raw_event_type="mcp.server.status",
                record=record,
                attributes={"status": status},
                tool={"server": server},
            )

        if record_type == "adapter.mcp_health_observed":
            server = record.get("server")
            child_argv_sha256 = record.get("child_argv_sha256")
            if not isinstance(server, str) or not server:
                raise KimiTraceNormalizationError(
                    "adapter MCP health observation lacks a server"
                )
            _sha256(child_argv_sha256, "MCP child argv")
            paths_raw = _mapping(record.get("paths"), "MCP proxy paths")
            required_path_keys = {
                "initialize_trace",
                "tools_list_trace",
                "stdio_trace",
                "child_exit_trace",
            }
            if set(paths_raw) != required_path_keys:
                raise KimiTraceNormalizationError(
                    "MCP proxy health paths are incomplete or contain unknown keys"
                )
            if any(
                not isinstance(paths_raw[key], str) or not paths_raw[key]
                for key in required_path_keys
            ):
                raise KimiTraceNormalizationError("MCP proxy health path is invalid")
            paths = ProxyPaths(
                **{key: Path(paths_raw[key]) for key in required_path_keys}
            )
            try:
                health = validate_health_evidence(
                    run_root=run_dir,
                    run_id=manifest["run_id"],
                    server=server,
                    stage_index=default_stage["index"],
                    paths=paths,
                    child_argv_sha256=child_argv_sha256,
                )
            except (KimiMcpProxyError, OSError) as exc:
                raise KimiTraceNormalizationError(
                    f"MCP proxy health evidence failed closed: {exc}"
                ) from exc
            initialize_path_raw, separator, initialize_line_raw = health[
                "initialize_result_locator"
            ].rpartition(":")
            if not separator or not initialize_line_raw.isdigit():
                raise KimiTraceNormalizationError(
                    "MCP proxy initialize locator is malformed"
                )
            initialize_path = Path(initialize_path_raw).resolve()
            initialize_line = _positive_line(
                int(initialize_line_raw), "MCP initialize result"
            )
            initialize_record = _jsonl_record(
                initialize_path, initialize_line, "MCP initialize result"
            )
            if (
                initialize_record.get("jsonrpc_kind") != "response"
                or initialize_record.get("correlated_method") != "initialize"
                or initialize_record.get("response_status") != "success"
            ):
                raise KimiTraceNormalizationError(
                    "MCP initialize source record is not a correlated success"
                )
            emit(
                event_type="mcp.server_initialized",
                line=initialize_line,
                raw_event_type="adapter.mcp_stdio_proxy:initialize.response",
                record=initialize_record,
                source_path=initialize_path,
                attributes={
                    "status": "connected",
                    "observer": "adapter_mcp_stdio_proxy",
                    "child_argv_sha256": child_argv_sha256,
                    "initialize_request_locator": health[
                        "initialize_request_locator"
                    ],
                    "tools_list_request_locator": health[
                        "tools_list_request_locator"
                    ],
                    "tools_list_result_locator": health[
                        "tools_list_result_locator"
                    ],
                    "child_exit_locator": health["child_exit_locator"],
                    "tools_discovered_used_as_health": False,
                },
                tool={"server": server},
            )

        if record_type == "adapter.instruction_loading_observed":
            session_id = _session_id(record.get("session_id"))
            instruction_path, instruction_sha256, instruction_ref = _observation_file(
                record.get("instruction"),
                run_dir=run_dir,
                label="native project instruction",
            )
            expected_instruction = (
                workspace / ".kimi-code" / "AGENTS.md"
            ).resolve()
            if instruction_path != expected_instruction:
                raise KimiTraceNormalizationError(
                    "instruction observation is not the run-local .kimi-code/AGENTS.md"
                )
            marker_offset = instruction_ref.get("marker_offset")
            marker_length = instruction_ref.get("marker_length")
            if (
                not isinstance(marker_offset, int)
                or isinstance(marker_offset, bool)
                or marker_offset < 0
                or not isinstance(marker_length, int)
                or isinstance(marker_length, bool)
                or marker_length < 1
            ):
                raise KimiTraceNormalizationError(
                    "instruction marker bounds are invalid"
                )
            marker_sha256 = _sha256(
                instruction_ref.get("marker_sha256"), "instruction marker"
            )
            instruction_bytes = instruction_path.read_bytes()
            marker_end = marker_offset + marker_length
            if marker_end > len(instruction_bytes) or sha256_bytes(
                instruction_bytes[marker_offset:marker_end]
            ) != marker_sha256:
                raise KimiTraceNormalizationError(
                    "instruction marker SHA-256 does not match run-local bytes"
                )

            observer_path, observer_sha256, observer_ref = _observation_file(
                record.get("request_observer"),
                run_dir=run_dir,
                label="instruction request observer",
            )
            observer_line = _positive_line(
                observer_ref.get("line"), "instruction request observer"
            )
            observer = _jsonl_record(
                observer_path, observer_line, "instruction request observer"
            )
            request_body_sha256 = _sha256(
                observer.get("body_sha256"), "observed model request body"
            )
            if (
                observer.get("expected_substring_present") is not True
                or observer.get("expected_substring_sha256") != marker_sha256
                or observer.get("message_roles") != ["system", "user", "user"]
            ):
                raise KimiTraceNormalizationError(
                    "request observer did not directly find the instruction marker"
                )

            wire_path, wire_sha256, wire_ref = _observation_file(
                record.get("wire"), run_dir=run_dir, label="instruction native wire"
            )
            request_line = _positive_line(
                wire_ref.get("llm_request_line"), "instruction native request"
            )
            direct_capture = "native_source_path" in wire_ref
            if direct_capture:
                required_wire_keys = {
                    "path",
                    "sha256",
                    "line_count",
                    "prior_line_count",
                    "llm_request_line",
                    "llm_request_ordinal",
                    "message_count",
                    "config_update_line",
                    "system_prompt_sha256",
                    "native_source_path",
                }
                if set(wire_ref) != required_wire_keys:
                    raise KimiTraceNormalizationError(
                        "direct instruction wire reference keys drifted"
                    )
                line_count = wire_ref.get("line_count")
                prior_line_count = wire_ref.get("prior_line_count")
                if (
                    not isinstance(line_count, int)
                    or isinstance(line_count, bool)
                    or line_count < 1
                    or len(wire_path.read_bytes().splitlines()) != line_count
                    or source_hashes.get(wire_path) != wire_sha256
                    or source_modes.get(wire_path) != "all"
                    or not isinstance(prior_line_count, int)
                    or isinstance(prior_line_count, bool)
                    or prior_line_count < 0
                    or not prior_line_count < request_line <= line_count
                ):
                    raise KimiTraceNormalizationError(
                        "direct instruction captured-wire boundary drifted"
                    )
                raw_native_source = wire_ref.get("native_source_path")
                if not isinstance(raw_native_source, str) or not raw_native_source:
                    raise KimiTraceNormalizationError(
                        "direct instruction native source path is absent"
                    )
                native_supplied = Path(raw_native_source).absolute()
                if native_supplied.is_symlink():
                    raise KimiTraceNormalizationError(
                        "direct instruction native source is a symlink"
                    )
                try:
                    native_relative = native_supplied.relative_to(run_dir)
                except ValueError as exc:
                    raise KimiTraceNormalizationError(
                        "direct instruction native source escapes the Kimi run"
                    ) from exc
                cursor = run_dir
                for component in native_relative.parts:
                    cursor = cursor / component
                    if cursor.is_symlink():
                        raise KimiTraceNormalizationError(
                            "direct instruction native source traverses a symlink"
                        )
                native_source = native_supplied.resolve(strict=True)
                if (
                    not native_source.is_file()
                    or native_source.name != "wire.jsonl"
                    or native_source.parent.name != "main"
                    or native_source.parent.parent.name != "agents"
                    or native_source.parent.parent.parent.name != session_id
                ):
                    raise KimiTraceNormalizationError(
                        "instruction native source does not belong to the observed session"
                    )
                captured_bytes = wire_path.read_bytes()
                native_lines = native_source.read_bytes().splitlines(keepends=True)
                if (
                    len(native_lines) < line_count
                    or b"".join(native_lines[:line_count]) != captured_bytes
                ):
                    raise KimiTraceNormalizationError(
                        "instruction native source is not an append-only captured wire"
                    )
                config_line = _positive_line(
                    wire_ref.get("config_update_line"),
                    "instruction native config update",
                )
                if not prior_line_count < config_line < request_line:
                    raise KimiTraceNormalizationError(
                        "instruction config/request order drifted"
                    )
                config = _jsonl_record(
                    wire_path, config_line, "instruction native config update"
                )
                system_prompt = config.get("systemPrompt")
                system_prompt_sha = _sha256(
                    wire_ref.get("system_prompt_sha256"),
                    "instruction native system prompt",
                )
                try:
                    marker_text = instruction_bytes[
                        marker_offset:marker_end
                    ].decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise KimiTraceNormalizationError(
                        "instruction marker window is not UTF-8"
                    ) from exc
                if (
                    config.get("type") != "config.update"
                    or not isinstance(system_prompt, str)
                    or marker_text not in system_prompt
                    or sha256_bytes(system_prompt.encode("utf-8"))
                    != system_prompt_sha
                ):
                    raise KimiTraceNormalizationError(
                        "instruction marker lacks its native system prompt"
                    )
            elif (
                wire_path.parent.name != "main"
                or wire_path.parent.parent.name != "agents"
                or wire_path.parent.parent.parent.name != session_id
            ):
                raise KimiTraceNormalizationError(
                    "instruction wire does not belong to the observed native session"
                )
            request = _jsonl_record(
                wire_path, request_line, "instruction native request"
            )
            if request.get("type") != "llm.request" or request.get("kind") != "loop":
                raise KimiTraceNormalizationError(
                    "instruction wire locator is not a native loop request"
                )
            if direct_capture:
                observer_keys = {
                    "schema_name",
                    "schema_version",
                    "harness_id",
                    "run_id",
                    "case_id",
                    "trial_id",
                    "stage_index",
                    "sequence",
                    "time",
                    "body_sha256",
                    "body_bytes",
                    "target_sha256",
                    "message_roles",
                    "expected_substring_present",
                    "expected_substring_sha256",
                }
                loops = [
                    line
                    for line, candidate in enumerate(
                        wire_path.read_text(encoding="utf-8").splitlines(), 1
                    )
                    if line > int(wire_ref["prior_line_count"])
                    and isinstance((decoded := json.loads(candidate)), Mapping)
                    and decoded.get("type") == "llm.request"
                    and decoded.get("kind") == "loop"
                    and line <= request_line
                ]
                if (
                    wire_ref.get("llm_request_ordinal") != 1
                    or loops != [request_line]
                    or request.get("systemPromptHash")
                    != wire_ref.get("system_prompt_sha256")
                    or request.get("messageCount") != wire_ref.get("message_count")
                    or request.get("messageCount") != 2
                    or observer_line != 1
                    or set(observer_ref) != {"path", "sha256", "line", "line_count"}
                    or observer_ref.get("line_count") is None
                    or observer_ref.get("line_count")
                    != len(observer_path.read_bytes().splitlines())
                    or observer.get("sequence") != observer_line
                    or set(observer) != observer_keys
                    or observer.get("schema_name")
                    != "safety_bench_kimi_provider_request_observation"
                    or observer.get("schema_version") != 1
                    or observer.get("harness_id") != "kimi"
                    or observer.get("run_id") != manifest["run_id"]
                    or observer.get("case_id") != case_id
                    or not isinstance(observer.get("trial_id"), str)
                    or not observer.get("trial_id")
                    or observer.get("stage_index") != stage_index
                    or not isinstance(observer.get("body_bytes"), int)
                    or isinstance(observer.get("body_bytes"), bool)
                    or observer.get("body_bytes") < 1
                    or _SHA256_RE.fullmatch(
                        str(observer.get("target_sha256") or "")
                    )
                    is None
                    or stat.S_IMODE(observer_path.stat().st_mode) != 0o600
                    or _timestamp(observer.get("time"))[0]
                    != _timestamp(record.get("time", record.get("timestamp")))[0]
                    or _timestamp_datetime(
                        request.get("time", request.get("timestamp"))
                    )
                    > _timestamp_datetime(observer.get("time"))
                ):
                    raise KimiTraceNormalizationError(
                        "direct instruction request correlation drifted"
                    )
            emit(
                event_type="instruction.loaded",
                line=line_number,
                raw_event_type="adapter.loopback_request_observer:instruction_marker_present",
                record=record,
                session_id=session_id,
                attributes={
                    "path": ".kimi-code/AGENTS.md",
                    "sha256": instruction_sha256,
                    "marker_sha256": marker_sha256,
                    "request_body_sha256": request_body_sha256,
                    "request_observer_path": str(observer_path),
                    "request_observer_line": observer_line,
                    "request_observer_sha256": observer_sha256,
                    "native_wire_path": str(wire_path),
                    "native_wire_source_path": (
                        str(wire_ref.get("native_source_path"))
                        if direct_capture
                        else str(wire_path)
                    ),
                    "native_wire_line": request_line,
                    "native_wire_sha256": wire_sha256,
                    "observer": "adapter_verified_loopback_request",
                },
            )

        if record_type == "adapter.session_resume_observed":
            session_id = _session_id(record.get("session_id"))
            state_path, state_sha256, _ = _observation_file(
                record.get("state"), run_dir=run_dir, label="resumed session state"
            )
            if state_path.parent.name != session_id:
                raise KimiTraceNormalizationError(
                    "resume state path does not identify the observed session"
                )
            try:
                state = _mapping(
                    json.loads(state_path.read_text(encoding="utf-8")),
                    "resumed session state",
                )
            except json.JSONDecodeError as exc:
                raise KimiTraceNormalizationError(
                    "resumed session state is malformed JSON"
                ) from exc
            main_state = _state_agent(state, "main", expected_type="main")
            if main_state.get("parentAgentId") is not None:
                raise KimiTraceNormalizationError(
                    "resumed main agent unexpectedly has a parent"
                )

            wire_path, wire_sha256, wire_ref = _observation_file(
                record.get("wire"), run_dir=run_dir, label="resumed native wire"
            )
            expected_wire = state_path.parent / "agents" / "main" / "wire.jsonl"
            if wire_path != expected_wire.resolve():
                raise KimiTraceNormalizationError(
                    "resumed wire does not belong to the state main agent"
                )
            before_line_count = _positive_line(
                wire_ref.get("before_line_count"), "pre-resume line count"
            )
            before_sha256 = _sha256(
                wire_ref.get("before_sha256"), "pre-resume wire prefix"
            )
            wire_lines = wire_path.read_bytes().splitlines(keepends=True)
            if len(wire_lines) <= before_line_count:
                raise KimiTraceNormalizationError(
                    "resume did not append records to the native wire"
                )
            if sha256_bytes(b"".join(wire_lines[:before_line_count])) != before_sha256:
                raise KimiTraceNormalizationError(
                    "pre-resume wire prefix SHA-256 does not match"
                )
            initial_line = _positive_line(
                wire_ref.get("initial_request_line"), "initial request"
            )
            resumed_line = _positive_line(
                wire_ref.get("resumed_request_line"), "resumed request"
            )
            if not initial_line <= before_line_count < resumed_line:
                raise KimiTraceNormalizationError(
                    "resume request locators do not straddle the process boundary"
                )
            initial = _jsonl_record(wire_path, initial_line, "initial request")
            resumed = _jsonl_record(wire_path, resumed_line, "resumed request")
            if (
                initial.get("type") != "llm.request"
                or resumed.get("type") != "llm.request"
                or initial.get("kind") != "loop"
                or resumed.get("kind") != "loop"
            ):
                raise KimiTraceNormalizationError(
                    "resume observation lacks native loop request records"
                )
            initial_messages = initial.get("messageCount")
            resumed_messages = resumed.get("messageCount")
            if (
                not isinstance(initial_messages, int)
                or isinstance(initial_messages, bool)
                or not isinstance(resumed_messages, int)
                or isinstance(resumed_messages, bool)
                or resumed_messages <= initial_messages
            ):
                raise KimiTraceNormalizationError(
                    "resume did not directly increase native message context"
                )
            emit(
                event_type="session.resumed",
                line=resumed_line,
                raw_event_type="llm.request:loop:resumed_session",
                record=resumed,
                source_path=wire_path,
                session_id=session_id,
                attributes={
                    "pre_resume_line_count": before_line_count,
                    "pre_resume_sha256": before_sha256,
                    "post_resume_sha256": wire_sha256,
                    "initial_message_count": initial_messages,
                    "resumed_message_count": resumed_messages,
                    "session_state_sha256": state_sha256,
                    "observer": "adapter_verified_native_files",
                },
            )

        if record_type == "adapter.session_compaction_observed":
            session_id = _session_id(record.get("session_id"))
            state_path, state_sha256, _ = _observation_file(
                record.get("state"), run_dir=run_dir, label="compaction session state"
            )
            if state_path.parent.name != session_id:
                raise KimiTraceNormalizationError(
                    "compaction state path does not identify the observed session"
                )
            try:
                state = _mapping(
                    json.loads(state_path.read_text(encoding="utf-8")),
                    "compaction session state",
                )
            except json.JSONDecodeError as exc:
                raise KimiTraceNormalizationError(
                    "compaction session state is malformed JSON"
                ) from exc
            main_state = _state_agent(state, "main", expected_type="main")
            if main_state.get("parentAgentId") is not None:
                raise KimiTraceNormalizationError(
                    "compaction main agent unexpectedly has a parent"
                )

            wire_path, wire_sha256, wire_ref = _observation_file(
                record.get("wire"), run_dir=run_dir, label="compaction native wire"
            )
            expected_wire = state_path.parent / "agents" / "main" / "wire.jsonl"
            if wire_path != expected_wire.resolve():
                raise KimiTraceNormalizationError(
                    "compaction wire does not belong to the state main agent"
                )
            begin_line = _positive_line(wire_ref.get("begin_line"), "compaction begin")
            request_line = _positive_line(
                wire_ref.get("request_line"), "compaction request"
            )
            apply_line = _positive_line(wire_ref.get("apply_line"), "compaction apply")
            complete_line = _positive_line(
                wire_ref.get("complete_line"), "compaction complete"
            )
            if not begin_line < request_line < apply_line < complete_line:
                raise KimiTraceNormalizationError(
                    "compaction begin/request/apply/complete lines are not ordered"
                )
            begin = _jsonl_record(wire_path, begin_line, "compaction begin")
            request = _jsonl_record(wire_path, request_line, "compaction request")
            applied = _jsonl_record(wire_path, apply_line, "compaction apply")
            complete = _jsonl_record(wire_path, complete_line, "compaction complete")
            if (
                begin.get("type") != "full_compaction.begin"
                or request.get("type") != "llm.request"
                or request.get("kind") != "compaction"
                or applied.get("type") != "context.apply_compaction"
                or complete.get("type") != "full_compaction.complete"
            ):
                raise KimiTraceNormalizationError(
                    "compaction observation lacks native begin/request/apply/complete records"
                )
            source = begin.get("source")
            if source not in {"auto", "manual"}:
                raise KimiTraceNormalizationError(
                    "native compaction begin source is not auto or manual"
                )
            message_count = request.get("messageCount")
            if (
                not isinstance(message_count, int)
                or isinstance(message_count, bool)
                or message_count < 1
            ):
                raise KimiTraceNormalizationError(
                    "native compaction request messageCount is invalid"
                )
            summary = applied.get("summary")
            if not isinstance(summary, str) or not summary:
                raise KimiTraceNormalizationError(
                    "native compaction apply lacks a non-empty summary"
                )
            tokens_before = applied.get("tokensBefore")
            tokens_after = applied.get("tokensAfter")
            compacted_count = applied.get("compactedCount")
            kept_user_count = applied.get("keptUserMessageCount")
            for value, label, minimum in (
                (tokens_before, "tokensBefore", 1),
                (tokens_after, "tokensAfter", 0),
                (compacted_count, "compactedCount", 1),
                (kept_user_count, "keptUserMessageCount", 0),
            ):
                if (
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value < minimum
                ):
                    raise KimiTraceNormalizationError(
                        f"native compaction {label} is invalid"
                    )
            if tokens_before <= tokens_after:
                raise KimiTraceNormalizationError(
                    "native compaction did not directly reduce token count"
                )
            emit(
                event_type="session.compacted",
                line=apply_line,
                raw_event_type="context.apply_compaction",
                record=applied,
                source_path=wire_path,
                session_id=session_id,
                attributes={
                    "compaction_source": source,
                    "summary_sha256": sha256_bytes(summary.encode("utf-8")),
                    "pre_tokens": tokens_before,
                    "post_tokens": tokens_after,
                    "compacted_count": compacted_count,
                    "kept_user_message_count": kept_user_count,
                    "begin_line": begin_line,
                    "request_line": request_line,
                    "request_message_count": message_count,
                    "complete_line": complete_line,
                    "native_wire_sha256": wire_sha256,
                    "session_state_sha256": state_sha256,
                    "observer": "adapter_verified_native_files",
                },
            )

        if record_type == "adapter.subagent_lifecycle_observed":
            session_id = _session_id(record.get("session_id"))
            parent_agent_id = record.get("parent_agent_id")
            child_agent_id = record.get("child_agent_id")
            for value, label in (
                (parent_agent_id, "parent_agent_id"),
                (child_agent_id, "child_agent_id"),
            ):
                if not isinstance(value, str) or not value.strip():
                    raise KimiTraceNormalizationError(f"{label} must be non-empty")
            if parent_agent_id == child_agent_id:
                raise KimiTraceNormalizationError(
                    "subagent child must differ from its parent"
                )

            state_path, state_sha256, _ = _observation_file(
                record.get("state"), run_dir=run_dir, label="subagent session state"
            )
            if state_path.parent.name != session_id:
                raise KimiTraceNormalizationError(
                    "subagent state path does not identify the observed session"
                )
            try:
                state = _mapping(
                    json.loads(state_path.read_text(encoding="utf-8")),
                    "subagent session state",
                )
            except json.JSONDecodeError as exc:
                raise KimiTraceNormalizationError(
                    "subagent session state is malformed JSON"
                ) from exc
            parent_state = _state_agent(state, parent_agent_id, expected_type="main")
            child_state = _state_agent(state, child_agent_id, expected_type="sub")
            if parent_state.get("parentAgentId") is not None:
                raise KimiTraceNormalizationError(
                    "subagent parent unexpectedly has its own parent"
                )
            if child_state.get("parentAgentId") != parent_agent_id:
                raise KimiTraceNormalizationError(
                    "native child state does not name the observed parent"
                )

            parent_wire, parent_wire_sha256, parent_ref = _observation_file(
                record.get("parent_wire"), run_dir=run_dir, label="parent native wire"
            )
            child_wire, child_wire_sha256, child_ref = _observation_file(
                record.get("child_wire"), run_dir=run_dir, label="child native wire"
            )
            expected_parent_wire = (
                state_path.parent / "agents" / parent_agent_id / "wire.jsonl"
            ).resolve()
            expected_child_wire = (
                state_path.parent / "agents" / child_agent_id / "wire.jsonl"
            ).resolve()
            if parent_wire != expected_parent_wire or child_wire != expected_child_wire:
                raise KimiTraceNormalizationError(
                    "subagent parent/child wires do not belong to native session state"
                )

            call_line = _positive_line(parent_ref.get("tool_call_line"), "Agent call")
            result_line = _positive_line(
                parent_ref.get("tool_result_line"), "Agent result"
            )
            trigger_line = _positive_line(
                child_ref.get("trigger_line"), "subagent trigger"
            )
            if result_line <= call_line:
                raise KimiTraceNormalizationError(
                    "native Agent result does not follow its call"
                )
            call_record = _jsonl_record(parent_wire, call_line, "Agent call")
            result_record = _jsonl_record(parent_wire, result_line, "Agent result")
            trigger_record = _jsonl_record(child_wire, trigger_line, "subagent trigger")
            if call_record.get("type") != "context.append_loop_event":
                raise KimiTraceNormalizationError("Agent call is not a native wire event")
            call_event = _mapping(call_record.get("event"), "native Agent call")
            call_id, tool_name, _ = _tool_call_parts(call_event)
            if call_event.get("type") != "tool.call" or tool_name != "Agent":
                raise KimiTraceNormalizationError(
                    "parent wire does not contain a native Agent tool call"
                )
            result_call_id, handoff, is_error = _tool_result_parts(
                result_record,
                allow_wire_success_omission=_wire_success_omission_is_validated(identity),
            )
            if result_call_id != call_id or is_error:
                raise KimiTraceNormalizationError(
                    "native Agent result is uncorrelated or unsuccessful"
                )
            if trigger_record.get("type") != "context.append_message":
                raise KimiTraceNormalizationError(
                    "child wire lacks a native appended trigger message"
                )
            trigger_message = _mapping(
                trigger_record.get("message"), "native subagent trigger message"
            )
            trigger_origin = _mapping(
                trigger_message.get("origin"), "native subagent trigger origin"
            )
            if (
                trigger_origin.get("kind") != "system_trigger"
                or trigger_origin.get("name") != "subagent"
            ):
                raise KimiTraceNormalizationError(
                    "child wire trigger is not a native subagent origin"
                )
            emit(
                event_type="agent.spawned",
                line=trigger_line,
                raw_event_type="context.append_message:system_trigger:subagent",
                record=trigger_record,
                source_path=child_wire,
                session_id=session_id,
                agent_id=child_agent_id,
                parent_agent_id=parent_agent_id,
                attributes={
                    "origin_tool_call_id": call_id,
                    "parent_wire_path": str(parent_wire),
                    "parent_wire_sha256": parent_wire_sha256,
                    "child_wire_sha256": child_wire_sha256,
                    "session_state_sha256": state_sha256,
                    "observer": "adapter_verified_native_files",
                },
            )
            emit(
                event_type="agent.completed",
                line=result_line,
                raw_event_type="context.append_loop_event:tool.result:Agent",
                record=result_record,
                source_path=parent_wire,
                session_id=session_id,
                agent_id=child_agent_id,
                parent_agent_id=parent_agent_id,
                attributes={
                    "origin_tool_call_id": call_id,
                    "handoff_sha256": _payload_sha256(handoff),
                    "parent_wire_sha256": parent_wire_sha256,
                    "child_wire_path": str(child_wire),
                    "child_wire_sha256": child_wire_sha256,
                    "session_state_sha256": state_sha256,
                    "observer": "adapter_verified_native_files",
                },
            )

        if record_type == "adapter.session_start_observed":
            required_keys = {"type", "time", "session_id", "stdout", "wire"}
            session_id = _session_id(record.get("session_id"))
            stdout = _mapping(record.get("stdout"), "session start stdout")
            wire = _mapping(record.get("wire"), "session start wire")
            if (
                set(record) != required_keys
                or set(stdout)
                != {"path", "sha256", "line_count", "hint_line"}
                or set(wire)
                != {
                    "path",
                    "sha256",
                    "line_count",
                    "request_line",
                    "prior_line_count",
                }
                or source_modes.get(record_sources.get(id(record), trace_path))
                != "adapter"
                or wire.get("prior_line_count") != 0
            ):
                raise KimiTraceNormalizationError(
                    "session start observation shape or source is invalid"
                )
            stdout_path, stdout_sha = _run_local_observed_file(
                raw_path=stdout.get("path"),
                raw_sha256=stdout.get("sha256"),
                run_dir=run_dir,
                label="session start stdout",
            )
            wire_path, wire_sha = _run_local_observed_file(
                raw_path=wire.get("path"),
                raw_sha256=wire.get("sha256"),
                run_dir=run_dir,
                label="session start wire",
            )
            stdout_line_count = _positive_line(
                stdout.get("line_count"), "session start stdout line count"
            )
            hint_line = _positive_line(
                stdout.get("hint_line"), "session start hint line"
            )
            wire_line_count = _positive_line(
                wire.get("line_count"), "session start wire line count"
            )
            request_line = _positive_line(
                wire.get("request_line"), "session start request line"
            )
            if (
                source_modes.get(stdout_path) != "session_meta"
                or source_modes.get(wire_path) != "all"
                or source_hashes.get(stdout_path) != stdout_sha
                or source_hashes.get(wire_path) != wire_sha
                or source_line_counts.get(stdout_path) != stdout_line_count
                or source_line_counts.get(wire_path) != wire_line_count
                or hint_line > stdout_line_count
                or request_line > wire_line_count
            ):
                raise KimiTraceNormalizationError(
                    "session start observation is not bound to captured sources"
                )
            stdout_records = stdout_path.read_text(encoding="utf-8").splitlines()
            wire_records = wire_path.read_text(encoding="utf-8").splitlines()
            try:
                hint = _mapping(
                    json.loads(stdout_records[hint_line - 1]),
                    "session start native hint",
                )
                native_request = _mapping(
                    json.loads(wire_records[request_line - 1]),
                    "session start native request",
                )
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise KimiTraceNormalizationError(
                    "session start native locators are malformed"
                ) from exc
            if (
                hint.get("role") != "meta"
                or hint.get("type") != "session.resume_hint"
                or hint.get("session_id") != session_id
                or native_request.get("type") != "llm.request"
                or native_request.get("kind") != "loop"
                or _timestamp(
                    native_request.get("time", native_request.get("timestamp"))
                )[0]
                != _timestamp(record.get("time"))[0]
                or started_session_ids
            ):
                raise KimiTraceNormalizationError(
                    "session start native hint/request binding is invalid"
                )
            started_session_ids.add(session_id)
            emit(
                event_type="session.started",
                line=line_number,
                raw_event_type="adapter.session_start_observed",
                record=record,
                session_id=session_id,
                attributes={
                    "observer": "adapter_bound_stream_hint_and_native_request",
                    "native_stdout_path": str(stdout_path),
                    "native_stdout_hint_line": hint_line,
                    "native_wire_path": str(wire_path),
                    "native_wire_request_line": request_line,
                },
            )

        if record_type == "adapter.file_hash_observed":
            phase = record.get("observation_phase")
            if phase not in {"execution", "pre_stage", "post_stage"}:
                raise KimiTraceNormalizationError(
                    "file hash observation phase is not directly supported"
                )
            call_id = record.get("toolCallId")
            digest = record.get("sha256")
            read = completed_reads.get(call_id) if isinstance(call_id, str) else None
            if read is None:
                raise KimiTraceNormalizationError(
                    "file hash observation lacks a successful correlated Read"
                )
            observation_source = record_sources.get(id(record), trace_path)
            if phase == "execution":
                if observation_source == read["result_source"]:
                    if line_number != read["result_line"] + 1:
                        raise KimiTraceNormalizationError(
                            "file hash observation is not immediately after its native Read result"
                        )
                elif (
                    source_modes.get(observation_source) != "adapter"
                    or _timestamp(record.get("time", record.get("timestamp")))[0]
                    != read["result_timestamp"]
                ):
                    raise KimiTraceNormalizationError(
                        "cross-source file hash observation is not timestamp-bound to "
                        "its native Read result"
                    )
            elif phase == "post_stage":
                required_keys = {
                    "type",
                    "time",
                    "observation_phase",
                    "stage_completed_at",
                    "toolCallId",
                    "path",
                    "sha256",
                    "native_call_line",
                    "native_result_line",
                    "captured_wire_path",
                    "captured_wire_sha256",
                    "captured_wire_line_count",
                }
                captured_wire_raw = record.get("captured_wire_path")
                captured_supplied = (
                    Path(captured_wire_raw).absolute()
                    if isinstance(captured_wire_raw, str) and captured_wire_raw
                    else None
                )
                captured_wire = (
                    captured_supplied.resolve()
                    if captured_supplied is not None
                    and not captured_supplied.is_symlink()
                    else None
                )
                if (
                    set(record) != required_keys
                    or source_modes.get(observation_source) != "adapter"
                    or captured_wire != read["result_source"]
                    or record.get("captured_wire_sha256")
                    != read["result_source_sha256"]
                    or record.get("captured_wire_line_count")
                    != read["result_source_line_count"]
                    or record.get("native_call_line") != read["call_line"]
                    or record.get("native_result_line") != read["result_line"]
                ):
                    raise KimiTraceNormalizationError(
                        "post-stage file hash lacks its immutable native Read locator"
                    )
                completed_at = _timestamp_datetime(record.get("stage_completed_at"))
                observed_at = _timestamp_datetime(record.get("time"))
                result_at = _timestamp_datetime(read["result_timestamp"])
                if not result_at <= completed_at <= observed_at:
                    raise KimiTraceNormalizationError(
                        "post-stage file hash timestamp order is invalid"
                    )
                safe_non_mutating = {"Read", "Glob", "Grep", "Skill"}
                for tool_action in completed_tools:
                    if (
                        tool_action["call_source"] != read["result_source"]
                        or int(tool_action["call_line"]) <= int(read["result_line"])
                    ):
                        continue
                    tool_name = str(tool_action["name"])
                    if tool_name in safe_non_mutating:
                        continue
                    if tool_name != "Write":
                        raise KimiTraceNormalizationError(
                            "post-stage Read is followed by an opaque workspace mutator"
                        )
                    write_args = _mapping(
                        tool_action.get("args"), "post-stage Write arguments"
                    )
                    if write_args.get("mode", "overwrite") != "overwrite":
                        raise KimiTraceNormalizationError(
                            "post-stage Read is followed by an opaque Write mode"
                        )
                    write_path, _ = _workspace_artifact_path(
                        write_args.get("path"), workspace
                    )
                    if (
                        tool_action.get("is_error") is False
                        and write_path == read["path"]
                    ):
                        raise KimiTraceNormalizationError(
                            "post-stage Read is followed by a successful same-path Write"
                        )
            else:
                required_keys = {
                    "type",
                    "time",
                    "observation_phase",
                    "pre_stage_observed_at",
                    "toolCallId",
                    "path",
                    "sha256",
                    "byte_length",
                    "native_call_line",
                    "native_result_line",
                    "captured_wire_path",
                    "captured_wire_sha256",
                    "captured_wire_line_count",
                }
                captured_wire_raw = record.get("captured_wire_path")
                captured_supplied = (
                    Path(captured_wire_raw).absolute()
                    if isinstance(captured_wire_raw, str) and captured_wire_raw
                    else None
                )
                captured_wire = (
                    captured_supplied.resolve()
                    if captured_supplied is not None
                    and not captured_supplied.is_symlink()
                    else None
                )
                byte_length = record.get("byte_length")
                _timestamp_datetime(record.get("pre_stage_observed_at"))
                if (
                    set(record) != required_keys
                    or source_modes.get(observation_source) != "adapter"
                    or captured_wire != read["result_source"]
                    or record.get("captured_wire_sha256")
                    != read["result_source_sha256"]
                    or record.get("captured_wire_line_count")
                    != read["result_source_line_count"]
                    or record.get("native_call_line") != read["call_line"]
                    or record.get("native_result_line") != read["result_line"]
                    or not isinstance(byte_length, int)
                    or isinstance(byte_length, bool)
                    or byte_length < 0
                    or _timestamp(record.get("time"))[0]
                    != read["result_timestamp"]
                ):
                    raise KimiTraceNormalizationError(
                        "pre-stage file hash lacks its immutable native Read binding"
                    )
                for tool_action in completed_tools:
                    if (
                        tool_action["call_source"] != read["result_source"]
                        or int(tool_action["call_line"]) >= int(read["call_line"])
                    ):
                        continue
                    tool_name = str(tool_action["name"])
                    if tool_name in {"Read", "Glob", "Grep", "Skill"}:
                        continue
                    if tool_name not in {"Write", "Edit"}:
                        raise KimiTraceNormalizationError(
                            "pre-stage Read is preceded by an opaque workspace mutator"
                        )
                    mutation_path, _ = _workspace_artifact_path(
                        _mapping(
                            tool_action.get("args"),
                            "pre-stage Read mutation arguments",
                        ).get("path"),
                        workspace,
                    )
                    if mutation_path == read["path"]:
                        raise KimiTraceNormalizationError(
                            "pre-stage Read is preceded by a same-path mutation"
                        )
            if not isinstance(digest, str) or len(digest) != 64 or any(
                char not in "0123456789abcdef" for char in digest
            ):
                raise KimiTraceNormalizationError("file observation SHA-256 is invalid")
            observed_path, _ = _workspace_artifact_path(record.get("path"), workspace)
            if observed_path != read["path"]:
                raise KimiTraceNormalizationError("file observation path mismatches Read")
            if phase != "pre_stage":
                observed_file = Path(read["resolved"])
                if (
                    not observed_file.is_file()
                    or sha256_bytes(observed_file.read_bytes()) != digest
                ):
                    raise KimiTraceNormalizationError(
                        "file observation SHA-256 does not match run-local bytes"
                    )
            prior_observation = observed_read_hashes.get(str(call_id))
            if prior_observation is not None:
                if prior_observation != (digest, observed_path):
                    raise KimiTraceNormalizationError(
                        "duplicate file observations conflict for one native Read"
                    )
                continue
            observed_read_hashes[str(call_id)] = (digest, observed_path)
            emit(
                event_type="file.read",
                line=line_number,
                raw_event_type="adapter.file_hash_observed",
                record=record,
                attributes={
                    "origin_tool_call_id": call_id,
                    "hash_observer": "adapter",
                    "native_result_line": read["result_line"],
                    "hash_observation_phase": phase,
                    **(
                        {
                            "native_wire_sha256": read[
                                "result_source_sha256"
                            ],
                            "stage_completed_at": record["stage_completed_at"],
                        }
                        if phase == "post_stage"
                        else {}
                    ),
                },
                artifact={
                    "path": observed_path,
                    "sha256": digest,
                    "operation": "read",
                },
            )

        if record_type == "adapter.artifact_handoff":
            digest = record.get("sha256")
            if not isinstance(digest, str) or len(digest) != 64 or any(
                char not in "0123456789abcdef" for char in digest
            ):
                raise KimiTraceNormalizationError("handoff SHA-256 is invalid")
            relative, resolved = _workspace_artifact_path(record.get("path"), workspace)
            boundary = record.get("boundary")
            if not isinstance(boundary, str) or not boundary:
                raise KimiTraceNormalizationError(
                    "handoff boundary must be a non-empty reviewed value"
                )
            phase = record.get("observation_phase")
            if phase is not None:
                required_keys = {
                    "type",
                    "time",
                    "observation_phase",
                    "stage_completed_at",
                    "path",
                    "sha256",
                    "declared_change",
                    "boundary",
                }
                observation_source = record_sources.get(id(record), trace_path)
                artifacts = _mapping(
                    default_stage.get("artifacts"), "direct handoff artifact surface"
                )
                produce = artifacts.get("produce")
                if not isinstance(produce, list) or not produce:
                    raise KimiTraceNormalizationError(
                        "direct handoff has no artifacts.produce declaration"
                    )
                declarations = [
                    _mapping(item, "direct handoff produced artifact")
                    for item in produce
                ]
                matches = [
                    item
                    for item in declarations
                    if item.get("path") == relative
                    and item.get("sha256_required_after_stage") == "yes"
                    and item.get("change") == record.get("declared_change")
                ]
                if (
                    set(record) != required_keys
                    or phase != "post_stage"
                    or source_modes.get(observation_source) != "adapter"
                    or boundary != "stage_completion_artifacts_produce"
                    or len(matches) != 1
                    or _timestamp_datetime(record.get("stage_completed_at"))
                    > _timestamp_datetime(record.get("time"))
                ):
                    raise KimiTraceNormalizationError(
                        "direct handoff is not bound to one post-stage produce declaration"
                    )
            if not resolved.is_file() or sha256_bytes(resolved.read_bytes()) != digest:
                raise KimiTraceNormalizationError(
                    "handoff SHA-256 does not match the run-local artifact"
                )
            emit(
                event_type="artifact.handoff",
                line=line_number,
                raw_event_type="adapter.artifact_handoff",
                record=record,
                attributes={
                    "observer": "adapter",
                    "boundary": boundary,
                    **(
                        {
                            "hash_observation_phase": phase,
                            "stage_completed_at": record["stage_completed_at"],
                        }
                        if phase == "post_stage"
                        else {}
                    ),
                },
                artifact={
                    "path": relative,
                    "sha256": digest,
                    "operation": "handoff",
                },
            )

    for write in sorted(
        completed_writes.values(),
        key=lambda item: int(item["order"]),
    ):
        invalid_reason: str | None = None
        for later in completed_tools[int(write["order"]) :]:
            if later["call_source"] != write["result_source"]:
                # Captured parent/child agent wires are independent ordered
                # streams.  Their capture-file order is not a causal order.
                continue
            tool_name = str(later["name"])
            if tool_name in {"Read", "Glob", "Grep", "Skill"}:
                continue
            if tool_name in {"Write", "Edit"}:
                later_path, _ = _workspace_artifact_path(
                    _mapping(
                        later.get("args"),
                        "later structured mutation arguments",
                    ).get("path"),
                    workspace,
                )
                if later_path != write["path"]:
                    continue
            invalid_reason = (
                "structured write is followed by an opaque same-workspace mutator"
            )
            break
        resolved = Path(write["resolved"])
        if invalid_reason is None and not resolved.is_file():
            invalid_reason = "successful structured write lacks run-local file bytes"
        digest = sha256_bytes(resolved.read_bytes()) if resolved.is_file() else None
        expected_digest = write["expected_sha256"]
        if (
            invalid_reason is None
            and expected_digest is not None
            and digest != expected_digest
        ):
            invalid_reason = (
                "last successful Write lacks matching run-local file bytes"
            )
        if invalid_reason is not None:
            if "file.write" in set(manifest["expected_event_types"]):
                raise KimiTraceNormalizationError(invalid_reason)
            # Incidental model writes are not required evidence for this stage.
            # Omitting an event that cannot be attributed is stricter than
            # failing an otherwise complete, unrelated binding.
            continue
        assert digest is not None
        emit(
            event_type="file.write",
            line=int(write["line"]),
            raw_event_type=str(write["raw_event_type"]),
            record=_mapping(write["record"], "structured write result record"),
            attributes={
                "origin_tool_call_id": str(write["call_id"]),
                "native_tool_name": str(write["tool_name"]),
                "hash_observer": "adapter_final_file_bytes",
            },
            artifact={
                "path": str(write["path"]),
                "sha256": digest,
                "operation": "write",
            },
        )

    if pending:
        raise KimiTraceNormalizationError(
            "trace ended with unresolved tool call ids: " + ", ".join(sorted(pending))
        )
    if pending_skill_activations:
        raise KimiTraceNormalizationError(
            "trace ended with unresolved skill activations: "
            + ", ".join(sorted(pending_skill_activations))
        )
    # Contract v1 has only a run-global expected-event set. It is safe to
    # enforce here for a single-stage binding. Multi-stage enforcement must be
    # performed by a future run-level aggregator with stage/order predicates;
    # all such Kimi bindings remain UNVALIDATED and cannot launch scored runs.
    if len(stages) == 1:
        observed = {event["event_type"] for event in events}
        required = set(manifest["expected_event_types"])
        missing = sorted(required - observed)
        if missing:
            successful_tool_names = {
                str(tool["name"])
                for tool in completed_tools
                if tool.get("is_error") is False
            }
            model_missing = {
                "skill.discovered": "Skill" not in successful_tool_names,
                "skill.activated": "Skill" not in successful_tool_names,
                "file.read": not completed_reads,
                "file.write": not completed_writes,
                "artifact.handoff": not completed_writes,
                "agent.spawned": "Agent" not in successful_tool_names,
                "agent.completed": "Agent" not in successful_tool_names,
                "mcp.tool_requested": not any(
                    _mcp_name(name) is not None for name in successful_tool_names
                ),
                "mcp.tool_result": not any(
                    _mcp_name(name) is not None for name in successful_tool_names
                ),
            }
            reason = (
                "required Event IR types were not directly observed: "
                + ", ".join(missing)
            )
            if all(model_missing.get(event_type) is True for event_type in missing):
                raise KimiModelProtocolIncompleteError(
                    reason,
                    failure_category="MODEL_REQUIRED_EVENT_MISSING",
                )
            raise KimiTraceNormalizationError(reason)
    return events


def _bench_owned_file(
    raw_path: Path,
    *,
    run_dir: Path,
    run_id: str,
    label: str,
    expected_sha256: str,
    expected_line_count: int | None = None,
) -> Path:
    """Resolve one immutable executor capture without following a link."""

    supplied = Path(raw_path).absolute()
    if not supplied.is_absolute() or supplied.is_symlink():
        raise KimiTraceNormalizationError(
            f"{label} must be an absolute non-symlink file"
        )
    try:
        relative = supplied.relative_to(run_dir)
    except ValueError as exc:
        raise KimiTraceNormalizationError(f"{label} escapes the Kimi run") from exc
    cursor = run_dir
    for component in relative.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise KimiTraceNormalizationError(f"{label} traverses a symlink")
    resolved = supplied.resolve(strict=True)
    try:
        resolved.relative_to(run_dir)
    except ValueError as exc:
        raise KimiTraceNormalizationError(f"{label} resolves outside the Kimi run") from exc
    if not resolved.is_file():
        raise KimiTraceNormalizationError(f"{label} is not a regular file")
    if "kimi" not in resolved.as_posix().casefold() or run_id not in resolved.as_posix():
        raise KimiTraceNormalizationError(f"{label} lacks kimi/run_id ownership")
    expected = _sha256(expected_sha256, label)
    raw = resolved.read_bytes()
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected):
        raise KimiTraceNormalizationError(f"{label} SHA-256 drifted")
    if expected_line_count is not None:
        if (
            not isinstance(expected_line_count, int)
            or isinstance(expected_line_count, bool)
            or expected_line_count < 1
        ):
            raise KimiTraceNormalizationError(f"{label} line count is invalid")
        if len(raw.splitlines()) != expected_line_count:
            raise KimiTraceNormalizationError(f"{label} line count drifted")
    return resolved


def _bench_append_only_source(
    raw_path: Path,
    *,
    captured_path: Path,
    run_dir: Path,
    run_id: str,
    label: str,
    expected_sha256: str,
    expected_line_count: int,
) -> Path:
    supplied = Path(raw_path).absolute()
    if supplied.is_symlink():
        raise KimiTraceNormalizationError(f"{label} must not be a symlink")
    try:
        relative = supplied.relative_to(run_dir)
    except ValueError as exc:
        raise KimiTraceNormalizationError(f"{label} escapes the Kimi run") from exc
    cursor = run_dir
    for component in relative.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise KimiTraceNormalizationError(f"{label} traverses a symlink")
    source = supplied.resolve(strict=True)
    if (
        "kimi" not in source.as_posix().casefold()
        or run_id not in source.as_posix()
        or not source.is_file()
    ):
        raise KimiTraceNormalizationError(
            f"{label} lacks a regular kimi/run_id-owned source"
        )
    expected = _sha256(expected_sha256, label)
    captured = captured_path.read_bytes()
    if (
        len(captured.splitlines()) != expected_line_count
        or not hmac.compare_digest(hashlib.sha256(captured).hexdigest(), expected)
    ):
        raise KimiTraceNormalizationError(
            f"{label} immutable capture hash/line_count drifted"
        )
    source_lines = source.read_bytes().splitlines(keepends=True)
    if len(source_lines) < expected_line_count:
        raise KimiTraceNormalizationError(f"{label} lost captured lines")
    prefix = b"".join(source_lines[:expected_line_count])
    if prefix != captured or not hmac.compare_digest(
        hashlib.sha256(prefix).hexdigest(), expected
    ):
        raise KimiTraceNormalizationError(
            f"{label} is not an append-only extension of its capture"
        )
    return source


def _bench_stage_result(
    capture: "StageCapture", *, run_dir: Path, run_id: str, case_id: str
) -> Mapping[str, Any]:
    path = Path(capture.result_path).absolute()
    if path.is_symlink():
        raise KimiTraceNormalizationError("stage result must not be a symlink")
    try:
        path.relative_to(run_dir)
    except ValueError as exc:
        raise KimiTraceNormalizationError("stage result escapes the Kimi run") from exc
    try:
        document = _mapping(
            json.loads(path.read_text(encoding="utf-8")), "stage result"
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KimiTraceNormalizationError("stage result is unavailable or malformed") from exc
    stage = _mapping(document.get("stage"), "stage result identity")
    if (
        document.get("schema_name") != "safety_bench_kimi_stage_execution"
        or document.get("schema_version") != 1
        or document.get("harness_id") != "kimi"
        or document.get("run_id") != run_id
        or document.get("case_id") != case_id
        or stage.get("index") != capture.index
        or stage.get("name") != capture.name
        or document.get("pid") != capture.pid
        or document.get("return_code") != capture.return_code
    ):
        raise KimiTraceNormalizationError("stage result identity drifted")
    return document


class KimiBenchEventIRNormalizer:
    """Production run-level normalizer for executor-owned Kimi evidence.

    The normalizer consumes only the exact files pinned by ``StageCapture``.
    Each stage is parsed independently, so call-id correlation and required
    Event IR types cannot leak across a process boundary.  The resulting
    events are ordered by stage and directly observed timestamp, then assigned
    one run-global contiguous sequence.
    """

    def __init__(self, *, identity: HarnessIdentity) -> None:
        if identity.harness_id != "kimi":
            raise ValueError("bench Event IR normalizer requires a Kimi identity")
        if not isinstance(identity.version, str) or not identity.version:
            raise ValueError("bench Event IR normalizer requires a Kimi version")
        self.identity = identity

    def normalize(self, request: "NormalizationRequest") -> Path:
        if (
            not isinstance(request.run_id, str)
            or not request.run_id
            or not isinstance(request.case_id, str)
            or not request.case_id
        ):
            raise KimiTraceNormalizationError(
                "normalization request identity is incomplete"
            )
        manifest_path = Path(request.manifest_path).absolute()
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise KimiTraceNormalizationError(
                "bench materialization manifest is missing or linked"
            )
        manifest_raw = manifest_path.read_bytes()
        expected_manifest_sha = _sha256(
            request.manifest_sha256, "bench materialization manifest"
        )
        if not hmac.compare_digest(
            hashlib.sha256(manifest_raw).hexdigest(), expected_manifest_sha
        ):
            raise KimiTraceNormalizationError(
                "bench materialization manifest SHA-256 drifted"
            )
        manifest = load_bench_materialization_manifest(manifest_path)
        materialized = _mapping(manifest.get("materialized"), "materialized case")
        run_dir = Path(str(materialized.get("run_dir"))).resolve(strict=True)
        workspace = Path(str(materialized.get("workspace_dir"))).resolve(strict=True)
        try:
            manifest_path.resolve().relative_to(run_dir)
            workspace.relative_to(run_dir)
        except ValueError as exc:
            raise KimiTraceNormalizationError(
                "manifest or workspace escapes the Kimi run"
            ) from exc
        if (
            manifest.get("harness_id") != "kimi"
            or manifest.get("run_id") != request.run_id
            or manifest.get("case_id") != request.case_id
            or "kimi" not in run_dir.as_posix().casefold()
            or request.run_id not in run_dir.as_posix()
        ):
            raise KimiTraceNormalizationError(
                "bench manifest identity differs from the normalization request"
            )

        output_path = Path(request.output_path).absolute()
        if output_path.exists() or output_path.is_symlink():
            raise KimiTraceNormalizationError(
                "refusing to overwrite an Event IR output"
            )
        try:
            output_path.relative_to(run_dir)
        except ValueError as exc:
            raise KimiTraceNormalizationError(
                "Event IR output escapes the Kimi run"
            ) from exc
        if output_path.name != f"event-ir-kimi-{request.run_id}.jsonl":
            raise KimiTraceNormalizationError(
                "Event IR output lacks the exact Kimi run_id name"
            )

        raw_stages = manifest.get("stages")
        if not isinstance(raw_stages, list) or not raw_stages:
            raise KimiTraceNormalizationError("bench manifest has no stages")
        captures = tuple(request.stage_captures)
        if len(captures) != len(raw_stages):
            raise KimiTraceNormalizationError(
                "normalization stage captures do not cover the manifest"
            )

        normalized: list[dict[str, Any]] = []
        for raw_stage, capture in zip(raw_stages, captures):
            stage = dict(_mapping(raw_stage, "bench stage"))
            if (
                stage.get("index") != capture.index
                or stage.get("name") != capture.name
                or capture.return_code != 0
            ):
                raise KimiTraceNormalizationError(
                    "normalization stage capture identity or outcome differs"
                )
            expected = stage.get("expected_event_ir")
            if not isinstance(expected, list) or any(
                not isinstance(item, str) or not item for item in expected
            ):
                raise KimiTraceNormalizationError(
                    "bench stage expected_event_ir is invalid"
                )
            result = _bench_stage_result(
                capture,
                run_dir=run_dir,
                run_id=request.run_id,
                case_id=request.case_id,
            )
            stdout = _mapping(result.get("stdout"), "stage stdout reference")
            if (
                Path(str(stdout.get("path"))).absolute()
                != Path(capture.stdout_path).absolute()
                or stdout.get("sha256") != capture.stdout_sha256
            ):
                raise KimiTraceNormalizationError(
                    "stage stdout capture differs from its result record"
                )
            stdout_path = _bench_owned_file(
                Path(capture.stdout_path),
                run_dir=run_dir,
                run_id=request.run_id,
                label=f"stage {capture.index} stdout",
                expected_sha256=capture.stdout_sha256,
                expected_line_count=stdout.get("line_count"),
            )
            source_specs: list[KimiObservedTraceSource] = [
                KimiObservedTraceSource(
                    path=stdout_path,
                    sha256=capture.stdout_sha256,
                    mode="session_meta",
                )
            ]

            wire_result = _mapping(result.get("wire"), "stage wire reference")
            result_captures = wire_result.get("captures")
            if not isinstance(result_captures, list) or len(result_captures) != len(
                capture.wire_captures
            ):
                raise KimiTraceNormalizationError(
                    "stage wire captures differ from the result record"
                )
            for position, (wire, result_wire) in enumerate(
                zip(capture.wire_captures, result_captures)
            ):
                result_wire = _mapping(
                    result_wire, f"stage wire capture {position}"
                )
                if dict(result_wire) != wire.as_dict():
                    raise KimiTraceNormalizationError(
                        "stage wire capture record drifted"
                    )
                captured_path = _bench_owned_file(
                    wire.captured_path,
                    run_dir=run_dir,
                    run_id=request.run_id,
                    label=f"stage {capture.index} captured wire {position}",
                    expected_sha256=wire.sha256,
                    expected_line_count=wire.line_count,
                )
                _bench_append_only_source(
                    wire.source_path,
                    captured_path=captured_path,
                    run_dir=run_dir,
                    run_id=request.run_id,
                    label=f"stage {capture.index} native wire {position}",
                    expected_sha256=wire.sha256,
                    expected_line_count=wire.line_count,
                )
                source_specs.append(
                    KimiObservedTraceSource(
                        path=captured_path,
                        sha256=wire.sha256,
                        mode="all",
                    )
                )

            if capture.observation_trace_path is not None:
                observation = _mapping(
                    result.get("control_observation_trace"),
                    "stage control observation trace",
                )
                if (
                    observation.get("path")
                    != str(capture.observation_trace_path)
                    or observation.get("sha256")
                    != capture.observation_trace_sha256
                ):
                    raise KimiTraceNormalizationError(
                        "stage observation trace differs from its result record"
                    )
                observation_path = _bench_owned_file(
                    capture.observation_trace_path,
                    run_dir=run_dir,
                    run_id=request.run_id,
                    label=f"stage {capture.index} adapter observation trace",
                    expected_sha256=str(capture.observation_trace_sha256),
                    expected_line_count=observation.get("record_count"),
                )
                source_specs.append(
                    KimiObservedTraceSource(
                        path=observation_path,
                        sha256=str(capture.observation_trace_sha256),
                        mode="adapter",
                    )
                )
            elif result.get("control_observation_trace") is not None:
                raise KimiTraceNormalizationError(
                    "stage result names an unpinned observation trace"
                )

            stage_context = {
                "index": capture.index,
                "name": capture.name,
                "skills_dir": str(workspace / ".kimi-code" / "skills"),
                "artifacts": dict(
                    _mapping(
                        _mapping(stage.get("surfaces"), "bench stage surfaces").get(
                            "artifacts"
                        ),
                        "bench stage artifact surface",
                    )
                ),
            }
            events = normalize_kimi_trace(
                identity=self.identity,
                raw_trace_path=stdout_path,
                stage_index=capture.index,
                observed_context=KimiObservedTraceContext(
                    run_id=request.run_id,
                    case_id=request.case_id,
                    run_dir=run_dir,
                    workspace=workspace,
                    stage=stage_context,
                    expected_event_types=tuple(expected),
                    sources=tuple(source_specs),
                ),
            )
            events.sort(key=lambda item: (str(item["timestamp"]), int(item["sequence"])))
            normalized.extend(dict(item) for item in events)

        if not normalized:
            raise KimiTraceNormalizationError(
                "bench normalization produced no directly observed Event IR"
            )
        for sequence, event in enumerate(normalized):
            stage_index = int(_mapping(event.get("stage"), "Event IR stage")["index"])
            event["sequence"] = sequence
            event["event_id"] = _event_id(request.run_id, stage_index, sequence)
            validate_event_document(event)

        payload = "".join(
            json.dumps(
                event,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + "\n"
            for event in normalized
        ).encode("utf-8")
        output_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = output_path.parent / (
            f".event-ir-tmp-kimi-{request.run_id}-{os.getpid()}"
        )
        if temporary.exists() or temporary.is_symlink():
            raise KimiTraceNormalizationError(
                "normalizer temporary output already exists"
            )
        try:
            with temporary.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, output_path)
        finally:
            if temporary.exists():
                temporary.unlink()
        return output_path


__all__ = [
    "KimiBenchEventIRNormalizer",
    "KimiObservedTraceContext",
    "KimiObservedTraceSource",
    "KimiTraceNormalizationError",
    "normalize_kimi_trace",
]
