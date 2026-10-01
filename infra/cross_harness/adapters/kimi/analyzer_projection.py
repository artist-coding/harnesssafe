"""Strict Kimi evidence projection for the legacy Safety Bench analyzer.

This module is an evidence adapter, not a second trace normalizer.  It consumes
hash-pinned Kimi 0.26.0 stdout, native wire, Event IR, stage-result, and
callback-collector records and writes the narrow Claude-stream-json-shaped
surface currently understood by :mod:`infra.analyze_trace`.

The projected files are deliberately labelled as analyzer compatibility
artifacts.  They must never be described as Kimi native trace, and no record is
created unless a directly observed, hash-pinned source supports it.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from typing import Any, Mapping, Sequence

from ...contract import validate_event_document
from .callback_collector import (
    CALLBACK_EVIDENCE_SCHEMA_NAME,
    CALLBACK_MANIFEST_SCHEMA_NAME,
    CALLBACK_MANIFEST_SCHEMA_VERSION,
)


PROJECTION_SCHEMA_NAME = "safety_bench_kimi_analyzer_projection"
PROJECTION_SCHEMA_VERSION = 1
SEMANTIC_TRANSLATION = "analyzer_compatibility_only_not_native_trace"
# Backwards-free alias for callers which describe one collector evidence line
# as a record.  The value is owned by callback_collector.py.
CALLBACK_RECORD_SCHEMA_NAME = CALLBACK_EVIDENCE_SCHEMA_NAME

_KIMI_VERSION = "0.26.0"
_KIMI_BINARY_SHA256 = (
    "bc310a7d2f0c3c2cb1367fa7b2092375351efff51c6d4a358b8681b4a01fb7b0"
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_STAGE_RE = re.compile(r"[^A-Za-z0-9._-]+")


class KimiAnalyzerProjectionError(ValueError):
    """Raised when compatibility output cannot be proven from exact inputs."""


@dataclass(frozen=True)
class PinnedProjectionInput:
    """One immutable run-local input and its complete byte/line identity."""

    path: Path
    sha256: str
    line_count: int | None = None
    kind: str = "evidence"


@dataclass(frozen=True)
class KimiProjectionStage:
    """All directly captured evidence for one Kimi stage."""

    index: int
    name: str
    case_document: PinnedProjectionInput
    stdout: PinnedProjectionInput
    native_wires: tuple[PinnedProjectionInput, ...]
    auxiliary_sources: tuple[PinnedProjectionInput, ...]
    result: PinnedProjectionInput


@dataclass(frozen=True)
class KimiCallbackCollectorEvidence:
    """Independent callback collector manifest plus append-only observations."""

    manifest: PinnedProjectionInput
    observations: PinnedProjectionInput


@dataclass(frozen=True)
class KimiAnalyzerProjectionRequest:
    """Inputs for one run-local, analyzer-only compatibility tree."""

    run_id: str
    case_id: str
    trial_id: str
    run_root: Path
    output_dir: Path
    harness_version: str
    binary_sha256: str
    case_document: PinnedProjectionInput
    event_ir: PinnedProjectionInput
    stages: tuple[KimiProjectionStage, ...]
    callback: KimiCallbackCollectorEvidence | None = None


@dataclass(frozen=True)
class KimiAnalyzerProjectionResult:
    root: Path
    manifest_path: Path
    trace_path: Path
    honeypot_path: Path
    case_path: Path


@dataclass(frozen=True)
class _WireProjectionInput:
    """One full immutable wire snapshot and its append-only stage boundary."""

    stage_identity: tuple[int, str]
    path: Path
    item: PinnedProjectionInput
    records: tuple[Mapping[str, Any], ...]
    source_path: Path
    start_line: int = 0


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_sha256(value: Any) -> str:
    content = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return _sha256_bytes(content)


def _payload_sha256(value: Any) -> str:
    """Match the Event IR payload hashing rule used by the Kimi normalizer."""

    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return _sha256_bytes(value.encode("utf-8"))
        return _canonical_sha256(decoded)
    return _canonical_sha256(value)


def _valid_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise KimiAnalyzerProjectionError(f"{label} SHA-256 is invalid")
    return value


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise KimiAnalyzerProjectionError(f"{label} must be an object")
    return value


def _safe_stage_name(name: str) -> str:
    cleaned = _SAFE_STAGE_RE.sub("_", name).strip("._-")
    if not cleaned:
        raise KimiAnalyzerProjectionError("stage name has no safe path identity")
    return cleaned


def _validate_identity(request: KimiAnalyzerProjectionRequest) -> None:
    if not request.run_id or not request.case_id or not request.trial_id:
        raise KimiAnalyzerProjectionError(
            "run_id, case_id, and trial_id must be non-empty"
        )
    if request.harness_version != _KIMI_VERSION:
        raise KimiAnalyzerProjectionError(
            "successful native-wire projection is pinned to Kimi 0.26.0"
        )
    if not hmac.compare_digest(
        _valid_sha256(request.binary_sha256, "Kimi binary"),
        _KIMI_BINARY_SHA256,
    ):
        raise KimiAnalyzerProjectionError("Kimi executable pin is not reviewed")
    if not request.stages:
        raise KimiAnalyzerProjectionError("projection requires at least one stage")


def _strict_run_root(request: KimiAnalyzerProjectionRequest) -> Path:
    supplied = request.run_root.absolute()
    if supplied.is_symlink() or not supplied.is_dir():
        raise KimiAnalyzerProjectionError("run_root must be a real directory")
    resolved = supplied.resolve()
    if "kimi" not in resolved.as_posix().casefold() or request.run_id not in resolved.as_posix():
        raise KimiAnalyzerProjectionError("run_root lacks exact kimi/run_id ownership")
    return resolved


def _strict_run_path(path: Path, *, run_root: Path, label: str) -> Path:
    supplied = path.absolute()
    if supplied.is_symlink():
        raise KimiAnalyzerProjectionError(f"{label} must not be a symlink")
    try:
        relative = supplied.relative_to(run_root)
    except ValueError as exc:
        raise KimiAnalyzerProjectionError(f"{label} escapes the exact run root") from exc
    cursor = run_root
    for component in relative.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise KimiAnalyzerProjectionError(f"{label} traverses a symlink")
    resolved = supplied.resolve()
    try:
        resolved.relative_to(run_root)
    except ValueError as exc:
        raise KimiAnalyzerProjectionError(f"{label} resolves outside the run root") from exc
    return resolved


def _read_pinned(
    item: PinnedProjectionInput, *, run_root: Path, label: str
) -> tuple[Path, bytes]:
    path = _strict_run_path(Path(item.path), run_root=run_root, label=label)
    if not path.is_file():
        raise KimiAnalyzerProjectionError(f"{label} is not a regular file")
    expected = _valid_sha256(item.sha256, label)
    content = path.read_bytes()
    if not hmac.compare_digest(_sha256_bytes(content), expected):
        raise KimiAnalyzerProjectionError(f"{label} SHA-256 drifted")
    if (
        not isinstance(item.line_count, int)
        or isinstance(item.line_count, bool)
        or item.line_count < 0
    ):
        raise KimiAnalyzerProjectionError(f"{label} line_count is invalid")
    observed = len(content.splitlines())
    if observed != item.line_count:
        raise KimiAnalyzerProjectionError(f"{label} line_count drifted")
    return path, content


def _decode_json(content: bytes, label: str) -> Mapping[str, Any]:
    try:
        decoded = json.loads(content.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KimiAnalyzerProjectionError(f"{label} is malformed JSON") from exc
    return _mapping(decoded, label)


def _decode_jsonl(content: bytes, label: str) -> list[Mapping[str, Any]]:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise KimiAnalyzerProjectionError(f"{label} is not UTF-8") from exc
    records: list[Mapping[str, Any]] = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            raise KimiAnalyzerProjectionError(
                f"{label}:{line_number} is an empty JSONL record"
            )
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise KimiAnalyzerProjectionError(
                f"{label}:{line_number} is malformed JSON"
            ) from exc
        records.append(_mapping(decoded, f"{label}:{line_number}"))
    return records


def _source_record(
    event: Mapping[str, Any],
    *,
    sources: Mapping[Path, tuple[PinnedProjectionInput, list[Mapping[str, Any]]]],
    run_root: Path,
) -> tuple[Path, int, Mapping[str, Any], PinnedProjectionInput]:
    source = _mapping(event.get("source"), "Event IR source")
    raw_path = source.get("trace_path")
    line = source.get("line")
    if not isinstance(raw_path, str) or not raw_path:
        raise KimiAnalyzerProjectionError("Event IR source path is missing")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        raise KimiAnalyzerProjectionError("Event IR source line is invalid")
    path = _strict_run_path(Path(raw_path), run_root=run_root, label="Event IR source")
    pinned = sources.get(path)
    if pinned is None:
        raise KimiAnalyzerProjectionError(
            "Event IR references a source absent from the exact input set"
        )
    item, records = pinned
    if line > len(records):
        raise KimiAnalyzerProjectionError("Event IR source line is outside its input")
    return path, line, records[line - 1], item


def _observed_raw_type(record: Mapping[str, Any]) -> str:
    record_type = str(record.get("type") or "")
    if record_type == "context.append_loop_event":
        event = record.get("event")
        if isinstance(event, Mapping):
            return f"context.append_loop_event:{event.get('type', '')}"
    if record_type == "context.append_message":
        message = record.get("message")
        if isinstance(message, Mapping):
            origin = message.get("origin")
            if isinstance(origin, Mapping):
                kind = str(origin.get("kind") or "")
                name = str(origin.get("name") or "")
                if kind == "system_trigger" and name:
                    return f"context.append_message:system_trigger:{name}"
                if kind == "skill_activation":
                    return "context.append_message:skill_activation"
    if record_type == "config.update" and "systemPrompt" in record:
        return "config.update:systemPrompt:skill_listing"
    if record_type == "llm.request" and record.get("kind") == "loop":
        return "llm.request:loop:resumed_session"
    if (
        record.get("event") == "jsonrpc.frame"
        and record.get("jsonrpc_kind") == "response"
        and record.get("correlated_method") == "initialize"
        and record.get("response_status") == "success"
    ):
        return "adapter.mcp_stdio_proxy:initialize.response"
    if record_type:
        return record_type
    if record.get("jsonrpc") == "2.0" and "result" in record:
        return "adapter.mcp_stdio_proxy:initialize.response"
    return "unknown"


def _validate_source_raw_type(
    event: Mapping[str, Any], record: Mapping[str, Any]
) -> None:
    source = _mapping(event.get("source"), "Event IR source")
    claimed = source.get("raw_event_type")
    if not isinstance(claimed, str) or not claimed:
        raise KimiAnalyzerProjectionError("Event IR raw_event_type is missing")
    observed = _observed_raw_type(record)
    if claimed == observed:
        return
    # The native Agent completion adds a reviewed tool-name suffix to the
    # otherwise exact wire record type.
    if claimed == "context.append_loop_event:tool.result:Agent" and observed == (
        "context.append_loop_event:tool.result"
    ):
        return
    # Fresh-session hints are explicitly qualified by the adapter.
    if claimed == "session.resume_hint:fresh_process" and observed == (
        "session.resume_hint"
    ):
        return
    # The request observer record has its own exact adapter schema type.
    if claimed.startswith("adapter.loopback_request_observer:") and observed == str(
        record.get("type") or ""
    ):
        return
    raise KimiAnalyzerProjectionError(
        f"Event IR raw type {claimed!r} does not match source {observed!r}"
    )


def _tool_call_parts(record: Mapping[str, Any]) -> tuple[str, str, dict[str, Any]]:
    event = _mapping(record.get("event"), "native tool-call event")
    if event.get("type") != "tool.call":
        raise KimiAnalyzerProjectionError("native wire record is not tool.call")
    call_id = event.get("toolCallId", event.get("id"))
    name = event.get("name")
    arguments = event.get("args", event.get("arguments", {}))
    function = event.get("function")
    if isinstance(function, Mapping):
        name = function.get("name")
        arguments = function.get("arguments", {})
    if not isinstance(call_id, str) or not call_id:
        raise KimiAnalyzerProjectionError("native tool call lacks call_id")
    if not isinstance(name, str) or not name:
        raise KimiAnalyzerProjectionError("native tool call lacks name")
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError as exc:
            raise KimiAnalyzerProjectionError(
                f"native tool call {call_id!r} has malformed arguments"
            ) from exc
    if not isinstance(arguments, Mapping):
        raise KimiAnalyzerProjectionError("native tool arguments must be an object")
    return call_id, name, dict(arguments)


def _tool_result_parts(record: Mapping[str, Any]) -> tuple[str, Any, bool]:
    event = _mapping(record.get("event"), "native tool-result event")
    if event.get("type") != "tool.result":
        raise KimiAnalyzerProjectionError("native wire record is not tool.result")
    call_id = event.get("toolCallId")
    result = _mapping(event.get("result"), "native tool result")
    is_error = result.get("isError")
    if is_error is not None and not isinstance(is_error, bool):
        raise KimiAnalyzerProjectionError("native tool result isError is malformed")
    if not isinstance(call_id, str) or not call_id:
        raise KimiAnalyzerProjectionError("native tool result lacks call_id")
    # Kimi 0.26.0 normalizeToolResult omits isError only on success.  The
    # executable/version checks above are therefore part of this conclusion.
    return call_id, result.get("output"), is_error is True


def _provenance(
    *, path: Path, line: int, sha256: str, raw_type: str, role: str
) -> dict[str, Any]:
    return {
        "path": str(path),
        "line": line,
        "sha256": sha256,
        "raw_event_type": raw_type,
        "projection_role": role,
        "semantic_translation": SEMANTIC_TRANSLATION,
    }


def _assistant_text(content: Any) -> list[dict[str, str]]:
    if isinstance(content, str):
        return [{"type": "text", "text": content}] if content else []
    if not isinstance(content, list):
        return []
    visible: list[dict[str, str]] = []
    for block in content:
        if isinstance(block, str) and block:
            visible.append({"type": "text", "text": block})
        elif isinstance(block, Mapping) and str(block.get("type") or "").lower() in {
            "text",
            "output_text",
        }:
            text = block.get("text")
            if isinstance(text, str) and text:
                visible.append({"type": "text", "text": text})
    return visible


def _stdout_projection(
    *, path: Path, digest: str, records: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for line, record in enumerate(records, start=1):
        if str(record.get("role") or "").lower() != "assistant":
            continue
        content = _assistant_text(record.get("content"))
        if not content:
            continue
        projected.append(
            {
                "type": "assistant",
                "message": {"role": "assistant", "content": content},
                "kimi_projection_source": _provenance(
                    path=path,
                    line=line,
                    sha256=digest,
                    raw_type="assistant.visible_text",
                    role="assistant_authored_visible_text_only",
                ),
            }
        )
    return projected


def _wire_append_boundaries(
    wire_inputs: Sequence[_WireProjectionInput],
) -> tuple[_WireProjectionInput, ...]:
    """Prove full snapshots of a reused native wire form one append chain.

    Kimi native session resume and ACP compaction append to the same
    ``wire.jsonl``.  The executor deliberately preserves a full immutable
    snapshot after every stage.  Re-projecting every full snapshot would
    duplicate prior tool call IDs, so only the newly appended suffix belongs to
    a later stage.  This function derives that suffix only after byte-for-byte
    prefix and final live-source checks; it never writes a trimmed trace.
    """

    by_source: dict[Path, list[_WireProjectionInput]] = {}
    for wire in wire_inputs:
        by_source.setdefault(wire.source_path, []).append(wire)
    bounded: dict[Path, _WireProjectionInput] = {}
    for source_path, snapshots in by_source.items():
        previous_content: bytes | None = None
        previous_line_count = 0
        previous_stage = -1
        for wire in snapshots:
            stage_index = wire.stage_identity[0]
            if stage_index <= previous_stage:
                raise KimiAnalyzerProjectionError(
                    "one native wire source was captured multiple times in one "
                    "stage or out of stage order"
                )
            content = wire.path.read_bytes()
            if len(content.splitlines()) != wire.item.line_count:
                raise KimiAnalyzerProjectionError(
                    "native wire snapshot line count drifted"
                )
            if previous_content is not None:
                if (
                    len(content) <= len(previous_content)
                    or wire.item.line_count <= previous_line_count
                    or not content.startswith(previous_content)
                ):
                    raise KimiAnalyzerProjectionError(
                        "reused native wire snapshots are not a strict append-only "
                        "prefix chain"
                    )
            bounded[wire.path] = replace(wire, start_line=previous_line_count)
            previous_content = content
            previous_line_count = wire.item.line_count
            previous_stage = stage_index
        if previous_content is None:
            raise KimiAnalyzerProjectionError(
                "native wire source has no immutable snapshot"
            )
        if source_path.read_bytes() != previous_content:
            raise KimiAnalyzerProjectionError(
                "live native wire differs from its final immutable full snapshot"
            )
    return tuple(bounded[wire.path] for wire in wire_inputs)


def _wire_projection(
    *,
    wire_inputs: Sequence[_WireProjectionInput],
    child_parent_by_wire: Mapping[Path, str],
) -> tuple[
    list[dict[str, Any]],
    dict[str, tuple[str, dict[str, Any], Path, int]],
    dict[str, tuple[Any, bool, Path, int]],
]:
    projected: list[dict[str, Any]] = []
    calls: dict[str, tuple[str, dict[str, Any], Path, int]] = {}
    results: dict[str, tuple[Any, bool, Path, int]] = {}
    pending: set[str] = set()
    for wire in wire_inputs:
        path = wire.path
        item = wire.item
        parent = child_parent_by_wire.get(path)
        for line, record in enumerate(
            wire.records[wire.start_line :], start=wire.start_line + 1
        ):
            if record.get("type") != "context.append_loop_event":
                continue
            event = record.get("event")
            if not isinstance(event, Mapping):
                raise KimiAnalyzerProjectionError(
                    f"native wire {path}:{line} loop event is malformed"
                )
            event_type = event.get("type")
            if event_type == "tool.call":
                call_id, name, arguments = _tool_call_parts(record)
                if call_id in calls or call_id in results:
                    raise KimiAnalyzerProjectionError(
                        f"duplicate native tool call id {call_id!r}"
                    )
                calls[call_id] = (name, arguments, path, line)
                pending.add(call_id)
                compat: dict[str, Any] = {
                    "type": "assistant",
                    "message": {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "tool_use",
                                "id": call_id,
                                "name": name,
                                "input": arguments,
                            }
                        ],
                    },
                    "kimi_projection_source": _provenance(
                        path=path,
                        line=line,
                        sha256=item.sha256,
                        raw_type="context.append_loop_event:tool.call",
                        role="native_wire_tool_call",
                    ),
                }
                if parent is not None:
                    compat["parent_tool_use_id"] = parent
                projected.append(compat)
            elif event_type == "tool.result":
                call_id, output, is_error = _tool_result_parts(record)
                if call_id not in pending or call_id in results:
                    raise KimiAnalyzerProjectionError(
                        f"native tool result {call_id!r} has no unique prior call"
                    )
                call = calls[call_id]
                if call[2] != path:
                    raise KimiAnalyzerProjectionError(
                        f"native tool result {call_id!r} crosses wire identities"
                    )
                pending.remove(call_id)
                results[call_id] = (output, is_error, path, line)
                compat = {
                    "type": "user",
                    "message": {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": call_id,
                                "content": output,
                                "is_error": is_error,
                            }
                        ],
                    },
                    "kimi_projection_source": _provenance(
                        path=path,
                        line=line,
                        sha256=item.sha256,
                        raw_type="context.append_loop_event:tool.result",
                        role=(
                            "native_wire_tool_error"
                            if is_error
                            else "version_pinned_native_wire_tool_success"
                        ),
                    ),
                }
                if parent is not None:
                    compat["parent_tool_use_id"] = parent
                projected.append(compat)
    if pending:
        raise KimiAnalyzerProjectionError(
            "native wires contain unresolved call_ids: " + ", ".join(sorted(pending))
        )
    return projected, calls, results


def _mcp_wire_name(name: str) -> tuple[str, str] | None:
    if not name.startswith("mcp__"):
        return None
    server, separator, tool = name[len("mcp__") :].partition("__")
    if not separator or not server or not tool:
        raise KimiAnalyzerProjectionError(f"malformed native MCP name {name!r}")
    return server, tool


def _same_artifact_path(raw_path: Any, relative_path: Any) -> bool:
    if not isinstance(raw_path, str) or not isinstance(relative_path, str):
        return False
    raw = raw_path.replace("\\", "/").rstrip("/")
    relative = relative_path.replace("\\", "/").lstrip("/").rstrip("/")
    return bool(relative and (raw == relative or raw.endswith("/" + relative)))


def _validate_event_semantics(
    event: Mapping[str, Any],
    *,
    source_record: Mapping[str, Any],
    source_path: Path,
    source_line: int,
    calls: Mapping[str, tuple[str, dict[str, Any], Path, int]],
    results: Mapping[str, tuple[Any, bool, Path, int]],
) -> None:
    event_type = str(event.get("event_type") or "")
    attributes = _mapping(event.get("attributes"), "Event IR attributes")
    if event_type.startswith("mcp.tool_"):
        tool = _mapping(event.get("tool"), "Event IR MCP tool")
        call_id = tool.get("call_id")
        if not isinstance(call_id, str) or call_id not in calls:
            raise KimiAnalyzerProjectionError("Event IR MCP call_id has no native call")
        name, arguments, _, _ = calls[call_id]
        mcp_name = _mcp_wire_name(name)
        if mcp_name != (tool.get("server"), tool.get("name")):
            raise KimiAnalyzerProjectionError("Event IR MCP identity mismatches native wire")
        if event_type == "mcp.tool_requested":
            if (source_path, source_line) != (calls[call_id][2], calls[call_id][3]):
                raise KimiAnalyzerProjectionError(
                    "Event IR MCP request locator mismatches native wire"
                )
            if not hmac.compare_digest(
                str(tool.get("arguments_sha256") or ""),
                _canonical_sha256(arguments),
            ):
                raise KimiAnalyzerProjectionError("Event IR MCP argument hash drifted")
        else:
            result = results.get(call_id)
            if result is None:
                raise KimiAnalyzerProjectionError("Event IR MCP result is unresolved")
            output, is_error, _, _ = result
            if (source_path, source_line) != (result[2], result[3]):
                raise KimiAnalyzerProjectionError(
                    "Event IR MCP result locator mismatches native wire"
                )
            expected_status = "error" if is_error else "success"
            if tool.get("status") != expected_status:
                raise KimiAnalyzerProjectionError("Event IR MCP status mismatches native wire")
            if not hmac.compare_digest(
                str(tool.get("result_sha256") or ""), _payload_sha256(output)
            ):
                raise KimiAnalyzerProjectionError("Event IR MCP result hash drifted")
    if event_type == "skill.activated":
        call_id = attributes.get("origin_tool_call_id")
        call = calls.get(str(call_id))
        result = results.get(str(call_id))
        if call is None or call[0].casefold() != "skill" or result is None or result[1]:
            raise KimiAnalyzerProjectionError(
                "skill activation lacks a successful native Skill call"
            )
        expected_skill = str(attributes.get("skill_name") or "")
        actual_skill = str(
            call[1].get("skill")
            or call[1].get("name")
            or call[1].get("skill_name")
            or ""
        )
        if not expected_skill or actual_skill != expected_skill:
            raise KimiAnalyzerProjectionError("skill activation identity drifted")
    if event_type in {"file.read", "file.write"}:
        call_id = attributes.get("origin_tool_call_id")
        call = calls.get(str(call_id))
        result = results.get(str(call_id))
        expected = "read" if event_type == "file.read" else "write"
        if call is None or expected not in call[0].casefold() or result is None or result[1]:
            raise KimiAnalyzerProjectionError(
                f"{event_type} lacks a successful correlated native call"
            )
        artifact = _mapping(event.get("artifact"), f"{event_type} artifact")
        if event_type == "file.write":
            if (source_path, source_line) != (result[2], result[3]):
                raise KimiAnalyzerProjectionError(
                    "file.write locator mismatches its native result"
                )
        else:
            if (
                source_record.get("type") != "adapter.file_hash_observed"
                or source_record.get("toolCallId") != call_id
                or source_record.get("sha256") != artifact.get("sha256")
            ):
                raise KimiAnalyzerProjectionError(
                    "file.read adapter observation does not bind its call and SHA-256"
                )
    if event_type == "artifact.handoff":
        artifact = _mapping(event.get("artifact"), "artifact handoff")
        if (
            source_record.get("type") != "adapter.artifact_handoff"
            or source_record.get("sha256") != artifact.get("sha256")
            or not _same_artifact_path(
                source_record.get("path"), artifact.get("path")
            )
        ):
            raise KimiAnalyzerProjectionError(
                "artifact.handoff source does not bind the projected artifact"
            )
    # Adapter lifecycle observations are themselves validated against their
    # exact raw source line below; this check prevents arbitrary Event IR rows
    # from being treated as native lifecycle evidence.
    if event_type.startswith("session.") and _observed_raw_type(source_record) == "unknown":
        raise KimiAnalyzerProjectionError("session Event IR source is not observable")


def _lifecycle_projection(
    *,
    event: Mapping[str, Any],
    source_path: Path,
    source_line: int,
    source_record: Mapping[str, Any],
    source_sha256: str,
    stage_result_path: Path,
    stage_result_sha256: str,
) -> list[dict[str, Any]]:
    event_type = str(event["event_type"])
    session_id = event.get("session_id")
    if event_type not in {"session.started", "session.resumed", "session.compacted"}:
        return []
    if not isinstance(session_id, str) or not session_id:
        raise KimiAnalyzerProjectionError("session Event IR lacks session_id")
    source = _mapping(event["source"], "session Event IR source")
    source_provenance = _provenance(
        path=source_path,
        line=source_line,
        sha256=source_sha256,
        raw_type=str(source["raw_event_type"]),
        role=f"event_ir_{event_type}",
    )
    if event_type in {"session.started", "session.resumed"}:
        return [
            {
                "type": "system",
                "subtype": "init",
                "session_id": session_id,
                "kimi_projection_source": source_provenance,
            },
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "session_id": session_id,
                "kimi_projection_source": _provenance(
                    path=stage_result_path,
                    line=1,
                    sha256=stage_result_sha256,
                    raw_type="safety_bench_kimi_stage_execution:return_code_0",
                    role="hash_pinned_stage_process_success",
                ),
            },
        ]

    attributes = _mapping(event.get("attributes"), "compaction attributes")
    if source_record.get("type") != "context.apply_compaction":
        raise KimiAnalyzerProjectionError(
            "session.compacted does not point to context.apply_compaction"
        )
    summary = source_record.get("summary")
    if not isinstance(summary, str) or not summary:
        raise KimiAnalyzerProjectionError("compaction source lacks summary text")
    if not hmac.compare_digest(
        _canonical_text_sha(summary), str(attributes.get("summary_sha256") or "")
    ):
        raise KimiAnalyzerProjectionError("compaction summary SHA-256 drifted")
    pre_tokens = attributes.get("pre_tokens")
    post_tokens = attributes.get("post_tokens")
    if (
        not isinstance(pre_tokens, int)
        or isinstance(pre_tokens, bool)
        or not isinstance(post_tokens, int)
        or isinstance(post_tokens, bool)
        or pre_tokens <= post_tokens
    ):
        raise KimiAnalyzerProjectionError("compaction token reduction is invalid")
    return [
        {
            "type": "system",
            "subtype": "status",
            "status": "compacting",
            "session_id": session_id,
            "kimi_projection_source": source_provenance,
        },
        {
            "type": "system",
            "subtype": "status",
            "compact_result": "success",
            "session_id": session_id,
            "kimi_projection_source": source_provenance,
        },
        {
            "type": "user",
            "isSynthetic": True,
            "session_id": session_id,
            "message": {"role": "user", "content": summary},
            "kimi_projection_source": source_provenance,
        },
        {
            "type": "system",
            "subtype": "compact_boundary",
            "session_id": session_id,
            "compact_metadata": {
                "trigger": attributes.get("compaction_source"),
                "pre_tokens": pre_tokens,
                "post_tokens": post_tokens,
            },
            "kimi_projection_source": source_provenance,
        },
    ]


def _canonical_text_sha(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def _validate_stage_result(
    *,
    stage: KimiProjectionStage,
    result_path: Path,
    result_sha256: str,
    result: Mapping[str, Any],
    stdout_path: Path,
    stdout_sha256: str,
    wires: Sequence[tuple[Path, PinnedProjectionInput, Sequence[Mapping[str, Any]]]],
    request: KimiAnalyzerProjectionRequest,
) -> dict[Path, Path]:
    if (
        result.get("schema_name") != "safety_bench_kimi_stage_execution"
        or result.get("schema_version") != 1
        or result.get("harness_id") != "kimi"
        or result.get("run_id") != request.run_id
        or result.get("case_id") != request.case_id
    ):
        raise KimiAnalyzerProjectionError("stage result identity is invalid")
    result_stage = _mapping(result.get("stage"), "stage result stage")
    if result_stage.get("index") != stage.index or result_stage.get("name") != stage.name:
        raise KimiAnalyzerProjectionError("stage result stage identity drifted")
    if result.get("return_code") != 0 or result.get("timed_out") is not False:
        raise KimiAnalyzerProjectionError("stage process did not complete successfully")
    disposition = result.get("execution_disposition")
    if isinstance(disposition, Mapping) and disposition.get("outcome") not in {
        None,
        "COMPLETED",
    }:
        raise KimiAnalyzerProjectionError("stage result is not a completed disposition")
    stdout = _mapping(result.get("stdout"), "stage result stdout")
    stdout_reference = Path(str(stdout.get("path") or "")).absolute()
    if (
        stdout_reference != stdout_path
        or not hmac.compare_digest(str(stdout.get("sha256") or ""), stdout_sha256)
        or stdout.get("line_count") != stage.stdout.line_count
    ):
        raise KimiAnalyzerProjectionError("stage result does not pin exact stdout")
    wire_document = _mapping(result.get("wire"), "stage result wire")
    captures = wire_document.get("captures")
    if not isinstance(captures, list):
        raise KimiAnalyzerProjectionError("stage result wire captures are malformed")
    captured: dict[Path, tuple[str, Any]] = {}
    sources: dict[Path, Path] = {}
    main_paths: list[Path] = []
    for raw_capture in captures:
        capture = _mapping(raw_capture, "stage result wire capture")
        if set(capture) != {
            "source_path",
            "captured_path",
            "sha256",
            "line_count",
            "is_main",
        } or not isinstance(capture.get("is_main"), bool):
            raise KimiAnalyzerProjectionError(
                "stage result wire capture keys drifted"
            )
        raw_path = capture.get("captured_path")
        raw_source = capture.get("source_path")
        if (
            not isinstance(raw_path, str)
            or not raw_path
            or not isinstance(raw_source, str)
            or not raw_source
        ):
            raise KimiAnalyzerProjectionError(
                "wire capture/source path is missing"
            )
        captured_path = _strict_run_path(
            Path(raw_path),
            run_root=request.run_root.resolve(),
            label="stage result captured wire",
        )
        source_path = _strict_run_path(
            Path(raw_source),
            run_root=request.run_root.resolve(),
            label="stage result native wire source",
        )
        if not captured_path.is_file() or not source_path.is_file():
            raise KimiAnalyzerProjectionError(
                "stage result wire capture/source is not a regular file"
            )
        if captured_path in captured:
            raise KimiAnalyzerProjectionError("wire capture path is duplicated")
        captured[captured_path] = (
            str(capture.get("sha256") or ""),
            capture.get("line_count"),
        )
        sources[captured_path] = source_path
        if capture["is_main"]:
            main_paths.append(captured_path)
    expected = {
        path: (item.sha256, item.line_count) for path, item, _ in wires
    }
    if captured != expected:
        raise KimiAnalyzerProjectionError("stage result does not pin exact native wires")
    if len(main_paths) != 1:
        raise KimiAnalyzerProjectionError(
            "stage result does not identify exactly one main native wire"
        )
    main_path = _strict_run_path(
        Path(str(wire_document.get("main_path") or "")),
        run_root=request.run_root.resolve(),
        label="stage result main wire copy",
    )
    main_sha256 = str(wire_document.get("main_sha256") or "")
    main_item = expected[main_paths[0]]
    if (
        not main_path.is_file()
        or not hmac.compare_digest(main_sha256, main_item[0])
        or not hmac.compare_digest(_sha256_bytes(main_path.read_bytes()), main_sha256)
        or main_path.read_bytes() != main_paths[0].read_bytes()
    ):
        raise KimiAnalyzerProjectionError(
            "stage result main wire copy does not match its immutable capture"
        )
    # Keep these arguments used and make the evidence relationship explicit.
    if not result_path.is_file() or not hmac.compare_digest(
        _sha256_bytes(result_path.read_bytes()), result_sha256
    ):
        raise KimiAnalyzerProjectionError("stage result changed during validation")
    return sources


def _validate_case_document(
    document: Mapping[str, Any], *, request: KimiAnalyzerProjectionRequest, label: str
) -> None:
    case_id = document.get("case_id")
    if case_id is not None and case_id != request.case_id:
        raise KimiAnalyzerProjectionError(f"{label} case_id drifted")
    workspace = document.get("workspace_dir")
    if not isinstance(workspace, str) or not workspace:
        raise KimiAnalyzerProjectionError(f"{label} lacks workspace_dir")
    workspace_path = _strict_run_path(
        Path(workspace), run_root=request.run_root.resolve(), label=f"{label} workspace"
    )
    if not workspace_path.is_dir():
        raise KimiAnalyzerProjectionError(f"{label} workspace is not a directory")


def _event_stage(event: Mapping[str, Any]) -> tuple[int, str]:
    stage = _mapping(event.get("stage"), "Event IR stage")
    index = stage.get("index")
    name = stage.get("name")
    if (
        not isinstance(index, int)
        or isinstance(index, bool)
        or index < 0
        or not isinstance(name, str)
        or not name
    ):
        raise KimiAnalyzerProjectionError("Event IR stage identity is invalid")
    return index, name


def _callback_records(
    *,
    request: KimiAnalyzerProjectionRequest,
    run_root: Path,
    stage_identities: set[tuple[int, str]],
    inputs: list[dict[str, Any]],
) -> dict[tuple[int, str], list[dict[str, Any]]]:
    split = {identity: [] for identity in stage_identities}
    if request.callback is None:
        return split
    manifest_path, manifest_bytes = _read_pinned(
        request.callback.manifest, run_root=run_root, label="callback collector manifest"
    )
    observations_path, observations_bytes = _read_pinned(
        request.callback.observations,
        run_root=run_root,
        label="callback collector observations",
    )
    manifest = _decode_json(manifest_bytes, "callback collector manifest")
    records = _decode_jsonl(observations_bytes, "callback collector observations")
    if (
        manifest.get("schema_name") != CALLBACK_MANIFEST_SCHEMA_NAME
        or manifest.get("schema_version") != CALLBACK_MANIFEST_SCHEMA_VERSION
        or manifest.get("harness_id") != "kimi"
        or manifest.get("run_id") != request.run_id
        or manifest.get("case_id") != request.case_id
        or manifest.get("trial_id") != request.trial_id
    ):
        raise KimiAnalyzerProjectionError("callback collector manifest identity is invalid")
    claimed_manifest_sha = manifest.get("manifest_payload_sha256")
    expected_manifest_sha = _canonical_sha256(
        {
            key: value
            for key, value in manifest.items()
            if key != "manifest_payload_sha256"
        }
    )
    if (
        not isinstance(claimed_manifest_sha, str)
        or not hmac.compare_digest(claimed_manifest_sha, expected_manifest_sha)
    ):
        raise KimiAnalyzerProjectionError(
            "callback collector manifest self-hash drifted"
        )
    evidence_metadata = observations_path.stat()
    if (
        Path(str(manifest.get("evidence_path") or "")).absolute()
        != observations_path
        or not hmac.compare_digest(
            str(manifest.get("evidence_sha256") or ""),
            request.callback.observations.sha256,
        )
        or manifest.get("line_count") != len(records)
        or manifest.get("evidence_inode") != evidence_metadata.st_ino
        or stat.S_IMODE(evidence_metadata.st_mode) != 0o600
    ):
        raise KimiAnalyzerProjectionError(
            "callback collector evidence path/inode/hash/line pin drifted"
        )

    identity_by_index = {index: name for index, name in stage_identities}
    previous: str | None = None
    for line, record in enumerate(records, start=1):
        stage_index = record.get("stage_index")
        claimed_record_sha = record.get("record_sha256")
        expected_record_sha = _canonical_sha256(
            {key: value for key, value in record.items() if key != "record_sha256"}
        )
        if (
            record.get("schema_name") != CALLBACK_RECORD_SCHEMA_NAME
            or record.get("schema_version") != 1
            or record.get("harness_id") != "kimi"
            or record.get("run_id") != request.run_id
            or record.get("case_id") != request.case_id
            or record.get("trial_id") != request.trial_id
            or not isinstance(stage_index, int)
            or isinstance(stage_index, bool)
            or stage_index not in identity_by_index
            or record.get("sequence") != line
            or record.get("previous_record_sha256") != previous
            or not isinstance(claimed_record_sha, str)
            or not hmac.compare_digest(claimed_record_sha, expected_record_sha)
        ):
            raise KimiAnalyzerProjectionError(
                "callback observation identity or hash chain is invalid"
            )
        previous = claimed_record_sha
        identity = (stage_index, identity_by_index[stage_index])
        projected = dict(record)
        projected["stage"] = {"index": identity[0], "name": identity[1]}
        projected["kimi_projection_source"] = _provenance(
            path=observations_path,
            line=line,
            sha256=request.callback.observations.sha256,
            raw_type=CALLBACK_RECORD_SCHEMA_NAME,
            role="independent_callback_collector_observation",
        )
        split[identity].append(projected)
    if manifest.get("hash_chain_head_sha256") != previous:
        raise KimiAnalyzerProjectionError(
            "callback collector manifest hash-chain head drifted"
        )

    segments = manifest.get("completed_stage_connections")
    if not isinstance(segments, list) or not segments:
        raise KimiAnalyzerProjectionError(
            "callback collector has no completed stage connections"
        )
    covered_lines: set[int] = set()
    for raw_segment in segments:
        segment = _mapping(raw_segment, "callback completed stage connection")
        stage_index = segment.get("stage_index")
        connection_id = segment.get("connection_id")
        record_count = segment.get("record_count")
        if (
            not isinstance(stage_index, int)
            or isinstance(stage_index, bool)
            or stage_index not in identity_by_index
            or not isinstance(connection_id, str)
            or not connection_id
            or not isinstance(record_count, int)
            or isinstance(record_count, bool)
            or record_count < 0
            or segment.get("outcome") != "completed"
        ):
            raise KimiAnalyzerProjectionError(
                "callback completed-stage connection is invalid"
            )
        first_line = segment.get("first_line")
        last_line = segment.get("last_line")
        if record_count == 0:
            if any(
                segment.get(key) is not None
                for key in (
                    "first_line",
                    "last_line",
                    "first_record_sha256",
                    "last_record_sha256",
                )
            ):
                raise KimiAnalyzerProjectionError(
                    "empty callback connection has non-empty line locators"
                )
            continue
        if (
            not isinstance(first_line, int)
            or isinstance(first_line, bool)
            or not isinstance(last_line, int)
            or isinstance(last_line, bool)
            or first_line < 1
            or last_line - first_line + 1 != record_count
            or last_line > len(records)
        ):
            raise KimiAnalyzerProjectionError(
                "callback connection line segment is invalid"
            )
        selected = records[first_line - 1 : last_line]
        if (
            segment.get("first_record_sha256") != selected[0].get("record_sha256")
            or segment.get("last_record_sha256") != selected[-1].get("record_sha256")
            or any(
                record.get("stage_index") != stage_index
                or record.get("connection_id") != connection_id
                for record in selected
            )
        ):
            raise KimiAnalyzerProjectionError(
                "callback connection does not bind its exact record segment"
            )
        for line in range(first_line, last_line + 1):
            if line in covered_lines:
                raise KimiAnalyzerProjectionError(
                    "callback record belongs to multiple completed connections"
                )
            covered_lines.add(line)
    if covered_lines != set(range(1, len(records) + 1)):
        raise KimiAnalyzerProjectionError(
            "callback records are not fully bound to completed connections"
        )
    inputs.extend(
        [
            _input_manifest_record(request.callback.manifest, manifest_path),
            _input_manifest_record(request.callback.observations, observations_path),
        ]
    )
    return split


def _input_manifest_record(item: PinnedProjectionInput, path: Path) -> dict[str, Any]:
    return {
        "kind": item.kind,
        "path": str(path),
        "sha256": item.sha256,
        "line_count": item.line_count,
    }


def _jsonl_bytes(records: Sequence[Mapping[str, Any]]) -> bytes:
    return b"".join(
        json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
        for record in records
    )


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def project_kimi_analyzer_compatibility(
    request: KimiAnalyzerProjectionRequest,
) -> KimiAnalyzerProjectionResult:
    """Create one fail-closed, run-local analyzer compatibility tree."""

    _validate_identity(request)
    run_root = _strict_run_root(request)
    output_dir = _strict_run_path(
        request.output_dir, run_root=run_root, label="projection output directory"
    )
    if output_dir.exists():
        raise KimiAnalyzerProjectionError("projection output directory already exists")
    if output_dir.parent.is_symlink():
        raise KimiAnalyzerProjectionError("projection output parent is a symlink")

    case_path, case_bytes = _read_pinned(
        request.case_document, run_root=run_root, label="run case document"
    )
    case_document = _decode_json(case_bytes, "run case document")
    _validate_case_document(case_document, request=request, label="run case document")
    event_ir_path, event_ir_bytes = _read_pinned(
        request.event_ir, run_root=run_root, label="Event IR"
    )
    event_ir_records = _decode_jsonl(event_ir_bytes, "Event IR")

    inputs = [
        _input_manifest_record(request.case_document, case_path),
        _input_manifest_record(request.event_ir, event_ir_path),
    ]
    stage_data: dict[tuple[int, str], dict[str, Any]] = {}
    all_sources: dict[
        Path, tuple[PinnedProjectionInput, list[Mapping[str, Any]]]
    ] = {}
    all_wire_inputs: list[_WireProjectionInput] = []
    indices: set[int] = set()
    for expected_stage_index, stage in enumerate(request.stages):
        if (
            stage.index in indices
            or stage.index != expected_stage_index
            or not stage.name
        ):
            raise KimiAnalyzerProjectionError("stage identities must be unique and valid")
        indices.add(stage.index)
        identity = (stage.index, stage.name)
        stage_case_path, stage_case_bytes = _read_pinned(
            stage.case_document,
            run_root=run_root,
            label=f"stage {stage.index} case document",
        )
        stage_case = _decode_json(stage_case_bytes, f"stage {stage.index} case document")
        _validate_case_document(
            stage_case, request=request, label=f"stage {stage.index} case document"
        )
        if (
            stage_case.get("stage_index") != stage.index + 1
            or stage_case.get("stage_name") != stage.name
        ):
            raise KimiAnalyzerProjectionError(
                "stage case document lacks the exact one-based analyzer stage identity"
            )
        stdout_path, stdout_bytes = _read_pinned(
            stage.stdout, run_root=run_root, label=f"stage {stage.index} stdout"
        )
        stdout_records = _decode_jsonl(stdout_bytes, f"stage {stage.index} stdout")
        result_path, result_bytes = _read_pinned(
            stage.result, run_root=run_root, label=f"stage {stage.index} result"
        )
        result = _decode_json(result_bytes, f"stage {stage.index} result")
        wires: list[tuple[Path, PinnedProjectionInput, Sequence[Mapping[str, Any]]]] = []
        stage_sources: list[
            tuple[Path, PinnedProjectionInput, Sequence[Mapping[str, Any]]]
        ] = [(stdout_path, stage.stdout, stdout_records)]
        for wire_index, wire in enumerate(stage.native_wires):
            wire_path, wire_bytes = _read_pinned(
                wire,
                run_root=run_root,
                label=f"stage {stage.index} native wire {wire_index}",
            )
            wire_records = _decode_jsonl(
                wire_bytes, f"stage {stage.index} native wire {wire_index}"
            )
            entry = (wire_path, wire, wire_records)
            wires.append(entry)
            stage_sources.append(entry)
        for source_index, source in enumerate(stage.auxiliary_sources):
            source_path, source_bytes = _read_pinned(
                source,
                run_root=run_root,
                label=f"stage {stage.index} auxiliary source {source_index}",
            )
            records = _decode_jsonl(
                source_bytes, f"stage {stage.index} auxiliary source {source_index}"
            )
            stage_sources.append((source_path, source, records))
        for path, item, records in stage_sources:
            if path in all_sources:
                raise KimiAnalyzerProjectionError("projection input path is duplicated")
            all_sources[path] = (item, list(records))
            inputs.append(_input_manifest_record(item, path))
        inputs.extend(
            [
                _input_manifest_record(stage.case_document, stage_case_path),
                _input_manifest_record(stage.result, result_path),
            ]
        )
        wire_sources = _validate_stage_result(
            stage=stage,
            result_path=result_path,
            result_sha256=stage.result.sha256,
            result=result,
            stdout_path=stdout_path,
            stdout_sha256=stage.stdout.sha256,
            wires=wires,
            request=request,
        )
        all_wire_inputs.extend(
            _WireProjectionInput(
                stage_identity=identity,
                path=path,
                item=item,
                records=tuple(records),
                source_path=wire_sources[path],
            )
            for path, item, records in wires
        )
        stage_data[identity] = {
            "stage": stage,
            "case_bytes": stage_case_bytes,
            "stdout_path": stdout_path,
            "stdout_records": stdout_records,
            "result_path": result_path,
            "wires": wires,
            "events": [],
        }

    if indices != set(range(len(request.stages))):
        raise KimiAnalyzerProjectionError("stage indices must be contiguous from zero")
    bounded_wire_inputs = _wire_append_boundaries(all_wire_inputs)

    event_by_stage: dict[tuple[int, str], list[Mapping[str, Any]]] = {
        identity: [] for identity in stage_data
    }
    seen_event_ids: set[str] = set()
    seen_sequences: set[int] = set()
    source_refs: dict[str, tuple[Path, int, Mapping[str, Any], PinnedProjectionInput]] = {}
    for event in event_ir_records:
        try:
            validate_event_document(event)
        except Exception as exc:
            raise KimiAnalyzerProjectionError("Event IR schema validation failed") from exc
        if (
            event.get("run_id") != request.run_id
            or event.get("case_id") != request.case_id
            or _mapping(event.get("harness"), "Event IR harness").get("id") != "kimi"
            or _mapping(event.get("harness"), "Event IR harness").get("version")
            != request.harness_version
        ):
            raise KimiAnalyzerProjectionError("Event IR identity drifted")
        flags = _mapping(
            _mapping(event.get("harness"), "Event IR harness").get("feature_flags"),
            "Event IR feature_flags",
        )
        if flags.get("binary_sha256") != request.binary_sha256:
            raise KimiAnalyzerProjectionError("Event IR executable identity drifted")
        event_id = event.get("event_id")
        sequence = event.get("sequence")
        if (
            not isinstance(event_id, str)
            or event_id in seen_event_ids
            or not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence in seen_sequences
        ):
            raise KimiAnalyzerProjectionError("Event IR event identity is duplicated")
        seen_event_ids.add(event_id)
        seen_sequences.add(sequence)
        identity = _event_stage(event)
        if identity not in stage_data:
            raise KimiAnalyzerProjectionError("Event IR references an unknown stage")
        source_ref = _source_record(event, sources=all_sources, run_root=run_root)
        _validate_source_raw_type(event, source_ref[2])
        source_refs[event_id] = source_ref
        event_by_stage[identity].append(event)
    if seen_sequences != set(range(len(event_ir_records))):
        raise KimiAnalyzerProjectionError("Event IR sequences are not contiguous from zero")

    # Establish the child-wire causal mapping only from paired, already
    # schema/source-validated Event IR lifecycle records.
    spawned: dict[tuple[str, str], tuple[str, Path]] = {}
    completed: dict[tuple[str, str], tuple[Path, int]] = {}
    for event in event_ir_records:
        if event.get("event_type") not in {"agent.spawned", "agent.completed"}:
            continue
        attributes = _mapping(event.get("attributes"), "agent lifecycle attributes")
        origin = attributes.get("origin_tool_call_id")
        agent_id = event.get("agent_id")
        if not isinstance(origin, str) or not origin or not isinstance(agent_id, str) or not agent_id:
            raise KimiAnalyzerProjectionError("agent lifecycle origin is incomplete")
        key = (agent_id, origin)
        source_path = source_refs[str(event["event_id"])][0]
        if event["event_type"] == "agent.spawned":
            if key in spawned:
                raise KimiAnalyzerProjectionError("duplicate agent.spawned evidence")
            spawned[key] = (origin, source_path)
        else:
            if key in completed:
                raise KimiAnalyzerProjectionError("duplicate agent.completed evidence")
            completion_record = source_refs[str(event["event_id"])][2]
            completion_id, completion_output, completion_error = _tool_result_parts(
                completion_record
            )
            if completion_id != origin or completion_error:
                raise KimiAnalyzerProjectionError(
                    "agent.completed locator is not its successful native Agent result"
                )
            expected_handoff = attributes.get("handoff_sha256")
            if not isinstance(expected_handoff, str) or not hmac.compare_digest(
                expected_handoff, _payload_sha256(completion_output)
            ):
                raise KimiAnalyzerProjectionError("agent handoff SHA-256 drifted")
            completed[key] = (
                source_path,
                int(_mapping(event["source"], "agent completion source")["line"]),
            )
    if set(spawned) != set(completed):
        raise KimiAnalyzerProjectionError("agent lifecycle is unpaired")
    native_wire_paths = {wire.path for wire in bounded_wire_inputs}
    child_parent_by_wire: dict[Path, str] = {}
    for origin, path in spawned.values():
        if path not in native_wire_paths:
            raise KimiAnalyzerProjectionError(
                "agent.spawned source is not an exact native child wire input"
            )
        prior = child_parent_by_wire.get(path)
        if prior is not None and prior != origin:
            raise KimiAnalyzerProjectionError(
                "one native child wire is attributed to multiple Agent calls"
            )
        child_parent_by_wire[path] = origin

    wire_projection, calls, results = _wire_projection(
        wire_inputs=bounded_wire_inputs, child_parent_by_wire=child_parent_by_wire
    )
    wire_projection_by_stage: dict[tuple[int, str], list[dict[str, Any]]] = {
        identity: [] for identity in stage_data
    }
    path_to_stage = {
        wire.path: wire.stage_identity for wire in bounded_wire_inputs
    }
    for record in wire_projection:
        source_path = Path(record["kimi_projection_source"]["path"]).resolve()
        wire_projection_by_stage[path_to_stage[source_path]].append(record)

    for key, (origin, _) in spawned.items():
        call = calls.get(origin)
        result = results.get(origin)
        if call is None or call[0] != "Agent" or result is None or result[1]:
            raise KimiAnalyzerProjectionError(
                f"agent lifecycle {key[0]!r} lacks successful native Agent call"
            )
        if completed[key] != (result[2], result[3]):
            raise KimiAnalyzerProjectionError(
                "agent.completed source does not identify its native result"
            )

    for identity, events in event_by_stage.items():
        data = stage_data[identity]
        for event in sorted(events, key=lambda item: int(item["sequence"])):
            source_path, source_line, source_record, source_item = source_refs[
                str(event["event_id"])
            ]
            _validate_event_semantics(
                event,
                source_record=source_record,
                source_path=source_path,
                source_line=source_line,
                calls=calls,
                results=results,
            )
            data["events"].extend(
                _lifecycle_projection(
                    event=event,
                    source_path=source_path,
                    source_line=source_line,
                    source_record=source_record,
                    source_sha256=source_item.sha256,
                    stage_result_path=data["result_path"],
                    stage_result_sha256=data["stage"].result.sha256,
                )
            )

    callback_by_stage = _callback_records(
        request=request,
        run_root=run_root,
        stage_identities=set(stage_data),
        inputs=inputs,
    )

    output_payloads: dict[Path, bytes] = {}
    all_trace: list[Mapping[str, Any]] = []
    all_honeypot: list[Mapping[str, Any]] = []
    output_payloads[output_dir / "case.json"] = case_bytes
    for identity in sorted(stage_data):
        data = stage_data[identity]
        stage = data["stage"]
        stage_dir = output_dir / "stages" / f"{stage.index:03d}_{_safe_stage_name(stage.name)}"
        records = [
            *_stdout_projection(
                path=data["stdout_path"],
                digest=stage.stdout.sha256,
                records=data["stdout_records"],
            ),
            *wire_projection_by_stage[identity],
            *data["events"],
        ]
        honeypot = callback_by_stage[identity]
        output_payloads[stage_dir / "case.json"] = data["case_bytes"]
        output_payloads[stage_dir / "trace.jsonl"] = _jsonl_bytes(records)
        output_payloads[stage_dir / "honeypot.jsonl"] = _jsonl_bytes(honeypot)
        all_trace.extend(records)
        all_honeypot.extend(honeypot)
    output_payloads[output_dir / "trace.jsonl"] = _jsonl_bytes(all_trace)
    output_payloads[output_dir / "honeypot.jsonl"] = _jsonl_bytes(all_honeypot)

    outputs = [
        {
            "path": str(path),
            "sha256": _sha256_bytes(content),
            "bytes": len(content),
            "line_count": len(content.splitlines()),
        }
        for path, content in sorted(output_payloads.items(), key=lambda item: str(item[0]))
    ]
    manifest = {
        "schema_name": PROJECTION_SCHEMA_NAME,
        "schema_version": PROJECTION_SCHEMA_VERSION,
        "semantic_translation": SEMANTIC_TRANSLATION,
        "harness_id": "kimi",
        "harness_version": request.harness_version,
        "binary_sha256": request.binary_sha256,
        "run_id": request.run_id,
        "case_id": request.case_id,
        "trial_id": request.trial_id,
        "run_root": str(run_root),
        "projection_root": str(output_dir),
        "inputs": sorted(inputs, key=lambda item: (item["path"], item["kind"])),
        "outputs": outputs,
        "event_ir_sha256": request.event_ir.sha256,
        "record_counts": {
            "projected_trace": len(all_trace),
            "projected_honeypot": len(all_honeypot),
            "event_ir": len(event_ir_records),
        },
        "claims": {
            "native_trace": False,
            "analyzer_compatibility_only": True,
            "raw_evidence_modified": False,
        },
    }
    manifest["manifest_payload_sha256"] = _canonical_sha256(manifest)
    manifest_path = output_dir / f"projection-manifest-kimi-{request.run_id}.json"
    manifest_bytes = json.dumps(
        manifest, indent=2, sort_keys=True, ensure_ascii=False
    ).encode("utf-8") + b"\n"

    # Validation above is intentionally complete before the first write.  A
    # failed projection therefore cannot leave a partial analyzer tree.
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".projection-kimi-{request.run_id}.", dir=output_dir.parent
        )
    )
    try:
        for path, content in output_payloads.items():
            _atomic_write(staging / path.relative_to(output_dir), content)
        _atomic_write(staging / manifest_path.relative_to(output_dir), manifest_bytes)
        os.replace(staging, output_dir)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return KimiAnalyzerProjectionResult(
        root=output_dir,
        manifest_path=manifest_path,
        trace_path=output_dir / "trace.jsonl",
        honeypot_path=output_dir / "honeypot.jsonl",
        case_path=output_dir / "case.json",
    )


__all__ = [
    "CALLBACK_MANIFEST_SCHEMA_NAME",
    "CALLBACK_RECORD_SCHEMA_NAME",
    "KimiAnalyzerProjectionError",
    "KimiAnalyzerProjectionRequest",
    "KimiAnalyzerProjectionResult",
    "KimiCallbackCollectorEvidence",
    "KimiProjectionStage",
    "PinnedProjectionInput",
    "PROJECTION_SCHEMA_NAME",
    "SEMANTIC_TRANSLATION",
    "project_kimi_analyzer_compatibility",
]
