"""Normalize OpenCode JSON events into Cross-Harness Event IR v1."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from ...adapter import HarnessIdentity, MaterializedBinding
from ...contract import validate_event_document
from .materializer import (
    OpenCodeMaterializationError,
    canonical_sha256,
    load_materialization_manifest,
    sha256_file,
)


class OpenCodeTraceError(RuntimeError):
    """OpenCode raw evidence cannot be normalized without guessing."""


def _timestamp(value: Any) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(
            float(value) / 1000.0, tz=timezone.utc
        ).isoformat()
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
        else:
            if parsed.tzinfo is not None:
                return parsed.isoformat()
    return datetime.now(timezone.utc).isoformat()


def _read_jsonl(path: Path) -> list[tuple[int, dict[str, Any]]]:
    result: list[tuple[int, dict[str, Any]]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise OpenCodeTraceError(f"cannot read OpenCode trace {path}: {exc}") from exc
    for line_number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OpenCodeTraceError(
                f"{path}:{line_number} is not valid JSON: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise OpenCodeTraceError(
                f"{path}:{line_number} must contain a JSON object"
            )
        result.append((line_number, value))
    return result


def _safe_workspace_artifact(
    *, workspace: Path, value: Any
) -> tuple[str, str] | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = Path(value)
    resolved = (
        candidate.resolve()
        if candidate.is_absolute()
        else (workspace / candidate).resolve()
    )
    try:
        relative = resolved.relative_to(workspace)
    except ValueError:
        return None
    if not resolved.is_file():
        return None
    return relative.as_posix(), sha256_file(resolved)


def _tool_path(arguments: Mapping[str, Any]) -> Any:
    for key in ("filePath", "file_path", "path"):
        if key in arguments:
            return arguments[key]
    return None


def _memory_for_path(
    path: str, bindings: Any, *, digest: str
) -> dict[str, str] | None:
    if not isinstance(bindings, list):
        return None
    for raw in bindings:
        if not isinstance(raw, Mapping) or raw.get("path") != path:
            continue
        values = {
            "store": raw.get("store"),
            "scope": raw.get("scope"),
            "entry_id": raw.get("entry_id"),
            "sha256": digest,
        }
        if all(isinstance(value, str) and value for value in values.values()):
            return values  # type: ignore[return-value]
    return None


def _mcp_identity(tool_name: str, servers: Any) -> tuple[str, str] | None:
    if not isinstance(servers, list):
        return None
    for server in servers:
        if not isinstance(server, str) or not server:
            continue
        prefixes = {
            server + "_",
            server.replace("-", "_") + "_",
        }
        for prefix in prefixes:
            if tool_name.startswith(prefix) and len(tool_name) > len(prefix):
                return server, tool_name[len(prefix) :]
    return None


def _session_id(records: list[tuple[int, dict[str, Any]]]) -> str | None:
    for _, record in records:
        value = record.get("sessionID")
        if isinstance(value, str) and value:
            return value
        part = record.get("part")
        if isinstance(part, Mapping):
            value = part.get("sessionID")
            if isinstance(value, str) and value:
                return value
    return None


def normalize_opencode_trace(
    *,
    identity: HarnessIdentity,
    materialized: MaterializedBinding,
    raw_trace_path: Path,
    stage_index: int,
    run_id: str,
    artifact_snapshot_before: Mapping[str, str | None] | None = None,
) -> Iterable[Mapping[str, Any]]:
    try:
        manifest = load_materialization_manifest(materialized)
    except OpenCodeMaterializationError as exc:
        raise OpenCodeTraceError(str(exc)) from exc
    stages = manifest.get("stages")
    if not isinstance(stages, list):
        raise OpenCodeTraceError("materialization manifest has no stages")
    stage = next(
        (
            value
            for value in stages
            if isinstance(value, Mapping) and value.get("index") == stage_index
        ),
        None,
    )
    if stage is None:
        raise OpenCodeTraceError(f"manifest has no stage {stage_index}")
    records = _read_jsonl(Path(raw_trace_path))
    if not records:
        raise OpenCodeTraceError("OpenCode raw trace is empty")
    for line_number, record in records:
        if record.get("type") == "error":
            raise OpenCodeTraceError(
                f"OpenCode emitted a session error at line {line_number}"
            )

    workspace = Path(str(manifest["workspace_dir"])).resolve()
    session_id = _session_id(records)
    if not session_id:
        raise OpenCodeTraceError("OpenCode trace has no sessionID")
    feature_flags = {
        key: value
        for key, value in identity.feature_flags.items()
        if isinstance(value, (bool, str, int, float)) and not isinstance(value, complex)
    }
    sequence = 0

    def event(
        *,
        event_type: str,
        source_path: Path,
        source_line: int,
        raw_event_type: str,
        timestamp: Any,
        attributes: Mapping[str, Any] | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        nonlocal sequence
        sequence += 1
        result = {
            "schema_name": "safety_bench_cross_harness_event",
            "schema_version": 1,
            "event_id": f"{run_id}:s{stage_index}:{sequence:04d}",
            "event_type": event_type,
            "run_id": run_id,
            "case_id": materialized.case_id,
            "harness": {
                "id": "opencode",
                "version": identity.version,
                "feature_flags": feature_flags,
            },
            "stage": {"name": str(stage["name"]), "index": stage_index},
            "sequence": sequence,
            "timestamp": _timestamp(timestamp),
            "source": {
                "trace_path": str(source_path),
                "line": source_line,
                "raw_event_type": raw_event_type,
            },
            "attributes": dict(attributes or {}),
            **extra,
        }
        validate_event_document(result)
        return result

    first_line, first_record = records[0]
    action = stage.get("session_action", "fresh")
    yield event(
        event_type="session.resumed" if action in {"resume", "continue"} else "session.started",
        source_path=Path(raw_trace_path),
        source_line=first_line,
        raw_event_type=str(first_record.get("type", "opencode.event")),
        timestamp=first_record.get("timestamp"),
        attributes={"launch_action": str(action)},
        session_id=session_id,
    )

    hook_path = Path(str(manifest["hook_log_path"]))
    if hook_path.is_file():
        for line_number, record in _read_jsonl(hook_path):
            record_session = record.get("sessionID")
            if record_session not in {None, session_id}:
                continue
            record_stage = record.get("stageIndex")
            if record_stage not in {None, stage_index}:
                continue
            if record.get("kind") == "instruction.loaded":
                path = record.get("path")
                digest = record.get("sha256")
                if (
                    isinstance(path, str)
                    and isinstance(digest, str)
                    and len(digest) == 64
                ):
                    yield event(
                        event_type="instruction.loaded",
                        source_path=hook_path,
                        source_line=line_number,
                        raw_event_type="hook.instruction.loaded",
                        timestamp=record.get("timestamp"),
                        attributes={"path": path, "sha256": digest},
                    )
            if record.get("kind") == "event":
                raw_event = record.get("event")
                if (
                    isinstance(raw_event, Mapping)
                    and raw_event.get("type") == "session.compacted"
                ):
                    properties = raw_event.get("properties")
                    if not isinstance(properties, Mapping):
                        continue
                    pre_tokens = properties.get("preTokens")
                    post_tokens = properties.get("postTokens")
                    summary = properties.get("summary")
                    if (
                        isinstance(pre_tokens, int)
                        and isinstance(post_tokens, int)
                        and pre_tokens > post_tokens
                        and isinstance(summary, str)
                    ):
                        yield event(
                            event_type="session.compacted",
                            source_path=hook_path,
                            source_line=line_number,
                            raw_event_type="session.compacted",
                            timestamp=record.get("timestamp"),
                            attributes={
                                "pre_tokens": pre_tokens,
                                "post_tokens": post_tokens,
                                "summary_sha256": hashlib.sha256(
                                    summary.encode("utf-8")
                                ).hexdigest(),
                            },
                            session_id=session_id,
                        )

    handoff_paths = {
        value for value in manifest.get("handoff_paths", []) if isinstance(value, str)
    }
    skills = manifest.get("skills", {})
    memory_bindings = manifest.get("memory_bindings", [])
    mcp_servers = manifest.get("mcp_servers", [])
    initialized_mcp_servers: set[str] = set()
    observed_write_paths: set[str] = set()
    for line_number, record in records:
        if record.get("type") != "tool_use":
            continue
        part = record.get("part")
        if not isinstance(part, Mapping):
            continue
        state = part.get("state")
        if not isinstance(state, Mapping) or state.get("status") != "completed":
            continue
        tool_name = part.get("tool")
        if not isinstance(tool_name, str) or not tool_name:
            continue
        arguments = state.get("input")
        if not isinstance(arguments, Mapping):
            arguments = {}
        output = state.get("output")
        call_id = part.get("callID", part.get("id"))
        if not isinstance(call_id, str) or not call_id:
            call_id = f"line-{line_number}"
        raw_timestamp = record.get("timestamp")

        mcp = _mcp_identity(tool_name, mcp_servers)
        if mcp is not None:
            server, name = mcp
            tool = {
                "server": server,
                "name": name,
                "call_id": call_id,
                "arguments_sha256": canonical_sha256(arguments),
            }
            if server not in initialized_mcp_servers:
                initialized_mcp_servers.add(server)
                # A completed native MCP tool call is direct runtime evidence
                # that OpenCode connected to the configured server and listed
                # its tools.  OpenCode's JSON stream has no separate initial
                # connection record, so the first successful call is the
                # earliest non-inferred initialization evidence available.
                yield event(
                    event_type="mcp.server_initialized",
                    source_path=Path(raw_trace_path),
                    source_line=line_number,
                    raw_event_type="tool_use",
                    timestamp=raw_timestamp,
                    attributes={"status": "connected"},
                    tool={"server": server},
                )
            yield event(
                event_type="mcp.tool_requested",
                source_path=Path(raw_trace_path),
                source_line=line_number,
                raw_event_type="tool_use",
                timestamp=raw_timestamp,
                tool=tool,
            )
            yield event(
                event_type="mcp.tool_result",
                source_path=Path(raw_trace_path),
                source_line=line_number,
                raw_event_type="tool_use",
                timestamp=raw_timestamp,
                tool={
                    **tool,
                    "result_sha256": hashlib.sha256(
                        str(output).encode("utf-8")
                    ).hexdigest(),
                    "status": "success",
                },
            )
            continue

        if tool_name == "skill":
            skill_name = arguments.get("name")
            if not isinstance(skill_name, str) or not isinstance(skills, Mapping):
                continue
            raw_skill = skills.get(skill_name)
            if not isinstance(raw_skill, Mapping):
                continue
            digest = raw_skill.get("sha256")
            if not isinstance(digest, str) or len(digest) != 64:
                continue
            attributes = {
                "skill_name": skill_name,
                "skill_sha256": digest,
            }
            yield event(
                event_type="skill.discovered",
                source_path=Path(raw_trace_path),
                source_line=line_number,
                raw_event_type="tool_use",
                timestamp=raw_timestamp,
                attributes=attributes,
            )
            yield event(
                event_type="skill.activated",
                source_path=Path(raw_trace_path),
                source_line=line_number,
                raw_event_type="tool_use",
                timestamp=raw_timestamp,
                attributes=attributes,
            )
            continue

        if tool_name == "task":
            metadata = state.get("metadata")
            if not isinstance(metadata, Mapping):
                metadata = {}
            agent_id = metadata.get("sessionID", metadata.get("sessionId", call_id))
            if not isinstance(agent_id, str) or not agent_id:
                agent_id = call_id
            subagent = arguments.get(
                "subagent_type", arguments.get("agent", "opencode-subagent")
            )
            attributes = {"subagent_type": str(subagent)}
            yield event(
                event_type="agent.spawned",
                source_path=Path(raw_trace_path),
                source_line=line_number,
                raw_event_type="tool_use",
                timestamp=raw_timestamp,
                attributes=attributes,
                session_id=session_id,
                agent_id=agent_id,
                parent_agent_id=session_id,
            )
            yield event(
                event_type="agent.completed",
                source_path=Path(raw_trace_path),
                source_line=line_number,
                raw_event_type="tool_use",
                timestamp=raw_timestamp,
                attributes=attributes,
                session_id=session_id,
                agent_id=agent_id,
                parent_agent_id=session_id,
            )
            continue

        if tool_name not in {"read", "write", "edit", "apply_patch"}:
            continue
        artifact = _safe_workspace_artifact(
            workspace=workspace, value=_tool_path(arguments)
        )
        if artifact is None:
            continue
        path, digest = artifact
        operation = "read" if tool_name == "read" else "write"
        event_type = "file.read" if operation == "read" else "file.write"
        if operation == "write":
            observed_write_paths.add(path)
        yield event(
            event_type=event_type,
            source_path=Path(raw_trace_path),
            source_line=line_number,
            raw_event_type="tool_use",
            timestamp=raw_timestamp,
            artifact={
                "path": path,
                "sha256": digest,
                "operation": operation,
            },
        )
        memory = _memory_for_path(path, memory_bindings, digest=digest)
        if memory is not None:
            yield event(
                event_type=(
                    "memory.retrieved"
                    if operation == "read"
                    else "memory.written"
                ),
                source_path=Path(raw_trace_path),
                source_line=line_number,
                raw_event_type="tool_use",
                timestamp=raw_timestamp,
                memory=memory,
            )
        if operation == "write" and path in handoff_paths:
            yield event(
                event_type="artifact.handoff",
                source_path=Path(raw_trace_path),
                source_line=line_number,
                raw_event_type="tool_use",
                timestamp=raw_timestamp,
                artifact={
                    "path": path,
                    "sha256": digest,
                    "operation": "handoff",
                },
            )

    if artifact_snapshot_before is not None:
        last_line, last_record = records[-1]
        for path in sorted(handoff_paths):
            artifact_path = workspace / path
            if not artifact_path.is_file() or path in observed_write_paths:
                continue
            digest = sha256_file(artifact_path)
            if artifact_snapshot_before.get(path) == digest:
                continue
            attributes = {
                "evidence": "post_stage_artifact_diff",
                "previous_sha256": artifact_snapshot_before.get(path) or "",
            }
            yield event(
                event_type="file.write",
                source_path=Path(raw_trace_path),
                source_line=last_line,
                raw_event_type="post_stage_artifact_diff",
                timestamp=last_record.get("timestamp"),
                attributes=attributes,
                artifact={
                    "path": path,
                    "sha256": digest,
                    "operation": "write",
                },
            )
            yield event(
                event_type="artifact.handoff",
                source_path=Path(raw_trace_path),
                source_line=last_line,
                raw_event_type="post_stage_artifact_diff",
                timestamp=last_record.get("timestamp"),
                attributes=attributes,
                artifact={
                    "path": path,
                    "sha256": digest,
                    "operation": "handoff",
                },
            )


__all__ = ["OpenCodeTraceError", "normalize_opencode_trace"]
