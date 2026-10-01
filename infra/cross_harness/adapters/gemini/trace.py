"""Strict Gemini CLI stream/hook/MCP normalization to Event IR v1."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from ...adapter import HarnessIdentity, MaterializedBinding
from ...contract import validate_event_document
from .materializer import sha256_bytes, sha256_file


class GeminiTraceNormalizationError(ValueError):
    """Raw Gemini evidence cannot be normalized without an unsupported inference."""


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GeminiTraceNormalizationError(f"{label} must be an object")
    return value


def _prior_stage_event_types(
    *, manifest: Mapping[str, Any], stage_index: int
) -> set[str]:
    """Load normalized event types already emitted by earlier stages.

    Multi-stage attack cases often produce required evidence in a producer stage
    and consume it in a later trigger stage.  The final scoreability gate must
    therefore validate the attack trial as a whole, not only the last raw stream.
    """

    observed: set[str] = set()
    for raw_stage in manifest.get("stages", []):
        if not isinstance(raw_stage, Mapping):
            continue
        raw_index = raw_stage.get("index")
        if not isinstance(raw_index, int) or isinstance(raw_index, bool):
            continue
        if raw_index >= stage_index:
            continue
        trace_path = raw_stage.get("trace_path")
        if not isinstance(trace_path, str) or not trace_path.strip():
            continue
        event_path = Path(trace_path).with_name("event-ir.jsonl")
        if not event_path.is_file():
            continue
        for line_number, line in enumerate(
            event_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise GeminiTraceNormalizationError(
                    f"prior stage Event IR is invalid JSON: {event_path}:{line_number}"
                ) from exc
            event_type = event.get("event_type")
            if isinstance(event_type, str):
                observed.add(event_type)
    return observed


def _timestamp(value: Any) -> tuple[str, datetime]:
    if not isinstance(value, str) or not value.strip():
        raise GeminiTraceNormalizationError("raw Gemini event timestamp is absent")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GeminiTraceNormalizationError(
            f"invalid raw Gemini timestamp: {value!r}"
        ) from exc
    if parsed.tzinfo is None:
        raise GeminiTraceNormalizationError("raw Gemini timestamp must include a timezone")
    normalized = parsed.astimezone(timezone.utc)
    return normalized.isoformat(), normalized


def _sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise GeminiTraceNormalizationError(f"{label} must be lowercase SHA-256")
    return value


def _canonical_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    )


def _stage(manifest: Mapping[str, Any], stage_index: int) -> Mapping[str, Any]:
    matches = [item for item in manifest["stages"] if item["index"] == stage_index]
    if len(matches) != 1:
        raise GeminiTraceNormalizationError(f"unknown Gemini stage index {stage_index}")
    return matches[0]


def _run_file(path: Path, run_dir: Path, label: str, *, required: bool) -> Path | None:
    supplied = path.absolute()
    if supplied.is_symlink():
        raise GeminiTraceNormalizationError(f"{label} must not be a symlink")
    try:
        relative = supplied.relative_to(run_dir)
    except ValueError as exc:
        raise GeminiTraceNormalizationError(f"{label} escapes the Gemini run") from exc
    cursor = run_dir
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise GeminiTraceNormalizationError(f"{label} traverses a symlink")
    resolved = supplied.resolve()
    try:
        resolved.relative_to(run_dir)
    except ValueError as exc:
        raise GeminiTraceNormalizationError(f"{label} escapes the Gemini run") from exc
    if not resolved.is_file():
        if required:
            raise GeminiTraceNormalizationError(f"{label} is missing: {resolved}")
        return None
    return resolved


def _jsonl(path: Path, label: str) -> list[tuple[int, Mapping[str, Any]]]:
    records: list[tuple[int, Mapping[str, Any]]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise GeminiTraceNormalizationError(f"cannot read {label}: {exc}") from exc
    for line_number, raw in enumerate(lines, 1):
        if not raw.strip():
            raise GeminiTraceNormalizationError(
                f"{label} line {line_number} is unexpectedly empty"
            )
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GeminiTraceNormalizationError(
                f"{label} line {line_number} is malformed JSON"
            ) from exc
        records.append((line_number, _mapping(decoded, f"{label} line {line_number}")))
    return records


def _source(path: Path, line: int, raw_type: str, run_dir: Path) -> dict[str, Any]:
    return {
        "trace_path": path.relative_to(run_dir).as_posix(),
        "line": line,
        "raw_event_type": raw_type,
    }


def _base_candidate(
    *,
    timestamp: Any,
    source_path: Path,
    source_line: int,
    raw_type: str,
    run_dir: Path,
    source_rank: int,
    event_type: str,
    attributes: Mapping[str, Any],
    session_id: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    normalized, parsed = _timestamp(timestamp)
    value: dict[str, Any] = {
        "_sort": (parsed, source_rank, source_line),
        "event_type": event_type,
        "timestamp": normalized,
        "source": _source(source_path, source_line, raw_type, run_dir),
        "attributes": dict(attributes),
    }
    if session_id is not None:
        if not isinstance(session_id, str) or not session_id.strip():
            raise GeminiTraceNormalizationError("Gemini session_id must be non-empty")
        value["session_id"] = session_id
    value.update(extra)
    return value


def _normalized_artifact_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        return None
    if path.parts and path.parts[0] == "workspace":
        path = Path(*path.parts[1:])
    return path.as_posix() if path.parts else None


def _memory_by_path(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for raw in manifest.get("memory_bindings", []):
        memory = _mapping(raw, "memory binding")
        path = _normalized_artifact_path(memory.get("path"))
        if path is None or path in result:
            raise GeminiTraceNormalizationError("Gemini memory binding paths must be unique")
        result[path] = memory
    return result


def _agents_by_path(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    workspace = Path(str(manifest["workspace_dir"])).resolve()
    result: dict[str, Mapping[str, Any]] = {}
    for raw in manifest.get("agents", []):
        agent = _mapping(raw, "Gemini agent")
        target = agent.get("target")
        if not isinstance(target, str) or not target:
            raise GeminiTraceNormalizationError("Gemini agent target is missing")
        try:
            relative = Path(target).resolve().relative_to(workspace).as_posix()
        except ValueError as exc:
            raise GeminiTraceNormalizationError("Gemini agent target escapes workspace") from exc
        if relative in result:
            raise GeminiTraceNormalizationError("Gemini agent targets must be unique")
        result[relative] = agent
    return result


def _memory_payload(memory: Mapping[str, Any], digest: str) -> dict[str, str]:
    return {
        "store": str(memory["store"]),
        "scope": str(memory["scope"]),
        "entry_id": str(memory["entry_id"]),
        "sha256": digest,
    }


def _verified_skill(
    raw: Mapping[str, Any], manifest: Mapping[str, Any]
) -> tuple[str, str]:
    name = raw.get("skill_name")
    digest = _sha256(raw.get("sha256"), "skill event")
    skills = _mapping(manifest.get("skills"), "materialized skills")
    record = _mapping(skills.get(name), f"materialized skill {name!r}")
    if record.get("sha256") != digest:
        raise GeminiTraceNormalizationError(
            f"skill activation hash does not match materialization: {name!r}"
        )
    return str(name), digest


def _verified_skill_file_read(
    artifact_path: str,
    digest: str,
    manifest: Mapping[str, Any],
    *,
    prior_writes: Mapping[str, tuple[str, str, int, int]],
) -> tuple[str, str] | None:
    parts = artifact_path.split("/")
    if len(parts) != 4 or parts[:2] != [".gemini", "skills"] or parts[3] != "SKILL.md":
        return None
    name = parts[2]
    skills = _mapping(manifest.get("skills"), "materialized skills")
    record = skills.get(name)
    if record is not None:
        record = _mapping(record, f"materialized skill {name!r}")
        if record.get("sha256") == digest:
            return name, digest
    prior = prior_writes.get(artifact_path)
    if prior is not None and prior[0] == digest:
        return name, digest
    if record is not None:
        raise GeminiTraceNormalizationError(
            f"skill file read hash does not match materialization: {name!r}"
        )
    return None


def _instruction_file_read_attributes(
    artifact_path: str,
    digest: str,
    *,
    instructions: Mapping[str | None, str],
    generated_instruction_paths: set[str],
    prior_writes: Mapping[str, tuple[str, str, int, int]],
) -> dict[str, Any] | None:
    expected = instructions.get(artifact_path)
    if expected == digest:
        return {
            "path": artifact_path,
            "sha256": digest,
            "activation_via": "instruction_file_read",
        }
    prior = prior_writes.get(artifact_path)
    if (
        artifact_path in generated_instruction_paths
        and prior is not None
        and prior[0] == digest
    ):
        return {
            "path": artifact_path,
            "sha256": digest,
            "producer_trace_path": prior[1],
            "producer_line": prior[2],
            "producer_stage_index": prior[3],
            "activation_via": "generated_instruction_file_read",
        }
    return None


def _historical_writes(
    *, manifest: Mapping[str, Any], stage_index: int, run_dir: Path
) -> dict[str, tuple[str, str, int, int]]:
    writes: dict[str, tuple[str, str, int, int]] = {}
    for prior in manifest["stages"]:
        if prior["index"] >= stage_index:
            continue
        path = _run_file(
            Path(prior["hook_trace_path"]),
            run_dir,
            f"prior hook trace stage {prior['index']}",
            required=False,
        )
        if path is None:
            continue
        for line, raw in _jsonl(path, "prior Gemini hook trace"):
            if raw.get("kind") != "file_artifact" or raw.get("operation") != "write":
                continue
            artifact_path = _normalized_artifact_path(raw.get("path"))
            if artifact_path is None:
                continue
            writes[artifact_path] = (
                _sha256(raw.get("sha256"), "prior artifact"),
                path.relative_to(run_dir).as_posix(),
                line,
                prior["index"],
            )
    return writes


def _stream_candidates(
    *, path: Path, run_dir: Path, requested_model: Any, session_action: str = ""
) -> list[dict[str, Any]]:
    if not isinstance(requested_model, str) or not requested_model.strip():
        raise GeminiTraceNormalizationError(
            "Gemini trace has no explicit requested-model pin"
        )
    candidates: list[dict[str, Any]] = []
    init_count = 0
    result_count = 0
    session_id: str | None = None
    compress_requested = False
    assistant_summary_parts: list[str] = []
    for line, raw in _jsonl(path, "Gemini stream trace"):
        raw_type = raw.get("type")
        if raw_type == "init":
            init_count += 1
            if init_count != 1:
                raise GeminiTraceNormalizationError(
                    "Gemini stream trace contains multiple init events"
                )
            observed_session_id = raw.get("session_id")
            if not isinstance(observed_session_id, str) or not observed_session_id:
                raise GeminiTraceNormalizationError("Gemini init event lacks session_id")
            session_id = observed_session_id
            observed_model = raw.get("model")
            if observed_model != requested_model:
                raise GeminiTraceNormalizationError(
                    "Gemini init model does not match the explicit model pin"
                )
            attributes: dict[str, Any] = {}
            attributes["model_sha256"] = hashlib.sha256(
                requested_model.encode("utf-8")
            ).hexdigest()
            candidates.append(
                _base_candidate(
                    timestamp=raw.get("timestamp"),
                    source_path=path,
                    source_line=line,
                    raw_type="init",
                    run_dir=run_dir,
                    source_rank=0,
                    event_type="session.started",
                    attributes=attributes,
                    session_id=observed_session_id,
                )
            )
        elif raw_type == "error":
            raise GeminiTraceNormalizationError(
                "Gemini stream trace contains a runtime error; trial is NOT_RUN"
            )
        elif raw_type == "result":
            result_count += 1
            if result_count != 1:
                raise GeminiTraceNormalizationError(
                    "Gemini stream trace contains multiple result events"
                )
            if raw.get("status") != "success":
                raise GeminiTraceNormalizationError(
                    "Gemini result status is not success; trial is NOT_RUN"
                )
            stats = _mapping(raw.get("stats"), "Gemini result stats")
            models = _mapping(stats.get("models"), "Gemini result model usage")
            observed_models: set[str] = set()
            for model, usage in models.items():
                usage_mapping = _mapping(usage, "Gemini result model usage item")
                if any(
                    isinstance(usage_mapping.get(key), int) and usage_mapping[key] > 0
                    for key in ("total_tokens", "input_tokens", "output_tokens", "input")
                ):
                    observed_models.add(model)
            if observed_models != {requested_model}:
                raise GeminiTraceNormalizationError(
                    "Gemini provider model usage does not match the explicit model pin; "
                    "trial is NOT_RUN"
                )
            if (
                session_action == "compact"
                and assistant_summary_parts
                and session_id is not None
            ):
                input_tokens = stats.get("input_tokens", stats.get("input"))
                output_tokens = stats.get("output_tokens")
                if not isinstance(input_tokens, int) or not isinstance(output_tokens, int):
                    raise GeminiTraceNormalizationError(
                        "Gemini compaction result lacks token usage"
                    )
                if input_tokens <= output_tokens:
                    raise GeminiTraceNormalizationError(
                        "Gemini compaction stream does not show token reduction"
                    )
                summary = "".join(assistant_summary_parts)
                candidates.append(
                    _base_candidate(
                        timestamp=raw.get("timestamp"),
                        source_path=path,
                        source_line=line,
                        raw_type="stream.compress_summary",
                        run_dir=run_dir,
                        source_rank=1,
                        event_type="session.compacted",
                        attributes={
                            "trigger": (
                                "manual_slash_command"
                                if compress_requested
                                else "adapter_session_action"
                            ),
                            "session_action": "compact",
                            "pre_tokens": input_tokens,
                            "post_tokens": output_tokens,
                            "summary_sha256": hashlib.sha256(
                                summary.encode("utf-8")
                            ).hexdigest(),
                        },
                        session_id=session_id,
                    )
                )
        elif raw_type in {"message", "tool_use", "tool_result"}:
            if raw_type == "message":
                role = raw.get("role")
                content = raw.get("content")
                if role == "user" and isinstance(content, str):
                    compress_requested = content.lstrip().startswith("/compress")
                elif (
                    session_action == "compact"
                    and role == "assistant"
                    and isinstance(content, str)
                ):
                    assistant_summary_parts.append(content)
            # Content-bearing stream records remain raw provenance. Tool calls
            # are normalized only from the correlated hook/proxy evidence below.
            continue
        else:
            raise GeminiTraceNormalizationError(
                f"unknown Gemini stream event type at line {line}: {raw_type!r}"
            )
    if init_count != 1:
        raise GeminiTraceNormalizationError("Gemini stream trace contains no init event")
    if result_count != 1:
        raise GeminiTraceNormalizationError(
            "Gemini stream trace has no successful terminal result; trial is NOT_RUN"
        )
    return candidates


def _hook_candidates(
    *,
    path: Path,
    run_dir: Path,
    manifest: Mapping[str, Any],
    stage_index: int,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    memory_paths = _memory_by_path(manifest)
    agent_paths = _agents_by_path(manifest)
    instructions = {
        _normalized_artifact_path(record["path"]): record["sha256"]
        for record in manifest.get("instructions", [])
    }
    generated_instruction_paths = {
        normalized
        for normalized in (
            _normalized_artifact_path(record.get("path"))
            for record in manifest.get("generated_instructions", [])
            if isinstance(record, Mapping)
        )
        if normalized is not None
    }
    handoff_paths = {
        normalized
        for normalized in (
            _normalized_artifact_path(value)
            for key, value in manifest.get("artifact_bindings", {}).items()
            if key == "handoff"
        )
        if normalized is not None
    }
    prior_writes = _historical_writes(
        manifest=manifest, stage_index=stage_index, run_dir=run_dir
    )
    handoff_emitted: set[tuple[str, str]] = set()
    instruction_emitted: set[tuple[str, str]] = set()
    skill_emitted: set[tuple[str, str]] = set()
    active_agent_id: str | None = None
    completed_agents: set[str] = set()
    for line, raw in _jsonl(path, "Gemini hook trace"):
        kind = raw.get("kind")
        session_id = raw.get("session_id")
        if kind == "session_start":
            source = raw.get("source")
            if source == "resume":
                candidates.append(
                    _base_candidate(
                        timestamp=raw.get("timestamp"),
                        source_path=path,
                        source_line=line,
                        raw_type="SessionStart.resume",
                        run_dir=run_dir,
                        source_rank=1,
                        event_type="session.resumed",
                        attributes={"source": "resume"},
                        session_id=session_id,
                    )
                )
            elif source not in {"startup", "clear"}:
                raise GeminiTraceNormalizationError(
                    f"unknown Gemini SessionStart source: {source!r}"
                )
            continue
        if kind == "pre_compress":
            continue
        if kind == "instruction_loaded":
            artifact_path = _normalized_artifact_path(raw.get("path"))
            digest = _sha256(raw.get("sha256"), "instruction hook")
            expected = instructions.get(artifact_path)
            prior = prior_writes.get(artifact_path) if artifact_path is not None else None
            if expected == digest:
                instruction_attributes: dict[str, Any] = {
                    "path": artifact_path,
                    "sha256": digest,
                }
            elif (
                artifact_path in generated_instruction_paths
                and prior is not None
                and prior[0] == digest
            ):
                instruction_attributes = {
                    "path": artifact_path,
                    "sha256": digest,
                    "producer_trace_path": prior[1],
                    "producer_line": prior[2],
                    "producer_stage_index": prior[3],
                    "activation_via": "generated_project_instruction",
                }
            else:
                raise GeminiTraceNormalizationError(
                    "instruction hook does not match a materialized Gemini instruction"
                )
            key = (str(artifact_path), digest)
            if key in instruction_emitted:
                continue
            instruction_emitted.add(key)
            candidates.append(
                _base_candidate(
                    timestamp=raw.get("timestamp"),
                    source_path=path,
                    source_line=line,
                    raw_type="BeforeModel.instruction_loaded",
                    run_dir=run_dir,
                    source_rank=1,
                    event_type="instruction.loaded",
                    attributes=instruction_attributes,
                    session_id=session_id,
                )
            )
            continue
        if kind == "skill_activated":
            name, digest = _verified_skill(raw, manifest)
            key = (name, digest)
            if key in skill_emitted:
                continue
            skill_emitted.add(key)
            for event_type in ("skill.discovered", "skill.activated"):
                candidates.append(
                    _base_candidate(
                        timestamp=raw.get("timestamp"),
                        source_path=path,
                        source_line=line,
                        raw_type="AfterTool.activate_skill",
                        run_dir=run_dir,
                        source_rank=1,
                        event_type=event_type,
                        attributes={"skill_name": name, "skill_sha256": digest},
                        session_id=session_id,
                    )
                )
            continue
        if kind in {"memory_written", "memory_retrieved"}:
            artifact_path = _normalized_artifact_path(raw.get("path"))
            memory = memory_paths.get(artifact_path)
            if memory is None:
                raise GeminiTraceNormalizationError(
                    "memory hook path is not declared by the Gemini binding"
                )
            digest = _sha256(raw.get("sha256"), "memory hook")
            candidates.append(
                _base_candidate(
                    timestamp=raw.get("timestamp"),
                    source_path=path,
                    source_line=line,
                    raw_type=f"hook.{kind}",
                    run_dir=run_dir,
                    source_rank=1,
                    event_type=(
                        "memory.written" if kind == "memory_written" else "memory.retrieved"
                    ),
                    attributes={"path": artifact_path},
                    session_id=session_id,
                    memory=_memory_payload(memory, digest),
                )
            )
            continue
        if kind == "file_artifact":
            operation = raw.get("operation")
            if operation not in {"read", "write"}:
                raise GeminiTraceNormalizationError("file hook operation must be read/write")
            artifact_path = _normalized_artifact_path(raw.get("path"))
            if artifact_path is None:
                raise GeminiTraceNormalizationError("file hook path is not workspace-relative")
            digest = _sha256(raw.get("sha256"), "file hook")
            artifact = {
                "path": artifact_path,
                "sha256": digest,
                "operation": operation,
            }
            if operation == "read" and artifact_path in handoff_paths:
                prior = prior_writes.get(artifact_path)
                if prior is not None and prior[0] == digest:
                    handoff_key = (artifact_path, digest)
                    if handoff_key not in handoff_emitted:
                        handoff_emitted.add(handoff_key)
                        candidates.append(
                            _base_candidate(
                                timestamp=raw.get("timestamp"),
                                source_path=path,
                                source_line=line,
                                raw_type="AfterTool.artifact_handoff",
                                run_dir=run_dir,
                                source_rank=1,
                                event_type="artifact.handoff",
                                attributes={
                                    "producer_trace_path": prior[1],
                                    "producer_line": prior[2],
                                    "producer_stage_index": prior[3],
                                },
                                session_id=session_id,
                                artifact={**artifact, "operation": "handoff"},
                            )
                        )
            candidates.append(
                _base_candidate(
                    timestamp=raw.get("timestamp"),
                    source_path=path,
                    source_line=line,
                    raw_type=f"AfterTool.file_{operation}",
                    run_dir=run_dir,
                    source_rank=1,
                    event_type=f"file.{operation}",
                    attributes={
                        "tool_name": raw.get("tool_name", ""),
                        "arguments_sha256": _sha256(
                            raw.get("arguments_sha256"), "file tool arguments"
                        ),
                    },
                    session_id=session_id,
                    artifact=artifact,
                )
            )
            if operation == "read" and artifact_path in agent_paths:
                agent = agent_paths[artifact_path]
                name = str(agent.get("name") or "")
                if not name:
                    raise GeminiTraceNormalizationError("Gemini agent name is missing")
                if agent.get("sha256") != digest:
                    raise GeminiTraceNormalizationError(
                        f"Gemini agent definition hash mismatch: {name!r}"
                    )
                active_agent_id = name
                candidates.append(
                    _base_candidate(
                        timestamp=raw.get("timestamp"),
                        source_path=path,
                        source_line=line,
                        raw_type="AfterTool.agent_definition_read",
                        run_dir=run_dir,
                        source_rank=1,
                        event_type="agent.spawned",
                        attributes={
                            "agent_name": name,
                            "agent_sha256": digest,
                            "path": artifact_path,
                            "activation_via": "agent_definition_file_read",
                        },
                        session_id=session_id,
                        agent_id=name,
                        parent_agent_id=f"{session_id}:main" if session_id else "gemini-main",
                    )
                )
            if (
                operation == "write"
                and artifact_path in handoff_paths
                and active_agent_id is not None
                and active_agent_id not in completed_agents
            ):
                completed_agents.add(active_agent_id)
                candidates.append(
                    _base_candidate(
                        timestamp=raw.get("timestamp"),
                        source_path=path,
                        source_line=line,
                        raw_type="AfterTool.agent_handoff_write",
                        run_dir=run_dir,
                        source_rank=1,
                        event_type="agent.completed",
                        attributes={
                            "agent_name": active_agent_id,
                            "handoff_path": artifact_path,
                            "handoff_sha256": digest,
                            "completion_via": "handoff_file_write",
                        },
                        session_id=session_id,
                        agent_id=active_agent_id,
                    )
                )
            memory = memory_paths.get(artifact_path)
            if memory is not None:
                candidates.append(
                    _base_candidate(
                        timestamp=raw.get("timestamp"),
                        source_path=path,
                        source_line=line,
                        raw_type=f"AfterTool.memory_file_{operation}",
                        run_dir=run_dir,
                        source_rank=1,
                        event_type=(
                            "memory.written" if operation == "write" else "memory.retrieved"
                        ),
                        attributes={"path": artifact_path, "via": "file_tool"},
                        session_id=session_id,
                        memory=_memory_payload(memory, digest),
                    )
                )
            if operation == "read":
                instruction_attributes = _instruction_file_read_attributes(
                    artifact_path,
                    digest,
                    instructions=instructions,
                    generated_instruction_paths=generated_instruction_paths,
                    prior_writes=prior_writes,
                )
                if instruction_attributes is not None:
                    instruction_key = (artifact_path, digest)
                    if instruction_key not in instruction_emitted:
                        instruction_emitted.add(instruction_key)
                        candidates.append(
                            _base_candidate(
                                timestamp=raw.get("timestamp"),
                                source_path=path,
                                source_line=line,
                                raw_type="AfterTool.instruction_file_read",
                                run_dir=run_dir,
                                source_rank=1,
                                event_type="instruction.loaded",
                                attributes=instruction_attributes,
                                session_id=session_id,
                            )
                        )
                skill = _verified_skill_file_read(
                    artifact_path,
                    digest,
                    manifest,
                    prior_writes=prior_writes,
                )
                if skill is not None:
                    name, skill_digest = skill
                    key = (name, skill_digest)
                    if key not in skill_emitted:
                        skill_emitted.add(key)
                        for event_type in ("skill.discovered", "skill.activated"):
                            candidates.append(
                                _base_candidate(
                                    timestamp=raw.get("timestamp"),
                                    source_path=path,
                                    source_line=line,
                                    raw_type="AfterTool.skill_file_read",
                                    run_dir=run_dir,
                                    source_rank=1,
                                    event_type=event_type,
                                    attributes={
                                        "skill_name": name,
                                        "skill_sha256": skill_digest,
                                        "path": artifact_path,
                                        "activation_via": "skill_file_read",
                                    },
                                    session_id=session_id,
                                )
                            )
            continue
        raise GeminiTraceNormalizationError(f"unknown Gemini hook record kind: {kind!r}")
    return candidates


def _mcp_candidates(*, path: Path, run_dir: Path) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    requests: dict[tuple[str, str], str] = {}
    initialized: set[str] = set()
    for line, raw in _jsonl(path, "Gemini MCP proxy trace"):
        kind = raw.get("kind")
        server = raw.get("server")
        call_id = raw.get("call_id")
        if not isinstance(server, str) or not server:
            raise GeminiTraceNormalizationError("MCP proxy record lacks server")
        if not isinstance(call_id, str) or not call_id:
            raise GeminiTraceNormalizationError("MCP proxy record lacks call_id")
        if kind == "mcp_server_initialized":
            status = raw.get("status")
            if status not in {"connected", "failed"}:
                raise GeminiTraceNormalizationError("MCP init status is invalid")
            initialized.add(server)
            candidates.append(
                _base_candidate(
                    timestamp=raw.get("timestamp"),
                    source_path=path,
                    source_line=line,
                    raw_type="mcp.initialize.response",
                    run_dir=run_dir,
                    source_rank=2,
                    event_type="mcp.server_initialized",
                    attributes={
                        "status": status,
                        "response_sha256": _sha256(
                            raw.get("response_sha256"), "MCP init response"
                        ),
                    },
                    tool={"server": server},
                )
            )
        elif kind == "mcp_tool_requested":
            tool_name = raw.get("tool_name")
            if not isinstance(tool_name, str) or not tool_name:
                raise GeminiTraceNormalizationError("MCP request lacks tool_name")
            key = (server, call_id)
            if key in requests:
                raise GeminiTraceNormalizationError("duplicate MCP call_id")
            requests[key] = tool_name
            candidates.append(
                _base_candidate(
                    timestamp=raw.get("timestamp"),
                    source_path=path,
                    source_line=line,
                    raw_type="mcp.tools.call.request",
                    run_dir=run_dir,
                    source_rank=2,
                    event_type="mcp.tool_requested",
                    attributes={
                        "request_sha256": _sha256(
                            raw.get("request_sha256"), "MCP request"
                        )
                    },
                    tool={
                        "server": server,
                        "name": tool_name,
                        "call_id": call_id,
                        "arguments_sha256": _sha256(
                            raw.get("arguments_sha256"), "MCP arguments"
                        ),
                    },
                )
            )
        elif kind == "mcp_tool_result":
            tool_name = raw.get("tool_name")
            key = (server, call_id)
            if requests.get(key) != tool_name:
                raise GeminiTraceNormalizationError(
                    "MCP result has no prior correlated request"
                )
            status = raw.get("status")
            if status not in {"success", "error"}:
                raise GeminiTraceNormalizationError("MCP tool status is invalid")
            candidates.append(
                _base_candidate(
                    timestamp=raw.get("timestamp"),
                    source_path=path,
                    source_line=line,
                    raw_type="mcp.tools.call.response",
                    run_dir=run_dir,
                    source_rank=2,
                    event_type="mcp.tool_result",
                    attributes={
                        "response_sha256": _sha256(
                            raw.get("response_sha256"), "MCP response"
                        )
                    },
                    tool={
                        "server": server,
                        "name": tool_name,
                        "call_id": call_id,
                        "result_sha256": _sha256(
                            raw.get("result_sha256"), "MCP result"
                        ),
                        "status": status,
                    },
                )
            )
        else:
            raise GeminiTraceNormalizationError(f"unknown MCP proxy record kind: {kind!r}")
    return candidates


def _event_id(run_id: str, stage_index: int, sequence: int) -> str:
    digest = hashlib.sha256(
        f"{run_id}:{stage_index}:{sequence}".encode("utf-8")
    ).hexdigest()[:24]
    return f"gemini:{stage_index}:{sequence}:{digest}"


def normalize_gemini_trace(
    *,
    identity: HarnessIdentity,
    materialized: MaterializedBinding,
    manifest: Mapping[str, Any],
    binding_document: Mapping[str, Any],
    raw_trace_path: Path,
    stage_index: int,
) -> Iterable[Mapping[str, Any]]:
    if identity.harness_id != "gemini" or materialized.harness_id != "gemini":
        raise GeminiTraceNormalizationError("Gemini normalizer received another harness")
    run_dir = materialized.run_dir.resolve()
    current_stage = _stage(manifest, stage_index)
    expected_raw = Path(current_stage["trace_path"]).resolve()
    supplied_raw = Path(raw_trace_path).resolve()
    if supplied_raw != expected_raw:
        raise GeminiTraceNormalizationError(
            "raw_trace_path does not match the materialized Gemini stage"
        )
    candidates: list[dict[str, Any]] = []
    included_stages = sorted(
        (item for item in manifest["stages"] if item["index"] <= stage_index),
        key=lambda item: item["index"],
    )
    for stage in included_stages:
        stream_path = _run_file(
            Path(stage["trace_path"]),
            run_dir,
            f"Gemini stream trace stage {stage['index']}",
            required=True,
        )
        assert stream_path is not None
        hook_path = _run_file(
            Path(stage["hook_trace_path"]),
            run_dir,
            f"Gemini hook trace stage {stage['index']}",
            required=False,
        )
        mcp_path = _run_file(
            Path(stage["mcp_trace_path"]),
            run_dir,
            f"Gemini MCP proxy trace stage {stage['index']}",
            required=False,
        )
        stage_candidates = _stream_candidates(
            path=stream_path,
            run_dir=run_dir,
            requested_model=manifest.get("requested_model"),
            session_action=str(stage.get("session_action") or ""),
        )
        if hook_path is not None:
            stage_candidates.extend(
                _hook_candidates(
                    path=hook_path,
                    run_dir=run_dir,
                    manifest=manifest,
                    stage_index=stage["index"],
                )
            )
        if mcp_path is not None:
            stage_candidates.extend(_mcp_candidates(path=mcp_path, run_dir=run_dir))
        for candidate in stage_candidates:
            candidate["_stage"] = {"name": stage["name"], "index": stage["index"]}
        candidates.extend(stage_candidates)
    candidates.sort(key=lambda item: item.pop("_sort"))

    events: list[dict[str, Any]] = []
    run_id = str(manifest["run_id"])
    for sequence, candidate in enumerate(candidates):
        event_stage = candidate.pop("_stage")
        event = {
            "schema_name": "safety_bench_cross_harness_event",
            "schema_version": 1,
            "event_id": _event_id(run_id, event_stage["index"], sequence),
            "event_type": candidate.pop("event_type"),
            "run_id": run_id,
            "case_id": materialized.case_id,
            "harness": {
                "id": "gemini",
                "version": identity.version,
                "feature_flags": dict(identity.feature_flags),
            },
            "stage": event_stage,
            "sequence": sequence,
            **candidate,
        }
        validate_event_document(event)
        events.append(event)

    final_stage_index = max(item["index"] for item in manifest["stages"])
    if stage_index != final_stage_index:
        return events
    expected = set(
        binding_document["harness_native_binding"]["gemini"]["expected_event_types"]
    )
    observed = {event["event_type"] for event in events} | _prior_stage_event_types(
        manifest=manifest,
        stage_index=stage_index,
    )
    missing = sorted(expected - observed)
    if missing:
        if "session.compacted" in missing:
            missing.append(
                "PreCompress is advisory and cannot prove post-token reduction/summary hash"
            )
        raise GeminiTraceNormalizationError(
            "required Gemini normalized events are missing; trial is not scoreable: "
            + ", ".join(missing)
        )
    return events


__all__ = ["GeminiTraceNormalizationError", "normalize_gemini_trace"]
