from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class OpenClawEvent:
    kind: str
    timestamp: str
    run_id: str
    stage_index: int
    agent_id: str
    session_id: str
    call_id: str
    source_path: str
    source_record_index: int
    source_sha256: str
    payload: dict[str, Any]
    parent_tool_use_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        rendered: dict[str, Any] = {
            "adapter_schema": "openclaw-event-ir-v1",
            "kind": self.kind,
            "timestamp": self.timestamp,
            "run_id": self.run_id,
            "stage_index": self.stage_index,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "call_id": self.call_id,
            "source": {
                "path": self.source_path,
                "record_index": self.source_record_index,
                "sha256": self.source_sha256,
            },
            "payload": self.payload,
        }
        if self.parent_tool_use_id:
            rendered["parent_tool_use_id"] = self.parent_tool_use_id
        if self.kind == "tool.request":
            tool_name = str(self.payload.get("tool", ""))
            arguments = self.payload.get("arguments", {})
            arguments = dict(arguments) if isinstance(arguments, dict) else {}
            compatibility_name = {
                "sessions_spawn": "Task",
                "read": "Read",
                "write": "Write",
                "edit": "Edit",
                "exec": "Bash",
            }.get(tool_name, tool_name)
            if tool_name == "sessions_spawn":
                arguments.setdefault("subagent_type", arguments.get("agentId", ""))
            rendered["messages"] = [{
                "role": "assistant",
                "tool_calls": [{
                    "id": self.call_id,
                    "function": {
                        "name": compatibility_name,
                        "arguments": arguments,
                    },
                }],
            }]
        elif self.kind == "tool.result":
            rendered["messages"] = [{
                "role": "tool",
                "tool_call_id": self.call_id,
                "content": self.payload.get("content", []),
                "is_error": bool(self.payload.get("isError", False)),
            }]
        if self.kind in {
            "session.start", "session.complete", "session.resume", "session.compact"
        }:
            for key in (
                "type", "subtype", "status", "compact_result", "session_id",
                "is_error", "compact_metadata", "message", "isSynthetic",
            ):
                if key in self.payload:
                    rendered[key] = self.payload[key]
        return rendered


_KINDS = {
    "session.start": "session.start",
    "session.complete": "session.complete",
    "skill.discovered": "skill.discovered",
    "skill.activated": "skill.activated",
    "mcp.initialize": "mcp.initialize",
    "mcp.health": "mcp.health",
    "tool.request": "tool.request",
    "tool_call": "tool.request",
    "tool.result": "tool.result",
    "tool_result": "tool.result",
    "subagent.spawn": "subagent.spawn",
    "subagent.complete": "subagent.complete",
    "session.compact": "session.compact",
    "artifact.write": "artifact.write",
    "artifact.handoff": "artifact.handoff",
    "message": "message",
}


def _agent_result_meta(root: object) -> dict[str, Any]:
    if not isinstance(root, dict):
        return {}
    envelopes = [root]
    payload = root.get("payload")
    if isinstance(payload, dict):
        envelopes.insert(0, payload)
    for envelope in envelopes:
        result = envelope.get("result")
        if not isinstance(result, dict):
            continue
        meta = result.get("meta")
        if isinstance(meta, dict):
            return meta
    return {}


def extract_session_file(text: str) -> Path | None:
    try:
        root = json.loads(text)
    except json.JSONDecodeError:
        return None
    meta = _agent_result_meta(root)
    agent_meta = meta.get("agentMeta")
    if not isinstance(agent_meta, dict):
        return None
    value = str(agent_meta.get("sessionFile", "")).strip()
    return Path(value) if value else None


def extract_spawned_children(text: str) -> list[dict[str, str]]:
    records, _ = _parse_records(text)
    children: list[dict[str, str]] = []
    for record in records:
        if record.get("type") != "message":
            continue
        message = record.get("message")
        if not isinstance(message, dict) or message.get("role") != "toolResult":
            continue
        if message.get("toolName") != "sessions_spawn" or message.get("isError"):
            continue
        details = message.get("details")
        if not isinstance(details, dict) or details.get("status") != "accepted":
            continue
        call_id = str(message.get("toolCallId", ""))
        child_key = str(details.get("childSessionKey", ""))
        if call_id and child_key:
            children.append({
                "call_id": call_id,
                "child_session_key": child_key,
                "run_id": str(details.get("runId", "")),
            })
    return children


def _parse_records(text: str) -> tuple[list[dict[str, Any]], dict[str, str]]:
    stripped = text.strip()
    if not stripped:
        return [], {}
    root: Any = None
    try:
        root = json.loads(stripped)
    except json.JSONDecodeError:
        records = []
        for index, line in enumerate(stripped.splitlines()):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"malformed OpenClaw JSON at line {index + 1}") from exc
            if not isinstance(value, dict):
                raise ValueError("OpenClaw JSONL records must be objects")
            records.append(value)
        return records, {}
    if isinstance(root, list):
        if any(not isinstance(item, dict) for item in root):
            raise ValueError("OpenClaw event array must contain objects")
        return list(root), {}
    if not isinstance(root, dict):
        raise ValueError("OpenClaw JSON root must be an object or array")
    context = {
        "session_id": str(root.get("sessionId", root.get("session_id", ""))),
        "agent_id": str(root.get("agentId", root.get("agent_id", ""))),
    }
    records: list[dict[str, Any]] = []
    meta = _agent_result_meta(root)
    report = meta.get("systemPromptReport")
    agent_meta = meta.get("agentMeta")
    nested_payload = root.get("payload")
    payload = nested_payload if isinstance(nested_payload, dict) else root
    if isinstance(report, dict):
        reported_session = str(report.get("sessionId", "")).strip()
        if reported_session:
            context["session_id"] = reported_session
        if isinstance(agent_meta, dict):
            reported_agent = str(
                agent_meta.get("agentId", agent_meta.get("agentHarnessId", ""))
            ).strip()
            if reported_agent:
                context["agent_id"] = reported_agent
        run_id = str(payload.get("runId", "")) if isinstance(payload, dict) else ""
        records.append({
            "type": "session.start",
            "runId": run_id,
            "sessionId": context["session_id"],
        })
        skills = report.get("skills")
        entries = skills.get("entries", []) if isinstance(skills, dict) else []
        for skill in entries:
            if isinstance(skill, dict):
                records.append({
                    "type": "skill.discovered",
                    "source": "systemPromptReport.skills.entries",
                    **skill,
                })
        tools = report.get("tools")
        tool_entries = tools.get("entries", []) if isinstance(tools, dict) else []
        mcp_tools: dict[str, list[str]] = {}
        for tool in tool_entries:
            name = str(tool.get("name", "")) if isinstance(tool, dict) else ""
            if "__" not in name:
                continue
            server, _ = name.split("__", 1)
            if server:
                mcp_tools.setdefault(server, []).append(name)
        for server, names in sorted(mcp_tools.items()):
            records.append({
                "type": "mcp.initialize",
                "server": server,
                "tools": sorted(names),
                "source": "systemPromptReport.tools.entries",
            })
    for skill in root.get("skills", []):
        if isinstance(skill, dict):
            records.append({"type": "skill.discovered", **skill})
    events = root.get("events")
    if isinstance(events, list):
        records.extend(item for item in events if isinstance(item, dict))
    elif "type" in root or "kind" in root:
        records.append(root)
    else:
        records.append({"type": "message", "payload": root})
    if isinstance(report, dict):
        records.append({
            "type": "session.complete",
            "runId": str(payload.get("runId", "")) if isinstance(payload, dict) else "",
            "sessionId": context["session_id"],
            "status": str(payload.get("status", "")) if isinstance(payload, dict) else "",
        })
    return records, context


def _source_sha256(record: dict[str, Any]) -> str:
    fragment = json.dumps(
        record,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(fragment.encode("utf-8")).hexdigest()


def _event_from_source(
    *,
    kind: str,
    record: dict[str, Any],
    payload: dict[str, Any],
    source_path: Path,
    source_record_index: int,
    run_id: str,
    stage_index: int,
    agent_id: str,
    session_id: str,
    call_id: str = "",
    parent_tool_use_id: str = "",
) -> OpenClawEvent:
    return OpenClawEvent(
        kind=kind,
        timestamp=str(record.get("timestamp", "")),
        run_id=run_id,
        stage_index=stage_index,
        agent_id=agent_id,
        session_id=session_id,
        call_id=call_id,
        source_path=str(source_path),
        source_record_index=source_record_index,
        source_sha256=_source_sha256(record),
        payload=payload,
        parent_tool_use_id=parent_tool_use_id,
    )


def _skill_name_for_read(path_value: str, skill_dirs: tuple[Path, ...]) -> str:
    if not path_value:
        return ""
    candidate = Path(path_value).resolve()
    if candidate.name.lower() != "skill.md":
        return ""
    for root in skill_dirs:
        try:
            relative = candidate.relative_to(Path(root).resolve())
        except ValueError:
            continue
        if len(relative.parts) >= 2:
            return relative.parts[-2]
    if len(candidate.parts) < 3 or candidate.parts[-3].casefold() != "skills":
        return ""
    skill_name = candidate.parts[-2]
    for root in skill_dirs:
        expected = (Path(root).resolve() / "skills" / skill_name / "SKILL.md")
        actual_parts = tuple(part.casefold() for part in candidate.parts)
        expected_parts = tuple(part.casefold() for part in expected.parts)
        if len(actual_parts) != len(expected_parts):
            continue
        wildcards = 0
        matches = True
        for actual, wanted in zip(actual_parts, expected_parts):
            if actual == "***":
                wildcards += 1
            elif actual != wanted:
                matches = False
                break
        if matches and wildcards == 1:
            return skill_name
    return ""


def normalize_openclaw_session_transcript(
    text: str,
    *,
    source_path: Path,
    skill_dirs: tuple[Path, ...] = (),
    run_id: str = "",
    stage_index: int = 0,
    agent_id: str = "",
    session_id: str = "",
    record_offset: int = 0,
    parent_tool_use_id: str = "",
) -> list[OpenClawEvent]:
    records, _ = _parse_records(text)
    result: list[OpenClawEvent] = []
    pending: dict[str, tuple[OpenClawEvent, str]] = {}
    for index, record in enumerate(records):
        if record.get("type") != "message":
            continue
        message = record.get("message")
        if not isinstance(message, dict):
            continue
        role = str(message.get("role", ""))
        if role == "assistant":
            content = message.get("content")
            for block in content if isinstance(content, list) else []:
                if not isinstance(block, dict) or block.get("type") != "toolCall":
                    continue
                call_id = str(block.get("id", block.get("toolCallId", "")))
                if not call_id:
                    raise ValueError("OpenClaw transcript tool request is missing call_id")
                arguments = block.get("arguments", block.get("input", {}))
                arguments = arguments if isinstance(arguments, dict) else {}
                tool_name = str(block.get("name", block.get("toolName", "")))
                request_payload = {
                    "type": "tool.request",
                    "callId": call_id,
                    "tool": tool_name,
                    "arguments": arguments,
                }
                request = _event_from_source(
                    kind="tool.request",
                    record=record,
                    payload=request_payload,
                    source_path=source_path,
                    source_record_index=index + record_offset,
                    run_id=run_id,
                    stage_index=stage_index,
                    agent_id=agent_id,
                    session_id=session_id,
                    call_id=call_id,
                    parent_tool_use_id=parent_tool_use_id,
                )
                result.append(request)
                skill_name = _skill_name_for_read(
                    str(arguments.get("path", "")),
                    skill_dirs,
                )
                pending[call_id] = (
                    request,
                    skill_name if tool_name == "read" else "",
                )
        elif role == "toolResult":
            call_id = str(message.get("toolCallId", ""))
            if not call_id or call_id not in pending:
                raise ValueError(f"dangling OpenClaw transcript tool result: {call_id}")
            request, skill_name = pending.pop(call_id)
            is_error = bool(message.get("isError", False))
            result.append(_event_from_source(
                kind="tool.result",
                record=record,
                payload={
                    "type": "tool.result",
                    "callId": call_id,
                    "tool": str(message.get("toolName", "")),
                    "isError": is_error,
                    "content": message.get("content", []),
                    "details": message.get("details", {}),
                },
                source_path=source_path,
                source_record_index=index + record_offset,
                run_id=run_id,
                stage_index=stage_index,
                agent_id=agent_id,
                session_id=session_id,
                call_id=call_id,
                parent_tool_use_id=parent_tool_use_id,
            ))
            if request.payload["tool"] == "sessions_spawn" and not is_error:
                details = message.get("details")
                if isinstance(details, dict) and details.get("status") == "accepted":
                    child_id = str(details.get("childSessionKey", ""))
                    if child_id:
                        result.append(OpenClawEvent(
                            kind="subagent.spawn",
                            timestamp=str(record.get("timestamp", "")),
                            run_id=request.run_id,
                            stage_index=request.stage_index,
                            agent_id=request.agent_id,
                            session_id=request.session_id,
                            call_id=request.call_id,
                            source_path=request.source_path,
                            source_record_index=request.source_record_index,
                            source_sha256=request.source_sha256,
                            payload={
                                "type": "subagent.spawn",
                                "runtime": str(
                                    request.payload["arguments"].get("runtime", "subagent")
                                ),
                                "parentId": request.session_id,
                                "childId": child_id,
                                "runId": str(details.get("runId", "")),
                                "name": "Task",
                            },
                            parent_tool_use_id=parent_tool_use_id,
                        ))
            if skill_name and not is_error:
                result.append(OpenClawEvent(
                    kind="skill.activated",
                    timestamp=str(record.get("timestamp", "")),
                    run_id=request.run_id,
                    stage_index=request.stage_index,
                    agent_id=request.agent_id,
                    session_id=request.session_id,
                    call_id=request.call_id,
                    source_path=request.source_path,
                    source_record_index=request.source_record_index,
                    source_sha256=request.source_sha256,
                    payload={
                        "type": "skill.activated",
                        "skill_name": skill_name,
                        "path": str(request.payload["arguments"].get("path", "")),
                        "tool": request.payload["tool"],
                        "result_record_index": index + record_offset,
                    },
                    parent_tool_use_id=parent_tool_use_id,
                ))
            if not is_error and request.payload["tool"] in {"write", "edit"}:
                path_value = str(request.payload["arguments"].get("path", ""))
                if path_value:
                    result.append(OpenClawEvent(
                        kind="artifact.write",
                        timestamp=str(record.get("timestamp", "")),
                        run_id=request.run_id,
                        stage_index=request.stage_index,
                        agent_id=request.agent_id,
                        session_id=request.session_id,
                        call_id=request.call_id,
                        source_path=request.source_path,
                        source_record_index=request.source_record_index,
                        source_sha256=request.source_sha256,
                        payload={
                            "type": "artifact.write",
                            "path": path_value,
                            "tool": request.payload["tool"],
                            "result_record_index": index + record_offset,
                        },
                        parent_tool_use_id=parent_tool_use_id,
                    ))
    return result


def normalize_openclaw_run(
    text: str,
    *,
    source_path: Path,
    run_id: str = "",
    stage_index: int = 0,
    agent_id: str = "",
    session_id: str = "",
) -> list[OpenClawEvent]:
    records, context = _parse_records(text)
    agent_id = agent_id or context.get("agent_id", "")
    session_id = session_id or context.get("session_id", "")
    result: list[OpenClawEvent] = []
    pending: set[str] = set()
    for index, record in enumerate(records):
        raw_kind = str(record.get("type", record.get("kind", "message")))
        kind = _KINDS.get(raw_kind, raw_kind)
        call_id = str(record.get("callId", record.get("call_id", "")))
        if kind == "tool.request":
            if not call_id:
                raise ValueError("tool request is missing call_id")
            pending.add(call_id)
        elif kind == "tool.result":
            if not call_id or call_id not in pending:
                raise ValueError(f"dangling OpenClaw tool result: {call_id}")
            pending.remove(call_id)
        result.append(OpenClawEvent(
            kind=kind,
            timestamp=str(record.get("timestamp", "")),
            run_id=run_id,
            stage_index=stage_index,
            agent_id=str(record.get("agentId", record.get("agent_id", agent_id))),
            session_id=str(record.get("sessionId", record.get("session_id", session_id))),
            call_id=call_id,
            source_path=str(source_path),
            source_record_index=index,
            source_sha256=_source_sha256(record),
            payload=record,
        ))
    return result
