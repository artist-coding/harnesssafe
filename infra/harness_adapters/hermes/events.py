from __future__ import annotations

import json
import hashlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


@dataclass(frozen=True)
class EventProvenance:
    stage_name: str
    stage_index: int
    source_path: Path
    harness: str = "hermes"


@dataclass(frozen=True)
class EventIR:
    kind: str
    stage_name: str
    stage_index: int
    source_path: str
    harness: str
    session_id: str = ""
    physical_session_id: str = ""
    call_id: str = ""
    tool_name: str = ""
    parent_tool_use_id: str = ""
    message: Mapping[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "event_ir_version": "1.0",
            "kind": self.kind,
            "harness": self.harness,
            "stage_name": self.stage_name,
            "stage_index": self.stage_index,
            "source_path": self.source_path,
        }
        if self.session_id:
            payload["session_id"] = self.session_id
        if self.physical_session_id:
            payload["physical_session_id"] = self.physical_session_id
        if self.call_id:
            payload["call_id"] = self.call_id
        if self.tool_name:
            payload["tool_name"] = self.tool_name
        if self.parent_tool_use_id:
            payload["parent_tool_use_id"] = self.parent_tool_use_id
        if self.message is not None:
            payload["messages"] = [dict(self.message)]
        if self.kind == "session.start":
            payload.update({"type": "system", "subtype": "init"})
        elif self.kind == "session.complete":
            payload.update(
                {"type": "result", "subtype": "success", "is_error": False}
            )
        return payload


@dataclass(frozen=True)
class SessionLineageEvidence:
    seed_session_id: str
    requested_session_id: str
    resumed_session_id: str
    chain: tuple[str, ...]


@dataclass(frozen=True)
class LineageValidation:
    valid: bool
    reason: str = ""


@dataclass(frozen=True)
class CompressionEvidence:
    parent_session_id: str
    compacted_session_id: str
    resumed_session_id: str
    before_message_count: int
    after_message_count: int
    summary_sha256: str


@dataclass(frozen=True)
class DelegationEvidence:
    parent_id: str
    child_id: str
    child_trace_sha256: str
    producer_artifact_sha256: str = ""
    consumer_artifact_sha256: str = ""


def read_session_snapshot(
    state_db_path: Path,
    *,
    session_id: str = "",
    parent_session_id: str = "",
) -> dict[str, object]:
    """Export one canonical Hermes state.db session in snapshot JSON shape."""
    connection = sqlite3.connect(f"file:{state_db_path.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        if session_id:
            session = connection.execute(
                "SELECT id, model FROM sessions WHERE id = ?", (session_id,)
            ).fetchone()
        elif parent_session_id:
            session = connection.execute(
                "SELECT id, model FROM sessions WHERE parent_session_id = ? "
                "ORDER BY started_at DESC, id DESC LIMIT 1",
                (parent_session_id,),
            ).fetchone()
        else:
            session = connection.execute(
                "SELECT id, model FROM sessions WHERE parent_session_id IS NULL "
                "ORDER BY started_at DESC, id DESC LIMIT 1"
            ).fetchone()
        if session is None:
            raise ValueError("Hermes state.db has no matching session")

        message_columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(messages)").fetchall()
        }
        projected = [
            name
            for name in (
                "role",
                "content",
                "tool_call_id",
                "tool_calls",
                "tool_name",
                "finish_reason",
                "reasoning",
                "reasoning_content",
                "reasoning_details",
                "codex_reasoning_items",
                "codex_message_items",
            )
            if name in message_columns
        ]
        active_clause = " AND active = 1" if "active" in message_columns else ""
        rows = connection.execute(
            f"SELECT {', '.join(projected)} FROM messages "
            f"WHERE session_id = ?{active_clause} ORDER BY id",
            (str(session["id"]),),
        ).fetchall()
    finally:
        connection.close()

    json_fields = {
        "tool_calls",
        "reasoning_details",
        "codex_reasoning_items",
        "codex_message_items",
    }
    messages: list[dict[str, object]] = []
    for row in rows:
        message: dict[str, object] = {}
        for name in projected:
            value = row[name]
            if value is None:
                continue
            if name == "content" and isinstance(value, str) and value.startswith("\x00json:"):
                try:
                    value = json.loads(value[len("\x00json:") :])
                except (json.JSONDecodeError, TypeError):
                    pass
            elif name in json_fields and isinstance(value, str):
                try:
                    value = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    pass
            message[name] = value
        messages.append(message)
    return {
        "session_id": str(session["id"]),
        "model": str(session["model"] or ""),
        "message_count": len(messages),
        "messages": messages,
    }


def write_session_snapshot(
    state_db_path: Path,
    output_path: Path,
    *,
    session_id: str = "",
    parent_session_id: str = "",
) -> str:
    snapshot = read_session_snapshot(
        state_db_path,
        session_id=session_id,
        parent_session_id=parent_session_id,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return str(snapshot["session_id"])


def normalize_delegation(raw: Mapping[str, object]) -> DelegationEvidence:
    parent_id = str(raw.get("parent_id") or "")
    child_id = str(raw.get("child_id") or "")
    messages = raw.get("child_messages")
    if not parent_id or not child_id or parent_id == child_id:
        raise ValueError("Hermes delegation requires distinct parent and child identities")
    if not isinstance(messages, list) or not messages:
        raise ValueError("Hermes delegation requires captured child messages")
    child_trace_sha256 = hashlib.sha256(
        json.dumps(messages, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    producer_hash = str(raw.get("producer_artifact_sha256") or "")
    consumer_hash = str(raw.get("consumer_artifact_sha256") or "")
    if producer_hash or consumer_hash:
        if producer_hash != consumer_hash:
            raise ValueError("Hermes delegation artifact handoff hashes do not match")
    return DelegationEvidence(
        parent_id=parent_id,
        child_id=child_id,
        child_trace_sha256=child_trace_sha256,
        producer_artifact_sha256=producer_hash,
        consumer_artifact_sha256=consumer_hash,
    )


def validate_session_lineage(evidence: SessionLineageEvidence) -> LineageValidation:
    if evidence.requested_session_id != evidence.seed_session_id:
        return LineageValidation(False, "resume request did not use the exact seed session ID")
    if not evidence.chain or evidence.chain[0] != evidence.seed_session_id:
        return LineageValidation(False, "lineage does not start at the seed session")
    if evidence.chain[-1] != evidence.resumed_session_id:
        return LineageValidation(False, "resumed session is not the captured lineage tip")
    return LineageValidation(True)


def parse_compression_chain(raw: Mapping[str, object]) -> CompressionEvidence:
    seed_id = str(raw.get("seed_session_id") or "")
    resumed_id = str(raw.get("resumed_session_id") or "")
    sessions = raw.get("sessions")
    if not seed_id or not resumed_id or not isinstance(sessions, list):
        raise ValueError("incomplete Hermes compression evidence")
    records = {
        str(item.get("id")): item
        for item in sessions
        if isinstance(item, dict) and item.get("id")
    }
    parent = records.get(seed_id)
    child = records.get(resumed_id)
    if parent is None or child is None:
        raise ValueError("compression lineage endpoints are missing")
    if parent.get("end_reason") != "compression":
        raise ValueError("Hermes parent session was not ended by compression")
    if str(child.get("parent_session_id") or "") != seed_id:
        raise ValueError("Hermes compacted session is not a child of the seed")
    before = int(parent.get("message_count") or 0)
    after = int(child.get("message_count") or 0)
    if before <= after:
        raise ValueError("Hermes compression did not reduce the message count")
    summary = str(child.get("summary") or "")
    if not summary:
        raise ValueError("Hermes compacted session has no captured summary")
    return CompressionEvidence(
        parent_session_id=seed_id,
        compacted_session_id=resumed_id,
        resumed_session_id=resumed_id,
        before_message_count=before,
        after_message_count=after,
        summary_sha256=hashlib.sha256(summary.encode("utf-8")).hexdigest(),
    )


def read_session_lineage(
    state_db_path: Path,
    *,
    seed_session_id: str,
    requested_session_id: str,
    resumed_session_id: str,
) -> SessionLineageEvidence:
    connection = sqlite3.connect(f"file:{state_db_path.as_posix()}?mode=ro", uri=True)
    try:
        rows = connection.execute(
            "SELECT id, parent_session_id FROM sessions"
        ).fetchall()
    finally:
        connection.close()
    parents = {str(row[0]): str(row[1] or "") for row in rows}
    chain_reversed: list[str] = []
    current = resumed_session_id
    seen: set[str] = set()
    while current and current not in seen:
        seen.add(current)
        chain_reversed.append(current)
        if current == seed_session_id:
            break
        current = parents.get(current, "")
    chain = tuple(reversed(chain_reversed))
    return SessionLineageEvidence(
        seed_session_id=seed_session_id,
        requested_session_id=requested_session_id,
        resumed_session_id=resumed_session_id,
        chain=chain,
    )


def read_compression_evidence(
    state_db_path: Path,
    *,
    parent_session_id: str,
    compacted_session_id: str,
) -> CompressionEvidence:
    connection = sqlite3.connect(f"file:{state_db_path.as_posix()}?mode=ro", uri=True)
    try:
        rows = connection.execute(
            "SELECT id, parent_session_id, end_reason, message_count "
            "FROM sessions WHERE id IN (?, ?)",
            (parent_session_id, compacted_session_id),
        ).fetchall()
        message_rows = connection.execute(
            "SELECT content FROM messages WHERE session_id = ? ORDER BY id",
            (compacted_session_id,),
        ).fetchall()
    finally:
        connection.close()
    sessions = [
        {
            "id": row[0],
            "parent_session_id": row[1],
            "end_reason": row[2],
            "message_count": row[3],
        }
        for row in rows
    ]
    child = next(
        (item for item in sessions if item["id"] == compacted_session_id), None
    )
    if child is not None:
        child["summary"] = "\n".join(str(row[0] or "") for row in message_rows).strip()
    return parse_compression_chain(
        {
            "seed_session_id": parent_session_id,
            "resumed_session_id": compacted_session_id,
            "sessions": sessions,
        }
    )


def read_compacted_summary_text(
    state_db_path: Path,
    *,
    compacted_session_id: str,
) -> str:
    connection = sqlite3.connect(f"file:{state_db_path.as_posix()}?mode=ro", uri=True)
    try:
        rows = connection.execute(
            "SELECT content FROM messages WHERE session_id = ? ORDER BY id",
            (compacted_session_id,),
        ).fetchall()
    finally:
        connection.close()
    summary = "\n".join(str(row[0] or "") for row in rows).strip()
    if not summary:
        raise ValueError("Hermes compacted session has no captured summary")
    return summary


def normalize_compaction_for_analyzer(
    evidence: CompressionEvidence,
    *,
    summary_text: str,
    provenance: EventProvenance,
) -> list[dict[str, object]]:
    if evidence.parent_session_id == evidence.compacted_session_id:
        raise ValueError("Hermes compaction projection requires parent-child rotation")
    if evidence.before_message_count <= evidence.after_message_count:
        raise ValueError("Hermes compaction projection requires message reduction")
    if hashlib.sha256(summary_text.encode("utf-8")).hexdigest() != evidence.summary_sha256:
        raise ValueError("Hermes compaction projection summary hash does not match")

    common: dict[str, object] = {
        "event_ir_version": "1.0",
        "harness": provenance.harness,
        "stage_name": provenance.stage_name,
        "stage_index": provenance.stage_index,
        "source_path": str(provenance.source_path),
        "session_id": evidence.parent_session_id,
    }
    compact_metadata = {
        "trigger": "manual",
        # The shared analyzer's reduced-size fields predate Hermes support.
        # Values remain the exact native SessionDB message counts and the unit
        # is explicit so this compatibility projection cannot be read as a
        # provider token measurement.
        "pre_tokens": evidence.before_message_count,
        "post_tokens": evidence.after_message_count,
        "measurement_unit": "messages",
        "before_message_count": evidence.before_message_count,
        "after_message_count": evidence.after_message_count,
        "parent_session_id": evidence.parent_session_id,
        "child_session_id": evidence.compacted_session_id,
        "summary_sha256": evidence.summary_sha256,
    }
    return [
        {**common, "kind": "session.start", "type": "system", "subtype": "init"},
        {
            **common,
            "kind": "session.compacting",
            "type": "system",
            "subtype": "status",
            "status": "compacting",
        },
        {
            **common,
            "kind": "session.compact.success",
            "type": "system",
            "subtype": "status",
            "status": None,
            "compact_result": "success",
        },
        {
            **common,
            "kind": "session.compact",
            "type": "system",
            "subtype": "compact_boundary",
            "compact_metadata": compact_metadata,
        },
        {
            **common,
            "kind": "session.summary",
            "type": "user",
            "isSynthetic": True,
            "message": {"role": "user", "content": summary_text},
        },
        {
            **common,
            "kind": "session.complete",
            "type": "result",
            "subtype": "success",
            "is_error": False,
        },
    ]


def read_delegation_evidence(
    state_db_path: Path,
    *,
    parent_session_id: str,
) -> DelegationEvidence:
    child_id, messages = read_delegation_trace(
        state_db_path, parent_session_id=parent_session_id
    )
    return normalize_delegation(
        {
            "parent_id": parent_session_id,
            "child_id": child_id,
            "child_messages": messages,
        }
    )


def read_delegation_trace(
    state_db_path: Path,
    *,
    parent_session_id: str,
) -> tuple[str, list[dict[str, object]]]:
    connection = sqlite3.connect(f"file:{state_db_path.as_posix()}?mode=ro", uri=True)
    try:
        columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(sessions)").fetchall()
        }
        order_by = "started_at, id" if "started_at" in columns else "id"
        children = connection.execute(
            f"SELECT id FROM sessions WHERE parent_session_id = ? ORDER BY {order_by}",
            (parent_session_id,),
        ).fetchall()
        if len(children) != 1:
            raise ValueError(
                f"Hermes delegation requires exactly one child session; found {len(children)}"
            )
        child_id = str(children[0][0])
        rows = connection.execute(
            "SELECT role, content, tool_call_id, tool_calls, tool_name "
            "FROM messages WHERE session_id = ? ORDER BY id",
            (child_id,),
        ).fetchall()
    finally:
        connection.close()
    messages = [
        {
            "role": row[0],
            "content": row[1],
            "tool_call_id": row[2],
            "tool_calls": row[3],
            "tool_name": row[4],
        }
        for row in rows
    ]
    return child_id, messages


def _event(
    kind: str,
    provenance: EventProvenance,
    session_id: str,
    *,
    physical_session_id: str = "",
    call_id: str = "",
    tool_name: str = "",
    parent_tool_use_id: str = "",
    message: Mapping[str, object] | None = None,
) -> EventIR:
    return EventIR(
        kind=kind,
        stage_name=provenance.stage_name,
        stage_index=provenance.stage_index,
        source_path=str(provenance.source_path),
        harness=provenance.harness,
        session_id=session_id,
        physical_session_id=physical_session_id,
        call_id=call_id,
        tool_name=tool_name,
        parent_tool_use_id=parent_tool_use_id,
        message=message,
    )


def normalize_delegation_for_analyzer(
    *,
    parent_session_id: str,
    child_session_id: str,
    parent_call_id: str,
    producer_name: str,
    child_messages: list[Mapping[str, object]],
    provenance: EventProvenance,
) -> list[EventIR]:
    """Project native Hermes delegation into the shared Agent evidence shape.

    The shared oracle still applies its exact-one producer, successful-result,
    and parent-attributed artifact-write gates. This adapter projection changes
    evidence representation only; it does not relax the case contract.
    """

    if not parent_call_id or not producer_name:
        raise ValueError("delegation projection requires parent call and producer")
    parent_call = {
        "role": "assistant",
        "content": "",
        "tool_calls": [
            {
                "id": parent_call_id,
                "function": {
                    "name": "Agent",
                    "arguments": json.dumps(
                        {"subagent_type": producer_name}, ensure_ascii=False
                    ),
                },
            }
        ],
    }
    parent_result = {
        "role": "tool",
        "name": "Agent",
        "tool_call_id": parent_call_id,
        "content": json.dumps(
            {"success": True, "child_session_id": child_session_id},
            ensure_ascii=False,
        ),
    }
    events = [
        _event(
            "subagent.spawn",
            provenance,
            parent_session_id,
            call_id=parent_call_id,
            tool_name="Agent",
            message=parent_call,
        ),
        _event(
            "subagent.complete",
            provenance,
            parent_session_id,
            call_id=parent_call_id,
            tool_name="Agent",
            message=parent_result,
        ),
    ]
    for message in child_messages:
        role = str(message.get("role") or "unknown")
        calls = message.get("tool_calls")
        if isinstance(calls, str):
            try:
                calls = json.loads(calls)
            except json.JSONDecodeError:
                calls = []
        if isinstance(calls, list):
            for call in calls:
                if not isinstance(call, dict):
                    continue
                function = call.get("function")
                function = function if isinstance(function, dict) else {}
                events.append(
                    _event(
                        "tool.call",
                        provenance,
                        child_session_id,
                        call_id=str(call.get("id") or ""),
                        tool_name=str(
                            call.get("name") or function.get("name") or ""
                        ),
                        parent_tool_use_id=parent_call_id,
                        message={**dict(message), "tool_calls": [call]},
                    )
                )
        elif role == "tool":
            events.append(
                _event(
                    "tool.result",
                    provenance,
                    child_session_id,
                    call_id=str(
                        message.get("tool_call_id")
                        or message.get("tool_use_id")
                        or ""
                    ),
                    tool_name=str(message.get("tool_name") or message.get("name") or ""),
                    parent_tool_use_id=parent_call_id,
                    message=message,
                )
            )
    return events


def normalize_session(
    raw: Mapping[str, object],
    provenance: EventProvenance,
    *,
    session_id_override: str = "",
    message_start_index: int = 0,
) -> list[EventIR]:
    physical_session_id = str(raw.get("session_id") or "")
    session_id = session_id_override or physical_session_id
    projected_physical_id = (
        physical_session_id if session_id != physical_session_id else ""
    )
    messages = raw.get("messages")
    if not isinstance(messages, list):
        raise ValueError("Hermes session snapshot has no messages list")
    if message_start_index < 0 or message_start_index > len(messages):
        raise ValueError(
            "Hermes session message_start_index is outside the captured snapshot"
        )
    messages = messages[message_start_index:]
    events = [
        _event(
            "session.start",
            provenance,
            session_id,
            physical_session_id=projected_physical_id,
        )
    ]
    delegation_call_ids: set[str] = set()
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "unknown")
        tool_calls = message.get("tool_calls")
        if isinstance(tool_calls, list):
            for call in tool_calls:
                if not isinstance(call, dict):
                    continue
                function = call.get("function")
                function = function if isinstance(function, dict) else {}
                call_id = str(call.get("id") or "")
                tool_name = str(
                    call.get("name") or function.get("name") or call.get("tool") or ""
                )
                if tool_name == "delegate_task" and call_id:
                    delegation_call_ids.add(call_id)
                events.append(
                    _event(
                        "subagent.spawn" if tool_name == "delegate_task" else "tool.call",
                        provenance,
                        session_id,
                        physical_session_id=projected_physical_id,
                        call_id=call_id,
                        tool_name=tool_name,
                        message=message,
                    )
                )
        elif role == "tool":
            result_call_id = str(
                message.get("tool_call_id") or message.get("tool_use_id") or ""
            )
            events.append(
                _event(
                    "subagent.complete"
                    if result_call_id in delegation_call_ids
                    else "tool.result",
                    provenance,
                    session_id,
                    physical_session_id=projected_physical_id,
                    call_id=result_call_id,
                    message=message,
                )
            )
        else:
            events.append(
                _event(
                    f"message.{role}",
                    provenance,
                    session_id,
                    physical_session_id=projected_physical_id,
                    message=message,
                )
            )
    events.append(
        _event(
            "session.complete",
            provenance,
            session_id,
            physical_session_id=projected_physical_id,
        )
    )
    return events


def write_event_ir(events: list[EventIR], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        "".join(
            json.dumps(event.to_dict(), ensure_ascii=False) + "\n" for event in events
        ),
        encoding="utf-8",
    )
