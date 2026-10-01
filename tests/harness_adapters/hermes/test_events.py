import hashlib
import json
import sqlite3
from pathlib import Path

from infra.harness_adapters.hermes.events import (
    CompressionEvidence,
    EventProvenance,
    normalize_compaction_for_analyzer,
    normalize_delegation_for_analyzer,
    normalize_session,
)
from infra.harness_adapters.hermes.cli import main
from infra.analyze_trace import (
    _session_runtime_provenance,
    _subagent_boundary_producer_evidence,
)


FIXTURES = Path(__file__).parent / "fixtures"


def test_tool_result_keeps_source_pointer() -> None:
    source = FIXTURES / "hermes_session_tool.json"
    raw = json.loads(source.read_text(encoding="utf-8"))
    provenance = EventProvenance(
        stage_name="stage-1",
        stage_index=1,
        source_path=Path("artifacts/hermes_session.json"),
    )

    events = normalize_session(raw, provenance)

    result = next(event for event in events if event.kind == "tool.result")
    assert result.stage_name == "stage-1"
    assert result.source_path.endswith("hermes_session.json")
    assert result.call_id == "call-7"


def test_normalized_tool_events_remain_analyzer_compatible() -> None:
    source = FIXTURES / "hermes_session_tool.json"
    raw = json.loads(source.read_text(encoding="utf-8"))
    events = normalize_session(
        raw,
        EventProvenance("stage-1", 1, Path("hermes_session.json")),
    )

    call = next(event for event in events if event.kind == "tool.call").to_dict()
    result = next(event for event in events if event.kind == "tool.result").to_dict()

    assert call["messages"][0]["tool_calls"][0]["id"] == "call-7"
    assert result["messages"][0]["tool_call_id"] == "call-7"
    assert call["stage_index"] == result["stage_index"] == 1


def test_normalize_cli_writes_jsonl_with_stage_provenance(tmp_path: Path) -> None:
    output = tmp_path / "event_ir.jsonl"

    exit_code = main(
        [
            "normalize",
            "--session",
            str(FIXTURES / "hermes_session_tool.json"),
            "--output",
            str(output),
            "--stage-name",
            "trigger",
            "--stage-index",
            "2",
        ]
    )

    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert exit_code == 0
    assert records[0]["kind"] == "session.start"
    assert all(record["stage_name"] == "trigger" for record in records)


def test_normalized_session_projects_native_start_and_success() -> None:
    raw = {"session_id": "session-1", "messages": []}

    records = [
        event.to_dict()
        for event in normalize_session(
            raw,
            EventProvenance("seed", 1, Path("hermes_session.json")),
        )
    ]

    assert records[0]["type"] == "system"
    assert records[0]["subtype"] == "init"
    assert records[-1]["type"] == "result"
    assert records[-1]["subtype"] == "success"
    assert records[-1]["is_error"] is False


def test_normalized_resume_projects_logical_id_and_keeps_physical_id() -> None:
    raw = {"session_id": "child-1", "messages": []}

    records = [
        event.to_dict()
        for event in normalize_session(
            raw,
            EventProvenance("resume", 3, Path("hermes_session.json")),
            session_id_override="root-1",
        )
    ]

    assert {record["session_id"] for record in records} == {"root-1"}
    assert {record["physical_session_id"] for record in records} == {"child-1"}


def test_normalized_resume_excludes_messages_from_seed_snapshot() -> None:
    raw = {
        "session_id": "session-1",
        "messages": [
            {"role": "user", "content": "seed prompt"},
            {
                "role": "assistant",
                "tool_calls": [{
                    "id": "seed-read",
                    "function": {
                        "name": "read_file",
                        "arguments": '{"path":"inputs/project_notes.md"}',
                    },
                }],
            },
            {"role": "user", "content": "resumed prompt"},
            {
                "role": "assistant",
                "tool_calls": [{
                    "id": "resume-read",
                    "function": {
                        "name": "read_file",
                        "arguments": '{"path":"README.md"}',
                    },
                }],
            },
        ],
    }

    records = [
        event.to_dict()
        for event in normalize_session(
            raw,
            EventProvenance("resume", 2, Path("hermes_session.json")),
            message_start_index=2,
        )
    ]

    calls = [record for record in records if record["kind"] == "tool.call"]
    assert [record["call_id"] for record in calls] == ["resume-read"]
    assert not any("seed prompt" in json.dumps(record) for record in records)


def test_compaction_projection_uses_reduced_native_counts_and_child_summary() -> None:
    summary_text = "summary contains carrier-marker"
    summary_sha256 = hashlib.sha256(summary_text.encode("utf-8")).hexdigest()
    evidence = CompressionEvidence(
        parent_session_id="parent-1",
        compacted_session_id="child-1",
        resumed_session_id="child-1",
        before_message_count=8,
        after_message_count=3,
        summary_sha256=summary_sha256,
    )

    records = normalize_compaction_for_analyzer(
        evidence,
        summary_text=summary_text,
        provenance=EventProvenance("compact", 2, Path("state.db")),
    )
    runtime = _session_runtime_provenance(
        {"session_action": "compact", "session_id": "parent-1"},
        records,
        ["carrier-marker"],
    )

    assert runtime["compaction_boundary"] is True
    assert runtime["compaction_carrier_preserved"] is True
    compact = next(
        record for record in records if record.get("subtype") == "compact_boundary"
    )
    assert compact["compact_metadata"]["measurement_unit"] == "messages"
    assert compact["compact_metadata"]["before_message_count"] == 8
    assert compact["compact_metadata"]["after_message_count"] == 3
    assert compact["compact_metadata"]["summary_sha256"] == summary_sha256
    assert not any(record.get("kind") in {"tool.call", "tool.result"} for record in records)


def test_compaction_event_cli_writes_only_hard_lineage_projection(tmp_path: Path) -> None:
    state_db = tmp_path / "state.db"
    output = tmp_path / "compaction_event_ir.jsonl"
    summary_text = "native summary with carrier-marker"
    connection = sqlite3.connect(state_db)
    connection.executescript(
        """
        CREATE TABLE sessions (
            id TEXT PRIMARY KEY,
            parent_session_id TEXT,
            end_reason TEXT,
            message_count INTEGER
        );
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY,
            session_id TEXT,
            role TEXT,
            content TEXT
        );
        INSERT INTO sessions VALUES ('parent-1', NULL, 'compression', 8);
        INSERT INTO sessions VALUES ('child-1', 'parent-1', NULL, 3);
        """
    )
    connection.execute(
        "INSERT INTO messages VALUES (1, 'child-1', 'assistant', ?)",
        (summary_text,),
    )
    connection.commit()
    connection.close()

    exit_code = main(
        [
            "compaction-event-ir",
            "--state-db",
            str(state_db),
            "--parent-session-id",
            "parent-1",
            "--child-session-id",
            "child-1",
            "--stage-name",
            "compact",
            "--stage-index",
            "2",
            "--output",
            str(output),
        ]
    )

    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert exit_code == 0
    assert {record["session_id"] for record in records} == {"parent-1"}
    assert any(record.get("isSynthetic") is True for record in records)
    assert all(record.get("kind") not in {"tool.call", "tool.result"} for record in records)


def test_delegate_task_is_normalized_as_native_subagent_lifecycle() -> None:
    raw = {
        "session_id": "parent",
        "messages": [
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "delegate-1",
                        "function": {
                            "name": "delegate_task",
                            "arguments": '{"task":"inspect"}',
                        },
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "delegate-1",
                "content": "child session: child-1 completed",
            },
        ],
    }

    events = normalize_session(
        raw,
        EventProvenance("producer", 1, Path("hermes_session.json")),
    )

    assert any(event.kind == "subagent.spawn" for event in events)
    assert any(event.kind == "subagent.complete" for event in events)


def test_native_delegation_projects_to_shared_subagent_oracle() -> None:
    child_messages = [
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "child-write-1",
                "function": {
                    "name": "write_file",
                    "arguments": '{"path":"handoff/produced_context.md","content":"review"}',
                },
            }],
        },
        {
            "role": "tool",
            "tool_call_id": "child-write-1",
            "name": "write_file",
            "content": '{"success":true}',
        },
    ]
    records = [
        event.to_dict()
        for event in normalize_delegation_for_analyzer(
            parent_session_id="parent-1",
            child_session_id="child-1",
            parent_call_id="delegate-1",
            producer_name="continuity-reviewer",
            child_messages=child_messages,
            provenance=EventProvenance("producer", 1, Path("state.db")),
        )
    ]

    evidence = _subagent_boundary_producer_evidence(
        {
            "boundary_runtime_mode": "claude_subagent_producer",
            "boundary_runtime_contract": {"subagent_name": "continuity-reviewer"},
            "workspace_artifact": "handoff/produced_context.md",
        },
        records,
    )

    assert len(evidence) == 1
    assert evidence[0]["producer"] == "continuity-reviewer"
    assert evidence[0]["attributed_writes"][0]["tool_use_id"] == "child-write-1"
