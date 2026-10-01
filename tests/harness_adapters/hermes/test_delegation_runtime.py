import json
import sqlite3
from dataclasses import replace
from pathlib import Path

from infra.harness_adapters.hermes.events import (
    normalize_delegation,
    read_delegation_evidence,
)
from infra.harness_adapters.hermes.launch import LaunchContext, build_launch_spec
from infra.harness_adapters.hermes.model import CapabilityEvidence, HermesCapabilities
from infra.harness_adapters.hermes.cli import main as adapter_main


FIXTURES = Path(__file__).parent / "fixtures"


def capabilities(**overrides: bool) -> HermesCapabilities:
    values = {
        name: CapabilityEvidence(overrides.get(name, True), "test", "fixture")
        for name in (
            "instruction",
            "skill",
            "mcp",
            "session_resume",
            "compaction",
            "subagent",
            "durable_memory",
        )
    }
    return HermesCapabilities(**values)


def context(tmp_path: Path) -> LaunchContext:
    return LaunchContext(
        hermes_python=Path("python.exe"),
        hermes_launcher=Path("hermes"),
        hermes_home=tmp_path / ".hermes",
        workspace_dir=tmp_path / "workspace",
        model="qwen3.6-plus",
        provider_base_url="https://coding.dashscope.aliyuncs.com/v1",
        timeout_sec=300,
        secret_env={"OPENAI_API_KEY": "secret"},
    )


def test_delegation_requires_distinct_child_identity() -> None:
    raw = json.loads((FIXTURES / "hermes_delegation.json").read_text(encoding="utf-8"))

    evidence = normalize_delegation(raw)

    assert evidence.parent_id
    assert evidence.child_id
    assert evidence.parent_id != evidence.child_id
    assert evidence.child_trace_sha256


def test_artifact_handoff_hashes_match() -> None:
    raw = json.loads((FIXTURES / "hermes_delegation.json").read_text(encoding="utf-8"))

    evidence = normalize_delegation(raw)

    assert evidence.producer_artifact_sha256 == evidence.consumer_artifact_sha256


def test_delegation_launch_is_scoped_to_bound_producer(tmp_path: Path) -> None:
    spec = build_launch_spec(
        {"runtime_mode": "hermes_subagent_producer", "user_prompt": "delegate"},
        replace(context(tmp_path), delegation_auto_approve=True),
        capabilities(subagent=True),
    )
    ordinary = build_launch_spec(
        {"runtime_mode": "fresh", "user_prompt": "ordinary"},
        replace(context(tmp_path), delegation_auto_approve=True),
        capabilities(subagent=True),
    )

    assert "delegation" in spec.argv[spec.argv.index("--toolsets") + 1].split(",")
    delegation = json.loads(spec.config_text)["delegation"]
    assert delegation["subagent_auto_approve"] is True
    assert delegation["child_timeout_seconds"] == 300
    delegated_prompt = spec.argv[spec.argv.index("-q") + 1]
    assert "Call `delegate_task` exactly once immediately" in delegated_prompt
    assert "continuity-reviewer" in delegated_prompt
    assert ordinary.argv[ordinary.argv.index("-q") + 1] == "ordinary"
    assert "delegation" not in ordinary.argv[ordinary.argv.index("--toolsets") + 1].split(",")


def test_read_delegation_evidence_uses_child_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    connection = sqlite3.connect(db_path)
    connection.executescript(
        """
        CREATE TABLE sessions (id TEXT PRIMARY KEY, parent_session_id TEXT, end_reason TEXT, message_count INTEGER);
        CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, content TEXT, tool_call_id TEXT, tool_calls TEXT, tool_name TEXT);
        INSERT INTO sessions VALUES ('session-parent', NULL, NULL, 4);
        INSERT INTO sessions VALUES ('session-child', 'session-parent', 'completed', 2);
        INSERT INTO messages VALUES (1, 'session-child', 'user', 'do work', NULL, NULL, NULL);
        INSERT INTO messages VALUES (2, 'session-child', 'assistant', 'done', NULL, NULL, NULL);
        """
    )
    connection.commit()
    connection.close()

    evidence = read_delegation_evidence(db_path, parent_session_id="session-parent")

    assert evidence.parent_id == "session-parent"
    assert evidence.child_id == "session-child"
    assert evidence.child_trace_sha256


def test_delegation_event_cli_emits_analyzer_projection(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    connection = sqlite3.connect(db_path)
    connection.executescript(
        """
        CREATE TABLE sessions (id TEXT PRIMARY KEY, parent_session_id TEXT, end_reason TEXT, message_count INTEGER);
        CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, content TEXT, tool_call_id TEXT, tool_calls TEXT, tool_name TEXT);
        INSERT INTO sessions VALUES ('parent', NULL, NULL, 2);
        INSERT INTO sessions VALUES ('child', 'parent', 'completed', 2);
        INSERT INTO messages VALUES (1, 'child', 'assistant', '', NULL,
          '[{"id":"write-1","function":{"name":"write_file","arguments":"{\\"path\\":\\"handoff/produced_context.md\\",\\"content\\":\\"review\\"}"}}]', NULL);
        INSERT INTO messages VALUES (2, 'child', 'tool', '{"success":true}', 'write-1', NULL, 'write_file');
        """
    )
    connection.commit()
    connection.close()
    parent = tmp_path / "parent.json"
    parent.write_text(json.dumps({
        "session_id": "parent",
        "messages": [{
            "role": "assistant",
            "tool_calls": [{
                "id": "delegate-1",
                "function": {"name": "delegate_task", "arguments": "{}"},
            }],
        }],
    }), encoding="utf-8")
    output = tmp_path / "delegation.jsonl"

    exit_code = adapter_main([
        "delegation-event-ir",
        "--state-db", str(db_path),
        "--parent-session", str(parent),
        "--parent-session-id", "parent",
        "--producer-name", "continuity-reviewer",
        "--stage-name", "producer",
        "--stage-index", "1",
        "--output", str(output),
    ])

    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert exit_code == 0
    assert records[0]["messages"][0]["tool_calls"][0]["function"]["name"] == "Agent"
    assert any(record.get("parent_tool_use_id") == "delegate-1" for record in records)
