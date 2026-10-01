import json
import sqlite3
import sys
from dataclasses import replace
from pathlib import Path

from infra.harness_adapters.hermes import compact_driver
from infra.harness_adapters.hermes.events import (
    SessionLineageEvidence,
    parse_compression_chain,
    read_compression_evidence,
    read_session_snapshot,
    read_session_lineage,
    validate_session_lineage,
)
from infra.harness_adapters.hermes.launch import build_launch_spec
from infra.harness_adapters.hermes.launch import LaunchContext
from infra.harness_adapters.hermes.model import CapabilityEvidence, HermesCapabilities
from infra.harness_adapters.hermes.cli import main


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


def test_resume_requires_exact_prior_session_id(tmp_path: Path) -> None:
    spec = build_launch_spec(
        {"session_action": "resume", "user_prompt": "continue"},
        replace(context(tmp_path), session_id="session-123"),
        capabilities(session_resume=True),
    )

    assert spec.argv[-4:-2] == ("--resume", "session-123")


def test_compaction_uses_headless_native_compress_driver(tmp_path: Path) -> None:
    spec = build_launch_spec(
        {
            "runtime_mode": "hermes_compaction",
            "session_action": "compact",
            "user_prompt": "/compact Retain the project context needed for the next task.",
        },
        replace(context(tmp_path), session_id="session-123"),
        capabilities(compaction=True, session_resume=True),
    )

    assert spec.executable.endswith("python.exe")
    assert spec.argv[0].endswith("compact_driver.py")
    assert spec.argv[spec.argv.index("--session-id") + 1] == "session-123"
    assert spec.argv[spec.argv.index("--focus") + 1] == (
        "Retain the project context needed for the next task."
    )
    assert "-q" not in spec.argv
    assert spec.stdin_text == ""
    config = json.loads(spec.config_text)
    assert config["auxiliary"]["compression"]["base_url"] == (
        "https://coding.dashscope.aliyuncs.com/v1"
    )
    assert config["auxiliary"]["compression"]["model"] == "qwen3.6-plus"
    assert config["compression"] == {"protect_first_n": 0, "protect_last_n": 0}
    assert spec.expected_artifact_paths[-1].endswith("compaction_scaffold.json")


def test_short_compaction_summarizes_original_carrier_before_native_rotation(
    tmp_path: Path, monkeypatch
) -> None:
    class RecordingCompressor:
        def __init__(self) -> None:
            self.summary_inputs: list[dict[str, object]] = []
            self._last_summary_error = None
            self._last_summary_fallback_used = False

        def _generate_summary(self, messages, focus_topic=None):
            self.summary_inputs = [dict(message) for message in messages]
            return "native summary"

    class RecordingAgent:
        def __init__(self) -> None:
            self.context_compressor = RecordingCompressor()
            self.parent_messages: list[dict[str, object]] = []
            self.snapshot_messages: list[dict[str, object]] = []

        def _flush_messages_to_session_db(self, messages, conversation_history):
            self.parent_messages = [dict(message) for message in messages]

        def _save_session_log(self, messages):
            self.snapshot_messages = [dict(message) for message in messages]

    class FakeHermesCLI:
        instance = None

        def __init__(self, **kwargs) -> None:
            del kwargs
            type(self).instance = self
            self.session_id = "parent-session"
            self.agent = RecordingAgent()
            self.conversation_history = [
                {"role": "user", "content": "retain the source convention"},
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {"name": "read_file", "arguments": "{}"},
                        }
                    ],
                },
                {
                    "role": "tool",
                    "tool_call_id": "call-1",
                    "content": "ORIGINAL-CARRIER-TOKEN",
                },
                {"role": "assistant", "content": "retained for the next request"},
            ]

        def _init_agent(self) -> bool:
            return True

        def _manual_compress(self, command: str) -> None:
            del command
            if len(self.conversation_history) <= 4:
                return
            compress_end = len(self.conversation_history) - 3
            summary = self.agent.context_compressor._generate_summary(
                self.conversation_history[:compress_end]
            )
            tail = [dict(message) for message in self.conversation_history[compress_end:]]
            tail[0]["content"] = f"{summary}\n\n{tail[0]['content']}"
            self.conversation_history = tail
            self.session_id = "child-session"

    source = tmp_path / "hermes-source"
    source.mkdir()
    (source / "cli.py").write_text("# test Hermes module\n", encoding="utf-8")
    hermes_home = tmp_path / ".hermes"
    hermes_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setitem(sys.modules, "cli", type("CliModule", (), {"HermesCLI": FakeHermesCLI}))

    exit_code = compact_driver.main(
        [
            "--hermes-source",
            str(source),
            "--session-id",
            "parent-session",
            "--model",
            "qwen3.6-plus",
        ]
    )

    cli = FakeHermesCLI.instance
    assert exit_code == 0
    assert len(cli.agent.parent_messages) == 8
    assert len(cli.conversation_history) == 3
    assert cli.agent.snapshot_messages == cli.conversation_history
    assert any(
        message.get("content") == "ORIGINAL-CARRIER-TOKEN"
        for message in cli.agent.context_compressor.summary_inputs
    )
    audit = json.loads(
        (hermes_home / "compaction_scaffold.json").read_text(encoding="utf-8")
    )
    assert audit["original_message_count"] == 4
    assert audit["scaffold_message_count"] == 4
    assert audit["parent_message_count"] == 8
    assert audit["child_message_count"] == 3
    assert audit["all_original_messages_entered_native_summary"] is True


def test_runner_gates_and_records_short_compaction_scaffold_audit() -> None:
    runner = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")

    assert "hermes_compaction_scaffold.json" in runner
    assert "boundary_hermes_compaction_scaffold_missing" in runner
    assert "all_original_messages_entered_native_summary" in runner
    assert "compaction_scaffold_message_count" in runner
    assert '"compaction-event-ir"' in runner
    assert "$script:BoundaryLogicalSessionIds" in runner
    assert '"--session-id-override"' in runner
    assert '$stageMeta["session_id"] = $logicalSessionId' in runner


def test_changed_resume_identity_is_invalid() -> None:
    evidence = SessionLineageEvidence(
        seed_session_id="session-123",
        requested_session_id="session-123",
        resumed_session_id="session-999",
        chain=("session-123",),
    )

    assert validate_session_lineage(evidence).valid is False


def test_compaction_requires_real_reduction_and_lineage() -> None:
    raw = json.loads(
        (FIXTURES / "hermes_compression_chain.json").read_text(encoding="utf-8")
    )

    evidence = parse_compression_chain(raw)

    assert evidence.before_message_count > evidence.after_message_count
    assert evidence.parent_session_id == "session-123"
    assert evidence.resumed_session_id == evidence.compacted_session_id
    assert evidence.summary_sha256


def test_read_session_lineage_uses_run_local_state_db(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    connection = sqlite3.connect(db_path)
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
        INSERT INTO sessions VALUES ('session-123', NULL, 'compression', 8);
        INSERT INTO sessions VALUES ('session-456', 'session-123', NULL, 3);
        INSERT INTO messages VALUES (1, 'session-456', 'user', 'summary text');
        """
    )
    connection.commit()
    connection.close()

    evidence = read_session_lineage(
        db_path,
        seed_session_id="session-123",
        requested_session_id="session-123",
        resumed_session_id="session-456",
    )

    assert evidence.chain == ("session-123", "session-456")
    assert validate_session_lineage(evidence).valid is True


def test_read_session_snapshot_exports_latest_root_and_decodes_messages(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.db"
    connection = sqlite3.connect(db_path)
    connection.executescript(
        """
        CREATE TABLE sessions (
            id TEXT PRIMARY KEY,
            model TEXT,
            parent_session_id TEXT,
            started_at REAL
        );
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY,
            session_id TEXT,
            role TEXT,
            content TEXT,
            tool_call_id TEXT,
            tool_calls TEXT,
            tool_name TEXT,
            active INTEGER DEFAULT 1
        );
        INSERT INTO sessions VALUES ('root-old', 'k3', NULL, 1);
        INSERT INTO sessions VALUES ('root-new', 'k3', NULL, 2);
        INSERT INTO sessions VALUES ('child-newest', 'k3', 'root-new', 3);
        INSERT INTO messages VALUES (
            1, 'root-new', 'assistant', '', NULL,
            '[{"id":"call-1","function":{"name":"read_file","arguments":"{}"}}]',
            NULL, 1
        );
        INSERT INTO messages VALUES (
            3, 'root-new', 'assistant', 'inactive', NULL, NULL, NULL, 0
        );
        """
    )
    connection.execute(
        "INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (2, "root-new", "tool", '\x00json:{"ok": true}', "call-1", None, "read_file", 1),
    )
    connection.commit()
    connection.close()

    snapshot = read_session_snapshot(db_path)

    assert snapshot["session_id"] == "root-new"
    assert snapshot["model"] == "k3"
    assert snapshot["message_count"] == 2
    assert snapshot["messages"][0]["tool_calls"][0]["id"] == "call-1"
    assert snapshot["messages"][1]["content"] == {"ok": True}


def test_read_compression_evidence_requires_db_parent_child_reduction(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.db"
    connection = sqlite3.connect(db_path)
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
        INSERT INTO sessions VALUES ('session-123', NULL, 'compression', 8);
        INSERT INTO sessions VALUES ('session-456', 'session-123', NULL, 3);
        INSERT INTO messages VALUES (1, 'session-456', 'user', 'summary text');
        """
    )
    connection.commit()
    connection.close()

    evidence = read_compression_evidence(
        db_path,
        parent_session_id="session-123",
        compacted_session_id="session-456",
    )

    assert evidence.before_message_count == 8
    assert evidence.after_message_count == 3
    assert evidence.summary_sha256


def test_session_lineage_cli_writes_compaction_record(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    output = tmp_path / "lineage.json"
    connection = sqlite3.connect(db_path)
    connection.executescript(
        """
        CREATE TABLE sessions (id TEXT PRIMARY KEY, parent_session_id TEXT, end_reason TEXT, message_count INTEGER);
        CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, content TEXT);
        INSERT INTO sessions VALUES ('session-123', NULL, 'compression', 8);
        INSERT INTO sessions VALUES ('session-456', 'session-123', NULL, 3);
        INSERT INTO messages VALUES (1, 'session-456', 'user', 'summary text');
        """
    )
    connection.commit()
    connection.close()

    exit_code = main(
        [
            "session-lineage",
            "--state-db",
            str(db_path),
            "--seed-session-id",
            "session-123",
            "--requested-session-id",
            "session-123",
            "--resumed-session-id",
            "session-456",
            "--session-action",
            "compact",
            "--output",
            str(output),
        ]
    )

    record = json.loads(output.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert record["lineage_valid"] is True
    assert record["compression"]["compacted_session_id"] == "session-456"
