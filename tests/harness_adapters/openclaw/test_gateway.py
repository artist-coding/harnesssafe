import io
import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from infra.harness_adapters.openclaw import cli as openclaw_cli
from infra.harness_adapters.openclaw.cli import (
    _capture_stream,
    _gateway_readiness_timeout,
    _operation_timeout,
    _subagent_completion_timeout,
    _remaining_seconds,
    _terminate_gateway_process,
    _wait_for_pending_subagent_announces,
    _wait_for_spawned_subagents,
    _wait_gateway,
)
from infra.harness_adapters.openclaw.config import build_paths
from infra.harness_adapters.openclaw.gateway import (
    OwnershipManifest,
    ProcessIdentity,
    build_gateway_spec,
    cleanup_owned_processes,
)


def test_cleanup_refuses_unowned_pid(tmp_path: Path) -> None:
    manifest = OwnershipManifest(123, "nonce-a", tmp_path / "ownership.json")
    observed = ProcessIdentity(123, "nonce-b")
    assert cleanup_owned_processes(manifest, observed).terminated == ()


def test_cleanup_allows_exact_owned_identity(tmp_path: Path) -> None:
    manifest = OwnershipManifest(123, "nonce-a", tmp_path / "ownership.json")
    observed = ProcessIdentity(123, "nonce-a")
    result = cleanup_owned_processes(manifest, observed, terminate=lambda pid: pid == 123)
    assert result.terminated == (123,)


def test_gateway_spec_uses_explicit_foreground_run(tmp_path: Path) -> None:
    paths = build_paths(tmp_path / "runtime", "case-a")
    spec = build_gateway_spec(
        tmp_path / "openclaw.cmd",
        paths,
        gateway_token="gateway-secret",
        stage_index=2,
    )

    assert spec.argv[1:3] == ("gateway", "run")
    assert "gateway-secret" not in spec.argv
    assert spec.ownership_path == paths.run_dir / "openclaw-gateway-stage-002-ownership.json"


def test_gateway_uses_owned_http_ready_without_spawning_hanging_health_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ready_checks = iter((False, True))
    health_calls: list[list[str]] = []

    monkeypatch.setattr(
        openclaw_cli,
        "_http_ready",
        lambda port: next(ready_checks),
    )

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        health_calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout='{"ok":true}', stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    _wait_gateway(
        tmp_path / "openclaw.cmd",
        {},
        timeout=1,
        gateway_port=18789,
        readiness_path=tmp_path / "readiness.jsonl",
    )

    assert health_calls == []
    records = [
        json.loads(line)
        for line in (tmp_path / "readiness.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert records[-1]["probe"] == "http_readyz"
    assert records[-1]["ready"] is True


def test_gateway_readiness_budget_covers_slow_first_start() -> None:
    assert _gateway_readiness_timeout(300) == 120
    assert _gateway_readiness_timeout(45) == 45


def test_agent_operation_keeps_full_declared_timeout() -> None:
    assert _operation_timeout(300) == 300.0
    assert _operation_timeout(0) == 1.0


def test_subagent_completion_has_independent_bounded_budget() -> None:
    assert _subagent_completion_timeout(300) == 120.0
    assert _subagent_completion_timeout(45) == 45.0
    assert _subagent_completion_timeout(0) == 1.0


def test_remaining_seconds_enforces_one_shared_deadline() -> None:
    assert _remaining_seconds(130.0, now=lambda: 100.0) == 30.0
    with pytest.raises(TimeoutError, match="stage deadline"):
        _remaining_seconds(100.0, now=lambda: 100.0)


def test_wait_for_spawned_subagent_requires_completed_owned_session(
    tmp_path: Path,
) -> None:
    child_key = "agent:continuity-reviewer:subagent:child-1"
    session_file = tmp_path / "agents" / "continuity-reviewer" / "sessions" / "child.jsonl"
    session_file.parent.mkdir(parents=True)
    session_file.write_text('{}\n', encoding="utf-8")
    (session_file.parent / "sessions.json").write_text(
        json.dumps({child_key: {
            "status": "completed",
            "sessionFile": str(session_file),
            "endedAt": 100,
            "updatedAt": 101,
        }}),
        encoding="utf-8",
    )

    completed = _wait_for_spawned_subagents(
        tmp_path,
        [{"call_id": "spawn-1", "child_session_key": child_key, "run_id": "run-1"}],
        deadline=10.0,
        now=lambda: 1.0,
        sleep=lambda _: None,
    )

    assert completed[0]["session_file"] == session_file.resolve()
    assert completed[0]["status"] == "completed"
    assert completed[0]["ended_at"] == 100
    assert completed[0]["updated_at"] == 101


def test_wait_for_pending_subagent_announce_requires_native_completion_state(
    tmp_path: Path,
) -> None:
    database = tmp_path / "state" / "openclaw.sqlite"
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as connection:
        connection.execute("""
            CREATE TABLE subagent_runs (
                run_id TEXT PRIMARY KEY,
                ended_at INTEGER,
                pending_final_delivery INTEGER,
                completion_announced_at INTEGER,
                suppress_announce_reason TEXT
            )
        """)
        connection.execute(
            "INSERT INTO subagent_runs VALUES (?, ?, ?, ?, ?)",
            ("run-1", 200, 1, None, None),
        )

    sleeps: list[float] = []

    def settle_announce(delay: float) -> None:
        sleeps.append(delay)
        with sqlite3.connect(database) as connection:
            connection.execute("""
                UPDATE subagent_runs
                SET pending_final_delivery = 0,
                    completion_announced_at = 300
                WHERE run_id = 'run-1'
            """)

    _wait_for_pending_subagent_announces(
        tmp_path,
        deadline=10.0,
        now=lambda: 1.0,
        sleep=settle_announce,
    )

    assert sleeps == [0.2]


def test_gateway_early_exit_is_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class ExitedProcess:
        def poll(self) -> int:
            return 23

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1, "", "not ready"),
    )
    readiness_path = tmp_path / "readiness.jsonl"

    with pytest.raises(RuntimeError, match="exited before readiness.*23"):
        _wait_gateway(
            tmp_path / "openclaw.cmd",
            {},
            timeout=1,
            gateway_port=18789,
            process=ExitedProcess(),
            readiness_path=readiness_path,
        )

    assert '"process_exit_code": 23' in readiness_path.read_text(encoding="utf-8")


def test_gateway_stream_capture_redacts_secret(tmp_path: Path) -> None:
    target = tmp_path / "gateway.stderr.log"

    _capture_stream(io.StringIO("before gateway-secret after\n"), target, ("gateway-secret",))

    captured = target.read_text(encoding="utf-8")
    assert captured == "before [REDACTED] after\n"


def test_gateway_stream_capture_redacts_secret_across_read_boundary(tmp_path: Path) -> None:
    target = tmp_path / "gateway.stderr.log"
    secret = "provider-secret-value"
    prefix = "x" * 4090

    _capture_stream(io.StringIO(prefix + secret + " after"), target, (secret,))

    captured = target.read_text(encoding="utf-8")
    assert secret not in captured
    assert captured == prefix + "[REDACTED] after"


def test_windows_gateway_cleanup_terminates_owned_process_tree(tmp_path: Path) -> None:
    class FakeProcess:
        pid = 321
        returncode: int | None = None

        def __init__(self) -> None:
            self.running = True

        def poll(self) -> int | None:
            return None if self.running else self.returncode

        def wait(self, timeout: float) -> int:
            assert timeout == 5
            assert not self.running
            return int(self.returncode or 0)

    process = FakeProcess()
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append((argv, _))
        process.running = False
        process.returncode = 1
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    cleanup_path = tmp_path / "cleanup.json"
    record = _terminate_gateway_process(
        process,
        cleanup_path,
        platform="nt",
        run=fake_run,
    )

    assert calls[0][0] == ["taskkill", "/PID", "321", "/T", "/F"]
    assert calls[0][1]["stdout"] is subprocess.DEVNULL
    assert calls[0][1]["stderr"] is subprocess.DEVNULL
    assert "text" not in calls[0][1]
    assert "capture_output" not in calls[0][1]
    assert record["live_after_cleanup"] is False
    assert record["method"] == "taskkill_tree"
    assert cleanup_path.is_file()


def test_windows_gateway_cleanup_falls_back_and_always_writes_manifest(
    tmp_path: Path,
) -> None:
    class FakeProcess:
        pid = 654
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float) -> int:
            if self.returncode is None:
                raise subprocess.TimeoutExpired("wait", timeout)
            return self.returncode

        def terminate(self) -> None:
            self.returncode = 7

        def kill(self) -> None:
            self.returncode = 9

    process = FakeProcess()
    cleanup_path = tmp_path / "cleanup.json"
    ownership = OwnershipManifest(654, "nonce-a", tmp_path / "ownership.json")
    ownership.write()

    record = _terminate_gateway_process(
        process,
        cleanup_path,
        platform="nt",
        ownership=ownership,
        run=lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1),
    )

    assert record["live_after_cleanup"] is False
    assert record["taskkill_return_code"] == 1
    assert record["method"] == "terminate_fallback"
    assert cleanup_path.is_file()


def test_gateway_cleanup_rejects_mismatched_ownership(tmp_path: Path) -> None:
    class FakeProcess:
        pid = 777

        def poll(self) -> None:
            return None

    ownership = OwnershipManifest(777, "expected", tmp_path / "ownership.json")
    ownership.path.write_text(
        '{"gateway_pid": 777, "launch_nonce": "different"}\n',
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="ownership"):
        _terminate_gateway_process(
            FakeProcess(),
            tmp_path / "cleanup.json",
            ownership=ownership,
        )

    assert (tmp_path / "cleanup.json").is_file()
