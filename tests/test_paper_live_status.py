import json
from datetime import datetime
from pathlib import Path

from infra import check_paper_live_status


def _status(
    *,
    completed: int = 10,
    include_execute_command: bool = True,
    job_name: str = "paper_core_claude_20260626",
    command_job_name: str | None = None,
    matrix_id: str = "",
) -> dict:
    command_job_name = command_job_name or job_name
    commands = {
        "job_list": "python infra/paper_queue_job.py list",
        "claude_status": f"python infra/paper_queue_job.py status --job-name {command_job_name}",
        "live_snapshot": "python infra/paper_queue_job.py snapshot --out-json docs/generated_artifacts/paper_live_status.json --out-md docs/generated_artifacts/paper_live_status.md --check-md docs/generated_artifacts/paper_live_status_check.md",
        "claude_watch": (
            f"python infra/paper_queue_job.py watch --job-name {command_job_name} "
            "--snapshot-json docs/generated_artifacts/paper_live_status.json --snapshot-md docs/generated_artifacts/paper_live_status.md "
            "--check-md docs/generated_artifacts/paper_live_status_check.md"
        ),
        "claude_restart_watch": f"python infra/paper_queue_job.py restart-watch --job-name {command_job_name}",
        "claude_execute": "python infra/paper_queue_job.py start --job-name paper_core_claude_20260626 --queue docs/generated_artifacts/paper_run_queue.json --queue-mode coalesced --harness claude --execute",
        "claude_post_run": "python infra/paper_queue_job.py start --job-name paper_core_claude_20260626_post --queue docs/generated_artifacts/paper_run_queue.json --queue-mode post-run --harness claude --execute",
    }
    if not include_execute_command:
        commands.pop("claude_execute")
    return {
        "generated_at": "2099-01-01T00:00:00",
        "active_baseline": {
            "name": "claude_code_kimi_k2.6",
            "harness": "claude",
            "model": "kimi-k2.6",
            "model_source": "Claude Code runtime default",
            "codex_in_current_scope": False,
        },
        "matrix_progress": {
            "full": {"matrix_id": matrix_id, "summary": {"completed_rows": completed, "expected_rows": 399}},
            "claude": {"matrix_id": matrix_id, "summary": {"completed_rows": completed, "expected_rows": 399}},
        },
        "jobs": [
            {
                "job_name": job_name,
                "observed_status": "running",
                "watcher_pid": 123,
                "watcher_running": True,
                "watcher_latest_sample_age_sec": 60,
                "watcher_latest_completed": completed,
                "watcher_latest_expected": 399,
            }
        ],
        "command_policy": {
            "matrix_complete": completed >= 399,
            "watch_or_execute_required": completed < 399,
            "note": "Matrix is incomplete; watcher and queued execution commands are available.",
        },
        "commands": commands,
    }


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _history_sample(
    *,
    completed: int = 10,
    expected: int = 399,
    generated_at: str = "2099-01-01T00:00:00",
    matrix_id: str = "",
) -> dict:
    progress = {"completed_rows": completed, "expected_rows": expected}
    row = {"generated_at": generated_at, "full": dict(progress), "claude": dict(progress)}
    if matrix_id:
        row["matrix_id"] = matrix_id
    return row


def _write_history(path: Path, *samples: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(sample) for sample in samples) + "\n", encoding="utf-8")


def test_live_status_check_accepts_current_snapshot(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    payload = _status(completed=10)
    _write(live, payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is True
    assert report["summary"]["claude"]["completed_rows"] == 10
    assert not report["issues"]


def test_live_status_check_accepts_matching_history(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    history = tmp_path / "paper_live_status_history.jsonl"
    payload = _status(completed=10)
    _write(live, payload)
    _write_history(history, _history_sample(completed=10))

    report = check_paper_live_status.build_report(
        live_status_path=live,
        history_path=history,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is True
    assert report["history_sample_count"] == 1
    assert report["history_latest_generated_at"] == payload["generated_at"]
    assert not report["issues"]


def test_live_status_check_accepts_complete_snapshot_without_action_commands(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    payload = _status(completed=399)
    payload["jobs"][0]["observed_status"] = "passed"
    payload["jobs"][0]["watcher_running"] = False
    payload["command_policy"] = {
        "matrix_complete": True,
        "watch_or_execute_required": False,
        "note": "Matrix is complete; no watcher restart or queued benchmark execution is required.",
    }
    for name in ["claude_watch", "claude_restart_watch", "claude_execute", "claude_post_run"]:
        payload["commands"].pop(name)
    _write(live, payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is True
    assert not report["issues"]


def test_live_status_check_rejects_complete_snapshot_with_action_commands(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    payload = _status(completed=399)
    payload["jobs"][0]["observed_status"] = "passed"
    payload["jobs"][0]["watcher_running"] = False
    payload["command_policy"] = {
        "matrix_complete": True,
        "watch_or_execute_required": False,
        "note": "Matrix is complete; no watcher restart or queued benchmark execution is required.",
    }
    _write(live, payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is False
    assert any("should not include action command" in item["message"] for item in report["issues"])


def test_live_status_check_rejects_missing_execute_command(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    payload = _status(include_execute_command=False)
    _write(live, payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is False
    assert any("claude_execute" in item["message"] for item in report["issues"])


def test_live_status_check_rejects_watcher_command_without_check_md(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    payload = _status()
    payload["commands"]["claude_watch"] = "python infra/paper_queue_job.py watch --snapshot-json docs/generated_artifacts/paper_live_status.json"
    _write(live, payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is False
    assert any(
        item["message"] == "live status watcher command does not refresh paper_live_status_check.md"
        for item in report["issues"]
    )


def test_live_status_check_rejects_missing_restart_watch_command(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    payload = _status()
    payload["commands"].pop("claude_restart_watch")
    _write(live, payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is False
    assert any("claude_restart_watch" in item["message"] for item in report["issues"])


def test_live_status_check_rejects_restart_watch_for_wrong_job(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    payload = _status(job_name="paper_core_claude_20260626_resume2")
    payload["commands"]["claude_restart_watch"] = "python infra/paper_queue_job.py restart-watch --job-name paper_core_claude_20260626"
    _write(live, payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is False
    assert any(
        item["message"] == "live status command does not target active Claude job: claude_restart_watch"
        for item in report["issues"]
    )


def test_live_status_check_rejects_restart_watch_not_restart_invocation(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    payload = _status()
    payload["commands"]["claude_restart_watch"] = "python infra/paper_queue_job.py status --job-name paper_core_claude_20260626"
    _write(live, payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is False
    assert any(
        item["message"] == "live status restart-watch command is not a restart-watch invocation"
        for item in report["issues"]
    )


def test_live_status_check_rejects_non_current_baseline_scope(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    payload = _status(completed=10)
    payload["active_baseline"] = {
        "name": "codex_kimi_k2.6",
        "harness": "codex",
        "model": "kimi-k2.6",
        "model_source": "DashScope",
        "codex_in_current_scope": True,
    }
    _write(live, payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is False
    assert any(item["scope"] == "baseline" for item in report["issues"])


def test_live_status_check_rejects_stale_progress(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    live_payload = _status(completed=10)
    fresh_payload = _status(completed=25)
    _write(live, live_payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        max_progress_lag=5,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: fresh_payload,
    )

    assert report["ok"] is False
    assert any("stale by 15 row" in item["message"] for item in report["issues"])


def test_live_status_check_rejects_stale_result_class_accounting_with_same_total(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    live_payload = _status(completed=10)
    fresh_payload = _status(completed=10)
    for scope in ["full", "claude"]:
        live_payload["matrix_progress"][scope]["summary"].update(
            {
                "execution_valid_completed_rows": 10,
                "model_protocol_terminal_rows": 0,
                "execution_invalid_or_unvalidated_rows": 389,
                "duplicate_accounted_expected_rows": 0,
            }
        )
        fresh_payload["matrix_progress"][scope]["summary"].update(
            {
                "execution_valid_completed_rows": 9,
                "model_protocol_terminal_rows": 1,
                "execution_invalid_or_unvalidated_rows": 389,
                "duplicate_accounted_expected_rows": 0,
            }
        )
    _write(live, live_payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: fresh_payload,
    )

    assert report["ok"] is False
    assert any("result-class accounting is stale" in item["message"] for item in report["issues"])


def test_live_status_check_rejects_single_baseline_full_claude_mismatch(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    payload = _status(completed=10)
    payload["matrix_progress"]["full"]["summary"]["completed_rows"] = 9
    _write(live, payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is False
    assert any("inconsistent full and claude completed_rows" in item["message"] for item in report["issues"])


def test_live_status_check_rejects_commands_targeting_old_job(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    payload = _status(
        completed=10,
        job_name="paper_core_claude_20260626_resume2",
        command_job_name="paper_core_claude_20260626",
    )
    _write(live, payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is False
    assert any("does not target active Claude job" in item["message"] for item in report["issues"])


def test_live_status_check_rejects_multiple_running_claude_jobs(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    payload = _status(completed=10, job_name="paper_core_claude_20260626_resume2")
    payload["jobs"].append(
        {
            "job_name": "paper_core_claude_20260626_resume3",
            "observed_status": "running",
            "watcher_pid": 456,
            "watcher_running": True,
            "watcher_latest_sample_age_sec": 60,
            "watcher_latest_completed": 10,
            "watcher_latest_expected": 399,
        }
    )
    _write(live, payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is False
    assert any("multiple Claude queue jobs" in item["message"] for item in report["issues"])


def test_live_status_check_rejects_stale_watcher_sample(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    payload = _status(completed=10)
    payload["jobs"][0]["watcher_latest_sample_age_sec"] = 1200
    _write(live, payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        max_watcher_sample_age_sec=900,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is False
    assert any("watcher progress sample is too old" in item["message"] for item in report["issues"])


def test_live_status_check_rejects_stale_watcher_progress(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    payload = _status(completed=20)
    payload["jobs"][0]["watcher_latest_completed"] = 12
    _write(live, payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        max_watcher_progress_lag=5,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is False
    assert any("watcher progress is stale by 8 row" in item["message"] for item in report["issues"])


def test_live_status_check_default_watcher_lag_allows_fast_control_batches(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    payload = _status(completed=20)
    payload["jobs"][0]["watcher_latest_completed"] = 12
    _write(live, payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is True
    assert not report["issues"]


def test_live_status_check_warns_on_runner_failure_markers(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    payload = _status(completed=10)
    payload["jobs"][0]["failure_marker_count"] = 3
    _write(live, payload)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is True
    assert any(
        item["severity"] == "warning"
        and item["message"] == "paper queue job has runner failure markers that may require resume"
        and item["detail"]["unresolved_failure_marker_count"] == 3
        for item in report["issues"]
    )


def test_live_status_check_rejects_history_latest_sample_mismatch(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    history = tmp_path / "paper_live_status_history.jsonl"
    payload = _status(completed=10)
    _write(live, payload)
    _write_history(history, _history_sample(completed=10, generated_at="2098-12-31T23:59:00"))

    report = check_paper_live_status.build_report(
        live_status_path=live,
        history_path=history,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is False
    assert any("history latest sample is stale" in item["message"] for item in report["issues"])


def test_live_status_check_warns_when_active_history_is_newer_than_live_json(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    history = tmp_path / "paper_live_status_history.jsonl"
    payload = _status(completed=10)
    _write(live, payload)
    _write_history(history, _history_sample(completed=10, generated_at="2099-01-01T00:01:00"))

    report = check_paper_live_status.build_report(
        live_status_path=live,
        history_path=history,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is True
    assert any(
        item["severity"] == "warning" and "trails active history sample" in item["message"]
        for item in report["issues"]
    )


def test_live_status_check_rejects_history_progress_decrease(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    history = tmp_path / "paper_live_status_history.jsonl"
    payload = _status(completed=9)
    _write(live, payload)
    _write_history(
        history,
        _history_sample(completed=10, generated_at="2098-12-31T23:59:00"),
        _history_sample(completed=9, generated_at=payload["generated_at"]),
    )

    report = check_paper_live_status.build_report(
        live_status_path=live,
        history_path=history,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is False
    assert any("history progress decreases" in item["message"] for item in report["issues"])


def test_live_status_check_rejects_history_terminal_result_class_decrease(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    history = tmp_path / "paper_live_status_history.jsonl"
    payload = _status(completed=10)
    for scope in ["full", "claude"]:
        payload["matrix_progress"][scope]["summary"].update(
            {
                "execution_valid_completed_rows": 9,
                "model_protocol_terminal_rows": 1,
                "execution_invalid_or_unvalidated_rows": 389,
                "duplicate_accounted_expected_rows": 0,
            }
        )
    earlier = _history_sample(
        completed=10, generated_at="2098-12-31T23:59:00"
    )
    latest = _history_sample(completed=10, generated_at=payload["generated_at"])
    for scope in ["full", "claude"]:
        earlier[scope].update(
            {
                "execution_valid_completed_rows": 10,
                "model_protocol_terminal_rows": 0,
            }
        )
        latest[scope].update(
            {
                "execution_valid_completed_rows": 9,
                "model_protocol_terminal_rows": 1,
            }
        )
    _write(live, payload)
    _write_history(history, earlier, latest)

    report = check_paper_live_status.build_report(
        live_status_path=live,
        history_path=history,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is False
    assert any(
        item["message"]
        == "paper live status history terminal result-class count decreases"
        for item in report["issues"]
    )


def test_live_status_check_warns_on_history_expected_transition(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    history = tmp_path / "paper_live_status_history.jsonl"
    payload = _status(completed=10)
    _write(live, payload)
    _write_history(
        history,
        _history_sample(completed=10, expected=798, generated_at="2098-12-31T23:59:00"),
        _history_sample(completed=10, expected=399, generated_at=payload["generated_at"]),
    )

    report = check_paper_live_status.build_report(
        live_status_path=live,
        history_path=history,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is True
    assert report["history_expected_transition_count"] == 2
    assert any(item["severity"] == "warning" and "expected row count changed" in item["message"] for item in report["issues"])


def test_live_status_check_ignores_expected_transitions_from_previous_matrix_epoch(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    history = tmp_path / "paper_live_status_history.jsonl"
    payload = _status(completed=10, matrix_id="current")
    _write(live, payload)
    _write_history(
        history,
        _history_sample(completed=50, expected=798, generated_at="2098-12-31T23:59:00", matrix_id="old"),
        _history_sample(completed=10, expected=399, generated_at=payload["generated_at"], matrix_id="current"),
    )

    report = check_paper_live_status.build_report(
        live_status_path=live,
        history_path=history,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is True
    assert report["history_expected_transition_count"] == 0
    assert not any("expected row count changed" in item["message"] for item in report["issues"])
    assert not any("history progress decreases" in item["message"] for item in report["issues"])


def test_live_status_check_still_warns_on_current_matrix_expected_transition(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    history = tmp_path / "paper_live_status_history.jsonl"
    payload = _status(completed=10, matrix_id="current")
    _write(live, payload)
    _write_history(
        history,
        _history_sample(completed=10, expected=398, generated_at="2098-12-31T23:59:00", matrix_id="current"),
        _history_sample(completed=10, expected=399, generated_at=payload["generated_at"], matrix_id="current"),
    )

    report = check_paper_live_status.build_report(
        live_status_path=live,
        history_path=history,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    assert report["ok"] is True
    assert report["history_expected_transition_count"] == 2
    assert any("expected row count changed" in item["message"] for item in report["issues"])


def test_live_status_check_markdown_lists_matrix_progress(tmp_path: Path):
    live = tmp_path / "paper_live_status.json"
    payload = _status(completed=10)
    _write(live, payload)
    report = check_paper_live_status.build_report(
        live_status_path=live,
        now=datetime.fromisoformat("2099-01-01T00:05:00"),
        fresh_status_builder=lambda: payload,
    )

    markdown = check_paper_live_status.render_markdown(report)

    assert "# Paper Live Status Check" in markdown
    assert "ok: `true`" in markdown
    assert "| claude | 10 | 0 | 0 | 0 | 0 | 399 |" in markdown


def test_live_status_check_markdown_uses_na_for_unknown_values():
    markdown = check_paper_live_status.render_markdown(
        {
            "generated_at": "2099-01-01T00:00:00",
            "ok": False,
            "live_age_sec": None,
            "max_age_sec": None,
            "max_progress_lag": None,
            "max_watcher_sample_age_sec": None,
            "max_watcher_progress_lag": None,
            "summary": {},
            "issues": [],
        }
    )

    assert "live_age_sec: `n/a`" in markdown
    assert "max_age_sec: `n/a`" in markdown
    assert "None" not in markdown
