import json
import os
import sys
from pathlib import Path

import pytest

from infra import paper_queue_job


def test_emit_text_replaces_unencodable_console_characters(monkeypatch):
    class GbkStdout:
        encoding = "gbk"

        def __init__(self):
            self.chunks: list[str] = []

        def write(self, text: str):
            text.encode(self.encoding)
            self.chunks.append(text)

    stdout = GbkStdout()
    monkeypatch.setattr(paper_queue_job.sys, "stdout", stdout)

    paper_queue_job.emit_text("bad char: \ufffd", end="")

    assert stdout.chunks == ["bad char: ?"]


def test_default_output_paths_use_harness_specific_claude_files():
    out_json, out_md = paper_queue_job.default_output_paths(
        queue_mode="coalesced",
        harnesses=["claude"],
    )
    post_json, post_md = paper_queue_job.default_output_paths(
        queue_mode="post-run",
        harnesses=["claude"],
    )

    assert out_json.name == "paper_run_execution_claude_plan.json"
    assert out_md.name == "paper_run_execution_claude_plan.md"
    assert post_json.name == "paper_run_execution_claude_post_run.json"
    assert post_md.name == "paper_run_execution_claude_post_run.md"


def test_latest_job_dir_selects_newest_state_file(tmp_path: Path):
    older = tmp_path / "older"
    newer = tmp_path / "newer"
    paper_queue_job.create_job_state(
        job_dir=older,
        job_name="older",
        command=[sys.executable, "-V"],
        metadata={},
    )
    paper_queue_job.create_job_state(
        job_dir=newer,
        job_name="newer",
        command=[sys.executable, "-V"],
        metadata={},
    )
    os.utime(older / "job.json", (100, 100))
    os.utime(newer / "job.json", (200, 200))

    assert paper_queue_job.latest_job_dir(tmp_path) == newer
    assert paper_queue_job.job_dir_from_args(tmp_path, "", default_latest=True) == newer


def test_latest_job_dir_reports_empty_job_root(tmp_path: Path):
    with pytest.raises(SystemExit, match="no paper queue jobs found"):
        paper_queue_job.latest_job_dir(tmp_path)


def test_build_queue_command_carries_execute_and_resume_options(tmp_path: Path):
    queue = tmp_path / "queue.json"
    out_json = tmp_path / "plan.json"
    out_md = tmp_path / "plan.md"

    command = paper_queue_job.build_queue_command(
        queue=queue,
        queue_mode="coalesced",
        harnesses=["claude"],
        start_at="control_claude_all_missing_types",
        execute=True,
        continue_on_failure=True,
        out_json=out_json,
        out_md=out_md,
    )

    assert command[0] == sys.executable
    assert "infra" in command[1]
    assert "--execute" in command
    assert "--continue-on-failure" in command
    assert command[command.index("--harness") + 1] == "claude"
    assert command[command.index("--start-at") + 1] == "control_claude_all_missing_types"
    assert command[command.index("--out-json") + 1] == str(out_json)


def test_run_job_updates_state_and_writes_logs(tmp_path: Path):
    job_dir = tmp_path / "job"
    command = [sys.executable, "-c", "print('hello from job')"]
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="unit_job",
        command=command,
        metadata={"out_json": ""},
    )

    exit_code = paper_queue_job.run_job(job_dir)
    state = json.loads((job_dir / "job.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert state["status"] == "passed"
    assert state["exit_code"] == 0
    assert state["process_pid"]
    assert "hello from job" in (job_dir / "stdout.log").read_text(encoding="utf-8")


def test_inspect_job_reads_execution_plan_summary(tmp_path: Path):
    job_dir = tmp_path / "job"
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "generated_at": "2099-01-01T00:00:00",
                "summary": {
                    "ok": True,
                    "executed_commands": 2,
                    "failed_commands": 0,
                    "pending_commands": 0,
                    "resume_batch": "",
                },
                "readiness_gate": {"requires_kimi": False},
            }
        ),
        encoding="utf-8",
    )
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="unit_job",
        command=[sys.executable, "-V"],
        metadata={"out_json": str(plan), "selected_commands": 2, "selected_missing_rows": 399},
    )
    paper_queue_job.update_job_state(job_dir, status="passed", exit_code=0)

    status = paper_queue_job.inspect_job(job_dir)
    markdown = paper_queue_job.render_status_markdown(status)

    assert status["execution_plan"]["summary"]["executed_commands"] == 2
    assert status["execution_plan"]["fresh_for_job"] is True
    assert status["execution_plan"]["matches_job_execute"] is True
    assert "selected_missing_rows: `399`" in markdown
    assert "fresh_for_job: `true`" in markdown
    assert "matches_job_execute: `true`" in markdown
    assert "executed_commands: `2`" in markdown


def test_running_execute_job_flags_dry_run_execution_plan_mismatch(tmp_path: Path):
    job_dir = tmp_path / "job"
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "generated_at": "2099-01-01T00:00:00",
                "execute": False,
                "summary": {
                    "ok": True,
                    "executed_commands": 0,
                    "failed_commands": 0,
                    "pending_commands": 0,
                    "resume_batch": "attack_claude",
                },
            }
        ),
        encoding="utf-8",
    )
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="running_execute_job",
        command=[sys.executable, "infra/run_paper_queue.py", "--execute"],
        metadata={"out_json": str(plan), "harnesses": ["claude"]},
    )
    paper_queue_job.update_job_state(
        job_dir,
        status="running",
        started_at="2099-01-01T00:00:00",
        supervisor_pid=os.getpid(),
        process_pid=os.getpid(),
    )

    status = paper_queue_job.inspect_job(job_dir, include_progress=False)
    markdown = paper_queue_job.render_status_markdown(status)

    assert status["execution_plan"]["job_execute"] is True
    assert status["execution_plan"]["plan_execute"] is False
    assert status["execution_plan"]["matches_job_execute"] is False
    assert status["next_action"]["action"] == "wait_for_job"
    assert "matches_job_execute: `false`" in markdown
    assert "dry-run artifact" in markdown


def test_inspect_running_job_reports_observed_elapsed_and_log_sizes(tmp_path: Path):
    job_dir = tmp_path / "job"
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="running_job",
        command=[sys.executable, "-V"],
        metadata={"out_json": ""},
    )
    paper_queue_job.update_job_state(
        job_dir,
        status="running",
        started_at="2000-01-01T00:00:00",
        supervisor_pid=os.getpid(),
        process_pid=os.getpid(),
    )
    (job_dir / "stdout.log").write_text("abc\n", encoding="utf-8")

    status = paper_queue_job.inspect_job(job_dir)
    markdown = paper_queue_job.render_status_markdown(status)

    assert status["observed_elapsed_sec"] > 0
    assert status["job"]["elapsed_sec"] == status["observed_elapsed_sec"]
    assert status["log_sizes"]["stdout"] >= 4
    assert "elapsed_sec: `0`" not in markdown
    assert "observed_elapsed_sec:" in markdown
    assert "stdout_bytes:" in markdown


def test_inspect_job_reports_runner_failure_markers(tmp_path: Path):
    job_dir = tmp_path / "job"
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="failure_marker_job",
        command=[sys.executable, "-V"],
        metadata={"out_json": ""},
    )
    (job_dir / "stdout.log").write_text(
        "\n".join(
            [
                "WARNING: [run_harness_case] fatal at line 206: Refusing to copy control workspace overlay outside materialized case:",
                "Microsoft.PowerShell.Core\\FileSystem::\\\\?\\C:\\bench\\runs\\active\\F3_t",
                "ool_mcp_runtime\\f304_hpae\\case_002\\results\\run\\materialized_case\\controls\\clean_workspace",
                "WARNING: [run_harness_case] line: throw \"Refusing to copy control workspace overlay outside materialized case:",
                "$rootToValidate\"",
                "WARNING: [run_paper_control_matrix] failed harness=claude control=no_persist_control",
                "case=active/F3_tool_mcp_runtime/f304_hpae/case_002: ScriptHalted",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    status = paper_queue_job.inspect_job(job_dir, include_progress=False)
    markdown = paper_queue_job.render_status_markdown(status)

    assert status["failure_markers"]["count"] == 1
    marker = status["failure_markers"]["recent"][0]
    assert marker["harness"] == "claude"
    assert marker["control_type"] == "no_persist_control"
    assert marker["case_dir"] == "active/F3_tool_mcp_runtime/f304_hpae/case_002"
    assert marker["error"] == "ScriptHalted"
    assert "Refusing to copy control workspace overlay" in marker["reason"]
    assert "Microsoft.PowerShell.Core\\FileSystem::\\\\?\\C:\\bench\\runs\\active\\F3_tool_mcp_runtime" in marker["reason"]
    assert "$rootToValidate" not in marker["reason"]
    assert status["failure_markers"]["unresolved_count"] == 1
    assert "failure_markers: `1/1`" in markdown
    assert "unresolved_count: `1`" in markdown
    assert "## Failure Markers" in markdown
    assert "active/F3_tool_mcp_runtime/f304_hpae/case_002" in markdown


def test_inspect_job_marks_failure_marker_resolved_when_matrix_row_completed(tmp_path: Path, monkeypatch):
    job_dir = tmp_path / "job"
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="resolved_marker_job",
        command=[sys.executable, "-V"],
        metadata={"out_json": "", "harnesses": ["claude"]},
    )
    (job_dir / "stdout.log").write_text(
        "WARNING: [run_paper_control_matrix] failed harness=claude control=no_persist_control\n"
        "case=active/F3_tool_mcp_runtime/f304_hpae/case_002: ScriptHalted\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        paper_queue_job.check_paper_matrix_progress,
        "build_progress_report",
        lambda **_kwargs: {
            "generated_at": "2099-01-01T00:00:00",
            "complete": True,
            "harnesses": ["claude"],
            "summary": {"expected_rows": 1, "completed_rows": 1, "incomplete_rows": 0},
            "groups": {},
            "issues": [],
            "rows": [
                {
                    "kind": "control",
                    "harness": "claude",
                    "control_type": "no_persist_control",
                    "case_dir": "active/F3_tool_mcp_runtime/f304_hpae/case_002",
                    "completed": True,
                }
            ],
        },
    )

    status = paper_queue_job.inspect_job(job_dir)
    markdown = paper_queue_job.render_status_markdown(status)

    assert status["failure_markers"]["count"] == 1
    assert status["failure_markers"]["unresolved_count"] == 0
    assert status["failure_markers"]["recent"][0]["resolved"] is True
    assert "failure_markers: `0/1`" in markdown
    assert "| 1 | claude | no_persist_control | active/F3_tool_mcp_runtime/f304_hpae/case_002 | ScriptHalted | true |" in markdown


def test_stale_running_job_reports_elapsed_since_start(tmp_path: Path, monkeypatch):
    job_dir = tmp_path / "job"
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="stale_running_job",
        command=[sys.executable, "-V"],
        metadata={"out_json": ""},
    )
    paper_queue_job.update_job_state(
        job_dir,
        status="running",
        started_at="2000-01-01T00:00:00",
        supervisor_pid=123,
        process_pid=456,
    )
    monkeypatch.setattr(paper_queue_job, "pid_running", lambda _pid: False)

    status = paper_queue_job.inspect_job(job_dir, include_progress=False)
    markdown = paper_queue_job.render_status_markdown(status)

    assert status["observed_status"] == "stale"
    assert status["observed_elapsed_sec"] > 0
    assert status["job"]["elapsed_sec"] == status["observed_elapsed_sec"]
    assert "observed_status: `stale`" in markdown
    assert "elapsed_sec: `0`" not in markdown


def test_running_job_markdown_explains_stale_execution_plan(tmp_path: Path):
    job_dir = tmp_path / "job"
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "generated_at": "2000-01-01T00:00:00",
                "summary": {
                    "ok": True,
                    "executed_commands": 0,
                    "failed_commands": 0,
                    "pending_commands": 0,
                },
            }
        ),
        encoding="utf-8",
    )
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="running_job",
        command=[sys.executable, "-V"],
        metadata={"out_json": str(plan), "harnesses": ["claude"]},
    )
    paper_queue_job.update_job_state(
        job_dir,
        status="running",
        started_at="2099-01-01T00:00:00",
        supervisor_pid=os.getpid(),
        process_pid=os.getpid(),
    )

    status = paper_queue_job.inspect_job(job_dir, include_progress=False)
    markdown = paper_queue_job.render_status_markdown(status)

    assert status["execution_plan"]["fresh_for_job"] is False
    assert "execution plan output predates this running job" in markdown


def test_inspect_job_can_include_matrix_progress(tmp_path: Path, monkeypatch):
    job_dir = tmp_path / "job"
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="progress_job",
        command=[sys.executable, "-V"],
        metadata={"out_json": "", "harnesses": ["claude"]},
    )

    def fake_progress_report(**kwargs):
        assert kwargs["harnesses"] == ["claude"]
        return {
            "generated_at": "2099-01-01T00:00:00",
            "complete": False,
            "harnesses": ["claude"],
            "summary": {
                "expected_rows": 399,
                "completed_rows": 7,
                "incomplete_rows": 392,
                "matched_without_oracle_rows": 1,
                "completion_rate": 7 / 399,
            },
            "groups": {},
            "issues": [],
        }

    monkeypatch.setattr(
        paper_queue_job.check_paper_matrix_progress,
        "build_progress_report",
        fake_progress_report,
    )

    status = paper_queue_job.inspect_job(job_dir)
    markdown = paper_queue_job.render_status_markdown(status)

    assert status["matrix_progress"]["summary"]["completed_rows"] == 7
    assert "## Matrix Progress" in markdown
    assert "completed_rows: `7`" in markdown
    assert "scored_rows: `0`" in markdown
    assert "model_protocol_terminal_rows: `0`" in markdown


def test_queue_status_markdown_preserves_null_matrix_completion_rate(
    tmp_path: Path, monkeypatch
):
    job_dir = tmp_path / "job"
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="empty_progress_job",
        command=[sys.executable, "-V"],
        metadata={"out_json": "", "harnesses": ["not-in-plan"]},
    )
    monkeypatch.setattr(
        paper_queue_job.check_paper_matrix_progress,
        "build_progress_report",
        lambda **_kwargs: {
            "generated_at": "2099-01-01T00:00:00",
            "complete": True,
            "harnesses": ["not-in-plan"],
            "summary": {
                "expected_rows": 0,
                "completed_rows": 0,
                "incomplete_rows": 0,
                "completion_rate": None,
            },
            "groups": {},
            "issues": [],
        },
    )

    status = paper_queue_job.inspect_job(job_dir)
    markdown = paper_queue_job.render_status_markdown(status)

    assert status["matrix_progress"]["summary"]["completion_rate"] is None
    assert "completion_rate: `n/a`" in markdown
    assert "completion_rate: `0.000`" not in markdown


def test_next_action_waits_when_job_is_running(tmp_path: Path, monkeypatch):
    job_dir = tmp_path / "job"
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="running_job",
        command=[sys.executable, "-V"],
        metadata={"out_json": "", "harnesses": ["claude"]},
    )
    paper_queue_job.update_job_state(
        job_dir,
        status="running",
        started_at="2000-01-01T00:00:00",
        supervisor_pid=os.getpid(),
        process_pid=os.getpid(),
    )
    monkeypatch.setattr(
        paper_queue_job.check_paper_matrix_progress,
        "build_progress_report",
        lambda **_kwargs: {
            "generated_at": "2099-01-01T00:00:00",
            "complete": False,
            "harnesses": ["claude"],
            "summary": {"expected_rows": 399, "completed_rows": 9, "incomplete_rows": 390},
            "groups": {},
            "issues": [],
        },
    )

    status = paper_queue_job.inspect_job(job_dir)
    markdown = paper_queue_job.render_status_markdown(status)

    assert status["next_action"]["action"] == "wait_for_job"
    assert "paper_queue_job.py" in status["next_action"]["command"]
    assert "## Next Action" in markdown
    assert "wait_for_job" in markdown


def test_next_action_suggests_post_run_when_passed_and_complete(tmp_path: Path, monkeypatch):
    job_dir = tmp_path / "job"
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="complete_job",
        command=[sys.executable, "-V"],
        metadata={
            "out_json": "docs/generated_artifacts/paper_run_execution_claude_plan.json",
            "out_md": "docs/generated_artifacts/paper_run_execution_claude_plan.md",
            "harnesses": ["claude"],
            "queue": "docs/generated_artifacts/paper_run_queue.json",
            "queue_mode": "coalesced",
        },
    )
    paper_queue_job.update_job_state(job_dir, status="passed", exit_code=0)
    monkeypatch.setattr(
        paper_queue_job.check_paper_matrix_progress,
        "build_progress_report",
        lambda **_kwargs: {
            "generated_at": "2099-01-01T00:00:00",
            "complete": True,
            "harnesses": ["claude"],
            "summary": {"expected_rows": 399, "completed_rows": 399, "incomplete_rows": 0},
            "groups": {},
            "issues": [],
        },
    )

    status = paper_queue_job.inspect_job(job_dir)
    command = status["next_action"]["command"]

    assert status["next_action"]["action"] == "run_post_run"
    assert "--queue-mode post-run" in command
    assert "--harness claude" in command
    assert "paper_run_execution_claude_post_run.json" in command


def test_watch_job_once_returns_while_running(tmp_path: Path):
    job_dir = tmp_path / "job"
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="watch_job",
        command=[sys.executable, "-V"],
        metadata={"harnesses": ["claude"]},
    )

    def fake_inspector(_job_dir: Path, tail_lines: int = 20):
        state = paper_queue_job.read_json(job_dir / "job.json")
        return {
            "job": state,
            "observed_status": "running",
            "observed_elapsed_sec": 1,
            "supervisor_running": True,
            "process_running": True,
            "execution_plan": None,
            "matrix_progress": {
                "summary": {"completed_rows": 10, "expected_rows": 399},
                "harnesses": ["claude"],
                "complete": False,
            },
            "log_sizes": {"stdout": 0, "stderr": 0},
            "stdout_tail": "",
            "stderr_tail": "",
            "next_action": {"action": "wait_for_job", "reason": "running", "command": "status"},
        }

    code = paper_queue_job.watch_job(job_dir, once=True, inspector=fake_inspector)

    assert code == 0
    assert "wait_for_job" in (job_dir / "status.md").read_text(encoding="utf-8")


def test_watch_from_args_writes_current_pid(tmp_path: Path, monkeypatch):
    job_root = tmp_path / "jobs"
    job_dir = job_root / "watch_job"
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="watch_job",
        command=[sys.executable, "-V"],
        metadata={"harnesses": ["claude"]},
    )
    (job_dir / "watch.pid").write_text("12345", encoding="utf-8")
    seen: list[Path] = []

    def fake_watch_job(path: Path, **_kwargs):
        seen.append(path)
        return 0

    monkeypatch.setattr(paper_queue_job, "watch_job", fake_watch_job)
    args = type(
        "Args",
        (),
        {
            "job_root": str(job_root),
            "job_name": "watch_job",
            "job_dir": "",
            "poll_sec": 60,
            "max_wait_sec": 0,
            "auto_post_run": False,
            "snapshot_json": "",
            "snapshot_md": "",
            "check_md": "",
            "history_jsonl": "",
            "tail_lines": 20,
            "once": True,
        },
    )()

    code = paper_queue_job.watch_from_args(args)

    assert code == 0
    assert seen == [job_dir]
    assert (job_dir / "watch.pid").read_text(encoding="utf-8") == str(os.getpid())


def test_restart_watcher_rotates_logs_and_launches_check_md(tmp_path: Path, monkeypatch):
    job_dir = tmp_path / "jobs" / "watch_job"
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="watch_job",
        command=[sys.executable, "-V"],
        metadata={"harnesses": ["claude"]},
    )
    (job_dir / "watch.pid").write_text("12345", encoding="utf-8")
    (job_dir / "watch.stdout.log").write_text("old stdout\n", encoding="utf-8")
    (job_dir / "watch.stderr.log").write_text("old stderr\n", encoding="utf-8")
    monkeypatch.setattr(paper_queue_job, "pid_running", lambda _pid: False)
    launched: list[list[str]] = []

    class FakeProcess:
        pid = 67890

    def fake_runner(command, **_kwargs):
        launched.append(command)
        return FakeProcess()

    result = paper_queue_job.restart_watcher(job_dir, poll_sec=123, runner=fake_runner)

    assert result["pid"] == 67890
    assert result["stopped"]["reason"] == "not_running"
    assert (job_dir / "watch.pid").read_text(encoding="utf-8") == "67890"
    assert any(path.endswith(".prev") for path in result["rotated_logs"])
    assert not (job_dir / "watch.stdout.log").read_text(encoding="utf-8")
    assert launched
    command = launched[0]
    assert "watch" in command
    assert "--job-dir" in command
    assert "--check-md" in command
    assert "--history-jsonl" in command


def test_restart_watcher_refuses_non_matching_live_pid(tmp_path: Path, monkeypatch):
    job_dir = tmp_path / "jobs" / "watch_job"
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="watch_job",
        command=[sys.executable, "-V"],
        metadata={"harnesses": ["claude"]},
    )
    (job_dir / "watch.pid").write_text("12345", encoding="utf-8")
    monkeypatch.setattr(paper_queue_job, "pid_running", lambda _pid: True)
    monkeypatch.setattr(paper_queue_job, "process_command_line", lambda _pid: "python other_script.py")

    with pytest.raises(SystemExit, match="non-matching process"):
        paper_queue_job.restart_watcher(job_dir, runner=lambda *_args, **_kwargs: None)


def test_watch_job_auto_post_run_launches_when_complete(tmp_path: Path):
    job_dir = tmp_path / "job"
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="watch_complete",
        command=[sys.executable, "-V"],
        metadata={"harnesses": ["claude"], "queue": "docs/generated_artifacts/paper_run_queue.json"},
    )
    launched: list[list[str]] = []

    def fake_inspector(_job_dir: Path, tail_lines: int = 20):
        state = paper_queue_job.read_json(job_dir / "job.json")
        return {
            "job": state,
            "observed_status": "passed",
            "observed_elapsed_sec": 1,
            "supervisor_running": False,
            "process_running": False,
            "execution_plan": None,
            "matrix_progress": {
                "summary": {"completed_rows": 399, "expected_rows": 399},
                "harnesses": ["claude"],
                "complete": True,
            },
            "log_sizes": {"stdout": 0, "stderr": 0},
            "stdout_tail": "",
            "stderr_tail": "",
            "next_action": {"action": "run_post_run", "reason": "complete", "command": "post"},
        }

    class Proc:
        returncode = 0

    def fake_runner(command, cwd=None, check=False):
        launched.append(command)
        return Proc()

    code = paper_queue_job.watch_job(
        job_dir,
        auto_post_run=True,
        inspector=fake_inspector,
        runner=fake_runner,
    )

    assert code == 0
    assert launched
    assert "--queue-mode" in launched[0]
    assert "post-run" in launched[0]
    assert "--harness" in launched[0]
    assert "claude" in launched[0]


def test_watch_job_does_not_duplicate_existing_post_run(tmp_path: Path):
    job_root = tmp_path / "jobs"
    job_dir = job_root / "job"
    state = paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="watch_complete",
        command=[sys.executable, "-V"],
        metadata={"harnesses": ["claude"], "queue": "docs/generated_artifacts/paper_run_queue.json"},
    )
    post_dir = paper_queue_job.post_run_job_dir_for_state(state, job_root=job_root)
    paper_queue_job.create_job_state(
        job_dir=post_dir,
        job_name=post_dir.name,
        command=[sys.executable, "-V"],
        metadata={},
    )
    launched: list[list[str]] = []

    def fake_inspector(_job_dir: Path, tail_lines: int = 20):
        return {
            "job": state,
            "observed_status": "passed",
            "observed_elapsed_sec": 1,
            "supervisor_running": False,
            "process_running": False,
            "execution_plan": None,
            "matrix_progress": {
                "summary": {"completed_rows": 399, "expected_rows": 399},
                "harnesses": ["claude"],
                "complete": True,
            },
            "log_sizes": {"stdout": 0, "stderr": 0},
            "watcher": {},
            "stdout_tail": "",
            "stderr_tail": "",
            "next_action": {"action": "run_post_run", "reason": "complete", "command": "post"},
        }

    def fake_runner(command, cwd=None, check=False):
        launched.append(command)
        raise AssertionError(command)

    code = paper_queue_job.watch_job(
        job_dir,
        auto_post_run=True,
        inspector=fake_inspector,
        runner=fake_runner,
    )

    assert code == 0
    assert launched == []


def test_live_status_job_table_lists_failure_marker_counts(tmp_path: Path, monkeypatch):
    job_root = tmp_path / "jobs"
    job_dir = job_root / "job"
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="failure_marker_job",
        command=[sys.executable, "-V"],
        metadata={"harnesses": ["claude"]},
    )
    (job_dir / "stdout.log").write_text(
        "WARNING: [run_paper_control_matrix] failed harness=claude control=clean_control\n"
        "case=active/F1_memory_runtime/example/case_001: ScriptHalted\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        paper_queue_job.check_paper_matrix_progress,
        "build_progress_report",
        lambda **_kwargs: {
            "generated_at": "2099-01-01T00:00:00",
            "complete": False,
            "harnesses": ["claude"],
            "summary": {"expected_rows": 399, "completed_rows": 10, "incomplete_rows": 389},
            "groups": {},
            "issues": [],
        },
    )
    (tmp_path / "docs").mkdir()
    monkeypatch.setattr(paper_queue_job, "ROOT", tmp_path)

    status = paper_queue_job.build_live_status(job_root=job_root)
    markdown = paper_queue_job.render_live_status_markdown(status)

    assert "claude_scored_rows:" in markdown
    assert "claude_n_minus_1_rows:" in markdown
    assert "claude_unresolved_invalid_rows:" in markdown

    assert status["jobs"][0]["failure_marker_count"] == 1
    assert status["jobs"][0]["unresolved_failure_marker_count"] == 1
    assert "| Job | Status | Progress | Failures |" in markdown
    assert "| failure_marker_job |" in markdown
    assert "| failure_marker_job | queued | 10/399 | 1/1 |" in markdown


def test_watch_job_can_refresh_live_status_snapshot(tmp_path: Path, monkeypatch):
    job_dir = tmp_path / "jobs" / "job"
    state = paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="watch_snapshot",
        command=[sys.executable, "-V"],
        metadata={"harnesses": ["claude"]},
    )
    out_json = tmp_path / "live.json"
    out_md = tmp_path / "live.md"
    check_md = tmp_path / "live_check.md"
    history = tmp_path / "history.jsonl"
    payload = {
        "generated_at": "2099-01-01T00:00:00",
        "active_baseline": {"name": "claude_code_kimi_k2.6", "harness": "claude", "model": "kimi-k2.6"},
        "matrix_progress": {
            "full": {"summary": {"completed_rows": 0, "expected_rows": 399}},
            "claude": {"complete": False, "summary": {"completed_rows": 21, "expected_rows": 399}},
        },
        "submission_gap": {"submission_ready": False, "errors": [], "warnings": []},
        "jobs": [],
        "commands": {},
    }
    monkeypatch.setattr(paper_queue_job, "build_live_status", lambda **_kwargs: payload)

    def fake_inspector(_job_dir: Path, tail_lines: int = 20):
        return {
            "job": state,
            "observed_status": "running",
            "observed_elapsed_sec": 1,
            "supervisor_running": True,
            "process_running": True,
            "execution_plan": None,
            "matrix_progress": {
                "summary": {"completed_rows": 21, "expected_rows": 399},
                "harnesses": ["claude"],
                "complete": False,
            },
            "log_sizes": {"stdout": 0, "stderr": 0},
            "watcher": {},
            "stdout_tail": "",
            "stderr_tail": "",
            "next_action": {"action": "wait_for_job", "reason": "running", "command": "status"},
        }

    code = paper_queue_job.watch_job(
        job_dir,
        once=True,
        snapshot_json=out_json,
        snapshot_md=out_md,
        check_md=check_md,
        history_jsonl=history,
        inspector=fake_inspector,
    )

    assert code == 0
    assert json.loads(out_json.read_text(encoding="utf-8"))["generated_at"] == "2099-01-01T00:00:00"
    assert "claude_matrix: `21/399`" in out_md.read_text(encoding="utf-8")
    assert "Paper Live Status Check" in check_md.read_text(encoding="utf-8")
    assert json.loads(history.read_text(encoding="utf-8").strip())["claude"]["completed_rows"] == 21


def test_job_list_rows_include_progress_and_next_action(tmp_path: Path, monkeypatch):
    job_root = tmp_path / "jobs"
    job_dir = job_root / "job_a"
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="job_a",
        command=[sys.executable, "-V"],
        metadata={"harnesses": ["claude"]},
    )

    def fake_progress_report(**_kwargs):
        return {
            "generated_at": "2099-01-01T00:00:00",
            "complete": False,
            "harnesses": ["claude"],
            "summary": {"expected_rows": 399, "completed_rows": 13, "incomplete_rows": 386},
            "groups": {},
            "issues": [],
        }

    monkeypatch.setattr(
        paper_queue_job.check_paper_matrix_progress,
        "build_progress_report",
        fake_progress_report,
    )

    rows = paper_queue_job.job_list_rows(job_root)

    assert rows == [
        {
            "job_name": "job_a",
            "observed_status": "queued",
            "exit_code": None,
            "progress_completed": 13,
            "progress_expected": 399,
            "progress_complete": False,
            "next_action": "inspect",
            "failure_marker_count": 0,
            "unresolved_failure_marker_count": 0,
            "watcher_pid": None,
            "watcher_running": False,
            "watcher_rows_per_hour": None,
            "watcher_eta_sec": None,
            "watcher_latest_sample_age_sec": None,
            "watcher_latest_completed": None,
            "watcher_latest_expected": None,
            "job_dir": str(job_dir),
            "updated_at": rows[0]["updated_at"],
        }
    ]


def test_job_list_rows_hides_stale_watcher_rate_and_eta(tmp_path: Path, monkeypatch):
    job_root = tmp_path / "jobs"
    job_dir = job_root / "job_a"
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="job_a",
        command=[sys.executable, "-V"],
        metadata={"harnesses": ["claude"]},
    )

    def fake_inspect_job(_job_dir: Path, tail_lines: int = 0, include_progress: bool = True):
        state = paper_queue_job.read_json(job_dir / "job.json")
        return {
            "job": state,
            "observed_status": "failed",
            "matrix_progress": {
                "complete": False,
                "summary": {"completed_rows": 88, "expected_rows": 399},
            },
            "watcher": {
                "pid": 14976,
                "running": False,
                "progress": {"rows_per_hour": 11.0, "eta_sec": 90000.0},
            },
            "next_action": {"action": "resume_failed_queue"},
        }

    monkeypatch.setattr(paper_queue_job, "inspect_job", fake_inspect_job)

    rows = paper_queue_job.job_list_rows(job_root)

    assert rows[0]["watcher_pid"] == 14976
    assert rows[0]["watcher_running"] is False
    assert rows[0]["watcher_rows_per_hour"] is None
    assert rows[0]["watcher_eta_sec"] is None


def test_list_from_args_prints_progress(tmp_path: Path, monkeypatch, capsys):
    job_root = tmp_path / "jobs"
    job_dir = job_root / "job_a"
    paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="job_a",
        command=[sys.executable, "-V"],
        metadata={"harnesses": ["claude"]},
    )
    monkeypatch.setattr(
        paper_queue_job,
        "job_list_rows",
        lambda *_args, **_kwargs: [
            {
                "job_name": "job_a",
                "observed_status": "running",
                "exit_code": None,
                "progress_completed": 13,
                "progress_expected": 399,
                "progress_complete": False,
                "next_action": "wait_for_job",
                "watcher_pid": None,
                "watcher_running": False,
                "watcher_rows_per_hour": 36.0,
                "watcher_eta_sec": 38300.0,
                "job_dir": str(job_dir),
                "updated_at": "now",
            }
        ],
    )

    args = type("Args", (), {"job_root": str(job_root), "json": False, "no_progress": False})()
    code = paper_queue_job.list_from_args(args)
    output = capsys.readouterr().out

    assert code == 0
    assert "progress=13/399" in output
    assert "next=wait_for_job" in output
    assert "rate=36.0r/h" in output
    assert "eta=38300.0s" in output


def test_list_from_args_prints_missing_rate_and_eta_as_na(tmp_path: Path, monkeypatch, capsys):
    job_root = tmp_path / "jobs"
    job_dir = job_root / "job_a"
    monkeypatch.setattr(
        paper_queue_job,
        "job_list_rows",
        lambda *_args, **_kwargs: [
            {
                "job_name": "job_a",
                "observed_status": "running",
                "exit_code": None,
                "progress_completed": 13,
                "progress_expected": 399,
                "progress_complete": False,
                "next_action": "wait_for_job",
                "watcher_pid": None,
                "watcher_running": False,
                "watcher_rows_per_hour": None,
                "watcher_eta_sec": None,
                "job_dir": str(job_dir),
                "updated_at": "now",
            }
        ],
    )

    args = type("Args", (), {"job_root": str(job_root), "json": False, "no_progress": False})()
    code = paper_queue_job.list_from_args(args)
    output = capsys.readouterr().out

    assert code == 0
    assert "rate=n/a\t" in output
    assert "eta=n/a\t" in output
    assert "n/ar/h" not in output
    assert "n/as" not in output


def test_watcher_info_reads_pid_and_log_tail(tmp_path: Path, monkeypatch):
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    (job_dir / "watch.pid").write_text(str(os.getpid()), encoding="utf-8")
    (job_dir / "watch.stdout.log").write_text(
        "first\n"
        "[paper_queue_job.watch] 2026-06-26T08:41:07 status=running action=wait_for_job progress=13/399\n"
        "[paper_queue_job.watch] 2026-06-26T08:46:07 status=running action=wait_for_job progress=16/399\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(paper_queue_job, "pid_running", lambda pid: pid == os.getpid())
    monkeypatch.setattr(
        paper_queue_job,
        "process_command_line",
        lambda pid: f"{sys.executable} infra\\paper_queue_job.py watch --job-name {job_dir.name}",
    )

    info = paper_queue_job.watcher_info(job_dir, tail_lines=1)

    assert info["pid"] == os.getpid()
    assert info["pid_alive"] is True
    assert info["running"] is True
    assert info["stdout_bytes"] > 0
    assert info["progress"]["sample_count"] == 2
    assert info["progress"]["latest_completed"] == 16
    assert info["progress"]["latest_expected"] == 399
    assert info["progress"]["rows_per_hour"] == 36.0
    assert info["progress"]["eta_sec"] == 38300.0
    assert "progress=16/399" in info["stdout_tail"]


def test_watcher_info_rejects_reused_pid_with_unrelated_command(tmp_path: Path, monkeypatch):
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    (job_dir / "watch.pid").write_text("14976", encoding="utf-8")
    monkeypatch.setattr(paper_queue_job, "pid_running", lambda pid: pid == 14976)
    monkeypatch.setattr(
        paper_queue_job,
        "process_command_line",
        lambda pid: "git.exe config --null --get core.fsmonitor",
    )

    info = paper_queue_job.watcher_info(job_dir)

    assert info["pid"] == 14976
    assert info["pid_alive"] is True
    assert info["running"] is False


def test_watcher_info_uses_rotated_stdout_logs_for_progress_rate(tmp_path: Path):
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    (job_dir / "watch.pid").write_text(str(os.getpid()), encoding="utf-8")
    (job_dir / "watch.stdout.log.20990101000000.prev").write_text(
        "[paper_queue_job.watch] 2099-01-01T00:00:00 status=running action=wait_for_job progress=10/399\n",
        encoding="utf-8",
    )
    (job_dir / "watch.stdout.log").write_text(
        "[paper_queue_job.watch] 2099-01-01T00:10:00 status=running action=wait_for_job progress=14/399\n",
        encoding="utf-8",
    )

    info = paper_queue_job.watcher_info(job_dir, tail_lines=1)

    assert info["progress"]["sample_count"] == 2
    assert info["progress"]["latest_completed"] == 14
    assert info["progress"]["rows_per_hour"] == 24.0
    assert info["progress"]["eta_sec"] == 57750.0


def test_watch_progress_samples_ignore_unmatched_lines(tmp_path: Path):
    log_path = tmp_path / "watch.stdout.log"
    log_path.write_text(
        "noise\n"
        "[paper_queue_job.watch] 2026-06-26T08:41:07 status=running action=wait_for_job progress=13/399\n",
        encoding="utf-8",
    )

    samples = paper_queue_job.watch_progress_samples(log_path)

    assert len(samples) == 1
    assert samples[0]["completed"] == 13


def test_render_status_includes_watcher_section(tmp_path: Path):
    job_dir = tmp_path / "job"
    state = paper_queue_job.create_job_state(
        job_dir=job_dir,
        job_name="watcher_render",
        command=[sys.executable, "-V"],
        metadata={},
    )
    status = {
        "job": state,
        "observed_status": "queued",
        "observed_elapsed_sec": 0,
        "supervisor_running": False,
        "process_running": False,
        "execution_plan": None,
        "matrix_progress": None,
        "log_sizes": {"stdout": 0, "stderr": 0},
        "watcher": {
            "pid": os.getpid(),
            "running": True,
            "stdout_bytes": 7,
            "stderr_bytes": 0,
            "progress": {
                "sample_count": 2,
                "latest_completed": 16,
                "latest_expected": 399,
                "latest_sample_age_sec": 1,
                "rows_per_hour": 36.0,
                "eta_sec": 38300.0,
            },
            "stdout_tail": "watch",
            "stderr_tail": "",
        },
        "stdout_tail": "",
        "stderr_tail": "",
        "next_action": {"action": "inspect", "reason": "x", "command": "status"},
    }

    markdown = paper_queue_job.render_status_markdown(status)

    assert "## Watcher" in markdown
    assert "running: `true`" in markdown
    assert "rows_per_hour: `36.0`" in markdown
    assert "eta_sec: `38300.0`" in markdown
    assert "watch" in markdown


def test_render_live_status_markdown_contains_jobs_and_blockers():
    status = {
        "generated_at": "2099-01-01T00:00:00",
        "active_baseline": {"name": "claude_code_kimi_k2.6", "harness": "claude", "model": "kimi-k2.6"},
        "matrix_progress": {
            "full": {"summary": {"completed_rows": 0, "expected_rows": 399}},
            "claude": {
                "complete": False,
                "summary": {"completed_rows": 19, "expected_rows": 399},
            },
        },
        "submission_gap": {
            "submission_ready": False,
            "errors": [{"scope": "readiness", "message": "missing key"}],
            "warnings": [],
        },
        "jobs": [
            {
                "job_name": "paper_core_claude_20260626",
                "observed_status": "running",
                "progress_completed": 19,
                "progress_expected": 399,
                "next_action": "wait_for_job",
                "watcher_pid": 32744,
                "watcher_running": True,
                "watcher_latest_sample_age_sec": 12.5,
                "watcher_rows_per_hour": 35.0,
                "watcher_eta_sec": 39000.0,
            }
        ],
        "commands": {"job_list": "python infra/paper_queue_job.py list"},
    }

    markdown = paper_queue_job.render_live_status_markdown(status)

    assert "# Paper Live Status" in markdown
    assert "active_baseline: `claude_code_kimi_k2.6`" in markdown
    assert "claude_matrix: `19/399`" in markdown
    assert "codex_matrix" not in markdown
    assert "paper_core_claude_20260626" in markdown
    assert "Sample Age" in markdown
    assert "12.5s" in markdown
    assert "35.0r/h" in markdown
    assert "39000.0s" in markdown
    assert "`readiness`: missing key" in markdown


def test_build_live_status_watch_command_refreshes_snapshot_and_history(monkeypatch):
    monkeypatch.setattr(paper_queue_job, "job_list_rows", lambda *_args, **_kwargs: [])
    seen_harnesses = []

    def fake_progress_report(**kwargs):
        seen_harnesses.append(tuple(kwargs.get("harnesses") or ["full"]))
        expected = 399
        return {
            "generated_at": "2099-01-01T00:00:00",
            "matrix_id": "m",
            "case_set": "core",
            "harnesses": kwargs.get("harnesses", []),
            "complete": False,
            "summary": {"completed_rows": 0, "expected_rows": expected},
            "issues": [],
        }

    monkeypatch.setattr(
        paper_queue_job.check_paper_matrix_progress,
        "build_progress_report",
        fake_progress_report,
    )
    monkeypatch.setattr(
        paper_queue_job,
        "load_submission_gap_summary",
        lambda: {"submission_ready": False, "errors": [], "warnings": []},
    )

    status = paper_queue_job.build_live_status()
    command = status["commands"]["claude_watch"]

    assert status["active_baseline"]["name"] == "claude_code_kimi_k2.6"
    assert status["command_policy"]["watch_or_execute_required"] is True
    assert ("codex",) not in seen_harnesses
    assert "--snapshot-json" in command
    assert "--snapshot-md" in command
    assert "--check-md" in command
    assert "--history-jsonl" in command
    assert "paper_live_status_check.md" in command
    assert "paper_live_status_history.jsonl" in command
    assert "restart-watch" in status["commands"]["claude_restart_watch"]
    assert "--harness claude" in status["commands"]["claude_execute"]
    assert "--queue-mode post-run" in status["commands"]["claude_post_run"]


def test_build_live_status_omits_execution_commands_when_matrix_complete(monkeypatch):
    monkeypatch.setattr(paper_queue_job, "job_list_rows", lambda *_args, **_kwargs: [])

    def fake_progress_report(**kwargs):
        return {
            "generated_at": "2099-01-01T00:00:00",
            "matrix_id": "m",
            "case_set": "core",
            "harnesses": kwargs.get("harnesses", []),
            "complete": True,
            "summary": {"completed_rows": 399, "expected_rows": 399},
            "issues": [],
        }

    monkeypatch.setattr(
        paper_queue_job.check_paper_matrix_progress,
        "build_progress_report",
        fake_progress_report,
    )
    monkeypatch.setattr(
        paper_queue_job,
        "load_submission_gap_summary",
        lambda: {"submission_ready": False, "errors": [], "warnings": []},
    )

    status = paper_queue_job.build_live_status()
    markdown = paper_queue_job.render_live_status_markdown(status)

    assert status["command_policy"]["matrix_complete"] is True
    assert status["command_policy"]["watch_or_execute_required"] is False
    assert "live_snapshot" in status["commands"]
    assert "claude_watch" not in status["commands"]
    assert "claude_restart_watch" not in status["commands"]
    assert "claude_execute" not in status["commands"]
    assert "claude_post_run" not in status["commands"]
    assert "no watcher restart or queued benchmark execution is required" in markdown
    assert "--execute" not in markdown
    assert "restart-watch" not in markdown


def test_build_live_status_uses_single_claude_progress_snapshot(monkeypatch):
    monkeypatch.setattr(paper_queue_job, "job_list_rows", lambda *_args, **_kwargs: [])
    calls = []

    def fake_progress_report(**kwargs):
        calls.append(kwargs)
        return {
            "generated_at": "2099-01-01T00:00:00",
            "matrix_id": "m",
            "case_set": "core",
            "harnesses": kwargs.get("harnesses", []),
            "complete": False,
            "summary": {"completed_rows": 17, "expected_rows": 399},
            "issues": [],
        }

    monkeypatch.setattr(
        paper_queue_job.check_paper_matrix_progress,
        "build_progress_report",
        fake_progress_report,
    )
    monkeypatch.setattr(
        paper_queue_job,
        "load_submission_gap_summary",
        lambda: {"submission_ready": False, "errors": [], "warnings": []},
    )

    status = paper_queue_job.build_live_status()

    assert [call.get("harnesses") for call in calls] == [["claude"]]
    assert status["matrix_progress"]["full"]["summary"] == status["matrix_progress"]["claude"]["summary"]


def test_build_live_status_commands_follow_running_resume_job(monkeypatch):
    monkeypatch.setattr(
        paper_queue_job,
        "job_list_rows",
        lambda *_args, **_kwargs: [
            {
                "job_name": "paper_core_claude_20260626",
                "observed_status": "failed",
                "updated_at": "2099-01-01T00:00:00",
            },
            {
                "job_name": "paper_core_claude_20260626_resume",
                "observed_status": "running",
                "updated_at": "2099-01-01T00:05:00",
            },
        ],
    )

    def fake_progress_report(**kwargs):
        return {
            "generated_at": "2099-01-01T00:00:00",
            "matrix_id": "m",
            "case_set": "core",
            "harnesses": kwargs.get("harnesses", []),
            "complete": False,
            "summary": {"completed_rows": 82, "expected_rows": 399},
            "issues": [],
        }

    monkeypatch.setattr(
        paper_queue_job.check_paper_matrix_progress,
        "build_progress_report",
        fake_progress_report,
    )
    monkeypatch.setattr(
        paper_queue_job,
        "load_submission_gap_summary",
        lambda: {"submission_ready": False, "errors": [], "warnings": []},
    )

    status = paper_queue_job.build_live_status()

    assert "--job-name paper_core_claude_20260626_resume" in status["commands"]["claude_status"]
    assert "--job-name paper_core_claude_20260626_resume" in status["commands"]["claude_watch"]
    assert "--job-name paper_core_claude_20260626 --queue" in status["commands"]["claude_execute"]


def test_build_live_status_complete_matrix_status_targets_passed_resume_job(monkeypatch):
    monkeypatch.setattr(
        paper_queue_job,
        "job_list_rows",
        lambda *_args, **_kwargs: [
            {
                "job_name": "paper_core_claude_20260626",
                "observed_status": "failed",
                "updated_at": "2099-01-01T00:00:00",
            },
            {
                "job_name": "paper_core_claude_20260626_resume",
                "observed_status": "failed",
                "updated_at": "2099-01-01T00:05:00",
            },
            {
                "job_name": "paper_core_claude_20260626_resume2",
                "observed_status": "passed",
                "updated_at": "2099-01-01T00:10:00",
            },
        ],
    )

    def fake_progress_report(**kwargs):
        return {
            "generated_at": "2099-01-01T00:00:00",
            "matrix_id": "m",
            "case_set": "core",
            "harnesses": kwargs.get("harnesses", []),
            "complete": True,
            "summary": {"completed_rows": 399, "expected_rows": 399},
            "issues": [],
        }

    monkeypatch.setattr(
        paper_queue_job.check_paper_matrix_progress,
        "build_progress_report",
        fake_progress_report,
    )
    monkeypatch.setattr(
        paper_queue_job,
        "load_submission_gap_summary",
        lambda: {"submission_ready": False, "errors": [], "warnings": []},
    )

    status = paper_queue_job.build_live_status()

    assert "--job-name paper_core_claude_20260626_resume2" in status["commands"]["claude_status"]
    assert "claude_watch" not in status["commands"]
    assert "claude_execute" not in status["commands"]


def test_render_live_status_complete_matrix_suppresses_stale_job_next_actions():
    status = {
        "generated_at": "2099-01-01T00:00:00",
        "active_baseline": {"name": "claude_code_kimi_k2.6", "harness": "claude", "model": "kimi-k2.6"},
        "matrix_progress": {
            "full": {"summary": {"completed_rows": 399, "expected_rows": 399}},
            "claude": {"complete": True, "summary": {"completed_rows": 399, "expected_rows": 399}},
        },
        "submission_gap": {"submission_ready": False, "errors": [], "warnings": []},
        "command_policy": {
            "matrix_complete": True,
            "watch_or_execute_required": False,
            "note": "Matrix is complete; no watcher restart or queued benchmark execution is required.",
        },
        "jobs": [
            {
                "job_name": "paper_core_claude_20260626",
                "observed_status": "failed",
                "progress_completed": 399,
                "progress_expected": 399,
                "failure_marker_count": 0,
                "unresolved_failure_marker_count": 0,
                "next_action": "resume_failed_queue",
            },
            {
                "job_name": "paper_core_claude_20260626_resume2",
                "observed_status": "passed",
                "progress_completed": 399,
                "progress_expected": 399,
                "failure_marker_count": 10,
                "unresolved_failure_marker_count": 0,
                "next_action": "run_post_run",
            },
        ],
        "commands": {"job_list": "python infra/paper_queue_job.py list"},
    }

    markdown = paper_queue_job.render_live_status_markdown(status)

    assert "superseded_by_completed_matrix" in markdown
    assert "| paper_core_claude_20260626_resume2 | passed | 399/399 | 0/10 | complete |" in markdown
    assert "resume_failed_queue" not in markdown
    assert "run_post_run" not in markdown


def test_render_live_status_uses_na_for_unknown_submission_readiness():
    markdown = paper_queue_job.render_live_status_markdown(
        {
            "generated_at": "2099-01-01T00:00:00",
            "matrix_progress": {"full": {}, "claude": {}},
            "submission_gap": {
                "submission_ready": None,
                "errors": [],
                "warnings": [],
            },
            "jobs": [],
            "commands": {},
        }
    )

    assert "submission_ready: `n/a`" in markdown
    assert "None" not in markdown


def test_snapshot_from_args_writes_outputs(tmp_path: Path, monkeypatch, capsys):
    out_json = tmp_path / "live.json"
    out_md = tmp_path / "live.md"
    check_md = tmp_path / "live_check.md"
    history = tmp_path / "live.jsonl"
    payload = {
        "generated_at": "2099-01-01T00:00:00",
        "active_baseline": {"name": "claude_code_kimi_k2.6", "harness": "claude", "model": "kimi-k2.6"},
        "matrix_progress": {
            "full": {"summary": {"completed_rows": 0, "expected_rows": 399}},
            "claude": {"complete": False, "summary": {"completed_rows": 19, "expected_rows": 399}},
        },
        "submission_gap": {"submission_ready": False, "errors": [], "warnings": []},
        "jobs": [],
        "commands": {},
    }
    monkeypatch.setattr(paper_queue_job, "build_live_status", lambda **_kwargs: payload)

    args = type(
        "Args",
        (),
        {
            "job_root": str(tmp_path / "jobs"),
            "out_json": str(out_json),
            "out_md": str(out_md),
            "check_md": str(check_md),
            "history_jsonl": str(history),
            "json": False,
            "no_progress": False,
        },
    )()
    code = paper_queue_job.snapshot_from_args(args)
    output = capsys.readouterr().out

    assert code == 0
    assert json.loads(out_json.read_text(encoding="utf-8"))["generated_at"] == "2099-01-01T00:00:00"
    assert "Paper Live Status" in out_md.read_text(encoding="utf-8")
    assert "Paper Live Status Check" in check_md.read_text(encoding="utf-8")
    history_rows = [json.loads(line) for line in history.read_text(encoding="utf-8").splitlines()]
    assert history_rows[0]["claude"]["completed_rows"] == 19
    assert history_rows[0]["active_baseline"]["name"] == "claude_code_kimi_k2.6"
    assert "claude_matrix" in output
    assert "codex_matrix" not in output


def test_append_live_status_history_writes_compact_records(tmp_path: Path):
    history = tmp_path / "history.jsonl"
    status = {
        "generated_at": "2099-01-01T00:00:00",
        "active_baseline": {"name": "claude_code_kimi_k2.6", "harness": "claude", "model": "kimi-k2.6"},
        "matrix_progress": {
            "full": {"summary": {"completed_rows": 0, "expected_rows": 399}},
            "claude": {"summary": {"completed_rows": 22, "expected_rows": 399}},
        },
        "jobs": [
            {
                "job_name": "job",
                "observed_status": "running",
                "progress_completed": 22,
                "progress_expected": 399,
                "next_action": "wait_for_job",
                "watcher_pid": 11380,
                "watcher_running": True,
                "watcher_rows_per_hour": None,
                "watcher_eta_sec": None,
            }
        ],
        "submission_gap": {"submission_ready": False, "errors": [{"x": 1}], "warnings": []},
    }

    paper_queue_job.append_live_status_history(history, status)

    row = json.loads(history.read_text(encoding="utf-8").strip())
    assert row["generated_at"] == "2099-01-01T00:00:00"
    assert row["claude"]["completed_rows"] == 22
    assert row["active_baseline"]["name"] == "claude_code_kimi_k2.6"
    assert row["jobs"][0]["watcher_pid"] == 11380
    assert row["submission_error_count"] == 1
