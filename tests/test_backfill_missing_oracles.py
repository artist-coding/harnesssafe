import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from infra import backfill_missing_oracles


def _touch(path: Path, *, mtime: datetime) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}\n", encoding="utf-8")
    ts = mtime.timestamp()
    path.touch()
    path.write_text("{}\n", encoding="utf-8")
    import os

    os.utime(path, (ts, ts))


def test_backfill_classifies_old_missing_oracle_as_eligible(tmp_path: Path):
    now = datetime.fromisoformat("2099-01-01T00:10:00")
    run = tmp_path / "runs/active/case/results/run1"
    old = now - timedelta(seconds=900)
    _touch(run / "trace.jsonl", mtime=old)
    _touch(run / "case.json", mtime=old)
    rows = [{"case_dir": "active/case", "run_dir": "runs/active/case/results/run1", "has_oracle": False}]

    plan = backfill_missing_oracles.classify_missing_rows(
        rows,
        root=tmp_path,
        now=now,
        min_age_sec=600,
    )

    assert plan[0]["eligible"] is True
    assert plan[0]["reason"] == "ready"


def test_backfill_skips_recent_missing_oracle(tmp_path: Path):
    now = datetime.fromisoformat("2099-01-01T00:10:00")
    run = tmp_path / "runs/active/case/results/run1"
    recent = now - timedelta(seconds=30)
    _touch(run / "trace.jsonl", mtime=recent)
    _touch(run / "case.json", mtime=recent)
    rows = [{"case_dir": "active/case", "run_dir": "runs/active/case/results/run1", "has_oracle": False}]

    plan = backfill_missing_oracles.classify_missing_rows(
        rows,
        root=tmp_path,
        now=now,
        min_age_sec=600,
    )

    assert plan[0]["eligible"] is False
    assert plan[0]["reason"] == "result directory is too recent"


def test_backfill_dry_run_does_not_execute(tmp_path: Path):
    row = {
        "case_dir": "active/case",
        "run_dir": "runs/active/case/results/run1",
        "eligible": True,
        "reason": "ready",
    }

    result = backfill_missing_oracles.execute_plan([row], root=tmp_path, execute=False)

    assert result[0]["action"] == "would_analyze"
    assert "analyze_trace.py" in result[0]["command"]


def test_backfill_execute_uses_runner(tmp_path: Path):
    calls = []
    run = tmp_path / "runs/active/case/results/run1"
    run.mkdir(parents=True)
    row = {
        "case_dir": "active/case",
        "run_dir": "runs/active/case/results/run1",
        "eligible": True,
        "reason": "ready",
    }

    def fake_runner(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="ok\n", stderr="")

    result = backfill_missing_oracles.execute_plan(
        [row],
        root=tmp_path,
        execute=True,
        runner=fake_runner,
    )

    assert result[0]["action"] == "analyzed"
    assert result[0]["exit_code"] == 0
    assert calls


def test_backfill_report_can_fail_on_pending_eligible_rows(monkeypatch, tmp_path: Path):
    run = tmp_path / "runs/active/case/results/run1"
    old = datetime.now() - timedelta(seconds=900)
    _touch(run / "trace.jsonl", mtime=old)
    _touch(run / "case.json", mtime=old)

    monkeypatch.setattr(
        backfill_missing_oracles,
        "collect_rows",
        lambda **kwargs: [{"case_dir": "active/case", "run_dir": "runs/active/case/results/run1", "has_oracle": False}],
    )

    report = backfill_missing_oracles.build_report(
        label="paper_core_20260625",
        harnesses=["claude"],
        root=tmp_path,
        min_age_sec=600,
        fail_on_eligible=True,
    )

    assert report["ok"] is False
    assert report["summary"]["eligible_rows"] == 1
    assert report["summary"]["pending_eligible_rows"] == 1
    assert "pending_eligible_rows: `1`" in backfill_missing_oracles.render_markdown(report)


def test_backfill_report_fail_on_eligible_allows_successful_execute(monkeypatch, tmp_path: Path):
    run = tmp_path / "runs/active/case/results/run1"
    old = datetime.now() - timedelta(seconds=900)
    _touch(run / "trace.jsonl", mtime=old)
    _touch(run / "case.json", mtime=old)

    monkeypatch.setattr(
        backfill_missing_oracles,
        "collect_rows",
        lambda **kwargs: [{"case_dir": "active/case", "run_dir": "runs/active/case/results/run1", "has_oracle": False}],
    )

    def fake_runner(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="ok\n", stderr="")

    report = backfill_missing_oracles.build_report(
        label="paper_core_20260625",
        harnesses=["claude"],
        root=tmp_path,
        min_age_sec=600,
        execute=True,
        fail_on_eligible=True,
        runner=fake_runner,
    )

    assert report["ok"] is True
    assert report["summary"]["eligible_rows"] == 1
    assert report["summary"]["pending_eligible_rows"] == 0
    assert report["summary"]["analyzed_rows"] == 1
