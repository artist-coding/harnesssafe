"""Validate the live paper experiment status snapshot."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

try:
    from infra import paper_queue_job
except ModuleNotFoundError:  # direct `python infra/check_paper_live_status.py`
    import paper_queue_job  # type: ignore


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LIVE_STATUS = ROOT / "docs" / "paper_live_status.json"
DEFAULT_LIVE_STATUS_HISTORY = ROOT / "docs" / "paper_live_status_history.jsonl"
DEFAULT_MAX_PROGRESS_LAG = 5
DEFAULT_MAX_WATCHER_PROGRESS_LAG = 20
REQUIRED_PROGRESS_KEYS = ["full", "claude"]
RESULT_CLASS_PROGRESS_FIELDS = [
    "execution_valid_completed_rows",
    "model_protocol_terminal_rows",
    "execution_invalid_or_unvalidated_rows",
    "duplicate_accounted_expected_rows",
]
REQUIRED_COMMANDS = [
    "job_list",
    "claude_status",
    "live_snapshot",
]
ACTION_COMMANDS = [
    "claude_watch",
    "claude_restart_watch",
    "claude_execute",
    "claude_post_run",
]
EXPECTED_BASELINE = {
    "name": "claude_code_kimi_k2.6",
    "harness": "claude",
    "model": "kimi-k2.6",
    "model_source": "Claude Code runtime default",
    "codex_in_current_scope": False,
}


def issue(severity: str, scope: str, message: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"severity": severity, "scope": scope, "message": message, "detail": detail or {}}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def progress_summary(status: dict[str, Any], key: str) -> dict[str, Any]:
    progress = status.get("matrix_progress", {}).get(key, {})
    summary = progress.get("summary", {}) if isinstance(progress, dict) else {}
    return summary if isinstance(summary, dict) else {}


def claude_matrix_complete(status: dict[str, Any]) -> bool:
    policy = status.get("command_policy", {})
    if isinstance(policy, dict) and policy.get("matrix_complete") is True:
        return True
    progress = status.get("matrix_progress", {}).get("claude", {})
    if isinstance(progress, dict) and progress.get("complete") is True:
        return True
    summary = progress_summary(status, "claude")
    expected = int_or_zero(summary.get("expected_rows"))
    completed = int_or_zero(summary.get("completed_rows"))
    return expected > 0 and completed >= expected


def history_progress_summary(sample: dict[str, Any], key: str) -> dict[str, Any]:
    progress = sample.get(key, {}) if isinstance(sample, dict) else {}
    return progress if isinstance(progress, dict) else {}


def int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def int_or_zero(value: Any) -> int:
    parsed = int_or_none(value)
    return parsed if parsed is not None else 0


def display_optional(value: Any) -> Any:
    return "n/a" if value is None else value


def live_matrix_id(live_status: dict[str, Any]) -> str:
    progress = live_status.get("matrix_progress", {})
    for key in ["claude", "full"]:
        value = progress.get(key, {}) if isinstance(progress, dict) else {}
        if isinstance(value, dict) and value.get("matrix_id"):
            return str(value.get("matrix_id") or "")
    return ""


def history_sample_matrix_id(sample: dict[str, Any]) -> str:
    return str(sample.get("matrix_id") or "")


def baseline_checks(live_status: dict[str, Any]) -> list[dict[str, Any]]:
    baseline = live_status.get("active_baseline", {})
    issues: list[dict[str, Any]] = []
    for key, expected in EXPECTED_BASELINE.items():
        actual = baseline.get(key)
        if actual != expected:
            issues.append(
                issue(
                    "error",
                    "baseline",
                    f"live status active baseline field is not current Claude/Kimi scope: {key}",
                    {"expected": expected, "actual": actual},
                )
            )
    return issues


def active_running_claude_jobs(live_status: dict[str, Any]) -> list[str]:
    jobs = []
    for row in live_status.get("jobs", []):
        name = str(row.get("job_name") or "")
        if (
            row.get("observed_status") == "running"
            and name.startswith(paper_queue_job.DEFAULT_CLAUDE_JOB_NAME)
            and "_post" not in name
        ):
            jobs.append(name)
    return jobs


def active_running_claude_job(live_status: dict[str, Any]) -> str:
    jobs = active_running_claude_jobs(live_status)
    return jobs[0] if len(jobs) == 1 else ""


def command_targets_job(command: str, job_name: str) -> bool:
    if not command or not job_name:
        return False
    normalized = command.replace("/", "\\")
    return f"--job-name {job_name}" in command or f"--job-name={job_name}" in command or f"\\{job_name}" in normalized


def command_checks(live_status: dict[str, Any]) -> list[dict[str, Any]]:
    commands = live_status.get("commands", {})
    matrix_complete = claude_matrix_complete(live_status)
    issues: list[dict[str, Any]] = []
    required_commands = list(REQUIRED_COMMANDS)
    if not matrix_complete:
        required_commands.extend(ACTION_COMMANDS)
    for name in required_commands:
        value = str(commands.get(name, ""))
        if not value:
            issues.append(issue("error", "commands", f"live status missing command: {name}"))
            continue
        if name == "live_snapshot" and "snapshot" not in value:
            issues.append(
                issue(
                    "error",
                    "commands",
                    "live status snapshot command is not a snapshot invocation",
                    {"command": value},
                )
            )
        if name in {"claude_execute", "claude_post_run"} and "--harness claude" not in value:
            issues.append(
                issue(
                    "error",
                    "commands",
                    f"live status command is not scoped to claude harness: {name}",
                    {"command": value},
                )
            )
        if name == "claude_watch" and "--check-md" not in value:
            issues.append(
                issue(
                    "error",
                    "commands",
                    "live status watcher command does not refresh paper_live_status_check.md",
                    {"command": value},
                )
            )
        if name == "claude_restart_watch" and "restart-watch" not in value:
            issues.append(
                issue(
                    "error",
                    "commands",
                    "live status restart-watch command is not a restart-watch invocation",
                    {"command": value},
                )
            )
    if matrix_complete:
        policy = live_status.get("command_policy", {})
        if isinstance(policy, dict) and policy.get("watch_or_execute_required") is not False:
            issues.append(
                issue(
                    "error",
                    "commands",
                    "completed live status command policy does not mark watcher/execution as unnecessary",
                    {"command_policy": policy},
                )
            )
        for name in ACTION_COMMANDS:
            if commands.get(name):
                issues.append(
                    issue(
                        "error",
                        "commands",
                        f"completed live status should not include action command: {name}",
                        {"command": str(commands.get(name, ""))},
                    )
                )
    active_job = active_running_claude_job(live_status)
    if active_job:
        target_commands = ["claude_status"]
        if not matrix_complete:
            target_commands.extend(["claude_watch", "claude_restart_watch"])
        for name in target_commands:
            value = str(commands.get(name, ""))
            if not command_targets_job(value, active_job):
                issues.append(
                    issue(
                        "error",
                        "commands",
                        f"live status command does not target active Claude job: {name}",
                        {"command": value, "active_job": active_job},
                    )
                )
    return issues


def job_topology_checks(live_status: dict[str, Any]) -> list[dict[str, Any]]:
    active_jobs = active_running_claude_jobs(live_status)
    if len(active_jobs) <= 1:
        return []
    return [
        issue(
            "error",
            "jobs",
            "multiple Claude queue jobs are running for the active baseline",
            {"job_names": active_jobs},
        )
    ]


def progress_checks(
    live_status: dict[str, Any],
    fresh_status: dict[str, Any],
    *,
    max_progress_lag: int,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    baseline = live_status.get("active_baseline", {})
    full_live = progress_summary(live_status, "full")
    claude_live = progress_summary(live_status, "claude")
    if baseline.get("codex_in_current_scope") is False and full_live and claude_live:
        for field in ["completed_rows", "expected_rows", *RESULT_CLASS_PROGRESS_FIELDS]:
            if field in RESULT_CLASS_PROGRESS_FIELDS and field not in full_live and field not in claude_live:
                continue
            if full_live.get(field) != claude_live.get(field):
                issues.append(
                    issue(
                        "error",
                        "matrix_progress",
                        f"single-baseline live status has inconsistent full and claude {field}",
                        {"full": full_live.get(field), "claude": claude_live.get(field)},
                    )
                )
    for key in REQUIRED_PROGRESS_KEYS:
        live = progress_summary(live_status, key)
        fresh = progress_summary(fresh_status, key)
        if not live:
            issues.append(issue("error", "matrix_progress", f"live status missing {key} matrix progress"))
            continue
        if not fresh:
            issues.append(issue("warning", "matrix_progress", f"fresh scan missing {key} matrix progress"))
            continue
        live_expected = live.get("expected_rows")
        fresh_expected = fresh.get("expected_rows")
        if live_expected != fresh_expected:
            issues.append(
                issue(
                    "error",
                    "matrix_progress",
                    f"{key} expected row count is stale",
                    {"live": live_expected, "fresh": fresh_expected},
                )
            )
        for field in RESULT_CLASS_PROGRESS_FIELDS:
            if field not in live and field not in fresh:
                continue
            if live.get(field) != fresh.get(field):
                issues.append(
                    issue(
                        "error",
                        "matrix_progress",
                        f"{key} result-class accounting is stale: {field}",
                        {"live": live.get(field), "fresh": fresh.get(field)},
                    )
                )
        live_completed = int(live.get("completed_rows") or 0)
        fresh_completed = int(fresh.get("completed_rows") or 0)
        if live_completed > fresh_completed:
            issues.append(
                issue(
                    "error",
                    "matrix_progress",
                    f"{key} live progress is ahead of fresh scan",
                    {"live": live_completed, "fresh": fresh_completed},
                )
            )
        lag = fresh_completed - live_completed
        if lag > max_progress_lag:
            issues.append(
                issue(
                    "error",
                    "matrix_progress",
                    f"{key} live progress is stale by {lag} row(s)",
                    {"live": live_completed, "fresh": fresh_completed, "max_progress_lag": max_progress_lag},
                )
            )
    return issues


def watcher_checks(
    live_status: dict[str, Any],
    *,
    max_watcher_sample_age_sec: int,
    max_watcher_progress_lag: int,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    claude_summary = progress_summary(live_status, "claude")
    for row in live_status.get("jobs", []):
        if row.get("observed_status") == "running" and row.get("watcher_running") is not True:
            issues.append(
                issue(
                    "error",
                    "watcher",
                    "running paper queue job has no live watcher",
                    {"job_name": row.get("job_name"), "watcher_pid": row.get("watcher_pid")},
                )
            )
            continue
        if row.get("observed_status") != "running":
            continue
        sample_age = row.get("watcher_latest_sample_age_sec")
        if sample_age is None:
            issues.append(
                issue(
                    "error",
                    "watcher",
                    "running paper queue job watcher has no progress sample",
                    {"job_name": row.get("job_name"), "watcher_pid": row.get("watcher_pid")},
                )
            )
            continue
        if float(sample_age) > max_watcher_sample_age_sec:
            issues.append(
                issue(
                    "error",
                    "watcher",
                    "running paper queue job watcher progress sample is too old",
                    {
                        "job_name": row.get("job_name"),
                        "watcher_pid": row.get("watcher_pid"),
                        "sample_age_sec": sample_age,
                        "max_watcher_sample_age_sec": max_watcher_sample_age_sec,
                    },
                )
            )
        watcher_completed = int_or_none(row.get("watcher_latest_completed"))
        watcher_expected = int_or_none(row.get("watcher_latest_expected"))
        if watcher_completed is None or watcher_expected is None:
            issues.append(
                issue(
                    "error",
                    "watcher",
                    "running paper queue job watcher has no parsed progress counters",
                    {
                        "job_name": row.get("job_name"),
                        "watcher_pid": row.get("watcher_pid"),
                        "watcher_latest_completed": row.get("watcher_latest_completed"),
                        "watcher_latest_expected": row.get("watcher_latest_expected"),
                    },
                )
            )
            continue
        live_completed = int_or_none(row.get("progress_completed"))
        live_expected = int_or_none(row.get("progress_expected"))
        if live_completed is None:
            live_completed = int_or_none(claude_summary.get("completed_rows"))
        if live_expected is None:
            live_expected = int_or_none(claude_summary.get("expected_rows"))
        if live_expected is not None and watcher_expected != live_expected:
            issues.append(
                issue(
                    "error",
                    "watcher",
                    "running paper queue job watcher expected row count differs from live progress",
                    {
                        "job_name": row.get("job_name"),
                        "watcher_pid": row.get("watcher_pid"),
                        "watcher_expected": watcher_expected,
                        "live_expected": live_expected,
                    },
                )
            )
        if live_completed is None:
            continue
        lag = live_completed - watcher_completed
        if lag > max_watcher_progress_lag:
            issues.append(
                issue(
                    "error",
                    "watcher",
                    f"running paper queue job watcher progress is stale by {lag} row(s)",
                    {
                        "job_name": row.get("job_name"),
                        "watcher_pid": row.get("watcher_pid"),
                        "watcher_completed": watcher_completed,
                        "live_completed": live_completed,
                        "max_watcher_progress_lag": max_watcher_progress_lag,
                    },
                )
            )
    return issues


def failure_marker_checks(live_status: dict[str, Any]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for row in live_status.get("jobs", []):
        count = int_or_zero(row.get("unresolved_failure_marker_count", row.get("failure_marker_count")))
        if count <= 0:
            continue
        issues.append(
            issue(
                "warning",
                "jobs",
                "paper queue job has runner failure markers that may require resume",
                {
                    "job_name": row.get("job_name"),
                    "observed_status": row.get("observed_status"),
                    "failure_marker_count": int_or_zero(row.get("failure_marker_count")),
                    "unresolved_failure_marker_count": count,
                },
            )
        )
    return issues


def history_checks(
    live_status: dict[str, Any],
    history_path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    report = {
        "history_path": str(history_path),
        "history_latest_generated_at": "",
        "history_sample_count": 0,
        "history_expected_transition_count": 0,
    }
    if not history_path.is_file():
        issues.append(
            issue(
                "error",
                "live_status_history",
                "paper live status history JSONL does not exist",
                {"path": str(history_path)},
            )
        )
        return report, issues

    lines = [line.strip() for line in history_path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    report["history_sample_count"] = len(lines)
    if not lines:
        issues.append(issue("error", "live_status_history", "paper live status history JSONL is empty"))
        return report, issues

    parsed_samples: list[tuple[int, dict[str, Any]]] = []
    for index, line in enumerate(lines, start=1):
        try:
            sample = json.loads(line)
        except json.JSONDecodeError as exc:
            issues.append(
                issue(
                    "error",
                    "live_status_history",
                    "could not parse paper live status history sample",
                    {"line": index, "error": str(exc)},
                )
            )
            continue
        if not isinstance(sample, dict):
            issues.append(
                issue(
                    "error",
                    "live_status_history",
                    "paper live status history sample is not an object",
                    {"line": index, "type": type(sample).__name__},
                )
            )
            continue
        parsed_samples.append((index, sample))

    if not parsed_samples:
        return report, issues

    latest_line, latest_sample = parsed_samples[-1]
    latest_generated_at = str(latest_sample.get("generated_at") or "")
    live_generated_at = str(live_status.get("generated_at") or "")
    report["history_latest_generated_at"] = latest_generated_at
    if live_generated_at and latest_generated_at != live_generated_at:
        live_dt = parse_timestamp(live_generated_at)
        history_dt = parse_timestamp(latest_generated_at)
        history_newer_than_live = bool(live_dt and history_dt and history_dt > live_dt)
        active_job_names = active_running_claude_jobs(live_status)
        if history_newer_than_live and active_job_names:
            issues.append(
                issue(
                    "warning",
                    "live_status_history",
                    "paper live status JSON trails active history sample",
                    {
                        "line": latest_line,
                        "live_generated_at": live_generated_at,
                        "history_latest_generated_at": latest_generated_at,
                        "active_jobs": active_job_names,
                    },
                )
            )
        else:
            issues.append(
                issue(
                    "error",
                    "live_status_history",
                    "paper live status history latest sample is stale for paper live status JSON",
                    {
                        "line": latest_line,
                        "live_generated_at": live_generated_at,
                        "history_latest_generated_at": latest_generated_at,
                    },
                )
            )

    current_matrix_id = live_matrix_id(live_status)
    expected_transitions: list[dict[str, Any]] = []
    previous_sample: dict[str, Any] | None = None
    for index, sample in parsed_samples:
        if previous_sample:
            previous_matrix_id = history_sample_matrix_id(previous_sample)
            current_sample_matrix_id = history_sample_matrix_id(sample)
            if current_matrix_id and (
                previous_matrix_id != current_matrix_id or current_sample_matrix_id != current_matrix_id
            ):
                previous_sample = sample
                continue
            for scope in REQUIRED_PROGRESS_KEYS:
                previous_progress = history_progress_summary(previous_sample, scope)
                current_progress = history_progress_summary(sample, scope)
                previous_completed = int_or_zero(previous_progress.get("completed_rows"))
                current_completed = int_or_zero(current_progress.get("completed_rows"))
                previous_expected = int_or_zero(previous_progress.get("expected_rows"))
                current_expected = int_or_zero(current_progress.get("expected_rows"))
                if current_completed < previous_completed:
                    issues.append(
                        issue(
                            "error",
                            "live_status_history",
                            "paper live status history progress decreases",
                            {
                                "line": index,
                                "scope": scope,
                                "previous_completed": previous_completed,
                                "current_completed": current_completed,
                            },
                        )
                    )
                for field in [
                    "execution_valid_completed_rows",
                    "model_protocol_terminal_rows",
                ]:
                    if field not in previous_progress or field not in current_progress:
                        continue
                    previous_value = int_or_zero(previous_progress.get(field))
                    current_value = int_or_zero(current_progress.get(field))
                    if current_value < previous_value:
                        issues.append(
                            issue(
                                "error",
                                "live_status_history",
                                "paper live status history terminal result-class count decreases",
                                {
                                    "line": index,
                                    "scope": scope,
                                    "field": field,
                                    "previous": previous_value,
                                    "current": current_value,
                                },
                            )
                        )
                if current_expected != previous_expected:
                    expected_transitions.append(
                        {
                            "line": index,
                            "scope": scope,
                            "matrix_id": current_sample_matrix_id,
                            "previous_expected": previous_expected,
                            "current_expected": current_expected,
                        }
                    )
        previous_sample = sample

    for scope in REQUIRED_PROGRESS_KEYS:
        latest_expected = int_or_zero(history_progress_summary(latest_sample, scope).get("expected_rows"))
        live_expected = int_or_zero(progress_summary(live_status, scope).get("expected_rows"))
        if live_expected and latest_expected and latest_expected != live_expected:
            issues.append(
                issue(
                    "error",
                    "live_status_history",
                    "paper live status history latest expected rows differ from paper live status JSON",
                    {"scope": scope, "history_latest_expected": latest_expected, "live_expected": live_expected},
                )
            )
    report["history_expected_transition_count"] = len(expected_transitions)
    if expected_transitions:
        issues.append(
            issue(
                "warning",
                "live_status_history",
                "paper live status history expected row count changed across samples",
                {"transitions": expected_transitions[:5]},
            )
        )
    return report, issues


def build_report(
    *,
    live_status_path: Path = DEFAULT_LIVE_STATUS,
    history_path: Path | None = None,
    max_age_sec: int = 900,
    max_progress_lag: int = DEFAULT_MAX_PROGRESS_LAG,
    max_watcher_sample_age_sec: int = 900,
    max_watcher_progress_lag: int = DEFAULT_MAX_WATCHER_PROGRESS_LAG,
    now: datetime | None = None,
    fresh_status_builder: Callable[[], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    if not live_status_path.is_file():
        return {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "ok": False,
            "live_status_path": str(live_status_path),
            "issues": [issue("error", "live_status", "live status JSON does not exist")],
            "summary": {},
        }

    live_status = read_json(live_status_path)
    history_report: dict[str, Any] = {}
    generated_at = str(live_status.get("generated_at", ""))
    generated_dt = parse_timestamp(generated_at)
    current_time = now or datetime.now()
    age_sec = None
    if generated_dt:
        age_sec = round(max(0.0, (current_time - generated_dt).total_seconds()), 3)
        if age_sec > max_age_sec:
            issues.append(
                issue(
                    "error",
                    "live_status",
                    "live status snapshot is too old",
                    {"age_sec": age_sec, "max_age_sec": max_age_sec},
                )
            )
    else:
        issues.append(issue("error", "live_status", "live status has invalid generated_at", {"generated_at": generated_at}))

    builder = fresh_status_builder or (lambda: paper_queue_job.build_live_status())
    fresh_status = builder()
    issues.extend(baseline_checks(live_status))
    issues.extend(progress_checks(live_status, fresh_status, max_progress_lag=max_progress_lag))
    issues.extend(job_topology_checks(live_status))
    issues.extend(command_checks(live_status))
    issues.extend(
        watcher_checks(
            live_status,
            max_watcher_sample_age_sec=max_watcher_sample_age_sec,
            max_watcher_progress_lag=max_watcher_progress_lag,
        )
    )
    issues.extend(failure_marker_checks(live_status))
    if history_path is not None:
        history_report, history_issues = history_checks(live_status, history_path)
        issues.extend(history_issues)

    errors = [item for item in issues if item.get("severity") == "error"]
    warnings = [item for item in issues if item.get("severity") == "warning"]
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "ok": not errors,
        "live_status_path": str(live_status_path),
        "live_generated_at": generated_at,
        "live_age_sec": age_sec,
        "max_age_sec": max_age_sec,
        "max_progress_lag": max_progress_lag,
        "max_watcher_sample_age_sec": max_watcher_sample_age_sec,
        "max_watcher_progress_lag": max_watcher_progress_lag,
        **history_report,
        "summary": {
            "error_count": len(errors),
            "warning_count": len(warnings),
            "issue_count": len(issues),
            "full": progress_summary(live_status, "full"),
            "claude": progress_summary(live_status, "claude"),
        },
        "issues": issues,
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    lines = [
        "# Paper Live Status Check",
        "",
        f"- generated_at: `{report.get('generated_at', '')}`",
        f"- ok: `{str(report.get('ok', False)).lower()}`",
        f"- live_status_path: `{report.get('live_status_path', '')}`",
        f"- live_generated_at: `{report.get('live_generated_at', '')}`",
        f"- live_age_sec: `{display_optional(report.get('live_age_sec'))}`",
        f"- max_age_sec: `{display_optional(report.get('max_age_sec'))}`",
        f"- max_progress_lag: `{display_optional(report.get('max_progress_lag'))}`",
        f"- max_watcher_sample_age_sec: `{display_optional(report.get('max_watcher_sample_age_sec'))}`",
        f"- max_watcher_progress_lag: `{display_optional(report.get('max_watcher_progress_lag'))}`",
        f"- history_path: `{report.get('history_path', '')}`",
        f"- history_latest_generated_at: `{report.get('history_latest_generated_at', '')}`",
        f"- history_sample_count: `{report.get('history_sample_count', 0)}`",
        f"- history_expected_transition_count: `{report.get('history_expected_transition_count', 0)}`",
        f"- errors: `{summary.get('error_count', 0)}`",
        f"- warnings: `{summary.get('warning_count', 0)}`",
        "",
        "## Matrix Progress",
        "",
        "| Scope | Accounted | Scored | N-1 | Unresolved invalid | Duplicate accounted | Expected |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for key in REQUIRED_PROGRESS_KEYS:
        item = summary.get(key, {})
        lines.append(
            f"| {key} | {item.get('completed_rows', 0)} | "
            f"{item.get('execution_valid_completed_rows', 0)} | "
            f"{item.get('model_protocol_terminal_rows', 0)} | "
            f"{item.get('execution_invalid_or_unvalidated_rows', 0)} | "
            f"{item.get('duplicate_accounted_expected_rows', 0)} | "
            f"{item.get('expected_rows', 0)} |"
        )
    lines += ["", "## Issues", ""]
    if report.get("issues"):
        lines += ["| Severity | Scope | Message |", "| --- | --- | --- |"]
        for item in report["issues"]:
            lines.append(f"| {item.get('severity')} | {item.get('scope')} | {item.get('message')} |")
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate docs/generated_artifacts/paper_live_status.json.")
    parser.add_argument("--live-status", default=str(DEFAULT_LIVE_STATUS))
    parser.add_argument("--history-jsonl", default=str(DEFAULT_LIVE_STATUS_HISTORY))
    parser.add_argument("--max-age-sec", type=int, default=900)
    parser.add_argument("--max-progress-lag", type=int, default=DEFAULT_MAX_PROGRESS_LAG)
    parser.add_argument("--max-watcher-sample-age-sec", type=int, default=900)
    parser.add_argument("--max-watcher-progress-lag", type=int, default=DEFAULT_MAX_WATCHER_PROGRESS_LAG)
    parser.add_argument("--out", default="")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--require-ok", action="store_true")
    args = parser.parse_args()

    report = build_report(
        live_status_path=Path(args.live_status),
        history_path=Path(args.history_jsonl) if args.history_jsonl else None,
        max_age_sec=args.max_age_sec,
        max_progress_lag=args.max_progress_lag,
        max_watcher_sample_age_sec=args.max_watcher_sample_age_sec,
        max_watcher_progress_lag=args.max_watcher_progress_lag,
    )
    output = json.dumps(report, indent=2, ensure_ascii=False) if args.json else render_markdown(report)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output if output.endswith("\n") else output + "\n", encoding="utf-8")
    else:
        print(output, end="" if output.endswith("\n") else "\n")
    if args.require_ok and not report.get("ok"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
