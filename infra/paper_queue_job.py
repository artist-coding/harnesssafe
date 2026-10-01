"""Launch and inspect long-running paper queue jobs."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import signal
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

try:
    from infra import check_paper_matrix_progress, run_paper_queue
except ModuleNotFoundError:  # direct `python infra/paper_queue_job.py`
    import check_paper_matrix_progress  # type: ignore
    import run_paper_queue  # type: ignore


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_JOB_ROOT = ROOT / "runs" / "_artifacts" / "paper_queue_jobs"
DEFAULT_QUEUE = ROOT / "docs" / "generated_artifacts" / "paper_run_queue.json"
DEFAULT_LIVE_STATUS_JSON = ROOT / "docs" / "generated_artifacts" / "paper_live_status.json"
DEFAULT_LIVE_STATUS_MD = ROOT / "docs" / "generated_artifacts" / "paper_live_status.md"
DEFAULT_LIVE_STATUS_CHECK = ROOT / "docs" / "generated_artifacts" / "paper_live_status_check.md"
DEFAULT_LIVE_STATUS_HISTORY = ROOT / "docs" / "generated_artifacts" / "paper_live_status_history.jsonl"
DEFAULT_CLAUDE_JOB_NAME = "paper_core_claude_20260626"

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
STILL_ACTIVE = 259
PROCESS_COMMAND_TIMEOUT_SEC = 10
WATCH_PROGRESS_RE = re.compile(
    r"^\[paper_queue_job\.watch\]\s+"
    r"(?P<at>\S+)\s+status=(?P<status>\S+)\s+action=(?P<action>\S+)\s+"
    r"progress=(?P<completed>\d+)/(?P<expected>\d+)"
)
RUN_FAILURE_RE = re.compile(
    r"failed harness=(?P<harness>\S+)(?:\s+control=(?P<control_type>\S+))?"
)
RUN_FAILURE_CASE_RE = re.compile(r"^case=(?P<case_dir>\S+):\s*(?P<error>.+)$")
HARNESS_FATAL_RE = re.compile(r"\[run_harness_case\]\s+fatal at line \d+:\s*(?P<reason>.+)$")


def timestamp() -> str:
    return datetime.now().isoformat(timespec="seconds")


def relpath(path: Path, root: Path = ROOT) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def safe_name(value: str) -> str:
    token = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value.strip())
    return token.strip("._-") or "paper_queue_job"


def emit_text(text: str, *, end: str = "\n") -> None:
    payload = f"{text}{end}"
    try:
        sys.stdout.write(payload)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        safe_payload = payload.encode(encoding, errors="replace").decode(encoding, errors="replace")
        sys.stdout.write(safe_payload)


def display_optional(value: Any) -> Any:
    return "n/a" if value is None else value


def format_optional_decimal(value: Any, digits: int = 3) -> str:
    """Format an optional numeric value without turning absence into zero."""

    if value is None:
        return "n/a"
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return "n/a"


def split_cli_values(values: Iterable[str] | None) -> list[str]:
    return run_paper_queue.split_cli_values(list(values or []))


def default_output_paths(
    *,
    queue_mode: str,
    harnesses: list[str],
    out_json: str = "",
    out_md: str = "",
) -> tuple[Path, Path]:
    if out_json and out_md:
        return Path(out_json), Path(out_md)

    selected = [item.lower() for item in harnesses]
    if len(selected) == 1:
        harness = safe_name(selected[0])
        stem = f"paper_run_execution_{harness}_post_run" if queue_mode == "post-run" else f"paper_run_execution_{harness}_plan"
    else:
        stem = "paper_run_execution_plan"

    default_json = ROOT / "docs" / "generated_artifacts" / f"{stem}.json"
    default_md = ROOT / "docs" / "generated_artifacts" / f"{stem}.md"
    return Path(out_json) if out_json else default_json, Path(out_md) if out_md else default_md


def build_queue_command(
    *,
    queue: Path = DEFAULT_QUEUE,
    queue_mode: str = "serial",
    batches: list[str] | None = None,
    harnesses: list[str] | None = None,
    start_at: str = "",
    include_post_run: bool = False,
    execute: bool = False,
    continue_on_failure: bool = False,
    skip_readiness_check: bool = False,
    out_json: Path | None = None,
    out_md: Path | None = None,
) -> list[str]:
    command = [
        sys.executable,
        str(ROOT / "infra" / "run_paper_queue.py"),
        "--queue",
        str(queue),
        "--queue-mode",
        queue_mode,
    ]
    for batch in batches or []:
        command.extend(["--batch", batch])
    for harness in harnesses or []:
        command.extend(["--harness", harness])
    if start_at:
        command.extend(["--start-at", start_at])
    if include_post_run:
        command.append("--include-post-run")
    if execute:
        command.append("--execute")
    if continue_on_failure:
        command.append("--continue-on-failure")
    if skip_readiness_check:
        command.append("--skip-readiness-check")
    if out_json:
        command.extend(["--out-json", str(out_json)])
    if out_md:
        command.extend(["--out-md", str(out_md)])
    return command


def command_line(args: list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(args)
    return " ".join(subprocess.list2cmdline([arg]) for arg in args)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def job_state_path(job_dir: Path) -> Path:
    return job_dir / "job.json"


def create_job_state(
    *,
    job_dir: Path,
    job_name: str,
    command: list[str],
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    job_dir.mkdir(parents=True, exist_ok=True)
    state = {
        "job_name": job_name,
        "job_dir": str(job_dir),
        "created_at": timestamp(),
        "updated_at": timestamp(),
        "status": "queued",
        "exit_code": None,
        "supervisor_pid": None,
        "process_pid": None,
        "started_at": "",
        "finished_at": "",
        "elapsed_sec": 0,
        "command": command,
        "command_line": command_line(command),
        "logs": {
            "stdout": str(job_dir / "stdout.log"),
            "stderr": str(job_dir / "stderr.log"),
            "launcher_stdout": str(job_dir / "launcher.stdout.log"),
            "launcher_stderr": str(job_dir / "launcher.stderr.log"),
        },
        "metadata": metadata or {},
    }
    write_json(job_state_path(job_dir), state)
    return state


def update_job_state(job_dir: Path, **updates: Any) -> dict[str, Any]:
    state = read_json(job_state_path(job_dir))
    state.update(updates)
    state["updated_at"] = timestamp()
    write_json(job_state_path(job_dir), state)
    return state


def pid_running(pid: int | None) -> bool:
    if not pid:
        return False
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return False
        return code.value == STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def process_command_line(pid: int | None) -> str:
    if not pid:
        return ""
    if os.name != "nt":
        cmdline = Path(f"/proc/{int(pid)}/cmdline")
        try:
            return cmdline.read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except OSError:
            return ""

    try:
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"(Get-CimInstance Win32_Process -Filter 'ProcessId = {int(pid)}').CommandLine",
            ],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=PROCESS_COMMAND_TIMEOUT_SEC,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (proc.stdout or "").strip()


def command_tokens(command_line_text: str) -> list[str]:
    return [token.strip("\"'") for token in re.findall(r'"[^"]*"|\'[^\']*\'|\S+', command_line_text)]


def watcher_command_matches(command_line_text: str, job_dir: Path) -> bool:
    tokens = command_tokens(command_line_text)
    lowered = [token.lower().replace("/", "\\") for token in tokens]
    if "watch" not in lowered:
        return False
    if not any(token.endswith("paper_queue_job.py") for token in lowered):
        return False

    expected_job_name = job_dir.name.lower()
    expected_job_dir = str(job_dir.resolve()).lower().replace("/", "\\")
    for index, token in enumerate(lowered):
        if token == "--job-name" and index + 1 < len(lowered) and lowered[index + 1] == expected_job_name:
            return True
        if token.startswith("--job-name=") and token.split("=", 1)[1] == expected_job_name:
            return True
        if token == "--job-dir" and index + 1 < len(lowered) and lowered[index + 1] == expected_job_dir:
            return True
        if token.startswith("--job-dir=") and token.split("=", 1)[1] == expected_job_dir:
            return True
    return False


def parse_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def elapsed_since(started_at: str) -> float:
    started = parse_timestamp(started_at)
    if started is None:
        return 0
    return round(max(0.0, (datetime.now() - started).total_seconds()), 3)


def file_size(path: Path) -> int:
    try:
        return path.stat().st_size if path.is_file() else 0
    except OSError:
        return 0


def int_or_zero(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def run_job(job_dir: Path) -> int:
    state = update_job_state(
        job_dir,
        status="running",
        supervisor_pid=os.getpid(),
        started_at=timestamp(),
    )
    logs = state.get("logs", {})
    stdout_path = Path(logs.get("stdout") or job_dir / "stdout.log")
    stderr_path = Path(logs.get("stderr") or job_dir / "stderr.log")
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)

    start = time.monotonic()
    command = [str(item) for item in state.get("command", [])]
    try:
        with stdout_path.open("ab") as stdout, stderr_path.open("ab") as stderr:
            proc = subprocess.Popen(
                command,
                cwd=ROOT,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                close_fds=True,
            )
            update_job_state(job_dir, process_pid=proc.pid, process_started_at=timestamp())
            exit_code = proc.wait()
    except Exception as exc:  # pragma: no cover - defensive runtime guard
        stderr_path.write_text(str(exc) + "\n", encoding="utf-8")
        exit_code = 1

    elapsed = round(time.monotonic() - start, 3)
    status = "passed" if exit_code == 0 else "failed"
    update_job_state(
        job_dir,
        status=status,
        exit_code=exit_code,
        finished_at=timestamp(),
        elapsed_sec=elapsed,
    )
    return exit_code


def read_tail(path: Path, lines: int = 30) -> str:
    if not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    return "\n".join(text.splitlines()[-lines:])


def collapse_failure_reason(parts: list[str]) -> str:
    if not parts:
        return ""
    head = parts[0].strip()
    continuation = [part.strip() for part in parts[1:] if part.strip()]
    if not continuation:
        return head
    if any("\\" in part or "::" in part for part in continuation):
        return f"{head} {''.join(continuation)}".strip()
    return " ".join([head, *continuation]).strip()


def marker_resolution_key(marker: dict[str, Any]) -> str:
    return "|".join(
        [
            str(marker.get("harness") or ""),
            str(marker.get("control_type") or ""),
            str(marker.get("case_dir") or ""),
        ]
    )


def completed_failure_marker_keys(progress_report: dict[str, Any]) -> list[str]:
    keys: set[str] = set()
    for row in progress_report.get("rows", []):
        if not row.get("completed"):
            continue
        if str(row.get("kind") or "") != "control":
            continue
        keys.add(
            "|".join(
                [
                    str(row.get("harness") or ""),
                    str(row.get("control_type") or ""),
                    str(row.get("case_dir") or ""),
                ]
            )
        )
    return sorted(keys)


def scan_failure_markers(path: Path, *, limit: int = 200) -> dict[str, Any]:
    if not path.is_file():
        return {"count": 0, "recent": []}
    markers: list[dict[str, Any]] = []
    pending: dict[str, Any] | None = None
    last_reason = ""
    reason_parts: list[str] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        line = raw_line.strip()
        fatal = HARNESS_FATAL_RE.search(line)
        if fatal:
            reason_parts = [fatal.group("reason").strip()]
            last_reason = collapse_failure_reason(reason_parts)
            continue
        if reason_parts and line and not line.startswith(("WARNING:", "[", "=", "case=")):
            reason_parts.append(line)
            last_reason = collapse_failure_reason(reason_parts)
            continue
        if reason_parts and line.startswith("WARNING:"):
            reason_parts = []
        failure = RUN_FAILURE_RE.search(line)
        if failure:
            pending = {
                "line": line_number,
                "harness": failure.group("harness"),
                "control_type": failure.group("control_type") or "",
                "reason": last_reason,
            }
            continue
        case_match = RUN_FAILURE_CASE_RE.match(line)
        if pending and case_match:
            marker = {
                **pending,
                "case_dir": case_match.group("case_dir"),
                "error": case_match.group("error"),
            }
            if not marker.get("reason"):
                marker["reason"] = marker["error"]
            markers.append(marker)
            pending = None
    recent = markers[-limit:]
    return {"count": len(markers), "recent": recent, "unresolved_count": len(recent)}


def annotate_failure_marker_resolution(markers: dict[str, Any], progress: dict[str, Any] | None) -> dict[str, Any]:
    completed_keys = set((progress or {}).get("completed_failure_marker_keys", []))
    recent: list[dict[str, Any]] = []
    unresolved_count = 0
    for marker in markers.get("recent", []):
        resolved = bool(completed_keys and marker_resolution_key(marker) in completed_keys)
        updated = dict(marker)
        updated["resolved"] = resolved
        recent.append(updated)
        if not resolved:
            unresolved_count += 1
    return {
        **markers,
        "recent": recent,
        "unresolved_count": unresolved_count,
    }


def watch_progress_samples(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    samples: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = WATCH_PROGRESS_RE.match(line.strip())
        if not match:
            continue
        at = parse_timestamp(match.group("at"))
        if at is None:
            continue
        samples.append(
            {
                "at": match.group("at"),
                "status": match.group("status"),
                "action": match.group("action"),
                "completed": int(match.group("completed")),
                "expected": int(match.group("expected")),
            }
        )
    return samples


def watch_progress_samples_for_job(job_dir: Path) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, int, int]] = set()
    for path in sorted(job_dir.glob("watch.stdout.log*")):
        for sample in watch_progress_samples(path):
            key = (
                str(sample.get("at", "")),
                str(sample.get("status", "")),
                str(sample.get("action", "")),
                int(sample.get("completed", 0)),
                int(sample.get("expected", 0)),
            )
            if key in seen:
                continue
            seen.add(key)
            samples.append(sample)

    samples.sort(key=lambda sample: parse_timestamp(str(sample.get("at") or "")) or datetime.min)
    return samples


def watch_progress_metrics(samples: list[dict[str, Any]]) -> dict[str, Any]:
    if not samples:
        return {
            "sample_count": 0,
            "latest_completed": None,
            "latest_expected": None,
            "latest_sample_age_sec": None,
            "rows_per_hour": None,
            "eta_sec": None,
        }
    latest = samples[-1]
    latest_at = parse_timestamp(str(latest.get("at") or ""))
    latest_age = round(max(0.0, (datetime.now() - latest_at).total_seconds()), 3) if latest_at else None
    rate_start = None
    for sample in reversed(samples[:-1]):
        if int(sample.get("completed", 0)) < int(latest.get("completed", 0)):
            rate_start = sample
            break
    rows_per_hour = None
    eta_sec = None
    if rate_start:
        start_at = parse_timestamp(str(rate_start.get("at") or ""))
        if start_at and latest_at:
            elapsed = max(0.0, (latest_at - start_at).total_seconds())
            delta = int(latest.get("completed", 0)) - int(rate_start.get("completed", 0))
            if elapsed > 0 and delta > 0:
                rows_per_hour = delta / elapsed * 3600
                remaining = max(0, int(latest.get("expected", 0)) - int(latest.get("completed", 0)))
                eta_sec = remaining / (rows_per_hour / 3600) if rows_per_hour > 0 else None
    return {
        "sample_count": len(samples),
        "latest_completed": latest.get("completed"),
        "latest_expected": latest.get("expected"),
        "latest_sample_age_sec": latest_age,
        "rows_per_hour": round(rows_per_hour, 3) if rows_per_hour is not None else None,
        "eta_sec": round(eta_sec, 3) if eta_sec is not None else None,
    }


def read_pid(path: Path) -> int | None:
    if not path.is_file():
        return None
    try:
        return int(path.read_text(encoding="utf-8-sig").strip())
    except (OSError, ValueError):
        return None


def watcher_info(job_dir: Path, *, tail_lines: int = 5) -> dict[str, Any]:
    pid_path = job_dir / "watch.pid"
    stdout_path = job_dir / "watch.stdout.log"
    stderr_path = job_dir / "watch.stderr.log"
    pid = read_pid(pid_path)
    pid_alive = pid_running(pid)
    command = process_command_line(pid) if pid_alive else ""
    samples = watch_progress_samples_for_job(job_dir)
    return {
        "pid": pid,
        "pid_alive": pid_alive,
        "running": pid_alive and watcher_command_matches(command, job_dir),
        "pid_path": str(pid_path),
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
        "command_line": command,
        "stdout_bytes": file_size(stdout_path),
        "stderr_bytes": file_size(stderr_path),
        "progress": watch_progress_metrics(samples),
        "stdout_tail": read_tail(stdout_path, tail_lines),
        "stderr_tail": read_tail(stderr_path, tail_lines),
    }


def terminate_process(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"Stop-Process -Id {int(pid)} -Force",
            ],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=PROCESS_COMMAND_TIMEOUT_SEC,
        )
        return
    os.kill(int(pid), signal.SIGTERM)


def rotate_path(path: Path, *, stamp: str | None = None) -> Path | None:
    if not path.exists():
        return None
    stamp = stamp or datetime.now().strftime("%Y%m%d%H%M%S")
    target = path.with_name(f"{path.name}.{stamp}.prev")
    counter = 1
    while target.exists():
        target = path.with_name(f"{path.name}.{stamp}.{counter}.prev")
        counter += 1
    path.replace(target)
    return target


def watcher_launch_command(
    job_dir: Path,
    *,
    poll_sec: float = 300,
    auto_post_run: bool = True,
    snapshot_json: Path = DEFAULT_LIVE_STATUS_JSON,
    snapshot_md: Path = DEFAULT_LIVE_STATUS_MD,
    check_md: Path = DEFAULT_LIVE_STATUS_CHECK,
    history_jsonl: Path = DEFAULT_LIVE_STATUS_HISTORY,
) -> list[str]:
    command = [
        sys.executable,
        str(ROOT / "infra" / "paper_queue_job.py"),
        "watch",
        "--job-dir",
        str(job_dir),
        "--poll-sec",
        str(int(poll_sec) if float(poll_sec).is_integer() else poll_sec),
    ]
    if auto_post_run:
        command.append("--auto-post-run")
    command.extend(
        [
            "--snapshot-json",
            str(snapshot_json),
            "--snapshot-md",
            str(snapshot_md),
            "--check-md",
            str(check_md),
            "--history-jsonl",
            str(history_jsonl),
        ]
    )
    return command


def stop_existing_watcher(job_dir: Path, *, terminator: Any = terminate_process) -> dict[str, Any]:
    pid = read_pid(job_dir / "watch.pid")
    if not pid or not pid_running(pid):
        return {"pid": pid, "stopped": False, "reason": "not_running"}
    command = process_command_line(pid)
    if not watcher_command_matches(command, job_dir):
        raise SystemExit(f"watch.pid points to a non-matching process; refusing to stop pid={pid}")
    terminator(pid)
    return {"pid": pid, "stopped": True, "reason": "stopped"}


def launch_watcher(
    job_dir: Path,
    *,
    poll_sec: float = 300,
    auto_post_run: bool = True,
    snapshot_json: Path = DEFAULT_LIVE_STATUS_JSON,
    snapshot_md: Path = DEFAULT_LIVE_STATUS_MD,
    check_md: Path = DEFAULT_LIVE_STATUS_CHECK,
    history_jsonl: Path = DEFAULT_LIVE_STATUS_HISTORY,
    runner: Any = subprocess.Popen,
) -> int:
    command = watcher_launch_command(
        job_dir,
        poll_sec=poll_sec,
        auto_post_run=auto_post_run,
        snapshot_json=snapshot_json,
        snapshot_md=snapshot_md,
        check_md=check_md,
        history_jsonl=history_jsonl,
    )
    flags = 0
    if os.name == "nt":
        flags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        flags |= getattr(subprocess, "DETACHED_PROCESS", 0)
    stdout_path = job_dir / "watch.stdout.log"
    stderr_path = job_dir / "watch.stderr.log"
    job_dir.mkdir(parents=True, exist_ok=True)
    with stdout_path.open("ab") as stdout, stderr_path.open("ab") as stderr:
        proc = runner(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            creationflags=flags,
            close_fds=True,
        )
    (job_dir / "watch.pid").write_text(str(proc.pid), encoding="utf-8")
    return int(proc.pid)


def restart_watcher(
    job_dir: Path,
    *,
    poll_sec: float = 300,
    auto_post_run: bool = True,
    snapshot_json: Path = DEFAULT_LIVE_STATUS_JSON,
    snapshot_md: Path = DEFAULT_LIVE_STATUS_MD,
    check_md: Path = DEFAULT_LIVE_STATUS_CHECK,
    history_jsonl: Path = DEFAULT_LIVE_STATUS_HISTORY,
    terminator: Any = terminate_process,
    runner: Any = subprocess.Popen,
) -> dict[str, Any]:
    stopped = stop_existing_watcher(job_dir, terminator=terminator)
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    rotated = [
        str(path)
        for path in [
            rotate_path(job_dir / "watch.stdout.log", stamp=stamp),
            rotate_path(job_dir / "watch.stderr.log", stamp=stamp),
        ]
        if path
    ]
    pid = launch_watcher(
        job_dir,
        poll_sec=poll_sec,
        auto_post_run=auto_post_run,
        snapshot_json=snapshot_json,
        snapshot_md=snapshot_md,
        check_md=check_md,
        history_jsonl=history_jsonl,
        runner=runner,
    )
    return {"pid": pid, "stopped": stopped, "rotated_logs": rotated}


def load_execution_summary(state: dict[str, Any]) -> dict[str, Any] | None:
    out_json = state.get("metadata", {}).get("out_json", "")
    if not out_json:
        return None
    path = Path(out_json)
    if not path.is_absolute():
        path = ROOT / path
    if not path.is_file():
        return None
    try:
        plan = read_json(path)
    except (OSError, json.JSONDecodeError):
        return None
    generated_at = str(plan.get("generated_at") or "")
    started_at = str(state.get("started_at") or state.get("created_at") or "")
    job_execute = "--execute" in [str(item) for item in state.get("command", [])]
    plan_execute = bool(plan.get("execute", False))
    matches_job_execute = plan_execute == job_execute
    return {
        "path": relpath(path),
        "generated_at": generated_at,
        "fresh_for_job": bool(generated_at and started_at and generated_at >= started_at),
        "job_execute": job_execute,
        "plan_execute": plan_execute,
        "matches_job_execute": matches_job_execute,
        "summary": plan.get("summary", {}),
        "readiness_gate": plan.get("readiness_gate", {}),
    }


def load_progress_summary(state: dict[str, Any]) -> dict[str, Any] | None:
    harnesses = [str(item) for item in state.get("metadata", {}).get("harnesses", []) if str(item)]
    if not harnesses:
        return None
    try:
        report = check_paper_matrix_progress.build_progress_report(
            harnesses=harnesses,
            preview_limit=0,
        )
    except Exception as exc:  # pragma: no cover - defensive status guard
        return {
            "error": str(exc),
            "harnesses": harnesses,
        }
    return {
        "generated_at": report.get("generated_at", ""),
        "complete": bool(report.get("complete", False)),
        "harnesses": report.get("harnesses", harnesses),
        "summary": report.get("summary", {}),
        "groups": report.get("groups", {}),
        "issues": report.get("issues", []),
        "completed_failure_marker_keys": completed_failure_marker_keys(report),
    }


def status_command_for_job(state: dict[str, Any]) -> list[str]:
    return [
        sys.executable,
        str(ROOT / "infra" / "paper_queue_job.py"),
        "status",
        "--job-dir",
        str(state.get("job_dir") or ""),
    ]


def post_run_command_for_job(state: dict[str, Any]) -> list[str]:
    metadata = state.get("metadata", {})
    harnesses = [str(item) for item in metadata.get("harnesses", []) if str(item)]
    queue = ROOT / str(metadata.get("queue") or relpath(DEFAULT_QUEUE))
    out_json, out_md = default_output_paths(queue_mode="post-run", harnesses=harnesses)
    job_name = safe_name(f"{state.get('job_name', 'paper_queue_job')}_post_run")
    command = [
        sys.executable,
        str(ROOT / "infra" / "paper_queue_job.py"),
        "start",
        "--job-name",
        job_name,
        "--queue",
        str(queue),
        "--queue-mode",
        "post-run",
        "--execute",
        "--out-json",
        str(out_json),
        "--out-md",
        str(out_md),
    ]
    for harness in harnesses:
        command.extend(["--harness", harness])
    return command


def post_run_job_dir_for_state(state: dict[str, Any], job_root: Path = DEFAULT_JOB_ROOT) -> Path:
    job_name = safe_name(f"{state.get('job_name', 'paper_queue_job')}_post_run")
    return job_root / job_name


def post_run_job_exists(state: dict[str, Any], job_root: Path = DEFAULT_JOB_ROOT) -> bool:
    return job_state_path(post_run_job_dir_for_state(state, job_root=job_root)).is_file()


def resume_command_for_job(state: dict[str, Any], execution: dict[str, Any] | None) -> list[str]:
    metadata = state.get("metadata", {})
    harnesses = [str(item) for item in metadata.get("harnesses", []) if str(item)]
    queue_mode = str(metadata.get("queue_mode") or "coalesced")
    queue = ROOT / str(metadata.get("queue") or relpath(DEFAULT_QUEUE))
    default_out_json, default_out_md = default_output_paths(queue_mode=queue_mode, harnesses=harnesses)
    out_json = ROOT / str(metadata.get("out_json") or relpath(default_out_json))
    out_md = ROOT / str(metadata.get("out_md") or relpath(default_out_md))
    resume_batch = ""
    if execution and execution.get("matches_job_execute", True):
        resume_batch = str(execution.get("summary", {}).get("resume_batch") or "")
    command = [
        sys.executable,
        str(ROOT / "infra" / "paper_queue_job.py"),
        "start",
        "--job-name",
        safe_name(f"{state.get('job_name', 'paper_queue_job')}_resume"),
        "--queue",
        str(queue),
        "--queue-mode",
        queue_mode,
        "--execute",
        "--out-json",
        str(out_json),
        "--out-md",
        str(out_md),
    ]
    for harness in harnesses:
        command.extend(["--harness", harness])
    if resume_batch:
        command.extend(["--start-at", resume_batch])
    return command


def next_action_for_status(
    state: dict[str, Any],
    *,
    observed_status: str,
    execution: dict[str, Any] | None,
    progress: dict[str, Any] | None,
) -> dict[str, Any]:
    if observed_status == "running":
        command = status_command_for_job(state)
        return {
            "action": "wait_for_job",
            "reason": "queue job is still running",
            "command": command_line(command),
        }
    if observed_status == "stale":
        command = resume_command_for_job(state, execution)
        return {
            "action": "inspect_or_resume",
            "reason": "job is marked running but no tracked process is alive",
            "command": command_line(command),
        }
    if observed_status == "failed":
        command = resume_command_for_job(state, execution)
        return {
            "action": "resume_failed_queue",
            "reason": "queue job failed before all selected commands completed",
            "command": command_line(command),
        }
    if observed_status == "passed" and progress and progress.get("complete"):
        command = post_run_command_for_job(state)
        return {
            "action": "run_post_run",
            "reason": "selected matrix rows are complete",
            "command": command_line(command),
        }
    if observed_status == "passed":
        command = resume_command_for_job(state, execution)
        return {
            "action": "resume_incomplete_matrix",
            "reason": "queue job exited successfully but selected matrix rows are still incomplete",
            "command": command_line(command),
        }
    return {
        "action": "inspect",
        "reason": f"unhandled observed status: {observed_status}",
        "command": command_line(status_command_for_job(state)),
    }


def inspect_job(job_dir: Path, *, tail_lines: int = 30, include_progress: bool = True) -> dict[str, Any]:
    state = read_json(job_state_path(job_dir))
    supervisor_running = pid_running(state.get("supervisor_pid"))
    process_running = pid_running(state.get("process_pid"))
    observed = state.get("status", "unknown")
    if observed == "running" and not supervisor_running and not process_running:
        observed = "stale"

    logs = state.get("logs", {})
    stdout_path = Path(logs.get("stdout") or job_dir / "stdout.log")
    stderr_path = Path(logs.get("stderr") or job_dir / "stderr.log")
    observed_elapsed = float(state.get("elapsed_sec") or 0)
    if state.get("status") == "running":
        observed_elapsed = elapsed_since(str(state.get("started_at") or ""))
    display_state = dict(state)
    if state.get("status") == "running":
        display_state["elapsed_sec"] = observed_elapsed
    execution = load_execution_summary(state)
    progress = load_progress_summary(state) if include_progress else None
    failure_markers = annotate_failure_marker_resolution(scan_failure_markers(stdout_path), progress)
    status = {
        "job": display_state,
        "observed_status": observed,
        "observed_elapsed_sec": observed_elapsed,
        "supervisor_running": supervisor_running,
        "process_running": process_running,
        "execution_plan": execution,
        "matrix_progress": progress,
        "log_sizes": {
            "stdout": file_size(stdout_path),
            "stderr": file_size(stderr_path),
        },
        "failure_markers": failure_markers,
        "watcher": watcher_info(job_dir, tail_lines=5),
        "stdout_tail": read_tail(stdout_path, tail_lines),
        "stderr_tail": read_tail(stderr_path, tail_lines),
    }
    status["next_action"] = next_action_for_status(
        state,
        observed_status=observed,
        execution=execution,
        progress=progress,
    )
    return status


def render_status_markdown(status: dict[str, Any]) -> str:
    job = status["job"]
    metadata = job.get("metadata", {})
    lines = [
        "# Paper Queue Job Status",
        "",
        f"- job_name: `{job.get('job_name', '')}`",
        f"- status: `{job.get('status', '')}`",
        f"- observed_status: `{status.get('observed_status', '')}`",
        f"- exit_code: `{job.get('exit_code') if job.get('exit_code') is not None else 'n/a'}`",
        f"- started_at: `{job.get('started_at') or 'n/a'}`",
        f"- finished_at: `{job.get('finished_at') or 'n/a'}`",
        f"- elapsed_sec: `{job.get('elapsed_sec', 0)}`",
        f"- observed_elapsed_sec: `{status.get('observed_elapsed_sec', 0)}`",
        f"- supervisor_pid: `{job.get('supervisor_pid') or 'n/a'}`",
        f"- process_pid: `{job.get('process_pid') or 'n/a'}`",
        f"- selected_commands: `{metadata.get('selected_commands', 'n/a')}`",
        f"- selected_missing_rows: `{metadata.get('selected_missing_rows', 'n/a')}`",
        f"- requires_kimi: `{str(metadata.get('requires_kimi', False)).lower()}`",
        f"- out_json: `{metadata.get('out_json', 'n/a')}`",
        f"- stdout_bytes: `{status.get('log_sizes', {}).get('stdout', 0)}`",
        f"- stderr_bytes: `{status.get('log_sizes', {}).get('stderr', 0)}`",
        f"- failure_markers: `{status.get('failure_markers', {}).get('unresolved_count', 0)}/{status.get('failure_markers', {}).get('count', 0)}`",
        "",
        "## Command",
        "",
        f"`{job.get('command_line', '')}`",
        "",
    ]
    execution = status.get("execution_plan")
    if execution:
        summary = execution.get("summary", {})
        lines += [
            "## Execution Plan",
            "",
            f"- path: `{execution.get('path', '')}`",
            f"- generated_at: `{execution.get('generated_at') or 'n/a'}`",
            f"- fresh_for_job: `{str(execution.get('fresh_for_job', False)).lower()}`",
            f"- job_execute: `{str(execution.get('job_execute', False)).lower()}`",
            f"- plan_execute: `{str(execution.get('plan_execute', False)).lower()}`",
            f"- matches_job_execute: `{str(execution.get('matches_job_execute', True)).lower()}`",
            f"- ok: `{str(summary.get('ok', False)).lower()}`",
            f"- executed_commands: `{summary.get('executed_commands', 0)}`",
            f"- failed_commands: `{summary.get('failed_commands', 0)}`",
            f"- pending_commands: `{summary.get('pending_commands', 0)}`",
            f"- incomplete_commands: `{summary.get('incomplete_commands', 0)}`",
            f"- resume_batch: `{summary.get('resume_batch') or 'n/a'}`",
            "",
        ]
        if not execution.get("fresh_for_job") and status.get("observed_status") == "running":
            lines += [
                "Note: execution plan output predates this running job; use Matrix Progress and Stdout Tail for live progress until the job rewrites the final plan.",
                "",
            ]
        if not execution.get("matches_job_execute", True):
            lines += [
                "Note: execution plan output does not match this job's execute mode; it may be a dry-run artifact. Use Matrix Progress and Stdout Tail for live progress until the job rewrites the final plan.",
                "",
            ]
    progress = status.get("matrix_progress")
    if progress:
        lines += ["## Matrix Progress", ""]
        if progress.get("error"):
            lines += [f"- error: `{progress.get('error')}`", ""]
        else:
            summary = progress.get("summary", {})
            lines += [
                f"- generated_at: `{progress.get('generated_at') or 'n/a'}`",
                f"- harnesses: `{','.join(progress.get('harnesses', [])) or 'all'}`",
                f"- complete: `{str(progress.get('complete', False)).lower()}`",
                f"- expected_rows: `{summary.get('expected_rows', 0)}`",
                f"- completed_rows: `{summary.get('completed_rows', 0)}`",
                f"- scored_rows: `{summary.get('execution_valid_completed_rows', 0)}`",
                f"- model_protocol_terminal_rows: `{summary.get('model_protocol_terminal_rows', 0)}`",
                f"- incomplete_rows: `{summary.get('incomplete_rows', 0)}`",
                f"- execution_invalid_or_unvalidated_rows: `{summary.get('execution_invalid_or_unvalidated_rows', 0)}`",
                f"- duplicate_accounted_expected_rows: `{summary.get('duplicate_accounted_expected_rows', 0)}`",
                f"- matched_without_oracle_rows: `{summary.get('matched_without_oracle_rows', 0)}`",
                f"- completion_rate: `{format_optional_decimal(summary.get('completion_rate'))}`",
                "",
            ]
    watcher = status.get("watcher", {})
    if watcher and watcher.get("pid"):
        lines += [
            "## Watcher",
            "",
            f"- pid: `{watcher.get('pid')}`",
            f"- pid_alive: `{str(watcher.get('pid_alive', False)).lower()}`",
            f"- running: `{str(watcher.get('running', False)).lower()}`",
            f"- stdout_bytes: `{watcher.get('stdout_bytes', 0)}`",
            f"- stderr_bytes: `{watcher.get('stderr_bytes', 0)}`",
            "",
        ]
        progress_metrics = watcher.get("progress") or {}
        if progress_metrics.get("sample_count"):
            rows_per_hour = progress_metrics.get("rows_per_hour")
            eta_sec = progress_metrics.get("eta_sec")
            lines += [
                "### Watcher Progress",
                "",
                f"- samples: `{progress_metrics.get('sample_count')}`",
                f"- latest_progress: `{progress_metrics.get('latest_completed')}/{progress_metrics.get('latest_expected')}`",
                f"- latest_sample_age_sec: `{progress_metrics.get('latest_sample_age_sec')}`",
                f"- rows_per_hour: `{rows_per_hour if rows_per_hour is not None else 'n/a'}`",
                f"- eta_sec: `{eta_sec if eta_sec is not None else 'n/a'}`",
                "",
            ]
        if watcher.get("stdout_tail"):
            lines += ["### Watcher Stdout Tail", "", "```text", watcher["stdout_tail"], "```", ""]
        if watcher.get("stderr_tail"):
            lines += ["### Watcher Stderr Tail", "", "```text", watcher["stderr_tail"], "```", ""]
    failure_markers = status.get("failure_markers", {})
    if failure_markers and failure_markers.get("count"):
        lines += [
            "## Failure Markers",
            "",
            f"- count: `{failure_markers.get('count', 0)}`",
            f"- unresolved_count: `{failure_markers.get('unresolved_count', 0)}`",
            "",
            "| Line | Harness | Control | Case | Error | Resolved | Reason |",
            "| ---: | --- | --- | --- | --- | --- | --- |",
        ]
        for marker in failure_markers.get("recent", [])[-10:]:
            lines.append(
                f"| {marker.get('line', '')} | {marker.get('harness', '')} | "
                f"{marker.get('control_type', '') or 'n/a'} | {marker.get('case_dir', '')} | "
                f"{marker.get('error', '')} | {str(marker.get('resolved', False)).lower()} | "
                f"{marker.get('reason', '')} |"
            )
        lines.append("")
    next_action = status.get("next_action", {})
    if next_action:
        lines += [
            "## Next Action",
            "",
            f"- action: `{next_action.get('action', '')}`",
            f"- reason: `{next_action.get('reason', '')}`",
            f"- command: `{next_action.get('command', '')}`",
            "",
        ]
    if status.get("stdout_tail"):
        lines += ["## Stdout Tail", "", "```text", status["stdout_tail"], "```", ""]
    if status.get("stderr_tail"):
        lines += ["## Stderr Tail", "", "```text", status["stderr_tail"], "```", ""]
    return "\n".join(lines).rstrip() + "\n"


def preflight_queue(
    *,
    queue: Path,
    queue_mode: str,
    batches: list[str],
    harnesses: list[str],
    start_at: str,
    include_post_run: bool,
    skip_readiness_check: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    queue_payload = run_paper_queue.load_json(queue)
    selected = run_paper_queue.select_commands(
        queue_payload,
        queue_mode=queue_mode,
        batches=batches,
        harnesses=harnesses,
        start_at=start_at,
        include_post_run=include_post_run,
    )
    gate = run_paper_queue.build_readiness_gate(
        selected,
        execute=True,
        skip_readiness_check=skip_readiness_check,
    )
    return selected, gate


def launch_job(job_dir: Path) -> int:
    launcher = [
        sys.executable,
        str(ROOT / "infra" / "paper_queue_job.py"),
        "run",
        "--job-dir",
        str(job_dir),
    ]
    flags = 0
    if os.name == "nt":
        flags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        flags |= getattr(subprocess, "DETACHED_PROCESS", 0)

    state = read_json(job_state_path(job_dir))
    logs = state.get("logs", {})
    launcher_stdout = Path(logs.get("launcher_stdout") or job_dir / "launcher.stdout.log")
    launcher_stderr = Path(logs.get("launcher_stderr") or job_dir / "launcher.stderr.log")
    launcher_stdout.parent.mkdir(parents=True, exist_ok=True)
    with launcher_stdout.open("ab") as stdout, launcher_stderr.open("ab") as stderr:
        proc = subprocess.Popen(
            launcher,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            creationflags=flags,
            close_fds=True,
        )
    update_job_state(job_dir, status="running", supervisor_pid=proc.pid, started_at=timestamp())
    return proc.pid


def latest_job_dir(job_root: Path) -> Path:
    candidates = sorted(job_root.glob("*/job.json")) if job_root.is_dir() else []
    if not candidates:
        raise SystemExit(f"no paper queue jobs found under {job_root}; pass --job-name or --job-dir")
    newest_state = max(candidates, key=lambda path: path.stat().st_mtime)
    return newest_state.parent


def job_dir_from_args(job_root: Path, job_name: str, job_dir: str = "", *, default_latest: bool = False) -> Path:
    if job_dir:
        return Path(job_dir)
    if default_latest and not job_name:
        return latest_job_dir(job_root)
    return job_root / safe_name(job_name)


def start_from_args(args: argparse.Namespace) -> int:
    harnesses = split_cli_values(args.harness)
    batches = split_cli_values(args.batch)
    if not args.execute:
        raise SystemExit("start requires --execute; use run_paper_queue.py for dry-run plans")
    out_json, out_md = default_output_paths(
        queue_mode=args.queue_mode,
        harnesses=harnesses,
        out_json=args.out_json,
        out_md=args.out_md,
    )
    queue = Path(args.queue)
    selected, gate = preflight_queue(
        queue=queue,
        queue_mode=args.queue_mode,
        batches=batches,
        harnesses=harnesses,
        start_at=args.start_at,
        include_post_run=args.include_post_run,
        skip_readiness_check=args.skip_readiness_check,
    )
    if gate.get("checked") and not gate.get("ready"):
        blockers = "; ".join(gate.get("blockers", [])) or "readiness check failed"
        raise SystemExit(f"readiness gate blocked job: {blockers}")

    job_name = safe_name(args.job_name or f"paper_queue_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    job_root = Path(args.job_root)
    job_dir = job_dir_from_args(job_root, job_name, args.job_dir)
    if job_state_path(job_dir).exists() and not args.replace:
        raise SystemExit(f"job already exists: {job_dir}; choose a new --job-name or pass --replace")
    if job_dir.exists() and args.replace:
        shutil.rmtree(job_dir)

    command = build_queue_command(
        queue=queue,
        queue_mode=args.queue_mode,
        batches=batches,
        harnesses=harnesses,
        start_at=args.start_at,
        include_post_run=args.include_post_run,
        execute=True,
        continue_on_failure=args.continue_on_failure,
        skip_readiness_check=args.skip_readiness_check,
        out_json=out_json,
        out_md=out_md,
    )
    metadata = {
        "queue": relpath(queue),
        "queue_mode": args.queue_mode,
        "batches": batches,
        "harnesses": harnesses,
        "start_at": args.start_at,
        "include_post_run": args.include_post_run,
        "continue_on_failure": args.continue_on_failure,
        "skip_readiness_check": args.skip_readiness_check,
        "out_json": relpath(out_json),
        "out_md": relpath(out_md),
        "selected_commands": len(selected),
        "selected_missing_rows": sum(int(item.get("missing_rows") or 0) for item in selected),
        "requires_kimi": bool(gate.get("requires_kimi")),
        "readiness_gate": gate,
    }
    create_job_state(job_dir=job_dir, job_name=job_name, command=command, metadata=metadata)
    pid = launch_job(job_dir)
    status = inspect_job(job_dir, tail_lines=10)
    (job_dir / "status.md").write_text(render_status_markdown(status), encoding="utf-8")
    emit_text(f"started paper queue job {job_name} pid={pid}")
    emit_text(f"job_dir={job_dir}")
    return 0


def status_from_args(args: argparse.Namespace) -> int:
    job_dir = job_dir_from_args(Path(args.job_root), args.job_name, args.job_dir, default_latest=True)
    status = inspect_job(job_dir, tail_lines=args.tail_lines, include_progress=not args.no_progress)
    markdown = render_status_markdown(status)
    (job_dir / "status.md").write_text(markdown, encoding="utf-8")
    if args.json:
        emit_text(json.dumps(status, indent=2, ensure_ascii=False))
    else:
        emit_text(markdown)
    return 0


def watch_job(
    job_dir: Path,
    *,
    poll_sec: float = 60,
    max_wait_sec: float = 0,
    auto_post_run: bool = False,
    snapshot_json: Path | None = None,
    snapshot_md: Path | None = None,
    check_md: Path | None = None,
    history_jsonl: Path | None = None,
    tail_lines: int = 20,
    once: bool = False,
    inspector: Any = inspect_job,
    live_status_checker: Any = None,
    sleeper: Any = time.sleep,
    runner: Any = subprocess.run,
) -> int:
    started = time.monotonic()
    while True:
        status = inspector(job_dir, tail_lines=tail_lines)
        markdown = render_status_markdown(status)
        (job_dir / "status.md").write_text(markdown, encoding="utf-8")
        if snapshot_json and snapshot_md:
            live_status = build_live_status(job_root=job_dir.parent)
            write_live_status_outputs(
                live_status,
                out_json=snapshot_json,
                out_md=snapshot_md,
                history_jsonl=history_jsonl,
                check_md=check_md,
                live_status_checker=live_status_checker,
            )
        action = str(status.get("next_action", {}).get("action") or "")
        progress = status.get("matrix_progress") or {}
        summary = progress.get("summary", {}) if isinstance(progress, dict) else {}
        completed = summary.get("completed_rows", "n/a")
        expected = summary.get("expected_rows", "n/a")
        print(
            f"[paper_queue_job.watch] {timestamp()} "
            f"status={status.get('observed_status')} action={action} progress={completed}/{expected}",
            flush=True,
        )

        if action == "run_post_run":
            command = post_run_command_for_job(status["job"])
            print(f"[paper_queue_job.watch] post-run command: {command_line(command)}", flush=True)
            if post_run_job_exists(status["job"], job_root=job_dir.parent):
                print("[paper_queue_job.watch] post-run job already exists; not starting another", flush=True)
                return 0
            if auto_post_run:
                proc = runner(command, cwd=ROOT, check=False)
                return int(getattr(proc, "returncode", 1))
            return 0
        if action in {"resume_failed_queue", "inspect_or_resume", "resume_incomplete_matrix", "inspect"}:
            print(
                f"[paper_queue_job.watch] next command: {status.get('next_action', {}).get('command', '')}",
                flush=True,
            )
            return 1
        if once:
            return 0
        if max_wait_sec and time.monotonic() - started >= max_wait_sec:
            return 124
        sleeper(max(poll_sec, 0))


def watch_from_args(args: argparse.Namespace) -> int:
    job_dir = job_dir_from_args(Path(args.job_root), args.job_name, args.job_dir, default_latest=True)
    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "watch.pid").write_text(str(os.getpid()), encoding="utf-8")
    return watch_job(
        job_dir,
        poll_sec=args.poll_sec,
        max_wait_sec=args.max_wait_sec,
        auto_post_run=args.auto_post_run,
        snapshot_json=Path(args.snapshot_json) if args.snapshot_json else None,
        snapshot_md=Path(args.snapshot_md) if args.snapshot_md else None,
        check_md=Path(args.check_md) if args.check_md else None,
        history_jsonl=Path(args.history_jsonl) if args.history_jsonl else None,
        tail_lines=args.tail_lines,
        once=args.once,
    )


def restart_watch_from_args(args: argparse.Namespace) -> int:
    job_dir = job_dir_from_args(Path(args.job_root), args.job_name, args.job_dir, default_latest=True)
    result = restart_watcher(
        job_dir,
        poll_sec=args.poll_sec,
        auto_post_run=not args.no_auto_post_run,
        snapshot_json=Path(args.snapshot_json),
        snapshot_md=Path(args.snapshot_md),
        check_md=Path(args.check_md),
        history_jsonl=Path(args.history_jsonl),
    )
    emit_text(f"restarted watcher pid={result['pid']}")
    stopped = result.get("stopped", {})
    emit_text(f"previous_watcher={stopped.get('pid') or 'n/a'} stopped={str(stopped.get('stopped', False)).lower()}")
    if result.get("rotated_logs"):
        emit_text("rotated_logs=" + ",".join(str(path) for path in result["rotated_logs"]))
    return 0


def job_list_rows(job_root: Path, *, include_progress: bool = True) -> list[dict[str, Any]]:
    rows = []
    if job_root.is_dir():
        for state_path in sorted(job_root.glob("*/job.json")):
            try:
                status = inspect_job(state_path.parent, tail_lines=0, include_progress=include_progress)
            except Exception:
                continue
            job = status["job"]
            progress = status.get("matrix_progress") or {}
            summary = progress.get("summary", {}) if isinstance(progress, dict) else {}
            next_action = status.get("next_action") or {}
            failure_markers = status.get("failure_markers") or {}
            watcher = status.get("watcher", {})
            watcher_running = bool(watcher.get("running"))
            watcher_progress = watcher.get("progress", {})
            rows.append(
                {
                    "job_name": job.get("job_name", state_path.parent.name),
                    "observed_status": status.get("observed_status", job.get("status")),
                    "exit_code": job.get("exit_code"),
                    "progress_completed": summary.get("completed_rows"),
                    "progress_expected": summary.get("expected_rows"),
                    "progress_complete": progress.get("complete") if isinstance(progress, dict) else None,
                    "next_action": next_action.get("action"),
                    "failure_marker_count": failure_markers.get("count", 0),
                    "unresolved_failure_marker_count": failure_markers.get("unresolved_count", 0),
                    "watcher_pid": watcher.get("pid"),
                    "watcher_running": watcher_running,
                    "watcher_rows_per_hour": watcher.get("progress", {}).get("rows_per_hour") if watcher_running else None,
                    "watcher_eta_sec": watcher.get("progress", {}).get("eta_sec") if watcher_running else None,
                    "watcher_latest_sample_age_sec": watcher_progress.get("latest_sample_age_sec") if watcher_running else None,
                    "watcher_latest_completed": watcher_progress.get("latest_completed") if watcher_running else None,
                    "watcher_latest_expected": watcher_progress.get("latest_expected") if watcher_running else None,
                    "job_dir": str(state_path.parent),
                    "updated_at": job.get("updated_at", ""),
                }
            )
    return rows


def load_submission_gap_summary(
    path: Path = ROOT / "docs" / "generated_artifacts" / "paper_submission_gap_report.json",
) -> dict[str, Any]:
    if not path.is_file():
        return {
            "path": relpath(path),
            "exists": False,
            "generated_at": "",
            "submission_ready": None,
            "errors": [],
            "warnings": [],
        }
    try:
        payload = read_json(path)
    except (OSError, json.JSONDecodeError):
        return {
            "path": relpath(path),
            "exists": True,
            "generated_at": "",
            "submission_ready": None,
            "errors": [{"message": "could not parse submission gap report"}],
            "warnings": [],
        }
    issues = payload.get("issues", []) or []
    return {
        "path": relpath(path),
        "exists": True,
        "generated_at": payload.get("generated_at", ""),
        "submission_ready": payload.get("submission_ready"),
        "errors": [item for item in issues if item.get("severity") == "error"],
        "warnings": [item for item in issues if item.get("severity") == "warning"],
    }


def compact_progress(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "generated_at": report.get("generated_at", ""),
        "matrix_id": report.get("matrix_id", ""),
        "case_set": report.get("case_set", ""),
        "harnesses": report.get("harnesses", []),
        "complete": report.get("complete", False),
        "summary": report.get("summary", {}),
        "issues": report.get("issues", []),
    }


def active_claude_job_name(jobs: list[dict[str, Any]], *, matrix_complete: bool = False) -> str:
    candidates = []
    for row in jobs:
        name = str(row.get("job_name") or "")
        if not name.startswith(DEFAULT_CLAUDE_JOB_NAME) or "_post" in name:
            continue
        candidates.append(row)
    if not candidates:
        return DEFAULT_CLAUDE_JOB_NAME

    if matrix_complete:
        priority = {
            "passed": 0,
            "running": 1,
            "stale": 2,
            "queued": 3,
            "failed": 4,
        }
    else:
        priority = {
            "running": 0,
            "stale": 1,
            "queued": 2,
            "failed": 3,
            "passed": 4,
        }
    candidates.sort(key=lambda row: str(row.get("updated_at") or ""), reverse=True)
    candidates.sort(key=lambda row: priority.get(str(row.get("observed_status") or ""), 9))
    return str(candidates[0].get("job_name") or DEFAULT_CLAUDE_JOB_NAME)


def build_live_status(
    *,
    job_root: Path = DEFAULT_JOB_ROOT,
    include_progress: bool = True,
) -> dict[str, Any]:
    jobs = job_list_rows(job_root, include_progress=include_progress)
    progress_claude = compact_progress(
        check_paper_matrix_progress.build_progress_report(harnesses=["claude"], preview_limit=0)
    )
    progress_full = progress_claude
    claude_summary = progress_claude.get("summary", {})
    claude_expected = int_or_zero(claude_summary.get("expected_rows"))
    claude_completed = int_or_zero(claude_summary.get("completed_rows"))
    claude_complete = bool(progress_claude.get("complete")) or (
        claude_expected > 0 and claude_completed >= claude_expected
    )
    claude_job = active_claude_job_name(jobs, matrix_complete=claude_complete)
    commands = {
        "job_list": f"{sys.executable} {ROOT / 'infra' / 'paper_queue_job.py'} list",
        "claude_status": f"{sys.executable} {ROOT / 'infra' / 'paper_queue_job.py'} status --job-name {claude_job}",
        "live_snapshot": (
            f"{sys.executable} {ROOT / 'infra' / 'paper_queue_job.py'} snapshot "
            f"--out-json {DEFAULT_LIVE_STATUS_JSON} "
            f"--out-md {DEFAULT_LIVE_STATUS_MD} "
            f"--check-md {DEFAULT_LIVE_STATUS_CHECK} "
            f"--history-jsonl {DEFAULT_LIVE_STATUS_HISTORY}"
        ),
    }
    command_policy = {
        "matrix_complete": claude_complete,
        "watch_or_execute_required": not claude_complete,
        "note": (
            "Matrix is complete; no watcher restart or queued benchmark execution is required."
            if claude_complete
            else "Matrix is incomplete; watcher and queued execution commands are available."
        ),
    }
    if not claude_complete:
        commands.update(
            {
                "claude_watch": (
                    f"{sys.executable} {ROOT / 'infra' / 'paper_queue_job.py'} watch "
                    f"--job-name {claude_job} --poll-sec 300 --auto-post-run "
                    f"--snapshot-json {DEFAULT_LIVE_STATUS_JSON} "
                    f"--snapshot-md {DEFAULT_LIVE_STATUS_MD} "
                    f"--check-md {DEFAULT_LIVE_STATUS_CHECK} "
                    f"--history-jsonl {DEFAULT_LIVE_STATUS_HISTORY}"
                ),
                "claude_restart_watch": (
                    f"{sys.executable} {ROOT / 'infra' / 'paper_queue_job.py'} restart-watch "
                    f"--job-name {claude_job}"
                ),
                "claude_execute": (
                    f"{sys.executable} {ROOT / 'infra' / 'paper_queue_job.py'} start "
                    f"--job-name {DEFAULT_CLAUDE_JOB_NAME} --queue {DEFAULT_QUEUE} "
                    "--queue-mode serial --harness claude --execute "
                    f"--out-json {ROOT / 'docs' / 'generated_artifacts' / 'paper_run_execution_claude_plan.json'} "
                    f"--out-md {ROOT / 'docs' / 'generated_artifacts' / 'paper_run_execution_claude_plan.md'}"
                ),
                "claude_post_run": (
                    f"{sys.executable} {ROOT / 'infra' / 'paper_queue_job.py'} start "
                    "--job-name paper_core_claude_20260626_post "
                    f"--queue {DEFAULT_QUEUE} --queue-mode post-run --harness claude --execute "
                    f"--out-json {ROOT / 'docs' / 'generated_artifacts' / 'paper_run_execution_claude_post_run.json'} "
                    f"--out-md {ROOT / 'docs' / 'generated_artifacts' / 'paper_run_execution_claude_post_run.md'}"
                ),
            }
        )
    return {
        "generated_at": timestamp(),
        "root": str(ROOT),
        "active_baseline": {
            "name": "claude_code_kimi_k2.6",
            "harness": "claude",
            "model": "kimi-k2.6",
            "model_source": "Claude Code runtime default",
            "codex_in_current_scope": False,
        },
        "jobs": jobs,
        "matrix_progress": {
            "full": progress_full,
            "claude": progress_claude,
        },
        "submission_gap": load_submission_gap_summary(),
        "command_policy": command_policy,
        "commands": commands,
    }


def render_live_status_markdown(status: dict[str, Any]) -> str:
    full = status.get("matrix_progress", {}).get("full", {})
    full_summary = full.get("summary", {})
    claude = status.get("matrix_progress", {}).get("claude", {})
    claude_summary = claude.get("summary", {})
    baseline = status.get("active_baseline", {})
    gap = status.get("submission_gap", {})
    policy = status.get("command_policy", {})
    matrix_complete = bool(policy.get("matrix_complete")) or (
        int_or_zero(claude_summary.get("expected_rows")) > 0
        and int_or_zero(claude_summary.get("completed_rows")) >= int_or_zero(claude_summary.get("expected_rows"))
    )
    lines = [
        "# Paper Live Status",
        "",
        f"- generated_at: `{status.get('generated_at', '')}`",
        f"- active_baseline: `{baseline.get('name', 'claude_code_kimi_k2.6')}`",
        f"- active_harness: `{baseline.get('harness', 'claude')}`",
        f"- active_model: `{baseline.get('model', 'kimi-k2.6')}`",
        f"- active_model_source: `{baseline.get('model_source', 'Claude Code runtime default')}`",
        f"- full_matrix: `{full_summary.get('completed_rows', 0)}/{full_summary.get('expected_rows', 0)}`",
        f"- full_scored_rows: `{full_summary.get('execution_valid_completed_rows', 0)}`",
        f"- full_n_minus_1_rows: `{full_summary.get('model_protocol_terminal_rows', 0)}`",
        f"- full_unresolved_invalid_rows: `{full_summary.get('execution_invalid_or_unvalidated_rows', 0)}`",
        f"- full_duplicate_accounted_rows: `{full_summary.get('duplicate_accounted_expected_rows', 0)}`",
        f"- claude_matrix: `{claude_summary.get('completed_rows', 0)}/{claude_summary.get('expected_rows', 0)}`",
        f"- claude_scored_rows: `{claude_summary.get('execution_valid_completed_rows', 0)}`",
        f"- claude_n_minus_1_rows: `{claude_summary.get('model_protocol_terminal_rows', 0)}`",
        f"- claude_unresolved_invalid_rows: `{claude_summary.get('execution_invalid_or_unvalidated_rows', 0)}`",
        f"- claude_duplicate_accounted_rows: `{claude_summary.get('duplicate_accounted_expected_rows', 0)}`",
        f"- claude_complete: `{str(claude.get('complete', False)).lower()}`",
        f"- codex_in_current_scope: `{str(baseline.get('codex_in_current_scope', False)).lower()}`",
        f"- submission_ready: `{display_optional(gap.get('submission_ready'))}`",
        f"- submission_errors: `{len(gap.get('errors', []))}`",
        f"- submission_warnings: `{len(gap.get('warnings', []))}`",
        "",
        "## Jobs",
        "",
    ]
    jobs = status.get("jobs", [])
    if jobs:
        lines += [
            "| Job | Status | Progress | Failures | Next | Watcher | Sample Age | Rate | ETA |",
            "| --- | --- | ---: | ---: | --- | --- | ---: | ---: | ---: |",
        ]
        for row in jobs:
            progress = "n/a"
            if row.get("progress_completed") is not None and row.get("progress_expected") is not None:
                progress = f"{row['progress_completed']}/{row['progress_expected']}"
            watcher = f"{row.get('watcher_pid') or 'n/a'}:{str(row.get('watcher_running')).lower()}"
            sample_age = row.get("watcher_latest_sample_age_sec")
            rate = row.get("watcher_rows_per_hour")
            eta = row.get("watcher_eta_sec")
            total_failures = int_or_zero(row.get("failure_marker_count"))
            unresolved_failures = int_or_zero(row.get("unresolved_failure_marker_count"))
            next_action = row.get("next_action") or "n/a"
            if matrix_complete and unresolved_failures == 0:
                if row.get("observed_status") == "passed":
                    next_action = "complete"
                elif row.get("observed_status") in {"failed", "stale", "queued"}:
                    next_action = "superseded_by_completed_matrix"
            lines.append(
                f"| {row.get('job_name', '')} | {row.get('observed_status', '')} | {progress} | "
                f"{unresolved_failures}/{total_failures} | {next_action} | {watcher} | "
                f"{format_optional_metric(sample_age, 's')} | "
                f"{format_optional_metric(rate, 'r/h')} | {format_optional_metric(eta, 's')} |"
            )
    else:
        lines.append("- none")
    lines += ["", "## Blocking Issues", ""]
    errors = gap.get("errors", [])
    if errors:
        for item in errors:
            lines.append(f"- `{item.get('scope', 'unknown')}`: {item.get('message', '')}")
    else:
        lines.append("- none")
    lines += ["", "## Commands", ""]
    note = policy.get("note")
    if note:
        lines.append(f"- note: {note}")
    for name, command in status.get("commands", {}).items():
        lines.append(f"- {name}: `{command}`")
    return "\n".join(lines) + "\n"


def append_live_status_history(path: Path, status: dict[str, Any]) -> None:
    full = status.get("matrix_progress", {}).get("full", {})
    claude = status.get("matrix_progress", {}).get("claude", {})
    gap = status.get("submission_gap", {})
    record = {
        "generated_at": status.get("generated_at", ""),
        "matrix_id": claude.get("matrix_id") or full.get("matrix_id") or "",
        "active_baseline": status.get("active_baseline", {}),
        "full": full.get("summary", {}),
        "claude": claude.get("summary", {}),
        "jobs": [
            {
                "job_name": row.get("job_name"),
                "observed_status": row.get("observed_status"),
                "progress_completed": row.get("progress_completed"),
                "progress_expected": row.get("progress_expected"),
                "next_action": row.get("next_action"),
                "watcher_pid": row.get("watcher_pid"),
                "watcher_running": row.get("watcher_running"),
                "watcher_rows_per_hour": row.get("watcher_rows_per_hour"),
                "watcher_eta_sec": row.get("watcher_eta_sec"),
                "watcher_latest_sample_age_sec": row.get("watcher_latest_sample_age_sec"),
                "watcher_latest_completed": row.get("watcher_latest_completed"),
                "watcher_latest_expected": row.get("watcher_latest_expected"),
            }
            for row in status.get("jobs", [])
        ],
        "submission_ready": gap.get("submission_ready"),
        "submission_error_count": len(gap.get("errors", [])),
        "submission_warning_count": len(gap.get("warnings", [])),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def load_live_status_checker() -> Any:
    try:
        from infra import check_paper_live_status
    except ModuleNotFoundError:  # direct `python infra/paper_queue_job.py`
        import check_paper_live_status  # type: ignore
    return check_paper_live_status


def write_live_status_outputs(
    status: dict[str, Any],
    *,
    out_json: Path,
    out_md: Path,
    history_jsonl: Path | None = None,
    check_md: Path | None = None,
    live_status_checker: Any = None,
) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(status, indent=2, ensure_ascii=False), encoding="utf-8")
    out_md.write_text(render_live_status_markdown(status), encoding="utf-8")
    if history_jsonl:
        append_live_status_history(history_jsonl, status)
    if check_md:
        checker = live_status_checker or load_live_status_checker()
        report = checker.build_report(
            live_status_path=out_json,
            history_path=history_jsonl,
            fresh_status_builder=lambda: status,
        )
        check_md.parent.mkdir(parents=True, exist_ok=True)
        check_md.write_text(checker.render_markdown(report), encoding="utf-8")


def snapshot_from_args(args: argparse.Namespace) -> int:
    status = build_live_status(job_root=Path(args.job_root), include_progress=not args.no_progress)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    write_live_status_outputs(
        status,
        out_json=out_json,
        out_md=out_md,
        history_jsonl=Path(args.history_jsonl) if args.history_jsonl else None,
        check_md=Path(args.check_md) if args.check_md else None,
    )
    if args.json:
        emit_text(json.dumps(status, indent=2, ensure_ascii=False))
    else:
        emit_text(render_live_status_markdown(status), end="")
    return 0


def format_optional_metric(value: Any, suffix: str = "") -> str:
    if value is None:
        return "n/a"
    return f"{value}{suffix}"


def list_from_args(args: argparse.Namespace) -> int:
    rows = job_list_rows(Path(args.job_root), include_progress=not args.no_progress)
    if args.json:
        emit_text(json.dumps(rows, indent=2, ensure_ascii=False))
    else:
        for row in rows:
            progress = "n/a"
            if row.get("progress_completed") is not None and row.get("progress_expected") is not None:
                progress = f"{row['progress_completed']}/{row['progress_expected']}"
            emit_text(
                f"{row['job_name']}\t{row['observed_status']}\t"
                f"exit={row['exit_code'] if row['exit_code'] is not None else 'n/a'}\t"
                f"progress={progress}\tnext={row.get('next_action') or 'n/a'}\t"
                f"watcher={row.get('watcher_pid') or 'n/a'}:{str(row.get('watcher_running')).lower()}\t"
                f"rate={format_optional_metric(row.get('watcher_rows_per_hour'), 'r/h')}\t"
                f"eta={format_optional_metric(row.get('watcher_eta_sec'), 's')}\t"
                f"{row['job_dir']}"
            )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Launch and inspect long-running paper queue jobs.")
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="Launch run_paper_queue.py in a detached background job.")
    start.add_argument("--job-name", default="")
    start.add_argument("--job-root", default=str(DEFAULT_JOB_ROOT))
    start.add_argument("--job-dir", default="")
    start.add_argument("--replace", action="store_true")
    start.add_argument("--queue", default=str(DEFAULT_QUEUE))
    start.add_argument(
        "--queue-mode",
        choices=["serial", "coalesced", "fine", "post-run"],
        default="serial",
    )
    start.add_argument("--batch", action="append", default=[])
    start.add_argument("--harness", action="append", default=[])
    start.add_argument("--start-at", default="")
    start.add_argument("--include-post-run", action="store_true")
    start.add_argument("--execute", action="store_true")
    start.add_argument("--continue-on-failure", action="store_true")
    start.add_argument("--skip-readiness-check", action="store_true")
    start.add_argument("--out-json", default="")
    start.add_argument("--out-md", default="")
    start.set_defaults(func=start_from_args)

    run = sub.add_parser("run", help=argparse.SUPPRESS)
    run.add_argument("--job-dir", required=True)
    run.set_defaults(func=lambda args: run_job(Path(args.job_dir)))

    status = sub.add_parser("status", help="Print and refresh a job status summary.")
    status.add_argument("--job-name", default="")
    status.add_argument("--job-root", default=str(DEFAULT_JOB_ROOT))
    status.add_argument("--job-dir", default="")
    status.add_argument("--tail-lines", type=int, default=30)
    status.add_argument("--json", action="store_true")
    status.add_argument("--no-progress", action="store_true", help="Do not scan result directories for matrix progress.")
    status.set_defaults(func=status_from_args)

    watch = sub.add_parser("watch", help="Poll a job until it needs attention or can launch post-run.")
    watch.add_argument("--job-name", default="")
    watch.add_argument("--job-root", default=str(DEFAULT_JOB_ROOT))
    watch.add_argument("--job-dir", default="")
    watch.add_argument("--poll-sec", type=float, default=60)
    watch.add_argument("--max-wait-sec", type=float, default=0)
    watch.add_argument("--tail-lines", type=int, default=20)
    watch.add_argument("--once", action="store_true")
    watch.add_argument("--auto-post-run", action="store_true")
    watch.add_argument("--snapshot-json", default="", help="Refresh this live-status JSON path on each poll.")
    watch.add_argument("--snapshot-md", default="", help="Refresh this live-status Markdown path on each poll.")
    watch.add_argument("--check-md", default="", help="Refresh this live-status check Markdown path on each poll.")
    watch.add_argument("--history-jsonl", default="", help="Append compact live-status records on each poll.")
    watch.set_defaults(func=watch_from_args)

    restart_watch = sub.add_parser("restart-watch", help="Restart only the live-status watcher for a queue job.")
    restart_watch.add_argument("--job-name", default="")
    restart_watch.add_argument("--job-root", default=str(DEFAULT_JOB_ROOT))
    restart_watch.add_argument("--job-dir", default="")
    restart_watch.add_argument("--poll-sec", type=float, default=300)
    restart_watch.add_argument("--no-auto-post-run", action="store_true")
    restart_watch.add_argument("--snapshot-json", default=str(DEFAULT_LIVE_STATUS_JSON))
    restart_watch.add_argument("--snapshot-md", default=str(DEFAULT_LIVE_STATUS_MD))
    restart_watch.add_argument("--check-md", default=str(DEFAULT_LIVE_STATUS_CHECK))
    restart_watch.add_argument("--history-jsonl", default=str(DEFAULT_LIVE_STATUS_HISTORY))
    restart_watch.set_defaults(func=restart_watch_from_args)

    snapshot = sub.add_parser("snapshot", help="Export a live paper experiment status snapshot.")
    snapshot.add_argument("--job-root", default=str(DEFAULT_JOB_ROOT))
    snapshot.add_argument("--out-json", default=str(DEFAULT_LIVE_STATUS_JSON))
    snapshot.add_argument("--out-md", default=str(DEFAULT_LIVE_STATUS_MD))
    snapshot.add_argument("--check-md", default=str(DEFAULT_LIVE_STATUS_CHECK))
    snapshot.add_argument("--history-jsonl", default="", help="Append a compact status record to this JSONL path.")
    snapshot.add_argument("--json", action="store_true")
    snapshot.add_argument("--no-progress", action="store_true", help="Do not scan tracked jobs for progress.")
    snapshot.set_defaults(func=snapshot_from_args)

    list_cmd = sub.add_parser("list", help="List known paper queue jobs.")
    list_cmd.add_argument("--job-root", default=str(DEFAULT_JOB_ROOT))
    list_cmd.add_argument("--json", action="store_true")
    list_cmd.add_argument("--no-progress", action="store_true", help="Do not scan result directories for progress.")
    list_cmd.set_defaults(func=list_from_args)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
