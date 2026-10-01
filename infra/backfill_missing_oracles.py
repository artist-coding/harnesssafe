"""Backfill missing oracle.json files for completed benchmark result dirs.

This is a post-processing helper: it never runs a harness. By default it only
prints a dry-run plan. Use --execute to invoke analyze_trace.py for eligible
result directories that already have trace.jsonl and case.json.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

try:
    from infra import report_active_run
except ModuleNotFoundError:  # direct `python infra/backfill_missing_oracles.py`
    import report_active_run  # type: ignore


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MIN_AGE_SEC = 600


def split_cli_values(values: list[str] | None) -> list[str]:
    out: list[str] = []
    for raw in values or []:
        for item in str(raw).split(","):
            value = item.strip()
            if value and value not in out:
                out.append(value)
    return out


def resolve_run_dir(value: str, root: Path = ROOT) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return root / path


def newest_required_mtime(run_dir: Path) -> float:
    mtimes = []
    for name in ["trace.jsonl", "honeypot.jsonl", "case.json", "trace.err"]:
        path = run_dir / name
        if path.exists():
            mtimes.append(path.stat().st_mtime)
    return max(mtimes) if mtimes else 0.0


def classify_missing_rows(
    rows: list[dict[str, Any]],
    *,
    root: Path = ROOT,
    now: datetime | None = None,
    min_age_sec: int = DEFAULT_MIN_AGE_SEC,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    current_time = (now or datetime.now()).timestamp()
    out: list[dict[str, Any]] = []
    eligible_seen = 0
    for row in rows:
        if row.get("has_oracle"):
            continue
        run_dir_value = str(row.get("run_dir") or "")
        item: dict[str, Any] = {
            "case_dir": row.get("case_dir", ""),
            "run_dir": run_dir_value,
            "harness": row.get("harness", ""),
            "run_kind": row.get("run_kind", ""),
            "control_type": row.get("control_type", ""),
            "eligible": False,
            "reason": "",
            "age_sec": None,
        }
        if not run_dir_value:
            item["reason"] = "missing run_dir"
            out.append(item)
            continue
        run_dir = resolve_run_dir(run_dir_value, root)
        if not run_dir.is_dir():
            item["reason"] = "result directory does not exist"
            out.append(item)
            continue
        if not (run_dir / "trace.jsonl").is_file():
            item["reason"] = "missing trace.jsonl"
            out.append(item)
            continue
        if not (run_dir / "case.json").is_file():
            item["reason"] = "missing case.json"
            out.append(item)
            continue
        if (run_dir / "oracle.json").exists():
            item["reason"] = "oracle already exists"
            out.append(item)
            continue
        newest_mtime = newest_required_mtime(run_dir)
        age_sec = round(max(0.0, current_time - newest_mtime), 3)
        item["age_sec"] = age_sec
        if age_sec < min_age_sec:
            item["reason"] = "result directory is too recent"
            out.append(item)
            continue
        if limit is not None and eligible_seen >= limit:
            item["reason"] = "eligible but beyond limit"
            out.append(item)
            continue
        item["eligible"] = True
        item["reason"] = "ready"
        eligible_seen += 1
        out.append(item)
    return out


def collect_rows(
    *,
    label: str,
    harnesses: list[str],
    case_set: str,
    all_matching_runs: bool,
    run_kind: str,
    control_types: list[str] | None,
) -> list[dict[str, Any]]:
    return report_active_run.collect(
        label,
        harnesses,
        case_set,
        all_matching_runs,
        run_kind,
        control_types,
    )


def analyze_result_dir(
    run_dir: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> subprocess.CompletedProcess[str]:
    return runner(
        [sys.executable, str(ROOT / "infra" / "analyze_trace.py"), "--results", str(run_dir)],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
    )


def execute_plan(
    plan_rows: list[dict[str, Any]],
    *,
    root: Path = ROOT,
    execute: bool = False,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for item in plan_rows:
        row = dict(item)
        if not row.get("eligible"):
            row["action"] = "skip"
            results.append(row)
            continue
        run_dir = resolve_run_dir(str(row.get("run_dir") or ""), root)
        command = f"{sys.executable} {ROOT / 'infra' / 'analyze_trace.py'} --results {run_dir}"
        row["command"] = command
        if not execute:
            row["action"] = "would_analyze"
            results.append(row)
            continue
        proc = analyze_result_dir(run_dir, runner=runner)
        row["action"] = "analyzed" if proc.returncode == 0 else "failed"
        row["exit_code"] = proc.returncode
        row["stdout_tail"] = proc.stdout[-1000:]
        row["stderr_tail"] = proc.stderr[-1000:]
        results.append(row)
    return results


def build_report(
    *,
    label: str,
    harnesses: list[str],
    case_set: str = "core",
    all_matching_runs: bool = False,
    run_kind: str = "attack",
    control_types: list[str] | None = None,
    min_age_sec: int = DEFAULT_MIN_AGE_SEC,
    limit: int | None = None,
    execute: bool = False,
    fail_on_eligible: bool = False,
    root: Path = ROOT,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    rows = collect_rows(
        label=label,
        harnesses=harnesses,
        case_set=case_set,
        all_matching_runs=all_matching_runs,
        run_kind=run_kind,
        control_types=control_types,
    )
    plan = classify_missing_rows(rows, root=root, min_age_sec=min_age_sec, limit=limit)
    results = execute_plan(plan, root=root, execute=execute, runner=runner)
    summary = {
        "missing_oracle_rows": len(results),
        "eligible_rows": sum(1 for row in results if row.get("eligible")),
        "pending_eligible_rows": sum(1 for row in results if row.get("action") == "would_analyze"),
        "analyzed_rows": sum(1 for row in results if row.get("action") == "analyzed"),
        "failed_rows": sum(1 for row in results if row.get("action") == "failed"),
        "skipped_rows": sum(1 for row in results if row.get("action") == "skip"),
    }
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "label": label,
        "harnesses": harnesses,
        "case_set": case_set,
        "run_kind": run_kind,
        "control_types": control_types or [],
        "all_matching_runs": all_matching_runs,
        "execute": execute,
        "fail_on_eligible": fail_on_eligible,
        "min_age_sec": min_age_sec,
        "limit": limit,
        "summary": summary,
        "rows": results,
        "ok": summary["failed_rows"] == 0 and (not fail_on_eligible or summary["pending_eligible_rows"] == 0),
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    lines = [
        "# Missing Oracle Backfill",
        "",
        f"- generated_at: `{report.get('generated_at', '')}`",
        f"- label: `{report.get('label', '')}`",
        f"- harnesses: `{','.join(report.get('harnesses', []))}`",
        f"- case_set: `{report.get('case_set', '')}`",
        f"- run_kind: `{report.get('run_kind', '')}`",
        f"- all_matching_runs: `{str(report.get('all_matching_runs', False)).lower()}`",
        f"- execute: `{str(report.get('execute', False)).lower()}`",
        f"- fail_on_eligible: `{str(report.get('fail_on_eligible', False)).lower()}`",
        f"- min_age_sec: `{report.get('min_age_sec')}`",
        f"- missing_oracle_rows: `{summary.get('missing_oracle_rows', 0)}`",
        f"- eligible_rows: `{summary.get('eligible_rows', 0)}`",
        f"- pending_eligible_rows: `{summary.get('pending_eligible_rows', 0)}`",
        f"- analyzed_rows: `{summary.get('analyzed_rows', 0)}`",
        f"- failed_rows: `{summary.get('failed_rows', 0)}`",
        f"- skipped_rows: `{summary.get('skipped_rows', 0)}`",
        "",
        "## Rows",
        "",
    ]
    rows = report.get("rows", [])
    if not rows:
        lines.append("- none")
    else:
        lines += ["| Action | Eligible | Reason | Age | Case | Run |", "| --- | --- | --- | ---: | --- | --- |"]
        for row in rows:
            lines.append(
                f"| {row.get('action', '')} | {str(row.get('eligible', False)).lower()} | "
                f"{row.get('reason', '')} | {row.get('age_sec', '')} | "
                f"{row.get('case_dir', '')} | {row.get('run_dir', '')} |"
            )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill missing oracle.json files from existing traces.")
    parser.add_argument("--label", required=True)
    parser.add_argument("--harness", action="append", default=["claude"])
    parser.add_argument("--case-set", default="core", choices=["core", "extended", "exploratory", "all"])
    parser.add_argument("--all-matching-runs", action="store_true")
    parser.add_argument("--run-kind", default="attack", choices=["any", "attack", "control"])
    parser.add_argument("--control-type", action="append", dest="control_types")
    parser.add_argument("--min-age-sec", type=int, default=DEFAULT_MIN_AGE_SEC)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument(
        "--fail-on-eligible",
        action="store_true",
        help="Return a non-zero exit code when dry-run finds stale missing oracles that are ready to analyze.",
    )
    parser.add_argument("--out-json", default="")
    parser.add_argument("--out-md", default="")
    args = parser.parse_args()

    control_types = report_active_run.parse_control_types(args.control_types)
    report = build_report(
        label=args.label,
        harnesses=split_cli_values(args.harness),
        case_set=args.case_set,
        all_matching_runs=args.all_matching_runs,
        run_kind=args.run_kind,
        control_types=control_types,
        min_age_sec=args.min_age_sec,
        limit=args.limit,
        execute=args.execute,
        fail_on_eligible=args.fail_on_eligible,
    )
    text = render_markdown(report)
    if args.out_md:
        path = Path(args.out_md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    if args.out_json:
        path = Path(args.out_json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
