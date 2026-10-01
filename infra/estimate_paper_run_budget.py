"""Estimate wall-clock budget for the planned paper experiment matrix."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Any

try:
    from infra import check_paper_matrix_progress, export_paper_run_queue, plan_paper_experiment_matrix
except ModuleNotFoundError:  # direct `python infra/estimate_paper_run_budget.py`
    import check_paper_matrix_progress  # type: ignore
    import export_paper_run_queue  # type: ignore
    import plan_paper_experiment_matrix  # type: ignore


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PLAN = ROOT / "docs" / "generated_artifacts" / "paper_experiment_matrix_plan.json"
DEFAULT_OUT_JSON = ROOT / "docs" / "generated_artifacts" / "paper_run_budget.json"
DEFAULT_OUT_MD = ROOT / "docs" / "generated_artifacts" / "paper_run_budget.md"
DEFAULT_SAMPLE_REPORT_DIRS = [
    ROOT / "runs" / "_reports" / "paper_core_20260625",
    ROOT / "runs" / "_reports" / "paper_controls_core_20260625",
]

RUN_ID_RE = re.compile(r"^(\d{6})_(\d{6})_")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def relpath(path: Path, root: Path = ROOT) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def parse_run_start(run_id: str) -> datetime | None:
    match = RUN_ID_RE.match(run_id)
    if not match:
        return None
    try:
        return datetime.strptime("".join(match.groups()), "%y%m%d%H%M%S")
    except ValueError:
        return None


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = (len(ordered) - 1) * pct
    lower = int(pos)
    upper = min(lower + 1, len(ordered) - 1)
    frac = pos - lower
    return ordered[lower] * (1 - frac) + ordered[upper] * frac


def summarize_seconds(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "mean_sec": 0.0, "p50_sec": 0.0, "p90_sec": 0.0, "min_sec": 0.0, "max_sec": 0.0}
    return {
        "count": len(values),
        "mean_sec": round(mean(values), 2),
        "p50_sec": round(percentile(values, 0.50), 2),
        "p90_sec": round(percentile(values, 0.90), 2),
        "min_sec": round(min(values), 2),
        "max_sec": round(max(values), 2),
    }


def format_duration(seconds: float) -> str:
    total = int(round(max(seconds, 0)))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def observation_key(row: dict[str, Any], depth: str) -> str:
    kind = str(row.get("run_kind") or row.get("kind") or "")
    harness = str(row.get("harness") or "")
    control_type = str(row.get("control_type") or "")
    if depth == "kind_harness_control":
        return f"{kind}:{harness}:{control_type}"
    if depth == "kind_harness":
        return f"{kind}:{harness}"
    if depth == "kind":
        return kind
    return "overall"


def expected_key(row: dict[str, Any], depth: str) -> str:
    kind = str(row.get("kind") or "")
    harness = str(row.get("harness") or "")
    control_type = str(row.get("control_type") or "")
    if depth == "kind_harness_control":
        return f"{kind}:{harness}:{control_type}"
    if depth == "kind_harness":
        return f"{kind}:{harness}"
    if depth == "kind":
        return kind
    return "overall"


def load_runtime_observations(
    report_dirs: list[Path],
    *,
    timeout_sec: int,
    max_sample_gap_sec: int,
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for report_dir in report_dirs:
        summary_path = report_dir / "summary.json"
        if not summary_path.is_file():
            continue
        summary = load_json(summary_path)
        timed_rows: list[dict[str, Any]] = []
        for row in summary.get("rows", []) or []:
            start = parse_run_start(str(row.get("run_id") or ""))
            if start is None:
                continue
            timed_rows.append({"start": start, "row": row})
        timed_rows.sort(key=lambda item: item["start"])
        for current, nxt in zip(timed_rows, timed_rows[1:]):
            seconds = (nxt["start"] - current["start"]).total_seconds()
            if seconds <= 0 or seconds > max_sample_gap_sec:
                continue
            if seconds > timeout_sec * 3:
                continue
            row = current["row"]
            observations.append(
                {
                    "seconds": seconds,
                    "source_report": relpath(report_dir),
                    "run_id": row.get("run_id", ""),
                    "run_kind": row.get("run_kind", ""),
                    "harness": row.get("harness", ""),
                    "control_type": row.get("control_type", ""),
                    "suite": row.get("suite", ""),
                    "paper_family": row.get("paper_family", ""),
                    "case_dir": row.get("case_dir", ""),
                }
            )
    return observations


def group_observations(observations: list[dict[str, Any]]) -> dict[str, dict[str, list[float]]]:
    groups: dict[str, dict[str, list[float]]] = {
        "overall": defaultdict(list),
        "kind": defaultdict(list),
        "kind_harness": defaultdict(list),
        "kind_harness_control": defaultdict(list),
    }
    for obs in observations:
        seconds = float(obs["seconds"])
        for depth in groups:
            groups[depth][observation_key(obs, depth)].append(seconds)
    return groups


def estimate_row_seconds(
    row: dict[str, Any],
    grouped: dict[str, dict[str, list[float]]],
    *,
    fallback_sec: int,
) -> tuple[float, str]:
    depths = ("kind_harness_control", "kind_harness", "kind", "overall")
    if str(row.get("kind") or "") != "control":
        depths = ("kind_harness", "kind", "overall")
    for depth in depths:
        key = expected_key(row, depth)
        values = grouped.get(depth, {}).get(key, [])
        if values:
            return percentile(values, 0.50), f"{depth}:{key}"
    return float(fallback_sec), "timeout_fallback"


def estimate_rows(
    rows: list[dict[str, Any]],
    grouped: dict[str, dict[str, list[float]]],
    *,
    fallback_sec: int,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        seconds, source = estimate_row_seconds(row, grouped, fallback_sec=fallback_sec)
        out.append({**row, "estimated_seconds": round(seconds, 2), "estimate_source": source})
    return out


def summarize_estimates(rows: list[dict[str, Any]], key_fields: list[str]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        key = ":".join(str(row.get(field) or "") for field in key_fields) or "all"
        grouped[key].append(float(row.get("estimated_seconds") or 0))
    return {
        key: {
            "rows": len(values),
            "estimated_sec": round(sum(values), 2),
            "estimated_human": format_duration(sum(values)),
            "p50_row_sec": round(percentile(values, 0.50), 2),
        }
        for key, values in sorted(grouped.items())
    }


def matching_batch_rows(batch: dict[str, Any], estimated_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    kind = batch.get("kind")
    harness = batch.get("harness")
    controls = set(batch.get("control_types") or [])
    rows: list[dict[str, Any]] = []
    for row in estimated_rows:
        if row.get("kind") != kind or row.get("harness") != harness:
            continue
        if kind == "control" and controls and row.get("control_type") not in controls:
            continue
        rows.append(row)
    return rows


def build_budget(
    *,
    root: Path = ROOT,
    plan_path: Path = DEFAULT_PLAN,
    sample_report_dirs: list[Path] | None = None,
    timeout_sec: int | None = None,
    max_sample_gap_sec: int = 900,
    buffer_fraction: float = 0.20,
    preview_limit: int = 25,
) -> dict[str, Any]:
    plan = plan_paper_experiment_matrix.load_json(plan_path)
    effective_timeout = int(timeout_sec or plan.get("timeout_sec") or plan_paper_experiment_matrix.DEFAULT_TIMEOUT_SEC)
    report_dirs = sample_report_dirs if sample_report_dirs is not None else DEFAULT_SAMPLE_REPORT_DIRS
    observations = load_runtime_observations(
        report_dirs,
        timeout_sec=effective_timeout,
        max_sample_gap_sec=max_sample_gap_sec,
    )
    grouped = group_observations(observations)
    progress = check_paper_matrix_progress.build_progress_report(root=root, plan_path=plan_path, preview_limit=preview_limit)
    missing_rows = [row for row in progress["rows"] if not row["completed"]]
    estimated_missing = estimate_rows(missing_rows, grouped, fallback_sec=effective_timeout)
    total_missing_sec = sum(float(row["estimated_seconds"]) for row in estimated_missing)
    timeout_upper_sec = len(missing_rows) * effective_timeout
    # Budget estimation is deliberately read-only and may be used before a
    # formal clean suite lock exists.  The resulting preview queue remains
    # non-executable; the formal queue consumer still requires a canonical
    # clean lock and rejects this preview provenance.
    queue = export_paper_run_queue.build_queue(
        root=root,
        plan_path=plan_path,
        preview_limit=preview_limit,
        allow_unlocked_preview=True,
    )
    batch_estimates: list[dict[str, Any]] = []
    for batch in queue.get("coalesced_batches", []):
        rows = matching_batch_rows(batch, estimated_missing)
        seconds = sum(float(row.get("estimated_seconds") or 0) for row in rows)
        batch_estimates.append(
            {
                "batch_id": batch.get("batch_id", ""),
                "kind": batch.get("kind", ""),
                "harness": batch.get("harness", ""),
                "control_types": batch.get("control_types", []),
                "missing_rows": len(rows),
                "estimated_sec": round(seconds, 2),
                "estimated_human": format_duration(seconds),
                "buffered_sec": round(seconds * (1 + buffer_fraction), 2),
                "buffered_human": format_duration(seconds * (1 + buffer_fraction)),
                "command": batch.get("command", ""),
            }
        )

    sample_reports = [relpath(path, root) for path in report_dirs]
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "plan_path": relpath(plan_path, root),
        "matrix_id": plan.get("matrix_id", ""),
        "case_set": plan.get("case_set", ""),
        "timeout_sec": effective_timeout,
        "max_sample_gap_sec": max_sample_gap_sec,
        "buffer_fraction": buffer_fraction,
        "sample_reports": sample_reports,
        "summary": {
            "expected_rows": progress["summary"]["expected_rows"],
            "completed_rows": progress["summary"]["completed_rows"],
            "missing_rows": len(missing_rows),
            "observed_runtime_samples": len(observations),
            "estimated_missing_sec": round(total_missing_sec, 2),
            "estimated_missing_human": format_duration(total_missing_sec),
            "buffered_missing_sec": round(total_missing_sec * (1 + buffer_fraction), 2),
            "buffered_missing_human": format_duration(total_missing_sec * (1 + buffer_fraction)),
            "timeout_upper_bound_sec": timeout_upper_sec,
            "timeout_upper_bound_human": format_duration(timeout_upper_sec),
        },
        "observed_runtime": {
            "overall": summarize_seconds(grouped["overall"].get("overall", [])),
            "by_kind": {key: summarize_seconds(values) for key, values in sorted(grouped["kind"].items())},
            "by_kind_harness": {key: summarize_seconds(values) for key, values in sorted(grouped["kind_harness"].items())},
            "by_kind_harness_control": {
                key: summarize_seconds(values) for key, values in sorted(grouped["kind_harness_control"].items())
            },
        },
        "estimated_missing": {
            "by_kind_harness": summarize_estimates(estimated_missing, ["kind", "harness"]),
            "by_control_type": summarize_estimates(
                [row for row in estimated_missing if row.get("kind") == "control"],
                ["control_type", "harness"],
            ),
            "source_counts": {
                source: sum(1 for row in estimated_missing if row.get("estimate_source") == source)
                for source in sorted({str(row.get("estimate_source") or "") for row in estimated_missing})
            },
        },
        "coalesced_batches": batch_estimates,
        "missing_rows_preview": estimated_missing[:preview_limit],
        "notes": [
            "Runtime samples are inferred from adjacent run_id start timestamps in report summary rows.",
            "The final row in each sampled report has no following start timestamp and is not used as a sample.",
            "The current budget is scoped to the Claude Code harness with its default-configured Kimi K2.6 runtime.",
            "Estimates are planning aids, not evidence for benchmark outcomes.",
        ],
    }


def render_stat_row(name: str, item: dict[str, Any]) -> str:
    return (
        f"| {name} | {item.get('count', 0)} | {item.get('mean_sec', 0)} | "
        f"{item.get('p50_sec', 0)} | {item.get('p90_sec', 0)} | {item.get('max_sec', 0)} |"
    )


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Paper Run Budget Estimate",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- matrix_id: `{report['matrix_id']}`",
        f"- case_set: `{report['case_set']}`",
        f"- timeout_sec: `{report['timeout_sec']}`",
        f"- expected_rows: `{summary['expected_rows']}`",
        f"- completed_rows: `{summary['completed_rows']}`",
        f"- missing_rows: `{summary['missing_rows']}`",
        f"- observed_runtime_samples: `{summary['observed_runtime_samples']}`",
        f"- estimated_missing: `{summary['estimated_missing_human']}`",
        f"- estimated_missing_with_buffer: `{summary['buffered_missing_human']}`",
        f"- timeout_upper_bound: `{summary['timeout_upper_bound_human']}`",
        "",
        "## Sample Reports",
        "",
    ]
    lines.extend(f"- `{path}`" for path in report["sample_reports"])
    lines += [
        "",
        "## Observed Runtime Samples",
        "",
        "| Group | Samples | Mean sec | P50 sec | P90 sec | Max sec |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
        render_stat_row("overall", report["observed_runtime"]["overall"]),
    ]
    for key, item in report["observed_runtime"]["by_kind_harness"].items():
        lines.append(render_stat_row(key, item))

    lines += [
        "",
        "## Missing Rows Estimate",
        "",
        "| Group | Rows | Estimate | P50 row sec |",
        "| --- | ---: | ---: | ---: |",
    ]
    for key, item in report["estimated_missing"]["by_kind_harness"].items():
        lines.append(f"| {key} | {item['rows']} | {item['estimated_human']} | {item['p50_row_sec']} |")

    lines += [
        "",
        "## Coalesced Batch Estimates",
        "",
        "| Batch | Rows | Estimate | With Buffer | Command |",
        "| --- | ---: | ---: | ---: | --- |",
    ]
    for batch in report["coalesced_batches"]:
        lines.append(
            f"| {batch['batch_id']} | {batch['missing_rows']} | {batch['estimated_human']} | "
            f"{batch['buffered_human']} | `{batch['command']}` |"
        )

    lines += [
        "",
        "## Estimate Sources",
        "",
        "| Source | Rows |",
        "| --- | ---: |",
    ]
    for source, count in report["estimated_missing"]["source_counts"].items():
        lines.append(f"| {source} | {count} |")

    lines += ["", "## Notes", ""]
    lines.extend(f"- {note}" for note in report["notes"])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Estimate paper run wall-clock budget.")
    parser.add_argument("--plan", default=str(DEFAULT_PLAN))
    parser.add_argument("--sample-report-dir", action="append", default=[])
    parser.add_argument("--timeout-sec", type=int, default=0)
    parser.add_argument("--max-sample-gap-sec", type=int, default=900)
    parser.add_argument("--buffer-fraction", type=float, default=0.20)
    parser.add_argument("--preview-limit", type=int, default=25)
    parser.add_argument("--out-json", default=str(DEFAULT_OUT_JSON))
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD))
    args = parser.parse_args()

    sample_dirs = [Path(item) for item in args.sample_report_dir] if args.sample_report_dir else None
    report = build_budget(
        root=ROOT,
        plan_path=Path(args.plan),
        sample_report_dirs=sample_dirs,
        timeout_sec=args.timeout_sec or None,
        max_sample_gap_sec=args.max_sample_gap_sec,
        buffer_fraction=args.buffer_fraction,
        preview_limit=args.preview_limit,
    )
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
