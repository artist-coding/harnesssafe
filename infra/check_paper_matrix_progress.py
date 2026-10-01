"""Compare the paper experiment plan with run-local result directories."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
import time
from typing import Any

try:
    from infra import plan_paper_experiment_matrix, result_classification
except ModuleNotFoundError:  # direct `python infra/check_paper_matrix_progress.py`
    import plan_paper_experiment_matrix  # type: ignore
    import result_classification  # type: ignore


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PLAN = ROOT / "docs" / "generated_artifacts" / "paper_experiment_matrix_plan.json"
DEFAULT_IN_PROGRESS_GRACE_SEC = 1800


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def split_cli_values(values: list[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or []:
        for part in str(value).split(","):
            token = part.strip()
            if token:
                out.append(token)
    return out


def norm_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def case_meta(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "case.json"
    if not path.is_file():
        return {}
    try:
        return load_json(path)
    except Exception:
        return {}


def run_kind_from_meta(meta: dict[str, Any]) -> str:
    return "control" if meta.get("is_control_run") or meta.get("control_type") else "attack"


def run_matches(run_dir: Path, expected: dict[str, Any]) -> bool:
    if not run_dir.is_dir() or not (run_dir / "case.json").is_file():
        return False
    meta = case_meta(run_dir)
    label = str(expected.get("label") or "")
    meta_label = str(meta.get("run_label") or "")
    formal_row_id = str(expected.get("expected_row_id") or "")
    if formal_row_id:
        # Formal rows are exact provenance matches.  Historical/ad-hoc runs
        # without these bindings must never satisfy SkipCompleted.
        if not label or meta_label != label:
            return False
        if str(meta.get("formal_row_id") or "") != formal_row_id:
            return False
        if str(meta.get("formal_isolated_home_id") or "") != str(
            expected.get("isolated_home_id") or ""
        ):
            return False
        token = str(expected.get("canary_token") or "")
        token_sha256 = hashlib.sha256(token.encode("utf-8")).hexdigest() if token else ""
        if not token or str(meta.get("canary_token") or "") != token:
            return False
        if str(meta.get("canary_token_sha256") or "").casefold() != token_sha256:
            return False
        if str(meta.get("model") or "") != str(expected.get("runtime_model") or ""):
            return False
        if str(meta.get("permission_profile") or "") != str(
            expected.get("permission_profile") or ""
        ):
            return False
        if str(meta.get("isolation_mode") or "") != str(expected.get("isolation_mode") or ""):
            return False
        try:
            if int(meta.get("timeout_sec") or 0) != int(expected.get("timeout_sec") or 0):
                return False
            if not 1 <= int(meta.get("formal_attempt") or 0) <= 3:
                return False
        except (TypeError, ValueError):
            return False
    elif label and label not in meta_label and label not in run_dir.name:
        return False
    harness = str(expected.get("harness") or "").lower()
    meta_harness = str(meta.get("harness") or "").lower()
    if formal_row_id:
        if not harness or meta_harness != harness:
            return False
    elif meta_harness:
        if meta_harness != harness:
            return False
    elif harness and f"_{harness}_" not in run_dir.name.lower():
        return False
    if run_kind_from_meta(meta) != str(expected.get("kind") or ""):
        return False
    control_type = str(expected.get("control_type") or "")
    if str(meta.get("control_type") or "") != control_type:
        return False
    return True


def matching_runs(root: Path, expected: dict[str, Any]) -> list[Path]:
    results_dir = root / "runs" / str(expected["case_dir"]) / "results"
    if not results_dir.is_dir():
        return []
    matches = [path for path in results_dir.iterdir() if run_matches(path, expected)]
    return sorted(matches, key=lambda path: (path.name, path.stat().st_mtime))


def newest_mtime(path: Path) -> float:
    mtimes = [path.stat().st_mtime]
    for child in path.iterdir():
        try:
            mtimes.append(child.stat().st_mtime)
        except OSError:
            continue
    return max(mtimes)


def run_without_oracle_is_in_progress(run_dir: Path, now: float, grace_sec: int) -> bool:
    if grace_sec <= 0:
        return False
    if (run_dir / "oracle.json").is_file():
        return False
    try:
        return now - newest_mtime(run_dir) <= grace_sec
    except OSError:
        return False


def run_has_authoritative_validity(run_dir: Path) -> bool:
    path = run_dir / "run_validity.json"
    if not path.is_file() or not (run_dir / "oracle.json").is_file():
        return False
    try:
        return result_classification.is_scored_run_validity(load_json(path))
    except Exception:
        return False


def run_has_terminal_model_protocol_outcome(run_dir: Path) -> bool:
    path = run_dir / "run_validity.json"
    if not path.is_file() or not (run_dir / "oracle.json").is_file():
        return False
    try:
        return result_classification.is_terminal_model_protocol_deviation(load_json(path))
    except Exception:
        return False


def row_key(row: dict[str, Any]) -> str:
    parts = [
        str(row.get("kind") or ""),
        str(row.get("control_type") or ""),
        str(row.get("trial") or ""),
        str(row.get("harness") or ""),
        str(row.get("label") or ""),
        str(row.get("case_dir") or ""),
    ]
    return "|".join(parts)


def empty_group() -> dict[str, int]:
    return {"expected": 0, "completed": 0, "incomplete": 0}


def add_group(groups: dict[str, dict[str, int]], key: str, completed: bool) -> None:
    group = groups[key]
    group["expected"] += 1
    if completed:
        group["completed"] += 1
    else:
        group["incomplete"] += 1


def build_progress_report(
    *,
    root: Path = ROOT,
    plan_path: Path = DEFAULT_PLAN,
    preview_limit: int = 25,
    harnesses: list[str] | None = None,
    in_progress_grace_sec: int = DEFAULT_IN_PROGRESS_GRACE_SEC,
) -> dict[str, Any]:
    plan = load_json(plan_path)
    plan_issues = plan_paper_experiment_matrix.validate_plan(plan, root=root)
    formal_locked = bool(
        plan.get("plan_status") == "formal_locked"
        and plan.get("formal_execution_eligible") is True
    )
    formal_provenance_matcher = None
    if formal_locked:
        # Import lazily to avoid the module-import cycle: the queue exporter
        # imports this progress module, while also owning the authoritative
        # strict materialization/runtime provenance matcher used by SkipCompleted.
        # A formal completion report must use exactly that matcher; otherwise
        # a row with a missing or tampered attestation could be reported as
        # complete even though the serial queue correctly refuses to skip it.
        try:
            from infra.export_paper_run_queue import formal_result_provenance_matches
        except ModuleNotFoundError:  # direct `python infra/check_paper_matrix_progress.py`
            from export_paper_run_queue import formal_result_provenance_matches  # type: ignore

        formal_provenance_matcher = formal_result_provenance_matches
    wanted_harnesses = {item.lower() for item in harnesses or []}
    rows: list[dict[str, Any]] = []
    by_kind: dict[str, dict[str, int]] = defaultdict(empty_group)
    by_harness: dict[str, dict[str, int]] = defaultdict(empty_group)
    by_kind_harness: dict[str, dict[str, int]] = defaultdict(empty_group)
    by_control_type: dict[str, dict[str, int]] = defaultdict(empty_group)
    duplicate_expected_rows = 0
    duplicate_run_count = 0
    duplicate_valid_expected_rows = 0
    duplicate_valid_run_count = 0
    duplicate_accounted_expected_rows = 0
    duplicate_accounted_run_count = 0
    unmatched_rows = 0
    matched_without_oracle_rows = 0
    in_progress_without_oracle_rows = 0
    stale_without_oracle_rows = 0
    now = time.time()

    for expected in plan.get("rows", []) or []:
        expected = (
            {**expected, "matrix_id": str(plan.get("matrix_id") or "")}
            if formal_locked
            else expected
        )
        expected_harness = str(expected.get("harness") or "")
        if wanted_harnesses and expected_harness.lower() not in wanted_harnesses:
            continue
        matches = matching_runs(root, expected)
        if formal_provenance_matcher is not None:
            matches = [
                path
                for path in matches
                if formal_provenance_matcher(path, expected)
            ]
        completed_matches = [path for path in matches if (path / "oracle.json").is_file()]
        valid_matches = [path for path in matches if run_has_authoritative_validity(path)]
        model_protocol_matches = [
            path for path in matches if run_has_terminal_model_protocol_outcome(path)
        ]
        accounted_matches = valid_matches + model_protocol_matches
        completed = len(accounted_matches) == 1
        selected = (
            accounted_matches[-1]
            if len(accounted_matches) == 1
            else (completed_matches[-1] if completed_matches else (matches[-1] if matches else None))
        )
        if not matches:
            unmatched_rows += 1
        elif not completed:
            matched_without_oracle_rows += 1
            if selected and run_without_oracle_is_in_progress(selected, now, in_progress_grace_sec):
                in_progress_without_oracle_rows += 1
            else:
                stale_without_oracle_rows += 1
        if len(matches) > 1:
            duplicate_expected_rows += 1
            duplicate_run_count += len(matches) - 1
        if len(valid_matches) > 1:
            duplicate_valid_expected_rows += 1
            duplicate_valid_run_count += len(valid_matches) - 1
        if len(accounted_matches) > 1:
            duplicate_accounted_expected_rows += 1
            duplicate_accounted_run_count += len(accounted_matches) - 1

        kind = str(expected.get("kind") or "")
        harness = expected_harness
        control_type = str(expected.get("control_type") or "")
        add_group(by_kind, kind, completed)
        add_group(by_harness, harness, completed)
        add_group(by_kind_harness, f"{kind}:{harness}", completed)
        if kind == "control":
            add_group(by_control_type, control_type, completed)

        rows.append(
            {
                "key": row_key(expected),
                "expected_row_id": expected.get("expected_row_id", ""),
                "queue_position": expected.get("queue_position", 0),
                "kind": kind,
                "control_type": control_type,
                "trial": expected.get("trial"),
                "harness": harness,
                "label": expected.get("label", ""),
                "suite": expected.get("suite", ""),
                "family": expected.get("family", ""),
                "case_dir": expected.get("case_dir", ""),
                "completed": completed,
                "execution_valid_completed": len(valid_matches) == 1,
                "model_protocol_terminal": len(model_protocol_matches) == 1,
                "matched_runs": len(matches),
                "completed_runs": len(completed_matches),
                "valid_completed_runs": len(valid_matches),
                "model_protocol_terminal_runs": len(model_protocol_matches),
                "accounted_terminal_runs": len(accounted_matches),
                "selected_run_dir": norm_path(selected, root) if selected else "",
                "selected_has_oracle": bool(selected and (selected / "oracle.json").is_file()),
                "selected_in_progress": bool(
                    selected
                    and not (selected / "oracle.json").is_file()
                    and run_without_oracle_is_in_progress(selected, now, in_progress_grace_sec)
                ),
            }
        )

    expected_rows = len(rows)
    completed_rows = sum(1 for row in rows if row["completed"])
    execution_valid_completed_rows = sum(1 for row in rows if row["execution_valid_completed"])
    model_protocol_terminal_rows = sum(1 for row in rows if row["model_protocol_terminal"])
    oracle_completed_rows = sum(1 for row in rows if row["completed_runs"] > 0)
    incomplete_rows = expected_rows - completed_rows
    # Count unresolved logical rows, not terminal artifacts.  A malformed
    # duplicate (for example one scored result plus one N-1 result for the
    # same expected row) must remain one unresolved row and must never drive
    # this summary negative through overlapping category counts.
    execution_invalid_or_unvalidated_rows = sum(
        1 for row in rows if not row["completed"]
    )
    issues: list[dict[str, Any]] = [
        {
            "severity": item.get("severity", "error"),
            "scope": "experiment_plan",
            "message": item.get("message", "experiment plan issue"),
            "detail": item.get("detail", {}),
        }
        for item in plan_issues
    ]
    if duplicate_expected_rows:
        issues.append(
            {
                "severity": "warning",
                "scope": "matrix_progress",
                "message": "multiple result directories match at least one expected row",
                "detail": {
                    "duplicate_expected_rows": duplicate_expected_rows,
                    "extra_matching_runs": duplicate_run_count,
                },
            }
        )
    if duplicate_valid_expected_rows:
        issues.append(
            {
                "severity": "error",
                "scope": "matrix_progress",
                "message": "multiple execution-valid results match at least one expected row",
                "detail": {
                    "duplicate_valid_expected_rows": duplicate_valid_expected_rows,
                    "extra_valid_runs": duplicate_valid_run_count,
                },
            }
        )
    if duplicate_accounted_expected_rows:
        issues.append(
            {
                "severity": "error",
                "scope": "matrix_progress",
                "message": "multiple terminal results match at least one expected row",
                "detail": {
                    "duplicate_accounted_expected_rows": duplicate_accounted_expected_rows,
                    "extra_accounted_runs": duplicate_accounted_run_count,
                },
            }
        )
    if stale_without_oracle_rows:
        issues.append(
            {
                "severity": "warning",
                "scope": "matrix_progress",
                "message": "some matching result directories do not have oracle.json",
                "detail": {
                    "matched_without_oracle_rows": matched_without_oracle_rows,
                    "stale_without_oracle_rows": stale_without_oracle_rows,
                    "in_progress_without_oracle_rows": in_progress_without_oracle_rows,
                },
            }
        )

    def freeze_groups(groups: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
        return {key: dict(value) for key, value in sorted(groups.items())}

    incomplete = [row for row in rows if not row["completed"]]
    complete = (
        completed_rows == expected_rows
        and duplicate_accounted_expected_rows == 0
        and not any(item.get("severity") == "error" for item in issues)
    )
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "plan_path": norm_path(plan_path, root),
        "matrix_id": plan.get("matrix_id", ""),
        "matrix_digest": plan.get("matrix_digest", ""),
        "case_set": plan.get("case_set", ""),
        "harnesses": sorted(wanted_harnesses) if wanted_harnesses else list(plan.get("harnesses", [])),
        "filtered": bool(wanted_harnesses),
        "complete": complete,
        "summary": {
            "expected_rows": expected_rows,
            "completed_rows": completed_rows,
            "oracle_completed_rows": oracle_completed_rows,
            "execution_valid_completed_rows": execution_valid_completed_rows,
            "model_protocol_terminal_rows": model_protocol_terminal_rows,
            "incomplete_rows": incomplete_rows,
            "execution_invalid_or_unvalidated_rows": execution_invalid_or_unvalidated_rows,
            "unmatched_rows": unmatched_rows,
            "matched_without_oracle_rows": matched_without_oracle_rows,
            "in_progress_without_oracle_rows": in_progress_without_oracle_rows,
            "stale_without_oracle_rows": stale_without_oracle_rows,
            "duplicate_expected_rows": duplicate_expected_rows,
            "extra_matching_runs": duplicate_run_count,
            "duplicate_valid_expected_rows": duplicate_valid_expected_rows,
            "extra_valid_runs": duplicate_valid_run_count,
            "duplicate_accounted_expected_rows": duplicate_accounted_expected_rows,
            "extra_accounted_runs": duplicate_accounted_run_count,
            # An empty filtered population has no completion rate.  Preserve
            # that distinction in JSON instead of presenting it as 0%.
            "completion_rate": completed_rows / expected_rows if expected_rows else None,
        },
        "groups": {
            "by_kind": freeze_groups(by_kind),
            "by_harness": freeze_groups(by_harness),
            "by_kind_harness": freeze_groups(by_kind_harness),
            "by_control_type": freeze_groups(by_control_type),
        },
        "issues": issues,
        "missing_preview": incomplete[:preview_limit],
        "rows": rows,
    }


def render_group_table(title: str, groups: dict[str, dict[str, int]]) -> list[str]:
    lines = [
        f"## {title}",
        "",
        "| Group | Expected | Completed | Incomplete |",
        "| --- | ---: | ---: | ---: |",
    ]
    for key, item in groups.items():
        lines.append(
            f"| {key or 'n/a'} | {item.get('expected', 0)} | "
            f"{item.get('completed', 0)} | {item.get('incomplete', 0)} |"
        )
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    completion_rate = summary.get("completion_rate")
    completion_rate_text = (
        f"{float(completion_rate):.3f}" if completion_rate is not None else "n/a"
    )
    lines = [
        "# Paper Matrix Progress",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- matrix_id: `{report['matrix_id']}`",
        f"- matrix_digest: `{report['matrix_digest']}`",
        f"- case_set: `{report['case_set']}`",
        f"- harnesses: `{','.join(report.get('harnesses', [])) or 'all'}`",
        f"- filtered: `{str(report.get('filtered', False)).lower()}`",
        f"- complete: `{str(report['complete']).lower()}`",
        f"- expected_rows: `{summary['expected_rows']}`",
        f"- completed_rows: `{summary['completed_rows']}`",
        f"- oracle_completed_rows: `{summary.get('oracle_completed_rows', 0)}`",
        f"- execution_valid_completed_rows: `{summary.get('execution_valid_completed_rows', 0)}`",
        f"- model_protocol_terminal_rows: `{summary.get('model_protocol_terminal_rows', 0)}`",
        f"- incomplete_rows: `{summary['incomplete_rows']}`",
        f"- execution_invalid_or_unvalidated_rows: `{summary.get('execution_invalid_or_unvalidated_rows', 0)}`",
        f"- unmatched_rows: `{summary['unmatched_rows']}`",
        f"- matched_without_oracle_rows: `{summary['matched_without_oracle_rows']}`",
        f"- in_progress_without_oracle_rows: `{summary.get('in_progress_without_oracle_rows', 0)}`",
        f"- stale_without_oracle_rows: `{summary.get('stale_without_oracle_rows', 0)}`",
        f"- duplicate_expected_rows: `{summary['duplicate_expected_rows']}`",
        f"- duplicate_valid_expected_rows: `{summary.get('duplicate_valid_expected_rows', 0)}`",
        f"- duplicate_accounted_expected_rows: `{summary.get('duplicate_accounted_expected_rows', 0)}`",
        f"- completion_rate: `{completion_rate_text}`",
        "",
    ]
    groups = report["groups"]
    lines.extend(render_group_table("By Kind And Harness", groups["by_kind_harness"]))
    lines += ["", *render_group_table("By Control Type", groups["by_control_type"])]

    lines += ["", "## Missing Preview", ""]
    if report.get("missing_preview"):
        lines += ["| Kind | Harness | Trial | Control | Case | Label |", "| --- | --- | ---: | --- | --- | --- |"]
        for row in report["missing_preview"]:
            lines.append(
                f"| {row.get('kind', '')} | {row.get('harness', '')} | "
                f"{row.get('trial', '')} | {row.get('control_type', '')} | "
                f"{row.get('case_dir', '')} | {row.get('label', '')} |"
            )
    else:
        lines.append("- none")

    lines += ["", "## Issues", ""]
    if report.get("issues"):
        lines += ["| Severity | Scope | Message |", "| --- | --- | --- |"]
        for issue in report["issues"]:
            lines.append(f"| {issue['severity']} | {issue['scope']} | {issue['message']} |")
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check paper experiment matrix completion against a plan.")
    parser.add_argument("--plan", default=str(DEFAULT_PLAN), help="Path to paper_experiment_matrix_plan.json.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of Markdown.")
    parser.add_argument("--out", default="", help="Optional output path.")
    parser.add_argument("--preview-limit", type=int, default=25)
    parser.add_argument(
        "--in-progress-grace-sec",
        type=int,
        default=DEFAULT_IN_PROGRESS_GRACE_SEC,
        help="Treat matching run directories without oracle.json as in-progress for this many seconds after their newest file update.",
    )
    parser.add_argument("--harness", action="append", default=[], help="Filter expected rows by harness. Repeat or comma-separate values.")
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="Exit non-zero when any expected row lacks a completed oracle.json.",
    )
    args = parser.parse_args()

    report = build_progress_report(
        plan_path=Path(args.plan),
        preview_limit=args.preview_limit,
        harnesses=split_cli_values(args.harness),
        in_progress_grace_sec=args.in_progress_grace_sec,
    )
    text = json.dumps(report, indent=2, ensure_ascii=False) if args.json else render_markdown(report)
    if args.out:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 1 if args.require_complete and not report["complete"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
