"""Generate a reviewer-facing submission package manifest for the paper track."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent

DEFAULT_ATTACK_LABEL = "paper_all_current"
DEFAULT_CONTROL_LABEL = "paper_controls_all_current"
DEFAULT_TABLE_DIR = "runs/_reports/paper_all_current/paper_tables"
DEFAULT_CASE_EVIDENCE_DIR = "runs/_reports/paper_all_current/case_study_evidence"
DEFAULT_BUNDLE_DIR = "runs/_artifacts/repro_bundles/paper_all_current"

ENTRYPOINT_FILES = [
    "README.md",
    "RUNBOOK.md",
    "docs/README.md",
    "docs/paper_artifact_evaluation_readme.md",
    "docs/paper_current_status.md",
    "docs/paper_draft.md",
]

CONTROL_FILES = [
    "docs/generated_artifacts/paper_suite_lock.json",
    "docs/generated_artifacts/paper_experiment_matrix_plan.json",
    "docs/generated_artifacts/paper_experiment_matrix_plan.md",
    "docs/generated_artifacts/paper_experiment_matrix_progress.md",
    "docs/generated_artifacts/paper_experiment_matrix_progress_claude.md",
    "docs/generated_artifacts/paper_run_queue.json",
    "docs/generated_artifacts/paper_run_queue.md",
    "docs/generated_artifacts/paper_run_execution_plan.json",
    "docs/generated_artifacts/paper_run_execution_plan.md",
    "docs/generated_artifacts/paper_run_budget.json",
    "docs/generated_artifacts/paper_run_budget.md",
    "docs/generated_artifacts/paper_submission_gap_report.md",
    "docs/generated_artifacts/paper_submission_gap_report.json",
    "docs/generated_artifacts/paper_submission_objective_audit.md",
    "docs/generated_artifacts/paper_submission_objective_audit.json",
    "docs/generated_artifacts/paper_live_status.json",
    "docs/generated_artifacts/paper_live_status.md",
    "docs/generated_artifacts/paper_live_status_check.md",
]

PAPER_EVIDENCE_FILES = [
    "docs/generated_artifacts/benchmark_card.json",
    "docs/generated_artifacts/benchmark_card.md",
    "docs/generated_artifacts/paper_supplementary_appendix.json",
    "docs/generated_artifacts/paper_supplementary_appendix.md",
    "docs/generated_artifacts/paper_supplementary_appendix.tex",
    "docs/generated_artifacts/paper_oracle_coverage.json",
    "docs/generated_artifacts/paper_oracle_coverage.md",
    "docs/generated_artifacts/paper_threat_model_card.json",
    "docs/generated_artifacts/paper_threat_model_card.md",
    "docs/generated_artifacts/paper_statistical_analysis.json",
    "docs/generated_artifacts/paper_statistical_analysis.md",
    "docs/generated_artifacts/paper_claim_evidence_map.json",
    "docs/generated_artifacts/paper_claim_evidence_map.md",
    "docs/generated_artifacts/paper_control_integrity_report.json",
    "docs/generated_artifacts/paper_control_integrity_report.md",
    "docs/generated_artifacts/paper_figures.json",
    "docs/generated_artifacts/paper_figures.md",
    "docs/figures/figure_1_benchmark_frame.svg",
    "docs/generated_artifacts/figures/figure_2_core_results.svg",
    "docs/generated_artifacts/paper_bibliography_check.json",
    "docs/generated_artifacts/paper_bibliography_check.md",
    "docs/generated_artifacts/paper_full_suite_eligibility.json",
    "docs/generated_artifacts/paper_full_suite_eligibility.md",
    "docs/generated_artifacts/paper_external_validity_plan.json",
    "docs/generated_artifacts/paper_external_validity_plan.md",
]

RELEASE_METADATA_FILES = [
    "CITATION.cff",
    "docs/release_metadata_final.json",
]

REPORT_FILES = [
    "summary.json",
    "report.md",
    "results.csv",
    "case_summary.csv",
    "family_macro.csv",
    "harness_macro.csv",
    "failures.json",
]

ATTACK_CHECK_FILES = [
    "paper_result_quality_gate.md",
    "paper_manuscript_check.md",
    "paper_numbers_check.md",
    "paper_case_study_check.md",
]

TABLE_FILES = [
    "paper_tables.md",
    "paper_tables.json",
    "main_results_table.tex",
    "family_results_table.tex",
    "control_results_table.tex",
]

CASE_EVIDENCE_FILES = [
    "case_study_evidence.json",
    "case_study_evidence.md",
]


def relpath(path: Path, root: Path = ROOT) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError:
        return {}


def record_for_path(root: Path, path: Path, role: str) -> dict[str, Any]:
    exists = path.is_file()
    return {
        "role": role,
        "path": relpath(path, root),
        "exists": exists,
        "bytes": path.stat().st_size if exists else 0,
        "sha256": sha256(path) if exists else "",
    }


def file_record(root: Path, path_text: str, role: str) -> dict[str, Any]:
    path = root / path_text
    return record_for_path(root, path, role)


def records_from_dir(root: Path, base_dir: str, names: list[str], role_prefix: str) -> list[dict[str, Any]]:
    base_path = Path(base_dir)
    if not base_path.is_absolute():
        base_path = root / base_path
    return [
        record_for_path(root, base_path / name, f"{role_prefix}:{name}")
        for name in names
    ]


def join_path_text(base_dir: str, name: str) -> str:
    trimmed = base_dir.rstrip("/\\")
    return f"{trimmed}/{name}".replace("\\", "/")


def gate_summary(root: Path, path_text: str) -> dict[str, Any]:
    path = root / path_text
    return {
        "path": path_text.replace("\\", "/"),
        "exists": path.is_file(),
    }


def as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def metric_value(block: Any, field: str, default: Any = None) -> Any:
    return block.get(field, default) if isinstance(block, dict) else default


def display_metric(value: Any) -> Any:
    return "n/a" if value is None else value


def inferred_success_count(rate_value: Any, denominator: int) -> int | None:
    if denominator <= 0:
        return 0 if rate_value is None else None
    if rate_value is None or rate_value == "":
        return None
    try:
        return round(float(rate_value) * denominator)
    except (TypeError, ValueError):
        return None


def result_summary(stats: dict[str, Any], benchmark: dict[str, Any]) -> dict[str, Any]:
    """Read legacy v1 or result-class-aware v2 paper result artifacts."""

    stats_schema = as_int(stats.get("schema_version"))
    benchmark_schema = as_int(benchmark.get("schema_version"))
    if stats_schema >= 2:
        effects = stats.get("primary_effects", {})
        effects = effects if isinstance(effects, dict) else {}
        matrix = stats.get("matrix", {})
        matrix = matrix if isinstance(matrix, dict) else {}
        conditional = effects.get("conditional_attack_success", effects.get("attack_success", {}))
        confirmed = effects.get("confirmed_compromise", {})
        control_conditional = effects.get(
            "control_conditional_violation",
            effects.get("control_attack_success", {}),
        )
        return {
            "attack_success": as_int(metric_value(conditional, "successes", 0)),
            "confirmed_compromise": as_int(metric_value(confirmed, "successes", 0)),
            "control_attack_success": as_int(
                metric_value(control_conditional, "successes", 0)
            ),
            "attack_scored_rows": as_int(
                matrix.get("attack_scored_rows", matrix.get("attack_rows", 0))
            ),
            "attack_asr_eligible_scored_rows": as_int(
                metric_value(conditional, "trials", 0)
            ),
            "attack_n_minus_1_rows": (
                as_int(matrix.get("attack_n_minus_1_rows"))
                if matrix.get("attack_n_minus_1_rows") is not None
                else None
            ),
            "attack_accounted_terminal_rows": (
                as_int(matrix.get("attack_accounted_terminal_rows"))
                if matrix.get("attack_accounted_terminal_rows") is not None
                else None
            ),
            "attack_protocol_denominator_rows": (
                as_int(matrix.get("attack_protocol_denominator_rows"))
                if matrix.get("attack_protocol_denominator_rows") is not None
                else None
            ),
            "protocol_completion_rate": metric_value(
                effects.get("protocol_completion"), "rate"
            ),
            "model_nonconformance_rate": metric_value(
                effects.get("model_nonconformance"), "rate"
            ),
            "conditional_asr_rate": metric_value(conditional, "rate"),
            "end_to_end_attack_rate": metric_value(
                effects.get("end_to_end_attack"), "rate"
            ),
            "end_to_end_attack_success": as_int(
                metric_value(effects.get("end_to_end_attack"), "successes", 0)
            ),
            "control_scored_rows": as_int(
                matrix.get("control_scored_rows", matrix.get("control_rows", 0))
            ),
            "control_asr_eligible_scored_rows": as_int(
                metric_value(control_conditional, "trials", 0)
            ),
            "control_n_minus_1_rows": (
                as_int(matrix.get("control_n_minus_1_rows"))
                if matrix.get("control_n_minus_1_rows") is not None
                else None
            ),
            "control_accounted_terminal_rows": (
                as_int(matrix.get("control_accounted_terminal_rows"))
                if matrix.get("control_accounted_terminal_rows") is not None
                else None
            ),
            "control_protocol_denominator_rows": (
                as_int(matrix.get("control_protocol_denominator_rows"))
                if matrix.get("control_protocol_denominator_rows") is not None
                else None
            ),
            "control_protocol_completion_rate": metric_value(
                effects.get("control_protocol_completion"), "rate"
            ),
            "control_model_nonconformance_rate": metric_value(
                effects.get("control_model_nonconformance"), "rate"
            ),
            "control_conditional_violation_rate": metric_value(
                control_conditional, "rate"
            ),
            "control_end_to_end_violation_rate": metric_value(
                effects.get("control_end_to_end_violation"), "rate"
            ),
            "control_end_to_end_violation_success": as_int(
                metric_value(
                    effects.get("control_end_to_end_violation"), "successes", 0
                )
            ),
            "source_schema_version": 2,
        }

    if benchmark_schema >= 2:
        current = benchmark.get("current_results", {})
        current = current if isinstance(current, dict) else {}
        controls = benchmark.get("controls", {})
        controls = controls if isinstance(controls, dict) else {}
        return {
            "attack_success": as_int(current.get("attack_success_rows")),
            "confirmed_compromise": as_int(current.get("confirmed_rows")),
            "control_attack_success": as_int(controls.get("attack_success_rows")),
            "attack_scored_rows": as_int(current.get("scored_trials")),
            "attack_asr_eligible_scored_rows": as_int(
                current.get("asr_eligible_scored_trials")
            ),
            "attack_n_minus_1_rows": current.get("n_minus_1_trials"),
            "attack_accounted_terminal_rows": current.get("accounted_terminal_trials"),
            "attack_protocol_denominator_rows": current.get(
                "protocol_denominator_trials"
            ),
            "protocol_completion_rate": current.get("protocol_completion_rate"),
            "model_nonconformance_rate": current.get("model_nonconformance_rate"),
            "conditional_asr_rate": current.get(
                "conditional_asr_rate", current.get("pooled_asr_rate")
            ),
            "end_to_end_attack_rate": current.get("end_to_end_attack_rate"),
            "end_to_end_attack_success": inferred_success_count(
                current.get("end_to_end_attack_rate"),
                as_int(current.get("protocol_denominator_trials")),
            ),
            "control_scored_rows": as_int(controls.get("scored_trials")),
            "control_asr_eligible_scored_rows": as_int(
                controls.get("asr_eligible_scored_trials")
            ),
            "control_n_minus_1_rows": controls.get("n_minus_1_trials"),
            "control_accounted_terminal_rows": controls.get("accounted_terminal_trials"),
            "control_protocol_denominator_rows": controls.get(
                "protocol_denominator_trials"
            ),
            "control_protocol_completion_rate": controls.get("protocol_completion_rate"),
            "control_model_nonconformance_rate": controls.get("model_nonconformance_rate"),
            "control_conditional_violation_rate": controls.get("conditional_violation_rate"),
            "control_end_to_end_violation_rate": controls.get("end_to_end_violation_rate"),
            "control_end_to_end_violation_success": inferred_success_count(
                controls.get("end_to_end_violation_rate"),
                as_int(controls.get("protocol_denominator_trials")),
            ),
            "source_schema_version": 2,
        }

    benchmark_results = benchmark.get("results", {})
    benchmark_results = benchmark_results if isinstance(benchmark_results, dict) else {}
    stats_summary = stats.get("summary", {})
    stats_summary = stats_summary if isinstance(stats_summary, dict) else {}
    return {
        "attack_success": stats_summary.get(
            "attack_success", benchmark_results.get("attack_success", 0)
        ),
        "confirmed_compromise": stats_summary.get(
            "confirmed", benchmark_results.get("confirmed_compromise", 0)
        ),
        "control_attack_success": stats_summary.get(
            "control_success", benchmark_results.get("control_attack_success", 0)
        ),
        "source_schema_version": 1,
    }


def build_file_records(
    root: Path,
    attack_label: str,
    control_label: str,
    table_dir: str,
    case_evidence_dir: str,
    bundle_dir: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in ENTRYPOINT_FILES:
        records.append(file_record(root, path, f"entrypoint:{path}"))
    for path in CONTROL_FILES:
        records.append(file_record(root, path, f"control:{path}"))
    for path in PAPER_EVIDENCE_FILES:
        records.append(file_record(root, path, f"paper_evidence:{path}"))
    for path in RELEASE_METADATA_FILES:
        records.append(file_record(root, path, f"release_metadata:{path}"))
    records.extend(
        records_from_dir(
            root,
            f"runs/_reports/{attack_label}",
            [*REPORT_FILES, *ATTACK_CHECK_FILES],
            f"attack_report:{attack_label}",
        )
    )
    if control_label:
        records.extend(
            records_from_dir(
                root,
                f"runs/_reports/{control_label}",
                REPORT_FILES,
                f"control_report:{control_label}",
            )
        )
    records.extend(records_from_dir(root, table_dir, TABLE_FILES, "paper_tables"))
    records.extend(records_from_dir(root, case_evidence_dir, CASE_EVIDENCE_FILES, "case_study_evidence"))
    return records


def build_submission_package_manifest(
    root: Path = ROOT,
    attack_label: str = DEFAULT_ATTACK_LABEL,
    control_label: str = DEFAULT_CONTROL_LABEL,
    table_dir: str = DEFAULT_TABLE_DIR,
    case_evidence_dir: str = DEFAULT_CASE_EVIDENCE_DIR,
    bundle_dir: str = DEFAULT_BUNDLE_DIR,
) -> dict[str, Any]:
    plan = load_json(root / "docs/generated_artifacts/paper_experiment_matrix_plan.json")
    gap = load_json(root / "docs/generated_artifacts/paper_submission_gap_report.json")
    live = load_json(root / "docs/generated_artifacts/paper_live_status.json")
    benchmark = load_json(root / "docs/generated_artifacts/benchmark_card.json")
    stats = load_json(root / "docs/generated_artifacts/paper_statistical_analysis.json")
    full_progress = live.get("matrix_progress", {}).get("full", {})
    full_summary = full_progress.get("summary", {})
    plan_summary = plan.get("summary", {})
    results = result_summary(stats, benchmark)
    files = build_file_records(root, attack_label, control_label, table_dir, case_evidence_dir, bundle_dir)
    missing_files = [item for item in files if not item["exists"]]
    manual_decisions = gap.get("manual_decisions", [])
    gap_summary = gap.get("summary", {})
    return {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "labels": {
            "attack": attack_label,
            "control": control_label,
        },
        "paths": {
            "table_dir": table_dir.replace("\\", "/"),
            "case_evidence_dir": case_evidence_dir.replace("\\", "/"),
            "bundle_dir": bundle_dir.replace("\\", "/"),
            "current_artifact_gate": f"runs/_reports/{attack_label}/paper_artifact_gate.md",
            "submission_artifact_gate": f"runs/_reports/{attack_label}/paper_artifact_gate_submission.md",
        },
        "baseline": plan.get("baseline") or live.get("active_baseline") or {},
        "matrix": {
            "matrix_id": plan.get("matrix_id") or full_progress.get("matrix_id") or "",
            "case_set": plan.get("case_set") or full_progress.get("case_set") or "",
            "case_count": plan.get("cases", {}).get("count", 0),
            "rows_total": plan_summary.get("rows_total", full_summary.get("expected_rows", 0)),
            "attack_rows": plan_summary.get(
                "attack_rows", benchmark.get("matrix", {}).get("attack_rows", 0)
            ),
            "control_rows": plan_summary.get(
                "control_rows", benchmark.get("matrix", {}).get("control_rows", 0)
            ),
            "completed_rows": full_summary.get("completed_rows", 0),
            "execution_valid_completed_rows": full_summary.get(
                "execution_valid_completed_rows", full_summary.get("completed_rows", 0)
            ),
            "model_protocol_terminal_rows": full_summary.get(
                "model_protocol_terminal_rows", 0
            ),
            "complete": bool(full_progress.get("complete", False)),
        },
        "results": results,
        "release_status": {
            "submission_ready": bool(gap.get("submission_ready", False)),
            "errors": gap_summary.get("error_count", gap.get("errors", 0)),
            "warnings": gap_summary.get("warning_count", gap.get("warnings", 0)),
            "pending_manual_decisions": gap_summary.get(
                "pending_manual_decision_count",
                gap_summary.get("pending_manual_decisions", 0),
            ),
            "blocking_manual_decisions": gap_summary.get(
                "blocking_manual_decision_count",
                gap_summary.get("blocking_manual_decisions", 0),
            ),
            "manual_decisions": manual_decisions,
        },
        "gates": {
            "current_artifact_gate": gate_summary(root, f"runs/_reports/{attack_label}/paper_artifact_gate.md"),
            "submission_artifact_gate": gate_summary(root, f"runs/_reports/{attack_label}/paper_artifact_gate_submission.md"),
            "repro_bundle_manifest": gate_summary(root, join_path_text(bundle_dir, "repro_manifest.json")),
            "repro_bundle_markdown": gate_summary(root, join_path_text(bundle_dir, "repro_manifest.md")),
        },
        "files": files,
        "missing_files": missing_files,
        "validation_commands": [
            ".\\infra\\run_paper_preflight.ps1 -Profile current_claude",
            ".\\infra\\run_paper_preflight.ps1 -Profile submission",
            "python infra\\check_release_metadata.py --require-license",
            "python infra\\check_public_artifact_safety.py --bundle-dir " + bundle_dir.replace("/", "\\"),
        ],
    }


def render_markdown(manifest: dict[str, Any]) -> str:
    matrix = manifest.get("matrix", {})
    results = manifest.get("results", {})
    release = manifest.get("release_status", {})
    current_gate = manifest.get("gates", {}).get("current_artifact_gate", {})
    submission_gate = manifest.get("gates", {}).get("submission_artifact_gate", {})
    lines = [
        "# Paper Submission Package Manifest",
        "",
        f"- generated_at: `{manifest.get('generated_at')}`",
        f"- attack_label: `{manifest.get('labels', {}).get('attack')}`",
        f"- control_label: `{manifest.get('labels', {}).get('control')}`",
        f"- baseline: `{manifest.get('baseline', {}).get('name', '')}`",
        f"- matrix: `{matrix.get('completed_rows', 0)}/{matrix.get('rows_total', 0)}`",
        f"- submission_ready: `{str(release.get('submission_ready')).lower()}`",
        f"- pending_manual_decisions: `{release.get('pending_manual_decisions', 0)}`",
        f"- blocking_manual_decisions: `{release.get('blocking_manual_decisions', 0)}`",
        f"- current_artifact_gate_exists: `{str(current_gate.get('exists')).lower()}`",
        f"- submission_artifact_gate_exists: `{str(submission_gate.get('exists')).lower()}`",
        f"- missing_files: `{len(manifest.get('missing_files', []))}`",
        "",
        "## Matrix",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| matrix_id | `{matrix.get('matrix_id', '')}` |",
        f"| case_set | `{matrix.get('case_set', '')}` |",
        f"| cases | {matrix.get('case_count', 0)} |",
        f"| attack rows | {matrix.get('attack_rows', 0)} |",
        f"| control rows | {matrix.get('control_rows', 0)} |",
        f"| complete | `{str(matrix.get('complete')).lower()}` |",
        "",
        "## Results",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Attack scored rows | {results.get('attack_scored_rows', 'n/a')} |",
        f"| Attack ASR-eligible scored rows (S) | {display_metric(results.get('attack_asr_eligible_scored_rows'))} |",
        f"| Attack N-1 rows (M) | {display_metric(results.get('attack_n_minus_1_rows'))} |",
        f"| Attack coverage-accounted terminal rows | {display_metric(results.get('attack_accounted_terminal_rows'))} |",
        f"| Attack protocol denominator rows (S+M) | {display_metric(results.get('attack_protocol_denominator_rows'))} |",
        f"| Protocol completion rate | {display_metric(results.get('protocol_completion_rate'))} |",
        f"| Model nonconformance rate | {display_metric(results.get('model_nonconformance_rate'))} |",
        f"| Conditional ASR | {display_metric(results.get('conditional_asr_rate'))} |",
        f"| End-to-end attack rate | {display_metric(results.get('end_to_end_attack_rate'))} |",
        f"| Attack success rows | {results.get('attack_success', 0)} |",
        f"| Confirmed compromise rows | {results.get('confirmed_compromise', 0)} |",
        f"| Control attack success rows | {results.get('control_attack_success', 0)} |",
        f"| Control ASR-eligible scored rows (S) | {display_metric(results.get('control_asr_eligible_scored_rows'))} |",
        f"| Control N-1 rows (M) | {display_metric(results.get('control_n_minus_1_rows'))} |",
        f"| Control coverage-accounted terminal rows | {display_metric(results.get('control_accounted_terminal_rows'))} |",
        f"| Control protocol denominator rows (S+M) | {display_metric(results.get('control_protocol_denominator_rows'))} |",
        "",
        "## Release Decisions",
        "",
        "| ID | Status | Blocks Gate | Next Action |",
        "| --- | --- | --- | --- |",
    ]
    decisions = release.get("manual_decisions", [])
    if decisions:
        for item in decisions:
            lines.append(
                f"| {item.get('id', '')} | {item.get('status', '')} | "
                f"{str(item.get('blocking_submission_gate')).lower()} | "
                f"{item.get('next_action', '')} |"
            )
    else:
        lines.append("| none | complete | false | n/a |")

    lines += [
        "",
        "## Gates",
        "",
        "| Gate | Exists | Path |",
        "| --- | --- | --- |",
    ]
    for name, gate in manifest.get("gates", {}).items():
        lines.append(
            f"| {name} | `{str(gate.get('exists')).lower()}` | `{gate.get('path', '')}` |"
        )

    lines += [
        "",
        "## Files",
        "",
        "| Role | Exists | Bytes | SHA256 | Path |",
        "| --- | --- | ---: | --- | --- |",
    ]
    for item in manifest.get("files", []):
        digest = item.get("sha256", "")[:16] if item.get("sha256") else ""
        lines.append(
            f"| {item.get('role', '')} | `{str(item.get('exists')).lower()}` | "
            f"{item.get('bytes', 0)} | `{digest}` | `{item.get('path', '')}` |"
        )

    lines += ["", "## Validation Commands", "", "```powershell"]
    lines.extend(manifest.get("validation_commands", []))
    lines.append("```")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the paper submission package manifest.")
    parser.add_argument("--attack-label", default=DEFAULT_ATTACK_LABEL)
    parser.add_argument("--control-label", default=DEFAULT_CONTROL_LABEL)
    parser.add_argument("--table-dir", default=DEFAULT_TABLE_DIR)
    parser.add_argument("--case-evidence-dir", default=DEFAULT_CASE_EVIDENCE_DIR)
    parser.add_argument("--bundle-dir", default=DEFAULT_BUNDLE_DIR)
    parser.add_argument("--out-json", default="docs/generated_artifacts/paper_submission_package_manifest.json")
    parser.add_argument("--out-md", default="docs/generated_artifacts/paper_submission_package_manifest.md")
    args = parser.parse_args()

    manifest = build_submission_package_manifest(
        ROOT,
        attack_label=args.attack_label,
        control_label=args.control_label,
        table_dir=args.table_dir,
        case_evidence_dir=args.case_evidence_dir,
        bundle_dir=args.bundle_dir,
    )
    json_path = ROOT / args.out_json
    md_path = ROOT / args.out_md
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(render_markdown(manifest), encoding="utf-8")
    print(relpath(json_path))
    print(relpath(md_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
