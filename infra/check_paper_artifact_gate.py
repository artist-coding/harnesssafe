"""Aggregate paper artifact checks into one submission-oriented gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

try:
    from infra import (
        check_paper_claims,
        check_paper_case_studies,
        check_paper_bibliography,
        check_paper_manuscript,
        check_paper_matrix_progress,
        check_paper_numbers,
        plan_paper_experiment_matrix,
        generate_full_suite_eligibility_appendix,
        generate_paper_appendix,
        generate_submission_package_manifest,
        check_paper_readiness,
        check_paper_results,
        check_paper_suite_lock,
        check_public_artifact_safety,
        check_release_metadata,
        export_paper_run_queue,
        report_paper_submission_gaps,
        run_paper_queue,
        plan_external_validity_calibration,
        audit_submission_objective,
    )
    from infra.export_paper_tables import safe_slug
except ModuleNotFoundError:  # direct `python infra/check_paper_artifact_gate.py`
    import check_paper_claims  # type: ignore
    import check_paper_case_studies  # type: ignore
    import check_paper_bibliography  # type: ignore
    import check_paper_manuscript  # type: ignore
    import check_paper_matrix_progress  # type: ignore
    import check_paper_numbers  # type: ignore
    import plan_paper_experiment_matrix  # type: ignore
    import generate_full_suite_eligibility_appendix  # type: ignore
    import generate_paper_appendix  # type: ignore
    import generate_submission_package_manifest  # type: ignore
    import check_paper_readiness  # type: ignore
    import check_paper_results  # type: ignore
    import check_paper_suite_lock  # type: ignore
    import check_public_artifact_safety  # type: ignore
    import check_release_metadata  # type: ignore
    import export_paper_run_queue  # type: ignore
    import report_paper_submission_gaps  # type: ignore
    import run_paper_queue  # type: ignore
    import plan_external_validity_calibration  # type: ignore
    import audit_submission_objective  # type: ignore
    from export_paper_tables import safe_slug  # type: ignore


ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"

REQUIRED_REPORT_FILES = [
    "summary.json",
    "report.md",
    "results.csv",
    "case_summary.csv",
    "family_macro.csv",
    "harness_macro.csv",
]

REQUIRED_TABLE_FILES = [
    "paper_tables.json",
    "paper_tables.md",
    "main_results_table.tex",
    "family_results_table.tex",
    "control_results_table.tex",
]

REQUIRED_BUNDLE_FILES = [
    "repro_manifest.json",
    "repro_manifest.md",
]

REQUIRED_REPRO_MANIFEST_ARTIFACT_PATHS = [
    "docs/generated_artifacts/paper_suite_lock.json",
    "docs/generated_artifacts/paper_experiment_matrix_plan.json",
    "docs/generated_artifacts/paper_experiment_matrix_plan.md",
    "docs/generated_artifacts/paper_experiment_matrix_progress.md",
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
    "docs/generated_artifacts/paper_submission_package_manifest.json",
    "docs/generated_artifacts/paper_submission_package_manifest.md",
    "docs/generated_artifacts/paper_live_status.json",
    "docs/generated_artifacts/paper_live_status.md",
    "docs/generated_artifacts/paper_live_status_check.md",
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
    "docs/paper_draft.md",
    "CITATION.cff",
    "docs/release_metadata_final.json",
    "docs/paper_artifact_evaluation_readme.md",
]

REQUIRED_REPRO_MANIFEST_COMMAND_FRAGMENTS = [
    "check_active_case_integrity.py",
    "audit_paper_suite.py --strict-controls",
    "check_paper_readiness.py",
    "check_paper_suite_lock.py",
    "plan_paper_experiment_matrix.py",
    "check_paper_matrix_progress.py",
    "export_paper_run_queue.py",
    "run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json --queue-mode serial",
    "estimate_paper_run_budget.py",
    "report_paper_submission_gaps.py",
    "audit_submission_objective.py",
    "generate_submission_package_manifest.py",
    "paper_queue_job.py snapshot",
    "--check-md docs\\generated_artifacts\\paper_live_status_check.md",
    "check_paper_live_status.py",
    "check_paper_claims.py",
    "check_paper_case_studies.py",
    "check_paper_manuscript.py",
    "check_paper_numbers.py",
    "generate_benchmark_card.py",
    "generate_paper_appendix.py",
    "generate_oracle_coverage_report.py",
    "generate_threat_model_card.py",
    "generate_statistical_analysis.py",
    "generate_claim_evidence_map.py",
    "generate_control_integrity_report.py",
    "generate_paper_figures.py",
    "check_paper_bibliography.py",
    "generate_full_suite_eligibility_appendix.py",
    "plan_external_validity_calibration.py",
    "check_release_metadata.py",
    "check_public_artifact_safety.py",
    "check_paper_artifact_gate.py",
    "--max-active-progress-drift-rows 20",
    "run_paper_preflight.ps1",
]

CURRENT_PROFILE_FORBIDDEN_REPRO_COMMAND_FRAGMENTS = [
    "--harness codex",
    "DASHSCOPE",
    "paper_run_execution_codex",
    "paper_core_kimi_",
]

REQUIRED_CASE_EVIDENCE_FILES = [
    "case_study_evidence.json",
    "case_study_evidence.md",
]

REQUIRED_EXPERIMENT_PLAN_FILES = [
    "docs/generated_artifacts/paper_experiment_matrix_plan.json",
    "docs/generated_artifacts/paper_experiment_matrix_plan.md",
]

REQUIRED_MATRIX_PROGRESS_FILES = [
    "docs/generated_artifacts/paper_experiment_matrix_progress.md",
    "docs/generated_artifacts/paper_experiment_matrix_progress_claude.md",
]

REQUIRED_RUN_QUEUE_FILES = [
    "docs/generated_artifacts/paper_run_queue.json",
    "docs/generated_artifacts/paper_run_queue.md",
]

REQUIRED_RUN_EXECUTION_FILES = [
    "docs/generated_artifacts/paper_run_execution_plan.json",
    "docs/generated_artifacts/paper_run_execution_plan.md",
]

REQUIRED_RUN_BUDGET_FILES = [
    "docs/generated_artifacts/paper_run_budget.json",
    "docs/generated_artifacts/paper_run_budget.md",
]

REQUIRED_SUBMISSION_GAP_FILES = [
    "docs/generated_artifacts/paper_submission_gap_report.md",
    "docs/generated_artifacts/paper_submission_gap_report.json",
]

REQUIRED_SUBMISSION_OBJECTIVE_AUDIT_FILES = [
    "docs/generated_artifacts/paper_submission_objective_audit.md",
    "docs/generated_artifacts/paper_submission_objective_audit.json",
]

REQUIRED_SUBMISSION_PACKAGE_FILES = [
    "docs/generated_artifacts/paper_submission_package_manifest.md",
    "docs/generated_artifacts/paper_submission_package_manifest.json",
]

REQUIRED_SUBMISSION_PACKAGE_ROLE_PREFIXES = [
    "attack_report:",
    "control_report:",
    "paper_tables:",
    "case_study_evidence:",
]

REQUIRED_LIVE_STATUS_FILES = [
    "docs/generated_artifacts/paper_live_status.json",
    "docs/generated_artifacts/paper_live_status.md",
    "docs/generated_artifacts/paper_live_status_check.md",
]

REQUIRED_PAPER_DOCS = [
    "docs/paper_current_status.md",
    "docs/paper_experiment_protocol.md",
    "docs/paper_artifact_evaluation_readme.md",
    "docs/paper_bibliography.bib",
    "docs/paper_draft.md",
]

REQUIRED_FULL_SUITE_ELIGIBILITY_FILES = [
    "docs/generated_artifacts/paper_full_suite_eligibility.json",
    "docs/generated_artifacts/paper_full_suite_eligibility.md",
]

REQUIRED_EXTERNAL_VALIDITY_PLAN_FILES = [
    "docs/generated_artifacts/paper_external_validity_plan.json",
    "docs/generated_artifacts/paper_external_validity_plan.md",
]

REQUIRED_BIB_KEYS = check_paper_bibliography.REQUIRED_BIB_KEYS

DEFAULT_ACTIVE_PROGRESS_DRIFT_ROWS = 5
VOLATILE_MATRIX_PROGRESS_KEYS = {
    "completed_rows",
    "incomplete_rows",
    "unmatched_rows",
    "matched_without_oracle_rows",
    "in_progress_without_oracle_rows",
    "stale_without_oracle_rows",
    "completion_rate",
}


def split_cli_values(values: Iterable[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or []:
        for part in str(value).split(","):
            token = part.strip()
            if token:
                out.append(token)
    return out


def report_dirs(labels: Iterable[str] | None, paths: Iterable[str] | None, root: Path) -> list[Path]:
    dirs = [Path(path) for path in split_cli_values(paths)]
    dirs.extend(root / "runs" / "_reports" / safe_slug(label) for label in split_cli_values(labels))
    return dirs


def artifact_issue(
    severity: str,
    scope: str,
    message: str,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "severity": severity,
        "scope": scope,
        "message": message,
        "detail": detail or {},
    }


def as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def as_float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def optional_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def rate_matches(value: Any, successes: int, trials: int, *, tolerance: float = 1.1e-6) -> bool:
    """Return whether a serialized rate agrees with its integer numerator/denominator."""

    if successes < 0 or trials < 0 or successes > trials:
        return False
    if trials == 0:
        return successes == 0 and value is None
    expected = successes / trials
    try:
        actual = float(value)
    except (TypeError, ValueError):
        return False
    return abs(actual - expected) <= tolerance


def percentage_matches(value: Any, successes: int, trials: int, *, tolerance: float = 0.051) -> bool:
    if successes < 0 or trials < 0 or successes > trials:
        return False
    if trials == 0:
        return successes == 0 and value is None
    text = str(value or "").strip()
    try:
        actual = float(text[:-1]) if text.endswith("%") else float(text) * 100.0
    except (TypeError, ValueError):
        return False
    expected = (successes / trials) * 100.0
    return abs(actual - expected) <= tolerance


def validate_metric_block(
    issues: list[dict[str, Any]],
    *,
    scope: str,
    metric: str,
    block: Any,
    expected_successes: int | None = None,
    expected_trials: int | None = None,
    require_available: bool = True,
) -> dict[str, Any]:
    """Validate the count/rate core shared by schema-v2 paper metric blocks."""

    if not isinstance(block, dict):
        issues.append(
            artifact_issue(
                "error",
                scope,
                "paper metric block is missing or malformed",
                {"metric": metric},
            )
        )
        return {}
    if require_available and block.get("available") is not True:
        issues.append(
            artifact_issue(
                "error",
                scope,
                "paper metric is unavailable",
                {"metric": metric, "available": block.get("available")},
            )
        )
        return block
    successes = as_int(block.get("successes"))
    trials = as_int(block.get("trials"))
    if successes < 0 or trials < 0 or successes > trials:
        issues.append(
            artifact_issue(
                "error",
                scope,
                "paper metric counts are invalid",
                {"metric": metric, "successes": successes, "trials": trials},
            )
        )
    if expected_successes is not None and successes != expected_successes:
        issues.append(
            artifact_issue(
                "error",
                scope,
                "paper metric numerator is inconsistent",
                {
                    "metric": metric,
                    "successes": successes,
                    "expected_successes": expected_successes,
                },
            )
        )
    if expected_trials is not None and trials != expected_trials:
        issues.append(
            artifact_issue(
                "error",
                scope,
                "paper metric denominator is inconsistent",
                {"metric": metric, "trials": trials, "expected_trials": expected_trials},
            )
        )
    if not rate_matches(block.get("rate"), successes, trials):
        issues.append(
            artifact_issue(
                "error",
                scope,
                "paper metric rate is inconsistent with its counts",
                {
                    "metric": metric,
                    "successes": successes,
                    "trials": trials,
                    "rate": block.get("rate"),
                },
            )
        )
    return block


def live_status_matrix_id(status: dict[str, Any]) -> str:
    progress = status.get("matrix_progress", {})
    for scope in ["claude", "full"]:
        scope_progress = progress.get(scope, {}) if isinstance(progress, dict) else {}
        if isinstance(scope_progress, dict) and scope_progress.get("matrix_id"):
            return str(scope_progress.get("matrix_id") or "")
    return ""


def live_history_sample_matrix_id(sample: dict[str, Any]) -> str:
    return str(sample.get("matrix_id") or "")


def active_progress_drift_rows(
    *,
    snapshot_completed: Any,
    snapshot_missing: Any,
    current_completed: Any,
    current_missing: Any,
    max_drift_rows: int,
) -> int | None:
    completed_delta = as_int(current_completed) - as_int(snapshot_completed)
    missing_delta = as_int(snapshot_missing) - as_int(current_missing)
    if completed_delta == missing_delta and 0 <= completed_delta <= max_drift_rows:
        return completed_delta
    return None


def active_summary_drift_rows(
    snapshot_summary: dict[str, Any],
    current_summary: dict[str, Any],
    *,
    max_drift_rows: int,
    snapshot_missing_key: str = "missing_rows",
    current_missing_key: str = "incomplete_rows",
) -> int | None:
    if as_int(snapshot_summary.get("expected_rows")) != as_int(current_summary.get("expected_rows")):
        return None
    return active_progress_drift_rows(
        snapshot_completed=snapshot_summary.get("completed_rows"),
        snapshot_missing=snapshot_summary.get(snapshot_missing_key),
        current_completed=current_summary.get("completed_rows"),
        current_missing=current_summary.get(current_missing_key),
        max_drift_rows=max_drift_rows,
    )


def marker_int(text: str, name: str) -> int | None:
    match = re.search(rf"{re.escape(name)}:\s*`(\d+)`", text)
    return int(match.group(1)) if match else None


def marker_text(text: str, name: str) -> str:
    match = re.search(rf"{re.escape(name)}:\s*`([^`]*)`", text)
    return match.group(1) if match else ""


def tolerate_active_artifact_drift(
    issues: list[dict[str, Any]],
    *,
    scope: str,
    message: str,
    detail: dict[str, Any],
    allow_active_progress_drift: bool,
    drift_rows: int | None,
) -> None:
    if allow_active_progress_drift and drift_rows is not None:
        issues.append(
            artifact_issue(
                "warning",
                scope,
                message,
                {**detail, "active_progress_drift_rows": drift_rows},
            )
        )
    else:
        issues.append(artifact_issue("error", scope, message, detail))


def missing_files(base: Path, names: Iterable[str]) -> list[str]:
    return [name for name in names if not (base / name).is_file()]


def check_report_files(report_name: str, dirs: list[Path]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if not dirs:
        issues.append(artifact_issue("error", report_name, f"no {report_name} report directory provided"))
        return issues
    for directory in dirs:
        if not directory.is_dir():
            issues.append(
                artifact_issue(
                    "error",
                    report_name,
                    "report directory does not exist",
                    {"path": str(directory)},
                )
            )
            continue
        missing = missing_files(directory, REQUIRED_REPORT_FILES)
        if missing:
            issues.append(
                artifact_issue(
                    "error",
                    report_name,
                    "report directory is missing required files",
                    {"path": str(directory), "missing": missing},
                )
            )
    return issues


def check_table_dir(table_dir: Path | None) -> list[dict[str, Any]]:
    if table_dir is None:
        return [artifact_issue("error", "tables", "no table directory provided")]
    if not table_dir.is_dir():
        return [artifact_issue("error", "tables", "table directory does not exist", {"path": str(table_dir)})]
    missing = missing_files(table_dir, REQUIRED_TABLE_FILES)
    if missing:
        return [
            artifact_issue(
                "error",
                "tables",
                "table directory is missing required files",
                {"path": str(table_dir), "missing": missing},
            )
        ]
    issues: list[dict[str, Any]] = []
    json_path = table_dir / "paper_tables.json"
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        return [
            artifact_issue(
                "error",
                "tables",
                "could not parse paper_tables.json",
                {"error": str(exc)},
            )
        ]
    contract = payload.get("metric_contract", {})
    expected_contract = {
        "conditional_asr_denominator": "ASR-eligible N0-N5b scored attack rows",
        "protocol_completion_rate": "S/D",
        "model_nonconformance_rate": "M/D",
        "conditional_asr": "A/S",
        "end_to_end_attack_rate": "A/D",
        "end_to_end_denominator": "ASR-eligible scored attack rows plus N-1 attack rows",
    }
    if payload.get("schema_version") != 2 or not isinstance(contract, dict) or any(
        contract.get(key) != value for key, value in expected_contract.items()
    ):
        issues.append(
            artifact_issue(
                "error",
                "tables",
                "paper table measurement contract is missing or inconsistent",
                {"schema_version": payload.get("schema_version"), "metric_contract": contract},
            )
        )
    required_headers = {
        "All Scored",
        "ASR Eligible (S)",
        "N-1 (M)",
        "Coverage Accounted (T)",
        "Protocol Denominator (D)",
        "Attack Success (A)",
        "Protocol Completion (S/D)",
        "Model Nonconformance (M/D)",
        "Conditional ASR (A/S) [95% CI]",
        "End-to-End Attack Rate (A/D)",
    }
    main = payload.get("main", {})
    headers = set(main.get("headers", [])) if isinstance(main, dict) else set()
    missing_headers = sorted(required_headers - headers)
    if missing_headers:
        issues.append(
            artifact_issue(
                "error",
                "tables",
                "paper main table is missing S/M/T/D/A audit columns",
                {"missing_headers": missing_headers},
            )
        )
    return issues


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relpath(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def path_is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def resolve_copied_bundle_path(root: Path, bundle_dir: Path, copied_to: str) -> Path:
    candidate = Path(copied_to)
    if candidate.is_absolute():
        return candidate
    root_candidate = root / candidate
    if path_is_relative_to(root_candidate, bundle_dir):
        return root_candidate
    return bundle_dir / candidate


def check_copied_bundle_artifacts(root: Path, bundle_dir: Path, payload: dict[str, Any]) -> list[dict[str, Any]]:
    if "copied_artifacts" not in payload:
        return []
    copied_artifacts = payload.get("copied_artifacts")
    if not isinstance(copied_artifacts, list):
        return [
            artifact_issue(
                "error",
                "bundle",
                "repro bundle copied_artifacts must be a list",
                {"type": type(copied_artifacts).__name__},
            )
        ]
    issues: list[dict[str, Any]] = []
    artifacts = payload.get("artifacts")
    manifest_paths: set[str] = set()
    existing_manifest_paths: set[str] = set()
    if isinstance(artifacts, list):
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            path = str(artifact.get("path") or "").replace("\\", "/")
            if not path:
                continue
            manifest_paths.add(path)
            if artifact.get("exists") is True:
                existing_manifest_paths.add(path)
    copied_source_paths: set[str] = set()
    for index, record in enumerate(copied_artifacts):
        if not isinstance(record, dict):
            issues.append(
                artifact_issue(
                    "error",
                    "bundle",
                    "repro bundle copied_artifacts entry is not an object",
                    {"index": index},
                )
            )
            continue
        source_path = str(record.get("path") or "").replace("\\", "/")
        if source_path:
            copied_source_paths.add(source_path)
        copied_to = str(record.get("copied_to") or "")
        if not copied_to:
            issues.append(
                artifact_issue(
                    "error",
                    "bundle",
                    "repro bundle copied artifact is missing copied_to",
                    {"index": index, "path": record.get("path")},
                )
            )
            continue
        copied_path = resolve_copied_bundle_path(root, bundle_dir, copied_to)
        if not path_is_relative_to(copied_path, bundle_dir):
            issues.append(
                artifact_issue(
                    "error",
                    "bundle",
                    "repro bundle copied artifact path escapes bundle directory",
                    {"index": index, "copied_to": copied_to},
                )
            )
            continue
        if not copied_path.is_file():
            issues.append(
                artifact_issue(
                    "error",
                    "bundle",
                    "repro bundle copied artifact is missing",
                    {"index": index, "copied_to": copied_to},
                )
            )
            continue
        actual_sha256 = file_sha256(copied_path)
        copied_sha256 = str(record.get("copied_sha256") or "")
        source_sha256 = str(record.get("sha256") or "")
        if not copied_sha256:
            issues.append(
                artifact_issue(
                    "error",
                    "bundle",
                    "repro bundle copied artifact is missing copied_sha256",
                    {"index": index, "copied_to": copied_to},
                )
            )
        elif actual_sha256 != copied_sha256:
            issues.append(
                artifact_issue(
                    "error",
                    "bundle",
                    "repro bundle copied artifact hash mismatch",
                    {
                        "index": index,
                        "copied_to": copied_to,
                        "expected_sha256": copied_sha256,
                        "actual_sha256": actual_sha256,
                    },
                )
            )
        if source_sha256 and actual_sha256 != source_sha256:
            issues.append(
                artifact_issue(
                    "error",
                    "bundle",
                    "repro bundle copied artifact hash differs from source record",
                    {
                        "index": index,
                        "copied_to": copied_to,
                        "source_sha256": source_sha256,
                        "actual_sha256": actual_sha256,
                    },
                )
            )
    missing_copied_sources = sorted(existing_manifest_paths - copied_source_paths)
    if missing_copied_sources:
        issues.append(
            artifact_issue(
                "error",
                "bundle",
                "repro bundle copied_artifacts is missing existing manifest artifacts",
                {"missing_paths": missing_copied_sources},
            )
        )
    extra_copied_sources = sorted(copied_source_paths - manifest_paths)
    if extra_copied_sources:
        issues.append(
            artifact_issue(
                "error",
                "bundle",
                "repro bundle copied_artifacts references paths absent from manifest artifacts",
                {"extra_paths": extra_copied_sources},
            )
        )
    return issues


def normalized_manifest_artifact_paths(payload: dict[str, Any]) -> tuple[set[str], list[dict[str, Any]]]:
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        return set(), [
            artifact_issue(
                "error",
                "bundle",
                "repro bundle manifest artifacts must be a list",
                {"type": type(artifacts).__name__},
            )
        ]
    issues: list[dict[str, Any]] = []
    paths: set[str] = set()
    for index, record in enumerate(artifacts):
        if not isinstance(record, dict):
            issues.append(
                artifact_issue(
                    "error",
                    "bundle",
                    "repro bundle manifest artifact entry is not an object",
                    {"index": index},
                )
            )
            continue
        path = str(record.get("path") or "").replace("\\", "/")
        if not path:
            issues.append(
                artifact_issue(
                    "error",
                    "bundle",
                    "repro bundle manifest artifact entry is missing path",
                    {"index": index},
                )
            )
            continue
        paths.add(path)
    return paths, issues


def check_repro_manifest_artifact_paths(payload: dict[str, Any]) -> list[dict[str, Any]]:
    paths, issues = normalized_manifest_artifact_paths(payload)
    if issues:
        return issues
    missing_paths = [path for path in REQUIRED_REPRO_MANIFEST_ARTIFACT_PATHS if path not in paths]
    if missing_paths:
        issues.append(
            artifact_issue(
                "error",
                "bundle",
                "repro bundle manifest is missing required artifact records",
                {"missing_paths": missing_paths},
            )
        )
    return issues


def check_repro_manifest_commands(payload: dict[str, Any], *, submission_profile: bool = False) -> list[dict[str, Any]]:
    commands = payload.get("reproduction_commands")
    if not isinstance(commands, list):
        return [
            artifact_issue(
                "error",
                "bundle",
                "repro bundle manifest reproduction_commands must be a list",
                {"type": type(commands).__name__},
            )
        ]
    normalized_commands: list[str] = []
    issues: list[dict[str, Any]] = []
    for index, command in enumerate(commands):
        if not isinstance(command, str):
            issues.append(
                artifact_issue(
                    "error",
                    "bundle",
                    "repro bundle manifest reproduction command is not a string",
                    {"index": index},
                )
            )
            continue
        normalized_commands.append(command.replace("/", "\\"))
    if issues:
        return issues
    if not submission_profile:
        forbidden_matches: list[dict[str, Any]] = []
        forbidden_fragments = [
            (fragment, fragment.replace("/", "\\").lower())
            for fragment in CURRENT_PROFILE_FORBIDDEN_REPRO_COMMAND_FRAGMENTS
        ]
        for index, command in enumerate(normalized_commands):
            command_lower = command.lower()
            for fragment, normalized_fragment in forbidden_fragments:
                if normalized_fragment in command_lower:
                    forbidden_matches.append(
                        {
                            "index": index,
                            "fragment": fragment,
                            "command": command,
                        }
                    )
        if forbidden_matches:
            issues.append(
                artifact_issue(
                    "error",
                    "bundle",
                    "current repro bundle manifest includes optional baseline reproduction commands",
                    {"matches": forbidden_matches},
                )
            )
    missing_fragments = [
        fragment
        for fragment in REQUIRED_REPRO_MANIFEST_COMMAND_FRAGMENTS
        if not any(fragment in command for command in normalized_commands)
    ]
    if missing_fragments:
        issues.append(
            artifact_issue(
                "error",
                "bundle",
                "repro bundle manifest is missing required reproduction commands",
                {"missing_fragments": missing_fragments},
            )
        )
    return issues


def manifest_missing_artifact_paths(payload: dict[str, Any]) -> tuple[set[str], list[dict[str, Any]]]:
    missing_artifacts = payload.get("missing_artifacts")
    if not isinstance(missing_artifacts, list):
        return set(), [
            artifact_issue(
                "error",
                "bundle",
                "repro bundle manifest missing_artifacts must be a list",
                {"type": type(missing_artifacts).__name__},
            )
        ]
    issues: list[dict[str, Any]] = []
    paths: set[str] = set()
    for index, record in enumerate(missing_artifacts):
        if not isinstance(record, dict):
            issues.append(
                artifact_issue(
                    "error",
                    "bundle",
                    "repro bundle manifest missing_artifacts entry is not an object",
                    {"index": index},
                )
            )
            continue
        path = str(record.get("path") or "").replace("\\", "/")
        if not path:
            issues.append(
                artifact_issue(
                    "error",
                    "bundle",
                    "repro bundle manifest missing_artifacts entry is missing path",
                    {"index": index},
                )
            )
            continue
        paths.add(path)
    return paths, issues


def check_repro_manifest_missing_artifacts(payload: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        return []
    missing_paths, issues = manifest_missing_artifact_paths(payload)
    if issues:
        return issues
    artifact_paths: set[str] = set()
    exists_false_paths: set[str] = set()
    for record in artifacts:
        if not isinstance(record, dict):
            continue
        path = str(record.get("path") or "").replace("\\", "/")
        if not path:
            continue
        artifact_paths.add(path)
        if record.get("exists") is not True:
            exists_false_paths.add(path)
    missing_not_marked = sorted(exists_false_paths - missing_paths)
    if missing_not_marked:
        issues.append(
            artifact_issue(
                "error",
                "bundle",
                "repro bundle manifest missing_artifacts omits missing artifact records",
                {"missing_paths": missing_not_marked},
            )
        )
    stale_missing = sorted(missing_paths - exists_false_paths)
    if stale_missing:
        issues.append(
            artifact_issue(
                "error",
                "bundle",
                "repro bundle manifest missing_artifacts lists artifacts not marked missing",
                {"stale_missing_paths": stale_missing},
            )
        )
    unknown_missing = sorted(missing_paths - artifact_paths)
    if unknown_missing:
        issues.append(
            artifact_issue(
                "error",
                "bundle",
                "repro bundle manifest missing_artifacts references paths absent from artifacts",
                {"unknown_missing_paths": unknown_missing},
            )
        )
    if missing_paths:
        issues.append(
            artifact_issue(
                "error",
                "bundle",
                "repro bundle records missing artifacts",
                {"missing_artifacts": sorted(missing_paths)},
            )
        )
    return issues


def check_bundle_dir(bundle_dir: Path | None, *, root: Path = ROOT, submission_profile: bool = False) -> list[dict[str, Any]]:
    if bundle_dir is None:
        return [artifact_issue("error", "bundle", "no repro bundle directory provided")]
    if not bundle_dir.is_dir():
        return [artifact_issue("error", "bundle", "bundle directory does not exist", {"path": str(bundle_dir)})]
    missing = missing_files(bundle_dir, REQUIRED_BUNDLE_FILES)
    if missing:
        return [
            artifact_issue(
                "error",
                "bundle",
                "bundle directory is missing required files",
                {"path": str(bundle_dir), "missing": missing},
            )
        ]
    manifest = bundle_dir / "repro_manifest.json"
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        return [artifact_issue("error", "bundle", "could not parse repro_manifest.json", {"error": str(exc)})]
    issues = check_repro_manifest_artifact_paths(payload)
    issues.extend(check_repro_manifest_commands(payload, submission_profile=submission_profile))
    issues.extend(check_repro_manifest_missing_artifacts(payload))
    issues.extend(check_copied_bundle_artifacts(root, bundle_dir, payload))
    return issues


def check_case_evidence_dir(case_evidence_dir: Path | None) -> list[dict[str, Any]]:
    if case_evidence_dir is None:
        return [artifact_issue("error", "case_evidence", "no case-study evidence directory provided")]
    if not case_evidence_dir.is_dir():
        return [
            artifact_issue(
                "error",
                "case_evidence",
                "case-study evidence directory does not exist",
                {"path": str(case_evidence_dir)},
            )
        ]
    missing = missing_files(case_evidence_dir, REQUIRED_CASE_EVIDENCE_FILES)
    if missing:
        return [
            artifact_issue(
                "error",
                "case_evidence",
                "case-study evidence directory is missing required files",
                {"path": str(case_evidence_dir), "missing": missing},
            )
        ]
    payload_path = case_evidence_dir / "case_study_evidence.json"
    try:
        payload = json.loads(payload_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        return [artifact_issue("error", "case_evidence", "could not parse case_study_evidence.json", {"error": str(exc)})]
    issues: list[dict[str, Any]] = []
    if not payload.get("ok"):
        issues.append(artifact_issue("error", "case_evidence", "case-study evidence pack is not ok"))
    if int(payload.get("case_count") or 0) <= 0:
        issues.append(artifact_issue("error", "case_evidence", "case-study evidence pack is empty"))
    if int(payload.get("recommended_main_paper_count") or 0) <= 0:
        issues.append(artifact_issue("error", "case_evidence", "case-study evidence pack has no recommended main-paper cases"))
    return issues


def extract_bib_keys(text: str) -> set[str]:
    return set(re.findall(r"@\w+\{([^,\s]+),", text))


def check_docs(root: Path) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for rel in REQUIRED_PAPER_DOCS:
        if not (root / rel).is_file():
            issues.append(artifact_issue("error", "docs", "missing required paper doc", {"path": rel}))

    readme = (root / "README.md").read_text(encoding="utf-8-sig") if (root / "README.md").is_file() else ""
    docs_readme = (
        (root / "docs" / "README.md").read_text(encoding="utf-8-sig")
        if (root / "docs" / "README.md").is_file()
        else ""
    )
    for rel in REQUIRED_PAPER_DOCS:
        basename = Path(rel).name
        if basename not in readme and basename not in docs_readme:
            issues.append(
                artifact_issue(
                    "error",
                    "docs",
                    "paper doc is not linked from README entry points",
                    {"path": rel},
                )
            )

    for rel in ["docs/paper_draft.md"]:
        doc = root / rel
        if doc.is_file() and "[CITE]" in doc.read_text(encoding="utf-8-sig"):
            issues.append(
                artifact_issue(
                    "error",
                    "docs",
                    "paper document still contains [CITE] placeholders",
                    {"path": rel},
                )
            )

    return issues


def check_bibliography_gate(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    report = check_paper_bibliography.build_bibliography_report(root=root)
    issues = [
        artifact_issue(
            item.get("severity", "error"),
            item.get("scope", "bibliography"),
            item.get("message", "bibliography issue"),
            item.get("detail", {}),
        )
        for item in report.get("issues", [])
    ]
    return report, issues


def stable_full_suite_eligibility_projection(report: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in report.items()
        if key not in {"generated_at"}
    }


def check_full_suite_eligibility(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    for rel in REQUIRED_FULL_SUITE_ELIGIBILITY_FILES:
        if not (root / rel).is_file():
            issues.append(
                artifact_issue(
                    "error",
                    "full_suite_eligibility",
                    "missing full-suite eligibility appendix file",
                    {"path": rel},
                )
            )
    json_path = root / REQUIRED_FULL_SUITE_ELIGIBILITY_FILES[0]
    md_path = root / REQUIRED_FULL_SUITE_ELIGIBILITY_FILES[1]
    if not json_path.is_file():
        return {"ok": False, "issue_count": len(issues)}, issues
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(
            artifact_issue(
                "error",
                "full_suite_eligibility",
                "could not parse full-suite eligibility JSON",
                {"path": str(json_path), "error": str(exc)},
            )
        )
        return {"ok": False, "issue_count": len(issues)}, issues
    expected = generate_full_suite_eligibility_appendix.build_report(
        root=root,
        suite_lock=Path("docs/generated_artifacts/paper_suite_lock.json"),
    )
    if stable_full_suite_eligibility_projection(payload) != stable_full_suite_eligibility_projection(expected):
        issues.append(
            artifact_issue(
                "error",
                "full_suite_eligibility",
                "full-suite eligibility appendix JSON is stale",
                {
                    "path": REQUIRED_FULL_SUITE_ELIGIBILITY_FILES[0],
                    "actual_summary": payload.get("summary", {}),
                    "expected_summary": expected.get("summary", {}),
                },
            )
        )
    summary = payload.get("summary", {})
    expected_summary = expected.get("summary", {})
    for key in [
        "active_cases",
        "main_asr_cases",
        "diagnostic_cases",
        "runnable_matrix_rows",
        "formal_main_table_rows",
        "diagnostic_matrix_rows",
        "core_cases",
        "extended_cases",
        "exploratory_cases",
        "hard_trace_oracle_cases",
        "soft_semantic_oracle_cases",
        "propagation_only_cases",
        "attack_success_metric_excluded_cases",
    ]:
        expected_value = as_int(expected_summary.get(key))
        if as_int(summary.get(key)) != expected_value:
            issues.append(
                artifact_issue(
                    "error",
                    "full_suite_eligibility",
                    "full-suite eligibility summary count is unexpected",
                    {"field": key, "actual": summary.get(key), "expected": expected_value},
                )
            )
    claim_boundary = str(summary.get("claim_boundary") or "")
    active_cases = as_int(expected_summary.get("active_cases"))
    main_asr_cases = as_int(expected_summary.get("main_asr_cases"))
    diagnostic_cases = as_int(expected_summary.get("diagnostic_cases"))
    required_boundary_phrases = [
        f"All {active_cases} active hard-oracle cases",
        f"{main_asr_cases} metric-eligible cases",
        f"remaining {diagnostic_cases} cases",
        "planned/design-time case scope",
    ]
    if any(phrase not in claim_boundary for phrase in required_boundary_phrases):
        issues.append(
            artifact_issue(
                "error",
                "full_suite_eligibility",
                "full-suite eligibility claim boundary does not separate planned scope from realized denominators",
            )
        )
    if md_path.is_file():
        text = md_path.read_text(encoding="utf-8-sig")
        required_phrases = [
            "Full-Suite Eligibility Appendix",
            f"All {active_cases} active hard-oracle cases define runnable benchmark coverage",
            f"formal main table ({main_asr_cases} cases; {as_int(expected_summary.get('formal_main_table_rows'))} rows)",
            f"diagnostics ({diagnostic_cases} cases; {as_int(expected_summary.get('diagnostic_matrix_rows'))} rows)",
            "core selector is a compatibility alias for all",
            "Per-Case Eligibility Table",
        ]
        for phrase in required_phrases:
            if phrase not in text:
                issues.append(
                    artifact_issue(
                        "error",
                        "full_suite_eligibility",
                        "full-suite eligibility Markdown omits required phrase",
                        {"phrase": phrase},
                    )
                )
    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "issue_count": len(issues),
        "active_cases": as_int(summary.get("active_cases")),
        "main_asr_cases": as_int(summary.get("main_asr_cases")),
        "diagnostic_cases": as_int(summary.get("diagnostic_cases")),
        "runnable_matrix_rows": as_int(summary.get("runnable_matrix_rows")),
        "formal_main_table_rows": as_int(summary.get("formal_main_table_rows")),
        "diagnostic_matrix_rows": as_int(summary.get("diagnostic_matrix_rows")),
        "core_cases": as_int(summary.get("core_cases")),
        "extended_cases": as_int(summary.get("extended_cases")),
        "exploratory_cases": as_int(summary.get("exploratory_cases")),
        "hard_trace_oracle_cases": as_int(summary.get("hard_trace_oracle_cases")),
        "soft_semantic_oracle_cases": as_int(summary.get("soft_semantic_oracle_cases")),
        "propagation_only_cases": as_int(summary.get("propagation_only_cases")),
        "attack_success_metric_excluded_cases": as_int(summary.get("attack_success_metric_excluded_cases")),
        "case_rows": len(payload.get("cases", [])) if isinstance(payload.get("cases"), list) else 0,
    }, issues


def stable_external_validity_projection(report: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in report.items()
        if key not in {"generated_at"}
    }


def check_external_validity_plan(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    for rel in REQUIRED_EXTERNAL_VALIDITY_PLAN_FILES:
        if not (root / rel).is_file():
            issues.append(
                artifact_issue(
                    "error",
                    "external_validity_plan",
                    "missing external-validity calibration plan file",
                    {"path": rel},
                )
            )
    json_path = root / REQUIRED_EXTERNAL_VALIDITY_PLAN_FILES[0]
    md_path = root / REQUIRED_EXTERNAL_VALIDITY_PLAN_FILES[1]
    if not json_path.is_file():
        return {"ok": False, "issue_count": len(issues)}, issues
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(
            artifact_issue(
                "error",
                "external_validity_plan",
                "could not parse external-validity calibration JSON",
                {"path": str(json_path), "error": str(exc)},
            )
        )
        return {"ok": False, "issue_count": len(issues)}, issues
    expected = plan_external_validity_calibration.build_report(
        root=root,
        suite_lock=Path("docs/generated_artifacts/paper_suite_lock.json"),
    )
    if stable_external_validity_projection(payload) != stable_external_validity_projection(expected):
        issues.append(
            artifact_issue(
                "error",
                "external_validity_plan",
                "external-validity calibration plan JSON is stale",
                {
                    "path": REQUIRED_EXTERNAL_VALIDITY_PLAN_FILES[0],
                    "actual_summary": payload.get("summary", {}),
                    "expected_summary": expected.get("summary", {}),
                },
            )
        )
    summary = payload.get("summary", {})
    expected_summary = expected.get("summary", {})
    for key in [
        "active_cases",
        "formal_cases",
        "diagnostic_cases",
        "runnable_matrix_rows",
        "formal_main_table_rows",
        "diagnostic_matrix_rows",
        "candidate_cases",
        "selected_cases",
        "per_suite_target",
    ]:
        expected_value = as_int(expected_summary.get(key))
        if as_int(summary.get(key)) != expected_value:
            issues.append(
                artifact_issue(
                    "error",
                    "external_validity_plan",
                    "external-validity calibration summary count is unexpected",
                    {"field": key, "actual": summary.get(key), "expected": expected_value},
                )
            )
    boundary = str(summary.get("main_asr_boundary") or "")
    active_cases = as_int(expected_summary.get("active_cases"))
    formal_cases = as_int(expected_summary.get("formal_cases"))
    formal_scope_phrase = (
        f"{formal_cases}-case metric-eligible set"
        if formal_cases == active_cases
        else f"{formal_cases}-case metric-eligible subset"
    )
    coverage_phrase = (
        "identical to the runnable hard-oracle coverage"
        if formal_cases == active_cases
        else f"{active_cases}-case runnable hard-oracle coverage"
    )
    if (
        formal_scope_phrase not in boundary
        or coverage_phrase not in boundary
        or "sensitivity analysis" not in boundary
    ):
        issues.append(
            artifact_issue(
                "error",
                "external_validity_plan",
                "external-validity plan omits the coverage/formal sensitivity-analysis boundary",
            )
        )
    commands = payload.get("commands", {})
    if not isinstance(commands, dict) or "run_harness_case.ps1" not in str(commands.get("attack_commands_powershell", "")):
        issues.append(
            artifact_issue(
                "error",
                "external_validity_plan",
                "external-validity plan omits attack execution commands",
            )
        )
    if not isinstance(commands, dict) or "-CaseDirFilter $externalCases" not in str(commands.get("control_commands_powershell", "")):
        issues.append(
            artifact_issue(
                "error",
                "external_validity_plan",
                "external-validity plan omits filtered control execution commands",
            )
        )
    if md_path.is_file():
        text = md_path.read_text(encoding="utf-8-sig")
        required_phrases = [
            "External-Validity Calibration Plan",
            "does not run benchmark cases",
            "does not replace the complete main matrix",
            "Future Execution Commands",
        ]
        for phrase in required_phrases:
            if phrase not in text:
                issues.append(
                    artifact_issue(
                        "error",
                        "external_validity_plan",
                        "external-validity Markdown omits required phrase",
                        {"phrase": phrase},
                    )
                )
    selected_cases = payload.get("selected_cases", [])
    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "issue_count": len(issues),
        "active_cases": as_int(summary.get("active_cases")),
        "formal_cases": as_int(summary.get("formal_cases")),
        "diagnostic_cases": as_int(summary.get("diagnostic_cases")),
        "runnable_matrix_rows": as_int(summary.get("runnable_matrix_rows")),
        "formal_main_table_rows": as_int(summary.get("formal_main_table_rows")),
        "diagnostic_matrix_rows": as_int(summary.get("diagnostic_matrix_rows")),
        "candidate_cases": as_int(summary.get("candidate_cases")),
        "selected_cases": len(selected_cases) if isinstance(selected_cases, list) else 0,
        "per_suite_target": as_int(summary.get("per_suite_target")),
        "selected_by_suite": summary.get("selected_by_suite", {}),
    }, issues


def check_experiment_plan(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    for rel in REQUIRED_EXPERIMENT_PLAN_FILES:
        if not (root / rel).is_file():
            issues.append(artifact_issue("error", "experiment_plan", "missing experiment plan file", {"path": rel}))
    json_path = root / REQUIRED_EXPERIMENT_PLAN_FILES[0]
    if not json_path.is_file():
        return {"ok": False, "issue_count": len(issues)}, issues
    try:
        plan = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(
            artifact_issue(
                "error",
                "experiment_plan",
                "could not parse experiment plan JSON",
                {"path": str(json_path), "error": str(exc)},
            )
        )
        return {"ok": False, "issue_count": len(issues)}, issues

    for item in plan_paper_experiment_matrix.validate_plan(plan, root=root):
        issues.append(
            artifact_issue(
                item.get("severity", "error"),
                "experiment_plan",
                item.get("message", "experiment plan issue"),
                item.get("detail", {}),
            )
        )
    if plan.get("case_set") != "all":
        issues.append(
            artifact_issue(
                "error",
                "experiment_plan",
                "experiment plan must use the canonical all-case selector",
                {"case_set": plan.get("case_set")},
            )
        )
    if plan.get("harnesses") != ["claude"]:
        issues.append(
            artifact_issue(
                "error",
                "experiment_plan",
                "experiment plan must target the current Claude Code + Kimi K2.6 baseline",
                {"harnesses": plan.get("harnesses")},
            )
        )
    if int(plan.get("attack_trials") or 0) < 3:
        issues.append(
            artifact_issue(
                "error",
                "experiment_plan",
                "experiment plan must include at least three attack trials",
                {"attack_trials": plan.get("attack_trials")},
            )
        )
    if int(plan.get("control_trials") or 0) < 1:
        issues.append(
            artifact_issue(
                "error",
                "experiment_plan",
                "experiment plan must include at least one control trial",
                {"control_trials": plan.get("control_trials")},
            )
        )
    expected_controls = plan_paper_experiment_matrix.CONTROL_TYPES
    if plan.get("control_types") != expected_controls:
        issues.append(
            artifact_issue(
                "error",
                "experiment_plan",
                "experiment plan must include all paper control types",
                {"control_types": plan.get("control_types"), "expected": expected_controls},
            )
        )
    suite_lock = plan.get("suite_lock", {}) or {}
    if (
        plan.get("plan_status") != "formal_locked"
        or plan.get("formal_execution_eligible") is not True
        or suite_lock.get("present") is not True
        or suite_lock.get("parse_valid") is not True
        or suite_lock.get("verified") is not True
        or not str(suite_lock.get("suite_content_sha256") or "")
    ):
        issues.append(
            artifact_issue(
                "error",
                "experiment_plan",
                "formal experiment plan must be generated after and bound to the paper suite lock",
                {"suite_lock": suite_lock},
            )
        )
    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "matrix_id": plan.get("matrix_id", ""),
        "matrix_digest": plan.get("matrix_digest", ""),
        "case_set": plan.get("case_set", ""),
        "harnesses": plan.get("harnesses", []),
        "suite_lock": plan.get("suite_lock", {}),
        "summary": plan.get("summary", {}),
        "issue_count": len(issues),
    }, issues


def check_matrix_progress(
    root: Path,
    require_complete: bool,
    *,
    harnesses: list[str] | None = None,
    artifact_path: str = "",
    scope: str = "matrix_progress",
    allow_active_progress_drift: bool = False,
    max_active_progress_drift_rows: int = DEFAULT_ACTIVE_PROGRESS_DRIFT_ROWS,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    progress = check_paper_matrix_progress.build_progress_report(
        root=root,
        plan_path=root / "docs" / "generated_artifacts" / "paper_experiment_matrix_plan.json",
        harnesses=harnesses,
    )
    issues = [
        artifact_issue(
            item.get("severity", "error"),
            scope,
            item.get("message", "matrix progress issue"),
            item.get("detail", {}),
        )
        for item in progress.get("issues", [])
        if item.get("severity") == "error"
    ]
    if require_complete and not progress.get("complete"):
        issues.append(
            artifact_issue(
                "error",
                scope,
                "paper submission matrix has incomplete expected rows",
                progress.get("summary", {}),
            )
        )
    summary = progress.get("summary", {})
    if artifact_path:
        path = root / artifact_path
        if not path.is_file():
            issues.append(artifact_issue("error", scope, "missing matrix progress artifact", {"path": artifact_path}))
        else:
            text = path.read_text(encoding="utf-8-sig")
            markers = [
                f"expected_rows: `{summary.get('expected_rows', 0)}`",
                f"completed_rows: `{summary.get('completed_rows', 0)}`",
                f"execution_valid_completed_rows: `{summary.get('execution_valid_completed_rows', 0)}`",
                f"model_protocol_terminal_rows: `{summary.get('model_protocol_terminal_rows', 0)}`",
                f"incomplete_rows: `{summary.get('incomplete_rows', 0)}`",
                f"execution_invalid_or_unvalidated_rows: `{summary.get('execution_invalid_or_unvalidated_rows', 0)}`",
                f"duplicate_accounted_expected_rows: `{summary.get('duplicate_accounted_expected_rows', 0)}`",
                f"harnesses: `{','.join(progress.get('harnesses', [])) or 'all'}`",
                f"filtered: `{str(progress.get('filtered', False)).lower()}`",
            ]
            missing_markers = [marker for marker in markers if marker not in text]
            if missing_markers:
                artifact_summary = {
                    "expected_rows": marker_int(text, "expected_rows"),
                    "completed_rows": marker_int(text, "completed_rows"),
                    "incomplete_rows": marker_int(text, "incomplete_rows"),
                }
                drift_rows = None
                if (
                    f"expected_rows: `{summary.get('expected_rows', 0)}`" in text
                    and f"harnesses: `{','.join(progress.get('harnesses', [])) or 'all'}`" in text
                    and f"filtered: `{str(progress.get('filtered', False)).lower()}`" in text
                ):
                    drift_rows = active_summary_drift_rows(
                        artifact_summary,
                        summary,
                        max_drift_rows=max_active_progress_drift_rows,
                        snapshot_missing_key="incomplete_rows",
                    )
                tolerate_active_artifact_drift(
                    issues,
                    scope=scope,
                    message="matrix progress artifact lags active run",
                    detail={"path": artifact_path, "missing_markers": missing_markers},
                    allow_active_progress_drift=allow_active_progress_drift,
                    drift_rows=drift_rows,
                )
                if not (allow_active_progress_drift and drift_rows is not None):
                    issues[-1]["message"] = "matrix progress artifact is stale"
    return {
        "complete": progress.get("complete"),
        "matrix_id": progress.get("matrix_id", ""),
        "harnesses": progress.get("harnesses", []),
        "filtered": progress.get("filtered", False),
        "expected_rows": summary.get("expected_rows", 0),
        "completed_rows": summary.get("completed_rows", 0),
        "execution_valid_completed_rows": summary.get("execution_valid_completed_rows", 0),
        "model_protocol_terminal_rows": summary.get("model_protocol_terminal_rows", 0),
        "incomplete_rows": summary.get("incomplete_rows", 0),
        "execution_invalid_or_unvalidated_rows": summary.get(
            "execution_invalid_or_unvalidated_rows", 0
        ),
        "duplicate_accounted_expected_rows": summary.get(
            "duplicate_accounted_expected_rows", 0
        ),
        "completion_rate": summary.get("completion_rate", 0.0),
        "active_progress_drift_rows": max(
            [
                as_int(item.get("detail", {}).get("active_progress_drift_rows"))
                for item in issues
                if item.get("severity") == "warning" and item.get("scope") == scope
            ]
            or [0]
        ),
        "issue_count": len(issues),
    }, issues


def check_run_budget(
    root: Path,
    experiment_plan: dict[str, Any],
    matrix_progress: dict[str, Any],
    *,
    allow_active_progress_drift: bool = False,
    max_active_progress_drift_rows: int = DEFAULT_ACTIVE_PROGRESS_DRIFT_ROWS,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    for rel in REQUIRED_RUN_BUDGET_FILES:
        if not (root / rel).is_file():
            issues.append(artifact_issue("error", "run_budget", "missing run budget file", {"path": rel}))
    json_path = root / REQUIRED_RUN_BUDGET_FILES[0]
    if not json_path.is_file():
        return {"ok": False, "issue_count": len(issues)}, issues
    try:
        budget = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(
            artifact_issue(
                "error",
                "run_budget",
                "could not parse run budget JSON",
                {"path": str(json_path), "error": str(exc)},
            )
        )
        return {"ok": False, "issue_count": len(issues)}, issues

    summary = budget.get("summary", {})
    plan_matrix_id = str(experiment_plan.get("matrix_id") or "")
    if plan_matrix_id and budget.get("matrix_id") != plan_matrix_id:
        issues.append(
            artifact_issue(
                "error",
                "run_budget",
                "run budget matrix id does not match experiment plan",
                {"budget_matrix_id": budget.get("matrix_id"), "plan_matrix_id": plan_matrix_id},
            )
        )
    expected_rows = int(matrix_progress.get("expected_rows") or 0)
    incomplete_rows = int(matrix_progress.get("incomplete_rows") or 0)
    completed_rows = int(matrix_progress.get("completed_rows") or 0)
    summary_drift_rows = active_summary_drift_rows(
        summary,
        {
            "expected_rows": expected_rows,
            "completed_rows": completed_rows,
            "incomplete_rows": incomplete_rows,
        },
        max_drift_rows=max_active_progress_drift_rows,
    )
    if int(summary.get("expected_rows") or 0) != expected_rows:
        issues.append(
            artifact_issue(
                "error",
                "run_budget",
                "run budget expected rows do not match matrix progress",
                {"budget_expected_rows": summary.get("expected_rows"), "progress_expected_rows": expected_rows},
            )
        )
    elif (
        int(summary.get("completed_rows") or 0) != completed_rows
        or int(summary.get("missing_rows") or 0) != incomplete_rows
    ):
        if allow_active_progress_drift and summary_drift_rows is not None:
            issues.append(
                artifact_issue(
                    "warning",
                    "run_budget",
                    "run budget lags active matrix progress",
                    {
                        "budget_completed_rows": summary.get("completed_rows"),
                        "progress_completed_rows": completed_rows,
                        "budget_missing_rows": summary.get("missing_rows"),
                        "progress_incomplete_rows": incomplete_rows,
                        "active_progress_drift_rows": summary_drift_rows,
                    },
                )
            )
        else:
            if int(summary.get("completed_rows") or 0) != completed_rows:
                issues.append(
                    artifact_issue(
                        "error",
                        "run_budget",
                        "run budget completed rows do not match matrix progress",
                        {"budget_completed_rows": summary.get("completed_rows"), "progress_completed_rows": completed_rows},
                    )
                )
            if int(summary.get("missing_rows") or 0) != incomplete_rows:
                issues.append(
                    artifact_issue(
                        "error",
                        "run_budget",
                        "run budget missing rows do not match matrix progress",
                        {"budget_missing_rows": summary.get("missing_rows"), "progress_incomplete_rows": incomplete_rows},
                    )
                )
    timeout_sec = int(budget.get("timeout_sec") or 0)
    if timeout_sec <= 0:
        issues.append(artifact_issue("error", "run_budget", "run budget timeout_sec must be positive"))
    if float(summary.get("timeout_upper_bound_sec") or 0) < float(summary.get("estimated_missing_sec") or 0):
        issues.append(
            artifact_issue(
                "error",
                "run_budget",
                "run budget estimate exceeds timeout upper bound",
                {
                    "estimated_missing_sec": summary.get("estimated_missing_sec"),
                    "timeout_upper_bound_sec": summary.get("timeout_upper_bound_sec"),
                },
            )
        )
    if int(summary.get("observed_runtime_samples") or 0) <= 0:
        issues.append(
            artifact_issue(
                "warning",
                "run_budget",
                "run budget has no observed runtime samples and relies entirely on fallback estimates",
            )
        )
    notes = " ".join(str(item) for item in budget.get("notes", []))
    if "planning aids" not in notes:
        issues.append(
            artifact_issue(
                "warning",
                "run_budget",
                "run budget notes should state that estimates are planning aids",
            )
        )

    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "matrix_id": budget.get("matrix_id", ""),
        "expected_rows": summary.get("expected_rows", 0),
        "completed_rows": summary.get("completed_rows", 0),
        "missing_rows": summary.get("missing_rows", 0),
        "observed_runtime_samples": summary.get("observed_runtime_samples", 0),
        "estimated_missing_human": summary.get("estimated_missing_human", ""),
        "buffered_missing_human": summary.get("buffered_missing_human", ""),
        "timeout_upper_bound_human": summary.get("timeout_upper_bound_human", ""),
        "active_progress_drift_rows": summary_drift_rows
        if allow_active_progress_drift and summary_drift_rows is not None
        else 0,
        "issue_count": len(issues),
    }, issues


def stable_gap_projection(report: dict[str, Any]) -> dict[str, Any]:
    sections = report.get("sections", {})
    return {
        "submission_ready": report.get("submission_ready"),
        "summary": report.get("summary", {}),
        "manual_decisions": report.get("manual_decisions", []),
        "sections": {
            "current_readiness": sections.get("current_readiness", {}),
            "submission_readiness": sections.get("submission_readiness", {}),
            "suite_lock": sections.get("suite_lock", {}),
            "experiment_plan": sections.get("experiment_plan", {}),
            "matrix_progress": sections.get("matrix_progress", {}),
            "release_metadata": sections.get("release_metadata", {}),
            "claim_boundary": sections.get("claim_boundary", {}),
        },
        "issues": [
            {
                "severity": item.get("severity", ""),
                "scope": item.get("scope", ""),
                "message": item.get("message", ""),
                "action": item.get("action", ""),
                "detail": item.get("detail", {}),
            }
            for item in report.get("issues", [])
        ],
    }


def active_gap_projection(report: dict[str, Any]) -> dict[str, Any]:
    projection = stable_gap_projection(report)
    matrix = projection.get("sections", {}).get("matrix_progress", {})
    projection["sections"]["matrix_progress"] = {
        "complete": matrix.get("complete"),
        "matrix_id": matrix.get("matrix_id", ""),
        "expected_rows": matrix.get("expected_rows", 0),
    }
    for item in projection.get("issues", []):
        if item.get("scope") == "matrix_progress" and item.get("message") == "final paper matrix is incomplete":
            detail = item.get("detail", {})
            if isinstance(detail, dict):
                item["detail"] = {**detail, "source_details": []}
    return projection


def check_submission_gap(
    root: Path,
    require_ready: bool,
    *,
    allow_active_progress_drift: bool = False,
    max_active_progress_drift_rows: int = DEFAULT_ACTIVE_PROGRESS_DRIFT_ROWS,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    for rel in REQUIRED_SUBMISSION_GAP_FILES:
        if not (root / rel).is_file():
            issues.append(artifact_issue("error", "submission_gap", "missing submission gap file", {"path": rel}))

    json_path = root / REQUIRED_SUBMISSION_GAP_FILES[1]
    md_path = root / REQUIRED_SUBMISSION_GAP_FILES[0]
    if not json_path.is_file():
        return {"ok": False, "issue_count": len(issues)}, issues
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(
            artifact_issue(
                "error",
                "submission_gap",
                "could not parse submission gap JSON",
                {"path": str(json_path), "error": str(exc)},
            )
        )
        return {"ok": False, "issue_count": len(issues)}, issues

    expected = report_paper_submission_gaps.build_gap_report(root=root)
    active_json_drift_rows = active_summary_drift_rows(
        payload.get("sections", {}).get("matrix_progress", {}),
        expected.get("sections", {}).get("matrix_progress", {}),
        max_drift_rows=max_active_progress_drift_rows,
        snapshot_missing_key="incomplete_rows",
    )
    json_drift_warning = False
    if stable_gap_projection(payload) != stable_gap_projection(expected):
        if (
            allow_active_progress_drift
            and active_json_drift_rows is not None
            and active_gap_projection(payload) == active_gap_projection(expected)
        ):
            json_drift_warning = True
            issues.append(
                artifact_issue(
                    "warning",
                    "submission_gap",
                    "submission gap JSON lags active matrix progress",
                    {
                        "path": REQUIRED_SUBMISSION_GAP_FILES[1],
                        "actual_matrix_progress": payload.get("sections", {}).get("matrix_progress", {}),
                        "expected_matrix_progress": expected.get("sections", {}).get("matrix_progress", {}),
                        "active_progress_drift_rows": active_json_drift_rows,
                    },
                )
            )
        else:
            issues.append(
                artifact_issue(
                    "error",
                    "submission_gap",
                    "submission gap JSON is stale",
                    {
                        "path": REQUIRED_SUBMISSION_GAP_FILES[1],
                        "actual_summary": payload.get("summary", {}),
                        "expected_summary": expected.get("summary", {}),
                    },
                )
            )

    active_md_drift_rows = None
    if md_path.is_file():
        md_text = md_path.read_text(encoding="utf-8-sig")
        expected_matrix = expected.get("sections", {}).get("matrix_progress", {})
        marker = (
            f"matrix_progress: `{expected_matrix.get('completed_rows', 0)}/"
            f"{expected_matrix.get('expected_rows', 0)}`"
        )
        if f"submission_ready: `{str(expected.get('submission_ready')).lower()}`" not in md_text:
            issues.append(
                artifact_issue(
                    "error",
                    "submission_gap",
                    "submission gap Markdown readiness marker is stale",
                    {"path": REQUIRED_SUBMISSION_GAP_FILES[0]},
                )
            )
        if marker not in md_text:
            actual_marker = marker_text(md_text, "matrix_progress")
            actual_parts = actual_marker.split("/", 1)
            if len(actual_parts) == 2:
                actual_expected = as_int(actual_parts[1])
                actual_completed = as_int(actual_parts[0])
                active_md_drift_rows = active_summary_drift_rows(
                    {
                        "expected_rows": actual_expected,
                        "completed_rows": actual_completed,
                        "incomplete_rows": actual_expected - actual_completed,
                    },
                    expected_matrix,
                    max_drift_rows=max_active_progress_drift_rows,
                    snapshot_missing_key="incomplete_rows",
                )
            if allow_active_progress_drift and active_md_drift_rows is not None:
                issues.append(
                    artifact_issue(
                        "warning",
                        "submission_gap",
                        "submission gap Markdown matrix marker lags active matrix progress",
                        {
                            "path": REQUIRED_SUBMISSION_GAP_FILES[0],
                            "actual": actual_marker,
                            "expected": marker,
                            "active_progress_drift_rows": active_md_drift_rows,
                        },
                    )
                )
            else:
                issues.append(
                    artifact_issue(
                        "error",
                        "submission_gap",
                        "submission gap Markdown matrix marker is stale",
                        {"path": REQUIRED_SUBMISSION_GAP_FILES[0], "expected": marker},
                    )
                )

    if require_ready and not expected.get("submission_ready"):
        issues.append(
            artifact_issue(
                "error",
                "submission_gap",
                "submission gap report is not submission-ready",
                expected.get("summary", {}),
            )
        )

    summary = payload.get("summary", {})
    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "submission_ready": payload.get("submission_ready"),
        "errors": summary.get("error_count", 0),
        "warnings": summary.get("warning_count", 0),
        "raw_error_occurrences": summary.get("raw_error_count", 0),
        "raw_warning_occurrences": summary.get("raw_warning_count", 0),
        "pending_manual_decisions": summary.get("pending_manual_decision_count", 0),
        "blocking_manual_decisions": summary.get("blocking_manual_decision_count", 0),
        "active_progress_drift_rows": max(
            [
                active_json_drift_rows if json_drift_warning else 0,
                active_md_drift_rows or 0,
            ]
        ),
        "issue_count": len(issues),
    }, issues


def stable_submission_objective_projection(report: dict[str, Any]) -> dict[str, Any]:
    def project_item(entry: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": entry.get("id"),
            "status": entry.get("status"),
            "required_for_submission": entry.get("required_for_submission"),
            "detail": entry.get("detail", {}),
        }

    return {
        "schema_version": report.get("schema_version"),
        "submission_ready": report.get("submission_ready"),
        "summary": report.get("summary", {}),
        "required_items": [project_item(entry) for entry in report.get("required_items", [])],
        "enhancement_items": [project_item(entry) for entry in report.get("enhancement_items", [])],
    }


def check_submission_objective_audit(root: Path, require_ready: bool) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    for rel in REQUIRED_SUBMISSION_OBJECTIVE_AUDIT_FILES:
        if not (root / rel).is_file():
            issues.append(artifact_issue("error", "submission_objective", "missing submission objective audit file", {"path": rel}))

    md_path = root / REQUIRED_SUBMISSION_OBJECTIVE_AUDIT_FILES[0]
    json_path = root / REQUIRED_SUBMISSION_OBJECTIVE_AUDIT_FILES[1]
    if not json_path.is_file():
        return {"ok": False, "issue_count": len(issues)}, issues
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(
            artifact_issue(
                "error",
                "submission_objective",
                "could not parse submission objective audit JSON",
                {"path": str(json_path), "error": str(exc)},
            )
        )
        return {"ok": False, "issue_count": len(issues)}, issues

    expected = audit_submission_objective.build_audit(root=root)
    if stable_submission_objective_projection(payload) != stable_submission_objective_projection(expected):
        issues.append(
            artifact_issue(
                "error",
                "submission_objective",
                "submission objective audit JSON is stale",
                {
                    "path": REQUIRED_SUBMISSION_OBJECTIVE_AUDIT_FILES[1],
                    "actual_summary": payload.get("summary", {}),
                    "expected_summary": expected.get("summary", {}),
                },
            )
        )

    if md_path.is_file():
        md_text = md_path.read_text(encoding="utf-8-sig")
        for phrase in [
            "# Paper Submission Objective Audit",
            "release_metadata",
            "paper_body",
            "final_submission_gate",
            "full_suite_eligibility_appendix",
            "external_validity_plan",
        ]:
            if phrase not in md_text:
                issues.append(
                    artifact_issue(
                        "error",
                        "submission_objective",
                        "submission objective audit Markdown omits required phrase",
                        {"path": REQUIRED_SUBMISSION_OBJECTIVE_AUDIT_FILES[0], "phrase": phrase},
                    )
                )
    if require_ready and not expected.get("submission_ready"):
        issues.append(
            artifact_issue(
                "error",
                "submission_objective",
                "submission objective audit is not submission-ready",
                expected.get("summary", {}),
            )
        )

    summary = payload.get("summary", {})
    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "submission_ready": payload.get("submission_ready"),
        "required_complete": summary.get("required_complete", 0),
        "required_total": summary.get("required_total", 0),
        "required_blocked": summary.get("required_blocked", 0),
        "required_pending": summary.get("required_pending", 0),
        "enhancements_complete": summary.get("enhancements_complete", 0),
        "enhancements_total": summary.get("enhancements_total", 0),
        "issue_count": len(issues),
    }, issues


def resolve_manifest_record_path(root: Path, path_text: str) -> Path:
    path = Path(path_text)
    if path.is_absolute():
        return path
    return root / path


def check_submission_package_manifest(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    for rel in REQUIRED_SUBMISSION_PACKAGE_FILES:
        if not (root / rel).is_file():
            issues.append(artifact_issue("error", "submission_package", "missing submission package file", {"path": rel}))

    json_path = root / REQUIRED_SUBMISSION_PACKAGE_FILES[1]
    md_path = root / REQUIRED_SUBMISSION_PACKAGE_FILES[0]
    if not json_path.is_file():
        return {"ok": False, "issue_count": len(issues)}, issues
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(
            artifact_issue(
                "error",
                "submission_package",
                "could not parse submission package manifest JSON",
                {"path": str(json_path), "error": str(exc)},
            )
        )
        return {"ok": False, "issue_count": len(issues)}, issues

    files = payload.get("files")
    if not isinstance(files, list):
        issues.append(
            artifact_issue(
                "error",
                "submission_package",
                "submission package manifest files must be a list",
                {"type": type(files).__name__},
            )
        )
        files = []

    missing_files = payload.get("missing_files", [])
    if not isinstance(missing_files, list):
        issues.append(
            artifact_issue(
                "error",
                "submission_package",
                "submission package manifest missing_files must be a list",
                {"type": type(missing_files).__name__},
            )
        )
        missing_files = []
    if missing_files:
        issues.append(
            artifact_issue(
                "error",
                "submission_package",
                "submission package manifest records missing files",
                {"missing_files": [item.get("path", item) if isinstance(item, dict) else item for item in missing_files]},
            )
        )

    role_counts = {prefix: 0 for prefix in REQUIRED_SUBMISSION_PACKAGE_ROLE_PREFIXES}
    hashed_records = 0
    for index, record in enumerate(files):
        if not isinstance(record, dict):
            issues.append(
                artifact_issue(
                    "error",
                    "submission_package",
                    "submission package file record is not an object",
                    {"index": index},
                )
            )
            continue
        role = str(record.get("role") or "")
        path_text = str(record.get("path") or "").replace("\\", "/")
        for prefix in role_counts:
            if role.startswith(prefix):
                role_counts[prefix] += 1
        if record.get("exists") is not True:
            continue
        if not path_text:
            issues.append(
                artifact_issue(
                    "error",
                    "submission_package",
                    "submission package file record is missing path",
                    {"index": index, "role": role},
                )
            )
            continue
        path = resolve_manifest_record_path(root, path_text)
        if not path.is_file():
            issues.append(
                artifact_issue(
                    "error",
                    "submission_package",
                    "submission package file record points to a missing file",
                    {"index": index, "role": role, "path": path_text},
                )
            )
            continue
        expected_hash = str(record.get("sha256") or "")
        if not expected_hash:
            issues.append(
                artifact_issue(
                    "error",
                    "submission_package",
                    "submission package file record is missing sha256",
                    {"index": index, "role": role, "path": path_text},
                )
            )
            continue
        actual_hash = file_sha256(path)
        hashed_records += 1
        if actual_hash != expected_hash:
            issues.append(
                artifact_issue(
                    "error",
                    "submission_package",
                    "submission package file record hash is stale",
                    {
                        "index": index,
                        "role": role,
                        "path": path_text,
                        "expected_sha256": expected_hash,
                        "actual_sha256": actual_hash,
                    },
                )
            )

    for prefix, count in role_counts.items():
        if count <= 0:
            issues.append(
                artifact_issue(
                    "error",
                    "submission_package",
                    "submission package manifest omits required artifact role",
                    {"role_prefix": prefix},
                )
            )

    manifest_schema = as_int(payload.get("schema_version"))
    if manifest_schema not in {1, 2}:
        issues.append(
            artifact_issue(
                "error",
                "submission_package",
                "submission package manifest schema_version must be 1 or 2",
                {"schema_version": payload.get("schema_version")},
            )
        )
    manifest_results = payload.get("results", {})
    if not isinstance(manifest_results, dict):
        issues.append(
            artifact_issue(
                "error",
                "submission_package",
                "submission package manifest results must be an object",
            )
        )
        manifest_results = {}
    source_schema_version = as_int(manifest_results.get("source_schema_version"))
    if source_schema_version != 2:
        issues.append(
            artifact_issue(
                "error",
                "submission_package",
                "submission package result source schema_version must be 2",
                {"source_schema_version": manifest_results.get("source_schema_version")},
            )
        )
    if source_schema_version == 2:
        benchmark_payload = generate_submission_package_manifest.load_json(
            root / "docs/generated_artifacts/benchmark_card.json"
        )
        stats_payload = generate_submission_package_manifest.load_json(
            root / "docs/generated_artifacts/paper_statistical_analysis.json"
        )
        expected_results = generate_submission_package_manifest.result_summary(
            stats_payload, benchmark_payload
        )
        mismatches = {
            key: {"manifest": manifest_results.get(key), "source": value}
            for key, value in expected_results.items()
            if manifest_results.get(key) != value
        }
        if mismatches:
            issues.append(
                artifact_issue(
                    "error",
                    "submission_package",
                    "submission package result summary is stale or inconsistent",
                    {"mismatches": mismatches},
                )
            )
        scored = as_int(manifest_results.get("attack_scored_rows"))
        asr_eligible = as_int(
            manifest_results.get("attack_asr_eligible_scored_rows")
        )
        n_minus_one = as_int(manifest_results.get("attack_n_minus_1_rows"))
        accounted = as_int(manifest_results.get("attack_accounted_terminal_rows"))
        protocol_denominator = as_int(
            manifest_results.get("attack_protocol_denominator_rows")
        )
        successes = as_int(manifest_results.get("attack_success"))
        end_to_end_successes = as_int(
            manifest_results.get("end_to_end_attack_success")
        )
        result_rate_expectations = [
            (
                "protocol_completion_rate",
                asr_eligible,
                protocol_denominator,
            ),
            (
                "model_nonconformance_rate",
                n_minus_one,
                protocol_denominator,
            ),
            ("conditional_asr_rate", successes, asr_eligible),
            (
                "end_to_end_attack_rate",
                end_to_end_successes,
                protocol_denominator,
            ),
        ]
        if (
            accounted != scored + n_minus_one
            or protocol_denominator != asr_eligible + n_minus_one
            or not (0 <= successes <= asr_eligible <= scored)
            or end_to_end_successes != successes
        ):
            issues.append(
                artifact_issue(
                    "error",
                    "submission_package",
                    "submission package result-class counts are inconsistent",
                    {
                        "scored": scored,
                        "asr_eligible_scored": asr_eligible,
                        "n_minus_1": n_minus_one,
                        "accounted_terminal": accounted,
                        "protocol_denominator": protocol_denominator,
                    },
                )
            )
        control_scored = as_int(manifest_results.get("control_scored_rows"))
        control_asr = as_int(
            manifest_results.get("control_asr_eligible_scored_rows")
        )
        control_n_minus_one = as_int(
            manifest_results.get("control_n_minus_1_rows")
        )
        control_accounted = as_int(
            manifest_results.get("control_accounted_terminal_rows")
        )
        control_protocol_denominator = as_int(
            manifest_results.get("control_protocol_denominator_rows")
        )
        control_successes = as_int(manifest_results.get("control_attack_success"))
        control_end_to_end_successes = as_int(
            manifest_results.get("control_end_to_end_violation_success")
        )
        if (
            control_accounted != control_scored + control_n_minus_one
            or control_protocol_denominator
            != control_asr + control_n_minus_one
            or not (0 <= control_successes <= control_asr <= control_scored)
            or control_end_to_end_successes != control_successes
        ):
            issues.append(
                artifact_issue(
                    "error",
                    "submission_package",
                    "submission package control result-class counts are inconsistent",
                    {
                        "scored": control_scored,
                        "asr_eligible_scored": control_asr,
                        "n_minus_1": control_n_minus_one,
                        "accounted_terminal": control_accounted,
                        "protocol_denominator": control_protocol_denominator,
                    },
                )
            )
        for field, numerator, denominator in [
            (
                "control_protocol_completion_rate",
                control_asr,
                control_protocol_denominator,
            ),
            (
                "control_model_nonconformance_rate",
                control_n_minus_one,
                control_protocol_denominator,
            ),
            (
                "control_conditional_violation_rate",
                control_successes,
                control_asr,
            ),
            (
                "control_end_to_end_violation_rate",
                control_end_to_end_successes,
                control_protocol_denominator,
            ),
        ]:
            if not rate_matches(manifest_results.get(field), numerator, denominator):
                issues.append(
                    artifact_issue(
                        "error",
                        "submission_package",
                        "submission package control result rate is inconsistent",
                        {
                            "field": field,
                            "value": manifest_results.get(field),
                            "numerator": numerator,
                            "denominator": denominator,
                        },
                    )
                )
        for field, numerator, denominator in result_rate_expectations:
            if not rate_matches(manifest_results.get(field), numerator, denominator):
                issues.append(
                    artifact_issue(
                        "error",
                        "submission_package",
                        "submission package result rate is inconsistent",
                        {
                            "field": field,
                            "value": manifest_results.get(field),
                            "numerator": numerator,
                            "denominator": denominator,
                        },
                    )
                )
    gates = payload.get("gates", {})
    if not isinstance(gates, dict):
        issues.append(
            artifact_issue(
                "error",
                "submission_package",
                "submission package manifest gates must be an object",
                {"type": type(gates).__name__},
            )
        )
        gates = {}
    for gate_name in ["current_artifact_gate", "submission_artifact_gate", "repro_bundle_manifest"]:
        gate = gates.get(gate_name)
        if not isinstance(gate, dict):
            issues.append(
                artifact_issue(
                    "error",
                    "submission_package",
                    "submission package manifest is missing gate record",
                    {"gate": gate_name},
                )
            )
            continue
        gate_path_text = str(gate.get("path") or "").replace("\\", "/")
        if gate.get("exists") is not True or not gate_path_text or not resolve_manifest_record_path(root, gate_path_text).is_file():
            issues.append(
                artifact_issue(
                    "error",
                    "submission_package",
                    "submission package manifest gate record is not present on disk",
                    {"gate": gate_name, "path": gate_path_text},
                )
            )

    if md_path.is_file():
        md_text = md_path.read_text(encoding="utf-8-sig")
        for phrase in ["Paper Submission Package Manifest", "attack_report:", "paper_tables:", "case_study_evidence:"]:
            if phrase not in md_text:
                issues.append(
                    artifact_issue(
                        "error",
                        "submission_package",
                        "submission package Markdown omits required phrase",
                        {"path": REQUIRED_SUBMISSION_PACKAGE_FILES[0], "phrase": phrase},
                    )
                )

    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "issue_count": len(issues),
        "file_records": len(files),
        "hashed_records": hashed_records,
        "missing_files": len(missing_files),
        "attack_report_records": role_counts.get("attack_report:", 0),
        "control_report_records": role_counts.get("control_report:", 0),
        "paper_table_records": role_counts.get("paper_tables:", 0),
        "case_evidence_records": role_counts.get("case_study_evidence:", 0),
    }, issues


def check_live_status_artifacts(
    root: Path,
    *,
    allow_active_status_drift: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    for rel in REQUIRED_LIVE_STATUS_FILES:
        if not (root / rel).is_file():
            issues.append(artifact_issue("error", "live_status", "missing live status file", {"path": rel}))
    if issues:
        return {"ok": False, "issue_count": len(issues), "generated_at": ""}, issues

    try:
        status = json.loads((root / "docs/generated_artifacts/paper_live_status.json").read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(artifact_issue("error", "live_status", "could not parse paper_live_status.json", {"error": str(exc)}))
        return {"ok": False, "issue_count": len(issues), "generated_at": ""}, issues

    failure_marker_jobs: list[dict[str, Any]] = []
    for job in status.get("jobs", []):
        if not isinstance(job, dict):
            continue
        try:
            count = int(job.get("unresolved_failure_marker_count", job.get("failure_marker_count")) or 0)
        except (TypeError, ValueError):
            count = 0
        if count > 0:
            failure_marker_jobs.append(
                {
                    "job_name": job.get("job_name", ""),
                    "observed_status": job.get("observed_status", ""),
                    "failure_marker_count": job.get("failure_marker_count", 0),
                    "unresolved_failure_marker_count": count,
                }
            )
    if failure_marker_jobs:
        issues.append(
            artifact_issue(
                "warning",
                "live_status",
                "paper live status reports runner failure markers",
                {"jobs": failure_marker_jobs},
            )
        )

    generated_at = str(status.get("generated_at") or "")
    if not generated_at:
        issues.append(artifact_issue("error", "live_status", "paper_live_status.json is missing generated_at"))

    status_md = (root / "docs/generated_artifacts/paper_live_status.md").read_text(encoding="utf-8-sig")
    check_md = (root / "docs/generated_artifacts/paper_live_status_check.md").read_text(encoding="utf-8-sig")
    status_md_generated_at = marker_text(status_md, "generated_at")
    check_live_generated_at = marker_text(check_md, "live_generated_at")
    check_ok = marker_text(check_md, "ok")
    if generated_at and status_md_generated_at != generated_at:
        issues.append(
            artifact_issue(
                "error",
                "live_status",
                "paper_live_status.md does not match paper_live_status.json generated_at",
                {"json_generated_at": generated_at, "md_generated_at": status_md_generated_at},
            )
        )
    if check_ok.lower() != "true":
        issues.append(
            artifact_issue(
                "error",
                "live_status",
                "paper_live_status_check.md does not record ok=true",
                {"ok": check_ok},
            )
        )
    history_latest_generated_at = ""
    history_sample_count = 0
    history_expected_transitions: list[dict[str, Any]] = []
    current_matrix_id = live_status_matrix_id(status)
    history_path = root / "docs/generated_artifacts/paper_live_status_history.jsonl"
    if history_path.is_file():
        history_lines = [line.strip() for line in history_path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
        history_sample_count = len(history_lines)
        if not history_lines:
            issues.append(artifact_issue("error", "live_status", "paper_live_status_history.jsonl is empty"))
        else:
            try:
                latest_history = json.loads(history_lines[-1])
            except Exception as exc:  # pragma: no cover - defensive parsing guard
                issues.append(
                    artifact_issue(
                        "error",
                        "live_status",
                        "could not parse latest paper_live_status_history.jsonl sample",
                        {"error": str(exc)},
                    )
                )
                latest_history = {}
            history_latest_generated_at = str(latest_history.get("generated_at") or "")
            if generated_at and history_latest_generated_at != generated_at:
                issues.append(
                    artifact_issue(
                        "error",
                        "live_status",
                        "paper_live_status_history.jsonl latest sample is stale for paper_live_status.json",
                        {
                            "json_generated_at": generated_at,
                            "history_latest_generated_at": history_latest_generated_at,
                        },
                    )
                )
            previous_sample: dict[str, Any] | None = None
            for index, line in enumerate(history_lines, start=1):
                try:
                    sample = json.loads(line)
                except Exception as exc:  # pragma: no cover - defensive parsing guard
                    issues.append(
                        artifact_issue(
                            "error",
                            "live_status",
                            "could not parse paper_live_status_history.jsonl sample",
                            {"line": index, "error": str(exc)},
                        )
                    )
                    continue
                if previous_sample:
                    previous_matrix_id = live_history_sample_matrix_id(previous_sample)
                    current_sample_matrix_id = live_history_sample_matrix_id(sample)
                    if current_matrix_id and (
                        previous_matrix_id != current_matrix_id or current_sample_matrix_id != current_matrix_id
                    ):
                        previous_sample = sample
                        continue
                    for scope in ["full", "claude"]:
                        prev_progress = previous_sample.get(scope, {}) if isinstance(previous_sample.get(scope), dict) else {}
                        curr_progress = sample.get(scope, {}) if isinstance(sample.get(scope), dict) else {}
                        prev_completed = as_int(prev_progress.get("completed_rows"))
                        curr_completed = as_int(curr_progress.get("completed_rows"))
                        prev_expected = as_int(prev_progress.get("expected_rows"))
                        curr_expected = as_int(curr_progress.get("expected_rows"))
                        if curr_completed < prev_completed:
                            issues.append(
                                artifact_issue(
                                    "error",
                                    "live_status",
                                    "paper_live_status_history.jsonl progress decreases",
                                    {
                                        "line": index,
                                        "scope": scope,
                                        "previous_completed": prev_completed,
                                        "current_completed": curr_completed,
                                    },
                                )
                            )
                        if curr_expected != prev_expected:
                            history_expected_transitions.append(
                                {
                                    "line": index,
                                    "scope": scope,
                                    "previous_expected": prev_expected,
                                    "current_expected": curr_expected,
                                    "previous_matrix_id": previous_matrix_id,
                                    "matrix_id": current_sample_matrix_id,
                                }
                            )
                previous_sample = sample
            current_summary = status.get("matrix_progress", {}) if isinstance(status.get("matrix_progress"), dict) else {}
            for scope in ["full", "claude"]:
                latest_progress = latest_history.get(scope, {}) if isinstance(latest_history.get(scope), dict) else {}
                latest_expected = as_int(latest_progress.get("expected_rows"))
                live_scope = current_summary.get(scope, {}) if isinstance(current_summary.get(scope), dict) else {}
                live_summary = live_scope.get("summary", {}) if isinstance(live_scope.get("summary"), dict) else {}
                live_expected = as_int(live_summary.get("expected_rows"))
                if live_expected and latest_expected and latest_expected != live_expected:
                    issues.append(
                        artifact_issue(
                            "error",
                            "live_status",
                            "paper_live_status_history.jsonl latest expected rows differ from paper_live_status.json",
                            {
                                "scope": scope,
                                "history_latest_expected": latest_expected,
                                "live_expected": live_expected,
                            },
                        )
                    )
            if history_expected_transitions:
                issues.append(
                    artifact_issue(
                        "warning",
                        "live_status",
                        "paper_live_status_history.jsonl expected row count changed across samples",
                        {"transitions": history_expected_transitions[:5]},
                    )
                )
    if generated_at and check_live_generated_at != generated_at:
        if allow_active_status_drift and history_latest_generated_at == generated_at and check_live_generated_at:
            issues.append(
                artifact_issue(
                    "warning",
                    "live_status",
                    "paper_live_status_check.md trails active live status snapshot",
                    {"json_generated_at": generated_at, "check_live_generated_at": check_live_generated_at},
                )
            )
        else:
            issues.append(
                artifact_issue(
                    "error",
                    "live_status",
                    "paper_live_status_check.md is stale for paper_live_status.json",
                    {"json_generated_at": generated_at, "check_live_generated_at": check_live_generated_at},
                )
            )
    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "issue_count": len(issues),
        "generated_at": generated_at,
        "check_ok": check_ok,
        "failure_marker_count": sum(int(item["failure_marker_count"] or 0) for item in failure_marker_jobs),
        "unresolved_failure_marker_count": sum(
            int(item["unresolved_failure_marker_count"] or 0) for item in failure_marker_jobs
        ),
        "history_latest_generated_at": history_latest_generated_at,
        "history_sample_count": history_sample_count,
        "history_expected_transition_count": len(history_expected_transitions),
    }, issues


def check_run_queue(
    root: Path,
    experiment_plan: dict[str, Any],
    matrix_progress: dict[str, Any],
    *,
    allow_active_progress_drift: bool = False,
    max_active_progress_drift_rows: int = DEFAULT_ACTIVE_PROGRESS_DRIFT_ROWS,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    for rel in REQUIRED_RUN_QUEUE_FILES:
        if not (root / rel).is_file():
            issues.append(artifact_issue("error", "run_queue", "missing run queue file", {"path": rel}))
    json_path = root / REQUIRED_RUN_QUEUE_FILES[0]
    if not json_path.is_file():
        return {"ok": False, "issue_count": len(issues)}, issues
    try:
        queue = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(
            artifact_issue(
                "error",
                "run_queue",
                "could not parse run queue JSON",
                {"path": str(json_path), "error": str(exc)},
            )
        )
        return {"ok": False, "issue_count": len(issues)}, issues

    summary = queue.get("summary", {})
    recorded_queue_digest = str(queue.get("queue_digest") or "")
    if recorded_queue_digest and recorded_queue_digest != export_paper_run_queue.queue_digest(queue):
        issues.append(
            artifact_issue(
                "error",
                "run_queue",
                "run queue digest does not match its contents",
            )
        )
    plan_matrix_id = str(experiment_plan.get("matrix_id") or "")
    if plan_matrix_id and queue.get("matrix_id") != plan_matrix_id:
        issues.append(
            artifact_issue(
                "error",
                "run_queue",
                "run queue matrix id does not match experiment plan",
                {"queue_matrix_id": queue.get("matrix_id"), "plan_matrix_id": plan_matrix_id},
            )
        )
    expected_rows = int(matrix_progress.get("expected_rows") or 0)
    completed_rows = int(matrix_progress.get("completed_rows") or 0)
    incomplete_rows = int(matrix_progress.get("incomplete_rows") or 0)
    summary_drift_rows = active_summary_drift_rows(
        summary,
        {
            "expected_rows": expected_rows,
            "completed_rows": completed_rows,
            "incomplete_rows": incomplete_rows,
        },
        max_drift_rows=max_active_progress_drift_rows,
    )
    if int(summary.get("expected_rows") or 0) != expected_rows:
        issues.append(
            artifact_issue(
                "error",
                "run_queue",
                "run queue expected rows do not match matrix progress",
                {"queue_expected_rows": summary.get("expected_rows"), "progress_expected_rows": expected_rows},
            )
        )
    elif (
        int(summary.get("completed_rows") or 0) != completed_rows
        or int(summary.get("missing_rows") or 0) != incomplete_rows
    ):
        if allow_active_progress_drift and summary_drift_rows is not None:
            issues.append(
                artifact_issue(
                    "warning",
                    "run_queue",
                    "run queue lags active matrix progress",
                    {
                        "queue_completed_rows": summary.get("completed_rows"),
                        "progress_completed_rows": completed_rows,
                        "queue_missing_rows": summary.get("missing_rows"),
                        "progress_incomplete_rows": incomplete_rows,
                        "active_progress_drift_rows": summary_drift_rows,
                    },
                )
            )
        else:
            if int(summary.get("completed_rows") or 0) != completed_rows:
                issues.append(
                    artifact_issue(
                        "error",
                        "run_queue",
                        "run queue completed rows do not match matrix progress",
                        {"queue_completed_rows": summary.get("completed_rows"), "progress_completed_rows": completed_rows},
                    )
                )
            if int(summary.get("missing_rows") or 0) != incomplete_rows:
                issues.append(
                    artifact_issue(
                        "error",
                        "run_queue",
                        "run queue missing rows do not match matrix progress",
                        {"queue_missing_rows": summary.get("missing_rows"), "progress_incomplete_rows": incomplete_rows},
                    )
                )
    batches = queue.get("batches", []) or []
    coalesced_batches = queue.get("coalesced_batches", []) or []
    serial_rows = queue.get("serial_rows", []) or []
    if int(summary.get("batch_count") or 0) != len(batches):
        issues.append(
            artifact_issue(
                "error",
                "run_queue",
                "run queue batch_count does not match batches",
                {"summary_batch_count": summary.get("batch_count"), "actual_batch_count": len(batches)},
            )
        )
    if int(summary.get("coalesced_batch_count") or 0) != len(coalesced_batches):
        issues.append(
            artifact_issue(
                "error",
                "run_queue",
                "run queue coalesced_batch_count does not match coalesced batches",
                {
                    "summary_coalesced_batch_count": summary.get("coalesced_batch_count"),
                    "actual_coalesced_batch_count": len(coalesced_batches),
                },
            )
        )
    fine_sum = sum(int(batch.get("missing_rows") or 0) for batch in batches)
    coalesced_sum = sum(int(batch.get("missing_rows") or 0) for batch in coalesced_batches)
    missing_rows = int(summary.get("missing_rows") or 0)
    if fine_sum != missing_rows:
        issues.append(
            artifact_issue(
                "error",
                "run_queue",
                "fine-grained run queue rows do not sum to missing rows",
                {"fine_grained_rows": fine_sum, "missing_rows": missing_rows},
            )
        )
    if coalesced_sum != missing_rows:
        issues.append(
            artifact_issue(
                "error",
                "run_queue",
                "coalesced run queue rows do not sum to missing rows",
                {"coalesced_rows": coalesced_sum, "missing_rows": missing_rows},
            )
        )
    for batch in coalesced_batches:
        command = str(batch.get("command") or "")
        if missing_rows and "-SkipCompleted" not in command:
            issues.append(
                artifact_issue(
                    "error",
                    "run_queue",
                    "coalesced run queue command is not resumable",
                    {"batch_id": batch.get("batch_id", ""), "command": command},
                )
            )
    if serial_rows:
        if queue.get("queue_status") != "formal_locked" or queue.get("formal_execution_eligible") is not True:
            issues.append(
                artifact_issue(
                    "error",
                    "run_queue",
                    "formal serial queue is marked as an unlocked development preview",
                )
            )
        if not str(queue.get("attempt_ledger") or "") or not str(queue.get("execution_lock") or ""):
            issues.append(
                artifact_issue(
                    "error",
                    "run_queue",
                    "formal serial queue lacks retry-ledger or single-consumer lock metadata",
                )
            )
        if queue.get("suite_lock", {}) != experiment_plan.get("suite_lock", {}):
            issues.append(
                artifact_issue(
                    "error",
                    "run_queue",
                    "formal serial queue suite-lock binding does not match experiment plan",
                )
            )
        positions = [int(row.get("queue_position") or 0) for row in serial_rows]
        row_ids = [str(row.get("expected_row_id") or "") for row in serial_rows]
        if int(summary.get("formal_serial_rows") or 0) != len(serial_rows):
            issues.append(
                artifact_issue(
                    "error",
                    "run_queue",
                    "formal serial row count does not match queue summary",
                )
            )
        if len(serial_rows) != expected_rows:
            issues.append(
                artifact_issue(
                    "error",
                    "run_queue",
                    "formal serial queue row count does not match expected matrix rows",
                    {
                        "serial_rows": len(serial_rows),
                        "expected_rows": expected_rows,
                    },
                )
            )
        if positions != list(range(1, len(serial_rows) + 1)):
            issues.append(
                artifact_issue("error", "run_queue", "formal serial queue positions are not contiguous")
            )
        if not all(row_ids) or len(set(row_ids)) != len(row_ids):
            issues.append(
                artifact_issue("error", "run_queue", "formal serial expected_row_id values are not unique")
            )
        if int(summary.get("duplicate_valid_rows") or 0) != 0:
            issues.append(
                artifact_issue("error", "run_queue", "formal serial queue contains duplicate valid results")
            )
        if int(summary.get("duplicate_accounted_rows") or 0) != 0:
            issues.append(
                artifact_issue(
                    "error",
                    "run_queue",
                    "formal serial queue contains duplicate accounted terminal results",
                )
            )

        required_accounting_fields = {
            "formal_valid_completed_rows",
            "formal_accounted_completed_rows",
            "formal_pending_rows",
            "duplicate_accounted_rows",
            "model_protocol_terminal_rows",
        }
        missing_accounting_fields = sorted(required_accounting_fields - set(summary))
        if missing_accounting_fields:
            issues.append(
                artifact_issue(
                    "error",
                    "run_queue",
                    "formal serial queue summary lacks terminal result-class accounting",
                    {"missing_fields": missing_accounting_fields},
                )
            )

        actual_accounted_completed = 0
        actual_valid_completed = 0
        actual_model_protocol_terminal = 0
        actual_duplicate_valid = 0
        actual_duplicate_accounted = 0
        malformed_state_rows: list[str] = []
        for row in serial_rows:
            valid_count = int(row.get("valid_result_count") or 0)
            protocol_count = int(row.get("model_protocol_terminal_count") or 0)
            accounted_count = int(row.get("accounted_result_count") or 0)
            in_progress_count = int(row.get("in_progress_attempt_count") or 0)
            expected_completed = accounted_count == 1 and in_progress_count == 0
            expected_missing = 0 if expected_completed else 1
            if valid_count > 1:
                actual_duplicate_valid += 1
            if accounted_count > 1:
                actual_duplicate_accounted += 1
            if expected_completed:
                actual_accounted_completed += 1
                if valid_count == 1 and protocol_count == 0:
                    actual_valid_completed += 1
                if protocol_count == 1 and valid_count == 0:
                    actual_model_protocol_terminal += 1
            if (
                accounted_count != valid_count + protocol_count
                or row.get("completed") is not expected_completed
                or int(row.get("missing_rows") or 0) != expected_missing
            ):
                malformed_state_rows.append(str(row.get("expected_row_id") or ""))

        if malformed_state_rows:
            issues.append(
                artifact_issue(
                    "error",
                    "run_queue",
                    "formal serial queue row state is inconsistent with authoritative terminal counts",
                    {"expected_row_ids": malformed_state_rows[:10]},
                )
            )

        actual_pending = len(serial_rows) - actual_accounted_completed
        accounting_expectations = {
            "completed_rows": actual_accounted_completed,
            "missing_rows": actual_pending,
            "formal_valid_completed_rows": actual_valid_completed,
            "formal_accounted_completed_rows": actual_accounted_completed,
            "formal_pending_rows": actual_pending,
            "duplicate_valid_rows": actual_duplicate_valid,
            "duplicate_accounted_rows": actual_duplicate_accounted,
            "model_protocol_terminal_rows": actual_model_protocol_terminal,
        }
        mismatched_accounting = {
            key: {"summary": summary.get(key), "actual": expected}
            for key, expected in accounting_expectations.items()
            if int(summary.get(key) or 0) != expected
        }
        if mismatched_accounting:
            issues.append(
                artifact_issue(
                    "error",
                    "run_queue",
                    "formal serial queue summary does not match terminal row accounting",
                    {"mismatches": mismatched_accounting},
                )
            )

        progress_accounting_expectations = {
            "completed_rows": actual_accounted_completed,
            "incomplete_rows": actual_pending,
            "execution_valid_completed_rows": actual_valid_completed,
            "model_protocol_terminal_rows": actual_model_protocol_terminal,
        }
        progress_accounting_mismatches = {
            key: {"matrix_progress": matrix_progress.get(key), "actual": expected}
            for key, expected in progress_accounting_expectations.items()
            if int(matrix_progress.get(key) or 0) != expected
        }
        if progress_accounting_mismatches:
            active_lag = allow_active_progress_drift and summary_drift_rows is not None
            issues.append(
                artifact_issue(
                    "warning" if active_lag else "error",
                    "run_queue",
                    "formal serial terminal accounting lags matrix progress"
                    if active_lag
                    else "formal serial terminal accounting does not match matrix progress",
                    {
                        "mismatches": progress_accounting_mismatches,
                        **(
                            {"active_progress_drift_rows": summary_drift_rows}
                            if active_lag
                            else {}
                        ),
                    },
                )
            )

        progress_summary = queue.get("progress_summary", {})
        if not isinstance(progress_summary, dict):
            progress_summary = {}
        progress_summary_mismatches = {
            key: {
                "queue_progress_summary": progress_summary.get(key),
                "matrix_progress": matrix_progress.get(key),
            }
            for key in progress_accounting_expectations
            if int(progress_summary.get(key) or 0) != int(matrix_progress.get(key) or 0)
        }
        if progress_summary_mismatches:
            active_lag = allow_active_progress_drift and summary_drift_rows is not None
            issues.append(
                artifact_issue(
                    "warning" if active_lag else "error",
                    "run_queue",
                    "run queue progress summary lags result-class accounting"
                    if active_lag
                    else "run queue progress summary lacks or disagrees with result-class accounting",
                    {
                        "mismatches": progress_summary_mismatches,
                        **(
                            {"active_progress_drift_rows": summary_drift_rows}
                            if active_lag
                            else {}
                        ),
                    },
                )
            )
        for row in serial_rows:
            command = str(row.get("command") or "")
            expected_row_id = str(row.get("expected_row_id") or "")
            isolated_home_id = str(row.get("isolated_home_id") or "")
            if (
                row.get("skip_completed") is not True
                or "run_harness_case.ps1" not in command
                or "-CanaryToken" not in command
                or run_paper_queue.powershell_switch_values(command, "FormalRowId") != [expected_row_id]
                or not isolated_home_id
                or run_paper_queue.powershell_switch_values(command, "FormalIsolatedHomeId")
                != [isolated_home_id]
            ):
                issues.append(
                    artifact_issue(
                        "error",
                        "run_queue",
                        "formal serial row lacks bound row/home provenance or resumable command metadata",
                        {"expected_row_id": expected_row_id},
                    )
                )
    post_run = "\n".join(str(command) for command in queue.get("post_run_commands", []) or [])
    if "check_paper_matrix_progress.py --require-complete" not in post_run:
        issues.append(
            artifact_issue(
                "error",
                "run_queue",
                "run queue post-run commands do not require final matrix completion",
            )
        )

    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "matrix_id": queue.get("matrix_id", ""),
        "expected_rows": summary.get("expected_rows", 0),
        "completed_rows": summary.get("completed_rows", 0),
        "missing_rows": summary.get("missing_rows", 0),
        "formal_valid_completed_rows": summary.get("formal_valid_completed_rows", 0),
        "formal_accounted_completed_rows": summary.get(
            "formal_accounted_completed_rows", 0
        ),
        "model_protocol_terminal_rows": summary.get("model_protocol_terminal_rows", 0),
        "duplicate_accounted_rows": summary.get("duplicate_accounted_rows", 0),
        "batch_count": summary.get("batch_count", 0),
        "coalesced_batch_count": summary.get("coalesced_batch_count", 0),
        "active_progress_drift_rows": summary_drift_rows
        if allow_active_progress_drift and summary_drift_rows is not None
        else 0,
        "issue_count": len(issues),
    }, issues


def live_status_has_running_job(root: Path) -> bool:
    path = root / "docs/generated_artifacts/paper_live_status.json"
    if not path.is_file():
        return False
    try:
        status = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return False
    jobs = status.get("jobs", [])
    if not isinstance(jobs, list):
        return False
    return any(
        str(job.get("observed_status") or job.get("status") or "").lower() == "running"
        for job in jobs
        if isinstance(job, dict)
    )


def run_execution_queue_compare_severity(root: Path, execution: dict[str, Any]) -> str:
    if (
        live_status_has_running_job(root)
        and execution.get("queue_mode") in {"serial", "coalesced"}
        and execution.get("execute") is False
    ):
        return "warning"
    return "error"


def check_run_execution(
    root: Path,
    experiment_plan: dict[str, Any],
    run_queue: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    for rel in REQUIRED_RUN_EXECUTION_FILES:
        if not (root / rel).is_file():
            issues.append(artifact_issue("error", "run_execution", "missing run execution file", {"path": rel}))
    json_path = root / REQUIRED_RUN_EXECUTION_FILES[0]
    queue_path = root / "docs/generated_artifacts/paper_run_queue.json"
    if not json_path.is_file():
        return {"ok": False, "issue_count": len(issues)}, issues
    try:
        execution = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(
            artifact_issue(
                "error",
                "run_execution",
                "could not parse run execution JSON",
                {"path": str(json_path), "error": str(exc)},
            )
        )
        return {"ok": False, "issue_count": len(issues)}, issues
    try:
        queue = json.loads(queue_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(
            artifact_issue(
                "error",
                "run_execution",
                "could not parse run queue JSON for execution-plan comparison",
                {"path": str(queue_path), "error": str(exc)},
            )
        )
        queue = {}

    plan_matrix_id = str(experiment_plan.get("matrix_id") or "")
    queue_matrix_id = str(run_queue.get("matrix_id") or queue.get("matrix_id") or "")
    if plan_matrix_id and execution.get("matrix_id") != plan_matrix_id:
        issues.append(
            artifact_issue(
                "error",
                "run_execution",
                "run execution matrix id does not match experiment plan",
                {"execution_matrix_id": execution.get("matrix_id"), "plan_matrix_id": plan_matrix_id},
            )
        )
    if queue_matrix_id and execution.get("matrix_id") != queue_matrix_id:
        issues.append(
            artifact_issue(
                "error",
                "run_execution",
                "run execution matrix id does not match run queue",
                {"execution_matrix_id": execution.get("matrix_id"), "queue_matrix_id": queue_matrix_id},
            )
        )

    serial_rows = (queue.get("serial_rows", []) or []) if isinstance(queue, dict) else []
    expected_mode = "serial" if serial_rows else "coalesced"
    expected_settings = {
        "queue_mode": expected_mode,
        "requested_batches": [],
        "requested_harnesses": [],
        "start_at": "",
        "include_post_run": False,
        "execute": False,
        "stop_on_failure": True,
        "skip_readiness_check": False,
    }
    for key, expected in expected_settings.items():
        if execution.get(key) != expected:
            issues.append(
                artifact_issue(
                    "error",
                    "run_execution",
                    f"run execution plan is not the default {expected_mode} dry-run",
                    {"field": key, "actual": execution.get(key), "expected": expected},
                )
            )

    queue_summary = queue.get("summary", {}) if isinstance(queue, dict) else {}
    execution_queue_summary = execution.get("queue_summary", {})
    queue_compare_severity = run_execution_queue_compare_severity(root, execution)
    for key in ["expected_rows", "completed_rows", "missing_rows"]:
        if int(execution_queue_summary.get(key) or 0) != int(queue_summary.get(key) or 0):
            issues.append(
                artifact_issue(
                    queue_compare_severity,
                    "run_execution",
                    "run execution queue summary does not match run queue",
                    {
                        "field": key,
                        "execution_value": execution_queue_summary.get(key),
                        "queue_value": queue_summary.get(key),
                        "active_running_job": queue_compare_severity == "warning",
                    },
                )
            )

    coalesced = (queue.get("coalesced_batches", []) or []) if isinstance(queue, dict) else []
    expected_queue_rows = serial_rows if expected_mode == "serial" else coalesced
    commands = execution.get("commands", []) or []
    summary = execution.get("summary", {})
    if int(summary.get("selected_commands") or 0) != len(expected_queue_rows):
        issues.append(
            artifact_issue(
                queue_compare_severity,
                "run_execution",
                f"run execution selected_commands does not match {expected_mode} run queue",
                {
                    "selected_commands": summary.get("selected_commands"),
                    "expected_command_count": len(expected_queue_rows),
                    "active_running_job": queue_compare_severity == "warning",
                },
            )
        )
    if len(commands) != len(expected_queue_rows):
        issues.append(
            artifact_issue(
                queue_compare_severity,
                "run_execution",
                f"run execution command count does not match {expected_mode} run queue",
                {
                    "command_count": len(commands),
                    "expected_command_count": len(expected_queue_rows),
                    "active_running_job": queue_compare_severity == "warning",
                },
            )
        )
    for key in ["executed_commands", "failed_commands", "blocked_commands", "pending_commands"]:
        if int(summary.get(key) or 0) != 0:
            issues.append(
                artifact_issue(
                    "error",
                    "run_execution",
                    "run execution dry-run summary should not record executed or blocked work",
                    {"field": key, "value": summary.get(key)},
                )
            )
    if summary.get("ok") is not True:
        issues.append(artifact_issue("error", "run_execution", "run execution dry-run summary is not ok"))

    expected_requires_kimi = run_paper_queue.selected_requires_kimi(
        [run_paper_queue.command_record(expected_mode, index + 1, str(batch.get("command") or ""), batch) for index, batch in enumerate(expected_queue_rows)]
    )
    gate = execution.get("readiness_gate", {})
    if gate.get("checked") is not False or gate.get("ready") is not None:
        issues.append(
            artifact_issue(
                "error",
                "run_execution",
                "dry-run execution plan should not run the readiness gate",
                {"readiness_gate": gate},
            )
        )
    if bool(gate.get("requires_kimi")) != expected_requires_kimi:
        issues.append(
            artifact_issue(
                queue_compare_severity,
                "run_execution",
                f"run execution requires_kimi flag does not match selected {expected_mode} rows",
                {
                    "requires_kimi": gate.get("requires_kimi"),
                    "expected": expected_requires_kimi,
                    "active_running_job": queue_compare_severity == "warning",
                },
            )
        )

    for index, batch in enumerate(expected_queue_rows):
        if index >= len(commands):
            break
        command = commands[index]
        expected = run_paper_queue.command_record(expected_mode, index + 1, str(batch.get("command") or ""), batch)
        compare_keys = ["index", "source", "batch_id", "kind", "harness", "control_types", "missing_rows", "command"]
        if expected_mode == "serial":
            compare_keys.extend(["expected_row_id", "queue_position"])
        for key in compare_keys:
            if command.get(key) != expected.get(key):
                issues.append(
                    artifact_issue(
                        queue_compare_severity,
                        "run_execution",
                        f"run execution command does not match {expected_mode} run queue",
                        {
                            "batch_id": batch.get("batch_id", ""),
                            "field": key,
                            "execution_value": command.get(key),
                            "queue_value": expected.get(key),
                            "active_running_job": queue_compare_severity == "warning",
                        },
                    )
                )
        if command.get("status") != "dry_run" or command.get("exit_code") != 0:
            issues.append(
                artifact_issue(
                    "error",
                    "run_execution",
                    "run execution command is not a dry-run record",
                    {"batch_id": batch.get("batch_id", ""), "status": command.get("status"), "exit_code": command.get("exit_code")},
                )
            )

    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "matrix_id": execution.get("matrix_id", ""),
        "queue_mode": execution.get("queue_mode", ""),
        "selected_commands": summary.get("selected_commands", 0),
        "executed_commands": summary.get("executed_commands", 0),
        "pending_commands": summary.get("pending_commands", 0),
        "requires_kimi": gate.get("requires_kimi"),
        "active_running_job": queue_compare_severity == "warning",
        "issue_count": len(issues),
    }, issues


def check_claim_boundary(root: Path, profile: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    report = check_paper_claims.build_claim_report(root, profile=profile)
    issues = [
        artifact_issue(
            item.get("severity", "error"),
            "claim_boundary",
            item.get("message", "claim-boundary issue"),
            {"path": item.get("path", ""), **item.get("detail", {})},
        )
        for item in report.get("issues", [])
    ]
    return report, issues


def check_manuscript_gate(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    report = check_paper_manuscript.build_manuscript_report(root=root)
    issues = [
        artifact_issue(
            item.get("severity", "error"),
            "manuscript",
            item.get("message", "paper manuscript issue"),
            {"manuscript_scope": item.get("scope", ""), **item.get("detail", {})},
        )
        for item in report.get("issues", [])
    ]
    return report, issues


def check_benchmark_card(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    json_path = root / "docs" / "generated_artifacts" / "benchmark_card.json"
    md_path = root / "docs" / "generated_artifacts" / "benchmark_card.md"
    for path in [json_path, md_path]:
        if not path.is_file():
            issues.append(
                artifact_issue(
                    "error",
                    "benchmark_card",
                    "missing benchmark card file",
                    {"path": str(path.relative_to(root)).replace("\\", "/")},
                )
            )
    if not json_path.is_file() or not md_path.is_file():
        return {"ok": False, "issue_count": len(issues), "total_rows": 0}, issues
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(artifact_issue("error", "benchmark_card", "could not parse benchmark_card.json", {"error": str(exc)}))
        return {"ok": False, "issue_count": len(issues), "total_rows": 0}, issues
    markdown = md_path.read_text(encoding="utf-8-sig")
    schema_version = as_int(payload.get("schema_version"))
    if schema_version != 2:
        issues.append(
            artifact_issue(
                "error",
                "benchmark_card",
                "benchmark card schema_version must be 2",
                {"schema_version": payload.get("schema_version")},
            )
        )
    if "Safety Bench" not in str(payload.get("benchmark", {}).get("name", "")):
        issues.append(artifact_issue("error", "benchmark_card", "benchmark card must name Safety Bench"))
    if payload.get("benchmark", {}).get("frame") != "Entry -> Carrier -> Boundary -> Trigger -> Violation":
        issues.append(artifact_issue("error", "benchmark_card", "benchmark card frame is missing or stale"))
    case_counts = payload.get("scope", {}).get("case_counts", {})
    if as_int(case_counts.get("all")) <= 0 or as_int(case_counts.get("core")) <= 0:
        issues.append(artifact_issue("error", "benchmark_card", "benchmark card case counts are missing"))
    baseline = payload.get("current_baseline", {})
    if baseline.get("harness") != "claude":
        issues.append(artifact_issue("error", "benchmark_card", "benchmark card baseline harness must be claude"))
    matrix = payload.get("matrix", {})
    attack_rows = as_int(matrix.get("attack_rows"))
    control_rows = as_int(matrix.get("control_rows"))
    total_rows = as_int(matrix.get("total_rows"))
    if attack_rows <= 0 or control_rows <= 0 or total_rows != attack_rows + control_rows:
        issues.append(
            artifact_issue(
                "error",
                "benchmark_card",
                "benchmark card row totals are inconsistent",
                {"attack_rows": attack_rows, "control_rows": control_rows, "total_rows": total_rows},
            )
        )
    scored_attack_rows = attack_rows
    n_minus_1_attack_rows = 0
    accounted_attack_rows = attack_rows
    protocol_denominator_attack_rows = attack_rows
    scored_control_rows = control_rows
    n_minus_1_control_rows = 0
    accounted_control_rows = control_rows
    protocol_denominator_control_rows = control_rows
    protocol_completion_rate: float | None = None
    model_nonconformance_rate: float | None = None
    conditional_asr_rate: float | None = None
    end_to_end_attack_rate: float | None = None
    attack_asr_eligible_scored_rows = 0
    control_asr_eligible_scored_rows = 0
    if schema_version == 2:
        metric_contract = payload.get("metric_contract", {})
        if not isinstance(metric_contract, dict) or metric_contract.get("n_minus_one_is_progress_node") is not False:
            issues.append(
                artifact_issue(
                    "error",
                    "benchmark_card",
                    "benchmark card metric contract must keep N-1 outside the progress ladder",
                )
            )
        elif (
            metric_contract.get("conditional_asr_denominator")
            != "ASR-eligible N0-N5b scored attack rows"
            or metric_contract.get("end_to_end_denominator")
            != "ASR-eligible scored attack rows plus N-1 attack rows"
        ):
            issues.append(
                artifact_issue(
                    "error",
                    "benchmark_card",
                    "benchmark card metric denominator contract is inconsistent",
                    {"metric_contract": metric_contract},
                )
            )
        if not isinstance(matrix, dict) or matrix.get("protocol_metrics_available") is not True:
            issues.append(
                artifact_issue(
                    "error",
                    "benchmark_card",
                    "benchmark card schema v2 must expose protocol result-class metrics",
                )
            )
        scored_attack_rows = as_int(matrix.get("scored_attack_rows"))
        n_minus_1_attack_rows = as_int(matrix.get("n_minus_1_attack_rows"))
        accounted_attack_rows = as_int(matrix.get("accounted_terminal_attack_rows"))
        protocol_denominator_attack_rows = as_int(
            matrix.get("protocol_denominator_attack_rows")
        )
        scored_control_rows = as_int(matrix.get("scored_control_rows"))
        n_minus_1_control_rows = as_int(matrix.get("n_minus_1_control_rows"))
        accounted_control_rows = as_int(matrix.get("accounted_terminal_control_rows"))
        protocol_denominator_control_rows = as_int(
            matrix.get("protocol_denominator_control_rows")
        )
        count_mismatches = {
            key: {"actual": actual, "expected": expected}
            for key, actual, expected in [
                ("scored_attack_rows", scored_attack_rows, attack_rows),
                (
                    "accounted_terminal_attack_rows",
                    accounted_attack_rows,
                    scored_attack_rows + n_minus_1_attack_rows,
                ),
                ("scored_control_rows", scored_control_rows, control_rows),
                (
                    "accounted_terminal_control_rows",
                    accounted_control_rows,
                    scored_control_rows + n_minus_1_control_rows,
                ),
            ]
            if actual != expected
        }
        if count_mismatches:
            issues.append(
                artifact_issue(
                    "error",
                    "benchmark_card",
                    "benchmark card result-class counts are inconsistent",
                    {"mismatches": count_mismatches},
                )
            )

        results = payload.get("current_results", {})
        controls = payload.get("controls", {})
        if not isinstance(results, dict) or not isinstance(controls, dict):
            issues.append(
                artifact_issue(
                    "error",
                    "benchmark_card",
                    "benchmark card schema v2 result sections are missing",
                )
            )
            results = results if isinstance(results, dict) else {}
            controls = controls if isinstance(controls, dict) else {}
        result_count_expectations = {
            "scored_trials": scored_attack_rows,
            "n_minus_1_trials": n_minus_1_attack_rows,
            "accounted_terminal_trials": accounted_attack_rows,
        }
        control_count_expectations = {
            "scored_trials": scored_control_rows,
            "n_minus_1_trials": n_minus_1_control_rows,
            "accounted_terminal_trials": accounted_control_rows,
        }
        for section_name, section, expectations in [
            ("current_results", results, result_count_expectations),
            ("controls", controls, control_count_expectations),
        ]:
            if section.get("protocol_metrics_available") is not True:
                issues.append(
                    artifact_issue(
                        "error",
                        "benchmark_card",
                        "benchmark card protocol metrics are unavailable",
                        {"section": section_name},
                    )
                )
            mismatches = {
                key: {"actual": section.get(key), "expected": expected}
                for key, expected in expectations.items()
                if as_int(section.get(key)) != expected
            }
            if mismatches:
                issues.append(
                    artifact_issue(
                        "error",
                        "benchmark_card",
                        "benchmark card result section counts are inconsistent",
                        {"section": section_name, "mismatches": mismatches},
                    )
                )

        protocol_completion_rate = optional_float(
            results.get("protocol_completion_rate")
        )
        model_nonconformance_rate = optional_float(
            results.get("model_nonconformance_rate")
        )
        conditional_asr_rate = optional_float(results.get("conditional_asr_rate"))
        end_to_end_attack_rate = optional_float(
            results.get("end_to_end_attack_rate")
        )
        attack_success_rows = as_int(results.get("attack_success_rows"))
        attack_asr_eligible_scored_rows = as_int(
            results.get("asr_eligible_scored_trials")
        )
        control_asr_eligible_scored_rows = as_int(
            controls.get("asr_eligible_scored_trials")
        )
        protocol_count_mismatches = {
            key: {"actual": actual, "expected": expected}
            for key, actual, expected in [
                (
                    "protocol_denominator_attack_rows",
                    protocol_denominator_attack_rows,
                    attack_asr_eligible_scored_rows + n_minus_1_attack_rows,
                ),
                (
                    "current_results.protocol_denominator_trials",
                    as_int(results.get("protocol_denominator_trials")),
                    protocol_denominator_attack_rows,
                ),
                (
                    "protocol_denominator_control_rows",
                    protocol_denominator_control_rows,
                    control_asr_eligible_scored_rows + n_minus_1_control_rows,
                ),
                (
                    "controls.protocol_denominator_trials",
                    as_int(controls.get("protocol_denominator_trials")),
                    protocol_denominator_control_rows,
                ),
            ]
            if actual != expected
        }
        if protocol_count_mismatches:
            issues.append(
                artifact_issue(
                    "error",
                    "benchmark_card",
                    "benchmark card protocol denominator counts are inconsistent",
                    {"mismatches": protocol_count_mismatches},
                )
            )
        rate_expectations = [
            (
                "protocol_completion_rate",
                results.get("protocol_completion_rate"),
                attack_asr_eligible_scored_rows,
                protocol_denominator_attack_rows,
            ),
            (
                "model_nonconformance_rate",
                results.get("model_nonconformance_rate"),
                n_minus_1_attack_rows,
                protocol_denominator_attack_rows,
            ),
            (
                "control_protocol_completion_rate",
                controls.get("protocol_completion_rate"),
                control_asr_eligible_scored_rows,
                protocol_denominator_control_rows,
            ),
            (
                "control_model_nonconformance_rate",
                controls.get("model_nonconformance_rate"),
                n_minus_1_control_rows,
                protocol_denominator_control_rows,
            ),
        ]
        bad_rates = {
            name: {
                "actual": value,
                "expected": successes / trials if trials else None,
            }
            for name, value, successes, trials in rate_expectations
            if not rate_matches(value, successes, trials)
        }
        if bad_rates:
            issues.append(
                artifact_issue(
                    "error",
                    "benchmark_card",
                    "benchmark card result-class rates are inconsistent",
                    {"mismatches": bad_rates},
                )
            )
        conditional_rate_issues: dict[str, Any] = {}
        for name, section, successes, trials, max_trials in [
            (
                "conditional_asr_rate",
                results,
                attack_success_rows,
                attack_asr_eligible_scored_rows,
                scored_attack_rows,
            ),
            (
                "control_conditional_violation_rate",
                controls,
                as_int(controls.get("attack_success_rows")),
                control_asr_eligible_scored_rows,
                scored_control_rows,
            ),
        ]:
            field = (
                "conditional_asr_rate"
                if name == "conditional_asr_rate"
                else "conditional_violation_rate"
            )
            valid = (
                "asr_eligible_scored_trials" in section
                and 0 <= successes <= trials <= max_trials
                and rate_matches(section.get(field), successes, trials)
            )
            if not valid:
                conditional_rate_issues[name] = {
                    "successes": successes,
                    "asr_eligible_scored_trials": section.get(
                        "asr_eligible_scored_trials"
                    ),
                    "scored_trials": max_trials,
                    "rate": section.get(field),
                }
        if conditional_rate_issues:
            issues.append(
                artifact_issue(
                    "error",
                    "benchmark_card",
                    "benchmark card conditional rates are inconsistent with ASR-eligible rows",
                    {"rates": conditional_rate_issues},
                )
            )
        inferred_rate_issues: dict[str, Any] = {}
        for name, value, successes, denominator in [
            (
                "end_to_end_attack_rate",
                results.get("end_to_end_attack_rate"),
                attack_success_rows,
                protocol_denominator_attack_rows,
            ),
            (
                "control_end_to_end_violation_rate",
                controls.get("end_to_end_violation_rate"),
                as_int(controls.get("attack_success_rows")),
                protocol_denominator_control_rows,
            ),
        ]:
            valid = rate_matches(value, successes, denominator)
            if not valid:
                inferred_rate_issues[name] = value
        if inferred_rate_issues:
            issues.append(
                artifact_issue(
                    "error",
                    "benchmark_card",
                    "benchmark card conditional/end-to-end rates have no valid denominator",
                    {"rates": inferred_rate_issues},
                )
            )
        if attack_success_rows > attack_asr_eligible_scored_rows:
            issues.append(
                artifact_issue(
                    "error",
                    "benchmark_card",
                    "benchmark card attack successes exceed ASR-eligible scored rows",
                )
            )
        if (
            as_int(controls.get("attack_success_rows"))
            > control_asr_eligible_scored_rows
        ):
            issues.append(
                artifact_issue(
                    "error",
                    "benchmark_card",
                    "benchmark card control violations exceed ASR-eligible scored rows",
                )
            )
    for phrase in [
        "# Safety Bench Benchmark Card",
        "Entry -> Carrier -> Boundary -> Trigger -> Violation",
        "Claude Code + Kimi K2.6",
        "Public Artifact Boundary",
    ]:
        if phrase not in markdown:
            issues.append(
                artifact_issue(
                    "error",
                    "benchmark_card",
                    "benchmark card markdown is missing required phrase",
                    {"phrase": phrase},
                )
            )
    if schema_version == 2:
        for phrase in [
            "Scored attack rows",
            "Attack ASR-eligible scored rows",
            "Attack N-1 rows",
            "Accounted terminal attack rows",
            "Attack protocol denominator (S+M)",
            "Protocol completion rate",
            "Model nonconformance rate",
            "Conditional ASR",
            "End-to-end attack rate",
            "control_asr_eligible_scored_rows",
            "control_protocol_denominator_rows",
        ]:
            if phrase not in markdown:
                issues.append(
                    artifact_issue(
                        "error",
                        "benchmark_card",
                        "benchmark card markdown is missing schema-v2 metric",
                        {"phrase": phrase},
                    )
                )
    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "issue_count": len(issues),
        "attack_rows": attack_rows,
        "control_rows": control_rows,
        "total_rows": total_rows,
        "scored_attack_rows": scored_attack_rows,
        "n_minus_1_attack_rows": n_minus_1_attack_rows,
        "accounted_terminal_attack_rows": accounted_attack_rows,
        "protocol_denominator_attack_rows": protocol_denominator_attack_rows,
        "scored_control_rows": scored_control_rows,
        "n_minus_1_control_rows": n_minus_1_control_rows,
        "accounted_terminal_control_rows": accounted_control_rows,
        "protocol_denominator_control_rows": protocol_denominator_control_rows,
        "protocol_completion_rate": protocol_completion_rate,
        "model_nonconformance_rate": model_nonconformance_rate,
        "conditional_asr_rate": conditional_asr_rate,
        "end_to_end_attack_rate": end_to_end_attack_rate,
        "attack_asr_eligible_scored_rows": attack_asr_eligible_scored_rows,
        "control_asr_eligible_scored_rows": control_asr_eligible_scored_rows,
        "baseline": f"{baseline.get('runtime', '')} + {baseline.get('model', '')}".strip(" +"),
    }, issues


def check_supplementary_appendix(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    json_path = root / "docs" / "generated_artifacts" / "paper_supplementary_appendix.json"
    md_path = root / "docs" / "generated_artifacts" / "paper_supplementary_appendix.md"
    tex_path = root / "docs" / "generated_artifacts" / "paper_supplementary_appendix.tex"
    for path in [json_path, md_path, tex_path]:
        if not path.is_file():
            issues.append(
                artifact_issue(
                    "error",
                    "supplementary_appendix",
                    "missing supplementary appendix file",
                    {"path": str(path.relative_to(root)).replace("\\", "/")},
                )
            )
    if not json_path.is_file() or not md_path.is_file() or not tex_path.is_file():
        return {"ok": False, "issue_count": len(issues), "family_rows": 0, "case_rows": 0}, issues
    try:
        appendix = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        issues.append(
            artifact_issue(
                "error",
                "supplementary_appendix",
                "supplementary appendix JSON is invalid",
                {"error": str(exc)},
            )
        )
        appendix = {}
    if not isinstance(appendix, dict):
        issues.append(
            artifact_issue(
                "error",
                "supplementary_appendix",
                "supplementary appendix JSON root must be an object",
            )
        )
        appendix = {}

    contract = appendix.get("metric_contract", {})
    matrix = appendix.get("matrix", {})
    contract = contract if isinstance(contract, dict) else {}
    matrix = matrix if isinstance(matrix, dict) else {}
    if appendix.get("schema_version") != 2:
        issues.append(artifact_issue("error", "supplementary_appendix", "supplementary appendix schema_version must be 2"))
    for key, expected in {
        "n_minus_one_is_progress_node": False,
        "protocol_completion_rate": "S/D",
        "model_nonconformance_rate": "M/D",
        "conditional_asr": "A/S",
        "end_to_end_attack_rate": "A/D",
    }.items():
        if contract.get(key) != expected:
            issues.append(
                artifact_issue(
                    "error",
                    "supplementary_appendix",
                    "supplementary appendix metric contract is inconsistent",
                    {"field": key, "expected": expected, "actual": contract.get(key)},
                )
            )

    required_matrix_counts = [
        "attack_scored_rows",
        "attack_asr_eligible_scored_rows",
        "attack_n_minus_1_rows",
        "attack_accounted_terminal_rows",
        "attack_protocol_denominator_rows",
        "control_scored_rows",
        "control_asr_eligible_scored_rows",
        "control_n_minus_1_rows",
        "control_accounted_terminal_rows",
        "control_protocol_denominator_rows",
        "attack_success_rows",
        "confirmed_rows",
        "total_rows",
    ]
    invalid_count_fields = [
        key for key in required_matrix_counts if not is_nonnegative_int(matrix.get(key))
    ]
    if invalid_count_fields:
        issues.append(
            artifact_issue(
                "error",
                "supplementary_appendix",
                "supplementary appendix matrix counts must be explicit non-negative integers",
                {"fields": invalid_count_fields},
            )
        )
    else:
        all_attack = matrix["attack_scored_rows"]
        attack_s = matrix["attack_asr_eligible_scored_rows"]
        attack_m = matrix["attack_n_minus_1_rows"]
        attack_t = matrix["attack_accounted_terminal_rows"]
        attack_d = matrix["attack_protocol_denominator_rows"]
        all_control = matrix["control_scored_rows"]
        control_s = matrix["control_asr_eligible_scored_rows"]
        control_m = matrix["control_n_minus_1_rows"]
        control_t = matrix["control_accounted_terminal_rows"]
        control_d = matrix["control_protocol_denominator_rows"]
        attack_a = matrix["attack_success_rows"]
        confirmed = matrix["confirmed_rows"]
        invariants = {
            "attack S <= all scored": attack_s <= all_attack,
            "attack T = all scored + M": attack_t == all_attack + attack_m,
            "attack D = S + M": attack_d == attack_s + attack_m,
            "attack A <= S": attack_a <= attack_s,
            "attack confirmed <= S": confirmed <= attack_s,
            "control S <= all scored": control_s <= all_control,
            "control T = all scored + M": control_t == all_control + control_m,
            "control D = S + M": control_d == control_s + control_m,
            "total rows = attack all scored + control all scored": matrix["total_rows"] == all_attack + all_control,
            "protocol completion = S/D": rate_matches(matrix.get("protocol_completion_rate"), attack_s, attack_d),
            "model nonconformance = M/D": rate_matches(matrix.get("model_nonconformance_rate"), attack_m, attack_d),
            "conditional ASR = A/S": rate_matches(matrix.get("conditional_asr"), attack_a, attack_s),
            "end-to-end attack = A/D": rate_matches(matrix.get("end_to_end_attack_rate"), attack_a, attack_d),
        }
        for invariant, ok in invariants.items():
            if not ok:
                issues.append(
                    artifact_issue(
                        "error",
                        "supplementary_appendix",
                        "supplementary appendix measurement invariant failed",
                        {"invariant": invariant},
                    )
                )

        progress = appendix.get("attack_progress", {})
        progress_nodes = ["N0", "N1", "N2", "N3", "N4", "N5a", "N5b"]
        if not isinstance(progress, dict) or any(
            not is_nonnegative_int(progress.get(node)) for node in progress_nodes
        ) or sum(progress.get(node, 0) for node in progress_nodes) != attack_s:
            issues.append(
                artifact_issue(
                    "error",
                    "supplementary_appendix",
                    "attack progress distribution must contain exactly S rows",
                    {"expected": attack_s},
                )
            )

    def validate_protocol_rows(rows: Any, *, kind: str) -> None:
        if not isinstance(rows, list):
            issues.append(artifact_issue("error", "supplementary_appendix", f"{kind} rows must be a list"))
            return
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                issues.append(artifact_issue("error", "supplementary_appendix", f"{kind} row must be an object", {"index": index}))
                continue
            if kind == "control":
                keys = {
                    "all": "scored_trials", "S": "asr_eligible_scored_trials", "M": "n_minus_1_trials",
                    "T": "accounted_terminal_trials", "D": "protocol_denominator_trials", "A": "attack_success",
                }
                rate_keys = ("protocol_completion_rate", "model_nonconformance_rate", "conditional_violation_rate", "end_to_end_violation_rate")
            else:
                keys = {
                    "all": "completed_trials", "S": "asr_eligible_scored_trials", "M": "n_minus_1_trials",
                    "T": "accounted_terminal_trials", "D": "protocol_denominator_trials", "A": "attack_success_trials",
                }
                rate_keys = ("protocol_completion_trial_rate", "model_nonconformance_trial_rate", "attack_success_trial_rate", "end_to_end_attack_trial_rate")
            if any(not is_nonnegative_int(row.get(key)) for key in keys.values()):
                issues.append(artifact_issue("error", "supplementary_appendix", f"{kind} protocol counts must be explicit non-negative integers", {"index": index}))
                continue
            all_scored, s, m, t, d, a = (row[keys[name]] for name in ("all", "S", "M", "T", "D", "A"))
            valid = all((s <= all_scored, t == all_scored + m, d == s + m, a <= s))
            expected_rates = ((s, d), (m, d), (a, s), (a, d))
            valid = valid and all(
                rate_matches(row.get(rate_key), numerator, denominator)
                for rate_key, (numerator, denominator) in zip(rate_keys, expected_rates)
            )
            if not valid:
                issues.append(artifact_issue("error", "supplementary_appendix", f"{kind} row violates T/S/M/D/A accounting", {"index": index}))

    validate_protocol_rows(appendix.get("controls"), kind="control")
    validate_protocol_rows(appendix.get("families"), kind="family")

    markdown = md_path.read_text(encoding="utf-8-sig")
    tex = tex_path.read_text(encoding="utf-8-sig")
    if appendix:
        try:
            expected_markdown = generate_paper_appendix.render_markdown(appendix)
            expected_tex = generate_paper_appendix.render_tex(appendix)
        except (KeyError, TypeError, ValueError) as exc:
            issues.append(
                artifact_issue(
                    "error",
                    "supplementary_appendix",
                    "supplementary appendix JSON cannot render its published views",
                    {"error": str(exc)},
                )
            )
        else:
            if markdown != expected_markdown:
                issues.append(
                    artifact_issue(
                        "error",
                        "supplementary_appendix",
                        "supplementary appendix Markdown does not match its JSON source",
                    )
                )
            if tex != expected_tex:
                issues.append(
                    artifact_issue(
                        "error",
                        "supplementary_appendix",
                        "supplementary appendix TeX does not match its JSON source",
                    )
                )
    for phrase in [
        "# Safety Bench Supplementary Appendix",
        "Measurement contract:",
        "Rates are S/D, M/D, A/S, and A/D.",
        "Matrix Summary",
        "Attack ASR-eligible scored rows (S)",
        "Attack N-1 rows",
        "Attack coverage-accounted rows (T)",
        "Attack protocol denominator (D=S+M)",
        "Protocol completion rate",
        "Model nonconformance rate",
        "Conditional ASR",
        "End-to-end attack rate",
        "Control Summary",
        "| Control | All Scored | S | M | T | D |",
        "Family-Level Results",
        "| Suite | Family | Scored Cases | All Scored | S | M | T | D |",
        "Successful Or Confirmed Cases",
        "Success (A/S)",
        "Main Paper",
        "appendix_only_successful_cases",
        "Public Artifact Boundary",
    ]:
        if phrase not in markdown:
            issues.append(
                artifact_issue(
                    "error",
                    "supplementary_appendix",
                    "supplementary appendix markdown is missing required phrase",
                    {"phrase": phrase},
                )
            )
    for phrase in [
        r"\section{Safety Bench Supplementary Appendix}",
        r"\paragraph{Measurement contract.}",
        r"$D=S+M$",
        r"$S/D$, $M/D$, $A/S$, and $A/D$",
        r"\subsection{Matrix Summary}",
        r"Attack ASR-eligible scored rows (S)",
        r"Attack coverage-accounted rows (T)",
        r"Attack protocol denominator (D)",
        r"\subsection{Control Summary}",
        "Control & All & S & M & T & D & S/D & M/D & A/S & A/D",
        r"\subsection{Family-Level Results}",
        r"\subsection{Successful Or Confirmed Cases}",
        r"\begin{tabular}",
    ]:
        if phrase not in tex:
            issues.append(
                artifact_issue(
                    "error",
                    "supplementary_appendix",
                    "supplementary appendix TeX is missing required phrase",
                    {"phrase": phrase},
                )
            )
    family_rows = len(re.findall(r"^\| [^|\n]+ \| [^|\n]+ \| \d+/\d+ \|", markdown, flags=re.MULTILINE))
    case_rows = len(re.findall(r"^\| [^|\n]+ \| [^|\n]+ \| `active/", markdown, flags=re.MULTILINE))
    if family_rows <= 0:
        issues.append(artifact_issue("error", "supplementary_appendix", "supplementary appendix has no family rows"))
    if case_rows <= 0:
        issues.append(artifact_issue("error", "supplementary_appendix", "supplementary appendix has no successful case rows"))
    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "issue_count": len(issues),
        "family_rows": family_rows,
        "case_rows": case_rows,
    }, issues


def check_oracle_coverage(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    json_path = root / "docs" / "generated_artifacts" / "paper_oracle_coverage.json"
    md_path = root / "docs" / "generated_artifacts" / "paper_oracle_coverage.md"
    for path in [json_path, md_path]:
        if not path.is_file():
            issues.append(
                artifact_issue(
                    "error",
                    "oracle_coverage",
                    "missing oracle coverage file",
                    {"path": str(path.relative_to(root)).replace("\\", "/")},
                )
            )
    if not json_path.is_file() or not md_path.is_file():
        return {"ok": False, "issue_count": len(issues), "case_count": 0, "attack_rows": 0}, issues
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(
            artifact_issue("error", "oracle_coverage", "could not parse paper_oracle_coverage.json", {"error": str(exc)})
        )
        return {"ok": False, "issue_count": len(issues), "case_count": 0, "attack_rows": 0}, issues
    markdown = md_path.read_text(encoding="utf-8-sig")
    schema_version = as_int(payload.get("schema_version"))
    if schema_version not in {1, 2}:
        issues.append(
            artifact_issue(
                "error",
                "oracle_coverage",
                "oracle coverage schema_version must be 1 or 2",
                {"schema_version": payload.get("schema_version")},
            )
        )
    if payload.get("case_set") != "core":
        issues.append(
            artifact_issue(
                "error",
                "oracle_coverage",
                "oracle coverage must describe the core case set",
                {"case_set": payload.get("case_set")},
            )
        )
    design = payload.get("design_time", {}) if isinstance(payload.get("design_time"), dict) else {}
    observed = payload.get("observed_baseline", {}) if isinstance(payload.get("observed_baseline"), dict) else {}
    attack = observed.get("attack", {}) if isinstance(observed.get("attack"), dict) else {}
    control = observed.get("control", {}) if isinstance(observed.get("control"), dict) else {}
    case_count = as_int(design.get("case_count"))
    attack_rows = as_int(attack.get("row_count"))
    control_rows = as_int(control.get("row_count"))
    if case_count <= 0:
        issues.append(artifact_issue("error", "oracle_coverage", "oracle coverage has no design-time cases"))
    strengths = design.get("oracle_strength_counts", {}) if isinstance(design.get("oracle_strength_counts"), dict) else {}
    if not any(as_int(strengths.get(key)) > 0 for key in ["hard_trace_oracle", "propagation_only", "soft_semantic_oracle"]):
        issues.append(artifact_issue("error", "oracle_coverage", "oracle strength counts are missing"))
    if as_int(design.get("cases_with_declared_oracles")) <= 0:
        issues.append(artifact_issue("error", "oracle_coverage", "declared oracle coverage is empty"))
    if attack_rows <= 0 or control_rows <= 0:
        issues.append(
            artifact_issue(
                "error",
                "oracle_coverage",
                "observed oracle coverage row counts are missing",
                {"attack_rows": attack_rows, "control_rows": control_rows},
            )
        )
    if as_int(attack.get("rows_with_any_oracle")) <= 0:
        issues.append(artifact_issue("error", "oracle_coverage", "attack observed oracle hits are empty"))
    if schema_version == 2:
        scope = payload.get("scope", {})
        scope = scope if isinstance(scope, dict) else {}
        accounted_dirs = scope.get("accounted_observed_attack_case_dirs", [])
        unaccounted_dirs = scope.get("unaccounted_observed_attack_case_dirs", [])
        raw_dirs = scope.get("raw_observed_attack_case_dirs", [])
        missing_dirs = scope.get("missing_observed_cases", [])
        accounted_dirs = accounted_dirs if isinstance(accounted_dirs, list) else []
        unaccounted_dirs = unaccounted_dirs if isinstance(unaccounted_dirs, list) else []
        raw_dirs = raw_dirs if isinstance(raw_dirs, list) else []
        missing_dirs = missing_dirs if isinstance(missing_dirs, list) else []
        scope_mismatches = {
            key: {"actual": actual, "expected": expected}
            for key, actual, expected in [
                (
                    "observed_attack_cases",
                    as_int(scope.get("observed_attack_cases")),
                    len(accounted_dirs),
                ),
                (
                    "accounted_observed_attack_cases",
                    as_int(scope.get("accounted_observed_attack_cases")),
                    len(accounted_dirs),
                ),
                (
                    "unaccounted_observed_attack_cases",
                    as_int(scope.get("unaccounted_observed_attack_cases")),
                    len(unaccounted_dirs),
                ),
                (
                    "raw_observed_attack_cases",
                    as_int(scope.get("raw_observed_attack_cases")),
                    len(raw_dirs),
                ),
                (
                    "accounted_plus_missing_cases",
                    len(accounted_dirs) + len(missing_dirs),
                    as_int(scope.get("case_set_cases")),
                ),
            ]
            if actual != expected
        }
        if set(raw_dirs) != set(accounted_dirs) | set(unaccounted_dirs):
            scope_mismatches["raw_observed_attack_case_dirs"] = {
                "actual": sorted(set(raw_dirs)),
                "expected": sorted(set(accounted_dirs) | set(unaccounted_dirs)),
            }
        if scope_mismatches:
            issues.append(
                artifact_issue(
                    "error",
                    "oracle_coverage",
                    "oracle coverage observed-case scope accounting is inconsistent",
                    {"mismatches": scope_mismatches},
                )
            )
        for run_kind, row in [("attack", attack), ("control", control)]:
            observed_rows = as_int(row.get("observed_rows"))
            scored_rows = as_int(row.get("scored_rows"))
            protocol_rows = as_int(row.get("model_protocol_terminal_rows"))
            n_minus_one_rows = as_int(row.get("n_minus_1_rows"))
            accounted_rows = as_int(row.get("accounted_terminal_rows"))
            protocol_denominator_rows = as_int(
                row.get("protocol_denominator_rows")
            )
            unaccounted_rows = as_int(row.get("unaccounted_rows"))
            asr_rows = as_int(row.get("asr_eligible_scored_rows"))
            successes = as_int(row.get("attack_success_rows"))
            asr_successes = as_int(row.get("asr_attack_success_rows"))
            confirmed = as_int(row.get("confirmed_rows"))
            factual_successes = as_int(row.get("factual_attack_success_rows"))
            factual_confirmed = as_int(row.get("factual_confirmed_rows"))
            factual_oracle_rows = as_int(row.get("factual_rows_with_any_oracle"))
            missing_factual_fields = [
                field
                for field in (
                    "factual_attack_success_rows",
                    "factual_confirmed_rows",
                    "factual_rows_with_any_oracle",
                    "factual_scored_oracle_counts",
                )
                if field not in row
            ]
            if missing_factual_fields:
                issues.append(
                    artifact_issue(
                        "error",
                        "oracle_coverage",
                        "schema-v2 oracle coverage is missing factual all-scored diagnostics",
                        {"run_kind": run_kind, "fields": missing_factual_fields},
                    )
                )
            count_mismatches = {
                key: {"actual": actual, "expected": expected}
                for key, actual, expected in [
                    ("observed_rows", observed_rows, as_int(row.get("row_count"))),
                    ("n_minus_1_rows", n_minus_one_rows, protocol_rows),
                    (
                        "accounted_terminal_rows",
                        accounted_rows,
                        scored_rows + protocol_rows,
                    ),
                    (
                        "protocol_denominator_rows",
                        protocol_denominator_rows,
                        asr_rows + protocol_rows,
                    ),
                    (
                        "row_partition",
                        observed_rows,
                        accounted_rows + unaccounted_rows,
                    ),
                ]
                if actual != expected
            }
            if count_mismatches:
                issues.append(
                    artifact_issue(
                        "error",
                        "oracle_coverage",
                        "observed result-class counts are inconsistent",
                        {"run_kind": run_kind, "mismatches": count_mismatches},
                    )
                )
            if (
                min(
                    observed_rows,
                    scored_rows,
                    protocol_rows,
                    n_minus_one_rows,
                    accounted_rows,
                    protocol_denominator_rows,
                    unaccounted_rows,
                    asr_rows,
                    successes,
                    asr_successes,
                    confirmed,
                    factual_successes,
                    factual_confirmed,
                    factual_oracle_rows,
                )
                < 0
                or asr_rows > scored_rows
                or successes > asr_rows
                or successes != asr_successes
                or asr_successes > asr_rows
                or confirmed > asr_rows
                or successes > factual_successes
                or factual_successes > scored_rows
                or confirmed > factual_confirmed
                or factual_confirmed > scored_rows
                or as_int(row.get("rows_with_any_oracle")) > asr_rows
                or as_int(row.get("rows_with_any_oracle")) > factual_oracle_rows
                or factual_oracle_rows > scored_rows
                or as_int(row.get("model_protocol_rows_with_any_oracle"))
                > protocol_rows
            ):
                issues.append(
                    artifact_issue(
                        "error",
                        "oracle_coverage",
                        "observed oracle/outcome counts exceed their result-class denominators",
                        {"run_kind": run_kind},
                    )
                )

            def oracle_count_map(value: Any, *, denominator: int, label: str) -> dict[str, int]:
                counts: dict[str, int] = {}
                if not isinstance(value, list):
                    issues.append(
                        artifact_issue(
                            "error",
                            "oracle_coverage",
                            "oracle count diagnostics must be a list",
                            {"run_kind": run_kind, "field": label},
                        )
                    )
                    return counts
                for item in value:
                    if not isinstance(item, dict) or not isinstance(item.get("oracle"), str) or not is_nonnegative_int(item.get("count")) or item["count"] > denominator:
                        issues.append(
                            artifact_issue(
                                "error",
                                "oracle_coverage",
                                "oracle count exceeds its row denominator",
                                {"run_kind": run_kind, "field": label},
                            )
                        )
                        continue
                    counts[item["oracle"]] = item["count"]
                return counts

            formal_oracle_counts = oracle_count_map(
                row.get("observed_oracle_counts"),
                denominator=asr_rows,
                label="observed_oracle_counts",
            )
            factual_oracle_counts = oracle_count_map(
                row.get("factual_scored_oracle_counts"),
                denominator=scored_rows,
                label="factual_scored_oracle_counts",
            )
            if any(
                count > factual_oracle_counts.get(oracle, -1)
                for oracle, count in formal_oracle_counts.items()
            ):
                issues.append(
                    artifact_issue(
                        "error",
                        "oracle_coverage",
                        "formal oracle counts cannot exceed factual all-scored counts",
                        {"run_kind": run_kind},
                    )
                )
            bad_rates = {
                field: row.get(field)
                for field, numerator, denominator in [
                    (
                        "protocol_completion_rate",
                        asr_rows,
                        protocol_denominator_rows,
                    ),
                    (
                        "model_nonconformance_rate",
                        protocol_rows,
                        protocol_denominator_rows,
                    ),
                    ("conditional_asr", asr_successes, asr_rows),
                    (
                        "end_to_end_attack_rate",
                        asr_successes,
                        protocol_denominator_rows,
                    ),
                ]
                if not rate_matches(row.get(field), numerator, denominator)
            }
            if bad_rates:
                issues.append(
                    artifact_issue(
                        "error",
                        "oracle_coverage",
                        "observed protocol/attack rates are inconsistent",
                        {"run_kind": run_kind, "rates": bad_rates},
                    )
                )
            for family in row.get("by_family", []):
                if not isinstance(family, dict):
                    issues.append(
                        artifact_issue(
                            "error",
                            "oracle_coverage",
                            "observed family row must be an object",
                            {"run_kind": run_kind},
                        )
                    )
                    continue
                family_scored = as_int(family.get("scored_rows"))
                family_protocol = as_int(
                    family.get("model_protocol_terminal_rows")
                )
                family_s = as_int(family.get("asr_eligible_scored_rows"))
                family_t = as_int(family.get("accounted_terminal_rows"))
                family_d = as_int(family.get("protocol_denominator_rows"))
                family_a = as_int(family.get("attack_success_rows"))
                family_asr_a = as_int(family.get("asr_attack_success_rows"))
                family_confirmed = as_int(family.get("confirmed_rows"))
                family_oracle_rows = as_int(family.get("rows_with_any_oracle"))
                family_factual_a = as_int(family.get("factual_attack_success_rows"))
                family_factual_confirmed = as_int(family.get("factual_confirmed_rows"))
                family_factual_oracle_rows = as_int(family.get("factual_rows_with_any_oracle"))
                family_missing_factual = any(
                    field not in family
                    for field in (
                        "factual_attack_success_rows",
                        "factual_confirmed_rows",
                        "factual_rows_with_any_oracle",
                    )
                )
                family_bad_counts = (
                    family_missing_factual
                    or
                    min(
                        family_scored,
                        family_protocol,
                        family_s,
                        family_t,
                        family_d,
                        family_a,
                        family_asr_a,
                        family_confirmed,
                        family_oracle_rows,
                        family_factual_a,
                        family_factual_confirmed,
                        family_factual_oracle_rows,
                    )
                    < 0
                    or family_s > family_scored
                    or family_t != family_scored + family_protocol
                    or family_d != family_s + family_protocol
                    or family_a != family_asr_a
                    or family_a > family_s
                    or family_confirmed > family_s
                    or family_oracle_rows > family_s
                    or family_a > family_factual_a
                    or family_factual_a > family_scored
                    or family_confirmed > family_factual_confirmed
                    or family_factual_confirmed > family_scored
                    or family_oracle_rows > family_factual_oracle_rows
                    or family_factual_oracle_rows > family_scored
                )
                family_bad_rates = any(
                    not rate_matches(family.get(field), numerator, denominator)
                    for field, numerator, denominator in [
                        ("protocol_completion_rate", family_s, family_d),
                        (
                            "model_nonconformance_rate",
                            family_protocol,
                            family_d,
                        ),
                        ("conditional_asr", family_a, family_s),
                        ("end_to_end_attack_rate", family_a, family_d),
                    ]
                )
                if family_bad_counts or family_bad_rates:
                    issues.append(
                        artifact_issue(
                            "error",
                            "oracle_coverage",
                            "observed family metric contract is inconsistent",
                            {
                                "run_kind": run_kind,
                                "suite": family.get("suite"),
                                "paper_family": family.get("paper_family"),
                            },
                        )
                    )
    if not design.get("by_suite"):
        issues.append(artifact_issue("error", "oracle_coverage", "oracle coverage has no suite rows"))
    if not attack.get("by_family"):
        issues.append(artifact_issue("error", "oracle_coverage", "oracle coverage has no observed family rows"))
    for phrase in [
        "# Safety Bench Oracle Coverage Report",
        "Design-Time Oracle Coverage",
        "Oracle Strength By Suite",
        "Observed Baseline Oracle Coverage",
        "Public Artifact Boundary",
    ]:
        if phrase not in markdown:
            issues.append(
                artifact_issue(
                    "error",
                    "oracle_coverage",
                    "oracle coverage markdown is missing required phrase",
                    {"phrase": phrase},
                )
            )
    if schema_version == 2:
        for phrase in [
            "Coverage Accounted (T) | Protocol Denominator (D=S+M)",
            "Conditional ASR/Violation",
            "Protocol Completion",
            "Model Nonconformance",
            "End-to-End",
        ]:
            if phrase not in markdown:
                issues.append(
                    artifact_issue(
                        "error",
                        "oracle_coverage",
                        "oracle coverage markdown is missing schema-v2 accounting",
                        {"phrase": phrase},
                    )
                )
    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "issue_count": len(issues),
        "case_count": case_count,
        "attack_rows": attack_rows,
        "control_rows": control_rows,
        "attack_scored_rows": as_int(attack.get("scored_rows", attack_rows)),
        "attack_n_minus_1_rows": as_int(attack.get("n_minus_1_rows")),
        "attack_accounted_terminal_rows": as_int(
            attack.get("accounted_terminal_rows", attack_rows)
        ),
        "hard_trace_cases": as_int(strengths.get("hard_trace_oracle")),
        "propagation_only_cases": as_int(strengths.get("propagation_only")),
        "soft_semantic_cases": as_int(strengths.get("soft_semantic_oracle")),
    }, issues


def check_threat_model_card(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    json_path = root / "docs" / "generated_artifacts" / "paper_threat_model_card.json"
    md_path = root / "docs" / "generated_artifacts" / "paper_threat_model_card.md"
    for path in [json_path, md_path]:
        if not path.is_file():
            issues.append(
                artifact_issue(
                    "error",
                    "threat_model_card",
                    "missing threat model card file",
                    {"path": str(path.relative_to(root)).replace("\\", "/")},
                )
            )
    if not json_path.is_file() or not md_path.is_file():
        return {"ok": False, "issue_count": len(issues), "case_count": 0}, issues
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(
            artifact_issue(
                "error",
                "threat_model_card",
                "could not parse paper_threat_model_card.json",
                {"error": str(exc)},
            )
        )
        return {"ok": False, "issue_count": len(issues), "case_count": 0}, issues
    markdown = md_path.read_text(encoding="utf-8-sig")
    if payload.get("schema_version") != 1:
        issues.append(artifact_issue("error", "threat_model_card", "threat model card schema_version must be 1"))
    benchmark = payload.get("benchmark", {}) if isinstance(payload.get("benchmark"), dict) else {}
    if benchmark.get("frame") != "Entry -> Carrier -> Boundary -> Trigger -> Violation":
        issues.append(artifact_issue("error", "threat_model_card", "threat model card frame is missing or stale"))
    scope = payload.get("scope", {}) if isinstance(payload.get("scope"), dict) else {}
    case_count = as_int(scope.get("case_count"))
    active_case_count = as_int(scope.get("active_case_count"))
    if scope.get("case_set") != "all" or case_count <= 0 or active_case_count <= 0 or case_count != active_case_count:
        issues.append(
            artifact_issue(
                "error",
                "threat_model_card",
                "threat model card must cover the full active suite",
                {"case_set": scope.get("case_set"), "case_count": case_count, "active_case_count": active_case_count},
            )
        )
    coverage = payload.get("coverage", {}) if isinstance(payload.get("coverage"), dict) else {}
    case_sets = coverage.get("case_sets", []) if isinstance(coverage.get("case_sets"), list) else []
    case_set_names = {str(row.get("case_set") or "") for row in case_sets if isinstance(row, dict)}
    for expected in ["core", "extended", "exploratory", "all"]:
        if expected not in case_set_names:
            issues.append(
                artifact_issue(
                    "error",
                    "threat_model_card",
                    "threat model card is missing case-set coverage row",
                    {"case_set": expected},
                )
            )
    frame_dimensions = coverage.get("frame_dimensions", {}) if isinstance(coverage.get("frame_dimensions"), dict) else {}
    missing_by_dimension: dict[str, int] = {}
    for dimension in ["entry", "carrier", "boundary", "trigger", "violation", "recovery"]:
        row = frame_dimensions.get(dimension, {}) if isinstance(frame_dimensions.get(dimension), dict) else {}
        if as_int(row.get("unique_values")) <= 0:
            issues.append(
                artifact_issue(
                    "error",
                    "threat_model_card",
                    "threat model card frame dimension has no values",
                    {"dimension": dimension},
                )
            )
        missing_cases = row.get("missing_cases", []) if isinstance(row.get("missing_cases"), list) else []
        if missing_cases:
            missing_by_dimension[dimension] = len(missing_cases)
    if missing_by_dimension:
        issues.append(
            artifact_issue(
                "error",
                "threat_model_card",
                "threat model card frame coverage has missing cases",
                {"missing_by_dimension": missing_by_dimension},
            )
        )
    control_model = coverage.get("control_model", {}) if isinstance(coverage.get("control_model"), dict) else {}
    if as_int(control_model.get("cases_with_controls")) != case_count:
        issues.append(
            artifact_issue(
                "error",
                "threat_model_card",
                "threat model card control coverage does not cover all selected cases",
                {"cases_with_controls": control_model.get("cases_with_controls"), "case_count": case_count},
            )
        )
    if not coverage.get("suites"):
        issues.append(artifact_issue("error", "threat_model_card", "threat model card has no suite coverage rows"))
    for phrase in [
        "# Safety Bench Threat Model Card",
        "Threat Model Summary",
        "Case-Set Coverage",
        "Frame Coverage",
        "Control And Recovery Model",
        "Public Artifact Boundary",
    ]:
        if phrase not in markdown:
            issues.append(
                artifact_issue(
                    "error",
                    "threat_model_card",
                    "threat model card markdown is missing required phrase",
                    {"phrase": phrase},
                )
            )
    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "issue_count": len(issues),
        "case_count": case_count,
        "active_case_count": active_case_count,
        "suite_rows": len(coverage.get("suites", []) if isinstance(coverage.get("suites"), list) else []),
        "control_cases": as_int(control_model.get("cases_with_controls")),
        "frame_dimensions": len(frame_dimensions),
    }, issues


def check_statistical_analysis(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    json_path = root / "docs" / "generated_artifacts" / "paper_statistical_analysis.json"
    md_path = root / "docs" / "generated_artifacts" / "paper_statistical_analysis.md"
    for path in [json_path, md_path]:
        if not path.is_file():
            issues.append(
                artifact_issue(
                    "error",
                    "statistical_analysis",
                    "missing statistical analysis file",
                    {"path": str(path.relative_to(root)).replace("\\", "/")},
                )
            )
    if not json_path.is_file() or not md_path.is_file():
        return {
            "ok": False,
            "issue_count": len(issues),
            "attack_rows": 0,
            "control_rows": 0,
            "attack_success": 0,
            "control_success": 0,
        }, issues
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(
            artifact_issue(
                "error",
                "statistical_analysis",
                "could not parse paper_statistical_analysis.json",
                {"error": str(exc)},
            )
        )
        return {
            "ok": False,
            "issue_count": len(issues),
            "attack_rows": 0,
            "control_rows": 0,
            "attack_success": 0,
            "control_success": 0,
        }, issues
    markdown = md_path.read_text(encoding="utf-8-sig")
    schema_version = as_int(payload.get("schema_version"))
    if schema_version != 2:
        issues.append(
            artifact_issue(
                "error",
                "statistical_analysis",
                "statistical analysis schema_version must be 2",
                {"schema_version": payload.get("schema_version")},
            )
        )
    baseline = payload.get("baseline", {}) if isinstance(payload.get("baseline"), dict) else {}
    if baseline.get("runtime") != "Claude Code" or baseline.get("model") != "Kimi K2.6":
        issues.append(
            artifact_issue(
                "error",
                "statistical_analysis",
                "statistical analysis baseline must be Claude Code + Kimi K2.6",
                {"baseline": baseline},
            )
        )
    matrix = payload.get("matrix", {}) if isinstance(payload.get("matrix"), dict) else {}
    effects = payload.get("primary_effects", {}) if isinstance(payload.get("primary_effects"), dict) else {}
    attack = effects.get("attack_success", {}) if isinstance(effects.get("attack_success"), dict) else {}
    confirmed = effects.get("confirmed_compromise", {}) if isinstance(effects.get("confirmed_compromise"), dict) else {}
    control = effects.get("control_attack_success", {}) if isinstance(effects.get("control_attack_success"), dict) else {}
    control_confirmed = (
        effects.get("control_confirmed_compromise", {})
        if isinstance(effects.get("control_confirmed_compromise"), dict)
        else {}
    )
    attack_rows = as_int(matrix.get("attack_rows"))
    control_rows = as_int(matrix.get("control_rows"))
    attack_success = as_int(attack.get("successes"))
    control_success = as_int(control.get("successes"))
    if attack_rows <= 0 or control_rows <= 0:
        issues.append(
            artifact_issue(
                "error",
                "statistical_analysis",
                "statistical analysis row counts are missing",
                {"attack_rows": attack_rows, "control_rows": control_rows},
            )
        )
    attack_asr_rows = as_int(attack.get("trials"))
    control_asr_rows = as_int(control.get("trials"))
    if schema_version == 1:
        if attack_asr_rows != attack_rows or as_int(confirmed.get("trials")) != attack_rows:
            issues.append(artifact_issue("error", "statistical_analysis", "attack metric denominators do not match matrix"))
        if control_asr_rows != control_rows or as_int(control_confirmed.get("trials")) != control_rows:
            issues.append(artifact_issue("error", "statistical_analysis", "control metric denominators do not match matrix"))
    else:
        if (
            attack_asr_rows < 0
            or attack_asr_rows > attack_rows
            or attack_success > attack_asr_rows
            or as_int(confirmed.get("successes")) > attack_asr_rows
            or as_int(confirmed.get("trials")) != attack_asr_rows
        ):
            issues.append(
                artifact_issue(
                    "error",
                    "statistical_analysis",
                    "attack scored ASR-eligible denominator is inconsistent",
                    {
                        "asr_eligible_scored_rows": attack_asr_rows,
                        "scored_rows": attack_rows,
                        "confirmed_trials": confirmed.get("trials"),
                    },
                )
            )
        if (
            control_asr_rows < 0
            or control_asr_rows > control_rows
            or control_success > control_asr_rows
            or as_int(control_confirmed.get("successes")) > control_asr_rows
            or as_int(control_confirmed.get("trials")) != control_asr_rows
        ):
            issues.append(
                artifact_issue(
                    "error",
                    "statistical_analysis",
                    "control scored ASR-eligible denominator is inconsistent",
                    {
                        "asr_eligible_scored_rows": control_asr_rows,
                        "scored_rows": control_rows,
                        "confirmed_trials": control_confirmed.get("trials"),
                    },
                )
            )
    attack_n_minus_1_rows = 0
    attack_accounted_rows = attack_rows
    control_n_minus_1_rows = 0
    control_accounted_rows = control_rows
    if schema_version == 2:
        metric_contract = payload.get("metric_contract", {})
        if not isinstance(metric_contract, dict) or metric_contract.get("n_minus_one_is_progress_node") is not False:
            issues.append(
                artifact_issue(
                    "error",
                    "statistical_analysis",
                    "statistical metric contract must keep N-1 outside the progress ladder",
                )
            )
        elif (
            metric_contract.get("conditional_asr_denominator")
            != "ASR-eligible N0-N5b scored attack rows"
            or metric_contract.get("end_to_end_denominator")
            != "ASR-eligible scored attack rows plus N-1 attack rows"
        ):
            issues.append(
                artifact_issue(
                    "error",
                    "statistical_analysis",
                    "statistical metric denominator contract is inconsistent",
                    {"metric_contract": metric_contract},
                )
            )
        if matrix.get("protocol_metrics_available") is not True:
            issues.append(
                artifact_issue(
                    "error",
                    "statistical_analysis",
                    "statistical analysis schema v2 must expose protocol result-class metrics",
                )
            )
        attack_scored_rows = as_int(matrix.get("attack_scored_rows"))
        attack_asr_eligible_rows = as_int(
            matrix.get("attack_asr_eligible_scored_rows")
        )
        attack_n_minus_1_rows = as_int(matrix.get("attack_n_minus_1_rows"))
        attack_accounted_rows = as_int(matrix.get("attack_accounted_terminal_rows"))
        attack_protocol_denominator_rows = as_int(
            matrix.get("attack_protocol_denominator_rows")
        )
        control_scored_rows = as_int(matrix.get("control_scored_rows"))
        control_asr_eligible_rows = as_int(
            matrix.get("control_asr_eligible_scored_rows")
        )
        control_n_minus_1_rows = as_int(matrix.get("control_n_minus_1_rows"))
        control_accounted_rows = as_int(matrix.get("control_accounted_terminal_rows"))
        control_protocol_denominator_rows = as_int(
            matrix.get("control_protocol_denominator_rows")
        )
        count_mismatches = {
            key: {"actual": actual, "expected": expected}
            for key, actual, expected in [
                ("attack_scored_rows", attack_scored_rows, attack_rows),
                (
                    "attack_asr_eligible_scored_rows",
                    attack_asr_eligible_rows,
                    attack_asr_rows,
                ),
                (
                    "attack_accounted_terminal_rows",
                    attack_accounted_rows,
                    attack_scored_rows + attack_n_minus_1_rows,
                ),
                (
                    "attack_protocol_denominator_rows",
                    attack_protocol_denominator_rows,
                    attack_asr_eligible_rows + attack_n_minus_1_rows,
                ),
                ("control_scored_rows", control_scored_rows, control_rows),
                (
                    "control_asr_eligible_scored_rows",
                    control_asr_eligible_rows,
                    control_asr_rows,
                ),
                (
                    "control_accounted_terminal_rows",
                    control_accounted_rows,
                    control_scored_rows + control_n_minus_1_rows,
                ),
                (
                    "control_protocol_denominator_rows",
                    control_protocol_denominator_rows,
                    control_asr_eligible_rows + control_n_minus_1_rows,
                ),
            ]
            if actual != expected
        }
        if count_mismatches:
            issues.append(
                artifact_issue(
                    "error",
                    "statistical_analysis",
                    "statistical result-class counts are inconsistent",
                    {"mismatches": count_mismatches},
                )
            )

        conditional_attack = validate_metric_block(
            issues,
            scope="statistical_analysis",
            metric="conditional_attack_success",
            block=effects.get("conditional_attack_success"),
            expected_successes=attack_success,
            expected_trials=attack_asr_rows,
        )
        protocol_completion = validate_metric_block(
            issues,
            scope="statistical_analysis",
            metric="protocol_completion",
            block=effects.get("protocol_completion"),
            expected_successes=attack_asr_rows,
            expected_trials=attack_protocol_denominator_rows,
        )
        model_nonconformance = validate_metric_block(
            issues,
            scope="statistical_analysis",
            metric="model_nonconformance",
            block=effects.get("model_nonconformance"),
            expected_successes=attack_n_minus_1_rows,
            expected_trials=attack_protocol_denominator_rows,
        )
        end_to_end_attack = validate_metric_block(
            issues,
            scope="statistical_analysis",
            metric="end_to_end_attack",
            block=effects.get("end_to_end_attack"),
            expected_successes=attack_success,
            expected_trials=attack_protocol_denominator_rows,
        )
        conditional_control = validate_metric_block(
            issues,
            scope="statistical_analysis",
            metric="control_conditional_violation",
            block=effects.get("control_conditional_violation"),
            expected_successes=control_success,
            expected_trials=control_asr_rows,
        )
        control_protocol_completion = validate_metric_block(
            issues,
            scope="statistical_analysis",
            metric="control_protocol_completion",
            block=effects.get("control_protocol_completion"),
            expected_successes=control_asr_rows,
            expected_trials=control_protocol_denominator_rows,
        )
        control_model_nonconformance = validate_metric_block(
            issues,
            scope="statistical_analysis",
            metric="control_model_nonconformance",
            block=effects.get("control_model_nonconformance"),
            expected_successes=control_n_minus_1_rows,
            expected_trials=control_protocol_denominator_rows,
        )
        control_end_to_end = validate_metric_block(
            issues,
            scope="statistical_analysis",
            metric="control_end_to_end_violation",
            block=effects.get("control_end_to_end_violation"),
            expected_successes=control_success,
            expected_trials=control_protocol_denominator_rows,
        )
        for name, block in [
            ("conditional_attack_success", conditional_attack),
            ("protocol_completion", protocol_completion),
            ("model_nonconformance", model_nonconformance),
            ("end_to_end_attack", end_to_end_attack),
            ("control_conditional_violation", conditional_control),
            ("control_protocol_completion", control_protocol_completion),
            ("control_model_nonconformance", control_model_nonconformance),
            ("control_end_to_end_violation", control_end_to_end),
        ]:
            interval = block.get("wilson95", []) if isinstance(block, dict) else []
            trials = as_int(block.get("trials")) if isinstance(block, dict) else 0
            expected_interval_length = 2 if trials > 0 else 0
            if (
                not isinstance(interval, list)
                or len(interval) != expected_interval_length
            ):
                issues.append(
                    artifact_issue(
                        "error",
                        "statistical_analysis",
                        "statistical metric is missing Wilson interval",
                        {"metric": name},
                    )
                )
    if attack_success <= 0:
        issues.append(artifact_issue("error", "statistical_analysis", "statistical analysis has no attack successes"))
    if control_success != 0 or as_int(control_confirmed.get("successes")) != 0:
        issues.append(
            artifact_issue(
                "error",
                "statistical_analysis",
                "pooled controls must remain zero-success in the statistical analysis",
                {
                    "control_attack_success": control_success,
                    "control_confirmed": control_confirmed.get("successes"),
                },
            )
        )
    for metric_name, block in [
        ("attack_success", attack),
        ("confirmed_compromise", confirmed),
        ("control_attack_success", control),
        ("control_confirmed_compromise", control_confirmed),
    ]:
        interval = block.get("wilson95", []) if isinstance(block, dict) else []
        trials = as_int(block.get("trials")) if isinstance(block, dict) else 0
        expected_interval_length = 2 if trials > 0 else 0
        if not isinstance(interval, list) or len(interval) != expected_interval_length:
            issues.append(
                artifact_issue(
                    "error",
                    "statistical_analysis",
                    "statistical metric is missing Wilson interval",
                    {"metric": metric_name},
                )
            )
    zero = payload.get("control_zero_success_bound", {}) if isinstance(payload.get("control_zero_success_bound"), dict) else {}
    if (
        as_int(zero.get("successes")) != 0
        or as_int(zero.get("trials")) != control_asr_rows
    ):
        issues.append(artifact_issue("error", "statistical_analysis", "control zero-success bound is inconsistent"))
    if (
        control_success == 0
        and control_asr_rows > 0
        and as_float(zero.get("one_sided_95_upper")) <= 0
    ):
        issues.append(artifact_issue("error", "statistical_analysis", "control zero-success upper bound is missing"))
    if control_asr_rows <= 0 and zero.get("one_sided_95_upper") is not None:
        issues.append(
            artifact_issue(
                "error",
                "statistical_analysis",
                "control zero-success upper bound must be null for a zero denominator",
            )
        )
    timeout = payload.get("timeout_sensitivity", {}) if isinstance(payload.get("timeout_sensitivity"), dict) else {}
    for key in ["attack_success", "confirmed_compromise", "control_attack_success", "control_confirmed_compromise"]:
        row = timeout.get(key, {}) if isinstance(timeout.get(key), dict) else {}
        for expected in ["observed_status_quo", "timeouts_as_successes", "timeouts_excluded"]:
            if expected not in row:
                issues.append(
                    artifact_issue(
                        "error",
                        "statistical_analysis",
                        "timeout sensitivity row is incomplete",
                        {"metric": key, "missing": expected},
                    )
                )
    family = payload.get("family_heterogeneity", {}) if isinstance(payload.get("family_heterogeneity"), dict) else {}
    case = payload.get("case_heterogeneity", {}) if isinstance(payload.get("case_heterogeneity"), dict) else {}
    if as_int(family.get("families")) <= 0 or not family.get("top_families"):
        issues.append(artifact_issue("error", "statistical_analysis", "family heterogeneity rows are missing"))
    if as_int(case.get("cases")) <= 0 or not case.get("top_cases"):
        issues.append(artifact_issue("error", "statistical_analysis", "case heterogeneity rows are missing"))
    for phrase in [
        "# Safety Bench Statistical Analysis",
        "Claude Code + Kimi K2.6",
        "Wilson 95%",
        "Control Zero-Success Bound",
        "Timeout Sensitivity",
        "Family Heterogeneity",
        "Public Artifact Boundary",
    ]:
        if phrase not in markdown:
            issues.append(
                artifact_issue(
                    "error",
                    "statistical_analysis",
                    "statistical analysis markdown is missing required phrase",
                    {"phrase": phrase},
                )
            )
    if schema_version == 2:
        for phrase in [
            "attack_scored_rows",
            "attack_n_minus_1_rows",
            "attack_accounted_terminal_rows",
            "attack_protocol_denominator_rows",
            "Conditional attack success (ASR-eligible scored denominator)",
            "Protocol completion (S+M denominator)",
            "Model nonconformance / N-1 (S+M denominator)",
            "End-to-end attack (S+M denominator)",
        ]:
            if phrase not in markdown:
                issues.append(
                    artifact_issue(
                        "error",
                        "statistical_analysis",
                        "statistical analysis markdown is missing schema-v2 metric",
                        {"phrase": phrase},
                    )
                )
    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "issue_count": len(issues),
        "attack_rows": attack_rows,
        "control_rows": control_rows,
        "attack_success": attack_success,
        "confirmed": as_int(confirmed.get("successes")),
        "control_success": control_success,
        "control_confirmed": as_int(control_confirmed.get("successes")),
        "attack_n_minus_1_rows": attack_n_minus_1_rows,
        "attack_asr_eligible_scored_rows": attack_asr_rows,
        "attack_accounted_terminal_rows": attack_accounted_rows,
        "control_n_minus_1_rows": control_n_minus_1_rows,
        "control_asr_eligible_scored_rows": control_asr_rows,
        "control_accounted_terminal_rows": control_accounted_rows,
        "families": as_int(family.get("families")),
        "cases": as_int(case.get("cases")),
    }, issues


def check_claim_evidence_map(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    json_path = root / "docs" / "generated_artifacts" / "paper_claim_evidence_map.json"
    md_path = root / "docs" / "generated_artifacts" / "paper_claim_evidence_map.md"
    for path in [json_path, md_path]:
        if not path.is_file():
            issues.append(
                artifact_issue(
                    "error",
                    "claim_evidence_map",
                    "missing claim evidence map file",
                    {"path": str(path.relative_to(root)).replace("\\", "/")},
                )
            )
    if not json_path.is_file() or not md_path.is_file():
        return {"ok": False, "issue_count": len(issues), "claims": 0}, issues
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(
            artifact_issue(
                "error",
                "claim_evidence_map",
                "could not parse paper_claim_evidence_map.json",
                {"error": str(exc)},
            )
        )
        return {"ok": False, "issue_count": len(issues), "claims": 0}, issues
    markdown = md_path.read_text(encoding="utf-8-sig")
    schema_version = as_int(payload.get("schema_version"))
    if schema_version not in {1, 2}:
        issues.append(
            artifact_issue(
                "error",
                "claim_evidence_map",
                "claim evidence map schema_version must be 1 or 2",
                {"schema_version": payload.get("schema_version")},
            )
        )
    baseline = payload.get("baseline", {}) if isinstance(payload.get("baseline"), dict) else {}
    if baseline.get("runtime") != "Claude Code" or baseline.get("model") != "Kimi K2.6":
        issues.append(
            artifact_issue(
                "error",
                "claim_evidence_map",
                "claim evidence map baseline must be Claude Code + Kimi K2.6",
                {"baseline": baseline},
            )
        )
    summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
    claims = payload.get("claims", []) if isinstance(payload.get("claims"), list) else []
    claim_ids = {str(claim.get("id") or "") for claim in claims if isinstance(claim, dict)}
    required_ids = {
        "C1_scope",
        "C2_configuration_boundary",
        "C3_matrix_protocol",
        "C4_results_reported",
        "C5_control_design",
        "C6_oracle_policy",
        "C7_public_artifact_boundary",
        "C8_release_status",
        "C9_limitations",
    }
    if schema_version == 2:
        required_ids.add("C10_measurement_accounting")
    missing_ids = sorted(required_ids - claim_ids)
    if missing_ids:
        issues.append(
            artifact_issue(
                "error",
                "claim_evidence_map",
                "claim evidence map is missing required claim ids",
                {"missing_ids": missing_ids},
            )
        )
    needs_attention = as_int(summary.get("needs_attention"))
    blocked_release = as_int(summary.get("blocked_on_release_metadata"))
    supported = as_int(summary.get("supported"))
    if needs_attention != 0:
        issues.append(
            artifact_issue(
                "error",
                "claim_evidence_map",
                "claim evidence map has unsupported or inconsistent claims",
                {"needs_attention": needs_attention},
            )
        )
    minimum_supported = 9 if schema_version == 2 else 8
    if supported < minimum_supported:
        issues.append(
            artifact_issue(
                "error",
                "claim_evidence_map",
                "claim evidence map has too few supported design and experiment-boundary claims",
                {"supported": supported, "minimum_supported": minimum_supported},
            )
        )
    if blocked_release < 1:
        issues.append(
            artifact_issue(
                "error",
                "claim_evidence_map",
                "claim evidence map should explicitly track the release metadata blocker",
            )
        )
    for claim in claims:
        if not isinstance(claim, dict):
            issues.append(artifact_issue("error", "claim_evidence_map", "claim row is not an object"))
            continue
        if not claim.get("claim") or not claim.get("status") or not claim.get("claim_type"):
            issues.append(
                artifact_issue(
                    "error",
                    "claim_evidence_map",
                    "claim row is missing required fields",
                    {"id": claim.get("id")},
                )
            )
    if schema_version == 2:
        measurement_claim = next(
            (
                claim
                for claim in claims
                if isinstance(claim, dict)
                and claim.get("id") == "C10_measurement_accounting"
            ),
            {},
        )
        claim_text = str(measurement_claim.get("claim") or "").lower()
        evidence_rows = (
            measurement_claim.get("evidence", [])
            if isinstance(measurement_claim.get("evidence"), list)
            else []
        )
        required_semantics = [
            "orthogonal",
            "not an n0-n5b",
            "conditional",
            "scored asr-eligible",
            "protocol completion",
            "model nonconformance",
            "end-to-end",
            "coverage accounting",
            "all scored rows plus n-1",
            "s+m",
        ]
        missing_semantics = [
            phrase for phrase in required_semantics if phrase not in claim_text
        ]
        bad_evidence = [
            row
            for row in evidence_rows
            if not isinstance(row, dict)
            or row.get("path")
            != "docs/generated_artifacts/paper_statistical_analysis.json"
        ]
        if (
            measurement_claim.get("status") != "supported"
            or missing_semantics
            or len(evidence_rows) < 7
            or bad_evidence
        ):
            issues.append(
                artifact_issue(
                    "error",
                    "claim_evidence_map",
                    "measurement-accounting claim is incomplete or unsupported",
                    {
                        "status": measurement_claim.get("status"),
                        "missing_semantics": missing_semantics,
                        "evidence_rows": len(evidence_rows),
                        "bad_evidence_rows": len(bad_evidence),
                    },
                )
            )
        evidence_rows = claim.get("evidence", []) if isinstance(claim.get("evidence"), list) else []
        if not evidence_rows:
            issues.append(
                artifact_issue(
                    "error",
                    "claim_evidence_map",
                    "claim row has no evidence rows",
                    {"id": claim.get("id")},
                )
            )
        if claim.get("id") != "C8_release_status" and claim.get("status") != "supported":
            issues.append(
                artifact_issue(
                    "error",
                    "claim_evidence_map",
                    "non-release claim must be supported",
                    {"id": claim.get("id"), "status": claim.get("status")},
                )
            )
    for phrase in [
        "# Paper Claim Evidence Map",
        "Claim Boundary",
        "Evidence Sources",
        "Supported Claims",
        "Blocked Release Claims",
        "Public Artifact Boundary",
        "Claude Code + Kimi K2.6",
    ]:
        if phrase not in markdown:
            issues.append(
                artifact_issue(
                    "error",
                    "claim_evidence_map",
                    "claim evidence map markdown is missing required phrase",
                    {"phrase": phrase},
                )
            )
    if schema_version == 2:
        for phrase in ["C10_measurement_accounting", "Coverage accounting", "S+M", "N-1"]:
            if phrase not in markdown:
                issues.append(
                    artifact_issue(
                        "error",
                        "claim_evidence_map",
                        "claim evidence map markdown is missing measurement accounting",
                        {"phrase": phrase},
                    )
                )
    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "issue_count": len(issues),
        "claims": as_int(summary.get("claims")) or len(claims),
        "supported": supported,
        "blocked_on_release_metadata": blocked_release,
        "needs_attention": needs_attention,
    }, issues


def check_control_integrity(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    json_path = root / "docs" / "generated_artifacts" / "paper_control_integrity_report.json"
    md_path = root / "docs" / "generated_artifacts" / "paper_control_integrity_report.md"
    for path in [json_path, md_path]:
        if not path.is_file():
            issues.append(
                artifact_issue(
                    "error",
                    "control_integrity",
                    "missing control integrity report file",
                    {"path": str(path.relative_to(root)).replace("\\", "/")},
                )
            )
    if not json_path.is_file() or not md_path.is_file():
        return {"ok": False, "issue_count": len(issues), "control_rows": 0}, issues
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(
            artifact_issue(
                "error",
                "control_integrity",
                "could not parse paper_control_integrity_report.json",
                {"error": str(exc)},
            )
        )
        return {"ok": False, "issue_count": len(issues), "control_rows": 0}, issues
    markdown = md_path.read_text(encoding="utf-8-sig")
    if payload.get("schema_version") != 1:
        issues.append(artifact_issue("error", "control_integrity", "control integrity schema_version must be 1"))
    baseline = payload.get("baseline", {}) if isinstance(payload.get("baseline"), dict) else {}
    if baseline.get("runtime") != "Claude Code" or baseline.get("model") != "Kimi K2.6":
        issues.append(
            artifact_issue(
                "error",
                "control_integrity",
                "control integrity baseline must be Claude Code + Kimi K2.6",
                {"baseline": baseline},
            )
        )
    summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
    control_rows = as_int(summary.get("control_rows"))
    has_oracle_rows = as_int(summary.get("has_oracle_rows"))
    control_types = summary.get("control_types", []) if isinstance(summary.get("control_types"), list) else []
    if control_rows <= 0 or has_oracle_rows != control_rows:
        issues.append(
            artifact_issue(
                "error",
                "control_integrity",
                "control integrity row counts are incomplete",
                {"control_rows": control_rows, "has_oracle_rows": has_oracle_rows},
            )
        )
    result_class_fields = {
        "observed_control_rows",
        "accounted_terminal_rows",
        "scored_control_rows",
        "asr_eligible_scored_control_rows",
        "model_protocol_terminal_rows",
        "protocol_denominator_rows",
        "unaccounted_control_rows",
        "protocol_completion_rate",
        "model_nonconformance_rate",
    }
    missing_fields = sorted(result_class_fields - set(summary))
    if missing_fields:
        issues.append(
            artifact_issue(
                "error",
                "control_integrity",
                "control integrity result-class accounting is incomplete",
                {"missing_fields": missing_fields},
            )
        )
    else:
        observed_rows = as_int(summary.get("observed_control_rows"))
        accounted_rows = as_int(summary.get("accounted_terminal_rows"))
        scored_rows = as_int(summary.get("scored_control_rows"))
        asr_eligible_rows = as_int(
            summary.get("asr_eligible_scored_control_rows")
        )
        protocol_rows = as_int(summary.get("model_protocol_terminal_rows"))
        protocol_denominator_rows = as_int(
            summary.get("protocol_denominator_rows")
        )
        unaccounted_rows = as_int(summary.get("unaccounted_control_rows"))
        if (
            control_rows != accounted_rows
            or accounted_rows != scored_rows + protocol_rows
            or asr_eligible_rows > scored_rows
            or protocol_denominator_rows != asr_eligible_rows + protocol_rows
            or observed_rows != accounted_rows + unaccounted_rows
        ):
            issues.append(
                artifact_issue(
                    "error",
                    "control_integrity",
                    "control integrity result-class counts are inconsistent",
                    {
                        "observed": observed_rows,
                        "accounted_terminal": accounted_rows,
                        "scored": scored_rows,
                        "asr_eligible_scored": asr_eligible_rows,
                        "model_protocol_terminal": protocol_rows,
                        "protocol_denominator": protocol_denominator_rows,
                        "unaccounted": unaccounted_rows,
                    },
                )
            )
        if not percentage_matches(
            summary.get("protocol_completion_rate"),
            asr_eligible_rows,
            protocol_denominator_rows,
        ) or not percentage_matches(
            summary.get("model_nonconformance_rate"),
            protocol_rows,
            protocol_denominator_rows,
        ):
            issues.append(
                artifact_issue(
                    "error",
                    "control_integrity",
                    "control integrity protocol rates are inconsistent",
                    {
                        "protocol_completion_rate": summary.get(
                            "protocol_completion_rate"
                        ),
                        "model_nonconformance_rate": summary.get(
                            "model_nonconformance_rate"
                        ),
                    },
                )
            )
    expected_types = {"clean_control", "no_persist_control", "no_trigger_control", "cleanup_control"}
    if set(control_types) != expected_types:
        issues.append(
            artifact_issue(
                "error",
                "control_integrity",
                "control integrity report has unexpected control types",
                {"control_types": control_types},
            )
        )
    if as_int(summary.get("attack_success_rows")) != 0 or as_int(summary.get("confirmed_rows")) != 0:
        issues.append(
            artifact_issue(
                "error",
                "control_integrity",
                "control integrity report has nonzero unsafe outcome rows",
                {
                    "attack_success_rows": summary.get("attack_success_rows"),
                    "confirmed_rows": summary.get("confirmed_rows"),
                },
            )
        )
    if as_int(summary.get("callback_probe_failures")) != 0 or as_int(summary.get("global_config_touched_rows")) != 0:
        issues.append(
            artifact_issue(
                "error",
                "control_integrity",
                "control integrity report has callback or global-config failures",
                {
                    "callback_probe_failures": summary.get("callback_probe_failures"),
                    "global_config_touched_rows": summary.get("global_config_touched_rows"),
                },
            )
        )
    if summary.get("ok_for_paper_controls") is not True:
        issues.append(artifact_issue("error", "control_integrity", "control integrity report is not ok for paper controls"))
    by_type = payload.get("by_control_type", []) if isinstance(payload.get("by_control_type"), list) else []
    if len(by_type) != 4:
        issues.append(artifact_issue("error", "control_integrity", "control type breakdown must contain four rows"))
    if not missing_fields:
        if (
            sum(
                as_int(row.get("scored_rows"))
                for row in by_type
                if isinstance(row, dict)
            )
            != as_int(summary.get("scored_control_rows"))
            or sum(
                as_int(row.get("asr_eligible_scored_rows"))
                for row in by_type
                if isinstance(row, dict)
            )
            != as_int(summary.get("asr_eligible_scored_control_rows"))
            or sum(
            as_int(row.get("model_protocol_terminal_rows"))
            for row in by_type
            if isinstance(row, dict)
            )
            != as_int(summary.get("model_protocol_terminal_rows"))
            or sum(
                as_int(row.get("protocol_denominator_rows"))
                for row in by_type
                if isinstance(row, dict)
            )
            != as_int(summary.get("protocol_denominator_rows"))
        ):
            issues.append(
                artifact_issue(
                    "error",
                    "control_integrity",
                    "control type result-class totals do not match the pooled summary",
                )
            )
    critical_hits = payload.get("critical_absent_oracle_hits", {})
    if not isinstance(critical_hits, dict):
        issues.append(artifact_issue("error", "control_integrity", "critical absent-oracle hits must be an object"))
    for phrase in [
        "# Paper Control Integrity Report",
        "Control Matrix Integrity",
        "Control Type Breakdown",
        "Protocol denominator rows (S+M)",
        "Critical Absent-Oracles",
        "Non-zero Exit Warning",
        "Public Artifact Boundary",
        "Claude Code + Kimi K2.6",
    ]:
        if phrase not in markdown:
            issues.append(
                artifact_issue(
                    "error",
                    "control_integrity",
                    "control integrity markdown is missing required phrase",
                    {"phrase": phrase},
                )
            )
    if not missing_fields:
        for phrase in [
            "accounted_terminal_rows",
            "scored_control_rows",
            "model_protocol_terminal_rows (N-1)",
            "protocol_completion_rate",
            "model_nonconformance_rate",
        ]:
            if phrase not in markdown:
                issues.append(
                    artifact_issue(
                        "error",
                        "control_integrity",
                        "control integrity markdown is missing result-class accounting",
                        {"phrase": phrase},
                    )
                )
    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "issue_count": len(issues),
        "control_rows": control_rows,
        "has_oracle_rows": has_oracle_rows,
        "attack_success_rows": as_int(summary.get("attack_success_rows")),
        "confirmed_rows": as_int(summary.get("confirmed_rows")),
        "timeout_rows": as_int(summary.get("timeout_rows")),
        "nonzero_exit_rows": as_int(summary.get("nonzero_exit_rows")),
        "critical_absent_oracle_hit_rows": as_int(summary.get("critical_absent_oracle_hit_rows")),
        "scored_control_rows": as_int(summary.get("scored_control_rows", control_rows)),
        "model_protocol_terminal_rows": as_int(summary.get("model_protocol_terminal_rows")),
        "accounted_terminal_rows": as_int(summary.get("accounted_terminal_rows", control_rows)),
    }, issues


def check_paper_figures(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    json_path = root / "docs" / "generated_artifacts" / "paper_figures.json"
    md_path = root / "docs" / "generated_artifacts" / "paper_figures.md"
    expected_figures = {
        "figure_1_benchmark_frame": "docs/figures/figure_1_benchmark_frame.svg",
        "figure_2_core_results": "docs/generated_artifacts/figures/figure_2_core_results.svg",
    }
    required_files = [json_path, md_path, *[root / path for path in expected_figures.values()]]
    for path in required_files:
        if not path.is_file():
            issues.append(
                artifact_issue(
                    "error",
                    "paper_figures",
                    "missing paper figure artifact",
                    {"path": str(path.relative_to(root)).replace("\\", "/")},
                )
            )
    if not json_path.is_file() or not md_path.is_file():
        return {"ok": False, "issue_count": len(issues), "figures": 0, "svg_files": 0}, issues
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        issues.append(
            artifact_issue(
                "error",
                "paper_figures",
                "could not parse paper_figures.json",
                {"error": str(exc)},
            )
        )
        return {"ok": False, "issue_count": len(issues), "figures": 0, "svg_files": 0}, issues
    markdown = md_path.read_text(encoding="utf-8-sig")
    schema_version = as_int(payload.get("schema_version"))
    if schema_version != 2:
        issues.append(
            artifact_issue(
                "error",
                "paper_figures",
                "paper figures schema_version must be 2",
                {"schema_version": payload.get("schema_version")},
            )
        )
    baseline = payload.get("baseline", {}) if isinstance(payload.get("baseline"), dict) else {}
    expected_baseline = {"runtime": "Claude Code", "model": "Kimi K2.6", "harness": "claude"}
    for key, expected in expected_baseline.items():
        if baseline.get(key) != expected:
            issues.append(
                artifact_issue(
                    "error",
                    "paper_figures",
                    "paper figures baseline has unexpected value",
                    {"key": key, "expected": expected, "actual": baseline.get(key)},
                )
            )
    figures = payload.get("figures", []) if isinstance(payload.get("figures"), list) else []
    figure_paths = {
        item.get("id"): item.get("path")
        for item in figures
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    if len(figures) < len(expected_figures):
        issues.append(
            artifact_issue(
                "error",
                "paper_figures",
                "paper figures report has too few figure entries",
                {"figures": len(figures), "expected_min": len(expected_figures)},
            )
        )
    for figure_id, expected_path in expected_figures.items():
        if figure_paths.get(figure_id) != expected_path:
            issues.append(
                artifact_issue(
                    "error",
                    "paper_figures",
                    "paper figures report is missing an expected figure path",
                    {"figure_id": figure_id, "expected_path": expected_path, "actual_path": figure_paths.get(figure_id)},
                )
            )
    if schema_version == 2:
        contract = payload.get("measurement_contract", {})
        contract = contract if isinstance(contract, dict) else {}
        if (
            contract.get("n_minus_one_is_progress_node") is not False
            or contract.get("conditional_asr_denominator")
            != "ASR-eligible N0-N5b scored attack rows"
            or contract.get("end_to_end_denominator")
            != "ASR-eligible scored attack rows plus N-1 attack rows"
            or contract.get("protocol_metrics_available") is not True
        ):
            issues.append(
                artifact_issue(
                    "error",
                    "paper_figures",
                    "paper figures measurement contract is missing or inconsistent",
                    {"measurement_contract": contract},
                )
            )
        matrix = payload.get("matrix", {})
        matrix = matrix if isinstance(matrix, dict) else {}
        effects = payload.get("primary_effects", {})
        effects = effects if isinstance(effects, dict) else {}
        attack_scored = as_int(matrix.get("attack_scored_rows"))
        attack_asr_eligible = as_int(
            matrix.get("attack_asr_eligible_scored_rows")
        )
        attack_n_minus_one = as_int(matrix.get("attack_n_minus_1_rows"))
        attack_accounted = as_int(matrix.get("attack_accounted_terminal_rows"))
        attack_protocol_denominator = as_int(
            matrix.get("attack_protocol_denominator_rows")
        )
        control_scored = as_int(matrix.get("control_scored_rows"))
        control_asr_eligible = as_int(
            matrix.get("control_asr_eligible_scored_rows")
        )
        control_n_minus_one = as_int(matrix.get("control_n_minus_1_rows"))
        control_accounted = as_int(matrix.get("control_accounted_terminal_rows"))
        control_protocol_denominator = as_int(
            matrix.get("control_protocol_denominator_rows")
        )
        if (
            matrix.get("protocol_metrics_available") is not True
            or as_int(matrix.get("attack_rows")) != attack_scored
            or attack_accounted != attack_scored + attack_n_minus_one
            or attack_protocol_denominator
            != attack_asr_eligible + attack_n_minus_one
            or as_int(matrix.get("control_rows")) != control_scored
            or control_accounted != control_scored + control_n_minus_one
            or control_protocol_denominator
            != control_asr_eligible + control_n_minus_one
        ):
            issues.append(
                artifact_issue(
                    "error",
                    "paper_figures",
                    "paper figures result-class matrix is inconsistent",
                    {"matrix": matrix},
                )
            )
        conditional = effects.get("conditional_attack_success", {})
        control_conditional = effects.get("control_conditional_violation", {})
        attack_successes = as_int(
            conditional.get("successes") if isinstance(conditional, dict) else 0
        )
        attack_asr_rows = as_int(
            conditional.get("trials") if isinstance(conditional, dict) else 0
        )
        control_successes = as_int(
            control_conditional.get("successes")
            if isinstance(control_conditional, dict)
            else 0
        )
        control_asr_rows = as_int(
            control_conditional.get("trials")
            if isinstance(control_conditional, dict)
            else 0
        )
        if (
            attack_asr_rows < 0
            or attack_asr_rows > attack_scored
            or attack_asr_rows != attack_asr_eligible
            or attack_successes > attack_asr_rows
            or control_asr_rows < 0
            or control_asr_rows > control_scored
            or control_asr_rows != control_asr_eligible
            or control_successes > control_asr_rows
        ):
            issues.append(
                artifact_issue(
                    "error",
                    "paper_figures",
                    "paper figures ASR-eligible denominators exceed scored rows",
                )
            )
        figure_metrics = [
            ("conditional_attack_success", attack_successes, attack_asr_rows),
            (
                "protocol_completion",
                attack_asr_eligible,
                attack_protocol_denominator,
            ),
            (
                "model_nonconformance",
                attack_n_minus_one,
                attack_protocol_denominator,
            ),
            (
                "end_to_end_attack",
                attack_successes,
                attack_protocol_denominator,
            ),
            ("control_conditional_violation", control_successes, control_asr_rows),
            (
                "control_protocol_completion",
                control_asr_eligible,
                control_protocol_denominator,
            ),
            (
                "control_model_nonconformance",
                control_n_minus_one,
                control_protocol_denominator,
            ),
            (
                "control_end_to_end_violation",
                control_successes,
                control_protocol_denominator,
            ),
        ]
        for name, successes, trials in figure_metrics:
            validate_metric_block(
                issues,
                scope="paper_figures",
                metric=name,
                block=effects.get(name),
                expected_successes=successes,
                expected_trials=trials,
            )
    svg_files = 0
    for expected_path in expected_figures.values():
        svg_path = root / expected_path
        if not svg_path.is_file():
            continue
        svg_files += 1
        svg_text = svg_path.read_text(encoding="utf-8-sig")
        lower_svg = svg_text.lower()
        rel_path = str(svg_path.relative_to(root)).replace("\\", "/")
        if "<svg" not in lower_svg:
            issues.append(artifact_issue("error", "paper_figures", "figure file does not contain an SVG root", {"path": rel_path}))
        for forbidden in ["<script", "http://", "https://", "<image"]:
            if forbidden in lower_svg:
                issues.append(
                    artifact_issue(
                        "error",
                        "paper_figures",
                        "figure SVG contains forbidden external or executable content",
                        {"path": rel_path, "forbidden": forbidden},
                    )
                )
    for phrase in [
        "# Paper Figures",
        "Claude Code + Kimi K2.6",
        "figure_1_benchmark_frame.svg",
        "figure_2_core_results.svg",
        "Public Artifact Boundary",
    ]:
        if phrase not in markdown:
            issues.append(
                artifact_issue(
                    "error",
                    "paper_figures",
                    "paper figures markdown is missing required phrase",
                    {"phrase": phrase},
                )
            )
    if schema_version == 2:
        for phrase in [
            "Measurement Accounting",
            "orthogonal terminal result class",
            "Scored | ASR eligible (S) | N-1 (M) | Coverage accounted | Protocol denominator (S+M)",
            "Conditional attack success",
            "Protocol completion",
            "Model nonconformance / N-1",
            "End-to-end attack",
        ]:
            if phrase not in markdown:
                issues.append(
                    artifact_issue(
                        "error",
                        "paper_figures",
                        "paper figures markdown is missing schema-v2 accounting",
                        {"phrase": phrase},
                    )
                )
    return {
        "ok": not any(item.get("severity") == "error" for item in issues),
        "issue_count": len(issues),
        "figures": len(figures),
        "svg_files": svg_files,
    }, issues


def check_paper_numbers_gate(
    *,
    root: Path,
    attack_dirs: list[Path],
    control_dirs: list[Path],
    table_dir: Path | None,
    case_evidence_dir: Path | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    report = check_paper_numbers.build_number_report(
        root=root,
        attack_dirs=attack_dirs,
        control_dirs=control_dirs,
        table_dir=table_dir,
        case_evidence_dir=case_evidence_dir,
    )
    issues = [
        artifact_issue(
            item.get("severity", "error"),
            "paper_numbers",
            item.get("message", "paper numeric claim issue"),
            {"number_scope": item.get("scope", ""), **item.get("detail", {})},
        )
        for item in report.get("issues", [])
    ]
    return report, issues


def check_case_studies_gate(
    *,
    root: Path,
    case_evidence_dir: Path | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if case_evidence_dir is None:
        report = {
            "ok": False,
            "issues": [
                {
                    "severity": "error",
                    "scope": "inputs",
                    "message": "no case-study evidence directory provided",
                    "detail": {},
                }
            ],
            "case_count": 0,
            "attack_row_count": 0,
            "recommended_main_paper_count": 0,
        }
    else:
        report = check_paper_case_studies.build_case_study_report(
            root=root,
            case_evidence_dir=case_evidence_dir,
            candidates_doc=root / "docs" / "generated_artifacts" / "paper_case_study_candidates.md",
        )
    issues = [
        artifact_issue(
            item.get("severity", "error"),
            "case_studies",
            item.get("message", "paper case-study issue"),
            {"case_study_scope": item.get("scope", ""), **item.get("detail", {})},
        )
        for item in report.get("issues", [])
    ]
    return report, issues


def check_release_metadata_gate(root: Path, require_license: bool) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    report = check_release_metadata.build_release_metadata_report(root, require_license=require_license)
    issues = [
        artifact_issue(
            item.get("severity", "error"),
            "release_metadata",
            item.get("message", "release metadata issue"),
            {"release_scope": item.get("scope", ""), **item.get("detail", {})},
        )
        for item in report.get("issues", [])
    ]
    return report, issues


def check_suite_lock_gate(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    report = check_paper_suite_lock.build_report(root)
    issues = [
        artifact_issue(
            item.get("severity", "error"),
            "suite_lock",
            item.get("message", "paper suite lock issue"),
            item.get("detail", {}),
        )
        for item in report.get("issues", [])
    ]
    return report, issues


def check_public_artifact_safety_gate(bundle_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    report = check_public_artifact_safety.build_safety_report(bundle_dir)
    issues = [
        artifact_issue(
            item.get("severity", "error"),
            "public_artifact_safety",
            item.get("message", "public artifact safety issue"),
            {"safety_scope": item.get("scope", ""), **item.get("detail", {})},
        )
        for item in report.get("issues", [])
    ]
    return report, issues


def build_artifact_gate(
    *,
    root: Path = ROOT,
    attack_dirs: list[Path] | None = None,
    control_dirs: list[Path] | None = None,
    table_dir: Path | None = None,
    bundle_dir: Path | None = None,
    case_evidence_dir: Path | None = None,
    case_set: str = "all",
    min_attack_trials: int = 1,
    min_control_trials: int = 1,
    control_types: list[str] | None = None,
    expected_harnesses: list[str] | None = None,
    require_kimi: bool = False,
    skip_readiness: bool = False,
    max_active_progress_drift_rows: int = DEFAULT_ACTIVE_PROGRESS_DRIFT_ROWS,
    max_timeouts: int = 0,
    include_historical_formal_workflow: bool = False,
) -> dict[str, Any]:
    attack_dirs = attack_dirs or []
    control_dirs = control_dirs or []
    issues: list[dict[str, Any]] = []
    sections: dict[str, Any] = {}

    if not skip_readiness:
        readiness = check_paper_readiness.build_readiness(require_kimi=require_kimi, root=root)
        sections["readiness"] = {
            "ready": readiness.get("ready"),
            "blockers": readiness.get("blockers", []),
            "warnings": readiness.get("warnings", []),
            "case_counts": readiness.get("case_counts", {}),
        }
        for blocker in readiness.get("blockers", []):
            issues.append(artifact_issue("error", "readiness", blocker))

    claim_profile = "submission" if require_kimi else "current_claude"
    claim_report, claim_issues = check_claim_boundary(root, profile=claim_profile)
    sections["claim_boundary"] = {
        "ok": claim_report.get("ok"),
        "profile": claim_profile,
        "issue_count": len(claim_report.get("issues", [])),
    }
    issues.extend(claim_issues)

    manuscript_report, manuscript_issues = check_manuscript_gate(root)
    sections["manuscript"] = {
        "ok": manuscript_report.get("ok"),
        "issue_count": len(manuscript_report.get("issues", [])),
        "required_sections": manuscript_report.get("required_sections", 0),
        "required_phrases": manuscript_report.get("required_phrases", 0),
        "markdown_table_rows": manuscript_report.get("markdown_table_rows", 0),
    }
    issues.extend(manuscript_issues)

    bibliography_report, bibliography_issues = check_bibliography_gate(root)
    sections["bibliography"] = {
        "ok": bibliography_report.get("ok"),
        "issue_count": len(bibliography_report.get("issues", [])),
        "required_keys": len(bibliography_report.get("required_keys", [])),
        "bib_keys": len(bibliography_report.get("bib_keys", [])),
        "cited_keys": len(bibliography_report.get("cited_keys", [])),
        "unknown_cited_keys": len(bibliography_report.get("unknown_cited_keys", [])),
    }
    issues.extend(bibliography_issues)

    full_suite_report, full_suite_issues = check_full_suite_eligibility(root)
    sections["full_suite_eligibility"] = full_suite_report
    issues.extend(full_suite_issues)

    external_validity_report, external_validity_issues = check_external_validity_plan(root)
    sections["external_validity_plan"] = external_validity_report
    issues.extend(external_validity_issues)

    benchmark_card_report, benchmark_card_issues = check_benchmark_card(root)
    sections["benchmark_card"] = {
        "ok": benchmark_card_report.get("ok"),
        "issue_count": benchmark_card_report.get("issue_count", 0),
        "total_rows": benchmark_card_report.get("total_rows", 0),
        "scored_attack_rows": benchmark_card_report.get("scored_attack_rows", 0),
        "n_minus_1_attack_rows": benchmark_card_report.get("n_minus_1_attack_rows", 0),
        "accounted_terminal_attack_rows": benchmark_card_report.get(
            "accounted_terminal_attack_rows", 0
        ),
        "protocol_completion_rate": benchmark_card_report.get(
            "protocol_completion_rate"
        ),
        "model_nonconformance_rate": benchmark_card_report.get(
            "model_nonconformance_rate"
        ),
        "conditional_asr_rate": benchmark_card_report.get("conditional_asr_rate"),
        "end_to_end_attack_rate": benchmark_card_report.get("end_to_end_attack_rate"),
        "baseline": benchmark_card_report.get("baseline", ""),
    }
    issues.extend(benchmark_card_issues)

    appendix_report, appendix_issues = check_supplementary_appendix(root)
    sections["supplementary_appendix"] = {
        "ok": appendix_report.get("ok"),
        "issue_count": appendix_report.get("issue_count", 0),
        "family_rows": appendix_report.get("family_rows", 0),
        "case_rows": appendix_report.get("case_rows", 0),
    }
    issues.extend(appendix_issues)

    oracle_coverage_report, oracle_coverage_issues = check_oracle_coverage(root)
    sections["oracle_coverage"] = {
        "ok": oracle_coverage_report.get("ok"),
        "issue_count": oracle_coverage_report.get("issue_count", 0),
        "case_count": oracle_coverage_report.get("case_count", 0),
        "attack_rows": oracle_coverage_report.get("attack_rows", 0),
        "control_rows": oracle_coverage_report.get("control_rows", 0),
        "hard_trace_cases": oracle_coverage_report.get("hard_trace_cases", 0),
        "propagation_only_cases": oracle_coverage_report.get("propagation_only_cases", 0),
        "soft_semantic_cases": oracle_coverage_report.get("soft_semantic_cases", 0),
    }
    issues.extend(oracle_coverage_issues)

    threat_model_report, threat_model_issues = check_threat_model_card(root)
    sections["threat_model_card"] = {
        "ok": threat_model_report.get("ok"),
        "issue_count": threat_model_report.get("issue_count", 0),
        "case_count": threat_model_report.get("case_count", 0),
        "active_case_count": threat_model_report.get("active_case_count", 0),
        "suite_rows": threat_model_report.get("suite_rows", 0),
        "control_cases": threat_model_report.get("control_cases", 0),
        "frame_dimensions": threat_model_report.get("frame_dimensions", 0),
    }
    issues.extend(threat_model_issues)

    statistical_report, statistical_issues = check_statistical_analysis(root)
    sections["statistical_analysis"] = {
        "ok": statistical_report.get("ok"),
        "issue_count": statistical_report.get("issue_count", 0),
        "attack_rows": statistical_report.get("attack_rows", 0),
        "control_rows": statistical_report.get("control_rows", 0),
        "attack_success": statistical_report.get("attack_success", 0),
        "confirmed": statistical_report.get("confirmed", 0),
        "control_success": statistical_report.get("control_success", 0),
        "control_confirmed": statistical_report.get("control_confirmed", 0),
        "attack_n_minus_1_rows": statistical_report.get("attack_n_minus_1_rows", 0),
        "attack_asr_eligible_scored_rows": statistical_report.get(
            "attack_asr_eligible_scored_rows", 0
        ),
        "attack_accounted_terminal_rows": statistical_report.get(
            "attack_accounted_terminal_rows", 0
        ),
        "control_n_minus_1_rows": statistical_report.get("control_n_minus_1_rows", 0),
        "control_asr_eligible_scored_rows": statistical_report.get(
            "control_asr_eligible_scored_rows", 0
        ),
        "control_accounted_terminal_rows": statistical_report.get(
            "control_accounted_terminal_rows", 0
        ),
        "families": statistical_report.get("families", 0),
        "cases": statistical_report.get("cases", 0),
    }
    issues.extend(statistical_issues)

    claim_map_report, claim_map_issues = check_claim_evidence_map(root)
    sections["claim_evidence_map"] = {
        "ok": claim_map_report.get("ok"),
        "issue_count": claim_map_report.get("issue_count", 0),
        "claims": claim_map_report.get("claims", 0),
        "supported": claim_map_report.get("supported", 0),
        "blocked_on_release_metadata": claim_map_report.get("blocked_on_release_metadata", 0),
        "needs_attention": claim_map_report.get("needs_attention", 0),
    }
    issues.extend(claim_map_issues)

    control_integrity_report, control_integrity_issues = check_control_integrity(root)
    sections["control_integrity"] = {
        "ok": control_integrity_report.get("ok"),
        "issue_count": control_integrity_report.get("issue_count", 0),
        "control_rows": control_integrity_report.get("control_rows", 0),
        "has_oracle_rows": control_integrity_report.get("has_oracle_rows", 0),
        "attack_success_rows": control_integrity_report.get("attack_success_rows", 0),
        "confirmed_rows": control_integrity_report.get("confirmed_rows", 0),
        "timeout_rows": control_integrity_report.get("timeout_rows", 0),
        "nonzero_exit_rows": control_integrity_report.get("nonzero_exit_rows", 0),
        "critical_absent_oracle_hit_rows": control_integrity_report.get("critical_absent_oracle_hit_rows", 0),
        "scored_control_rows": control_integrity_report.get("scored_control_rows", 0),
        "model_protocol_terminal_rows": control_integrity_report.get(
            "model_protocol_terminal_rows", 0
        ),
        "accounted_terminal_rows": control_integrity_report.get(
            "accounted_terminal_rows", 0
        ),
    }
    issues.extend(control_integrity_issues)

    paper_figures_report, paper_figures_issues = check_paper_figures(root)
    sections["paper_figures"] = {
        "ok": paper_figures_report.get("ok"),
        "issue_count": paper_figures_report.get("issue_count", 0),
        "figures": paper_figures_report.get("figures", 0),
        "svg_files": paper_figures_report.get("svg_files", 0),
    }
    issues.extend(paper_figures_issues)

    release_report, release_issues = check_release_metadata_gate(root, require_license=require_kimi)
    sections["release_metadata"] = {
        "ok": release_report.get("ok"),
        "require_license": require_kimi,
        "issue_count": len(release_report.get("issues", [])),
    }
    issues.extend(release_issues)

    suite_lock_report, suite_lock_issues = check_suite_lock_gate(root)
    sections["suite_lock"] = {
        "ok": suite_lock_report.get("ok"),
        "expected_digest": suite_lock_report.get("expected_digest", ""),
        "actual_digest": suite_lock_report.get("actual_digest", ""),
        "issue_count": len(suite_lock_report.get("issues", [])),
        "case_counts": suite_lock_report.get("case_counts", {}),
    }
    issues.extend(suite_lock_issues)

    if include_historical_formal_workflow:
        allow_active_progress_drift = not require_kimi
        experiment_plan_report, experiment_plan_issues = check_experiment_plan(root)
        sections["experiment_plan"] = experiment_plan_report
        issues.extend(experiment_plan_issues)

        matrix_progress_report, matrix_progress_issues = check_matrix_progress(
            root,
            require_complete=require_kimi,
            artifact_path="docs/generated_artifacts/paper_experiment_matrix_progress.md",
            allow_active_progress_drift=allow_active_progress_drift,
            max_active_progress_drift_rows=max_active_progress_drift_rows,
        )
        sections["matrix_progress"] = matrix_progress_report
        issues.extend(matrix_progress_issues)

        claude_matrix_progress_report, claude_matrix_progress_issues = check_matrix_progress(
            root,
            require_complete=False,
            harnesses=["claude"],
            artifact_path="docs/generated_artifacts/paper_experiment_matrix_progress_claude.md",
            scope="claude_matrix_progress",
            allow_active_progress_drift=allow_active_progress_drift,
            max_active_progress_drift_rows=max_active_progress_drift_rows,
        )
        sections["claude_matrix_progress"] = claude_matrix_progress_report
        issues.extend(claude_matrix_progress_issues)

        run_queue_report, run_queue_issues = check_run_queue(
            root,
            experiment_plan_report,
            matrix_progress_report,
            allow_active_progress_drift=allow_active_progress_drift,
            max_active_progress_drift_rows=max_active_progress_drift_rows,
        )
        sections["run_queue"] = run_queue_report
        issues.extend(run_queue_issues)

        run_execution_report, run_execution_issues = check_run_execution(
            root, experiment_plan_report, run_queue_report
        )
        sections["run_execution"] = run_execution_report
        issues.extend(run_execution_issues)

        run_budget_report, run_budget_issues = check_run_budget(
            root,
            experiment_plan_report,
            matrix_progress_report,
            allow_active_progress_drift=allow_active_progress_drift,
            max_active_progress_drift_rows=max_active_progress_drift_rows,
        )
        sections["run_budget"] = run_budget_report
        issues.extend(run_budget_issues)

        submission_gap_report, submission_gap_issues = check_submission_gap(
            root,
            require_ready=require_kimi,
            allow_active_progress_drift=allow_active_progress_drift,
            max_active_progress_drift_rows=max_active_progress_drift_rows,
        )
        sections["submission_gap"] = submission_gap_report
        issues.extend(submission_gap_issues)

    submission_objective_report, submission_objective_issues = check_submission_objective_audit(
        root,
        require_ready=require_kimi,
    )
    sections["submission_objective"] = submission_objective_report
    issues.extend(submission_objective_issues)

    submission_package_report, submission_package_issues = check_submission_package_manifest(root)
    sections["submission_package"] = submission_package_report
    issues.extend(submission_package_issues)

    if include_historical_formal_workflow:
        live_status_report, live_status_issues = check_live_status_artifacts(
            root,
            allow_active_status_drift=not require_kimi,
        )
        sections["live_status"] = live_status_report
        issues.extend(live_status_issues)

    issues.extend(check_report_files("attack", attack_dirs))
    issues.extend(check_report_files("control", control_dirs))
    if attack_dirs or control_dirs:
        quality = check_paper_results.build_quality_report(
            attack_dirs[0] if attack_dirs else None,
            control_dirs,
            case_set,
            min_attack_trials,
            min_control_trials,
            control_types or [],
            allow_partial=False,
            max_timeouts=max_timeouts,
            max_control_violation_rate=0.0,
            expected_harnesses=expected_harnesses or [],
        )
        sections["result_quality"] = {
            "ok": quality.get("ok"),
            "summaries": quality.get("summaries", {}),
            "expected_harnesses": quality.get("expected_harnesses", []),
            "max_timeouts": quality.get("max_timeouts", max_timeouts),
        }
        for item in quality.get("issues", []):
            issues.append(item)

    issues.extend(check_table_dir(table_dir))
    issues.extend(check_bundle_dir(bundle_dir, root=root, submission_profile=require_kimi))
    if bundle_dir is not None and bundle_dir.is_dir():
        safety_report, safety_issues = check_public_artifact_safety_gate(bundle_dir)
        sections["public_artifact_safety"] = {
            "ok": safety_report.get("ok"),
            "file_count": safety_report.get("summary", {}).get("file_count", 0),
            "issue_count": len(safety_report.get("issues", [])),
        }
        issues.extend(safety_issues)
    issues.extend(check_case_evidence_dir(case_evidence_dir))
    case_study_report, case_study_issues = check_case_studies_gate(root=root, case_evidence_dir=case_evidence_dir)
    sections["case_studies"] = {
        "ok": case_study_report.get("ok"),
        "issue_count": len(case_study_report.get("issues", [])),
        "case_count": case_study_report.get("case_count", 0),
        "attack_row_count": case_study_report.get("attack_row_count", 0),
        "recommended_main_paper_count": case_study_report.get("recommended_main_paper_count", 0),
    }
    issues.extend(case_study_issues)
    number_report, number_issues = check_paper_numbers_gate(
        root=root,
        attack_dirs=attack_dirs,
        control_dirs=control_dirs,
        table_dir=table_dir,
        case_evidence_dir=case_evidence_dir,
    )
    sections["paper_numbers"] = {
        "ok": number_report.get("ok"),
        "issue_count": len(number_report.get("issues", [])),
        "attack_rows": number_report.get("numbers", {}).get("attack", {}).get("rows", 0),
        "control_rows": number_report.get("numbers", {}).get("control", {}).get("rows", 0),
        "case_study_cases": number_report.get("numbers", {}).get("case_evidence", {}).get("case_count", 0),
    }
    issues.extend(number_issues)
    issues.extend(check_docs(root))

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "case_set": case_set,
        "min_attack_trials": min_attack_trials,
        "min_control_trials": min_control_trials,
        "submission_profile": require_kimi,
        "require_kimi": require_kimi,
        "sections": sections,
        "issues": issues,
        "ok": not any(item.get("severity") == "error" for item in issues),
    }


def display_optional(value: Any) -> Any:
    return "n/a" if value is None else value


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Paper Artifact Gate",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- case_set: `{report['case_set']}`",
        f"- min_attack_trials: `{report['min_attack_trials']}`",
        f"- min_control_trials: `{report['min_control_trials']}`",
        f"- submission_profile: `{str(report.get('submission_profile', report.get('require_kimi', False))).lower()}`",
        f"- ok: `{str(report['ok']).lower()}`",
        "",
        "## Sections",
        "",
    ]
    readiness = report.get("sections", {}).get("readiness")
    if readiness:
        lines += [
            f"- readiness: ready=`{str(readiness.get('ready')).lower()}`; "
            f"blockers={len(readiness.get('blockers', []))}; warnings={len(readiness.get('warnings', []))}",
        ]
    result_quality = report.get("sections", {}).get("result_quality")
    if result_quality:
        lines.append(f"- result_quality: ok=`{str(result_quality.get('ok')).lower()}`")
        expected_harnesses = result_quality.get("expected_harnesses", [])
        if expected_harnesses:
            lines.append(f"  - expected_harnesses: `{','.join(expected_harnesses)}`")
        if "max_timeouts" in result_quality:
            lines.append(f"  - max_timeouts: `{result_quality.get('max_timeouts')}`")
        for name, summary in result_quality.get("summaries", {}).items():
            lines.append(
                f"  - {name}: completed={summary.get('completed_rows', 0)} expected={summary.get('expected_rows', 0)}"
            )
    paper_numbers = report.get("sections", {}).get("paper_numbers")
    if paper_numbers:
        lines.append(
            f"- paper_numbers: ok=`{str(paper_numbers.get('ok')).lower()}`; "
            f"attack_rows={paper_numbers.get('attack_rows', 0)}; "
            f"control_rows={paper_numbers.get('control_rows', 0)}; "
            f"case_study_cases={paper_numbers.get('case_study_cases', 0)}; "
            f"issues={paper_numbers.get('issue_count', 0)}"
        )
    case_studies = report.get("sections", {}).get("case_studies")
    if case_studies:
        lines.append(
            f"- case_studies: ok=`{str(case_studies.get('ok')).lower()}`; "
            f"cases={case_studies.get('case_count', 0)}; "
            f"attack_rows={case_studies.get('attack_row_count', 0)}; "
            f"recommended={case_studies.get('recommended_main_paper_count', 0)}; "
            f"issues={case_studies.get('issue_count', 0)}"
        )
    claim_boundary = report.get("sections", {}).get("claim_boundary")
    if claim_boundary:
        lines.append(
            f"- claim_boundary: ok=`{str(claim_boundary.get('ok')).lower()}`; "
            f"profile=`{claim_boundary.get('profile')}`; issues={claim_boundary.get('issue_count', 0)}"
        )
    manuscript = report.get("sections", {}).get("manuscript")
    if manuscript:
        lines.append(
            f"- manuscript: ok=`{str(manuscript.get('ok')).lower()}`; "
            f"sections={manuscript.get('required_sections', 0)}; "
            f"phrases={manuscript.get('required_phrases', 0)}; "
            f"table_rows={manuscript.get('markdown_table_rows', 0)}; "
            f"issues={manuscript.get('issue_count', 0)}"
        )
    bibliography = report.get("sections", {}).get("bibliography")
    if bibliography:
        lines.append(
            f"- bibliography: ok=`{str(bibliography.get('ok')).lower()}`; "
            f"required={bibliography.get('required_keys', 0)}; "
            f"bib_keys={bibliography.get('bib_keys', 0)}; "
            f"cited={bibliography.get('cited_keys', 0)}; "
            f"unknown={bibliography.get('unknown_cited_keys', 0)}; "
            f"issues={bibliography.get('issue_count', 0)}"
        )
    full_suite_eligibility = report.get("sections", {}).get("full_suite_eligibility")
    if full_suite_eligibility:
        lines.append(
            f"- full_suite_eligibility: ok=`{str(full_suite_eligibility.get('ok')).lower()}`; "
            f"active={full_suite_eligibility.get('active_cases', 0)}; "
            f"main_asr={full_suite_eligibility.get('main_asr_cases', 0)}; "
            f"core={full_suite_eligibility.get('core_cases', 0)}; "
            f"extended={full_suite_eligibility.get('extended_cases', 0)}; "
            f"exploratory={full_suite_eligibility.get('exploratory_cases', 0)}; "
            f"case_rows={full_suite_eligibility.get('case_rows', 0)}; "
            f"issues={full_suite_eligibility.get('issue_count', 0)}"
        )
    external_validity_plan = report.get("sections", {}).get("external_validity_plan")
    if external_validity_plan:
        lines.append(
            f"- external_validity_plan: ok=`{str(external_validity_plan.get('ok')).lower()}`; "
            f"active={external_validity_plan.get('active_cases', 0)}; "
            f"candidates={external_validity_plan.get('candidate_cases', 0)}; "
            f"selected={external_validity_plan.get('selected_cases', 0)}; "
            f"per_suite={external_validity_plan.get('per_suite_target', 0)}; "
            f"issues={external_validity_plan.get('issue_count', 0)}"
        )
    benchmark_card = report.get("sections", {}).get("benchmark_card")
    if benchmark_card:
        lines.append(
            f"- benchmark_card: ok=`{str(benchmark_card.get('ok')).lower()}`; "
            f"baseline=`{benchmark_card.get('baseline', '')}`; "
            f"total_rows={benchmark_card.get('total_rows', 0)}; "
            f"scored_attack={benchmark_card.get('scored_attack_rows', 0)}; "
            f"N-1_attack={benchmark_card.get('n_minus_1_attack_rows', 0)}; "
            f"accounted_attack={benchmark_card.get('accounted_terminal_attack_rows', 0)}; "
            f"protocol_completion={display_optional(benchmark_card.get('protocol_completion_rate'))}; "
            f"model_nonconformance={display_optional(benchmark_card.get('model_nonconformance_rate'))}; "
            f"conditional_asr={display_optional(benchmark_card.get('conditional_asr_rate'))}; "
            f"end_to_end={display_optional(benchmark_card.get('end_to_end_attack_rate'))}; "
            f"issues={benchmark_card.get('issue_count', 0)}"
        )
    supplementary_appendix = report.get("sections", {}).get("supplementary_appendix")
    if supplementary_appendix:
        lines.append(
            f"- supplementary_appendix: ok=`{str(supplementary_appendix.get('ok')).lower()}`; "
            f"families={supplementary_appendix.get('family_rows', 0)}; "
            f"cases={supplementary_appendix.get('case_rows', 0)}; "
            f"issues={supplementary_appendix.get('issue_count', 0)}"
        )
    oracle_coverage = report.get("sections", {}).get("oracle_coverage")
    if oracle_coverage:
        lines.append(
            f"- oracle_coverage: ok=`{str(oracle_coverage.get('ok')).lower()}`; "
            f"cases={oracle_coverage.get('case_count', 0)}; "
            f"attack_rows={oracle_coverage.get('attack_rows', 0)}; "
            f"hard={oracle_coverage.get('hard_trace_cases', 0)}; "
            f"propagation={oracle_coverage.get('propagation_only_cases', 0)}; "
            f"soft={oracle_coverage.get('soft_semantic_cases', 0)}; "
            f"issues={oracle_coverage.get('issue_count', 0)}"
        )
    threat_model_card = report.get("sections", {}).get("threat_model_card")
    if threat_model_card:
        lines.append(
            f"- threat_model_card: ok=`{str(threat_model_card.get('ok')).lower()}`; "
            f"cases={threat_model_card.get('case_count', 0)}; "
            f"suites={threat_model_card.get('suite_rows', 0)}; "
            f"controls={threat_model_card.get('control_cases', 0)}; "
            f"frame_dimensions={threat_model_card.get('frame_dimensions', 0)}; "
            f"issues={threat_model_card.get('issue_count', 0)}"
        )
    statistical_analysis = report.get("sections", {}).get("statistical_analysis")
    if statistical_analysis:
        lines.append(
            f"- statistical_analysis: ok=`{str(statistical_analysis.get('ok')).lower()}`; "
            f"attack_rows={statistical_analysis.get('attack_rows', 0)}; "
            f"control_rows={statistical_analysis.get('control_rows', 0)}; "
            f"attack_success={statistical_analysis.get('attack_success', 0)}; "
            f"attack_N-1={statistical_analysis.get('attack_n_minus_1_rows', 0)}; "
            f"attack_ASR_eligible={statistical_analysis.get('attack_asr_eligible_scored_rows', 0)}; "
            f"attack_accounted={statistical_analysis.get('attack_accounted_terminal_rows', 0)}; "
            f"confirmed={statistical_analysis.get('confirmed', 0)}; "
            f"control_success={statistical_analysis.get('control_success', 0)}; "
            f"issues={statistical_analysis.get('issue_count', 0)}"
        )
    claim_evidence_map = report.get("sections", {}).get("claim_evidence_map")
    if claim_evidence_map:
        lines.append(
            f"- claim_evidence_map: ok=`{str(claim_evidence_map.get('ok')).lower()}`; "
            f"claims={claim_evidence_map.get('claims', 0)}; "
            f"supported={claim_evidence_map.get('supported', 0)}; "
            f"blocked_release={claim_evidence_map.get('blocked_on_release_metadata', 0)}; "
            f"needs_attention={claim_evidence_map.get('needs_attention', 0)}; "
            f"issues={claim_evidence_map.get('issue_count', 0)}"
        )
    control_integrity = report.get("sections", {}).get("control_integrity")
    if control_integrity:
        lines.append(
            f"- control_integrity: ok=`{str(control_integrity.get('ok')).lower()}`; "
            f"rows={control_integrity.get('control_rows', 0)}; "
            f"scored={control_integrity.get('scored_control_rows', 0)}; "
            f"N-1={control_integrity.get('model_protocol_terminal_rows', 0)}; "
            f"accounted={control_integrity.get('accounted_terminal_rows', 0)}; "
            f"oracle_rows={control_integrity.get('has_oracle_rows', 0)}; "
            f"attack_success={control_integrity.get('attack_success_rows', 0)}; "
            f"confirmed={control_integrity.get('confirmed_rows', 0)}; "
            f"timeouts={control_integrity.get('timeout_rows', 0)}; "
            f"nonzero_exits={control_integrity.get('nonzero_exit_rows', 0)}; "
            f"signal_hit_rows={control_integrity.get('critical_absent_oracle_hit_rows', 0)}; "
            f"issues={control_integrity.get('issue_count', 0)}"
        )
    paper_figures = report.get("sections", {}).get("paper_figures")
    if paper_figures:
        lines.append(
            f"- paper_figures: ok=`{str(paper_figures.get('ok')).lower()}`; "
            f"figures={paper_figures.get('figures', 0)}; "
            f"svg_files={paper_figures.get('svg_files', 0)}; "
            f"issues={paper_figures.get('issue_count', 0)}"
        )
    release_metadata = report.get("sections", {}).get("release_metadata")
    if release_metadata:
        lines.append(
            f"- release_metadata: ok=`{str(release_metadata.get('ok')).lower()}`; "
            f"require_license=`{str(release_metadata.get('require_license')).lower()}`; "
            f"issues={release_metadata.get('issue_count', 0)}"
        )
    suite_lock = report.get("sections", {}).get("suite_lock")
    if suite_lock:
        lines.append(
            f"- suite_lock: ok=`{str(suite_lock.get('ok')).lower()}`; "
            f"issues={suite_lock.get('issue_count', 0)}; "
            f"digest=`{str(suite_lock.get('actual_digest') or '')[:16]}`"
        )
    public_artifact_safety = report.get("sections", {}).get("public_artifact_safety")
    if public_artifact_safety:
        lines.append(
            f"- public_artifact_safety: ok=`{str(public_artifact_safety.get('ok')).lower()}`; "
            f"files={public_artifact_safety.get('file_count', 0)}; "
            f"issues={public_artifact_safety.get('issue_count', 0)}"
        )
    experiment_plan = report.get("sections", {}).get("experiment_plan")
    if experiment_plan:
        summary = experiment_plan.get("summary", {})
        lines.append(
            f"- experiment_plan: ok=`{str(experiment_plan.get('ok')).lower()}`; "
            f"matrix_id=`{experiment_plan.get('matrix_id')}`; "
            f"rows={summary.get('rows_total', 0)}; issues={experiment_plan.get('issue_count', 0)}"
        )
    matrix_progress = report.get("sections", {}).get("matrix_progress")
    if matrix_progress:
        lines.append(
            f"- matrix_progress: complete=`{str(matrix_progress.get('complete')).lower()}`; "
            f"completed={matrix_progress.get('completed_rows', 0)}/{matrix_progress.get('expected_rows', 0)}; "
            f"issues={matrix_progress.get('issue_count', 0)}"
        )
    claude_matrix_progress = report.get("sections", {}).get("claude_matrix_progress")
    if claude_matrix_progress:
        lines.append(
            f"- claude_matrix_progress: complete=`{str(claude_matrix_progress.get('complete')).lower()}`; "
            f"completed={claude_matrix_progress.get('completed_rows', 0)}/{claude_matrix_progress.get('expected_rows', 0)}; "
            f"issues={claude_matrix_progress.get('issue_count', 0)}"
        )
    run_queue = report.get("sections", {}).get("run_queue")
    if run_queue:
        lines.append(
            f"- run_queue: ok=`{str(run_queue.get('ok')).lower()}`; "
            f"missing={run_queue.get('missing_rows', 0)}; "
            f"coalesced={run_queue.get('coalesced_batch_count', 0)}; "
            f"batches={run_queue.get('batch_count', 0)}; "
            f"issues={run_queue.get('issue_count', 0)}"
        )
    run_execution = report.get("sections", {}).get("run_execution")
    if run_execution:
        lines.append(
            f"- run_execution: ok=`{str(run_execution.get('ok')).lower()}`; "
            f"queue_mode=`{run_execution.get('queue_mode', '')}`; "
            f"selected={run_execution.get('selected_commands', 0)}; "
            f"executed={run_execution.get('executed_commands', 0)}; "
            f"pending={run_execution.get('pending_commands', 0)}; "
            f"requires_kimi=`{str(run_execution.get('requires_kimi')).lower()}`; "
            f"issues={run_execution.get('issue_count', 0)}"
        )
    run_budget = report.get("sections", {}).get("run_budget")
    if run_budget:
        lines.append(
            f"- run_budget: ok=`{str(run_budget.get('ok')).lower()}`; "
            f"missing={run_budget.get('missing_rows', 0)}; "
            f"estimate=`{run_budget.get('estimated_missing_human', '')}`; "
            f"buffer=`{run_budget.get('buffered_missing_human', '')}`; "
            f"issues={run_budget.get('issue_count', 0)}"
        )
    submission_gap = report.get("sections", {}).get("submission_gap")
    if submission_gap:
        lines.append(
            f"- submission_gap: ok=`{str(submission_gap.get('ok')).lower()}`; "
            f"submission_ready=`{str(display_optional(submission_gap.get('submission_ready'))).lower()}`; "
            f"errors={submission_gap.get('errors', 0)}; "
            f"raw_errors={submission_gap.get('raw_error_occurrences', 0)}; "
            f"pending_manual_decisions={submission_gap.get('pending_manual_decisions', 0)}; "
            f"blocking_manual_decisions={submission_gap.get('blocking_manual_decisions', 0)}; "
            f"issues={submission_gap.get('issue_count', 0)}"
        )
    submission_objective = report.get("sections", {}).get("submission_objective")
    if submission_objective:
        lines.append(
            f"- submission_objective: ok=`{str(submission_objective.get('ok')).lower()}`; "
            f"submission_ready=`{str(display_optional(submission_objective.get('submission_ready'))).lower()}`; "
            f"required={submission_objective.get('required_complete', 0)}/{submission_objective.get('required_total', 0)}; "
            f"blocked={submission_objective.get('required_blocked', 0)}; "
            f"pending={submission_objective.get('required_pending', 0)}; "
            f"enhancements={submission_objective.get('enhancements_complete', 0)}/{submission_objective.get('enhancements_total', 0)}; "
            f"issues={submission_objective.get('issue_count', 0)}"
        )
    submission_package = report.get("sections", {}).get("submission_package")
    if submission_package:
        lines.append(
            f"- submission_package: ok=`{str(submission_package.get('ok')).lower()}`; "
            f"files={submission_package.get('file_records', 0)}; "
            f"hashed={submission_package.get('hashed_records', 0)}; "
            f"missing={submission_package.get('missing_files', 0)}; "
            f"attack_reports={submission_package.get('attack_report_records', 0)}; "
            f"control_reports={submission_package.get('control_report_records', 0)}; "
            f"tables={submission_package.get('paper_table_records', 0)}; "
            f"case_evidence={submission_package.get('case_evidence_records', 0)}; "
            f"issues={submission_package.get('issue_count', 0)}"
        )
    live_status = report.get("sections", {}).get("live_status")
    if live_status:
        lines.append(
            f"- live_status: ok=`{str(live_status.get('ok')).lower()}`; "
            f"generated_at=`{live_status.get('generated_at', '')}`; "
            f"check_ok=`{live_status.get('check_ok', '')}`; "
            f"history_samples={live_status.get('history_sample_count', 0)}; "
            f"failure_markers={live_status.get('unresolved_failure_marker_count', 0)}/{live_status.get('failure_marker_count', 0)}; "
            f"issues={live_status.get('issue_count', 0)}"
        )
    if (
        not readiness
        and not result_quality
        and not paper_numbers
        and not claim_boundary
        and not manuscript
        and not bibliography
        and not full_suite_eligibility
        and not benchmark_card
        and not supplementary_appendix
        and not release_metadata
        and not suite_lock
        and not public_artifact_safety
        and not experiment_plan
        and not matrix_progress
        and not claude_matrix_progress
        and not run_queue
        and not run_execution
        and not run_budget
        and not submission_gap
        and not submission_objective
        and not submission_package
        and not live_status
    ):
        lines.append("- none")

    lines += ["", "## Issues", ""]
    if report["issues"]:
        lines += [
            "| Severity | Scope | Message |",
            "| --- | --- | --- |",
        ]
        for item in report["issues"]:
            lines.append(f"| {item['severity']} | {item['scope']} | {item['message']} |")
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the aggregate paper artifact gate.")
    parser.add_argument("--attack-label", action="append", default=[])
    parser.add_argument("--attack-report-dir", action="append", default=[])
    parser.add_argument("--control-label", action="append", default=[])
    parser.add_argument("--control-report-dir", action="append", default=[])
    parser.add_argument("--table-dir", default="")
    parser.add_argument("--bundle-dir", default="")
    parser.add_argument("--case-evidence-dir", default="")
    parser.add_argument("--case-set", default="all", choices=list(check_paper_results.EXPECTED_CASE_COUNTS))
    parser.add_argument("--min-attack-trials", type=int, default=1)
    parser.add_argument("--min-control-trials", type=int, default=1)
    parser.add_argument("--control-type", action="append", dest="control_types")
    parser.add_argument("--expected-harness", action="append", default=[])
    parser.add_argument("--max-timeouts", type=int, default=0)
    parser.add_argument("--max-active-progress-drift-rows", type=int, default=DEFAULT_ACTIVE_PROGRESS_DRIFT_ROWS)
    parser.add_argument(
        "--submission-profile",
        action="store_true",
        help="Require final release metadata and submission claim boundaries for the current v3 artifact.",
    )
    parser.add_argument("--require-kimi", action="store_true", help="Deprecated alias for --submission-profile.")
    parser.add_argument(
        "--include-historical-formal-workflow",
        action="store_true",
        help="Also validate the optional legacy 3-trial/2,296-row plan, queue, and live-status artifacts.",
    )
    parser.add_argument("--skip-readiness", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    attack_dirs = report_dirs(args.attack_label, args.attack_report_dir, ROOT)
    control_dirs = report_dirs(args.control_label, args.control_report_dir, ROOT)
    table_dir = Path(args.table_dir) if args.table_dir else None
    bundle_dir = Path(args.bundle_dir) if args.bundle_dir else None
    case_evidence_dir = Path(args.case_evidence_dir) if args.case_evidence_dir else None
    control_types = check_paper_results.expand_control_types(args.control_types)
    expected_harnesses = check_paper_results.expand_expected_harnesses(args.expected_harness)
    report = build_artifact_gate(
        root=ROOT,
        attack_dirs=attack_dirs,
        control_dirs=control_dirs,
        table_dir=table_dir,
        bundle_dir=bundle_dir,
        case_evidence_dir=case_evidence_dir,
        case_set=args.case_set,
        min_attack_trials=args.min_attack_trials,
        min_control_trials=args.min_control_trials,
        control_types=control_types,
        expected_harnesses=expected_harnesses,
        require_kimi=args.submission_profile or args.require_kimi,
        skip_readiness=args.skip_readiness,
        max_active_progress_drift_rows=args.max_active_progress_drift_rows,
        max_timeouts=args.max_timeouts,
        include_historical_formal_workflow=args.include_historical_formal_workflow,
    )
    text = json.dumps(report, indent=2, ensure_ascii=False) if args.json else render_markdown(report)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
