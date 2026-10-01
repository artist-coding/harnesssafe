"""Build a reproducibility manifest for paper experiment artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from infra.check_paper_readiness import build_readiness
    from infra.export_paper_tables import report_dirs_from, safe_slug, split_cli_values
except ModuleNotFoundError:  # direct `python infra/build_repro_bundle.py`
    from check_paper_readiness import build_readiness
    from export_paper_tables import report_dirs_from, safe_slug, split_cli_values


ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"
CURRENT_PROFILE_MAX_TIMEOUTS = 3

REPORT_FILES = [
    "summary.json",
    "report.md",
    "results.csv",
    "case_summary.csv",
    "family_macro.csv",
    "harness_macro.csv",
    "failures.json",
]

OPTIONAL_REPORT_FILES = [
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

CASE_STUDY_EVIDENCE_FILES = [
    "case_study_evidence.json",
    "case_study_evidence.md",
]

BENCHMARK_CARD_FILES = [
    "docs/generated_artifacts/benchmark_card.json",
    "docs/generated_artifacts/benchmark_card.md",
]

SUPPLEMENTARY_APPENDIX_FILES = [
    "docs/generated_artifacts/paper_supplementary_appendix.json",
    "docs/generated_artifacts/paper_supplementary_appendix.md",
    "docs/generated_artifacts/paper_supplementary_appendix.tex",
]

ORACLE_COVERAGE_FILES = [
    "docs/generated_artifacts/paper_oracle_coverage.json",
    "docs/generated_artifacts/paper_oracle_coverage.md",
]

THREAT_MODEL_CARD_FILES = [
    "docs/generated_artifacts/paper_threat_model_card.json",
    "docs/generated_artifacts/paper_threat_model_card.md",
]

STATISTICAL_ANALYSIS_FILES = [
    "docs/generated_artifacts/paper_statistical_analysis.json",
    "docs/generated_artifacts/paper_statistical_analysis.md",
]

CLAIM_EVIDENCE_MAP_FILES = [
    "docs/generated_artifacts/paper_claim_evidence_map.json",
    "docs/generated_artifacts/paper_claim_evidence_map.md",
]

CONTROL_INTEGRITY_FILES = [
    "docs/generated_artifacts/paper_control_integrity_report.json",
    "docs/generated_artifacts/paper_control_integrity_report.md",
]

PAPER_FIGURE_FILES = [
    "docs/generated_artifacts/paper_figures.json",
    "docs/generated_artifacts/paper_figures.md",
    "docs/figures/figure_1_benchmark_frame.svg",
    "docs/generated_artifacts/figures/figure_2_core_results.svg",
]

BIBLIOGRAPHY_CHECK_FILES = [
    "docs/generated_artifacts/paper_bibliography_check.json",
    "docs/generated_artifacts/paper_bibliography_check.md",
]

MANUSCRIPT_FILES = [
    "docs/paper_draft.md",
]

FULL_SUITE_ELIGIBILITY_FILES = [
    "docs/generated_artifacts/paper_full_suite_eligibility.json",
    "docs/generated_artifacts/paper_full_suite_eligibility.md",
]

EXTERNAL_VALIDITY_PLAN_FILES = [
    "docs/generated_artifacts/paper_external_validity_plan.json",
    "docs/generated_artifacts/paper_external_validity_plan.md",
]

SUITE_LOCK_FILES = [
    "docs/generated_artifacts/paper_suite_lock.json",
]

EXPERIMENT_PLAN_FILES = [
    "docs/generated_artifacts/paper_experiment_matrix_plan.json",
    "docs/generated_artifacts/paper_experiment_matrix_plan.md",
]

MATRIX_PROGRESS_FILES = [
    "docs/generated_artifacts/paper_experiment_matrix_progress.md",
]

OPTIONAL_MATRIX_PROGRESS_FILES = [
    "docs/generated_artifacts/paper_experiment_matrix_progress_claude.md",
]

RUN_QUEUE_FILES = [
    "docs/generated_artifacts/paper_run_queue.json",
    "docs/generated_artifacts/paper_run_queue.md",
    "docs/generated_artifacts/paper_failure_marker_resume.md",
    "docs/generated_artifacts/paper_failure_marker_resume_cases.txt",
]

RUN_EXECUTION_FILES = [
    "docs/generated_artifacts/paper_run_execution_plan.json",
    "docs/generated_artifacts/paper_run_execution_plan.md",
]

OPTIONAL_RUN_EXECUTION_FILES = [
    "docs/generated_artifacts/paper_run_execution_claude_plan.json",
    "docs/generated_artifacts/paper_run_execution_claude_plan.md",
    "docs/generated_artifacts/paper_run_execution_claude_dry_run.json",
    "docs/generated_artifacts/paper_run_execution_claude_dry_run.md",
    "docs/generated_artifacts/paper_run_execution_claude_post_run.json",
    "docs/generated_artifacts/paper_run_execution_claude_post_run.md",
    "docs/generated_artifacts/paper_run_execution_claude_post_run_dry_run.json",
    "docs/generated_artifacts/paper_run_execution_claude_post_run_dry_run.md",
    "docs/generated_artifacts/paper_run_execution_codex_plan.json",
    "docs/generated_artifacts/paper_run_execution_codex_plan.md",
]

OUT_OF_SCOPE_RUN_EXECUTION_FILES = {
    "docs/generated_artifacts/paper_run_execution_codex_plan.json",
    "docs/generated_artifacts/paper_run_execution_codex_plan.md",
}

EXECUTE_RUN_EXECUTION_JSONS = {
    "docs/generated_artifacts/paper_run_execution_claude_plan.json",
    "docs/generated_artifacts/paper_run_execution_claude_post_run.json",
}

RUN_BUDGET_FILES = [
    "docs/generated_artifacts/paper_run_budget.json",
    "docs/generated_artifacts/paper_run_budget.md",
]

SUBMISSION_GAP_FILES = [
    "docs/generated_artifacts/paper_submission_gap_report.md",
    "docs/generated_artifacts/paper_submission_gap_report.json",
]

SUBMISSION_OBJECTIVE_AUDIT_FILES = [
    "docs/generated_artifacts/paper_submission_objective_audit.md",
    "docs/generated_artifacts/paper_submission_objective_audit.json",
]

SUBMISSION_PACKAGE_FILES = [
    "docs/generated_artifacts/paper_submission_package_manifest.json",
    "docs/generated_artifacts/paper_submission_package_manifest.md",
]

LIVE_STATUS_FILES = [
    "docs/generated_artifacts/paper_live_status.json",
    "docs/generated_artifacts/paper_live_status.md",
    "docs/generated_artifacts/paper_live_status_check.md",
]

OPTIONAL_LIVE_STATUS_FILES = [
    "docs/generated_artifacts/paper_live_status_history.jsonl",
]

RELEASE_METADATA_FILES = [
    "CITATION.cff",
    "docs/release_metadata_final.json",
    "docs/paper_artifact_evaluation_readme.md",
]

OPTIONAL_RELEASE_METADATA_FILES = [
    "LICENSE",
    "LICENSE.md",
    "COPYING",
    "COPYING.md",
]


def run_git(args: list[str]) -> str:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return f"unavailable: {exc}"
    output = (proc.stdout or proc.stderr or "").strip()
    return output


def filter_git_status_short(status: list[str]) -> list[str]:
    excluded_suffixes = tuple(OUT_OF_SCOPE_RUN_EXECUTION_FILES)
    return [
        line
        for line in status
        if not line.strip().replace("\\", "/").endswith(excluded_suffixes)
    ]


def git_state() -> dict[str, Any]:
    status = filter_git_status_short(run_git(["status", "--short"]).splitlines())
    return {
        "commit": run_git(["rev-parse", "HEAD"]),
        "branch": run_git(["branch", "--show-current"]),
        "dirty": bool(status),
        "status_short": status,
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relpath(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve())).replace("\\", "/")
    except ValueError:
        return str(path)


def artifact_record(path: Path, role: str) -> dict[str, Any]:
    return {
        "role": role,
        "path": relpath(path),
        "exists": path.is_file(),
        "bytes": path.stat().st_size if path.is_file() else 0,
        "sha256": sha256(path) if path.is_file() else "",
    }


def collect_report_artifacts(report_dir: Path, role: str) -> list[dict[str, Any]]:
    records = [artifact_record(report_dir / name, f"{role}:{name}") for name in REPORT_FILES]
    for name in OPTIONAL_REPORT_FILES:
        path = report_dir / name
        if path.is_file():
            records.append(artifact_record(path, f"{role}:{name}"))
    return records


def normalize_report_dirs(value: Path | list[Path] | tuple[Path, ...] | None) -> list[Path]:
    if value is None:
        return []
    if isinstance(value, Path):
        return [value]
    return [Path(item) for item in value]


def normalize_labels(value: str | list[str] | tuple[str, ...]) -> list[str]:
    if isinstance(value, str):
        return split_cli_values([value])
    return split_cli_values(value)


def unique_nonempty(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        token = str(value or "")
        if token and token not in out:
            out.append(token)
    return out


def report_label_from_summary(report_dir_path: Path) -> str:
    summary_path = report_dir_path / "summary.json"
    if summary_path.is_file():
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8-sig"))
            label = str(summary.get("label") or "")
            if label:
                return label
        except (OSError, json.JSONDecodeError):
            pass
    return report_dir_path.name


def report_control_types_from_summary(report_dir_path: Path) -> list[str]:
    summary_path = report_dir_path / "summary.json"
    if summary_path.is_file():
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8-sig"))
            return unique_nonempty([str(item or "") for item in summary.get("control_types", [])])
        except (OSError, json.JSONDecodeError):
            pass
    return []


def collect_table_artifacts(table_dir: Path) -> list[dict[str, Any]]:
    return [artifact_record(table_dir / name, f"tables:{name}") for name in TABLE_FILES]


def collect_release_metadata_artifacts() -> list[dict[str, Any]]:
    records = [artifact_record(ROOT / name, f"release_metadata:{name}") for name in RELEASE_METADATA_FILES]
    for name in OPTIONAL_RELEASE_METADATA_FILES:
        path = ROOT / name
        if path.is_file():
            records.append(artifact_record(path, f"release_metadata:{name}"))
    return records


def collect_case_study_evidence_artifacts(case_evidence_dir: Path) -> list[dict[str, Any]]:
    return [
        artifact_record(case_evidence_dir / name, f"case_study_evidence:{name}")
        for name in CASE_STUDY_EVIDENCE_FILES
    ]


def collect_benchmark_card_artifacts() -> list[dict[str, Any]]:
    return [artifact_record(ROOT / name, f"benchmark_card:{name}") for name in BENCHMARK_CARD_FILES]


def collect_supplementary_appendix_artifacts() -> list[dict[str, Any]]:
    return [
        artifact_record(ROOT / name, f"supplementary_appendix:{name}")
        for name in SUPPLEMENTARY_APPENDIX_FILES
    ]


def collect_oracle_coverage_artifacts() -> list[dict[str, Any]]:
    return [artifact_record(ROOT / name, f"oracle_coverage:{name}") for name in ORACLE_COVERAGE_FILES]


def collect_threat_model_card_artifacts() -> list[dict[str, Any]]:
    return [artifact_record(ROOT / name, f"threat_model_card:{name}") for name in THREAT_MODEL_CARD_FILES]


def collect_statistical_analysis_artifacts() -> list[dict[str, Any]]:
    return [artifact_record(ROOT / name, f"statistical_analysis:{name}") for name in STATISTICAL_ANALYSIS_FILES]


def collect_claim_evidence_map_artifacts() -> list[dict[str, Any]]:
    return [artifact_record(ROOT / name, f"claim_evidence_map:{name}") for name in CLAIM_EVIDENCE_MAP_FILES]


def collect_control_integrity_artifacts() -> list[dict[str, Any]]:
    return [artifact_record(ROOT / name, f"control_integrity:{name}") for name in CONTROL_INTEGRITY_FILES]


def collect_paper_figure_artifacts() -> list[dict[str, Any]]:
    return [artifact_record(ROOT / name, f"paper_figures:{name}") for name in PAPER_FIGURE_FILES]


def collect_bibliography_check_artifacts() -> list[dict[str, Any]]:
    return [artifact_record(ROOT / name, f"bibliography_check:{name}") for name in BIBLIOGRAPHY_CHECK_FILES]


def collect_manuscript_artifacts() -> list[dict[str, Any]]:
    return [artifact_record(ROOT / name, f"manuscript:{name}") for name in MANUSCRIPT_FILES]


def collect_full_suite_eligibility_artifacts() -> list[dict[str, Any]]:
    return [
        artifact_record(ROOT / name, f"full_suite_eligibility:{name}")
        for name in FULL_SUITE_ELIGIBILITY_FILES
    ]


def collect_external_validity_plan_artifacts() -> list[dict[str, Any]]:
    return [
        artifact_record(ROOT / name, f"external_validity_plan:{name}")
        for name in EXTERNAL_VALIDITY_PLAN_FILES
    ]


def collect_suite_lock_artifacts() -> list[dict[str, Any]]:
    return [artifact_record(ROOT / name, f"suite_lock:{name}") for name in SUITE_LOCK_FILES]


def collect_experiment_plan_artifacts() -> list[dict[str, Any]]:
    return [artifact_record(ROOT / name, f"experiment_plan:{name}") for name in EXPERIMENT_PLAN_FILES]


def collect_matrix_progress_artifacts() -> list[dict[str, Any]]:
    records = [artifact_record(ROOT / name, f"matrix_progress:{name}") for name in MATRIX_PROGRESS_FILES]
    for name in OPTIONAL_MATRIX_PROGRESS_FILES:
        path = ROOT / name
        if path.is_file():
            records.append(artifact_record(path, f"matrix_progress:{name}"))
    return records


def collect_run_queue_artifacts() -> list[dict[str, Any]]:
    return [artifact_record(ROOT / name, f"run_queue:{name}") for name in RUN_QUEUE_FILES]


def collect_run_execution_artifacts(*, require_kimi: bool = True) -> list[dict[str, Any]]:
    records = [artifact_record(ROOT / name, f"run_execution:{name}") for name in RUN_EXECUTION_FILES]
    for name in OPTIONAL_RUN_EXECUTION_FILES:
        path = ROOT / name
        if path.is_file() and should_include_optional_run_execution(name, require_kimi=require_kimi):
            records.append(artifact_record(path, f"run_execution:{name}"))
    return records


def execution_json_for_optional_run_execution(name: str) -> str:
    if name.endswith(".json"):
        return name
    if name.endswith(".md"):
        return f"{name[:-3]}.json"
    return name


def should_include_optional_run_execution(name: str, *, require_kimi: bool = True) -> bool:
    if name in OUT_OF_SCOPE_RUN_EXECUTION_FILES:
        return False
    json_name = execution_json_for_optional_run_execution(name)
    if json_name not in EXECUTE_RUN_EXECUTION_JSONS:
        return True
    json_path = ROOT / json_name
    if not json_path.is_file():
        return False
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return False
    return bool(payload.get("execute"))


def collect_run_budget_artifacts() -> list[dict[str, Any]]:
    return [artifact_record(ROOT / name, f"run_budget:{name}") for name in RUN_BUDGET_FILES]


def collect_submission_gap_artifacts() -> list[dict[str, Any]]:
    return [artifact_record(ROOT / name, f"submission_gap:{name}") for name in SUBMISSION_GAP_FILES]


def collect_submission_objective_audit_artifacts() -> list[dict[str, Any]]:
    return [
        artifact_record(ROOT / name, f"submission_objective:{name}")
        for name in SUBMISSION_OBJECTIVE_AUDIT_FILES
    ]


def collect_submission_package_artifacts() -> list[dict[str, Any]]:
    return [
        artifact_record(ROOT / name, f"submission_package:{name}")
        for name in SUBMISSION_PACKAGE_FILES
    ]


def collect_live_status_artifacts() -> list[dict[str, Any]]:
    records = [artifact_record(ROOT / name, f"live_status:{name}") for name in LIVE_STATUS_FILES]
    for name in OPTIONAL_LIVE_STATUS_FILES:
        path = ROOT / name
        if path.is_file():
            records.append(artifact_record(path, f"live_status:{name}"))
    return records


def copy_artifacts(records: list[dict[str, Any]], out_dir: Path) -> list[dict[str, Any]]:
    copied: list[dict[str, Any]] = []
    files_dir = out_dir / "files"
    if files_dir.exists():
        shutil.rmtree(files_dir)
    files_dir.mkdir(parents=True, exist_ok=True)
    for record in records:
        if not record["exists"]:
            continue
        src = ROOT / record["path"]
        dest = files_dir / record["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        copied.append(
            {
                **record,
                "copied_to": relpath(dest),
                "copied_sha256": sha256(dest),
            }
        )
    return copied


def report_dir(label: str = "", path: str = "") -> Path | None:
    if path:
        return Path(path)
    if label:
        return RUNS / "_reports" / safe_slug(label)
    return None


def reproduction_commands(
    attack_label: str,
    control_label: str | list[str] | tuple[str, ...],
    table_dir: str,
    bundle_dir: str = "",
    require_kimi: bool = True,
    control_report_records: list[dict[str, Any]] | None = None,
    attack_report_dir: str = "",
    control_report_dirs: list[str] | tuple[str, ...] | None = None,
    case_evidence_dir: str = "",
) -> list[str]:
    control_labels = unique_nonempty(normalize_labels(control_label))
    control_report_dir_values = unique_nonempty([str(path or "") for path in control_report_dirs or []])
    expected_harness_args = ["--expected-harness claude"]
    claim_profile = "submission" if require_kimi else "current_claude"
    readiness_command = "python infra\\check_paper_readiness.py"
    release_command = "python infra\\check_release_metadata.py"
    preflight_command = ".\\infra\\run_paper_preflight.ps1 -Profile submission"
    if not require_kimi:
        preflight_command = ".\\infra\\run_paper_preflight.ps1 -Profile current_claude"
    else:
        release_command += " --require-license"
    package_attack_label = attack_label or "paper_core_20260625"
    package_control_label = ",".join(control_labels) if control_labels else "paper_controls_core_20260625"
    package_table_dir = table_dir or "runs\\_reports\\paper_core_20260625\\paper_tables"
    package_case_evidence_dir = case_evidence_dir or "runs\\_reports\\paper_core_20260625\\case_study_evidence"
    package_bundle_dir = bundle_dir or "runs\\_artifacts\\repro_bundles\\paper_core_20260625"
    package_manifest_command = (
        "python infra\\generate_submission_package_manifest.py "
        "--attack-label "
        f"{package_attack_label} "
        "--control-label "
        f"{package_control_label} "
        "--table-dir "
        f"{package_table_dir} "
        "--case-evidence-dir "
        f"{package_case_evidence_dir} "
        "--bundle-dir "
        f"{package_bundle_dir} "
        "--out-json docs\\generated_artifacts\\paper_submission_package_manifest.json "
        "--out-md docs\\generated_artifacts\\paper_submission_package_manifest.md"
    )
    live_status_snapshot_command = (
        "python infra\\paper_queue_job.py snapshot "
        "--out-json docs\\generated_artifacts\\paper_live_status.json "
        "--out-md docs\\generated_artifacts\\paper_live_status.md "
        "--check-md docs\\generated_artifacts\\paper_live_status_check.md "
        "--history-jsonl docs\\generated_artifacts\\paper_live_status_history.jsonl"
    )
    commands = [
        "python infra\\check_active_case_integrity.py",
        "python infra\\audit_paper_suite.py --strict-controls",
        readiness_command,
        "python infra\\check_paper_suite_lock.py",
        (
        "python infra\\plan_paper_experiment_matrix.py "
        "--out-json docs\\generated_artifacts\\paper_experiment_matrix_plan.json "
        "--out-md docs\\generated_artifacts\\paper_experiment_matrix_plan.md"
        ),
        "python infra\\check_paper_matrix_progress.py --out docs\\generated_artifacts\\paper_experiment_matrix_progress.md",
        "python infra\\check_paper_matrix_progress.py --harness claude --out docs\\generated_artifacts\\paper_experiment_matrix_progress_claude.md",
        "python infra\\export_paper_run_queue.py --out-json docs\\generated_artifacts\\paper_run_queue.json --out-md docs\\generated_artifacts\\paper_run_queue.md",
        "python infra\\run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json --queue-mode serial --out-json docs\\generated_artifacts\\paper_run_execution_plan.json --out-md docs\\generated_artifacts\\paper_run_execution_plan.md",
        "python infra\\run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json --queue-mode serial --harness claude --out-json docs\\generated_artifacts\\paper_run_execution_claude_dry_run.json --out-md docs\\generated_artifacts\\paper_run_execution_claude_dry_run.md",
        "python infra\\run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json --queue-mode post-run --harness claude --out-json docs\\generated_artifacts\\paper_run_execution_claude_post_run_dry_run.json --out-md docs\\generated_artifacts\\paper_run_execution_claude_post_run_dry_run.md",
        "python infra\\estimate_paper_run_budget.py --out-json docs\\generated_artifacts\\paper_run_budget.json --out-md docs\\generated_artifacts\\paper_run_budget.md",
        "python infra\\report_paper_submission_gaps.py --out docs\\generated_artifacts\\paper_submission_gap_report.md --json-out docs\\generated_artifacts\\paper_submission_gap_report.json",
        "python infra\\audit_submission_objective.py --out docs\\generated_artifacts\\paper_submission_objective_audit.md --json-out docs\\generated_artifacts\\paper_submission_objective_audit.json",
        f"python infra\\check_paper_claims.py --profile {claim_profile}",
        f"python infra\\check_paper_manuscript.py --out runs\\_reports\\{safe_slug(attack_label or 'paper')}\\paper_manuscript_check.md",
        release_command,
    ]
    if require_kimi:
        commands.extend(
            [
                (
                    "python infra\\run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json "
                    "--queue-mode serial --harness claude --execute "
                    "--out-json docs\\generated_artifacts\\paper_run_execution_claude_plan.json "
                    "--out-md docs\\generated_artifacts\\paper_run_execution_claude_plan.md"
                ),
                (
                    "python infra\\run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json "
                    "--queue-mode post-run --harness claude --execute "
                    "--out-json docs\\generated_artifacts\\paper_run_execution_claude_post_run.json "
                    "--out-md docs\\generated_artifacts\\paper_run_execution_claude_post_run.md"
                ),
                (
                    "python infra\\report_paper_submission_gaps.py --require-ready "
                    "--out docs\\generated_artifacts\\paper_submission_gap_report.md "
                    "--json-out docs\\generated_artifacts\\paper_submission_gap_report.json"
                ),
                (
                    "python infra\\audit_submission_objective.py --require-ready "
                    "--out docs\\generated_artifacts\\paper_submission_objective_audit.md "
                    "--json-out docs\\generated_artifacts\\paper_submission_objective_audit.json"
                ),
            ]
        )
    if attack_label:
        matching_arg = " --all-matching-runs" if require_kimi else ""
        commands.append(
            "python infra\\report_active_run.py "
            f"--label {attack_label} --case-set all{matching_arg} "
            "--run-kind attack --harness claude"
        )
    if control_labels:
        matching_arg = " --all-matching-runs" if require_kimi else ""
        control_type_by_label = {
            str(item.get("label") or ""): unique_nonempty([str(value or "") for value in item.get("control_types", [])])
            for item in control_report_records or []
        }
        for label in control_labels:
            control_types = control_type_by_label.get(label) or ["all"]
            control_arg = ",".join(control_types)
            commands.append(
                "python infra\\report_active_run.py "
                f"--label {label} --case-set all{matching_arg} --run-kind control "
                f"--control-type {control_arg} --harness claude"
            )
    if attack_label or control_labels:
        quality_label = attack_label or control_labels[0]
        quality_parts = [
            "python infra\\check_paper_results.py",
            "--case-set all",
            *expected_harness_args,
        ]
        if attack_report_dir:
            quality_parts.append(f"--attack-report-dir {attack_report_dir}")
        elif attack_label:
            quality_parts.append(f"--attack-label {attack_label}")
        if control_report_dir_values:
            for path in control_report_dir_values:
                quality_parts.append(f"--control-report-dir {path}")
        else:
            for label in control_labels:
                quality_parts.append(f"--control-label {label}")
        if control_labels:
            quality_parts.append("--control-type all")
        quality_parts.extend(["--max-timeouts", str(CURRENT_PROFILE_MAX_TIMEOUTS)])
        quality_parts.extend(
            [
                "--out",
                f"runs\\_reports\\{safe_slug(quality_label)}\\paper_result_quality_gate.md",
            ]
        )
        commands.append(" ".join(quality_parts))
    if attack_label and table_dir:
        if attack_report_dir or control_report_dir_values:
            attack_arg = f"--attack-report-dir {attack_report_dir}" if attack_report_dir else f"--attack-label {attack_label}"
            control_arg = "".join(f" --control-report-dir {path}" for path in control_report_dir_values)
        else:
            attack_arg = f"--attack-label {attack_label}"
            control_arg = "".join(f" --control-label {label}" for label in control_labels)
        commands.append(
            "python infra\\export_paper_tables.py "
            f"{attack_arg}{control_arg} --out-dir {table_dir}"
        )
        evidence_out = case_evidence_dir or f"runs\\_reports\\{safe_slug(attack_label)}\\case_study_evidence"
        commands.append(
            "python infra\\export_case_study_evidence.py "
            f"{attack_arg}{control_arg} "
            f"--out-dir {evidence_out}"
        )
        commands.append(
            "python infra\\check_paper_case_studies.py "
            f"--case-evidence-dir {evidence_out} "
            f"--out runs\\_reports\\{safe_slug(attack_label)}\\paper_case_study_check.md"
        )
        commands.append(
            "python infra\\check_paper_numbers.py "
            f"{attack_arg}{control_arg} "
            f"--table-dir {table_dir} "
            f"--case-evidence-dir {evidence_out} "
            f"--out runs\\_reports\\{safe_slug(attack_label)}\\paper_numbers_check.md"
        )
        commands.append(
            "python infra\\generate_benchmark_card.py "
            f"{attack_arg}{control_arg} "
            f"--table-dir {table_dir} "
            "--out-json docs\\generated_artifacts\\benchmark_card.json "
            "--out-md docs\\generated_artifacts\\benchmark_card.md"
        )
        commands.append(
            "python infra\\generate_paper_appendix.py "
            f"{attack_arg}{control_arg} "
            f"--case-evidence-dir {evidence_out} "
            "--benchmark-card docs\\generated_artifacts\\benchmark_card.json "
            "--out-json docs\\generated_artifacts\\paper_supplementary_appendix.json "
            "--out-md docs\\generated_artifacts\\paper_supplementary_appendix.md "
            "--out-tex docs\\generated_artifacts\\paper_supplementary_appendix.tex"
        )
        commands.append(
            "python infra\\generate_oracle_coverage_report.py "
            f"{attack_arg}{control_arg} "
            "--case-set all "
            "--suite-lock docs\\generated_artifacts\\paper_suite_lock.json "
            "--out-json docs\\generated_artifacts\\paper_oracle_coverage.json "
            "--out-md docs\\generated_artifacts\\paper_oracle_coverage.md"
        )
        commands.append(
            "python infra\\generate_threat_model_card.py "
            "--suite-lock docs\\generated_artifacts\\paper_suite_lock.json "
            "--case-set all "
            "--out-json docs\\generated_artifacts\\paper_threat_model_card.json "
            "--out-md docs\\generated_artifacts\\paper_threat_model_card.md"
        )
        commands.append(
            "python infra\\generate_statistical_analysis.py "
            f"{attack_arg}{control_arg} "
            "--out-json docs\\generated_artifacts\\paper_statistical_analysis.json "
            "--out-md docs\\generated_artifacts\\paper_statistical_analysis.md"
        )
        commands.append(
            "python infra\\generate_claim_evidence_map.py "
            "--out-json docs\\generated_artifacts\\paper_claim_evidence_map.json "
            "--out-md docs\\generated_artifacts\\paper_claim_evidence_map.md"
        )
        commands.append(
            "python infra\\generate_control_integrity_report.py "
            f"{control_arg} "
            "--out-json docs\\generated_artifacts\\paper_control_integrity_report.json "
            "--out-md docs\\generated_artifacts\\paper_control_integrity_report.md"
        )
        commands.append(
            "python infra\\generate_paper_figures.py "
            "--out-json docs\\generated_artifacts\\paper_figures.json "
            "--out-md docs\\generated_artifacts\\paper_figures.md "
            "--figure-dir docs\\generated_artifacts\\figures"
        )
        commands.append(
            "python infra\\check_paper_bibliography.py "
            "--out-json docs\\generated_artifacts\\paper_bibliography_check.json "
            "--out-md docs\\generated_artifacts\\paper_bibliography_check.md"
        )
        commands.append(
            "python infra\\generate_full_suite_eligibility_appendix.py "
            "--suite-lock docs\\generated_artifacts\\paper_suite_lock.json "
            "--out-json docs\\generated_artifacts\\paper_full_suite_eligibility.json "
            "--out-md docs\\generated_artifacts\\paper_full_suite_eligibility.md"
        )
        commands.append(
            "python infra\\plan_external_validity_calibration.py "
            "--suite-lock docs\\generated_artifacts\\paper_suite_lock.json "
            "--out-json docs\\generated_artifacts\\paper_external_validity_plan.json "
            "--out-md docs\\generated_artifacts\\paper_external_validity_plan.md"
        )
    # Refresh live matrix accounting after any queue execution, then build the
    # submission manifest only after every result-derived public artifact has
    # been regenerated.  This prevents stale/empty scored and N-1 counts from
    # being frozen into the package manifest.
    commands.append(live_status_snapshot_command)
    commands.append(
        "python infra\\check_paper_live_status.py "
        "--out docs\\generated_artifacts\\paper_live_status_check.md --require-ok"
    )
    commands.append(package_manifest_command)
    bundle_path = bundle_dir or f"runs\\_artifacts\\repro_bundles\\{safe_slug(attack_label or (control_labels[0] if control_labels else 'paper'))}"
    commands.append(
        "python infra\\check_public_artifact_safety.py "
        f"--bundle-dir {bundle_path}"
    )
    if attack_label or control_labels:
        gate_parts = [
            "python infra\\check_paper_artifact_gate.py",
            "--case-set all",
            *expected_harness_args,
            "--max-timeouts",
            str(CURRENT_PROFILE_MAX_TIMEOUTS),
            "--max-active-progress-drift-rows 20",
        ]
        if attack_report_dir:
            gate_parts.append(f"--attack-report-dir {attack_report_dir}")
        elif attack_label:
            gate_parts.append(f"--attack-label {attack_label}")
        if control_report_dir_values:
            for path in control_report_dir_values:
                gate_parts.append(f"--control-report-dir {path}")
        else:
            for label in control_labels:
                gate_parts.append(f"--control-label {label}")
        if table_dir:
            gate_parts.append(f"--table-dir {table_dir}")
        if case_evidence_dir:
            gate_parts.append(f"--case-evidence-dir {case_evidence_dir}")
        elif attack_label:
            gate_parts.append(f"--case-evidence-dir runs\\_reports\\{safe_slug(attack_label)}\\case_study_evidence")
        gate_parts.append(f"--bundle-dir {bundle_path}")
        if attack_label:
            gate_name = "paper_artifact_gate_submission.md" if require_kimi else "paper_artifact_gate.md"
            gate_parts.extend(["--out", f"runs\\_reports\\{safe_slug(attack_label)}\\{gate_name}"])
        if require_kimi:
            gate_parts.append("--submission-profile")
        commands.append(" ".join(gate_parts))
    commands.append(preflight_command)
    return commands


def build_manifest(
    attack_report_dir: Path | None,
    control_report_dir: Path | list[Path] | tuple[Path, ...] | None,
    table_dir: Path | None,
    case_evidence_dir: Path | None = None,
    attack_label: str = "",
    control_label: str | list[str] | tuple[str, ...] = "",
    require_kimi: bool = True,
    bundle_dir: Path | None = None,
) -> dict[str, Any]:
    artifacts: list[dict[str, Any]] = []
    if attack_report_dir:
        artifacts.extend(collect_report_artifacts(attack_report_dir, "attack_report"))
    if not attack_label and attack_report_dir:
        attack_label = report_label_from_summary(attack_report_dir)
    control_report_dirs = normalize_report_dirs(control_report_dir)
    control_report_records: list[dict[str, Any]] = []
    for report_dir_path in control_report_dirs:
        role = "control_report" if len(control_report_dirs) == 1 else f"control_report:{report_dir_path.name}"
        artifacts.extend(collect_report_artifacts(report_dir_path, role))
        control_report_records.append(
            {
                "label": report_label_from_summary(report_dir_path),
                "control_types": report_control_types_from_summary(report_dir_path),
            }
        )
    if table_dir:
        artifacts.extend(collect_table_artifacts(table_dir))
    if case_evidence_dir:
        artifacts.extend(collect_case_study_evidence_artifacts(case_evidence_dir))
    artifacts.extend(collect_benchmark_card_artifacts())
    artifacts.extend(collect_supplementary_appendix_artifacts())
    artifacts.extend(collect_oracle_coverage_artifacts())
    artifacts.extend(collect_threat_model_card_artifacts())
    artifacts.extend(collect_statistical_analysis_artifacts())
    artifacts.extend(collect_claim_evidence_map_artifacts())
    artifacts.extend(collect_control_integrity_artifacts())
    artifacts.extend(collect_paper_figure_artifacts())
    artifacts.extend(collect_bibliography_check_artifacts())
    artifacts.extend(collect_manuscript_artifacts())
    artifacts.extend(collect_full_suite_eligibility_artifacts())
    artifacts.extend(collect_external_validity_plan_artifacts())
    artifacts.extend(collect_suite_lock_artifacts())
    artifacts.extend(collect_experiment_plan_artifacts())
    artifacts.extend(collect_matrix_progress_artifacts())
    artifacts.extend(collect_run_queue_artifacts())
    artifacts.extend(collect_run_execution_artifacts(require_kimi=require_kimi))
    artifacts.extend(collect_run_budget_artifacts())
    artifacts.extend(collect_submission_gap_artifacts())
    artifacts.extend(collect_submission_objective_audit_artifacts())
    artifacts.extend(collect_submission_package_artifacts())
    artifacts.extend(collect_live_status_artifacts())
    artifacts.extend(collect_release_metadata_artifacts())

    table_dir_text = relpath(table_dir).replace("/", "\\") if table_dir else ""
    attack_report_dir_text = relpath(attack_report_dir).replace("/", "\\") if attack_report_dir else ""
    control_report_dir_texts = [relpath(path).replace("/", "\\") for path in control_report_dirs]
    case_evidence_dir_text = relpath(case_evidence_dir).replace("/", "\\") if case_evidence_dir else ""
    explicit_control_labels = normalize_labels(control_label)
    control_labels = unique_nonempty(
        explicit_control_labels
        if explicit_control_labels
        else [report_label_from_summary(path) for path in control_report_dirs]
    )
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(ROOT),
        "labels": {
            "attack": attack_label,
            "control": ", ".join(control_labels),
            "controls": control_labels,
        },
        "git": git_state(),
        "readiness": build_readiness(require_kimi=require_kimi),
        "artifacts": artifacts,
        "missing_artifacts": [item for item in artifacts if not item["exists"]],
        "reproduction_commands": reproduction_commands(
            attack_label,
            control_labels,
            table_dir_text,
            relpath(bundle_dir).replace("/", "\\") if bundle_dir else "",
            require_kimi,
            control_report_records,
            attack_report_dir_text,
            control_report_dir_texts,
            case_evidence_dir_text,
        ),
    }


def render_markdown(manifest: dict[str, Any]) -> str:
    readiness = manifest["readiness"]
    lines = [
        "# Reproducibility Bundle Manifest",
        "",
        f"- generated_at: `{manifest['generated_at']}`",
        f"- attack_label: `{manifest['labels'].get('attack') or 'n/a'}`",
        f"- control_label: `{manifest['labels'].get('control') or 'n/a'}`",
        f"- git_commit: `{manifest['git'].get('commit')}`",
        f"- git_branch: `{manifest['git'].get('branch')}`",
        f"- git_dirty: `{str(manifest['git'].get('dirty')).lower()}`",
        f"- readiness_ready: `{str(readiness.get('ready')).lower()}`",
        f"- readiness_blockers: `{len(readiness.get('blockers', []))}`",
        f"- missing_artifacts: `{len(manifest['missing_artifacts'])}`",
        "",
        "## Case Counts",
        "",
        "| Set | Count |",
        "| --- | ---: |",
    ]
    for name, count in readiness.get("case_counts", {}).items():
        lines.append(f"| {name} | {count} |")

    lines += [
        "",
        "## Artifacts",
        "",
        "| Role | Exists | Bytes | SHA256 | Path |",
        "| --- | --- | ---: | --- | --- |",
    ]
    for item in manifest["artifacts"]:
        digest = item["sha256"][:16] if item["sha256"] else ""
        lines.append(
            f"| {item['role']} | {str(item['exists']).lower()} | "
            f"{item['bytes']} | `{digest}` | `{item['path']}` |"
        )

    lines += ["", "## Reproduction Commands", "", "```powershell"]
    lines.extend(manifest["reproduction_commands"])
    lines.append("```")

    if readiness.get("blockers"):
        lines += ["", "## Readiness Blockers", ""]
        lines.extend(f"- {item}" for item in readiness["blockers"])
    return "\n".join(lines) + "\n"


def write_bundle(
    manifest: dict[str, Any],
    out_dir: Path,
    copy_files: bool = False,
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    if copy_files:
        manifest["copied_artifacts"] = copy_artifacts(manifest["artifacts"], out_dir)
    json_path = out_dir / "repro_manifest.json"
    md_path = out_dir / "repro_manifest.md"
    json_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(render_markdown(manifest), encoding="utf-8")
    return {"json": json_path, "markdown": md_path}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a paper reproducibility bundle manifest.")
    parser.add_argument("--attack-label", default="", help="Attack report label under runs/_reports.")
    parser.add_argument("--attack-report-dir", default="", help="Explicit attack report directory.")
    parser.add_argument("--control-label", action="append", default=[], help="Control report label under runs/_reports. Repeat or comma-separate for multiple control reports.")
    parser.add_argument("--control-report-dir", action="append", default=[], help="Explicit control report directory. Repeat or comma-separate for multiple control reports.")
    parser.add_argument("--table-dir", default="", help="Directory produced by export_paper_tables.py.")
    parser.add_argument("--case-evidence-dir", default="", help="Directory produced by export_case_study_evidence.py.")
    parser.add_argument("--out-dir", default="", help="Output directory. Defaults to runs/_artifacts/repro_bundles/<attack-label>.")
    parser.add_argument("--copy-artifacts", action="store_true", help="Copy listed report/table files under the bundle directory.")
    parser.add_argument("--current-profile", action="store_true", help="Use the current local Claude Code + Kimi K2.6 artifact profile instead of the final submission profile.")
    parser.add_argument("--no-require-kimi", action="store_true", help="Deprecated alias for --current-profile.")
    args = parser.parse_args()

    attack_dir = report_dir(args.attack_label, args.attack_report_dir)
    control_dir = report_dirs_from(args.control_label, args.control_report_dir)
    table_dir = Path(args.table_dir) if args.table_dir else None
    case_evidence_dir = Path(args.case_evidence_dir) if args.case_evidence_dir else None
    default_label = args.attack_label or (attack_dir.name if attack_dir else "paper")
    out_dir = (
        Path(args.out_dir)
        if args.out_dir
        else RUNS / "_artifacts" / "repro_bundles" / safe_slug(default_label)
    )
    manifest = build_manifest(
        attack_dir,
        control_dir,
        table_dir,
        case_evidence_dir,
        args.attack_label,
        args.control_label,
        require_kimi=not (args.current_profile or args.no_require_kimi),
        bundle_dir=out_dir,
    )
    paths = write_bundle(manifest, out_dir, copy_files=args.copy_artifacts)
    for path in paths.values():
        print(path)
    return 0 if not manifest["missing_artifacts"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
