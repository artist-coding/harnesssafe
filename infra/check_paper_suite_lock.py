"""Freeze and verify the paper suite's membership and complete runtime inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from infra.audit_paper_suite import infer_paper_family
    from infra.check_paper_readiness import CASE_SETS, include_case_in_set
    from infra.runtime_input_policy import (
        EXCLUDED_DIRECTORY_NAMES,
        EXCLUDED_FILE_NAMES,
        EXCLUDED_FILE_SUFFIXES,
        excluded_directory_name,
        excluded_file_name,
        policy_record,
    )
except ModuleNotFoundError:  # direct `python infra/check_paper_suite_lock.py`
    from audit_paper_suite import infer_paper_family  # type: ignore
    from check_paper_readiness import CASE_SETS, include_case_in_set  # type: ignore
    from runtime_input_policy import (  # type: ignore
        EXCLUDED_DIRECTORY_NAMES,
        EXCLUDED_FILE_NAMES,
        EXCLUDED_FILE_SUFFIXES,
        excluded_directory_name,
        excluded_file_name,
        policy_record,
    )


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOCK = Path("docs/generated_artifacts/paper_suite_lock.json")
SCHEMA_VERSION = 2

# Compatibility aliases for callers that inspect the serialized policy.  The
# implementation itself is shared with ``case_materializer.py`` so the lock
# can never omit a file that the materializer copies.
RUNTIME_EXCLUDED_DIR_NAMES = set(EXCLUDED_DIRECTORY_NAMES)
RUNTIME_EXCLUDED_FILE_NAMES = set(EXCLUDED_FILE_NAMES)
RUNTIME_EXCLUDED_FILE_SUFFIXES = set(EXCLUDED_FILE_SUFFIXES)
# These exclusions apply only to porcelain ``??`` entries.  Tracked M/A/D
# state is always retained, including for the five freeze artifacts below.
GIT_STATUS_EXCLUDED_PREFIXES = (
    "runs/_reports/",
)
GIT_TRACKED_GENERATED_ARTIFACT_ALLOWLIST = (
    "docs/generated_artifacts/paper_suite_lock.json",
    "docs/generated_artifacts/paper_experiment_matrix_plan.json",
    "docs/generated_artifacts/paper_experiment_matrix_plan.md",
    "docs/generated_artifacts/paper_run_queue.json",
    "docs/generated_artifacts/paper_run_queue.md",
)
GIT_STATUS_EXCLUDED_UNTRACKED_PATHS = GIT_TRACKED_GENERATED_ARTIFACT_ALLOWLIST

POST_RUN_REVISION_PATHS = {
    "paper_preflight": Path("infra/run_paper_preflight.ps1"),
    "report_active_run": Path("infra/report_active_run.py"),
    "export_case_study_evidence": Path("infra/export_case_study_evidence.py"),
    "estimate_paper_run_budget": Path("infra/estimate_paper_run_budget.py"),
    "report_paper_submission_gaps": Path("infra/report_paper_submission_gaps.py"),
    "build_repro_bundle": Path("infra/build_repro_bundle.py"),
    "check_public_artifact_safety": Path("infra/check_public_artifact_safety.py"),
    "check_paper_artifact_gate": Path("infra/check_paper_artifact_gate.py"),
    "check_paper_claims": Path("infra/check_paper_claims.py"),
    "check_release_metadata": Path("infra/check_release_metadata.py"),
    "check_repo_release_cleanliness": Path("infra/check_repo_release_cleanliness.py"),
    "audit_submission_objective": Path("infra/audit_submission_objective.py"),
    "check_paper_bibliography": Path("infra/check_paper_bibliography.py"),
    "check_paper_case_studies": Path("infra/check_paper_case_studies.py"),
    "check_paper_manuscript": Path("infra/check_paper_manuscript.py"),
    "check_paper_numbers": Path("infra/check_paper_numbers.py"),
    "generate_full_suite_eligibility_appendix": Path(
        "infra/generate_full_suite_eligibility_appendix.py"
    ),
    "plan_external_validity_calibration": Path(
        "infra/plan_external_validity_calibration.py"
    ),
    "backfill_missing_oracles": Path("infra/backfill_missing_oracles.py"),
    "check_paper_live_status": Path("infra/check_paper_live_status.py"),
    "generate_benchmark_card": Path("infra/generate_benchmark_card.py"),
    "generate_claim_evidence_map": Path("infra/generate_claim_evidence_map.py"),
    "generate_control_integrity_report": Path(
        "infra/generate_control_integrity_report.py"
    ),
    "generate_oracle_coverage_report": Path(
        "infra/generate_oracle_coverage_report.py"
    ),
    "generate_paper_appendix": Path("infra/generate_paper_appendix.py"),
    "generate_paper_figures": Path("infra/generate_paper_figures.py"),
    "generate_statistical_analysis": Path(
        "infra/generate_statistical_analysis.py"
    ),
    "generate_submission_package_manifest": Path(
        "infra/generate_submission_package_manifest.py"
    ),
    "generate_threat_model_card": Path("infra/generate_threat_model_card.py"),
    "paper_queue_job": Path("infra/paper_queue_job.py"),
}

CODE_REVISION_PATHS = {
    "runner": Path("infra/run_harness_case.ps1"),
    "result_classification_ps": Path("infra/result_classification.ps1"),
    "result_classification_py": Path("infra/result_classification.py"),
    "evaluation_record": Path("infra/evaluation_record.py"),
    "materializer": Path("infra/case_materializer.py"),
    "honeypot": Path("infra/honeypot.py"),
    "callback_resolver": Path("infra/callback_resolver.py"),
    "kimi_compat_proxy": Path("infra/kimi_anthropic_compat_proxy.py"),
    "analyzer": Path("infra/analyze_trace.py"),
    "control_contract_evaluator": Path("infra/evaluate_control_contract.py"),
    "scoring": Path("infra/evaluation_scoring.py"),
    "f2_oracle_profiles": Path("infra/f2_oracle_profiles.py"),
    "f3_producer_prompt_contract": Path("infra/f3_producer_prompt_contract.py"),
    "t2_producer_prompt_contract": Path("infra/t2_producer_prompt_contract.py"),
    "control_auditor": Path("infra/audit_paper_suite.py"),
    "control_contract_repair": Path("infra/repair_active_control_contracts.py"),
    "clean_plugin_sanitizer": Path("infra/clean_plugin_sanitizer.py"),
    "f2_clean_plugin_registry": Path("infra/f2_clean_plugin_registry.py"),
    "mcp_interface_probe": Path("infra/mcp_interface_probe.py"),
    "control_smoke_planner": Path("infra/plan_control_smoke.py"),
    "control_smoke_consumer": Path("infra/run_control_smoke.py"),
    "paper_readiness_checker": Path("infra/check_paper_readiness.py"),
    "active_case_integrity_checker": Path("infra/check_active_case_integrity.py"),
    "paper_result_contract_checker": Path("infra/check_paper_results.py"),
    "paper_table_exporter": Path("infra/export_paper_tables.py"),
    "paper_matrix_progress_checker": Path("infra/check_paper_matrix_progress.py"),
    "formal_matrix_planner": Path("infra/plan_paper_experiment_matrix.py"),
    "formal_queue_exporter": Path("infra/export_paper_run_queue.py"),
    "formal_queue_consumer": Path("infra/run_paper_queue.py"),
    "runtime_input_policy": Path("infra/runtime_input_policy.py"),
    "runner_secrets_helper": Path("infra/secrets.ps1"),
    "runner_terminal_ui_helper": Path("infra/terminal_run_ui.ps1"),
    "suite_lock_checker": Path("infra/check_paper_suite_lock.py"),
    **POST_RUN_REVISION_PATHS,
}

PROTOCOL_REVISION_PATHS = {
    "formal_experiment_execution_policy": Path("docs/formal_experiment_execution_policy.md"),
    "paper_experiment_protocol": Path("docs/paper_experiment_protocol.md"),
    "run_and_evaluation_contract": Path("docs/run_and_evaluation_contract.md"),
    "evaluation_metrics_reference": Path("docs/evaluation_metrics_reference.md"),
    "idea_v2": Path("docs/idea_v2.md"),
}

PROVENANCE_FIELDS = {
    "git_commit_sha",
    "git_worktree_dirty",
    "git_status_sha256",
}

FRAME_FIELDS = ["entry", "carrier", "boundary", "trigger", "violation", "recovery"]
REPORTING_FIELDS = [
    "case_id",
    "variant",
    "reporting_track",
    "oracle_strength",
    "infection_mode",
    "paper_priority",
    "violation_oracle_status",
]

CONTROL_PATH_FIELDS = [
    "control_plugin_dirs",
    "control_mcp_configs",
    "control_workspace_dirs",
    "control_removed_carrier_paths",
]

CONTROL_STRUCTURED_FIELDS = [
    "control_workspace_overrides",
    "control_state_resets",
    "control_session_carrier_intervention",
    "control_mcp_interface_contract",
    "control_plugin_interface_contracts",
    "control_clean_entry_source_bundle",
    "control_carrier_lifecycle_contract",
    "control_intervention",
    "control_intervention_timing",
    "control_trigger_stage_index",
    "control_stage_prompts",
    "control_seed",
    "control_preseeded_semantics",
    "control_direct_resume_semantics",
]


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json_sha256(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def file_sha256(path: Path | str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def filesystem_path(path: Path) -> str:
    """Return a path usable for deep active-case trees on Windows."""

    resolved = str(path.resolve())
    if os.name != "nt" or resolved.startswith("\\\\?\\"):
        return resolved
    if resolved.startswith("\\\\"):
        return "\\\\?\\UNC\\" + resolved.lstrip("\\")
    return "\\\\?\\" + resolved


def relative_posix(path: str, base: str) -> str:
    relative = os.path.relpath(path, base)
    if relative == ".":
        return ""
    return relative.replace("\\", "/")


def excluded_runtime_file(name: str) -> bool:
    return excluded_file_name(name)


def is_reparse_point(path: str | Path) -> bool:
    """Detect Windows junctions/reparse points that ``islink`` may miss."""

    try:
        attributes = os.lstat(path).st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def linked_path_record(path: str, relative: str) -> dict[str, str]:
    """Describe a linked input without assuming every reparse point is readable.

    Some Windows reparse-point types are not accepted by ``os.readlink``.  The
    suite lock rejects them regardless, so a diagnostic placeholder is enough
    to preserve the fail-closed decision instead of crashing while formatting
    the error.
    """

    try:
        target = os.readlink(path).replace("\\", "/")
    except OSError:
        target = "<unreadable-reparse-target>"
    return {"path": relative, "target": target}


def runtime_input_tree(case_dir: Path) -> dict[str, Any]:
    """Inventory every materializable case input except declared local noise.

    The walker prunes excluded directories before descending.  This matters in
    real checkouts, where ``results/`` can be large and may contain transient
    or broken provider-created links.
    """

    root = filesystem_path(case_dir)
    directories: list[str] = []
    files: list[dict[str, Any]] = []
    symlinks: list[dict[str, str]] = []

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        kept_dirs: list[str] = []
        for name in sorted(dirnames):
            if excluded_directory_name(name):
                continue
            absolute = os.path.join(dirpath, name)
            relative = relative_posix(absolute, root)
            if os.path.islink(absolute) or is_reparse_point(absolute):
                symlinks.append(linked_path_record(absolute, relative))
                continue
            directories.append(relative)
            kept_dirs.append(name)
        dirnames[:] = kept_dirs

        for name in sorted(filenames):
            relative = relative_posix(os.path.join(dirpath, name), root)
            if relative == "case_meta.json" or excluded_runtime_file(name):
                continue
            absolute = os.path.join(dirpath, name)
            if os.path.islink(absolute) or is_reparse_point(absolute):
                symlinks.append(linked_path_record(absolute, relative))
                continue
            files.append(
                {
                    "path": relative,
                    "sha256": file_sha256(absolute),
                    "size": os.path.getsize(absolute),
                }
            )

    directories.sort()
    files.sort(key=lambda item: item["path"])
    symlinks.sort(key=lambda item: item["path"])
    if symlinks:
        linked_paths = ", ".join(item["path"] for item in symlinks)
        raise ValueError(
            "runtime input trees must not contain symlinks or reparse points; "
            f"external target content cannot be frozen: {linked_paths}"
        )
    payload = {"directories": directories, "files": files, "symlinks": symlinks}
    components = sorted({path.split("/", 1)[0] for path in directories})
    subtrees: dict[str, dict[str, Any]] = {}
    for component in components:
        prefix = component + "/"
        component_payload = {
            "directories": [path for path in directories if path == component or path.startswith(prefix)],
            "files": [item for item in files if item["path"].startswith(prefix)],
            "symlinks": [item for item in symlinks if item["path"].startswith(prefix)],
        }
        subtrees[component] = {
            "tree_sha256": canonical_json_sha256(component_payload),
            "file_count": len(component_payload["files"]),
        }
    root_payload = {
        "directories": [],
        "files": [item for item in files if "/" not in item["path"]],
        "symlinks": [item for item in symlinks if "/" not in item["path"]],
    }
    if root_payload["files"] or root_payload["symlinks"]:
        subtrees["."] = {
            "tree_sha256": canonical_json_sha256(root_payload),
            "file_count": len(root_payload["files"]),
        }
    return {
        "tree_sha256": canonical_json_sha256(payload),
        "file_count": len(files),
        "directory_count": len(directories),
        "symlink_count": len(symlinks),
        "total_bytes": sum(int(item["size"]) for item in files),
        "subtrees": dict(sorted(subtrees.items())),
        **payload,
    }


def content_revision(root: Path, path: Path) -> dict[str, Any]:
    absolute = root / path
    record: dict[str, Any] = {"path": path.as_posix()}
    if not absolute.is_file():
        record.update({"sha256": "", "size": 0, "missing": True})
        return record
    record.update({"sha256": file_sha256(absolute), "size": absolute.stat().st_size})
    return record


def live_runtime_revision_record(root: Path) -> dict[str, Any]:
    """Return stable digests for every global runtime/protocol dependency.

    Planners outside the formal matrix (for example representative smoke
    planners) can bind these fields directly without rebuilding or parsing a
    suite-lock artifact.
    """

    code_revisions = {
        name: content_revision(root, path) for name, path in CODE_REVISION_PATHS.items()
    }
    protocol_revisions = {
        name: content_revision(root, path) for name, path in PROTOCOL_REVISION_PATHS.items()
    }
    runtime_code_digest = canonical_json_sha256(code_revisions)
    protocol_digest = canonical_json_sha256(protocol_revisions)
    policy_digest = canonical_json_sha256(policy_record())
    return {
        "code_revisions": code_revisions,
        "runtime_code_revision_sha256": runtime_code_digest,
        "protocol_revisions": protocol_revisions,
        "protocol_revisions_sha256": protocol_digest,
        "runtime_input_policy_sha256": policy_digest,
        "runtime_revision_sha256": canonical_json_sha256(
            {
                "runtime_code_revision_sha256": runtime_code_digest,
                "protocol_revisions_sha256": protocol_digest,
                "runtime_input_policy_sha256": policy_digest,
            }
        ),
    }


def git_commit_sha(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def git_status_porcelain(root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    lines = result.stdout.replace("\r\n", "\n").splitlines()

    def status_paths(line: str) -> list[str]:
        payload = line[3:] if len(line) >= 3 else line
        # Porcelain v1 quotes unusual paths.  The freeze artifacts use plain
        # ASCII paths, so stripping the outer quotes is sufficient for the
        # explicit derived-artifact exclusions below.
        return [
            value.strip().strip('"').replace("\\", "/")
            for value in payload.split(" -> ")
            if value.strip()
        ]

    kept: list[str] = []
    for line in lines:
        paths = status_paths(line)
        is_untracked = line[:2] == "??"
        if is_untracked and paths and all(
            path in GIT_STATUS_EXCLUDED_UNTRACKED_PATHS
            or any(path.startswith(prefix) for prefix in GIT_STATUS_EXCLUDED_PREFIXES)
            for path in paths
        ):
            continue
        kept.append(line)
    return "".join(f"{line}\n" for line in kept)


def git_tracked_generated_artifacts(root: Path) -> list[str] | None:
    """Return tracked generated artifacts without binding their content.

    The formal freeze is intentionally two-stage: the source commit is named
    inside the suite lock, then a lock-only artifact commit may add the lock,
    matrix plan, and queue.  Consequently this inventory is a live policy
    gate, not suite-content input.  Recording it in ``lock_digest`` would make
    the valid artifact-only commit look like source drift.
    """

    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "-z",
                "--",
                "docs/generated_artifacts",
            ],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    stdout = result.stdout
    if isinstance(stdout, str):
        values = stdout.split("\0")
    else:
        values = stdout.decode("utf-8", errors="surrogateescape").split("\0")
    return sorted(
        {
            value.replace("\\", "/").removeprefix("./")
            for value in values
            if value
        }
    )


def generated_artifact_tracking_issues(
    tracked: list[str] | None,
    *,
    require_attestation_artifacts_tracked: bool = False,
) -> list[dict[str, Any]]:
    if tracked is None:
        return [
            issue(
                "error",
                "Git tracked generated-artifact inventory is unavailable",
            )
        ]
    allowed = set(GIT_TRACKED_GENERATED_ARTIFACT_ALLOWLIST)
    unexpected = sorted(set(tracked) - allowed)
    issues: list[dict[str, Any]] = []
    if unexpected:
        issues.append(
            issue(
                "error",
                "Git tracks generated artifacts outside the formal artifact allowlist",
                {
                    "unexpected": unexpected,
                    "allowlist": list(GIT_TRACKED_GENERATED_ARTIFACT_ALLOWLIST),
                },
            )
        )
    if require_attestation_artifacts_tracked:
        missing = sorted(allowed - set(tracked))
        if missing:
            issues.append(
                issue(
                    "error",
                    "artifact-attestation commit does not track every required freeze artifact",
                    {
                        "missing": missing,
                        "allowlist": list(GIT_TRACKED_GENERATED_ARTIFACT_ALLOWLIST),
                    },
                )
            )
    return issues


def git_provenance(root: Path) -> dict[str, Any]:
    status = git_status_porcelain(root)
    return {
        "git_commit_sha": git_commit_sha(root),
        "git_worktree_dirty": None if status is None else bool(status),
        "git_status_sha256": "" if status is None else sha256_bytes(status.encode("utf-8")),
    }


def valid_git_commit_sha(value: Any) -> bool:
    text = str(value or "").casefold()
    return len(text) in {40, 64} and all(character in "0123456789abcdef" for character in text)


def load_json(path: Path | str) -> dict[str, Any]:
    logical_path = Path(path)
    with open(filesystem_path(logical_path), "r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def norm_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return sorted(str(item) for item in value if str(item))
    return [str(value)]


def case_counts(cases: list[dict[str, Any]]) -> dict[str, int]:
    return {
        case_set: sum(1 for case in cases if case_set in case.get("case_sets", []))
        for case_set in CASE_SETS
    }


def control_record(control: dict[str, Any]) -> dict[str, Any]:
    record = {
        "control_type": str(control.get("control_type") or ""),
        "control_prompt": str(control.get("control_prompt") or ""),
        "expected_max_node": str(control.get("expected_max_node") or ""),
        "expected_present_oracles": norm_list(control.get("expected_present_oracles")),
        "expected_absent_oracles": norm_list(control.get("expected_absent_oracles")),
        # Independent of the enclosing case_meta hash, this pinpoints any
        # drift in the complete matched-control contract.
        "control_contract_canonical_sha256": canonical_json_sha256(control),
    }
    for field in CONTROL_PATH_FIELDS:
        record[field] = norm_list(control.get(field))
    for field in CONTROL_STRUCTURED_FIELDS:
        if field in control:
            record[field] = control[field]
    return record


def canonical_case_content_record(case_dir: Path | str) -> dict[str, Any]:
    """Return canonical content digests for any materializable case directory.

    Unlike :func:`live_case_content_record`, this helper does not require the
    directory to be present in ``runs/manifest.json``.  The materializer uses
    it on the source tree and on the just-copied tree before run-specific
    callback/canary injection, closing the prelaunch-to-copy TOCTOU window.

    ``control_contracts_canonical_sha256`` preserves the suite-lock's existing
    aggregation semantics: every typed control is represented by a digest of
    its *complete* canonical control object, then the typed records are sorted
    before aggregation.
    """

    absolute_case_dir = Path(case_dir).resolve()
    meta_path = absolute_case_dir / "case_meta.json"
    if not os.path.isfile(filesystem_path(meta_path)):
        raise FileNotFoundError(f"case_meta.json is missing: {meta_path}")
    meta = load_json(meta_path)
    controls = [
        control_record(control)
        for control in (meta.get("control_suite") or [])
        if isinstance(control, dict) and str(control.get("control_type") or "")
    ]
    controls.sort(key=lambda item: item["control_type"])
    meta_digest = canonical_json_sha256(meta)
    runtime_inputs = runtime_input_tree(absolute_case_dir)
    control_digest = canonical_json_sha256(
        [
            {
                "control_type": item["control_type"],
                "control_contract_canonical_sha256": item[
                    "control_contract_canonical_sha256"
                ],
            }
            for item in controls
        ]
    )
    case_content_digest = canonical_json_sha256(
        {
            "case_meta_canonical_sha256": meta_digest,
            "control_contracts_canonical_sha256": control_digest,
            "runtime_inputs_tree_sha256": runtime_inputs["tree_sha256"],
        }
    )
    return {
        "case_meta_canonical_sha256": meta_digest,
        "control_contracts_canonical_sha256": control_digest,
        "runtime_inputs_tree_sha256": runtime_inputs["tree_sha256"],
        "case_content_sha256": case_content_digest,
        "control_suite": controls,
        "runtime_inputs": runtime_inputs,
    }


def case_record(root: Path, suite_name: str, suite: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    runs = root / "runs"
    case_dir = str(entry.get("case_dir") or "")
    absolute_case_dir = runs / case_dir
    meta = load_json(absolute_case_dir / "case_meta.json")
    content = canonical_case_content_record(absolute_case_dir)
    controls = content["control_suite"]
    meta_digest = str(content["case_meta_canonical_sha256"])
    runtime_inputs = content["runtime_inputs"]
    control_digest = str(content["control_contracts_canonical_sha256"])
    case_content_digest = str(content["case_content_sha256"])
    record: dict[str, Any] = {
        "suite": suite_name,
        "canonical_suite": str(suite.get("canonical_suite") or meta.get("canonical_suite") or ""),
        "case_dir": case_dir,
        "paper_family": infer_paper_family(case_dir, meta),
        "main_table_eligible": bool(meta.get("main_table_eligible")),
        "attack_success_metric_excluded": bool(meta.get("attack_success_metric_excluded")),
        "case_study_representative": bool(meta.get("case_study_representative")),
        "case_sets": [case_set for case_set in CASE_SETS if include_case_in_set(meta, case_set)],
        "frame": {field: str(meta.get(field) or "") for field in FRAME_FIELDS},
        "oracles": norm_list(meta.get("oracles")),
        "hard_violation_oracles": norm_list(meta.get("hard_violation_oracles")),
        "control_suite": controls,
        # This hash freezes every case_meta field, including nested stage and
        # control intervention fields not duplicated in the human-readable
        # summary above.  JSON formatting and object-key order are ignored.
        "case_meta_sha256": meta_digest,
        "case_meta_canonical_sha256": meta_digest,
        "control_contracts_canonical_sha256": control_digest,
        "runtime_inputs_tree_sha256": runtime_inputs["tree_sha256"],
        "case_content_sha256": case_content_digest,
        # Everything else below the case directory is treated as a runtime
        # input unless the recorded exclusion policy says otherwise.
        "runtime_inputs": runtime_inputs,
    }
    for field in REPORTING_FIELDS:
        record[field] = str(meta.get(field) or "")
    return record


def build_cases(root: Path = ROOT, manifest: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    manifest = manifest if manifest is not None else load_json(root / "runs" / "manifest.json")
    cases: list[dict[str, Any]] = []
    for suite_name, suite in sorted(manifest.get("suites", {}).items()):
        if suite.get("status") != "active":
            continue
        for entry in suite.get("cases", []):
            cases.append(case_record(root, suite_name, suite, entry))
    return sorted(cases, key=lambda item: item["case_dir"])


def digest_payload(lock: dict[str, Any]) -> dict[str, Any]:
    # Git fields describe the source-freeze commit at generation time.  They
    # are attestation provenance, not current-content inputs: the lock is
    # normally committed in a subsequent lock-only commit.  attestation_digest
    # separately protects those stored provenance values from lock tampering.
    excluded = {
        "generated_at",
        "case_set_sha256",
        "suite_content_sha256",
        "attestation_sha256",
    } | PROVENANCE_FIELDS
    return {key: value for key, value in lock.items() if key not in excluded}


def lock_digest(lock: dict[str, Any]) -> str:
    return canonical_json_sha256(digest_payload(lock))


def attestation_digest(lock: dict[str, Any]) -> str:
    payload = {
        key: value
        for key, value in lock.items()
        if key not in {"generated_at", "case_set_sha256", "suite_content_sha256", "attestation_sha256"}
    }
    return canonical_json_sha256(payload)


def build_lock(root: Path = ROOT) -> dict[str, Any]:
    manifest_path = root / "runs" / "manifest.json"
    manifest = load_json(manifest_path)
    cases = build_cases(root, manifest)
    runtime_revisions = live_runtime_revision_record(root)
    lock: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source_manifest": "runs/manifest.json",
        "source_manifest_sha256": file_sha256(manifest_path),
        "source_manifest_canonical_sha256": canonical_json_sha256(manifest),
        "runtime_input_exclusions": policy_record(),
        "git_status_excluded_derived_prefixes": list(GIT_STATUS_EXCLUDED_PREFIXES),
        "git_status_excluded_untracked_paths": list(
            GIT_STATUS_EXCLUDED_UNTRACKED_PATHS
        ),
        "git_tracked_generated_artifact_allowlist": list(
            GIT_TRACKED_GENERATED_ARTIFACT_ALLOWLIST
        ),
        **runtime_revisions,
        **git_provenance(root),
        "active_case_count": len(cases),
        "case_counts": case_counts(cases),
        "cases": cases,
    }
    digest = lock_digest(lock)
    lock["suite_content_sha256"] = digest
    lock["case_set_sha256"] = digest
    lock["attestation_sha256"] = attestation_digest(lock)
    return lock


def issue(
    severity: str,
    message: str,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {"severity": severity, "message": message, "detail": detail or {}}


def first_changed_fields(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    fields: list[str] = []
    for key in sorted(set(expected) | set(actual)):
        if expected.get(key) != actual.get(key):
            fields.append(key)
    return fields


def compare_locks(expected: dict[str, Any], actual: dict[str, Any]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if expected.get("schema_version") != SCHEMA_VERSION:
        issues.append(
            issue(
                "error",
                "paper suite lock schema version is unsupported",
                {"schema_version": expected.get("schema_version"), "expected": SCHEMA_VERSION},
            )
        )
    for field, message in (
        ("source_manifest", "paper suite manifest path drifted"),
        ("source_manifest_sha256", "paper suite manifest content drifted"),
        ("source_manifest_canonical_sha256", "paper suite manifest canonical content drifted"),
        ("runtime_input_exclusions", "runtime input exclusion policy drifted"),
        (
            "git_status_excluded_derived_prefixes",
            "Git derived-artifact exclusion policy drifted",
        ),
        (
            "git_status_excluded_untracked_paths",
            "Git untracked freeze-artifact exclusion policy drifted",
        ),
        (
            "git_tracked_generated_artifact_allowlist",
            "Git tracked generated-artifact allowlist drifted",
        ),
        ("code_revisions", "runtime-critical infrastructure revisions drifted"),
        ("runtime_code_revision_sha256", "runtime-critical infrastructure digest drifted"),
        ("protocol_revisions", "frozen protocol revisions drifted"),
        ("protocol_revisions_sha256", "frozen protocol digest drifted"),
        ("runtime_input_policy_sha256", "runtime input policy digest drifted"),
        ("runtime_revision_sha256", "combined runtime/protocol revision digest drifted"),
    ):
        if expected.get(field) != actual.get(field):
            issues.append(
                issue(
                    "error",
                    message,
                    {"expected": expected.get(field), "actual": actual.get(field)},
                )
            )
    if not valid_git_commit_sha(expected.get("git_commit_sha")):
        issues.append(issue("error", "locked source Git commit revision is unavailable or invalid"))
    if expected.get("git_worktree_dirty") is not False:
        issues.append(
            issue(
                "error",
                "paper suite lock was generated from a dirty or unknown worktree",
                {"git_worktree_dirty": expected.get("git_worktree_dirty")},
            )
        )
    if not str(expected.get("git_status_sha256") or ""):
        issues.append(issue("error", "locked source Git status digest is unavailable"))
    if actual.get("git_worktree_dirty") is not False:
        issues.append(
            issue(
                "error",
                "current Git worktree is dirty or its status is unavailable",
                {"git_worktree_dirty": actual.get("git_worktree_dirty")},
            )
        )
    provenance_expected = {field: expected.get(field) for field in sorted(PROVENANCE_FIELDS)}
    provenance_actual = {field: actual.get(field) for field in sorted(PROVENANCE_FIELDS)}
    if provenance_expected != provenance_actual:
        issues.append(
            issue(
                "warning",
                "current Git provenance differs from the locked source-freeze commit",
                {"locked_source": provenance_expected, "current": provenance_actual},
            )
        )
    missing_revisions = sorted(
        name
        for name, record in (actual.get("code_revisions") or {}).items()
        if not isinstance(record, dict) or bool(record.get("missing")) or not str(record.get("sha256") or "")
    )
    if missing_revisions:
        issues.append(
            issue(
                "error",
                "required runner/analyzer/scoring revision is unavailable",
                {"missing": missing_revisions},
            )
        )
    missing_protocol_revisions = sorted(
        name
        for name, record in (actual.get("protocol_revisions") or {}).items()
        if not isinstance(record, dict) or bool(record.get("missing")) or not str(record.get("sha256") or "")
    )
    if missing_protocol_revisions:
        issues.append(
            issue(
                "error",
                "required frozen protocol revision is unavailable",
                {"missing": missing_protocol_revisions},
            )
        )
    if expected.get("case_counts") != actual.get("case_counts"):
        issues.append(
            issue(
                "error",
                "paper suite case counts drifted",
                {"expected": expected.get("case_counts"), "actual": actual.get("case_counts")},
            )
        )
    if expected.get("active_case_count") != actual.get("active_case_count"):
        issues.append(
            issue(
                "error",
                "active case count drifted",
                {"expected": expected.get("active_case_count"), "actual": actual.get("active_case_count")},
            )
        )

    expected_cases = {case["case_dir"]: case for case in expected.get("cases", [])}
    actual_cases = {case["case_dir"]: case for case in actual.get("cases", [])}
    added = sorted(set(actual_cases) - set(expected_cases))
    removed = sorted(set(expected_cases) - set(actual_cases))
    changed: list[dict[str, Any]] = []
    for case_dir in sorted(set(expected_cases) & set(actual_cases)):
        if expected_cases[case_dir] != actual_cases[case_dir]:
            changed.append(
                {
                    "case_dir": case_dir,
                    "fields": first_changed_fields(expected_cases[case_dir], actual_cases[case_dir]),
                }
            )
    if added or removed or changed:
        issues.append(
            issue(
                "error",
                "paper suite lock content drifted",
                {
                    "added_cases": added[:20],
                    "removed_cases": removed[:20],
                    "changed_cases": changed[:20],
                    "added_count": len(added),
                    "removed_count": len(removed),
                    "changed_count": len(changed),
                },
            )
        )
    expected_digest = str(expected.get("suite_content_sha256") or expected.get("case_set_sha256") or "")
    compatibility_digest = str(expected.get("case_set_sha256") or "")
    if compatibility_digest != expected_digest:
        issues.append(
            issue(
                "error",
                "paper suite lock digest aliases disagree",
                {"suite_content_sha256": expected_digest, "case_set_sha256": compatibility_digest},
            )
        )
    actual_digest = lock_digest(actual)
    if expected_digest != actual_digest:
        issues.append(
            issue(
                "error",
                "paper suite lock digest drifted",
                {"expected": expected_digest, "actual": actual_digest},
            )
        )
    expected_attestation = str(expected.get("attestation_sha256") or "")
    computed_attestation = attestation_digest(expected)
    if expected_attestation != computed_attestation:
        issues.append(
            issue(
                "error",
                "paper suite lock provenance attestation digest is invalid",
                {"expected": expected_attestation, "actual": computed_attestation},
            )
        )
    return issues


def live_case_content_record(
    root: Path,
    case_dir: str,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the canonical full-content record for one active manifest case."""

    manifest = manifest if manifest is not None else load_json(root / "runs" / "manifest.json")
    for suite_name, suite in manifest.get("suites", {}).items():
        if suite.get("status") != "active":
            continue
        for entry in suite.get("cases", []) or []:
            if str(entry.get("case_dir") or "") == case_dir:
                return case_record(root, suite_name, suite, entry)
    raise KeyError(f"active manifest case not found: {case_dir}")


def build_prelaunch_case_report(
    root: Path,
    case_dir: str,
    lock_path: Path = DEFAULT_LOCK,
) -> dict[str, Any]:
    """Verify locked global code plus one case immediately before launch.

    This avoids re-hashing all 328 case trees for every matrix row while still
    detecting lock-file tampering, manifest drift, runtime-code drift, and any
    change to the case that is about to execute.
    """

    absolute_lock = lock_path if lock_path.is_absolute() else root / lock_path
    issues: list[dict[str, Any]] = []
    if not absolute_lock.is_file():
        return {
            "ok": False,
            "case_dir": case_dir,
            "issues": [issue("error", "paper suite lock file is missing", {"path": str(lock_path)})],
        }
    try:
        expected = load_json(absolute_lock)
        actual_case_content_digest = ""
        actual_runtime_inputs_digest = ""
        actual_case_contract_digest = ""
        actual_control_contracts_digest = ""
        actual_control_contract_digests: dict[str, str] = {}
        if expected.get("schema_version") != SCHEMA_VERSION:
            issues.append(issue("error", "paper suite lock schema version is unsupported"))
        stored_digest = str(expected.get("suite_content_sha256") or "")
        if not stored_digest or stored_digest != str(expected.get("case_set_sha256") or ""):
            issues.append(issue("error", "paper suite lock digest aliases disagree"))
        if stored_digest != lock_digest(expected):
            issues.append(issue("error", "paper suite lock content digest is invalid"))
        if str(expected.get("attestation_sha256") or "") != attestation_digest(expected):
            issues.append(issue("error", "paper suite lock provenance attestation digest is invalid"))
        if not valid_git_commit_sha(expected.get("git_commit_sha")) or expected.get("git_worktree_dirty") is not False:
            issues.append(issue("error", "paper suite lock lacks a clean source-freeze Git attestation"))
        current_git = git_provenance(root)
        if current_git.get("git_worktree_dirty") is not False:
            issues.append(
                issue(
                    "error",
                    "current Git worktree is dirty or its status is unavailable",
                    {"git_worktree_dirty": current_git.get("git_worktree_dirty")},
                )
            )
        if expected.get("runtime_input_exclusions") != policy_record():
            issues.append(issue("error", "runtime input exclusion policy drifted"))

        manifest_path = root / "runs" / "manifest.json"
        manifest = load_json(manifest_path)
        if str(expected.get("source_manifest_sha256") or "") != file_sha256(manifest_path):
            issues.append(issue("error", "paper suite manifest content drifted"))
        if str(expected.get("source_manifest_canonical_sha256") or "") != canonical_json_sha256(manifest):
            issues.append(issue("error", "paper suite manifest canonical content drifted"))

        current_runtime_revisions = live_runtime_revision_record(root)
        current_revisions = current_runtime_revisions["code_revisions"]
        current_code_digest = str(current_runtime_revisions["runtime_code_revision_sha256"])
        if expected.get("code_revisions") != current_revisions or str(
            expected.get("runtime_code_revision_sha256") or ""
        ) != current_code_digest:
            issues.append(issue("error", "runtime-critical infrastructure revisions drifted"))
        current_protocol_revisions = current_runtime_revisions["protocol_revisions"]
        current_protocol_digest = str(current_runtime_revisions["protocol_revisions_sha256"])
        if expected.get("protocol_revisions") != current_protocol_revisions or str(
            expected.get("protocol_revisions_sha256") or ""
        ) != current_protocol_digest:
            issues.append(issue("error", "frozen protocol revisions drifted"))
        if str(expected.get("runtime_input_policy_sha256") or "") != str(
            current_runtime_revisions["runtime_input_policy_sha256"]
        ) or str(expected.get("runtime_revision_sha256") or "") != str(
            current_runtime_revisions["runtime_revision_sha256"]
        ):
            issues.append(issue("error", "combined runtime/protocol revision drifted"))

        expected_cases = {
            str(case.get("case_dir") or ""): case for case in expected.get("cases", []) or []
        }
        expected_case = expected_cases.get(case_dir)
        if expected_case is None:
            issues.append(issue("error", "formal case is absent from the suite lock", {"case_dir": case_dir}))
        else:
            try:
                actual_case = live_case_content_record(root, case_dir, manifest)
            except KeyError:
                issues.append(issue("error", "formal case is absent from the active manifest", {"case_dir": case_dir}))
            else:
                actual_case_content_digest = str(actual_case.get("case_content_sha256") or "")
                actual_runtime_inputs_digest = str(
                    actual_case.get("runtime_inputs_tree_sha256") or ""
                )
                actual_case_contract_digest = str(
                    actual_case.get("case_meta_canonical_sha256") or ""
                )
                actual_control_contracts_digest = str(
                    actual_case.get("control_contracts_canonical_sha256") or ""
                )
                actual_control_contract_digests = {
                    str(item.get("control_type") or ""): str(
                        item.get("control_contract_canonical_sha256") or ""
                    )
                    for item in (actual_case.get("control_suite") or [])
                    if isinstance(item, dict) and str(item.get("control_type") or "")
                }
                if expected_case != actual_case:
                    issues.append(
                        issue(
                            "error",
                            "formal case runtime content drifted",
                            {
                                "case_dir": case_dir,
                                "fields": first_changed_fields(expected_case, actual_case),
                            },
                        )
                    )
        return {
            "ok": not any(item.get("severity") == "error" for item in issues),
            "case_dir": case_dir,
            "suite_content_sha256": stored_digest,
            "source_manifest_sha256": file_sha256(manifest_path),
            "source_manifest_canonical_sha256": canonical_json_sha256(manifest),
            "runtime_code_revision_sha256": current_code_digest,
            "protocol_revisions_sha256": current_protocol_digest,
            "runtime_input_policy_sha256": str(
                current_runtime_revisions["runtime_input_policy_sha256"]
            ),
            "runtime_revision_sha256": str(current_runtime_revisions["runtime_revision_sha256"]),
            "case_content_sha256": actual_case_content_digest,
            "runtime_inputs_tree_sha256": actual_runtime_inputs_digest,
            "case_meta_canonical_sha256": actual_case_contract_digest,
            "control_contracts_canonical_sha256": actual_control_contracts_digest,
            "control_contract_digests": actual_control_contract_digests,
            "issues": issues,
        }
    except Exception as exc:
        return {
            "ok": False,
            "case_dir": case_dir,
            "issues": [issue("error", "could not verify prelaunch case binding", {"error": str(exc)})],
        }


def build_report(
    root: Path = ROOT,
    lock_path: Path = DEFAULT_LOCK,
    *,
    require_attestation_artifacts_tracked: bool = False,
) -> dict[str, Any]:
    absolute_lock = lock_path if lock_path.is_absolute() else root / lock_path
    if not absolute_lock.is_file():
        return {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "lock_path": str(lock_path),
            "ok": False,
            "expected_digest": "",
            "actual_digest": "",
            "case_counts": {},
            "require_attestation_artifacts_tracked": (
                require_attestation_artifacts_tracked
            ),
            "issues": [issue("error", "paper suite lock file is missing", {"path": str(lock_path)})],
        }
    try:
        expected = load_json(absolute_lock)
        actual = build_lock(root)
        issues = compare_locks(expected, actual)
        tracked_generated_artifacts = git_tracked_generated_artifacts(root)
        issues.extend(
            generated_artifact_tracking_issues(
                tracked_generated_artifacts,
                require_attestation_artifacts_tracked=(
                    require_attestation_artifacts_tracked
                ),
            )
        )
        if (
            require_attestation_artifacts_tracked
            and actual.get("git_worktree_dirty") is not False
        ):
            issues.append(
                issue(
                    "error",
                    "artifact-attestation commit/tag must have a clean Git worktree",
                    {
                        "git_worktree_dirty": actual.get("git_worktree_dirty"),
                        "git_status_sha256": actual.get("git_status_sha256"),
                    },
                )
            )
        return {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "lock_path": str(lock_path),
            "ok": not any(item.get("severity") == "error" for item in issues),
            "expected_digest": str(expected.get("suite_content_sha256") or expected.get("case_set_sha256") or ""),
            "actual_digest": lock_digest(actual),
            "case_counts": actual.get("case_counts", {}),
            "locked_git_commit_sha": str(expected.get("git_commit_sha") or ""),
            "current_git_commit_sha": str(actual.get("git_commit_sha") or ""),
            "locked_git_worktree_dirty": expected.get("git_worktree_dirty"),
            "current_git_worktree_dirty": actual.get("git_worktree_dirty"),
            "tracked_generated_artifacts": tracked_generated_artifacts or [],
            "tracked_generated_artifact_inventory_available": (
                tracked_generated_artifacts is not None
            ),
            "tracked_generated_artifact_allowlist": list(
                GIT_TRACKED_GENERATED_ARTIFACT_ALLOWLIST
            ),
            "require_attestation_artifacts_tracked": (
                require_attestation_artifacts_tracked
            ),
            "issues": issues,
        }
    except Exception as exc:  # pragma: no cover - defensive guard for malformed local state
        return {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "lock_path": str(lock_path),
            "ok": False,
            "expected_digest": "",
            "actual_digest": "",
            "case_counts": {},
            "require_attestation_artifacts_tracked": (
                require_attestation_artifacts_tracked
            ),
            "issues": [issue("error", "could not verify paper suite lock", {"error": str(exc)})],
        }


def write_lock(root: Path = ROOT, lock_path: Path = DEFAULT_LOCK, *, allow_dirty: bool = False) -> Path:
    absolute_lock = lock_path if lock_path.is_absolute() else root / lock_path
    absolute_lock.parent.mkdir(parents=True, exist_ok=True)
    tracked_generated_artifacts = git_tracked_generated_artifacts(root)
    tracking_issues = generated_artifact_tracking_issues(
        tracked_generated_artifacts
    )
    if tracking_issues:
        detail = tracking_issues[0].get("detail") or {}
        unexpected = detail.get("unexpected") or []
        suffix = f": {', '.join(unexpected)}" if unexpected else ""
        raise RuntimeError(
            "refusing to write suite lock because "
            f"{tracking_issues[0]['message']}{suffix}"
        )
    lock = build_lock(root)
    if not valid_git_commit_sha(lock.get("git_commit_sha")):
        raise RuntimeError("refusing to write suite lock without a source Git commit SHA")
    missing_revisions = sorted(
        name
        for name, record in (lock.get("code_revisions") or {}).items()
        if not isinstance(record, dict) or bool(record.get("missing")) or not str(record.get("sha256") or "")
    )
    if missing_revisions:
        raise RuntimeError(
            "refusing to write suite lock without required content revisions: " + ", ".join(missing_revisions)
        )
    missing_protocol_revisions = sorted(
        name
        for name, record in (lock.get("protocol_revisions") or {}).items()
        if not isinstance(record, dict) or bool(record.get("missing")) or not str(record.get("sha256") or "")
    )
    if missing_protocol_revisions:
        raise RuntimeError(
            "refusing to write suite lock without required protocol revisions: "
            + ", ".join(missing_protocol_revisions)
        )
    if lock.get("git_worktree_dirty") is None:
        raise RuntimeError("refusing to write suite lock because Git worktree status is unavailable")
    if lock.get("git_worktree_dirty") and not allow_dirty:
        raise RuntimeError(
            "refusing to write suite lock from a dirty worktree; commit the source freeze first "
            "or use --allow-dirty only for a non-freeze development audit"
        )
    absolute_lock.write_text(json.dumps(lock, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return absolute_lock


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Paper Suite Lock Check",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- lock_path: `{report['lock_path']}`",
        f"- ok: `{str(report['ok']).lower()}`",
        f"- expected_digest: `{report.get('expected_digest') or 'n/a'}`",
        f"- actual_digest: `{report.get('actual_digest') or 'n/a'}`",
        f"- locked_source_git: `{report.get('locked_git_commit_sha') or 'n/a'}`",
        f"- current_git: `{report.get('current_git_commit_sha') or 'n/a'}`",
        "- require_attestation_artifacts_tracked: "
        f"`{str(report.get('require_attestation_artifacts_tracked', False)).lower()}`",
        "",
        "## Case Counts",
        "",
        "| Set | Count |",
        "| --- | ---: |",
    ]
    for case_set in CASE_SETS:
        lines.append(f"| {case_set} | {report.get('case_counts', {}).get(case_set, 0)} |")

    lines += ["", "## Issues", ""]
    if report.get("issues"):
        lines += ["| Severity | Message |", "| --- | --- |"]
        for item in report["issues"]:
            lines.append(f"| {item['severity']} | {item['message']} |")
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Check or refresh the complete paper suite content lock. Commit and tag the clean source "
            "freeze first, then write the derived lock attestation without changing source inputs."
        )
    )
    parser.add_argument("--lock", default=str(DEFAULT_LOCK), help="suite lock path, relative to repo root by default")
    parser.add_argument(
        "--write",
        action="store_true",
        help="refresh the suite lock; refuses a dirty worktree by default",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="allow a dirty development attestation (it will not pass the formal freeze check)",
    )
    parser.add_argument(
        "--require-attestation-artifacts-tracked",
        action="store_true",
        help=(
            "artifact-attestation gate: require all five allowlisted lock/plan/queue "
            "files, and no other generated artifacts, to be tracked by Git"
        ),
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", default="")
    args = parser.parse_args()
    if args.allow_dirty and not args.write:
        parser.error("--allow-dirty is only valid together with --write")
    if args.require_attestation_artifacts_tracked and args.write:
        parser.error(
            "--require-attestation-artifacts-tracked verifies the later artifact commit "
            "and cannot be combined with --write"
        )

    lock_path = Path(args.lock)
    if args.write:
        try:
            written = write_lock(ROOT, lock_path, allow_dirty=args.allow_dirty)
            report = build_report(ROOT, lock_path)
            report["written"] = str(written)
        except RuntimeError as exc:
            report = {
                "generated_at": datetime.now().isoformat(timespec="seconds"),
                "lock_path": str(lock_path),
                "ok": False,
                "expected_digest": "",
                "actual_digest": "",
                "case_counts": {},
                "issues": [issue("error", str(exc))],
            }
    else:
        report = build_report(
            ROOT,
            lock_path,
            require_attestation_artifacts_tracked=(
                args.require_attestation_artifacts_tracked
            ),
        )
    text = json.dumps(report, indent=2, ensure_ascii=False) if args.json else render_markdown(report)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
