"""Generate a submission-readiness gap report for the paper track."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from infra import (
        check_paper_claims,
        check_paper_matrix_progress,
        check_paper_readiness,
        check_paper_suite_lock,
        check_release_metadata,
        plan_paper_experiment_matrix,
    )
except ModuleNotFoundError:  # direct `python infra/report_paper_submission_gaps.py`
    import check_paper_claims  # type: ignore
    import check_paper_matrix_progress  # type: ignore
    import check_paper_readiness  # type: ignore
    import check_paper_suite_lock  # type: ignore
    import check_release_metadata  # type: ignore
    import plan_paper_experiment_matrix  # type: ignore


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PLAN = ROOT / "docs" / "generated_artifacts" / "paper_experiment_matrix_plan.json"
DEFAULT_CLAUDE_JOB_NAME = "paper_core_claude_20260626"
RELEASE_METADATA_FINAL_DECISION = "docs/release_metadata_final.json"
RELEASE_METADATA_APPLY_TOOL = "infra/apply_release_metadata_decisions.py"
RELEASE_METADATA_DRY_RUN_COMMAND = (
    "python infra\\apply_release_metadata_decisions.py --decision "
    "docs\\release_metadata_final.json --require-license"
)
RELEASE_METADATA_WRITE_COMMAND = RELEASE_METADATA_DRY_RUN_COMMAND + " --write"
RELEASE_METADATA_CHECK_COMMAND = "python infra\\check_release_metadata.py --require-license"


def issue(
    severity: str,
    scope: str,
    message: str,
    action: str,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "severity": severity,
        "scope": scope,
        "message": message,
        "action": action,
        "detail": detail or {},
    }


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def active_claude_job_name(root: Path) -> str:
    path = root / "docs" / "generated_artifacts" / "paper_live_status.json"
    if not path.is_file():
        return DEFAULT_CLAUDE_JOB_NAME
    try:
        status = load_json(path)
    except Exception:
        return DEFAULT_CLAUDE_JOB_NAME
    jobs = status.get("jobs", [])
    if not isinstance(jobs, list):
        return DEFAULT_CLAUDE_JOB_NAME
    active = [
        str(job.get("job_name") or "")
        for job in jobs
        if isinstance(job, dict)
        and job.get("observed_status") == "running"
        and str(job.get("job_name") or "").startswith(DEFAULT_CLAUDE_JOB_NAME)
        and "_post" not in str(job.get("job_name") or "")
    ]
    return active[0] if len(active) == 1 else DEFAULT_CLAUDE_JOB_NAME


def aggregate_issues(issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for item in issues:
        key = (
            item.get("severity", ""),
            item.get("scope", ""),
            item.get("message", ""),
            item.get("action", ""),
        )
        if key not in grouped:
            grouped[key] = {
                "severity": key[0],
                "scope": key[1],
                "message": key[2],
                "action": key[3],
                "detail": {
                    "occurrences": 0,
                    "paths": {},
                    "phrases": [],
                    "source_details": [],
                },
            }
        target = grouped[key]["detail"]
        detail = dict(item.get("detail", {}))
        target["occurrences"] += 1
        if detail:
            target["source_details"].append(detail)
        path = str(detail.get("path", ""))
        if path:
            target["paths"][path] = target["paths"].get(path, 0) + 1
        phrase = str(detail.get("phrase", ""))
        if phrase and phrase not in target["phrases"]:
            target["phrases"].append(phrase)

    out = list(grouped.values())
    for item in out:
        detail = item["detail"]
        detail["paths"] = dict(sorted(detail["paths"].items()))
        detail["phrases"] = sorted(detail["phrases"])
    return out


def issue_evidence_summary(item: dict[str, Any]) -> str:
    detail = item.get("detail", {})
    paths = detail.get("paths", {})
    if paths:
        return ", ".join(
            f"{path} ({count})" if count > 1 else path for path, count in paths.items()
        )
    accepted_names = sorted(
        {
            name
            for source in detail.get("source_details", [])
            if isinstance(source, dict)
            for name in source.get("accepted_names", [])
        }
    )
    if accepted_names:
        return "accepted root names: " + ", ".join(accepted_names)
    occurrences = detail.get("occurrences", 1)
    if occurrences > 1:
        return f"{occurrences} occurrences"
    return ""


def release_metadata_details(report: dict[str, Any]) -> tuple[str, list[str], bool, bool]:
    release = report.get("sections", {}).get("release_metadata", {})
    license_file = str(release.get("license_file") or "n/a")
    accepted_names = sorted(
        {
            name
            for item in report.get("issues", [])
            if item.get("scope") == "release_metadata"
            for source in item.get("detail", {}).get("source_details", [])
            if isinstance(source, dict)
            for name in source.get("accepted_names", [])
        }
    )
    messages = [
        str(item.get("message", ""))
        for item in report.get("issues", [])
        if item.get("scope") == "release_metadata"
    ]
    missing_license = any("license" in message.lower() for message in messages) and license_file == "n/a"
    preprint_citation = any("preprint" in message.lower() for message in messages)
    return license_file, accepted_names, missing_license, preprint_citation


def markdown_code(value: Any) -> str:
    text = str(value).replace("`", "\\`")
    return f"`{text}`"


def claim_boundary_details(report: dict[str, Any]) -> tuple[dict[str, int], list[str], list[dict[str, Any]]]:
    for item in report.get("issues", []):
        if item.get("severity") != "error" or item.get("scope") != "claim_boundary":
            continue
        detail = item.get("detail", {})
        paths = detail.get("paths", {}) if isinstance(detail, dict) else {}
        phrases = detail.get("phrases", []) if isinstance(detail, dict) else []
        source_details = detail.get("source_details", []) if isinstance(detail, dict) else []
        locations = [
            source
            for source in source_details
            if isinstance(source, dict) and source.get("path") and source.get("phrase")
        ]
        return (
            dict(paths) if isinstance(paths, dict) else {},
            list(phrases) if isinstance(phrases, list) else [],
            locations,
        )
    return {}, [], []


def release_issue_messages(issues: list[dict[str, Any]]) -> list[str]:
    return [
        str(item.get("message", ""))
        for item in issues
        if item.get("scope") == "release_metadata"
    ]


def has_release_issue(messages: list[str], *needles: str) -> bool:
    lowered = [message.lower() for message in messages]
    return any(all(needle.lower() in message for needle in needles) for message in lowered)


def manual_decision(
    *,
    decision_id: str,
    title: str,
    status: str,
    blocking_submission_gate: bool,
    required_before_public_release: bool,
    evidence: list[str],
    next_action: str,
) -> dict[str, Any]:
    return {
        "id": decision_id,
        "title": title,
        "status": status,
        "blocking_submission_gate": blocking_submission_gate,
        "required_before_public_release": required_before_public_release,
        "evidence": evidence,
        "next_action": next_action,
    }


def release_metadata_evidence(*extra: str) -> list[str]:
    return [
        RELEASE_METADATA_FINAL_DECISION,
        RELEASE_METADATA_APPLY_TOOL,
        *extra,
    ]


def build_manual_decisions(sections: dict[str, Any], issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    release = sections.get("release_metadata", {})
    license_file = str(release.get("license_file") or "")
    messages = release_issue_messages(issues)
    license_pending = not license_file or has_release_issue(messages, "license")
    authors_pending = has_release_issue(messages, "placeholder", "author")
    link_pending = has_release_issue(messages, "repository", "url") or has_release_issue(messages, "doi")
    version_pending = has_release_issue(messages, "preprint")
    license_next_action = (
        "Fill docs/release_metadata_final.json with final license text, dry-run "
        "apply_release_metadata_decisions.py, rerun with --write, then run "
        "check_release_metadata.py --require-license."
        if license_pending
        else "No action required; the finalized root license and split license mapping are present."
    )
    split_mapping_present = bool(release.get("split_license_mapping_file"))
    return [
        manual_decision(
            decision_id="license_file",
            title="Choose and add the finalized root license",
            status="pending" if license_pending else "complete",
            blocking_submission_gate=license_pending,
            required_before_public_release=True,
            evidence=release_metadata_evidence("LICENSE"),
            next_action=license_next_action,
        ),
        manual_decision(
            decision_id="citation_authors",
            title="Replace placeholder citation author metadata",
            status="pending" if authors_pending else "complete",
            blocking_submission_gate=authors_pending,
            required_before_public_release=True,
            evidence=release_metadata_evidence("CITATION.cff"),
            next_action=(
                "Set final citation authors in docs/release_metadata_final.json, dry-run/apply "
                "with apply_release_metadata_decisions.py, then validate release metadata."
            ),
        ),
        manual_decision(
            decision_id="citation_public_url_or_doi",
            title="Add a public repository, artifact URL, or DOI",
            status="pending" if link_pending else "complete",
            blocking_submission_gate=link_pending,
            required_before_public_release=True,
            evidence=release_metadata_evidence("CITATION.cff"),
            next_action=(
                "Add the final repository URL, artifact URL, DOI, or artifact DOI to "
                "docs/release_metadata_final.json, apply it, then validate release metadata."
            ),
        ),
        manual_decision(
            decision_id="citation_version_date",
            title="Finalize citation version/date",
            status="pending" if version_pending else "complete",
            blocking_submission_gate=version_pending,
            required_before_public_release=True,
            evidence=release_metadata_evidence("CITATION.cff"),
            next_action=(
                "Set the final non-preprint citation version and release date in "
                "docs/release_metadata_final.json, apply it, then validate release metadata."
            ),
        ),
        manual_decision(
            decision_id="split_license_mapping",
            title="Add path-level license mapping if using split code/data licensing",
            status="complete" if split_mapping_present else "conditional",
            blocking_submission_gate=False,
            required_before_public_release=True,
            evidence=release_metadata_evidence("LICENSES.md", "NOTICE"),
            next_action=(
                "No action required; path-level license mapping is present."
                if split_mapping_present
                else (
                    "If using different licenses by path, include split_license_mapping in "
                    "docs/release_metadata_final.json before applying the release metadata."
                )
            ),
        ),
    ]


def plan_status(root: Path, plan_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not plan_path.is_file():
        return (
            {"ok": False, "matrix_id": "", "summary": {}},
            [
                issue(
                    "error",
                    "experiment_plan",
                    "missing paper experiment matrix plan",
                    "Run python infra\\plan_paper_experiment_matrix.py --out-json docs\\generated_artifacts\\paper_experiment_matrix_plan.json --out-md docs\\generated_artifacts\\paper_experiment_matrix_plan.md",
                    {"path": str(plan_path)},
                )
            ],
        )
    plan = load_json(plan_path)
    plan_issues = [
        issue(
            item.get("severity", "error"),
            "experiment_plan",
            item.get("message", "experiment plan issue"),
            "Regenerate the plan and review the diff before running the final matrix.",
            item.get("detail", {}),
        )
        for item in plan_paper_experiment_matrix.validate_plan(plan, root=root)
    ]
    return (
        {
            "ok": not any(item["severity"] == "error" for item in plan_issues),
            "matrix_id": plan.get("matrix_id", ""),
            "matrix_digest": plan.get("matrix_digest", ""),
            "case_set": plan.get("case_set", ""),
            "summary": plan.get("summary", {}),
        },
        plan_issues,
    )


def collect_issues(root: Path, plan_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    sections: dict[str, Any] = {}
    issues: list[dict[str, Any]] = []

    current_readiness = check_paper_readiness.build_readiness(require_kimi=True, root=root)
    submission_readiness = check_paper_readiness.build_readiness(require_kimi=True, root=root)
    sections["current_readiness"] = {
        "ready": current_readiness.get("ready"),
        "blockers": current_readiness.get("blockers", []),
        "warnings": current_readiness.get("warnings", []),
    }
    sections["submission_readiness"] = {
        "ready": submission_readiness.get("ready"),
        "blockers": submission_readiness.get("blockers", []),
        "warnings": submission_readiness.get("warnings", []),
    }
    for blocker in submission_readiness.get("blockers", []):
        action = "Fix the blocker reported by check_paper_readiness.py."
        if "Codex Kimi" in blocker or "DashScope" in blocker:
            action = "Configure providers.dashscope.coding_api_key in bench_state\\secrets\\api_keys.json (or DASHSCOPE_CODING_API_KEY / bench_state\\secrets\\codex\\api_key.txt) only if the optional Codex/Kimi path is in scope, then rerun readiness."
        issues.append(issue("error", "readiness", blocker, action))

    suite_lock = check_paper_suite_lock.build_report(root)
    sections["suite_lock"] = {
        "ok": suite_lock.get("ok"),
        "actual_digest": suite_lock.get("actual_digest", ""),
        "expected_digest": suite_lock.get("expected_digest", ""),
        "issue_count": len(suite_lock.get("issues", [])),
    }
    for item in suite_lock.get("issues", []):
        issues.append(
            issue(
                item.get("severity", "error"),
                "suite_lock",
                item.get("message", "paper suite lock issue"),
                "Review suite/case metadata changes; only refresh docs\\generated_artifacts\\paper_suite_lock.json after intentional case-set changes.",
                item.get("detail", {}),
            )
        )

    plan, plan_issues = plan_status(root, plan_path)
    sections["experiment_plan"] = plan
    issues.extend(plan_issues)

    progress = check_paper_matrix_progress.build_progress_report(root=root, plan_path=plan_path)
    progress_summary = progress.get("summary", {})
    sections["matrix_progress"] = {
        "complete": progress.get("complete"),
        "matrix_id": progress.get("matrix_id", ""),
        "expected_rows": progress_summary.get("expected_rows", 0),
        "completed_rows": progress_summary.get("completed_rows", 0),
        "scored_rows": progress_summary.get("execution_valid_completed_rows", 0),
        "model_protocol_terminal_rows": progress_summary.get(
            "model_protocol_terminal_rows", 0
        ),
        "incomplete_rows": progress_summary.get("incomplete_rows", 0),
        "execution_invalid_or_unvalidated_rows": progress_summary.get(
            "execution_invalid_or_unvalidated_rows", 0
        ),
        "duplicate_accounted_expected_rows": progress_summary.get(
            "duplicate_accounted_expected_rows", 0
        ),
        "completion_rate": progress_summary.get("completion_rate", 0.0),
    }
    if not progress.get("complete"):
        issues.append(
            issue(
                "error",
                "matrix_progress",
                "final paper matrix is incomplete",
                "Execute the readiness-gated run queue, then rerun check_paper_matrix_progress.py --require-complete.",
                progress_summary,
            )
        )
    for item in progress.get("issues", []):
        if item.get("severity") == "error":
            issues.append(
                issue(
                    "error",
                    "matrix_progress",
                    item.get("message", "matrix progress issue"),
                    "Resolve plan/progress inconsistency before claiming submission readiness.",
                    item.get("detail", {}),
                )
            )

    release = check_release_metadata.build_release_metadata_report(root, require_license=True)
    sections["release_metadata"] = {
        "ok": release.get("ok"),
        "license_file": release.get("license_file", ""),
        "split_license_mapping_file": release.get("split_license_mapping_file", ""),
        "issue_count": len(release.get("issues", [])),
    }
    for item in release.get("issues", []):
        if item.get("severity") == "error":
            action = (
                "Finalize docs\\release_metadata_final.json, dry-run/write with "
                "infra\\apply_release_metadata_decisions.py, then rerun "
                "check_release_metadata.py --require-license."
            )
            if item.get("scope") == "license":
                action = (
                    "Put the final root license text in docs\\release_metadata_final.json, "
                    "dry-run infra\\apply_release_metadata_decisions.py, rerun with --write, "
                    "then rerun check_release_metadata.py --require-license."
                )
            issues.append(
                issue(
                    "error",
                    "release_metadata",
                    item.get("message", "release metadata issue"),
                    action,
                    item.get("detail", {}),
                )
            )
        elif item.get("severity") == "warning":
            issues.append(
                issue(
                    "warning",
                    "release_metadata",
                    item.get("message", "release metadata warning"),
                    (
                        "Resolve in docs\\release_metadata_final.json, apply with "
                        "infra\\apply_release_metadata_decisions.py, then validate before "
                        "public artifact upload."
                    ),
                    item.get("detail", {}),
                )
            )

    claims = check_paper_claims.build_claim_report(root, profile="submission")
    sections["claim_boundary"] = {
        "ok": claims.get("ok"),
        "issue_count": len(claims.get("issues", [])),
    }
    for item in claims.get("issues", []):
        issues.append(
            issue(
                item.get("severity", "error"),
                "claim_boundary",
                item.get("message", "claim-boundary issue"),
                "Update paper prose so the claim boundary matches the completed local matrix.",
                {"path": item.get("path", ""), **item.get("detail", {})},
            )
        )

    return sections, issues


def build_gap_report(root: Path = ROOT, plan_path: Path | None = None) -> dict[str, Any]:
    path = plan_path or (root / "docs" / "generated_artifacts" / "paper_experiment_matrix_plan.json")
    sections, raw_issues = collect_issues(root, path)
    issues = aggregate_issues(raw_issues)
    errors = [item for item in issues if item.get("severity") == "error"]
    warnings = [item for item in issues if item.get("severity") == "warning"]
    raw_errors = [item for item in raw_issues if item.get("severity") == "error"]
    raw_warnings = [item for item in raw_issues if item.get("severity") == "warning"]
    manual_decisions = build_manual_decisions(sections, issues)
    pending_decisions = [item for item in manual_decisions if item.get("status") == "pending"]
    blocking_decisions = [item for item in manual_decisions if item.get("blocking_submission_gate")]
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "plan_path": str(path),
        "submission_ready": not errors and not blocking_decisions,
        "sections": sections,
        "manual_decisions": manual_decisions,
        "issues": issues,
        "raw_issues": raw_issues,
        "summary": {
            "error_count": len(errors),
            "warning_count": len(warnings),
            "issue_count": len(issues),
            "raw_error_count": len(raw_errors),
            "raw_warning_count": len(raw_warnings),
            "raw_issue_count": len(raw_issues),
            "manual_decision_count": len(manual_decisions),
            "pending_manual_decision_count": len(pending_decisions),
            "blocking_manual_decision_count": len(blocking_decisions),
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    sections = report["sections"]
    matrix = sections.get("matrix_progress", {})
    readiness = sections.get("submission_readiness", {})
    root = Path(report.get("root") or ROOT)
    active_job = active_claude_job_name(root)
    matrix_complete = bool(matrix.get("complete")) or (
        int(matrix.get("expected_rows") or 0) > 0
        and int(matrix.get("completed_rows") or 0) >= int(matrix.get("expected_rows") or 0)
    )
    lines = [
        "# Paper Submission Gap Report",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- submission_ready: `{str(report['submission_ready']).lower()}`",
        f"- errors: `{summary['error_count']}`",
        f"- warnings: `{summary['warning_count']}`",
        f"- raw_error_occurrences: `{summary.get('raw_error_count', summary['error_count'])}`",
        f"- raw_warning_occurrences: `{summary.get('raw_warning_count', summary['warning_count'])}`",
        f"- pending_manual_decisions: `{summary.get('pending_manual_decision_count', 0)}`",
        f"- blocking_manual_decisions: `{summary.get('blocking_manual_decision_count', 0)}`",
        f"- submission_readiness_ready: `{str(readiness.get('ready')).lower()}`",
        f"- matrix_progress: `{matrix.get('completed_rows', 0)}/{matrix.get('expected_rows', 0)}`",
        f"- matrix_scored_rows: `{matrix.get('scored_rows', 0)}`",
        f"- matrix_n_minus_1_rows: `{matrix.get('model_protocol_terminal_rows', 0)}`",
        f"- matrix_unresolved_invalid_rows: `{matrix.get('execution_invalid_or_unvalidated_rows', 0)}`",
        f"- matrix_duplicate_accounted_rows: `{matrix.get('duplicate_accounted_expected_rows', 0)}`",
        "",
        "## Sections",
        "",
        "| Section | Status | Detail |",
        "| --- | --- | --- |",
    ]
    current = sections.get("current_readiness", {})
    lines.append(
        f"| current_readiness | {'ready' if current.get('ready') else 'blocked'} | "
        f"blockers={len(current.get('blockers', []))}; warnings={len(current.get('warnings', []))} |"
    )
    lines.append(
        f"| submission_readiness | {'ready' if readiness.get('ready') else 'blocked'} | "
        f"blockers={len(readiness.get('blockers', []))}; warnings={len(readiness.get('warnings', []))} |"
    )
    suite_lock = sections.get("suite_lock", {})
    lines.append(
        f"| suite_lock | {'ok' if suite_lock.get('ok') else 'blocked'} | "
        f"digest={str(suite_lock.get('actual_digest', ''))[:16]}; issues={suite_lock.get('issue_count', 0)} |"
    )
    plan = sections.get("experiment_plan", {})
    plan_summary = plan.get("summary", {})
    lines.append(
        f"| experiment_plan | {'ok' if plan.get('ok') else 'blocked'} | "
        f"matrix_id={plan.get('matrix_id', '')}; rows={plan_summary.get('rows_total', 0)} |"
    )
    lines.append(
        f"| matrix_progress | {'complete' if matrix.get('complete') else 'incomplete'} | "
        f"accounted={matrix.get('completed_rows', 0)}/{matrix.get('expected_rows', 0)}; "
        f"scored={matrix.get('scored_rows', 0)}; "
        f"N-1={matrix.get('model_protocol_terminal_rows', 0)}; "
        f"unresolved_invalid={matrix.get('execution_invalid_or_unvalidated_rows', 0)}; "
        f"duplicate_accounted={matrix.get('duplicate_accounted_expected_rows', 0)} |"
    )
    release = sections.get("release_metadata", {})
    lines.append(
        f"| release_metadata | {'ok' if release.get('ok') else 'blocked'} | "
        f"license={release.get('license_file') or 'n/a'}; issues={release.get('issue_count', 0)} |"
    )
    claims = sections.get("claim_boundary", {})
    lines.append(
        f"| claim_boundary | {'ok' if claims.get('ok') else 'blocked'} | "
        f"issues={claims.get('issue_count', 0)} |"
    )

    lines += ["", "## Blocking Issues", ""]
    errors = [item for item in report["issues"] if item["severity"] == "error"]
    if errors:
        lines += [
            "| Scope | Issue | Occurrences | Evidence | Required Action |",
            "| --- | --- | ---: | --- | --- |",
        ]
        for item in errors:
            lines.append(
                f"| {item['scope']} | {item['message']} | "
                f"{item.get('detail', {}).get('occurrences', 1)} | "
                f"{issue_evidence_summary(item) or 'n/a'} | {item['action']} |"
            )
    else:
        lines.append("- none")

    license_file, accepted_license_names, missing_license, preprint_citation = release_metadata_details(report)
    if missing_license or preprint_citation:
        lines += ["", "## Release Metadata Details", ""]
        lines.append(f"- License file: {markdown_code(license_file)}")
        if accepted_license_names:
            lines.append(
                "- Accepted root license filenames: "
                + ", ".join(markdown_code(name) for name in accepted_license_names)
            )
        lines.append(f"- Final decision JSON: `{RELEASE_METADATA_FINAL_DECISION}`")
        lines.append(f"- Apply tool: `{RELEASE_METADATA_APPLY_TOOL}`")
        minimum_actions = [
            (
                "Decide the final citation authors, public URL/DOI, version/date, and license."
                if missing_license
                else "Decide the final citation authors, public URL/DOI, and version/date."
            ),
            f"Create `{RELEASE_METADATA_FINAL_DECISION}` with the final author, license, DOI/URL, version, and date decisions.",
        ]
        if missing_license:
            minimum_actions.append(
                "Include `split_license_mapping` only if using split code/data/artifact licensing."
            )
        minimum_actions.extend(
            [
                f"Dry-run `{RELEASE_METADATA_DRY_RUN_COMMAND}`.",
                f"Apply with `{RELEASE_METADATA_WRITE_COMMAND}`.",
                f"Validate with `{RELEASE_METADATA_CHECK_COMMAND}`.",
            ]
        )
        lines += [
            "",
            "Minimum author actions before submission/public release:",
            "",
        ]
        lines.extend(f"{idx}. {action}" for idx, action in enumerate(minimum_actions, start=1))

    lines += ["", "## Manual Release Decisions", ""]
    manual_decisions = report.get("manual_decisions", [])
    if manual_decisions:
        lines += [
            "| ID | Status | Blocks Gate | Required Before Public Release | Next Action |",
            "| --- | --- | --- | --- | --- |",
        ]
        for item in manual_decisions:
            lines.append(
                f"| {item.get('id', '')} | {item.get('status', '')} | "
                f"{str(item.get('blocking_submission_gate')).lower()} | "
                f"{str(item.get('required_before_public_release')).lower()} | "
                f"{item.get('next_action', '')} |"
            )
    else:
        lines.append("- none")

    claim_paths, claim_phrases, claim_locations = claim_boundary_details(report)
    if claim_paths or claim_phrases or claim_locations:
        lines += ["", "## Claim Boundary Details", ""]
        if claim_paths:
            lines += ["Paths:", ""]
            for path, count in claim_paths.items():
                suffix = f" ({count} occurrences)" if count != 1 else ""
                lines.append(f"- {markdown_code(path)}{suffix}")
            lines.append("")
        if claim_phrases:
            lines += ["Forbidden submission-profile phrases:", ""]
            for phrase in claim_phrases:
                lines.append(f"- {markdown_code(phrase)}")
            lines.append("")
        if claim_locations:
            lines += [
                "Locations:",
                "",
                "| Path | Line | Phrase | Preview |",
                "| --- | ---: | --- | --- |",
            ]
            for detail in claim_locations:
                line = detail.get("line") or "n/a"
                preview = str(detail.get("preview") or "").replace("|", "\\|")
                lines.append(
                    f"| {markdown_code(detail.get('path', ''))} | {line} | "
                    f"{markdown_code(detail.get('phrase', ''))} | {preview} |"
                )

    warnings = [item for item in report["issues"] if item["severity"] == "warning"]
    lines += ["", "## Warnings", ""]
    if warnings:
        lines += [
            "| Scope | Issue | Occurrences | Evidence | Action |",
            "| --- | --- | ---: | --- | --- |",
        ]
        for item in warnings:
            lines.append(
                f"| {item['scope']} | {item['message']} | "
                f"{item.get('detail', {}).get('occurrences', 1)} | "
                f"{issue_evidence_summary(item) or 'n/a'} | {item['action']} |"
            )
    else:
        lines.append("- none")

    lines += [
        "",
        "## Operational Handoffs",
        "",
        "- Active baseline execution: `docs/generated_artifacts/paper_live_status.md`",
    ]
    if matrix_complete:
        lines += [
            "- Final attack report: `runs/_reports/paper_all/report.md`",
            "- Final control report: `runs/_reports/paper_controls_all/report.md`",
            "- Final result quality gate: `runs/_reports/paper_all/paper_result_quality_gate.md`",
            "- Formal repro bundle: `runs/_artifacts/repro_bundles/paper_all/`",
        ]
    else:
        lines += [
            "- Live partial attack report: `runs/_reports/paper_all_live_attack_partial/report.md`",
            "- Missing-oracle backfill dry-run: `runs/_reports/paper_all_live_attack_partial/missing_oracle_backfill.md`",
        ]
    lines += [
        "- Live matrix monitoring: `docs/generated_artifacts/paper_live_status.md` and `docs/generated_artifacts/paper_live_status_history.jsonl`",
        f"- Release metadata final decision JSON: `{RELEASE_METADATA_FINAL_DECISION}`",
        "",
        "## Next Commands",
        "",
        "```powershell",
        "python infra\\paper_queue_job.py list",
        "python infra\\paper_queue_job.py snapshot --out-json docs\\generated_artifacts\\paper_live_status.json --out-md docs\\generated_artifacts\\paper_live_status.md --check-md docs\\generated_artifacts\\paper_live_status_check.md --history-jsonl docs\\generated_artifacts\\paper_live_status_history.jsonl",
        "python infra\\check_paper_live_status.py --out docs\\generated_artifacts\\paper_live_status_check.md --require-ok",
        "python infra\\check_paper_readiness.py",
        "python infra\\plan_paper_experiment_matrix.py --out-json docs\\generated_artifacts\\paper_experiment_matrix_plan.json --out-md docs\\generated_artifacts\\paper_experiment_matrix_plan.md",
        "python infra\\check_paper_matrix_progress.py --out docs\\generated_artifacts\\paper_experiment_matrix_progress.md",
        "python infra\\check_paper_matrix_progress.py --harness claude --out docs\\generated_artifacts\\paper_experiment_matrix_progress_claude.md",
        "python infra\\export_paper_run_queue.py --out-json docs\\generated_artifacts\\paper_run_queue.json --out-md docs\\generated_artifacts\\paper_run_queue.md",
        "python infra\\run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json --queue-mode serial --out-json docs\\generated_artifacts\\paper_run_execution_plan.json --out-md docs\\generated_artifacts\\paper_run_execution_plan.md",
        "python infra\\run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json --queue-mode serial --harness claude --out-json docs\\generated_artifacts\\paper_run_execution_claude_dry_run.json --out-md docs\\generated_artifacts\\paper_run_execution_claude_dry_run.md",
        "python infra\\run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json --queue-mode post-run --harness claude --out-json docs\\generated_artifacts\\paper_run_execution_claude_post_run_dry_run.json --out-md docs\\generated_artifacts\\paper_run_execution_claude_post_run_dry_run.md",
        "python infra\\estimate_paper_run_budget.py --out-json docs\\generated_artifacts\\paper_run_budget.json --out-md docs\\generated_artifacts\\paper_run_budget.md",
        "python infra\\report_paper_submission_gaps.py --out docs\\generated_artifacts\\paper_submission_gap_report.md --json-out docs\\generated_artifacts\\paper_submission_gap_report.json",
    ]
    if matrix_complete:
        lines += [
            "# Matrix is complete; no watcher restart or queued benchmark execution is required.",
            "python infra\\report_active_run.py --label paper_all --case-set all --all-matching-runs --run-kind attack --harness claude --out-dir runs\\_reports\\paper_all",
            "python infra\\report_active_run.py --label paper_controls_all --case-set all --all-matching-runs --run-kind control --control-type all --harness claude --out-dir runs\\_reports\\paper_controls_all",
            "python infra\\check_paper_results.py --attack-label paper_all --control-label paper_controls_all --case-set all --min-attack-trials 1 --min-control-trials 1 --expected-harness claude --max-timeouts 3 --out runs\\_reports\\paper_all\\paper_result_quality_gate.md",
            "python infra\\export_paper_tables.py --attack-label paper_all --control-label paper_controls_all --out-dir runs\\_reports\\paper_all\\paper_tables",
            "python infra\\export_case_study_evidence.py --attack-label paper_all --control-label paper_controls_all --out-dir runs\\_reports\\paper_all\\case_study_evidence",
        ]
    else:
        lines += [
            f"python infra\\paper_queue_job.py restart-watch --job-name {active_job}",
            "python infra\\run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json --queue-mode serial --harness claude --execute --out-json docs\\generated_artifacts\\paper_run_execution_claude_plan.json --out-md docs\\generated_artifacts\\paper_run_execution_claude_plan.md",
            "python infra\\run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json --queue-mode post-run --harness claude --execute --out-json docs\\generated_artifacts\\paper_run_execution_claude_post_run.json --out-md docs\\generated_artifacts\\paper_run_execution_claude_post_run.md",
            "python infra\\backfill_missing_oracles.py --label paper_all --case-set all --all-matching-runs --run-kind attack --harness claude --min-age-sec 600 --fail-on-eligible --out-json runs\\_reports\\paper_all_live_attack_partial\\missing_oracle_backfill.json --out-md runs\\_reports\\paper_all_live_attack_partial\\missing_oracle_backfill.md",
            "python infra\\report_active_run.py --label paper_all --case-set all --all-matching-runs --run-kind attack --harness claude --out-dir runs\\_reports\\paper_all_live_attack_partial",
            "python infra\\check_paper_results.py --attack-report-dir runs\\_reports\\paper_all_live_attack_partial --case-set all --min-attack-trials 1 --expected-harness claude --allow-partial --out runs\\_reports\\paper_all_live_attack_partial\\paper_result_quality_gate_partial.md",
        ]
    lines += [
        "python infra\\check_paper_numbers.py --attack-label paper_all --control-label paper_controls_all --table-dir runs\\_reports\\paper_all\\paper_tables --case-evidence-dir runs\\_reports\\paper_all\\case_study_evidence --out runs\\_reports\\paper_all\\paper_numbers_check.md",
        "python infra\\build_repro_bundle.py --attack-label paper_all --control-label paper_controls_all --table-dir runs\\_reports\\paper_all\\paper_tables --case-evidence-dir runs\\_reports\\paper_all\\case_study_evidence --out-dir runs\\_artifacts\\repro_bundles\\paper_all --copy-artifacts",
        "python infra\\check_public_artifact_safety.py --bundle-dir runs\\_artifacts\\repro_bundles\\paper_all",
        "python infra\\check_paper_artifact_gate.py --attack-label paper_all --control-label paper_controls_all --table-dir runs\\_reports\\paper_all\\paper_tables --bundle-dir runs\\_artifacts\\repro_bundles\\paper_all --case-evidence-dir runs\\_reports\\paper_all\\case_study_evidence --case-set all --min-attack-trials 1 --expected-harness claude --max-timeouts 3 --submission-profile --out runs\\_reports\\paper_all\\paper_artifact_gate_submission.md",
        RELEASE_METADATA_DRY_RUN_COMMAND,
        RELEASE_METADATA_WRITE_COMMAND,
        RELEASE_METADATA_CHECK_COMMAND,
        "python infra\\check_paper_matrix_progress.py --require-complete --harness claude --out runs\\_reports\\paper_all\\paper_matrix_progress.md",
        ".\\infra\\run_paper_preflight.ps1 -Profile submission",
        "```",
        "",
    ]
    if not matrix_complete:
        lines.append(
            "Resume interrupted runs with `--start-at <batch_id>` using the batch ids listed in `docs/generated_artifacts/paper_run_execution_plan.md`."
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a paper submission gap report.")
    parser.add_argument("--plan", default="", help="Path to paper_experiment_matrix_plan.json.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", default="", help="Optional output path.")
    parser.add_argument(
        "--json-out",
        default="",
        help="Optional machine-readable JSON output path, written in addition to --out/stdout.",
    )
    parser.add_argument(
        "--require-ready",
        action="store_true",
        help="Exit non-zero if submission blockers remain.",
    )
    args = parser.parse_args()

    report = build_gap_report(plan_path=Path(args.plan) if args.plan else None)
    json_text = json.dumps(report, indent=2, ensure_ascii=False)
    text = json_text if args.json else render_markdown(report)
    if args.out:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    if args.json_out:
        json_path = Path(args.json_out)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json_text + "\n", encoding="utf-8")
    return 1 if args.require_ready and not report["submission_ready"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
