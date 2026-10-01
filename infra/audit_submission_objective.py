"""Audit the paper submission objective against current repository evidence."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from infra import (
        check_paper_bibliography,
        check_paper_claims,
        check_paper_manuscript,
        check_repo_release_cleanliness,
        check_release_metadata,
    )
except ModuleNotFoundError:  # direct `python infra/audit_submission_objective.py`
    import check_paper_bibliography  # type: ignore
    import check_paper_claims  # type: ignore
    import check_paper_manuscript  # type: ignore
    import check_repo_release_cleanliness  # type: ignore
    import check_release_metadata  # type: ignore


ROOT = Path(__file__).resolve().parent.parent

DEFAULT_OUT_JSON = "docs/generated_artifacts/paper_submission_objective_audit.json"
DEFAULT_OUT_MD = "docs/generated_artifacts/paper_submission_objective_audit.md"


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError:
        return {}


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig") if path.is_file() else ""


def contains_phrase(text: str, phrase: str) -> bool:
    compact_text = re.sub(r"\s+", " ", text)
    compact_phrase = re.sub(r"\s+", " ", phrase)
    return compact_phrase in compact_text


def gate_ok(path: Path) -> bool | None:
    text = read_text(path)
    if not text:
        return None
    match = re.search(r"(?m)^- ok: `(?P<ok>true|false)`", text)
    if not match:
        return None
    return match.group("ok") == "true"


def item(
    item_id: str,
    title: str,
    status: str,
    *,
    required: bool,
    evidence: list[str],
    next_action: str,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": item_id,
        "title": title,
        "status": status,
        "required_for_submission": required,
        "evidence": evidence,
        "next_action": next_action,
        "detail": detail or {},
    }


def status_blocks_submission(status: str, required: bool) -> bool:
    return required and status in {"blocked", "missing", "failed"}


def release_metadata_item(root: Path) -> dict[str, Any]:
    report = check_release_metadata.build_release_metadata_report(root, require_license=True)
    summary = report.get("summary", {})
    next_actions = report.get("next_actions", [])
    status = "complete" if report.get("ok") and summary.get("public_release_ready") else "blocked"
    return item(
        "release_metadata",
        "Finalize root license and CITATION metadata",
        status,
        required=True,
        evidence=[
            "CITATION.cff",
            "docs/release_metadata_final.json",
            "infra/apply_release_metadata_decisions.py",
            "infra/check_release_metadata.py",
        ],
        next_action=(
            "Create docs/release_metadata_final.json, dry-run/apply it with "
            "infra/apply_release_metadata_decisions.py, then rerun "
            "python infra\\check_release_metadata.py --require-license."
        )
        if status != "complete"
        else "No action required.",
        detail={
            "ok": report.get("ok"),
            "public_release_ready": summary.get("public_release_ready"),
            "license_present": summary.get("license_present"),
            "citation_placeholder_author": summary.get("citation_placeholder_author"),
            "citation_preprint": summary.get("citation_preprint"),
            "citation_has_public_link": summary.get("citation_has_public_link"),
            "error_count": summary.get("error_count", 0),
            "warning_count": summary.get("warning_count", 0),
            "next_action_ids": [entry.get("id") for entry in next_actions],
        },
    )


def paper_body_item(root: Path) -> dict[str, Any]:
    manuscript = check_paper_manuscript.build_manuscript_report(root)
    current_claims = check_paper_claims.build_claim_report(root, profile="current_claude")
    submission_claims = check_paper_claims.build_claim_report(root, profile="submission")
    bibliography = check_paper_bibliography.build_bibliography_report(root)
    draft = read_text(root / "docs/paper_draft.md")
    boundary_ok = all(
        contains_phrase(draft, phrase)
        for phrase in [
            "328 active hard-oracle cases",
            "328 metric-eligible cases",
            "planned case scope",
        ]
    )
    ok = (
        manuscript.get("ok")
        and current_claims.get("ok")
        and submission_claims.get("ok")
        and bibliography.get("ok")
        and boundary_ok
    )
    return item(
        "paper_body",
        "Finalize paper prose and claim boundary",
        "complete" if ok else "failed",
        required=True,
        evidence=[
            "docs/paper_draft.md",
            "runs/_reports/<formal-label>/paper_manuscript_check.md",
            "runs/_reports/<formal-label>/paper_bibliography_check.md",
            "infra/check_paper_manuscript.py",
            "infra/check_paper_claims.py",
        ],
        next_action=(
            "Fix manuscript, claim-boundary, or bibliography issues before submission."
            if not ok
            else "Venue-specific formatting can be applied by the author without changing the claim boundary."
        ),
        detail={
            "manuscript_ok": manuscript.get("ok"),
            "manuscript_sections": manuscript.get("required_sections"),
            "manuscript_phrases": manuscript.get("required_phrases"),
            "current_claims_ok": current_claims.get("ok"),
            "submission_claims_ok": submission_claims.get("ok"),
            "bibliography_ok": bibliography.get("ok"),
            "boundary_phrases_ok": boundary_ok,
        },
    )


def final_gate_item(root: Path) -> dict[str, Any]:
    current_gate = gate_ok(root / "runs/_reports/paper_core_20260625/paper_artifact_gate.md")
    submission_gate = gate_ok(root / "runs/_reports/paper_core_20260625/paper_artifact_gate_submission.md")
    gap = load_json(root / "docs/generated_artifacts/paper_submission_gap_report.json")
    gap_summary = gap.get("summary", {})
    status = "complete" if submission_gate is True and gap.get("submission_ready") else "blocked"
    return item(
        "final_submission_gate",
        "Run final submission gate",
        status,
        required=True,
        evidence=[
            "runs/_reports/paper_core_20260625/paper_artifact_gate.md",
            "runs/_reports/paper_core_20260625/paper_artifact_gate_submission.md",
            "docs/generated_artifacts/paper_submission_gap_report.md",
            "infra/run_paper_preflight.ps1",
        ],
        next_action=(
            "After release metadata is finalized, run .\\infra\\run_paper_preflight.ps1 -Profile submission."
            if status != "complete"
            else "No action required."
        ),
        detail={
            "current_artifact_gate_ok": current_gate,
            "submission_artifact_gate_ok": submission_gate,
            "submission_gap_ready": gap.get("submission_ready"),
            "gap_errors": gap_summary.get("error_count", 0),
            "blocking_manual_decisions": gap_summary.get("blocking_manual_decision_count", 0),
        },
    )


def full_suite_item(root: Path) -> dict[str, Any]:
    path = root / "docs/generated_artifacts/paper_full_suite_eligibility.json"
    report = load_json(path)
    summary = report.get("summary", {})
    ok = (
        path.is_file()
        and (root / "docs/generated_artifacts/paper_full_suite_eligibility.md").is_file()
        and summary.get("active_cases") == 328
        and summary.get("main_asr_cases") == 328
        and summary.get("diagnostic_cases") == 0
        and summary.get("runnable_matrix_rows") == 2296
        and summary.get("formal_main_table_rows") == 2296
        and summary.get("diagnostic_matrix_rows") == 0
        and summary.get("core_cases") == 328
        and "planned/design-time case scope" in str(summary.get("claim_boundary", ""))
        and "planned/design-time" in str(summary.get("claim_boundary", ""))
    )
    return item(
        "full_suite_eligibility_appendix",
        "Document the 328-case runnable and planned/design-time case scope",
        "complete" if ok else "missing",
        required=False,
        evidence=[
            "docs/generated_artifacts/paper_full_suite_eligibility.md",
            "docs/generated_artifacts/paper_full_suite_eligibility.json",
            "infra/generate_full_suite_eligibility_appendix.py",
        ],
        next_action="Regenerate the full-suite eligibility appendix." if not ok else "No action required.",
        detail={
            "active_cases": summary.get("active_cases"),
            "main_asr_cases": summary.get("main_asr_cases"),
            "diagnostic_cases": summary.get("diagnostic_cases"),
            "runnable_matrix_rows": summary.get("runnable_matrix_rows"),
            "formal_main_table_rows": summary.get("formal_main_table_rows"),
            "diagnostic_matrix_rows": summary.get("diagnostic_matrix_rows"),
            "core_cases": summary.get("core_cases"),
            "extended_cases": summary.get("extended_cases"),
            "exploratory_cases": summary.get("exploratory_cases"),
        },
    )


def external_validity_item(root: Path) -> dict[str, Any]:
    path = root / "docs/generated_artifacts/paper_external_validity_plan.json"
    report = load_json(path)
    summary = report.get("summary", {})
    ok = (
        path.is_file()
        and (root / "docs/generated_artifacts/paper_external_validity_plan.md").is_file()
        and summary.get("active_cases") == 328
        and summary.get("formal_cases") == 328
        and summary.get("diagnostic_cases") == 0
        and summary.get("candidate_cases") == 137
        and summary.get("selected_cases") == 12
        and "328-case metric-eligible set" in str(summary.get("main_asr_boundary", ""))
        and "328-case runnable hard-oracle coverage" in str(summary.get("main_asr_boundary", ""))
    )
    return item(
        "external_validity_plan",
        "Prepare appendix-only external-validity calibration plan",
        "complete" if ok else "missing",
        required=False,
        evidence=[
            "docs/generated_artifacts/paper_external_validity_plan.md",
            "docs/generated_artifacts/paper_external_validity_plan.json",
            "infra/plan_external_validity_calibration.py",
        ],
        next_action="Regenerate the external-validity calibration plan." if not ok else "No action required.",
        detail={
            "active_cases": summary.get("active_cases"),
            "formal_cases": summary.get("formal_cases"),
            "diagnostic_cases": summary.get("diagnostic_cases"),
            "candidate_cases": summary.get("candidate_cases"),
            "selected_cases": summary.get("selected_cases"),
            "per_suite_target": summary.get("per_suite_target"),
            "selected_by_suite": summary.get("selected_by_suite", {}),
        },
    )


def repo_release_item(root: Path) -> dict[str, Any]:
    inventory = load_json(root / "docs/generated_artifacts/repo_change_inventory.json")
    summary = inventory.get("summary", {})
    logical_commits = summary.get("logical_commits", {})
    current_cleanliness = check_repo_release_cleanliness.build_report(root)
    strict_cleanliness = check_repo_release_cleanliness.build_report(
        root,
        require_clean=True,
        require_release_metadata=True,
    )
    has_plan = (
        bool(logical_commits)
        and (root / "docs/generated_artifacts/repo_change_inventory.md").is_file()
        and current_cleanliness.get("summary", {}).get("ordered_logical_commit_count", 0) > 0
    )
    final_release_ready = (
        strict_cleanliness.get("ok")
        and strict_cleanliness.get("summary", {}).get("tag_release_ready")
    )
    if final_release_ready:
        status = "complete"
    elif has_plan and current_cleanliness.get("ok"):
        status = "pending"
    elif has_plan:
        status = "failed"
    else:
        status = "missing"
    do_not_commit_entries = summary.get("do_not_commit_entries", 0)
    if do_not_commit_entries:
        next_action = (
            "After release metadata is finalized, remove or ignore do-not-commit local state, "
            "stage logical commit buckets from docs/generated_artifacts/repo_change_inventory.md, rerun "
            "python infra\\check_repo_release_cleanliness.py --require-clean --require-release-metadata, "
            "then tag/release and mint DOI."
        )
    else:
        next_action = (
            "After release metadata is finalized, stage logical commit buckets from "
            "docs/generated_artifacts/repo_change_inventory.md using docs/generated_artifacts/repo_release_stage_pathspecs/*.txt, rerun "
            "python infra\\check_repo_release_cleanliness.py --require-clean --require-release-metadata, "
            "then tag/release and mint DOI."
        )
    return item(
        "repo_cleanup_release",
        "Prepare logical commits, tag, release, and DOI",
        status,
        required=True,
        evidence=[
            "docs/generated_artifacts/repo_change_inventory.md",
            "docs/generated_artifacts/repo_change_inventory.json",
            "infra/check_repo_release_cleanliness.py",
            "runs/_artifacts/repro_bundles/paper_core_20260625/repro_manifest.json",
        ],
        next_action=next_action,
        detail={
            "changed_entries": summary.get("changed_entries", 0),
            "do_not_commit_entries": do_not_commit_entries,
            "logical_commits": logical_commits,
            "has_logical_commit_plan": has_plan,
            "current_cleanliness_ok": current_cleanliness.get("ok"),
            "strict_cleanliness_ok": strict_cleanliness.get("ok"),
            "stage_group_count": current_cleanliness.get("summary", {}).get("stage_group_count", 0),
            "tag_release_ready": strict_cleanliness.get("summary", {}).get("tag_release_ready"),
            "cleanliness_error_count": strict_cleanliness.get("summary", {}).get("error_count", 0),
        },
    )


def build_audit(root: Path = ROOT) -> dict[str, Any]:
    required = [
        release_metadata_item(root),
        paper_body_item(root),
        final_gate_item(root),
        repo_release_item(root),
    ]
    enhancements = [
        full_suite_item(root),
        external_validity_item(root),
    ]
    all_items = [*required, *enhancements]
    blockers = [entry for entry in all_items if status_blocks_submission(entry["status"], entry["required_for_submission"])]
    pending_required = [
        entry
        for entry in all_items
        if entry["required_for_submission"] and entry["status"] in {"pending", "conditional"}
    ]
    return {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "submission_ready": not blockers and not pending_required,
        "required_items": required,
        "enhancement_items": enhancements,
        "summary": {
            "required_total": len(required),
            "required_complete": sum(1 for entry in required if entry["status"] == "complete"),
            "required_blocked": len(blockers),
            "required_pending": len(pending_required),
            "enhancements_total": len(enhancements),
            "enhancements_complete": sum(1 for entry in enhancements if entry["status"] == "complete"),
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    lines = [
        "# Paper Submission Objective Audit",
        "",
        f"- generated_at: `{report.get('generated_at')}`",
        f"- submission_ready: `{str(report.get('submission_ready')).lower()}`",
        f"- required_complete: `{summary.get('required_complete', 0)}/{summary.get('required_total', 0)}`",
        f"- required_blocked: `{summary.get('required_blocked', 0)}`",
        f"- required_pending: `{summary.get('required_pending', 0)}`",
        f"- enhancements_complete: `{summary.get('enhancements_complete', 0)}/{summary.get('enhancements_total', 0)}`",
        "",
        "## Required Items",
        "",
        "| ID | Status | Evidence | Next Action |",
        "| --- | --- | --- | --- |",
    ]
    for entry in report.get("required_items", []):
        evidence = "<br>".join(f"`{path}`" for path in entry.get("evidence", []))
        lines.append(
            f"| {entry.get('id', '')} | `{entry.get('status', '')}` | "
            f"{evidence} | {entry.get('next_action', '')} |"
        )
    lines += [
        "",
        "## Enhancement Items",
        "",
        "| ID | Status | Evidence | Next Action |",
        "| --- | --- | --- | --- |",
    ]
    for entry in report.get("enhancement_items", []):
        evidence = "<br>".join(f"`{path}`" for path in entry.get("evidence", []))
        lines.append(
            f"| {entry.get('id', '')} | `{entry.get('status', '')}` | "
            f"{evidence} | {entry.get('next_action', '')} |"
        )
    lines += [
        "",
        "## Detail",
        "",
        "```json",
        json.dumps(
            {
                "required_items": {
                    entry["id"]: entry.get("detail", {})
                    for entry in report.get("required_items", [])
                },
                "enhancement_items": {
                    entry["id"]: entry.get("detail", {})
                    for entry in report.get("enhancement_items", [])
                },
            },
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        ),
        "```",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit paper submission objective completion.")
    parser.add_argument("--json-out", default=DEFAULT_OUT_JSON)
    parser.add_argument("--out", default=DEFAULT_OUT_MD)
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()

    report = build_audit(ROOT)
    json_text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    md_text = render_markdown(report)
    if args.json_out:
        json_path = ROOT / args.json_out
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json_text, encoding="utf-8")
    if args.out:
        md_path = ROOT / args.out
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(md_text, encoding="utf-8")
    else:
        print(md_text, end="")
    return 1 if args.require_ready and not report["submission_ready"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
