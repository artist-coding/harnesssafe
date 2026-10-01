import json
from pathlib import Path

from infra import audit_submission_objective as audit
from infra import check_repo_release_cleanliness


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _seed_static_reports(root: Path) -> None:
    _write(root / "runs/_reports/paper_core_20260625/paper_artifact_gate.md", "- ok: `true`\n")
    _write(root / "runs/_reports/paper_core_20260625/paper_artifact_gate_submission.md", "- ok: `false`\n")
    _write(
        root / "docs/generated_artifacts/paper_submission_gap_report.json",
        json.dumps(
            {
                "submission_ready": False,
                "summary": {
                    "error_count": 1,
                    "blocking_manual_decision_count": 1,
                },
            }
        ),
    )
    _write(
        root / "docs/generated_artifacts/paper_full_suite_eligibility.json",
        json.dumps(
            {
                "summary": {
                    "active_cases": 328,
                    "main_asr_cases": 328,
                    "diagnostic_cases": 0,
                    "runnable_matrix_rows": 2296,
                    "formal_main_table_rows": 2296,
                    "diagnostic_matrix_rows": 0,
                    "core_cases": 328,
                    "extended_cases": 137,
                    "exploratory_cases": 96,
                    "claim_boundary": (
                        "All 328 active hard-oracle cases define runnable coverage. The planned/design-time case scope "
                        "contains all metric-eligible cases; realized conditional ASR uses only ASR-eligible "
                        "N0-N5b scored attack rows and excludes N-1."
                    ),
                }
            }
        ),
    )
    _write(root / "docs/generated_artifacts/paper_full_suite_eligibility.md", "# Full-Suite Eligibility Appendix\n")
    _write(
        root / "docs/generated_artifacts/paper_external_validity_plan.json",
        json.dumps(
            {
                "summary": {
                    "active_cases": 328,
                    "formal_cases": 328,
                    "diagnostic_cases": 0,
                    "candidate_cases": 137,
                    "selected_cases": 12,
                    "per_suite_target": 6,
                    "selected_by_suite": {"v2_skill_runtime": 6, "v2_tool_mcp_runtime": 6},
                    "main_asr_boundary": "The calibration uses the 328-case metric-eligible set, identical to the 328-case runnable hard-oracle coverage.",
                }
            }
        ),
    )
    _write(root / "docs/generated_artifacts/paper_external_validity_plan.md", "# External-Validity Calibration Plan\n")
    _write(
        root / "docs/generated_artifacts/repo_change_inventory.json",
        json.dumps(
            {
                "summary": {
                    "changed_entries": 344,
                    "do_not_commit_entries": 1,
                    "logical_commits": {"paper-infra-and-gates": 74},
                    "manual_review_entries": 0,
                },
                "release_staging_plan": {
                    "ordered_logical_commits": [
                        {
                            "logical_commit": "paper-infra-and-gates",
                            "entries": 74,
                            "categories": ["paper_infra"],
                            "policies": ["include"],
                        }
                    ],
                    "stage_groups": [
                        {
                            "logical_commit": "paper-infra-and-gates",
                            "entries": 1,
                            "pathspec_file": "docs/generated_artifacts/repo_release_stage_pathspecs/paper-infra-and-gates.txt",
                            "stage_command": "git add --pathspec-from-file docs/generated_artifacts/repo_release_stage_pathspecs/paper-infra-and-gates.txt",
                            "commit_command": 'git commit -m "paper-infra-and-gates: add paper validation and reporting gates"',
                            "paths": ["infra/check_repo_release_cleanliness.py"],
                        }
                    ],
                    "do_not_commit_entries": 1,
                    "manual_review_entries": 0,
                    "validation_commands": list(check_repo_release_cleanliness.REQUIRED_VALIDATION_COMMANDS),
                    "release_blockers": [],
                },
            }
        ),
    )
    _write(root / "docs/generated_artifacts/repo_change_inventory.md", "# Repo Change Inventory\n")
    _write(
        root / "docs/generated_artifacts/repo_release_stage_pathspecs/paper-infra-and-gates.txt",
        "infra/check_repo_release_cleanliness.py\n",
    )
    _write(root / "runs/_artifacts/repro_bundles/paper_core_20260625/repro_manifest.json", "{}\n")
    _write(
        root / "docs/paper_draft.md",
        "328 active hard-oracle cases\n328 metric-eligible cases\nplanned case scope\n"
        "historical pilot\n",
    )


def _patch_green_paper_checks(monkeypatch):
    monkeypatch.setattr(
        audit.check_release_metadata,
        "build_release_metadata_report",
        lambda root=None, require_license=True: {
            "ok": False,
            "summary": {
                "public_release_ready": False,
                "license_present": False,
                "citation_placeholder_author": True,
                "citation_preprint": True,
                "citation_has_public_link": False,
                "error_count": 1,
                "warning_count": 3,
            },
            "next_actions": [{"id": "add_final_license"}],
        },
    )
    monkeypatch.setattr(
        audit.check_paper_manuscript,
        "build_manuscript_report",
        lambda *args, **kwargs: {"ok": True, "required_sections": 15, "required_phrases": 62},
    )
    monkeypatch.setattr(
        audit.check_paper_claims,
        "build_claim_report",
        lambda root=None, profile="current_claude": {"ok": True},
    )
    monkeypatch.setattr(
        audit.check_paper_bibliography,
        "build_bibliography_report",
        lambda root=None: {"ok": True},
    )


def test_submission_objective_audit_maps_current_blockers(tmp_path: Path, monkeypatch):
    _seed_static_reports(tmp_path)
    _patch_green_paper_checks(monkeypatch)

    report = audit.build_audit(tmp_path)

    assert report["submission_ready"] is False
    required = {item["id"]: item for item in report["required_items"]}
    enhancements = {item["id"]: item for item in report["enhancement_items"]}
    assert required["release_metadata"]["status"] == "blocked"
    assert required["paper_body"]["status"] == "complete"
    assert required["paper_body"]["detail"]["manuscript_ok"] is True
    assert required["final_submission_gate"]["status"] == "blocked"
    assert required["repo_cleanup_release"]["status"] == "pending"
    assert required["repo_cleanup_release"]["detail"]["stage_group_count"] == 1
    assert enhancements["full_suite_eligibility_appendix"]["status"] == "complete"
    assert enhancements["external_validity_plan"]["status"] == "complete"
    assert report["summary"]["required_complete"] == 1
    assert report["summary"]["required_blocked"] == 2
    assert report["summary"]["required_pending"] == 1


def test_submission_objective_audit_renders_markdown(tmp_path: Path, monkeypatch):
    _seed_static_reports(tmp_path)
    _patch_green_paper_checks(monkeypatch)

    markdown = audit.render_markdown(audit.build_audit(tmp_path))

    assert "# Paper Submission Objective Audit" in markdown
    assert "release_metadata" in markdown
    assert "paper_body" in markdown
    assert "full_suite_eligibility_appendix" in markdown
    assert "external_validity_plan" in markdown
    assert "docs/release_metadata_final.json" in markdown
