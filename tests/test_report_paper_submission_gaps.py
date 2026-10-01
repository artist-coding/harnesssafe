import json
import sys
from pathlib import Path

from infra import report_paper_submission_gaps


def _patch_common(monkeypatch, *, matrix_complete: bool = False, release_ok: bool = False, claims_ok: bool = False):
    monkeypatch.setattr(
        report_paper_submission_gaps.check_paper_readiness,
        "build_readiness",
        lambda require_kimi=True, root=None: {
            "ready": True,
            "blockers": [],
            "warnings": [],
        },
    )
    monkeypatch.setattr(
        report_paper_submission_gaps.check_paper_suite_lock,
        "build_report",
        lambda root=None: {
            "ok": True,
            "actual_digest": "abc123456789",
            "expected_digest": "abc123456789",
            "issues": [],
        },
    )
    monkeypatch.setattr(
        report_paper_submission_gaps,
        "plan_status",
        lambda root, plan_path: (
            {
                "ok": True,
                "matrix_id": "m123",
                "matrix_digest": "digest",
                "case_set": "core",
                "summary": {"rows_total": 399},
            },
            [],
        ),
    )
    monkeypatch.setattr(
        report_paper_submission_gaps.check_paper_matrix_progress,
        "build_progress_report",
        lambda root=None, plan_path=None: {
            "complete": matrix_complete,
            "matrix_id": "m123",
            "summary": {
                "expected_rows": 399,
                "completed_rows": 399 if matrix_complete else 0,
                "execution_valid_completed_rows": 398 if matrix_complete else 0,
                "model_protocol_terminal_rows": 1 if matrix_complete else 0,
                "incomplete_rows": 0 if matrix_complete else 399,
                "execution_invalid_or_unvalidated_rows": 0 if matrix_complete else 399,
                "duplicate_accounted_expected_rows": 0,
                "completion_rate": 1.0 if matrix_complete else 0.0,
            },
            "issues": [],
        },
    )
    monkeypatch.setattr(
        report_paper_submission_gaps.check_release_metadata,
        "build_release_metadata_report",
        lambda root=None, require_license=True: {
            "ok": release_ok,
            "license_file": "LICENSE" if release_ok else "",
            "issues": []
            if release_ok
            else [
                {
                    "severity": "error",
                    "scope": "license",
                    "message": "no finalized root license file found",
                    "detail": {"accepted_names": ["LICENSE", "LICENSE.md", "COPYING", "COPYING.md"]},
                }
            ],
        },
    )
    monkeypatch.setattr(
        report_paper_submission_gaps.check_paper_claims,
        "build_claim_report",
        lambda root=None, profile="submission": {
            "ok": claims_ok,
            "issues": []
            if claims_ok
            else [
                {
                    "severity": "error",
                    "path": "docs/paper_draft.md",
                    "message": "submission profile still contains current/preliminary claim language",
                    "detail": {},
                }
            ],
        },
    )


def test_submission_gap_report_collects_current_blockers(tmp_path: Path, monkeypatch):
    _patch_common(monkeypatch)

    report = report_paper_submission_gaps.build_gap_report(root=tmp_path)

    assert report["submission_ready"] is False
    scopes = {item["scope"] for item in report["issues"] if item["severity"] == "error"}
    assert {"matrix_progress", "release_metadata", "claim_boundary"} <= scopes
    assert "readiness" not in scopes
    assert report["sections"]["matrix_progress"]["completed_rows"] == 0
    assert report["sections"]["matrix_progress"]["scored_rows"] == 0
    assert report["sections"]["matrix_progress"]["model_protocol_terminal_rows"] == 0
    assert report["summary"]["raw_error_count"] >= report["summary"]["error_count"]
    assert report["summary"]["manual_decision_count"] == 5
    assert report["summary"]["pending_manual_decision_count"] == 1
    assert report["summary"]["blocking_manual_decision_count"] == 1
    assert any(item["id"] == "license_file" and item["status"] == "pending" for item in report["manual_decisions"])
    license_decision = next(item for item in report["manual_decisions"] if item["id"] == "license_file")
    assert "docs/release_metadata_final.json" in license_decision["evidence"]
    assert "infra/apply_release_metadata_decisions.py" in license_decision["evidence"]
    assert "docs/release_metadata_final.json" in license_decision["next_action"]


def test_submission_gap_report_aggregates_duplicate_claim_boundary_issues(
    tmp_path: Path, monkeypatch
):
    _patch_common(monkeypatch)
    monkeypatch.setattr(
        report_paper_submission_gaps.check_paper_claims,
        "build_claim_report",
        lambda root=None, profile="submission": {
            "ok": False,
            "issues": [
                {
                    "severity": "error",
                    "path": "docs/paper_draft.md",
                    "message": "submission profile still contains current/preliminary claim language",
                    "detail": {"phrase": "preliminary", "line": 12, "preview": "These numbers are preliminary."},
                },
                {
                    "severity": "error",
                    "path": "docs/paper_current_status.md",
                    "message": "submission profile still contains current/preliminary claim language",
                    "detail": {
                        "phrase": "missing DashScope coding key",
                        "line": 7,
                        "preview": "missing DashScope coding key blocks optional Codex.",
                    },
                },
            ],
        },
    )

    report = report_paper_submission_gaps.build_gap_report(root=tmp_path)
    claim_issues = [
        item
        for item in report["issues"]
        if item["scope"] == "claim_boundary" and item["severity"] == "error"
    ]

    assert len(claim_issues) == 1
    assert claim_issues[0]["detail"]["occurrences"] == 2
    assert set(claim_issues[0]["detail"]["paths"]) == {
        "docs/paper_current_status.md",
        "docs/paper_draft.md",
    }
    assert report["summary"]["raw_error_count"] == report["summary"]["error_count"] + 1

    markdown = report_paper_submission_gaps.render_markdown(report)
    assert "## Claim Boundary Details" in markdown
    assert "`docs/paper_draft.md`" in markdown
    assert "`docs/paper_current_status.md`" in markdown
    assert "`preliminary`" in markdown
    assert "`missing DashScope coding key`" in markdown
    assert "Locations:" in markdown
    assert "| `docs/paper_draft.md` | 12 | `preliminary` | These numbers are preliminary. |" in markdown
    assert (
        "| `docs/paper_current_status.md` | 7 | `missing DashScope coding key` | "
        "missing DashScope coding key blocks optional Codex. |"
    ) in markdown


def test_submission_gap_report_can_be_ready_when_all_sections_pass(tmp_path: Path, monkeypatch):
    _patch_common(monkeypatch, matrix_complete=True, release_ok=True, claims_ok=True)
    monkeypatch.setattr(
        report_paper_submission_gaps.check_paper_readiness,
        "build_readiness",
        lambda require_kimi=True, root=None: {"ready": True, "blockers": [], "warnings": []},
    )

    report = report_paper_submission_gaps.build_gap_report(root=tmp_path)

    assert report["submission_ready"] is True
    assert report["summary"]["error_count"] == 0
    assert report["summary"]["pending_manual_decision_count"] == 0
    assert any(item["id"] == "license_file" and item["status"] == "complete" for item in report["manual_decisions"])


def test_submission_gap_report_blocks_on_pending_citation_metadata_after_license(
    tmp_path: Path, monkeypatch
):
    _patch_common(monkeypatch, matrix_complete=True, release_ok=True, claims_ok=True)
    monkeypatch.setattr(
        report_paper_submission_gaps.check_release_metadata,
        "build_release_metadata_report",
        lambda root=None, require_license=True: {
            "ok": True,
            "license_file": "LICENSE",
            "split_license_mapping_file": "LICENSES.md",
            "issues": [
                {
                    "severity": "warning",
                    "scope": "citation",
                    "message": "CITATION.cff uses placeholder author metadata",
                    "detail": {},
                },
                {
                    "severity": "warning",
                    "scope": "citation",
                    "message": "CITATION.cff is still marked as preprint",
                    "detail": {},
                },
                {
                    "severity": "warning",
                    "scope": "citation",
                    "message": "CITATION.cff does not include repository URL or DOI",
                    "detail": {},
                },
            ],
        },
    )

    report = report_paper_submission_gaps.build_gap_report(root=tmp_path)

    assert report["submission_ready"] is False
    assert report["summary"]["error_count"] == 0
    assert report["summary"]["pending_manual_decision_count"] == 3
    assert report["summary"]["blocking_manual_decision_count"] == 3
    decisions = {item["id"]: item for item in report["manual_decisions"]}
    assert decisions["license_file"]["status"] == "complete"
    assert decisions["license_file"]["next_action"] == (
        "No action required; the finalized root license and split license mapping are present."
    )
    assert decisions["split_license_mapping"]["status"] == "complete"
    assert decisions["citation_authors"]["blocking_submission_gate"] is True
    assert decisions["citation_public_url_or_doi"]["blocking_submission_gate"] is True
    assert decisions["citation_version_date"]["blocking_submission_gate"] is True

    markdown = report_paper_submission_gaps.render_markdown(report)
    assert "Decide the final citation authors, public URL/DOI, and version/date." in markdown
    assert "Decide the final citation authors, public URL/DOI, version/date, and license." not in markdown
    assert "| split_license_mapping | complete | false | true |" in markdown


def test_submission_gap_report_markdown_has_next_commands(tmp_path: Path, monkeypatch):
    _patch_common(monkeypatch)
    report = report_paper_submission_gaps.build_gap_report(root=tmp_path)

    markdown = report_paper_submission_gaps.render_markdown(report)

    assert "# Paper Submission Gap Report" in markdown
    assert "submission_ready: `false`" in markdown
    assert "export_paper_run_queue.py" in markdown
    assert "## Operational Handoffs" in markdown
    assert "docs/paper_kimi_handoff.md" not in markdown
    assert "docs/generated_artifacts/paper_live_status.md" in markdown
    assert "paper_all_live_attack_partial/report.md" in markdown
    assert "missing_oracle_backfill.md" in markdown
    assert "paper_queue_job.py list" in markdown
    assert "paper_queue_job.py snapshot" in markdown
    assert "--check-md docs\\generated_artifacts\\paper_live_status_check.md" in markdown
    assert "paper_queue_job.py restart-watch --job-name paper_core_claude_20260626" in markdown
    assert "check_paper_live_status.py --out docs\\generated_artifacts\\paper_live_status_check.md --require-ok" in markdown
    assert "docs\\generated_artifacts\\paper_run_execution_claude_dry_run.json" in markdown
    assert "docs\\generated_artifacts\\paper_run_execution_claude_post_run_dry_run.json" in markdown
    assert "--harness codex" not in markdown
    assert "check_release_metadata.py --require-license" in markdown
    assert "## Release Metadata Details" in markdown
    assert "## Manual Release Decisions" in markdown
    assert "| license_file | pending | true | true |" in markdown
    assert "| citation_authors | complete | false | true |" in markdown
    assert "| split_license_mapping | conditional | false | true |" in markdown
    assert "License file: `n/a`" in markdown
    assert "Accepted root license filenames: `COPYING`, `COPYING.md`, `LICENSE`, `LICENSE.md`" in markdown
    assert "docs/release_metadata_decision_template.md" not in markdown
    assert "Final decision JSON: `docs/release_metadata_final.json`" in markdown
    assert "Release metadata final decision JSON: `docs/release_metadata_final.json`" in markdown
    assert "Decide the final citation authors, public URL/DOI, version/date, and license." in markdown
    assert "Create `docs/release_metadata_final.json` with the final author, license, DOI/URL, version, and date decisions." in markdown
    assert "apply_release_metadata_decisions.py --decision docs\\release_metadata_final.json --require-license" in markdown
    assert "apply_release_metadata_decisions.py --decision docs\\release_metadata_final.json --require-license --write" in markdown
    assert "run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json --queue-mode serial --harness claude --execute" in markdown
    assert "run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json --queue-mode post-run --harness claude --execute" in markdown
    assert "run_paper_baseline_matrix.ps1" not in markdown
    assert "run_paper_control_matrix.ps1" not in markdown
    assert "--start-at <batch_id>" in markdown
    assert "estimate_paper_run_budget.py" in markdown
    assert "check_paper_matrix_progress.py --harness claude" in markdown
    assert "check_paper_matrix_progress.py --require-complete" in markdown
    assert "--json-out docs\\generated_artifacts\\paper_submission_gap_report.json" in markdown
    assert "backfill_missing_oracles.py --label paper_all" in markdown
    assert "--min-age-sec 600" in markdown
    assert "--fail-on-eligible" in markdown
    assert "report_active_run.py --label paper_all --case-set all --all-matching-runs --run-kind attack --harness claude --out-dir runs\\_reports\\paper_all_live_attack_partial" in markdown
    assert "check_paper_results.py --attack-report-dir runs\\_reports\\paper_all_live_attack_partial" in markdown
    assert "--allow-partial" in markdown
    assert "check_paper_numbers.py --attack-label paper_all" in markdown
    assert "--out runs\\_reports\\paper_all\\paper_numbers_check.md" in markdown
    assert "--harness claude --execute" in markdown
    assert "--queue-mode post-run --harness claude --execute" in markdown
    assert "build_repro_bundle.py --attack-label paper_all" in markdown
    assert "--control-label paper_controls_all" in markdown
    assert "--table-dir runs\\_reports\\paper_all\\paper_tables" in markdown
    assert "--case-evidence-dir runs\\_reports\\paper_all\\case_study_evidence" in markdown
    assert "check_public_artifact_safety.py --bundle-dir runs\\_artifacts\\repro_bundles\\paper_all" in markdown
    assert "check_paper_artifact_gate.py --attack-label paper_all" in markdown
    assert "--bundle-dir runs\\_artifacts\\repro_bundles\\paper_all" in markdown
    assert "--expected-harness claude" in markdown
    assert "--submission-profile" in markdown
    assert "--out runs\\_reports\\paper_all\\paper_artifact_gate_submission.md" in markdown
    assert "## Claim Boundary Details" in markdown
    assert "`docs/paper_draft.md`" in markdown
    assert "Forbidden submission-profile phrases" not in markdown


def test_submission_gap_report_uses_active_live_job_for_restart_watch(tmp_path: Path, monkeypatch):
    _patch_common(monkeypatch)
    live = {
        "jobs": [
            {"job_name": "paper_core_claude_20260626", "observed_status": "failed"},
            {"job_name": "paper_core_claude_20260626_resume9", "observed_status": "running"},
        ]
    }
    live_path = tmp_path / "docs/generated_artifacts/paper_live_status.json"
    live_path.parent.mkdir(parents=True, exist_ok=True)
    live_path.write_text(json.dumps(live), encoding="utf-8")
    report = report_paper_submission_gaps.build_gap_report(root=tmp_path)

    markdown = report_paper_submission_gaps.render_markdown(report)

    assert "paper_queue_job.py restart-watch --job-name paper_core_claude_20260626_resume9" in markdown


def test_submission_gap_report_omits_execution_commands_when_matrix_complete(tmp_path: Path, monkeypatch):
    _patch_common(monkeypatch, matrix_complete=True)

    report = report_paper_submission_gaps.build_gap_report(root=tmp_path)
    markdown = report_paper_submission_gaps.render_markdown(report)

    assert "# Matrix is complete; no watcher restart or queued benchmark execution is required." in markdown
    assert "paper_queue_job.py restart-watch" not in markdown
    assert "--harness claude --execute" not in markdown
    assert "docs\\generated_artifacts\\paper_run_execution_claude_dry_run.json" in markdown
    assert "paper_all_live_attack_partial" not in markdown
    assert "backfill_missing_oracles.py --label paper_all" not in markdown
    assert "--allow-partial" not in markdown
    assert "--start-at <batch_id>" not in markdown
    assert "Final attack report: `runs/_reports/paper_all/report.md`" in markdown
    assert "Final control report: `runs/_reports/paper_controls_all/report.md`" in markdown
    assert "docs/release_metadata_decision_template.md" not in markdown
    assert "Release metadata final decision JSON: `docs/release_metadata_final.json`" in markdown
    assert "check_paper_results.py --attack-label paper_all --control-label paper_controls_all" in markdown
    assert "export_paper_tables.py --attack-label paper_all" in markdown
    assert "export_case_study_evidence.py --attack-label paper_all" in markdown


def test_submission_gap_report_cli_writes_json_sidecar(tmp_path: Path, monkeypatch):
    report = {
        "generated_at": "2026-06-26T00:00:00",
        "root": str(tmp_path),
        "plan_path": str(tmp_path / "docs/generated_artifacts/paper_experiment_matrix_plan.json"),
        "submission_ready": False,
        "sections": {
            "current_readiness": {"ready": True, "blockers": [], "warnings": []},
            "submission_readiness": {"ready": False, "blockers": ["missing Kimi"], "warnings": []},
            "suite_lock": {"ok": True, "actual_digest": "abc", "issue_count": 0},
            "experiment_plan": {"ok": True, "matrix_id": "m123", "summary": {"rows_total": 399}},
            "matrix_progress": {"complete": False, "completed_rows": 0, "expected_rows": 399},
            "release_metadata": {"ok": False, "license_file": "", "issue_count": 1},
            "claim_boundary": {"ok": False, "issue_count": 1},
        },
        "issues": [],
        "raw_issues": [],
        "summary": {
            "error_count": 1,
            "warning_count": 0,
            "issue_count": 1,
            "raw_error_count": 1,
            "raw_warning_count": 0,
            "raw_issue_count": 1,
        },
    }
    monkeypatch.setattr(report_paper_submission_gaps, "build_gap_report", lambda plan_path=None: report)
    out = tmp_path / "paper_submission_gap_report.md"
    json_out = tmp_path / "paper_submission_gap_report.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "report_paper_submission_gaps.py",
            "--out",
            str(out),
            "--json-out",
            str(json_out),
        ],
    )

    assert report_paper_submission_gaps.main() == 0

    assert "submission_ready: `false`" in out.read_text(encoding="utf-8")
    assert json.loads(json_out.read_text(encoding="utf-8"))["summary"]["error_count"] == 1
