import hashlib
import json
from pathlib import Path

from infra import check_public_artifact_safety


def _write(path: Path, text: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_bundle(bundle: Path, copied: list[dict] | None = None) -> None:
    _write(
        bundle / "repro_manifest.json",
        json.dumps({"missing_artifacts": [], "copied_artifacts": copied or []}),
    )
    _write(bundle / "repro_manifest.md", "# Repro\n")


def test_public_artifact_safety_accepts_allowlisted_copied_artifacts(tmp_path: Path):
    bundle = tmp_path / "bundle"
    copied_text = "{}\n"
    digest = _write(bundle / "files/runs/_reports/paper_core/summary.json", copied_text)
    _write_bundle(
        bundle,
        [
            {
                "role": "attack_report:summary.json",
                "copied_to": "files/runs/_reports/paper_core/summary.json",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True
    assert report["issues"] == []
    assert report["summary"]["file_count"] == 3


def test_public_artifact_safety_allows_documented_placeholder_credentials(tmp_path: Path):
    bundle = tmp_path / "bundle"
    doc = '$env:DASHSCOPE_CODING_API_KEY = "<dashscope-key>"\n'
    digest = _write(bundle / "files/docs/paper_artifact_evaluation_readme.md", doc)
    _write_bundle(
        bundle,
        [
            {
                "role": "release_metadata:docs/paper_artifact_evaluation_readme.md",
                "copied_to": "files/docs/paper_artifact_evaluation_readme.md",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_benchmark_card_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/benchmark_card.md", "# Safety Bench Benchmark Card\n")
    _write_bundle(
        bundle,
        [
            {
                "role": "benchmark_card:docs/generated_artifacts/benchmark_card.md",
                "copied_to": "files/docs/generated_artifacts/benchmark_card.md",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_supplementary_appendix_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_supplementary_appendix.md", "# Safety Bench Supplementary Appendix\n")
    _write_bundle(
        bundle,
        [
            {
                "role": "supplementary_appendix:docs/generated_artifacts/paper_supplementary_appendix.md",
                "copied_to": "files/docs/generated_artifacts/paper_supplementary_appendix.md",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_oracle_coverage_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_oracle_coverage.md", "# Safety Bench Oracle Coverage Report\n")
    _write_bundle(
        bundle,
        [
            {
                "role": "oracle_coverage:docs/generated_artifacts/paper_oracle_coverage.md",
                "copied_to": "files/docs/generated_artifacts/paper_oracle_coverage.md",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_threat_model_card_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_threat_model_card.md", "# Safety Bench Threat Model Card\n")
    _write_bundle(
        bundle,
        [
            {
                "role": "threat_model_card:docs/generated_artifacts/paper_threat_model_card.md",
                "copied_to": "files/docs/generated_artifacts/paper_threat_model_card.md",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_statistical_analysis_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_statistical_analysis.md", "# Safety Bench Statistical Analysis\n")
    _write_bundle(
        bundle,
        [
            {
                "role": "statistical_analysis:docs/generated_artifacts/paper_statistical_analysis.md",
                "copied_to": "files/docs/generated_artifacts/paper_statistical_analysis.md",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_claim_evidence_map_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_claim_evidence_map.md", "# Paper Claim Evidence Map\n")
    _write_bundle(
        bundle,
        [
            {
                "role": "claim_evidence_map:docs/generated_artifacts/paper_claim_evidence_map.md",
                "copied_to": "files/docs/generated_artifacts/paper_claim_evidence_map.md",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_control_integrity_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_control_integrity_report.md", "# Paper Control Integrity Report\n")
    _write_bundle(
        bundle,
        [
            {
                "role": "control_integrity:docs/generated_artifacts/paper_control_integrity_report.md",
                "copied_to": "files/docs/generated_artifacts/paper_control_integrity_report.md",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_paper_figure_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/figures/figure_1_benchmark_frame.svg", "<svg></svg>\n")
    _write_bundle(
        bundle,
        [
            {
                "role": "paper_figures:docs/figures/figure_1_benchmark_frame.svg",
                "copied_to": "files/docs/figures/figure_1_benchmark_frame.svg",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_bibliography_check_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_bibliography_check.md", "# Paper Bibliography Check\n")
    _write_bundle(
        bundle,
        [
            {
                "role": "bibliography_check:docs/generated_artifacts/paper_bibliography_check.md",
                "copied_to": "files/docs/generated_artifacts/paper_bibliography_check.md",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_manuscript_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/paper_draft.md", "# Safety Bench\n")
    _write_bundle(
        bundle,
        [
            {
                "role": "manuscript:docs/paper_draft.md",
                "copied_to": "files/docs/paper_draft.md",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_full_suite_eligibility_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_full_suite_eligibility.md", "# Full-Suite Eligibility Appendix\n")
    _write_bundle(
        bundle,
        [
            {
                "role": "full_suite_eligibility:docs/generated_artifacts/paper_full_suite_eligibility.md",
                "copied_to": "files/docs/generated_artifacts/paper_full_suite_eligibility.md",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_external_validity_plan_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_external_validity_plan.md", "# External-Validity Calibration Plan\n")
    _write_bundle(
        bundle,
        [
            {
                "role": "external_validity_plan:docs/generated_artifacts/paper_external_validity_plan.md",
                "copied_to": "files/docs/generated_artifacts/paper_external_validity_plan.md",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_suite_lock_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_suite_lock.json", '{"case_counts": {}}\n')
    _write_bundle(
        bundle,
        [
            {
                "role": "suite_lock:docs/generated_artifacts/paper_suite_lock.json",
                "copied_to": "files/docs/generated_artifacts/paper_suite_lock.json",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_experiment_plan_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_experiment_matrix_plan.json", '{"summary": {}}\n')
    _write_bundle(
        bundle,
        [
            {
                "role": "experiment_plan:docs/generated_artifacts/paper_experiment_matrix_plan.json",
                "copied_to": "files/docs/generated_artifacts/paper_experiment_matrix_plan.json",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_matrix_progress_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_experiment_matrix_progress.md", "# progress\n")
    _write_bundle(
        bundle,
        [
            {
                "role": "matrix_progress:docs/generated_artifacts/paper_experiment_matrix_progress.md",
                "copied_to": "files/docs/generated_artifacts/paper_experiment_matrix_progress.md",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_run_budget_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_run_budget.json", '{"summary": {}}\n')
    _write_bundle(
        bundle,
        [
            {
                "role": "run_budget:docs/generated_artifacts/paper_run_budget.json",
                "copied_to": "files/docs/generated_artifacts/paper_run_budget.json",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_run_queue_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_run_queue.json", '{"summary": {}}\n')
    _write_bundle(
        bundle,
        [
            {
                "role": "run_queue:docs/generated_artifacts/paper_run_queue.json",
                "copied_to": "files/docs/generated_artifacts/paper_run_queue.json",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_run_execution_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_run_execution_plan.json", '{"summary": {}}\n')
    _write_bundle(
        bundle,
        [
            {
                "role": "run_execution:docs/generated_artifacts/paper_run_execution_plan.json",
                "copied_to": "files/docs/generated_artifacts/paper_run_execution_plan.json",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_submission_gap_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_submission_gap_report.json", '{"summary": {}}\n')
    _write_bundle(
        bundle,
        [
            {
                "role": "submission_gap:docs/generated_artifacts/paper_submission_gap_report.json",
                "copied_to": "files/docs/generated_artifacts/paper_submission_gap_report.json",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_submission_objective_audit_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_submission_objective_audit.json", '{"summary": {}}\n')
    _write_bundle(
        bundle,
        [
            {
                "role": "submission_objective:docs/generated_artifacts/paper_submission_objective_audit.json",
                "copied_to": "files/docs/generated_artifacts/paper_submission_objective_audit.json",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_allows_live_status_artifact(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_live_status_history.jsonl", '{"generated_at":"2099-01-01T00:00:00"}\n')
    _write_bundle(
        bundle,
        [
            {
                "role": "live_status:docs/generated_artifacts/paper_live_status_history.jsonl",
                "copied_to": "files/docs/generated_artifacts/paper_live_status_history.jsonl",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_accepts_submission_package_manifest(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/docs/generated_artifacts/paper_submission_package_manifest.json", '{"schema_version":1}\n')
    _write_bundle(
        bundle,
        [
            {
                "role": "submission_package:docs/generated_artifacts/paper_submission_package_manifest.json",
                "copied_to": "files/docs/generated_artifacts/paper_submission_package_manifest.json",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is True


def test_public_artifact_safety_rejects_raw_run_files(tmp_path: Path):
    bundle = tmp_path / "bundle"
    digest = _write(bundle / "files/runs/active/case/results/run/trace.jsonl", "{}\n")
    _write_bundle(
        bundle,
        [
            {
                "role": "attack_report:trace.jsonl",
                "copied_to": "files/runs/active/case/results/run/trace.jsonl",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is False
    assert any(item["message"] == "bundle copies a forbidden raw run file" for item in report["issues"])


def test_public_artifact_safety_rejects_unmanifested_copied_files(tmp_path: Path):
    bundle = tmp_path / "bundle"
    _write(bundle / "files/runs/_reports/paper_core/summary.json", "{}\n")
    _write_bundle(bundle, [])

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is False
    assert any(item["message"] == "bundle files are not recorded in copied_artifacts" for item in report["issues"])


def test_public_artifact_safety_rejects_canary_and_secret_values(tmp_path: Path):
    bundle = tmp_path / "bundle"
    text = "\n".join(
        [
            "canary=dpl-AbCdEfGhIjKlMnOp",
            "OPENAI_API_KEY = sk-test01234567890123456789",
        ]
    )
    digest = _write(bundle / "files/runs/_reports/paper_core/report.md", text)
    _write_bundle(
        bundle,
        [
            {
                "role": "attack_report:report.md",
                "copied_to": "files/runs/_reports/paper_core/report.md",
                "copied_sha256": digest,
            }
        ],
    )

    report = check_public_artifact_safety.build_safety_report(bundle)

    assert report["ok"] is False
    messages = [item["message"] for item in report["issues"]]
    assert "bundle text contains a deployment canary token" in messages
    assert "bundle text contains a provider-style secret value" in messages
