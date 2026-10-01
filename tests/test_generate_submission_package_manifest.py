import json
from pathlib import Path

from infra import generate_submission_package_manifest


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_submission_package_manifest_summarizes_package_state(tmp_path: Path):
    root = tmp_path
    _write(
        root / "docs/generated_artifacts/paper_experiment_matrix_plan.json",
        json.dumps(
            {
                "matrix_id": "m123",
                "case_set": "all",
                "baseline": {"name": "claude_code_kimi_k2.6"},
                "cases": {"count": 328},
                "summary": {"rows_total": 2296, "attack_rows": 984, "control_rows": 1312},
            }
        ),
    )
    _write(
        root / "docs/generated_artifacts/paper_live_status.json",
        json.dumps(
            {
                "matrix_progress": {
                    "full": {
                        "complete": True,
                        "summary": {"expected_rows": 2296, "completed_rows": 2296},
                    }
                }
            }
        ),
    )
    _write(
        root / "docs/generated_artifacts/paper_submission_gap_report.json",
        json.dumps(
            {
                "submission_ready": False,
                "summary": {
                    "error_count": 1,
                    "warning_count": 3,
                    "pending_manual_decision_count": 4,
                    "blocking_manual_decision_count": 1,
                },
                "manual_decisions": [
                    {
                        "id": "license_file",
                        "status": "pending",
                        "blocking_submission_gate": True,
                        "next_action": "Add LICENSE.",
                    }
                ],
            }
        ),
    )
    _write(
        root / "docs/generated_artifacts/paper_statistical_analysis.json",
        json.dumps({"summary": {"attack_success": 23, "confirmed": 7, "control_success": 0}}),
    )
    _write(
        root / "runs/_reports/paper_all_current/paper_artifact_gate.md",
        "# Paper Artifact Gate\n\n- generated_at: `2026-06-27T11:16:04`\n- ok: `true`\n",
    )
    _write(
        root / "runs/_reports/paper_all_current/paper_artifact_gate_submission.md",
        "# Paper Artifact Gate\n\n- generated_at: `2026-06-27T11:16:04`\n- ok: `false`\n",
    )
    _write(root / "runs/_reports/paper_all_current/summary.json", '{"label": "paper_all_current"}\n')
    _write(root / "runs/_reports/paper_all_current/results.csv", "case_id,attack_success\ncase_a,true\n")
    _write(root / "runs/_reports/paper_all_current/paper_result_quality_gate.md", "# Result Gate\n")
    _write(root / "runs/_reports/paper_controls_all_current/summary.json", '{"label": "paper_controls_all_current"}\n')
    _write(root / "runs/_reports/paper_controls_all_current/results.csv", "case_id,attack_success\ncase_a,false\n")
    _write(root / "runs/_reports/paper_all_current/paper_tables/paper_tables.json", '{"tables": []}\n')
    _write(root / "runs/_reports/paper_all_current/case_study_evidence/case_study_evidence.json", '{"cases": []}\n')
    _write(root / "runs/_artifacts/repro_bundles/paper_all_current/repro_manifest.json", '{"schema_version": 1}\n')
    _write(root / "docs/generated_artifacts/paper_full_suite_eligibility.json", '{"schema_version": 1, "summary": {"active_cases": 328}}\n')
    _write(root / "docs/generated_artifacts/paper_full_suite_eligibility.md", "# Full-Suite Eligibility Appendix\n")
    _write(root / "docs/generated_artifacts/paper_external_validity_plan.json", '{"schema_version": 1, "summary": {"selected_cases": 12}}\n')
    _write(root / "docs/generated_artifacts/paper_external_validity_plan.md", "# External-Validity Calibration Plan\n")
    _write(root / "docs/paper_draft.md", "# Safety Bench\n")

    manifest = generate_submission_package_manifest.build_submission_package_manifest(root=root)
    markdown = generate_submission_package_manifest.render_markdown(manifest)

    assert manifest["schema_version"] == 1
    assert manifest["baseline"]["name"] == "claude_code_kimi_k2.6"
    assert manifest["matrix"]["completed_rows"] == 2296
    assert manifest["matrix"]["rows_total"] == 2296
    assert manifest["results"]["attack_success"] == 23
    assert manifest["results"]["source_schema_version"] == 1
    assert manifest["release_status"]["blocking_manual_decisions"] == 1
    assert manifest["gates"]["current_artifact_gate"]["exists"] is True
    assert manifest["gates"]["submission_artifact_gate"]["exists"] is True
    assert manifest["gates"]["repro_bundle_manifest"]["exists"] is True
    assert any(item["path"] == "docs/release_metadata_final.json" for item in manifest["files"])
    assert any(
        item["path"] == "docs/paper_draft.md" and item["exists"] is True
        for item in manifest["files"]
    )
    assert any(item["path"] == "docs/generated_artifacts/paper_submission_objective_audit.json" for item in manifest["files"])
    assert any(item["path"] == "docs/generated_artifacts/paper_bibliography_check.json" for item in manifest["files"])
    assert any(item["path"] == "docs/generated_artifacts/paper_full_suite_eligibility.json" for item in manifest["files"])
    assert any(item["path"] == "docs/generated_artifacts/paper_external_validity_plan.json" for item in manifest["files"])
    assert any(
        item["role"] == "attack_report:paper_all_current:results.csv" and item["exists"] is True
        for item in manifest["files"]
    )
    assert any(
        item["role"] == "attack_report:paper_all_current:paper_result_quality_gate.md" and item["exists"] is True
        for item in manifest["files"]
    )
    assert any(
        item["role"] == "control_report:paper_controls_all_current:results.csv" and item["exists"] is True
        for item in manifest["files"]
    )
    assert any(
        item["role"] == "paper_tables:paper_tables.json" and item["exists"] is True
        for item in manifest["files"]
    )
    assert any(
        item["role"] == "case_study_evidence:case_study_evidence.json" and item["exists"] is True
        for item in manifest["files"]
    )
    assert "Paper Submission Package Manifest" in markdown
    assert "| license_file | pending | true | Add LICENSE. |" in markdown
    assert "attack_report:paper_all_current:results.csv" in markdown
    assert "| repro_bundle_manifest | `true` | `runs/_artifacts/repro_bundles/paper_all_current/repro_manifest.json` |" in markdown


def test_submission_package_manifest_reads_schema_v2_result_accounting(tmp_path: Path):
    root = tmp_path
    _write(
        root / "docs/generated_artifacts/paper_experiment_matrix_plan.json",
        json.dumps(
            {
                "matrix_id": "m-v2",
                "case_set": "all",
                "cases": {"count": 328},
                "summary": {"rows_total": 24, "attack_rows": 12, "control_rows": 12},
            }
        ),
    )
    _write(
        root / "docs/generated_artifacts/paper_live_status.json",
        json.dumps(
            {
                "matrix_progress": {
                    "full": {
                        "complete": True,
                        "summary": {
                            "expected_rows": 24,
                            "completed_rows": 24,
                            "execution_valid_completed_rows": 21,
                            "model_protocol_terminal_rows": 3,
                        },
                    }
                }
            }
        ),
    )
    _write(
        root / "docs/generated_artifacts/paper_statistical_analysis.json",
        json.dumps(
            {
                "schema_version": 2,
                "matrix": {
                    "attack_rows": 10,
                    "attack_scored_rows": 10,
                    "attack_asr_eligible_scored_rows": 8,
                    "attack_n_minus_1_rows": 2,
                    "attack_accounted_terminal_rows": 12,
                    "attack_protocol_denominator_rows": 10,
                    "control_rows": 11,
                    "control_scored_rows": 11,
                    "control_asr_eligible_scored_rows": 9,
                    "control_n_minus_1_rows": 1,
                    "control_accounted_terminal_rows": 12,
                    "control_protocol_denominator_rows": 10,
                },
                "primary_effects": {
                    "conditional_attack_success": {"successes": 3, "trials": 8, "rate": 3 / 8},
                    "confirmed_compromise": {"successes": 1},
                    "protocol_completion": {"rate": 0.8},
                    "model_nonconformance": {"rate": 0.2},
                    "end_to_end_attack": {"successes": 3, "rate": 0.3},
                    "control_conditional_violation": {"successes": 0, "trials": 9, "rate": 0.0},
                    "control_protocol_completion": {"rate": 0.9},
                    "control_model_nonconformance": {"rate": 0.1},
                    "control_end_to_end_violation": {"successes": 0, "rate": 0.0},
                },
            }
        ),
    )
    _write(
        root / "docs/generated_artifacts/paper_submission_gap_report.json",
        json.dumps({"summary": {}, "manual_decisions": []}),
    )

    manifest = generate_submission_package_manifest.build_submission_package_manifest(
        root=root
    )
    markdown = generate_submission_package_manifest.render_markdown(manifest)

    results = manifest["results"]
    assert results["source_schema_version"] == 2
    assert results["attack_success"] == 3
    assert results["confirmed_compromise"] == 1
    assert results["attack_scored_rows"] == 10
    assert results["attack_asr_eligible_scored_rows"] == 8
    assert results["attack_n_minus_1_rows"] == 2
    assert results["attack_accounted_terminal_rows"] == 12
    assert results["attack_protocol_denominator_rows"] == 10
    assert results["protocol_completion_rate"] == 0.8
    assert results["model_nonconformance_rate"] == 0.2
    assert results["conditional_asr_rate"] == 3 / 8
    assert results["end_to_end_attack_rate"] == 0.3
    assert manifest["matrix"]["execution_valid_completed_rows"] == 21
    assert manifest["matrix"]["model_protocol_terminal_rows"] == 3
    assert "Attack N-1 rows (M) | 2" in markdown
    assert "Attack protocol denominator rows (S+M) | 10" in markdown
    assert "End-to-end attack rate | 0.3" in markdown


def test_result_summary_preserves_benchmark_asr_eligible_denominators():
    benchmark = {
        "schema_version": 2,
        "current_results": {
            "scored_trials": 10,
            "asr_eligible_scored_trials": 7,
            "n_minus_1_trials": 1,
            "accounted_terminal_trials": 11,
            "protocol_denominator_trials": 8,
            "attack_success_rows": 2,
            "confirmed_rows": 1,
            "protocol_completion_rate": 7 / 8,
            "model_nonconformance_rate": 1 / 8,
            "conditional_asr_rate": 2 / 7,
            "end_to_end_attack_rate": 2 / 8,
        },
        "controls": {
            "scored_trials": 12,
            "asr_eligible_scored_trials": 0,
            "n_minus_1_trials": 0,
            "accounted_terminal_trials": 12,
            "protocol_denominator_trials": 0,
            "attack_success_rows": 0,
            "protocol_completion_rate": None,
            "model_nonconformance_rate": None,
            "conditional_violation_rate": None,
            "end_to_end_violation_rate": None,
        },
    }

    results = generate_submission_package_manifest.result_summary({}, benchmark)

    assert results["attack_scored_rows"] == 10
    assert results["attack_asr_eligible_scored_rows"] == 7
    assert results["conditional_asr_rate"] == 2 / 7
    assert results["attack_protocol_denominator_rows"] == 8
    assert results["control_scored_rows"] == 12
    assert results["control_asr_eligible_scored_rows"] == 0
    assert results["control_conditional_violation_rate"] is None
    assert results["control_protocol_denominator_rows"] == 0


def test_result_summary_does_not_coerce_missing_benchmark_rates_to_zero():
    benchmark = {
        "schema_version": 2,
        "current_results": {
            "scored_trials": 0,
            "asr_eligible_scored_trials": 0,
            "n_minus_1_trials": 0,
            "accounted_terminal_trials": 0,
            "protocol_denominator_trials": 0,
            "attack_success_rows": 0,
            "confirmed_rows": 0,
            "protocol_completion_rate": None,
            "model_nonconformance_rate": None,
            "conditional_asr_rate": None,
            "end_to_end_attack_rate": None,
        },
        "controls": {
            "scored_trials": 0,
            "asr_eligible_scored_trials": 0,
            "n_minus_1_trials": 0,
            "accounted_terminal_trials": 0,
            "protocol_denominator_trials": 0,
            "attack_success_rows": 0,
            "protocol_completion_rate": None,
            "model_nonconformance_rate": None,
            "conditional_violation_rate": None,
            "end_to_end_violation_rate": None,
        },
    }

    results = generate_submission_package_manifest.result_summary({}, benchmark)

    for field in [
        "protocol_completion_rate",
        "model_nonconformance_rate",
        "conditional_asr_rate",
        "end_to_end_attack_rate",
        "control_protocol_completion_rate",
        "control_model_nonconformance_rate",
        "control_conditional_violation_rate",
        "control_end_to_end_violation_rate",
    ]:
        assert results[field] is None
    assert results["end_to_end_attack_success"] == 0
    assert results["control_end_to_end_violation_success"] == 0

    markdown = generate_submission_package_manifest.render_markdown(
        {
            "generated_at": "2026-07-17T00:00:00",
            "release_metadata": {},
            "matrix": {},
            "results": results,
            "files": [],
            "missing_files": [],
        }
    )
    assert "Protocol completion rate | n/a" in markdown
    assert "Model nonconformance rate | n/a" in markdown
    assert "Conditional ASR | n/a" in markdown
    assert "End-to-end attack rate | n/a" in markdown
