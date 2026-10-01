import hashlib
from pathlib import Path

from infra import build_repro_bundle


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_filter_git_status_short_hides_out_of_scope_codex_run_execution_files():
    status = build_repro_bundle.filter_git_status_short(
        [
            " M docs/paper_artifact_evaluation_readme.md",
            "?? docs/generated_artifacts/paper_run_execution_codex_plan.json",
            "?? docs/generated_artifacts/paper_run_execution_codex_plan.md",
            "?? docs/generated_artifacts/paper_run_execution_claude_dry_run.json",
        ]
    )

    assert " M docs/paper_artifact_evaluation_readme.md" in status
    assert "?? docs/generated_artifacts/paper_run_execution_claude_dry_run.json" in status
    assert not any("paper_run_execution_codex_plan" in line for line in status)


def test_build_repro_bundle_records_hashes_and_missing_artifacts(tmp_path: Path, monkeypatch):
    root = tmp_path / "bench"
    attack = root / "runs/_reports/paper_core"
    tables = attack / "paper_tables"
    _write(attack / "summary.json", "{}")
    _write(attack / "report.md", "# report\n")
    _write(attack / "harness_macro.csv", "harness\nclaude\n")
    _write(tables / "paper_tables.md", "# tables\n")
    _write(tables / "main_results_table.tex", "main")

    monkeypatch.setattr(build_repro_bundle, "ROOT", root)
    monkeypatch.setattr(build_repro_bundle, "RUNS", root / "runs")
    monkeypatch.setattr(
        build_repro_bundle,
        "build_readiness",
        lambda require_kimi=True: {
            "ready": True,
            "blockers": [],
            "case_counts": {"core": 57, "extended": 205, "exploratory": 96, "all": 328},
        },
    )
    monkeypatch.setattr(
        build_repro_bundle,
        "git_state",
        lambda: {"commit": "abc", "branch": "main", "dirty": False, "status_short": []},
    )

    manifest = build_repro_bundle.build_manifest(
        attack,
        None,
        tables,
        attack_label="paper_core",
        control_label="",
        require_kimi=False,
    )

    summary_record = next(item for item in manifest["artifacts"] if item["path"].endswith("summary.json"))
    expected_hash = hashlib.sha256(b"{}").hexdigest()
    assert summary_record["sha256"] == expected_hash
    assert summary_record["bytes"] == 2
    assert any(item["path"].endswith("results.csv") for item in manifest["missing_artifacts"])
    assert any("audit_paper_suite.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("check_paper_suite_lock.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("plan_paper_experiment_matrix.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("check_paper_matrix_progress.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("export_paper_run_queue.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("run_paper_queue.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("--harness claude --out-json docs\\generated_artifacts\\paper_run_execution_claude_dry_run.json" in cmd for cmd in manifest["reproduction_commands"])
    assert any("--queue-mode post-run --harness claude --out-json docs\\generated_artifacts\\paper_run_execution_claude_post_run_dry_run.json" in cmd for cmd in manifest["reproduction_commands"])
    assert not any("--harness codex" in cmd for cmd in manifest["reproduction_commands"])
    assert any("estimate_paper_run_budget.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("report_paper_submission_gaps.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("--json-out docs\\generated_artifacts\\paper_submission_gap_report.json" in cmd for cmd in manifest["reproduction_commands"])
    assert any("audit_submission_objective.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("--json-out docs\\generated_artifacts\\paper_submission_objective_audit.json" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_submission_package_manifest.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("--out-json docs\\generated_artifacts\\paper_submission_package_manifest.json" in cmd for cmd in manifest["reproduction_commands"])
    commands = manifest["reproduction_commands"]
    package_index = next(i for i, cmd in enumerate(commands) if "generate_submission_package_manifest.py" in cmd)
    assert package_index > next(i for i, cmd in enumerate(commands) if "generate_statistical_analysis.py" in cmd)
    assert package_index > next(i for i, cmd in enumerate(commands) if "generate_paper_figures.py" in cmd)
    assert package_index > next(i for i, cmd in enumerate(commands) if "paper_queue_job.py snapshot" in cmd)
    assert not any("--require-ready" in cmd for cmd in manifest["reproduction_commands"])
    assert not any("run_paper_baseline_matrix.ps1" in cmd for cmd in manifest["reproduction_commands"])
    assert any("report_active_run.py --label paper_core --case-set all --run-kind attack --harness claude" in cmd for cmd in manifest["reproduction_commands"])
    assert any("check_paper_results.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("check_paper_results.py" in cmd and "--attack-report-dir runs\\_reports\\paper_core" in cmd for cmd in manifest["reproduction_commands"])
    assert any("--expected-harness claude" in cmd for cmd in manifest["reproduction_commands"])
    assert not any("--expected-harness codex" in cmd for cmd in manifest["reproduction_commands"])
    assert any("export_paper_tables.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("export_paper_tables.py" in cmd and "--attack-report-dir runs\\_reports\\paper_core" in cmd for cmd in manifest["reproduction_commands"])
    assert any("export_case_study_evidence.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("export_case_study_evidence.py" in cmd and "--attack-report-dir runs\\_reports\\paper_core" in cmd for cmd in manifest["reproduction_commands"])
    assert any("check_paper_case_studies.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("paper_case_study_check.md" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_benchmark_card.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("docs\\generated_artifacts\\benchmark_card.json" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_paper_appendix.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("paper_supplementary_appendix.json" in cmd for cmd in manifest["reproduction_commands"])
    assert any("paper_supplementary_appendix.md" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_oracle_coverage_report.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("paper_oracle_coverage.json" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_threat_model_card.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("paper_threat_model_card.json" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_statistical_analysis.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("paper_statistical_analysis.json" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_claim_evidence_map.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("paper_claim_evidence_map.json" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_control_integrity_report.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("paper_control_integrity_report.json" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_paper_figures.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("paper_figures.json" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_full_suite_eligibility_appendix.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("paper_full_suite_eligibility.json" in cmd for cmd in manifest["reproduction_commands"])
    assert any("plan_external_validity_calibration.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("paper_external_validity_plan.json" in cmd for cmd in manifest["reproduction_commands"])
    assert any(cmd == "python infra\\check_paper_readiness.py" for cmd in manifest["reproduction_commands"])
    assert any("check_paper_claims.py --profile current_claude" in cmd for cmd in manifest["reproduction_commands"])
    assert any("check_paper_manuscript.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("paper_manuscript_check.md" in cmd for cmd in manifest["reproduction_commands"])
    assert any(cmd == "python infra\\check_release_metadata.py" for cmd in manifest["reproduction_commands"])
    assert any("check_public_artifact_safety.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("check_paper_artifact_gate.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("check_paper_artifact_gate.py" in cmd and "--attack-report-dir runs\\_reports\\paper_core" in cmd for cmd in manifest["reproduction_commands"])
    assert any("--max-active-progress-drift-rows 20" in cmd for cmd in manifest["reproduction_commands"])
    assert any("--out runs\\_reports\\paper_core\\paper_artifact_gate.md" in cmd for cmd in manifest["reproduction_commands"])
    assert any("run_paper_preflight.ps1 -Profile current_claude" in cmd for cmd in manifest["reproduction_commands"])
    assert any(item["path"].endswith("CITATION.cff") for item in manifest["missing_artifacts"])
    assert any(item["path"].endswith("docs/generated_artifacts/paper_suite_lock.json") for item in manifest["missing_artifacts"])
    assert any(item["path"].endswith("docs/generated_artifacts/paper_experiment_matrix_plan.json") for item in manifest["missing_artifacts"])
    assert any(item["path"].endswith("docs/generated_artifacts/paper_experiment_matrix_progress.md") for item in manifest["missing_artifacts"])
    assert any(item["path"].endswith("docs/generated_artifacts/paper_run_queue.json") for item in manifest["missing_artifacts"])
    assert any(item["path"].endswith("docs/generated_artifacts/paper_failure_marker_resume.md") for item in manifest["missing_artifacts"])
    assert any(item["path"].endswith("docs/generated_artifacts/paper_failure_marker_resume_cases.txt") for item in manifest["missing_artifacts"])
    assert any(item["path"].endswith("docs/generated_artifacts/paper_run_execution_plan.json") for item in manifest["missing_artifacts"])
    assert any(item["path"].endswith("docs/generated_artifacts/paper_run_budget.json") for item in manifest["missing_artifacts"])
    assert any(item["path"].endswith("docs/generated_artifacts/paper_submission_gap_report.json") for item in manifest["missing_artifacts"])
    assert any(item["path"].endswith("docs/generated_artifacts/paper_submission_objective_audit.json") for item in manifest["missing_artifacts"])
    assert any(item["path"].endswith("docs/generated_artifacts/paper_submission_package_manifest.json") for item in manifest["missing_artifacts"])
    assert any(item["path"].endswith("docs/generated_artifacts/paper_live_status.json") for item in manifest["missing_artifacts"])
    assert any(item["path"].endswith("docs/generated_artifacts/paper_full_suite_eligibility.json") for item in manifest["missing_artifacts"])
    assert any(item["path"].endswith("docs/generated_artifacts/paper_external_validity_plan.json") for item in manifest["missing_artifacts"])
    assert any("paper_queue_job.py snapshot" in cmd for cmd in manifest["reproduction_commands"])
    assert any("--check-md docs\\generated_artifacts\\paper_live_status_check.md" in cmd for cmd in manifest["reproduction_commands"])
    assert any("check_paper_live_status.py" in cmd for cmd in manifest["reproduction_commands"])


def test_build_repro_bundle_records_multiple_control_reports(tmp_path: Path, monkeypatch):
    root = tmp_path / "bench"
    attack = root / "runs/_reports/paper_core"
    clean = root / "runs/_reports/paper_clean"
    no_trigger = root / "runs/_reports/paper_no_trigger"
    tables = attack / "paper_tables"
    evidence = attack / "case_study_evidence"
    for report in (attack, clean, no_trigger):
        _write(report / "summary.json", "{}")
        _write(report / "report.md", "# report\n")
        _write(report / "harness_macro.csv", "harness\nclaude\n")
    _write(clean / "summary.json", '{"label": "paper_clean"}')
    _write(no_trigger / "summary.json", '{"label": "paper_no_trigger"}')
    _write(attack / "paper_case_study_check.md", "# case-study check\n")
    _write(attack / "paper_manuscript_check.md", "# manuscript check\n")
    _write(tables / "paper_tables.md", "# tables\n")
    _write(evidence / "case_study_evidence.json", "{}\n")
    _write(evidence / "case_study_evidence.md", "# evidence\n")
    _write(root / "docs/generated_artifacts/paper_suite_lock.json", "{}\n")
    _write(root / "docs/generated_artifacts/paper_experiment_matrix_plan.json", "{}\n")
    _write(root / "docs/generated_artifacts/paper_experiment_matrix_plan.md", "# plan\n")
    _write(root / "docs/generated_artifacts/paper_experiment_matrix_progress.md", "# progress\n")
    _write(root / "docs/generated_artifacts/paper_experiment_matrix_progress_claude.md", "# claude progress\n")
    _write(root / "docs/generated_artifacts/paper_run_queue.json", "{}\n")
    _write(root / "docs/generated_artifacts/paper_run_queue.md", "# queue\n")
    _write(root / "docs/generated_artifacts/paper_failure_marker_resume.md", "# resume\n")
    _write(root / "docs/generated_artifacts/paper_failure_marker_resume_cases.txt", "active/case\n")
    _write(root / "docs/generated_artifacts/paper_run_execution_plan.json", "{}\n")
    _write(root / "docs/generated_artifacts/paper_run_execution_plan.md", "# execution\n")
    _write(root / "docs/generated_artifacts/paper_run_execution_claude_plan.json", '{"execute": true}\n')
    _write(root / "docs/generated_artifacts/paper_run_execution_claude_plan.md", "# claude execution\n")
    _write(root / "docs/generated_artifacts/paper_run_execution_claude_dry_run.json", "{}\n")
    _write(root / "docs/generated_artifacts/paper_run_execution_claude_dry_run.md", "# claude dry-run\n")
    _write(root / "docs/generated_artifacts/paper_run_execution_claude_post_run.json", '{"execute": true}\n')
    _write(root / "docs/generated_artifacts/paper_run_execution_claude_post_run.md", "# claude post-run\n")
    _write(root / "docs/generated_artifacts/paper_run_execution_claude_post_run_dry_run.json", "{}\n")
    _write(root / "docs/generated_artifacts/paper_run_execution_claude_post_run_dry_run.md", "# claude post-run dry-run\n")
    _write(root / "docs/generated_artifacts/paper_run_budget.json", "{}\n")
    _write(root / "docs/generated_artifacts/paper_run_budget.md", "# budget\n")
    _write(root / "docs/generated_artifacts/paper_submission_gap_report.md", "# gap\n")
    _write(root / "docs/generated_artifacts/paper_submission_gap_report.json", "{}\n")
    _write(root / "docs/generated_artifacts/paper_submission_objective_audit.md", "# Paper Submission Objective Audit\n")
    _write(root / "docs/generated_artifacts/paper_submission_objective_audit.json", '{"schema_version": 1}\n')
    _write(root / "docs/generated_artifacts/paper_submission_package_manifest.json", '{"schema_version": 1}\n')
    _write(root / "docs/generated_artifacts/paper_submission_package_manifest.md", "# Paper Submission Package Manifest\n")
    _write(root / "docs/generated_artifacts/paper_live_status.json", "{}\n")
    _write(root / "docs/generated_artifacts/paper_live_status.md", "# live\n")
    _write(root / "docs/generated_artifacts/paper_live_status_check.md", "# live check\n")
    _write(root / "docs/generated_artifacts/paper_live_status_history.jsonl", "{}\n")
    _write(root / "docs/generated_artifacts/benchmark_card.json", '{"schema_version": 1}\n')
    _write(root / "docs/generated_artifacts/benchmark_card.md", "# Safety Bench Benchmark Card\n")
    _write(root / "docs/generated_artifacts/paper_supplementary_appendix.json", '{"schema_version": 2}\n')
    _write(root / "docs/generated_artifacts/paper_supplementary_appendix.md", "# Safety Bench Supplementary Appendix\n")
    _write(root / "docs/generated_artifacts/paper_supplementary_appendix.tex", "\\section{Safety Bench Supplementary Appendix}\n")
    _write(root / "docs/generated_artifacts/paper_oracle_coverage.json", '{"schema_version": 1}\n')
    _write(root / "docs/generated_artifacts/paper_oracle_coverage.md", "# Safety Bench Oracle Coverage Report\n")
    _write(root / "docs/generated_artifacts/paper_threat_model_card.json", '{"schema_version": 1}\n')
    _write(root / "docs/generated_artifacts/paper_threat_model_card.md", "# Safety Bench Threat Model Card\n")
    _write(root / "docs/generated_artifacts/paper_statistical_analysis.json", '{"schema_version": 1}\n')
    _write(root / "docs/generated_artifacts/paper_statistical_analysis.md", "# Safety Bench Statistical Analysis\n")
    _write(root / "docs/generated_artifacts/paper_claim_evidence_map.json", '{"schema_version": 1}\n')
    _write(root / "docs/generated_artifacts/paper_claim_evidence_map.md", "# Paper Claim Evidence Map\n")
    _write(root / "docs/generated_artifacts/paper_control_integrity_report.json", '{"schema_version": 1}\n')
    _write(root / "docs/generated_artifacts/paper_control_integrity_report.md", "# Paper Control Integrity Report\n")
    _write(root / "docs/generated_artifacts/paper_figures.json", '{"schema_version": 1}\n')
    _write(root / "docs/generated_artifacts/paper_figures.md", "# Paper Figures\n")
    _write(root / "docs/figures/figure_1_benchmark_frame.svg", "<svg></svg>\n")
    _write(root / "docs/generated_artifacts/figures/figure_2_core_results.svg", "<svg></svg>\n")
    _write(root / "docs/generated_artifacts/paper_bibliography_check.json", '{"schema_version": 1}\n')
    _write(root / "docs/generated_artifacts/paper_bibliography_check.md", "# Paper Bibliography Check\n")
    _write(root / "docs/paper_draft.md", "# Paper Draft\n")
    _write(root / "docs/generated_artifacts/paper_full_suite_eligibility.json", '{"schema_version": 1}\n')
    _write(root / "docs/generated_artifacts/paper_full_suite_eligibility.md", "# Full-Suite Eligibility Appendix\n")
    _write(root / "docs/generated_artifacts/paper_external_validity_plan.json", '{"schema_version": 1}\n')
    _write(root / "docs/generated_artifacts/paper_external_validity_plan.md", "# External-Validity Calibration Plan\n")
    _write(root / "CITATION.cff", "cff-version: 1.2.0\n")
    _write(root / "docs/release_metadata_final.json", '{"schema_version": 1}\n')
    _write(root / "docs/paper_artifact_evaluation_readme.md", "# artifact\n")

    monkeypatch.setattr(build_repro_bundle, "ROOT", root)
    monkeypatch.setattr(build_repro_bundle, "RUNS", root / "runs")
    monkeypatch.setattr(
        build_repro_bundle,
        "build_readiness",
        lambda require_kimi=True: {
            "ready": True,
            "blockers": [],
            "case_counts": {"core": 57, "extended": 205, "exploratory": 96, "all": 328},
        },
    )
    monkeypatch.setattr(
        build_repro_bundle,
        "git_state",
        lambda: {"commit": "abc", "branch": "main", "dirty": False, "status_short": []},
    )

    manifest = build_repro_bundle.build_manifest(
        attack,
        [clean, no_trigger],
        tables,
        evidence,
        attack_label="paper_core",
        control_label="",
        require_kimi=True,
    )

    assert manifest["labels"]["controls"] == ["paper_clean", "paper_no_trigger"]
    assert any(item["role"].startswith("control_report:paper_clean") for item in manifest["artifacts"])
    assert any(item["role"] == "attack_report:paper_manuscript_check.md" for item in manifest["artifacts"])
    assert any(item["role"] == "case_study_evidence:case_study_evidence.json" for item in manifest["artifacts"])
    assert any(item["role"] == "attack_report:paper_case_study_check.md" for item in manifest["artifacts"])
    assert any(item["role"] == "benchmark_card:docs/generated_artifacts/benchmark_card.json" for item in manifest["artifacts"])
    assert any(item["role"] == "benchmark_card:docs/generated_artifacts/benchmark_card.md" for item in manifest["artifacts"])
    assert any(item["role"] == "supplementary_appendix:docs/generated_artifacts/paper_supplementary_appendix.json" for item in manifest["artifacts"])
    assert any(item["role"] == "supplementary_appendix:docs/generated_artifacts/paper_supplementary_appendix.md" for item in manifest["artifacts"])
    assert any(item["role"] == "supplementary_appendix:docs/generated_artifacts/paper_supplementary_appendix.tex" for item in manifest["artifacts"])
    assert any(item["role"] == "oracle_coverage:docs/generated_artifacts/paper_oracle_coverage.json" for item in manifest["artifacts"])
    assert any(item["role"] == "oracle_coverage:docs/generated_artifacts/paper_oracle_coverage.md" for item in manifest["artifacts"])
    assert any(item["role"] == "threat_model_card:docs/generated_artifacts/paper_threat_model_card.json" for item in manifest["artifacts"])
    assert any(item["role"] == "threat_model_card:docs/generated_artifacts/paper_threat_model_card.md" for item in manifest["artifacts"])
    assert any(item["role"] == "statistical_analysis:docs/generated_artifacts/paper_statistical_analysis.json" for item in manifest["artifacts"])
    assert any(item["role"] == "statistical_analysis:docs/generated_artifacts/paper_statistical_analysis.md" for item in manifest["artifacts"])
    assert any(item["role"] == "claim_evidence_map:docs/generated_artifacts/paper_claim_evidence_map.json" for item in manifest["artifacts"])
    assert any(item["role"] == "claim_evidence_map:docs/generated_artifacts/paper_claim_evidence_map.md" for item in manifest["artifacts"])
    assert any(item["role"] == "control_integrity:docs/generated_artifacts/paper_control_integrity_report.json" for item in manifest["artifacts"])
    assert any(item["role"] == "control_integrity:docs/generated_artifacts/paper_control_integrity_report.md" for item in manifest["artifacts"])
    assert any(item["role"] == "paper_figures:docs/generated_artifacts/paper_figures.json" for item in manifest["artifacts"])
    assert any(item["role"] == "paper_figures:docs/generated_artifacts/paper_figures.md" for item in manifest["artifacts"])
    assert any(item["role"] == "paper_figures:docs/figures/figure_1_benchmark_frame.svg" for item in manifest["artifacts"])
    assert any(
        item["role"] == "paper_figures:docs/generated_artifacts/figures/figure_2_core_results.svg"
        for item in manifest["artifacts"]
    )
    assert any(item["role"] == "bibliography_check:docs/generated_artifacts/paper_bibliography_check.json" for item in manifest["artifacts"])
    assert any(item["role"] == "bibliography_check:docs/generated_artifacts/paper_bibliography_check.md" for item in manifest["artifacts"])
    manuscript_roles = {
        item["role"] for item in manifest["artifacts"] if item["role"].startswith("manuscript:")
    }
    assert manuscript_roles == {"manuscript:docs/paper_draft.md"}
    assert any(item["role"] == "full_suite_eligibility:docs/generated_artifacts/paper_full_suite_eligibility.json" for item in manifest["artifacts"])
    assert any(item["role"] == "full_suite_eligibility:docs/generated_artifacts/paper_full_suite_eligibility.md" for item in manifest["artifacts"])
    assert any(item["role"] == "external_validity_plan:docs/generated_artifacts/paper_external_validity_plan.json" for item in manifest["artifacts"])
    assert any(item["role"] == "external_validity_plan:docs/generated_artifacts/paper_external_validity_plan.md" for item in manifest["artifacts"])
    assert any(item["role"] == "suite_lock:docs/generated_artifacts/paper_suite_lock.json" for item in manifest["artifacts"])
    assert any(item["role"] == "experiment_plan:docs/generated_artifacts/paper_experiment_matrix_plan.json" for item in manifest["artifacts"])
    assert any(item["role"] == "matrix_progress:docs/generated_artifacts/paper_experiment_matrix_progress.md" for item in manifest["artifacts"])
    assert any(item["role"] == "matrix_progress:docs/generated_artifacts/paper_experiment_matrix_progress_claude.md" for item in manifest["artifacts"])
    assert any(item["role"] == "run_queue:docs/generated_artifacts/paper_run_queue.json" for item in manifest["artifacts"])
    assert any(item["role"] == "run_queue:docs/generated_artifacts/paper_failure_marker_resume.md" for item in manifest["artifacts"])
    assert any(item["role"] == "run_queue:docs/generated_artifacts/paper_failure_marker_resume_cases.txt" for item in manifest["artifacts"])
    assert any(item["role"] == "run_execution:docs/generated_artifacts/paper_run_execution_plan.json" for item in manifest["artifacts"])
    assert any(item["role"] == "run_execution:docs/generated_artifacts/paper_run_execution_claude_plan.json" for item in manifest["artifacts"])
    assert any(item["role"] == "run_execution:docs/generated_artifacts/paper_run_execution_claude_dry_run.json" for item in manifest["artifacts"])
    assert any(item["role"] == "run_execution:docs/generated_artifacts/paper_run_execution_claude_post_run.json" for item in manifest["artifacts"])
    assert any(item["role"] == "run_execution:docs/generated_artifacts/paper_run_execution_claude_post_run_dry_run.json" for item in manifest["artifacts"])
    assert any(item["role"] == "run_budget:docs/generated_artifacts/paper_run_budget.json" for item in manifest["artifacts"])
    assert any(item["role"] == "submission_gap:docs/generated_artifacts/paper_submission_gap_report.json" for item in manifest["artifacts"])
    assert any(item["role"] == "submission_objective:docs/generated_artifacts/paper_submission_objective_audit.json" for item in manifest["artifacts"])
    assert any(item["role"] == "submission_objective:docs/generated_artifacts/paper_submission_objective_audit.md" for item in manifest["artifacts"])
    assert any(item["role"] == "submission_package:docs/generated_artifacts/paper_submission_package_manifest.json" for item in manifest["artifacts"])
    assert any(item["role"] == "submission_package:docs/generated_artifacts/paper_submission_package_manifest.md" for item in manifest["artifacts"])
    assert any(item["role"] == "live_status:docs/generated_artifacts/paper_live_status.json" for item in manifest["artifacts"])
    assert any(item["role"] == "live_status:docs/generated_artifacts/paper_live_status_history.jsonl" for item in manifest["artifacts"])
    assert any(item["role"] == "release_metadata:CITATION.cff" for item in manifest["artifacts"])
    assert any(item["role"] == "release_metadata:docs/release_metadata_final.json" for item in manifest["artifacts"])
    assert any(
        "run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json --queue-mode serial --harness claude --execute" in cmd
        and "--out-json docs\\generated_artifacts\\paper_run_execution_claude_plan.json" in cmd
        for cmd in manifest["reproduction_commands"]
    )
    assert any(
        "run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json --queue-mode post-run --harness claude --execute" in cmd
        and "--out-json docs\\generated_artifacts\\paper_run_execution_claude_post_run.json" in cmd
        for cmd in manifest["reproduction_commands"]
    )
    assert not any(
        "run_paper_queue.py" in cmd and "--execute" in cmd and "--harness claude" not in cmd
        for cmd in manifest["reproduction_commands"]
    )
    assert not any("run_paper_baseline_matrix.ps1" in cmd for cmd in manifest["reproduction_commands"])
    assert not any("run_paper_control_matrix.ps1" in cmd for cmd in manifest["reproduction_commands"])
    assert any(cmd == "python infra\\check_paper_readiness.py" for cmd in manifest["reproduction_commands"])
    assert any("check_paper_claims.py --profile submission" in cmd for cmd in manifest["reproduction_commands"])
    assert any("check_release_metadata.py --require-license" in cmd for cmd in manifest["reproduction_commands"])
    assert any("report_paper_submission_gaps.py --require-ready" in cmd for cmd in manifest["reproduction_commands"])
    assert any("audit_submission_objective.py --require-ready" in cmd for cmd in manifest["reproduction_commands"])
    assert any("check_paper_artifact_gate.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_benchmark_card.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_paper_appendix.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_oracle_coverage_report.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_threat_model_card.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_statistical_analysis.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_claim_evidence_map.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_control_integrity_report.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_paper_figures.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("check_paper_bibliography.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_full_suite_eligibility_appendix.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("plan_external_validity_calibration.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("generate_submission_package_manifest.py" in cmd for cmd in manifest["reproduction_commands"])
    assert any("--submission-profile" in cmd for cmd in manifest["reproduction_commands"])
    assert any("run_paper_preflight.ps1 -Profile submission" in cmd for cmd in manifest["reproduction_commands"])
    assert not any("--harness codex" in cmd for cmd in manifest["reproduction_commands"])


def test_build_repro_bundle_records_explicit_bundle_dir_in_safety_command(tmp_path: Path, monkeypatch):
    root = tmp_path / "bench"
    attack = root / "runs/_reports/paper_core"
    tables = attack / "paper_tables"
    _write(attack / "summary.json", '{"label": "paper_core"}')
    _write(tables / "paper_tables.md", "# tables\n")

    monkeypatch.setattr(build_repro_bundle, "ROOT", root)
    monkeypatch.setattr(build_repro_bundle, "RUNS", root / "runs")
    monkeypatch.setattr(
        build_repro_bundle,
        "build_readiness",
        lambda require_kimi=True: {
            "ready": True,
            "blockers": [],
            "case_counts": {"core": 57, "extended": 205, "exploratory": 96, "all": 328},
        },
    )
    monkeypatch.setattr(
        build_repro_bundle,
        "git_state",
        lambda: {"commit": "abc", "branch": "main", "dirty": False, "status_short": []},
    )

    manifest = build_repro_bundle.build_manifest(
        attack,
        None,
        tables,
        attack_label="paper_core",
        require_kimi=False,
        bundle_dir=root / "runs/_artifacts/repro_bundles/custom_bundle",
    )

    assert any(
        "check_public_artifact_safety.py --bundle-dir runs\\_artifacts\\repro_bundles\\custom_bundle" in cmd
        for cmd in manifest["reproduction_commands"]
    )


def test_build_manifest_skips_dry_run_content_in_execute_output_slots(tmp_path: Path, monkeypatch):
    root = tmp_path
    attack = root / "runs/_reports/attack"
    clean = root / "runs/_reports/clean"
    tables = attack / "paper_tables"
    evidence = attack / "case_study_evidence"
    _write(attack / "summary.json", '{"label": "paper_attack"}')
    _write(clean / "summary.json", '{"label": "paper_clean"}')
    _write(tables / "paper_tables.md", "# tables\n")
    _write(evidence / "case_study_evidence.json", "{}\n")
    _write(evidence / "case_study_evidence.md", "# evidence\n")
    _write(root / "docs/generated_artifacts/paper_run_execution_plan.json", "{}\n")
    _write(root / "docs/generated_artifacts/paper_run_execution_plan.md", "# generic dry-run\n")
    _write(root / "docs/generated_artifacts/paper_run_execution_claude_plan.json", '{"execute": false}\n')
    _write(root / "docs/generated_artifacts/paper_run_execution_claude_plan.md", "# wrongly overwritten dry-run\n")
    _write(root / "docs/generated_artifacts/paper_run_execution_claude_dry_run.json", '{"execute": false}\n')
    _write(root / "docs/generated_artifacts/paper_run_execution_claude_dry_run.md", "# claude dry-run\n")

    monkeypatch.setattr(build_repro_bundle, "ROOT", root)
    monkeypatch.setattr(build_repro_bundle, "RUNS", root / "runs")
    monkeypatch.setattr(
        build_repro_bundle,
        "build_readiness",
        lambda require_kimi=True: {
            "ready": True,
            "blockers": [],
            "case_counts": {"core": 57, "extended": 205, "exploratory": 96, "all": 328},
        },
    )
    monkeypatch.setattr(
        build_repro_bundle,
        "git_state",
        lambda: {"commit": "abc", "branch": "main", "dirty": False, "status_short": []},
    )

    manifest = build_repro_bundle.build_manifest(
        attack,
        [clean],
        tables,
        evidence,
        attack_label="paper_attack",
        control_label="paper_clean",
        require_kimi=False,
    )

    roles = {item["role"] for item in manifest["artifacts"]}
    assert "run_execution:docs/generated_artifacts/paper_run_execution_claude_plan.json" not in roles
    assert "run_execution:docs/generated_artifacts/paper_run_execution_claude_plan.md" not in roles
    assert "run_execution:docs/generated_artifacts/paper_run_execution_claude_dry_run.json" in roles
    assert "run_execution:docs/generated_artifacts/paper_run_execution_claude_dry_run.md" in roles
    assert any(
        "check_paper_artifact_gate.py" in cmd
        and "--attack-report-dir runs\\_reports\\attack" in cmd
        and "--control-report-dir runs\\_reports\\clean" in cmd
        and "--max-timeouts 3" in cmd
        for cmd in manifest["reproduction_commands"]
    )


def test_build_manifest_excludes_codex_run_execution_from_current_paper_bundle(tmp_path: Path, monkeypatch):
    root = tmp_path
    attack = root / "runs/_reports/attack"
    tables = attack / "paper_tables"
    _write(attack / "summary.json", '{"label": "paper_attack"}')
    _write(tables / "paper_tables.md", "# tables\n")
    _write(root / "docs/generated_artifacts/paper_run_execution_plan.json", "{}\n")
    _write(root / "docs/generated_artifacts/paper_run_execution_plan.md", "# generic dry-run\n")
    _write(root / "docs/generated_artifacts/paper_run_execution_codex_plan.json", "{}\n")
    _write(root / "docs/generated_artifacts/paper_run_execution_codex_plan.md", "# codex dry-run\n")

    monkeypatch.setattr(build_repro_bundle, "ROOT", root)
    monkeypatch.setattr(build_repro_bundle, "RUNS", root / "runs")
    monkeypatch.setattr(
        build_repro_bundle,
        "build_readiness",
        lambda require_kimi=True: {
            "ready": True,
            "blockers": [],
            "case_counts": {"core": 57, "extended": 205, "exploratory": 96, "all": 328},
        },
    )
    monkeypatch.setattr(
        build_repro_bundle,
        "git_state",
        lambda: {"commit": "abc", "branch": "main", "dirty": False, "status_short": []},
    )

    current_manifest = build_repro_bundle.build_manifest(
        attack,
        None,
        tables,
        attack_label="paper_attack",
        require_kimi=False,
    )
    submission_manifest = build_repro_bundle.build_manifest(
        attack,
        None,
        tables,
        attack_label="paper_attack",
        require_kimi=True,
    )

    current_roles = {item["role"] for item in current_manifest["artifacts"]}
    submission_roles = {item["role"] for item in submission_manifest["artifacts"]}
    assert "run_execution:docs/generated_artifacts/paper_run_execution_codex_plan.json" not in current_roles
    assert "run_execution:docs/generated_artifacts/paper_run_execution_codex_plan.md" not in current_roles
    assert "run_execution:docs/generated_artifacts/paper_run_execution_codex_plan.json" not in submission_roles
    assert "run_execution:docs/generated_artifacts/paper_run_execution_codex_plan.md" not in submission_roles


def test_write_repro_bundle_can_copy_artifacts(tmp_path: Path, monkeypatch):
    root = tmp_path / "bench"
    artifact = root / "runs/_reports/paper_core/summary.json"
    _write(artifact, "{}")
    monkeypatch.setattr(build_repro_bundle, "ROOT", root)

    manifest = {
        "generated_at": "2026-06-25T00:00:00",
        "labels": {"attack": "paper_core", "control": ""},
        "git": {"commit": "abc", "branch": "main", "dirty": False},
        "readiness": {
            "ready": True,
            "blockers": [],
            "case_counts": {"core": 57, "extended": 205, "exploratory": 96, "all": 328},
        },
        "artifacts": [
            {
                "role": "attack_report:summary.json",
                "path": "runs/_reports/paper_core/summary.json",
                "exists": True,
                "bytes": 2,
                "sha256": hashlib.sha256(b"{}").hexdigest(),
            }
        ],
        "missing_artifacts": [],
        "reproduction_commands": ["python infra\\check_active_case_integrity.py"],
    }

    paths = build_repro_bundle.write_bundle(manifest, tmp_path / "bundle", copy_files=True)

    assert paths["json"].exists()
    assert paths["markdown"].exists()
    copied = tmp_path / "bundle/files/runs/_reports/paper_core/summary.json"
    assert copied.read_text(encoding="utf-8") == "{}"
    assert manifest["copied_artifacts"][0]["copied_sha256"] == manifest["artifacts"][0]["sha256"]


def test_write_repro_bundle_prunes_stale_copied_files(tmp_path: Path, monkeypatch):
    root = tmp_path / "bench"
    artifact = root / "runs/_reports/paper_core/summary.json"
    _write(artifact, "{}")
    monkeypatch.setattr(build_repro_bundle, "ROOT", root)
    stale = tmp_path / "bundle/files/runs/_reports/old_report/trace.jsonl"
    _write(stale, "stale\n")

    manifest = {
        "generated_at": "2026-06-25T00:00:00",
        "labels": {"attack": "paper_core", "control": ""},
        "git": {"commit": "abc", "branch": "main", "dirty": False},
        "readiness": {
            "ready": True,
            "blockers": [],
            "case_counts": {"core": 57, "extended": 205, "exploratory": 96, "all": 328},
        },
        "artifacts": [
            {
                "role": "attack_report:summary.json",
                "path": "runs/_reports/paper_core/summary.json",
                "exists": True,
                "bytes": 2,
                "sha256": hashlib.sha256(b"{}").hexdigest(),
            }
        ],
        "missing_artifacts": [],
        "reproduction_commands": ["python infra\\check_active_case_integrity.py"],
    }

    build_repro_bundle.write_bundle(manifest, tmp_path / "bundle", copy_files=True)

    assert not stale.exists()
    assert (tmp_path / "bundle/files/runs/_reports/paper_core/summary.json").exists()
