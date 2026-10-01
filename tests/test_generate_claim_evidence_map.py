import json
from pathlib import Path

from infra import generate_claim_evidence_map


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_generate_claim_evidence_map_binds_claims_to_current_artifacts(tmp_path: Path):
    generated = tmp_path / "docs/generated_artifacts"
    _write(
        generated / "benchmark_card.json",
        json.dumps(
            {
                "scope": {"active_case_count": 328, "case_counts": {"core": 328, "all": 328}},
                "current_baseline": {
                    "runtime": "Claude Code",
                    "model": "Kimi K2.6",
                    "harness": "claude",
                    "codex_in_current_scope": False,
                },
            }
        ),
    )
    _write(
        generated / "paper_statistical_analysis.json",
        json.dumps(
            {
                "schema_version": 2,
                "metric_contract": {
                    "n_minus_one_is_progress_node": False,
                    "conditional_asr_denominator": "ASR-eligible N0-N5b scored attack rows",
                    "end_to_end_denominator": "ASR-eligible scored attack rows plus N-1 attack rows",
                },
                "matrix": {
                    "attack_scored_rows": 10,
                    "attack_asr_eligible_scored_rows": 8,
                    "attack_n_minus_1_rows": 2,
                    "attack_accounted_terminal_rows": 12,
                    "attack_protocol_denominator_rows": 10,
                    "control_scored_rows": 20,
                    "control_asr_eligible_scored_rows": 18,
                    "control_n_minus_1_rows": 1,
                    "control_accounted_terminal_rows": 21,
                    "control_protocol_denominator_rows": 19,
                    "protocol_metrics_available": True,
                },
                "primary_effects": {
                    "conditional_attack_success": {
                        "available": True,
                        "successes": 3,
                        "trials": 8,
                        "rate": 3 / 8,
                    },
                    "protocol_completion": {
                        "available": True,
                        "successes": 8,
                        "trials": 10,
                        "rate": 0.8,
                    },
                    "model_nonconformance": {
                        "available": True,
                        "successes": 2,
                        "trials": 10,
                        "rate": 0.2,
                    },
                    "end_to_end_attack": {
                        "available": True,
                        "successes": 3,
                        "trials": 10,
                        "rate": 0.3,
                    },
                    "control_conditional_violation": {
                        "available": True,
                        "successes": 0,
                        "trials": 18,
                        "rate": 0.0,
                    },
                    "control_protocol_completion": {
                        "available": True,
                        "successes": 18,
                        "trials": 19,
                        "rate": 18 / 19,
                    },
                    "control_model_nonconformance": {
                        "available": True,
                        "successes": 1,
                        "trials": 19,
                        "rate": 1 / 19,
                    },
                    "control_end_to_end_violation": {
                        "available": True,
                        "successes": 0,
                        "trials": 19,
                        "rate": 0.0,
                    },
                },
            }
        ),
    )
    _write(
        generated / "paper_oracle_coverage.json",
        json.dumps(
            {
                "case_set": "all",
                "design_time": {
                    "case_count": 328,
                    "oracle_strength_counts": {"hard_trace_oracle": 328},
                },
            }
        ),
    )
    _write(
        generated / "paper_threat_model_card.json",
        json.dumps(
            {
                "scope": {"case_count": 328},
                "threat_model": {
                    "defender_assumptions": ["Model restatement is not sufficient evidence."],
                    "out_of_scope": ["Claims about all possible deployments."],
                },
            }
        ),
    )
    _write(
        generated / "paper_full_suite_eligibility.json",
        json.dumps(
            {
                "summary": {
                    "active_cases": 328,
                    "main_asr_cases": 328,
                    "diagnostic_cases": 0,
                }
            }
        ),
    )
    _write(
        tmp_path / "docs/paper_draft.md",
        "\n".join(
            [
                "The current baseline is the Claude Code + Kimi K2.6 model-harness configuration.",
                "The current protocol uses one attack trial per case, yielding 656 across the two configurations.",
                "Matched controls are not an exhaustive 328-case completion gate.",
                "Clean control; No-persist control; No-trigger control; Cleanup control.",
                "Evaluation Record v3 reports conditional ASR values of 53.37% and 53.97%.",
                "The first formal matrix covers one model-harness configuration.",
            ]
        ),
    )
    _write(
        tmp_path / "runs/_reports/paper_core_20260625/paper_artifact_gate.md",
        "claim_boundary: ok=`true`\npublic_artifact_safety: ok=`true`; files=71; issues=0\n",
    )
    _write(
        tmp_path / "runs/_reports/paper_core_20260625/paper_artifact_gate_submission.md",
        "release_metadata: ok=`false`\n",
    )
    _write(generated / "paper_submission_gap_report.json", json.dumps({"submission_ready": False}))

    claim_map = generate_claim_evidence_map.build_map(tmp_path)
    markdown = generate_claim_evidence_map.render_markdown(claim_map)

    assert claim_map["schema_version"] == 2
    assert claim_map["summary"]["claims"] == 10
    assert claim_map["summary"]["supported"] == 9
    assert claim_map["summary"]["blocked_on_release_metadata"] == 1
    assert claim_map["summary"]["needs_attention"] == 0
    assert claim_map["summary"]["ok_for_current_artifact"] is True
    assert {claim["id"] for claim in claim_map["claims"]} == {
        "C1_scope",
        "C2_configuration_boundary",
        "C3_matrix_protocol",
        "C4_results_reported",
        "C5_control_design",
        "C6_oracle_policy",
        "C7_public_artifact_boundary",
        "C8_release_status",
        "C9_limitations",
        "C10_measurement_accounting",
    }
    assert "# Paper Claim Evidence Map" in markdown
    assert "Claim Boundary" in markdown
    assert "Supported Claims" in markdown
    assert "Blocked Release Claims" in markdown
    assert "Public Artifact Boundary" in markdown
    assert "Claude Code + Kimi K2.6" in markdown
    assert "328 active hard-oracle cases" in markdown
    assert "one 328-case attack trial per configuration" in markdown
    assert "N-1 / MODEL_PROTOCOL_INCOMPLETE is an orthogonal terminal result class" in markdown
    assert "Coverage accounting uses all scored rows plus N-1" in markdown
    assert "rates use S+M" in markdown
    assert "57-case" not in markdown
    assert "23/171" not in markdown
    assert claim_map["sources"]["benchmark_card"] == "docs/generated_artifacts/benchmark_card.json"
    assert claim_map["sources"]["oracle_coverage"] == "docs/generated_artifacts/paper_oracle_coverage.json"


def test_measurement_accounting_claim_rejects_n_minus_one_as_progress_node():
    stats = {
        "schema_version": 2,
        "metric_contract": {
            "n_minus_one_is_progress_node": False,
            "conditional_asr_denominator": "ASR-eligible N0-N5b scored attack rows",
            "end_to_end_denominator": "ASR-eligible scored attack rows plus N-1 attack rows",
        },
        "matrix": {
            "attack_scored_rows": 2,
            "attack_asr_eligible_scored_rows": 1,
            "attack_n_minus_1_rows": 1,
            "attack_accounted_terminal_rows": 3,
            "attack_protocol_denominator_rows": 2,
            "control_scored_rows": 1,
            "control_asr_eligible_scored_rows": 1,
            "control_n_minus_1_rows": 0,
            "control_accounted_terminal_rows": 1,
            "control_protocol_denominator_rows": 1,
            "protocol_metrics_available": True,
        },
        "primary_effects": {
            "conditional_attack_success": {"available": True, "successes": 0, "trials": 1, "rate": 0.0},
            "protocol_completion": {"available": True, "successes": 1, "trials": 2, "rate": 0.5},
            "model_nonconformance": {"available": True, "successes": 1, "trials": 2, "rate": 0.5},
            "end_to_end_attack": {"available": True, "successes": 0, "trials": 2, "rate": 0.0},
            "control_conditional_violation": {"available": True, "successes": 0, "trials": 1, "rate": 0.0},
            "control_protocol_completion": {"available": True, "successes": 1, "trials": 1, "rate": 1.0},
            "control_model_nonconformance": {"available": True, "successes": 0, "trials": 1, "rate": 0.0},
            "control_end_to_end_violation": {"available": True, "successes": 0, "trials": 1, "rate": 0.0},
        },
    }

    assert generate_claim_evidence_map.measurement_accounting_supported(stats) is True

    forged = json.loads(json.dumps(stats))
    forged["matrix"]["attack_asr_eligible_scored_rows"] = 3
    forged["matrix"]["attack_protocol_denominator_rows"] = 4
    forged["primary_effects"]["conditional_attack_success"].update(
        {"trials": 3, "rate": 1 / 3}
    )
    forged["primary_effects"]["protocol_completion"].update(
        {"successes": 3, "trials": 4, "rate": 3 / 4}
    )
    forged["primary_effects"]["model_nonconformance"].update(
        {"trials": 4, "rate": 1 / 4}
    )
    forged["primary_effects"]["end_to_end_attack"].update(
        {"trials": 4, "rate": 1 / 4}
    )
    assert not generate_claim_evidence_map.measurement_accounting_supported(forged)

    stats["metric_contract"]["n_minus_one_is_progress_node"] = True
    assert generate_claim_evidence_map.measurement_accounting_supported(stats) is False


def test_measurement_accounting_accepts_null_rates_for_zero_denominators():
    zero_metric = {
        "available": True,
        "successes": 0,
        "trials": 0,
        "rate": None,
    }
    statistics = {
        "schema_version": 2,
        "metric_contract": {
            "n_minus_one_is_progress_node": False,
            "conditional_asr_denominator": "ASR-eligible N0-N5b scored attack rows",
            "end_to_end_denominator": "ASR-eligible scored attack rows plus N-1 attack rows",
        },
        "matrix": {
            "attack_scored_rows": 0,
            "attack_asr_eligible_scored_rows": 0,
            "attack_n_minus_1_rows": 0,
            "attack_accounted_terminal_rows": 0,
            "attack_protocol_denominator_rows": 0,
            "control_scored_rows": 0,
            "control_asr_eligible_scored_rows": 0,
            "control_n_minus_1_rows": 0,
            "control_accounted_terminal_rows": 0,
            "control_protocol_denominator_rows": 0,
            "protocol_metrics_available": True,
        },
        "primary_effects": {
            "conditional_attack_success": dict(zero_metric),
            "protocol_completion": dict(zero_metric),
            "model_nonconformance": dict(zero_metric),
            "end_to_end_attack": dict(zero_metric),
            "control_conditional_violation": dict(zero_metric),
            "control_protocol_completion": dict(zero_metric),
            "control_model_nonconformance": dict(zero_metric),
            "control_end_to_end_violation": dict(zero_metric),
        },
    }

    assert generate_claim_evidence_map.measurement_accounting_supported(statistics)

    statistics["primary_effects"]["conditional_attack_success"]["rate"] = 0.0
    assert not generate_claim_evidence_map.measurement_accounting_supported(statistics)
