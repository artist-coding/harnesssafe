import json
from pathlib import Path

import pytest

from infra import generate_statistical_analysis


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_generate_statistical_analysis_summarizes_rates_timeouts_and_heterogeneity(tmp_path: Path):
    attack = tmp_path / "runs/_reports/paper_core"
    control = tmp_path / "runs/_reports/paper_controls"
    _write(
        attack / "summary.json",
        json.dumps(
            {
                "label": "paper_core",
                "evaluation_schema_version": "2.1.0",
                "harness_macro": [
                    {
                        "run_kind": "attack",
                        "harness": "claude",
                        "completed_trials": 10,
                        "n_minus_1_trials": 2,
                        "accounted_terminal_trials": 12,
                        "asr_eligible_trials": 8,
                        "protocol_denominator_trials": 10,
                        "timeout_trials": 1,
                        "attack_success_trials": 3,
                        "factual_attack_success_trials": 3,
                        "confirmed_trials": 1,
                        "protocol_completion_trial_rate": 8 / 10,
                        "model_nonconformance_trial_rate": 2 / 10,
                        "end_to_end_attack_trial_rate": 3 / 10,
                    }
                ],
                "family_macro": [
                    {
                        "run_kind": "attack",
                        "suite": "v2_skill_runtime",
                        "paper_family": "F2.04",
                        "cases": 1,
                        "completed_trials": 5,
                        "n_minus_1_trials": 1,
                        "accounted_terminal_trials": 6,
                        "asr_eligible_trials": 5,
                        "protocol_denominator_trials": 6,
                        "attack_success_trials": 3,
                        "confirmed_trials": 1,
                        "attack_success_trial_rate": 0.6,
                        "protocol_completion_trial_rate": 5 / 6,
                        "model_nonconformance_trial_rate": 1 / 6,
                        "end_to_end_attack_trial_rate": 0.5,
                        "confirmed_trial_rate": 0.2,
                        "avg_risk_case_mean": 80.0,
                    }
                ],
                "case_summary": [
                    {
                        "run_kind": "attack",
                        "suite": "v2_skill_runtime",
                        "paper_family": "F2.04",
                        "case_dir": "active/F2/case_a",
                        "completed_trials": 5,
                        "n_minus_1_trials": 1,
                        "accounted_terminal_trials": 6,
                        "asr_eligible_trials": 5,
                        "protocol_denominator_trials": 6,
                        "attack_success_trials": 3,
                        "confirmed_trials": 1,
                        "attack_success_rate": 0.6,
                        "protocol_completion_rate": 5 / 6,
                        "model_nonconformance_rate": 1 / 6,
                        "end_to_end_attack_rate": 0.5,
                        "confirmed_rate": 0.2,
                        "max_progress_node": "N5",
                        "avg_risk": 80.0,
                    }
                ],
            }
        ),
    )
    _write(
        control / "summary.json",
        json.dumps(
            {
                "label": "paper_controls",
                "evaluation_schema_version": "2.1.0",
                "harness_macro": [
                    {
                        "run_kind": "control",
                        "control_type": "clean_control",
                        "harness": "claude",
                        "completed_trials": 5,
                        "n_minus_1_trials": 1,
                        "accounted_terminal_trials": 6,
                        "asr_eligible_trials": 4,
                        "protocol_denominator_trials": 5,
                        "timeout_trials": 1,
                        "attack_success_trials": 0,
                        "factual_attack_success_trials": 0,
                        "confirmed_trials": 0,
                        "protocol_completion_trial_rate": 4 / 5,
                        "model_nonconformance_trial_rate": 1 / 5,
                        "end_to_end_attack_trial_rate": 0,
                    },
                    {
                        "run_kind": "control",
                        "control_type": "no_trigger_control",
                        "harness": "claude",
                        "completed_trials": 5,
                        "n_minus_1_trials": 0,
                        "accounted_terminal_trials": 5,
                        "asr_eligible_trials": 5,
                        "protocol_denominator_trials": 5,
                        "timeout_trials": 0,
                        "attack_success_trials": 0,
                        "factual_attack_success_trials": 0,
                        "confirmed_trials": 0,
                        "protocol_completion_trial_rate": 1,
                        "model_nonconformance_trial_rate": 0,
                        "end_to_end_attack_trial_rate": 0,
                    },
                ],
            }
        ),
    )

    analysis = generate_statistical_analysis.build_analysis(
        attack_dirs=[attack],
        control_dirs=[control],
        root=tmp_path,
    )
    markdown = generate_statistical_analysis.render_markdown(analysis)

    assert analysis["schema_version"] == 2
    assert analysis["baseline"]["runtime"] == "Claude Code"
    assert analysis["baseline"]["model"] == "Kimi K2.6"
    assert analysis["matrix"]["attack_rows"] == 10
    assert analysis["matrix"]["attack_n_minus_1_rows"] == 2
    assert analysis["matrix"]["attack_accounted_terminal_rows"] == 12
    assert analysis["matrix"]["attack_asr_eligible_scored_rows"] == 8
    assert analysis["matrix"]["attack_protocol_denominator_rows"] == 10
    assert analysis["matrix"]["attack_timeouts"] == 1
    assert analysis["matrix"]["control_rows"] == 10
    assert analysis["matrix"]["control_n_minus_1_rows"] == 1
    assert analysis["matrix"]["control_accounted_terminal_rows"] == 11
    assert analysis["matrix"]["control_asr_eligible_scored_rows"] == 9
    assert analysis["matrix"]["control_protocol_denominator_rows"] == 10
    assert analysis["matrix"]["control_timeouts"] == 1
    assert analysis["primary_effects"]["attack_success"]["successes"] == 3
    assert analysis["primary_effects"]["attack_success"]["trials"] == 8
    assert analysis["primary_effects"]["protocol_completion"]["successes"] == 8
    assert analysis["primary_effects"]["protocol_completion"]["trials"] == 10
    assert analysis["primary_effects"]["model_nonconformance"]["successes"] == 2
    assert analysis["primary_effects"]["end_to_end_attack"]["rate"] == 0.3
    assert analysis["primary_effects"]["control_protocol_completion"]["successes"] == 9
    assert analysis["primary_effects"]["control_protocol_completion"]["trials"] == 10
    assert analysis["primary_effects"]["control_attack_success"]["successes"] == 0
    assert analysis["control_zero_success_bound"]["one_sided_95_upper"] > 0
    assert analysis["timeout_sensitivity"]["attack_success"]["timeouts_as_successes"]["successes"] == 4
    assert analysis["timeout_sensitivity"]["attack_success"]["timeouts_as_successes"]["trials"] == 9
    assert analysis["timeout_sensitivity"]["attack_success"]["timeouts_as_failures"]["trials"] == 9
    assert analysis["timeout_sensitivity"]["attack_success"]["timeouts_excluded"]["trials"] == 8
    assert analysis["family_heterogeneity"]["families"] == 1
    assert analysis["case_heterogeneity"]["cases"] == 1
    assert "# Safety Bench Statistical Analysis" in markdown
    assert "Claude Code + Kimi K2.6" in markdown
    assert "Wilson 95%" in markdown
    assert "Control Zero-Success Bound" in markdown
    assert "Timeout Sensitivity" in markdown
    assert "Family Heterogeneity" in markdown
    assert "Public Artifact Boundary" in markdown
    assert "Model nonconformance / N-1" in markdown
    assert "End-to-end attack (S+M denominator)" in markdown


def test_zero_denominator_metrics_remain_available_with_null_rates(tmp_path: Path):
    attack = tmp_path / "runs/_reports/empty_attack"
    control = tmp_path / "runs/_reports/empty_control"
    empty_macro = {
        "completed_trials": 0,
        "n_minus_1_trials": 0,
        "accounted_terminal_trials": 0,
        "asr_eligible_trials": 0,
        "protocol_denominator_trials": 0,
        "timeout_trials": 0,
        "attack_success_trials": 0,
        "factual_attack_success_trials": 0,
        "confirmed_trials": 0,
        "protocol_completion_trial_rate": None,
        "model_nonconformance_trial_rate": None,
        "attack_success_trial_rate": None,
        "end_to_end_attack_trial_rate": None,
    }
    _write(
        attack / "summary.json",
        json.dumps(
            {
                "label": "empty_attack",
                "evaluation_schema_version": "2.1.0",
                "harness_macro": [{**empty_macro, "run_kind": "attack"}],
            }
        ),
    )
    _write(
        control / "summary.json",
        json.dumps(
            {
                "label": "empty_control",
                "evaluation_schema_version": "2.1.0",
                "harness_macro": [
                    {
                        **empty_macro,
                        "run_kind": "control",
                        "control_type": "clean_control",
                    }
                ],
            }
        ),
    )

    analysis = generate_statistical_analysis.build_analysis(
        attack_dirs=[attack], control_dirs=[control], root=tmp_path
    )
    markdown = generate_statistical_analysis.render_markdown(analysis)

    for name in [
        "conditional_attack_success",
        "protocol_completion",
        "model_nonconformance",
        "end_to_end_attack",
        "control_conditional_violation",
        "control_protocol_completion",
        "control_model_nonconformance",
        "control_end_to_end_violation",
    ]:
        block = analysis["primary_effects"][name]
        assert block["available"] is True
        assert block["successes"] == 0
        assert block["trials"] == 0
        assert block["rate"] is None
        assert block["wilson95"] == []
    assert analysis["primary_effects"]["risk_difference_attack_success_vs_control"] is None
    assert analysis["control_zero_success_bound"]["one_sided_95_upper"] is None
    assert "0/0 (n/a), Wilson 95% n/a" in markdown


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda row: row.pop("protocol_denominator_trials"), "missing protocol_denominator_trials"),
        (lambda row: row.update(n_minus_1_trials=-1), "non-negative integer"),
        (lambda row: row.update(asr_eligible_trials=5), "S cannot exceed"),
        (lambda row: row.update(accounted_terminal_trials=99), "T must equal"),
        (lambda row: row.update(protocol_denominator_trials=99), "D must equal"),
        (lambda row: row.update(attack_success_trials=4), "A cannot exceed"),
    ],
)
def test_current_measurement_contract_fails_closed(mutation, message):
    row = {
        "completed_trials": 4,
        "asr_eligible_trials": 3,
        "n_minus_1_trials": 1,
        "accounted_terminal_trials": 5,
        "protocol_denominator_trials": 4,
        "attack_success_trials": 2,
        "confirmed_trials": 1,
    }
    mutation(row)
    with pytest.raises(ValueError, match=message):
        generate_statistical_analysis.measurement_counts(row, "attack_macro")


def test_current_summary_cannot_bypass_contract_by_omitting_every_marker(tmp_path: Path):
    attack = tmp_path / "attack"
    control = tmp_path / "control"
    legacy_shaped = {
        "completed_trials": 1,
        "attack_success_trials": 0,
        "confirmed_trials": 0,
    }
    _write(
        attack / "summary.json",
        json.dumps(
            {
                "evaluation_schema_version": "2.1.0",
                "harness_macro": [{**legacy_shaped, "run_kind": "attack"}],
            }
        ),
    )
    _write(
        control / "summary.json",
        json.dumps(
            {
                "evaluation_schema_version": "2.1.0",
                "harness_macro": [{**legacy_shaped, "run_kind": "control"}],
            }
        ),
    )

    with pytest.raises(ValueError, match="current measurement contract is missing"):
        generate_statistical_analysis.build_analysis(
            attack_dirs=[attack], control_dirs=[control], root=tmp_path
        )


def test_d_only_rows_keep_protocol_counts_but_null_safety_progress_and_risk():
    common = {
        "run_kind": "attack",
        "suite": "F2",
        "paper_family": "F2.test",
        "completed_trials": 1,
        "asr_eligible_trials": 0,
        "n_minus_1_trials": 1,
        "accounted_terminal_trials": 2,
        "protocol_denominator_trials": 1,
        "attack_success_trials": 0,
        "confirmed_trials": 0,
    }
    family = generate_statistical_analysis.family_heterogeneity(
        [{**common, "avg_risk_case_mean": 99.0}]
    )
    cases = generate_statistical_analysis.case_heterogeneity(
        [
            {
                **common,
                "case_dir": "active/F2/case_d_only",
                "max_progress_node": "N5b",
                "avg_risk": 99.0,
            }
        ]
    )

    assert family["top_families"][0]["protocol_denominator_trials"] == 1
    assert family["top_families"][0]["protocol_completion_trial_rate"] == 0.0
    assert family["top_families"][0]["attack_success_trial_rate"] is None
    assert family["top_families"][0]["avg_risk_case_mean"] is None
    assert cases["top_cases"][0]["protocol_denominator_trials"] == 1
    assert cases["top_cases"][0]["max_progress_node"] is None
    assert cases["top_cases"][0]["avg_risk"] is None

    markdown = generate_statistical_analysis.render_markdown(
        {
            "baseline": {},
            "matrix": {},
            "primary_effects": {},
            "control_zero_success_bound": {},
            "timeout_sensitivity": {},
            "family_heterogeneity": family,
            "case_heterogeneity": cases,
            "control_by_type": [],
            "sources": {},
        }
    )
    assert "case_d_only" in markdown
    assert "N5b" not in markdown
    assert "99.0" not in markdown
    assert "| n/a | n/a |" in markdown


def test_timeout_sensitivity_never_emits_impossible_success_counts():
    sensitivity = generate_statistical_analysis.timeout_sensitivity(1, 1, 1)

    assert sensitivity["timeouts_as_failures"]["successes"] == 1
    assert sensitivity["timeouts_as_failures"]["trials"] == 2
    assert sensitivity["timeouts_as_successes"]["successes"] == 2
    assert sensitivity["timeouts_as_successes"]["trials"] == 2
    assert sensitivity["timeouts_excluded"]["successes"] == 1
    assert sensitivity["timeouts_excluded"]["trials"] == 1
    for block_name in (
        "observed_status_quo",
        "timeouts_as_failures",
        "timeouts_as_successes",
        "timeouts_excluded",
    ):
        block = sensitivity[block_name]
        assert 0 <= block["successes"] <= block["trials"]
