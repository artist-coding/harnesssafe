import json
from pathlib import Path

import pytest

from infra import generate_benchmark_card


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_generate_benchmark_card_builds_current_baseline_summary(tmp_path: Path):
    attack = tmp_path / "runs/_reports/paper_core"
    control = tmp_path / "runs/_reports/paper_controls"
    tables = attack / "paper_tables"
    suite_lock = tmp_path / "docs/generated_artifacts/paper_suite_lock.json"
    _write(
        attack / "summary.json",
        json.dumps(
            {
                "label": "paper_core",
                "evaluation_schema_version": "2.1.0",
                "case_set": "core",
                "active_case_count": 2,
                "rows": [{}, {}, {}, {}, {}, {}],
                "harness_macro": [
                    {
                        "case_set": "core",
                        "run_kind": "attack",
                        "harness": "claude",
                        "completed_trials": 5,
                        "n_minus_1_trials": 1,
                        "accounted_terminal_trials": 6,
                        "asr_eligible_trials": 5,
                        "protocol_denominator_trials": 6,
                        "timeout_trials": 1,
                        "attack_success_trials": 2,
                        "factual_attack_success_trials": 2,
                        "confirmed_trials": 1,
                        "protocol_completion_trial_rate": 5 / 6,
                        "model_nonconformance_trial_rate": 1 / 6,
                        "attack_success_trial_rate": 0.4,
                        "end_to_end_attack_trial_rate": 1 / 3,
                        "attack_success_ci_low": 0.0968,
                        "attack_success_ci_high": 0.7000,
                        "family_macro_attack_success": 0.5,
                        "family_macro_end_to_end_attack": 1 / 3,
                        "family_macro_confirmed": 0.25,
                        "family_macro_risk": 42.0,
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
                "case_set": "core",
                "control_types": ["clean_control", "cleanup_control"],
                "rows": [{}, {}, {}, {}],
                "harness_macro": [
                    {
                        "case_set": "core",
                        "run_kind": "control",
                        "control_type": "clean_control",
                        "harness": "claude",
                        "completed_trials": 2,
                        "n_minus_1_trials": 1,
                        "accounted_terminal_trials": 3,
                        "asr_eligible_trials": 2,
                        "protocol_denominator_trials": 3,
                        "timeout_trials": 0,
                        "attack_success_trials": 0,
                        "factual_attack_success_trials": 0,
                        "confirmed_trials": 0,
                        "protocol_completion_trial_rate": 2 / 3,
                        "model_nonconformance_trial_rate": 1 / 3,
                        "attack_success_trial_rate": 0,
                        "end_to_end_attack_trial_rate": 0,
                    },
                    {
                        "case_set": "core",
                        "run_kind": "control",
                        "control_type": "cleanup_control",
                        "harness": "claude",
                        "completed_trials": 2,
                        "n_minus_1_trials": 0,
                        "accounted_terminal_trials": 2,
                        "asr_eligible_trials": 2,
                        "protocol_denominator_trials": 2,
                        "timeout_trials": 1,
                        "attack_success_trials": 0,
                        "factual_attack_success_trials": 0,
                        "confirmed_trials": 0,
                        "protocol_completion_trial_rate": 1,
                        "model_nonconformance_trial_rate": 0,
                        "attack_success_trial_rate": 0,
                        "end_to_end_attack_trial_rate": 0,
                    },
                ],
            }
        ),
    )
    _write(
        tables / "paper_tables.json",
        json.dumps(
            {
                "main": {
                    "headers": [
                        "Harness",
                        "Scored Families",
                        "Scored Trials",
                        "N-1",
                        "Accounted Terminal",
                        "Protocol Completion",
                        "Model Nonconformance",
                        "Conditional ASR [95% CI]",
                        "End-to-End Attack Rate",
                        "Family Macro Conditional ASR",
                        "Family Macro End-to-End",
                        "Family Macro Confirmed",
                        "Risk",
                        "Timeouts",
                    ],
                    "rows": [["claude", "2/2", "5", "1", "6", "83.3%", "16.7%", "40.0% [11.8%-76.9%]", "33.3%", "50.0%", "33.3%", "25.0%", "42.0000", "1"]],
                }
            }
        ),
    )
    _write(
        suite_lock,
        json.dumps(
            {
                "schema_version": 1,
                "source_manifest": "runs/manifest.json",
                "active_case_count": 4,
                "case_counts": {"core": 2, "extended": 1, "exploratory": 1, "all": 4},
            }
        ),
    )

    card = generate_benchmark_card.build_card(
        attack_dirs=[attack],
        control_dirs=[control],
        table_dir=tables,
        suite_lock_path=suite_lock,
        root=tmp_path,
    )
    markdown = generate_benchmark_card.render_markdown(card)

    assert card["benchmark"]["name"] == "Safety Bench"
    assert card["benchmark"]["frame"] == "Entry -> Carrier -> Boundary -> Trigger -> Violation"
    assert card["current_baseline"]["harness"] == "claude"
    assert card["current_baseline"]["model"] == "Kimi K2.6"
    assert card["schema_version"] == 2
    assert card["matrix"]["attack_rows"] == 5
    assert card["matrix"]["n_minus_1_attack_rows"] == 1
    assert card["matrix"]["accounted_terminal_attack_rows"] == 6
    assert card["matrix"]["protocol_denominator_attack_rows"] == 6
    assert card["matrix"]["control_rows"] == 4
    assert card["matrix"]["n_minus_1_control_rows"] == 1
    assert card["matrix"]["accounted_terminal_control_rows"] == 5
    assert card["matrix"]["protocol_denominator_control_rows"] == 5
    assert card["matrix"]["total_rows"] == 9
    assert card["current_results"]["attack_success_rows"] == 2
    assert card["current_results"]["asr_eligible_scored_trials"] == 5
    assert card["current_results"]["conditional_asr"] == "40.0% [9.7%-70.0%]"
    assert card["current_results"]["end_to_end_attack_rate"] == 1 / 3
    assert card["controls"]["attack_success_rows"] == 0
    assert card["controls"]["asr_eligible_scored_trials"] == 4
    assert "# Safety Bench Benchmark Card" in markdown
    assert "Claude Code + Kimi K2.6" in markdown
    assert "Public Artifact Boundary" in markdown
    assert "Entry -> Carrier -> Boundary -> Trigger -> Violation" in markdown
    assert "Attack N-1 rows | 1" in markdown
    assert "Attack ASR-eligible scored rows | 5" in markdown
    assert "control_asr_eligible_scored_rows: `4`" in markdown
    assert "End-to-end attack rate | 33.3%" in markdown


def test_generate_benchmark_card_preserves_null_zero_denominator_rates(tmp_path: Path):
    attack = tmp_path / "runs/_reports/empty_attack"
    control = tmp_path / "runs/_reports/empty_control"
    tables = attack / "paper_tables"
    suite_lock = tmp_path / "docs/generated_artifacts/paper_suite_lock.json"
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
                "case_set": "all",
                "active_case_count": 1,
                "rows": [],
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
                "case_set": "all",
                "rows": [],
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
    _write(
        suite_lock,
        json.dumps(
            {
                "schema_version": 1,
                "source_manifest": "runs/manifest.json",
                "active_case_count": 1,
                "case_counts": {"all": 1, "core": 1},
            }
        ),
    )
    _write(
        tables / "paper_tables.json",
        json.dumps(
            {
                "main": {
                    "headers": [
                        "Conditional ASR [95% CI]",
                        "Family Macro Conditional ASR",
                        "Family Macro End-to-End",
                        "Family Macro Confirmed",
                        "Risk",
                    ],
                    "rows": [["0.0% [0.0%-0.0%]", "0.0%", "0.0%", "0.0%", "0.0000"]],
                }
            }
        ),
    )

    card = generate_benchmark_card.build_card(
        attack_dirs=[attack],
        control_dirs=[control],
        table_dir=tables,
        suite_lock_path=suite_lock,
        root=tmp_path,
    )
    markdown = generate_benchmark_card.render_markdown(card)

    for field in [
        "protocol_completion_rate",
        "model_nonconformance_rate",
        "conditional_asr_rate",
        "end_to_end_attack_rate",
    ]:
        assert card["current_results"][field] is None
    for field in [
        "protocol_completion_rate",
        "model_nonconformance_rate",
        "conditional_violation_rate",
        "end_to_end_violation_rate",
    ]:
        assert card["controls"][field] is None
    assert card["controls"]["by_type"][0]["conditional_violation_rate"] is None
    assert card["current_results"]["mean_risk"] is None
    assert "Conditional ASR | n/a" in markdown
    assert "End-to-end attack rate | n/a" in markdown
    assert "Family macro conditional ASR | n/a" in markdown
    assert "Family macro end-to-end attack rate | n/a" in markdown
    assert "Family macro confirmed | n/a" in markdown
    assert "Mean risk | n/a" in markdown
    assert "0.0% [0.0%-0.0%]" not in markdown


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda row: row.pop("protocol_denominator_trials"), "missing protocol_denominator_trials"),
        (lambda row: row.update(completed_trials=-1), "non-negative integer"),
        (lambda row: row.update(asr_eligible_trials=5), "S cannot exceed"),
        (lambda row: row.update(accounted_terminal_trials=99), "T must equal"),
        (lambda row: row.update(protocol_denominator_trials=99), "D must equal"),
        (lambda row: row.update(attack_success_trials=4), "A cannot exceed"),
    ],
)
def test_benchmark_card_measurement_contract_fails_closed(mutation, message):
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
        generate_benchmark_card.measurement_counts(row, "attack_macro")


def test_benchmark_card_current_summary_cannot_omit_all_contract_markers(tmp_path: Path):
    attack = tmp_path / "attack"
    control = tmp_path / "control"
    suite_lock = tmp_path / "suite_lock.json"
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
    _write(
        suite_lock,
        json.dumps(
            {
                "schema_version": 1,
                "active_case_count": 1,
                "case_counts": {"all": 1},
            }
        ),
    )

    with pytest.raises(ValueError, match="current measurement contract is missing"):
        generate_benchmark_card.build_card(
            attack_dirs=[attack],
            control_dirs=[control],
            table_dir=None,
            suite_lock_path=suite_lock,
            root=tmp_path,
        )


def test_legacy_control_aggregate_uses_same_scored_fallback_as_by_type():
    summary = {
        "harness_macro": [
            {
                "run_kind": "control",
                "control_type": "legacy_control",
                "completed_trials": 3,
                "attack_success_trials": 1,
                "confirmed_trials": 0,
            }
        ]
    }

    totals = generate_benchmark_card.sum_harness_macro(summary)
    by_type = generate_benchmark_card.control_type_summaries([summary])[0]

    assert totals["protocol_metrics_available"] is False
    assert totals["asr_eligible_trials"] == 3
    assert by_type["asr_eligible_scored_trials"] == 3
    assert by_type["protocol_denominator_trials"] is None
