import csv
import json
from pathlib import Path

import pytest

from infra import export_paper_tables


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def test_export_paper_tables_uses_report_macro_artifacts(tmp_path: Path):
    attack_dir = tmp_path / "attack_report"
    control_dir = tmp_path / "control_report"
    no_trigger_dir = tmp_path / "no_trigger_report"
    _write_json(attack_dir / "summary.json", {"label": "paper_core"})
    _write_json(control_dir / "summary.json", {"label": "paper_controls"})
    _write_json(no_trigger_dir / "summary.json", {"label": "paper_no_trigger"})
    _write_csv(
        attack_dir / "harness_macro.csv",
        [
            {
                "case_set": "core",
                "run_kind": "attack",
                "control_type": "",
                "harness": "claude",
                "families": "2",
                "complete_families": "2",
                "completed_trials": "6",
                "asr_eligible_trials": "5",
                "n_minus_1_trials": "2",
                "accounted_terminal_trials": "8",
                "protocol_denominator_trials": "7",
                "attack_success_trials": "3",
                "timeout_trials": "1",
                "protocol_completion_trial_rate": "0.75",
                "model_nonconformance_trial_rate": "0.25",
                "attack_success_trial_rate": "0.5",
                "end_to_end_attack_trial_rate": "0.375",
                "attack_success_ci_low": "0.2",
                "attack_success_ci_high": "0.8",
                "confirmed_trial_rate": "0.3333",
                "confirmed_ci_low": "0.1",
                "confirmed_ci_high": "0.7",
                "family_macro_attack_success": "0.45",
                "family_macro_end_to_end_attack": "0.30",
                "family_macro_confirmed": "0.25",
                "family_macro_risk": "42.5",
            }
        ],
    )
    _write_csv(
        attack_dir / "family_macro.csv",
        [
            {
                "case_set": "core",
                "run_kind": "attack",
                "control_type": "",
                "harness": "claude",
                "suite": "v2_skill_runtime",
                "paper_family": "F2.01",
                "cases": "1",
                "complete_cases": "1",
                "completed_trials": "2",
                "asr_eligible_trials": "1",
                "n_minus_1_trials": "1",
                "accounted_terminal_trials": "3",
                "protocol_denominator_trials": "2",
                "attack_success_trials": "1",
                "timeout_trials": "0",
                "protocol_completion_trial_rate": "0.6667",
                "model_nonconformance_trial_rate": "0.3333",
                "attack_success_trial_rate": "0.5",
                "end_to_end_attack_trial_rate": "0.3333",
                "attack_success_ci_low": "0.05",
                "attack_success_ci_high": "0.8",
                "confirmed_trial_rate": "0",
                "confirmed_ci_low": "0",
                "confirmed_ci_high": "0.5",
                "attack_success_case_mean": "0.5",
                "end_to_end_attack_case_mean": "0.3333",
                "confirmed_case_mean": "0",
                "avg_risk_case_mean": "20",
            },
            {
                "case_set": "core",
                "run_kind": "attack",
                "control_type": "",
                "harness": "claude",
                "suite": "v2_skill_runtime",
                "paper_family": "F2.02",
                "cases": "1",
                "complete_cases": "0",
                "completed_trials": "0",
                "asr_eligible_trials": "0",
                "n_minus_1_trials": "1",
                "accounted_terminal_trials": "1",
                "protocol_denominator_trials": "1",
                "attack_success_trials": "0",
                "timeout_trials": "0",
                "protocol_completion_trial_rate": "0",
                "model_nonconformance_trial_rate": "1",
                "attack_success_trial_rate": "",
                "end_to_end_attack_trial_rate": "0",
                "attack_success_ci_low": "",
                "attack_success_ci_high": "",
                "confirmed_trial_rate": "",
                "confirmed_ci_low": "",
                "confirmed_ci_high": "",
                "attack_success_case_mean": "",
                "end_to_end_attack_case_mean": "0",
                "confirmed_case_mean": "",
                "avg_risk_case_mean": "",
            }
        ],
    )
    _write_csv(
        control_dir / "harness_macro.csv",
        [
            {
                "case_set": "core",
                "run_kind": "control",
                "control_type": "clean_control",
                "harness": "claude",
                "families": "2",
                "complete_families": "2",
                "completed_trials": "2",
                "asr_eligible_trials": "1",
                "n_minus_1_trials": "1",
                "accounted_terminal_trials": "3",
                "protocol_denominator_trials": "2",
                "attack_success_trials": "0",
                "timeout_trials": "0",
                "protocol_completion_trial_rate": "0.6667",
                "model_nonconformance_trial_rate": "0.3333",
                "attack_success_trial_rate": "0",
                "end_to_end_attack_trial_rate": "0",
                "attack_success_ci_low": "0",
                "attack_success_ci_high": "0.6576",
                "confirmed_trial_rate": "0",
                "confirmed_ci_low": "0",
                "confirmed_ci_high": "0.6576",
                "family_macro_attack_success": "0",
                "family_macro_end_to_end_attack": "0",
                "family_macro_confirmed": "0",
                "family_macro_risk": "0",
            }
        ],
    )
    _write_csv(
        no_trigger_dir / "harness_macro.csv",
        [
            {
                "case_set": "core",
                "run_kind": "control",
                "control_type": "no_trigger_control",
                "harness": "claude",
                "families": "2",
                "complete_families": "2",
                "completed_trials": "2",
                "asr_eligible_trials": "2",
                "n_minus_1_trials": "0",
                "accounted_terminal_trials": "2",
                "protocol_denominator_trials": "2",
                "attack_success_trials": "0",
                "timeout_trials": "0",
                "protocol_completion_trial_rate": "1",
                "model_nonconformance_trial_rate": "0",
                "attack_success_trial_rate": "0",
                "end_to_end_attack_trial_rate": "0",
                "attack_success_ci_low": "0",
                "attack_success_ci_high": "0.6576",
                "confirmed_trial_rate": "0",
                "confirmed_ci_low": "0",
                "confirmed_ci_high": "0.6576",
                "family_macro_attack_success": "0",
                "family_macro_end_to_end_attack": "0",
                "family_macro_confirmed": "0",
                "family_macro_risk": "0",
            }
        ],
    )

    tables = export_paper_tables.build_tables(attack_dir, [control_dir, no_trigger_dir])

    assert tables["attack_label"] == "paper_core"
    assert tables["control_label"] == "paper_controls, paper_no_trigger"
    assert tables["main"]["rows"][0] == [
        "claude",
        "2/2",
        "6",
        "5",
        "2",
        "8",
        "7",
        "3",
        "71.4%",
        "28.6%",
        "60.0% [20.0%-80.0%]",
        "42.9%",
        "45.0%",
        "30.0%",
        "25.0%",
        "42.5",
        "1",
    ]
    assert tables["family"]["rows"][0][2] == "F2.01"
    assert len(tables["family"]["rows"]) == 2
    assert tables["control"]["rows"][0] == [
        "clean_control",
        "claude",
        "2/2",
        "2",
        "1",
        "1",
        "3",
        "2",
        "0",
        "50.0%",
        "50.0%",
        "0.0%",
        "0.0%",
        "0.0%",
        "0",
    ]
    assert tables["control"]["rows"][1][0] == "no_trigger_control"
    assert tables["schema_version"] == 2
    assert tables["metric_contract"]["protocol_completion_rate"] == "S/D"
    assert tables["metric_contract"]["end_to_end_attack_rate"] == "A/D"
    assert "ASR Eligible (S)" in tables["main"]["headers"]
    assert "Coverage Accounted (T)" in tables["main"]["headers"]
    assert "Protocol Denominator (D)" in tables["main"]["headers"]


def test_export_paper_tables_fails_closed_for_legacy_protocol_columns():
    rows = export_paper_tables.main_results_rows(
        [
            {
                "run_kind": "attack",
                "harness": "claude",
                "families": "1",
                "complete_families": "1",
                "completed_trials": "3",
                "attack_success_trial_rate": "0",
            }
        ]
    )

    assert rows[0][2] == "3"
    assert rows[0][3:10] == ["n/a"] * 7
    assert rows[0][10] == "n/a"
    assert rows[0][11] == "n/a"


def test_export_tables_zero_denominators_render_na_in_markdown_and_latex():
    rows = export_paper_tables.main_results_rows(
        [
            {
                "run_kind": "attack",
                "harness": "claude",
                "families": "0",
                "complete_families": "0",
                "completed_trials": "0",
                "asr_eligible_trials": "0",
                "n_minus_1_trials": "0",
                "accounted_terminal_trials": "0",
                "protocol_denominator_trials": "0",
                "attack_success_trials": "0",
                "timeout_trials": "0",
            }
        ]
    )
    assert rows[0][8:12] == ["n/a"] * 4
    headers = [f"H{i}" for i in range(len(rows[0]))]
    tables = {
        "generated_at": "2026-07-17T00:00:00",
        "attack_label": "zero",
        "control_label": "",
        "main": {"headers": headers, "rows": rows},
        "family": {"headers": [], "rows": []},
        "control": {"headers": [], "rows": []},
    }
    markdown = export_paper_tables.render_markdown(tables)
    tex = export_paper_tables.latex_table(headers, rows, "zero", "tab:zero")
    assert "n/a" in markdown
    assert "n/a" in tex
    assert "None" not in markdown
    assert "None" not in tex


def test_export_tables_reject_inconsistent_t_or_d():
    base = {
        "completed_trials": "3",
        "asr_eligible_trials": "2",
        "n_minus_1_trials": "1",
        "accounted_terminal_trials": "4",
        "protocol_denominator_trials": "3",
        "attack_success_trials": "1",
    }
    with pytest.raises(ValueError, match="T must equal"):
        export_paper_tables.protocol_measurement(
            {**base, "accounted_terminal_trials": "3"},
            context="test",
        )
    with pytest.raises(ValueError, match="D must equal"):
        export_paper_tables.protocol_measurement(
            {**base, "protocol_denominator_trials": "4"},
            context="test",
        )


def test_write_paper_tables_outputs_markdown_and_latex(tmp_path: Path):
    tables = {
        "generated_at": "2026-06-25T00:00:00",
        "attack_label": "paper_core",
        "control_label": "",
        "main": {"headers": ["Harness", "ASR"], "rows": [["kimi_k2.6", "10.0%"]]},
        "family": {"headers": ["Family", "ASR"], "rows": [["F2.01", "10.0%"]]},
        "control": {"headers": ["Control", "Rate"], "rows": []},
    }

    paths = export_paper_tables.write_tables(tables, tmp_path / "out")

    assert paths["markdown"].exists()
    assert paths["main_latex"].exists()
    assert paths["control_latex"].read_text(encoding="utf-8") == "% No control report was provided.\n"
    assert r"kimi\_k2.6" in paths["main_latex"].read_text(encoding="utf-8")
