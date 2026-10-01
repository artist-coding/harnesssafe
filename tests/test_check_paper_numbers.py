import json
from pathlib import Path

from infra import check_paper_numbers


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: dict) -> None:
    _write(path, json.dumps(payload, indent=2))


def _attack_rows() -> list[dict]:
    return [
        {
            "case_dir": "case_a",
            "paper_family": "F2.01",
            "attack_success": True,
            "confirmed_compromise": True,
            "timed_out": False,
            "stage_timeouts": 0,
            "progress_node": "N5b",
            "risk_score": 80,
        },
        {
            "case_dir": "case_b",
            "paper_family": "F3.04",
            "attack_success": True,
            "confirmed_compromise": False,
            "timed_out": False,
            "stage_timeouts": 0,
            "progress_node": "N5a",
            "risk_score": 60,
        },
        {
            "case_dir": "case_b",
            "paper_family": "F3.04",
            "attack_success": False,
            "confirmed_compromise": False,
            "timed_out": True,
            "stage_timeouts": 0,
            "progress_node": "N1",
            "risk_score": 20,
        },
    ]


def _control_rows() -> list[dict]:
    return [
        {
            "case_dir": "case_a",
            "paper_family": "F2.01",
            "attack_success": False,
            "confirmed_compromise": False,
            "timed_out": False,
            "stage_timeouts": 0,
            "progress_node": "N0",
            "risk_score": 10,
        },
        {
            "case_dir": "case_b",
            "paper_family": "F3.04",
            "attack_success": False,
            "confirmed_compromise": False,
            "timed_out": False,
            "stage_timeouts": 1,
            "progress_node": "N1",
            "risk_score": 20,
        },
    ]


def _write_fixture(root: Path) -> tuple[Path, Path, Path, Path]:
    attack = root / "reports/attack"
    control = root / "reports/control"
    tables = root / "reports/attack/paper_tables"
    evidence = root / "reports/attack/case_study_evidence"
    _write_json(attack / "summary.json", {"rows": _attack_rows()})
    _write_json(control / "summary.json", {"rows": _control_rows()})
    _write_json(
        tables / "paper_tables.json",
        {
            "main": {
                "headers": [
                    "Harness",
                    "Families",
                    "Trials",
                    "Pooled ASR [95% CI]",
                    "Family Macro ASR",
                    "Family Macro Confirmed",
                    "Risk",
                    "Timeouts",
                ],
                "rows": [["claude", "2/2", "3", "66.7% [20.8%-93.9%]", "50.0%", "25.0%", "53.3333", "1"]],
            }
        },
    )
    _write_json(
        evidence / "case_study_evidence.json",
        {"ok": True, "case_count": 2, "attack_row_count": 2, "recommended_main_paper_count": 1},
    )

    _write(
        root / "docs/paper_draft.md",
        "\n".join(
            [
                "The matrix contains 3 attack rows and 2 matched control rows.",
                "It observes 2/3 attack successes and 1/3 confirmed compromises.",
                "The pooled ASR of 66.7% has Wilson interval [20.8%, 93.9%].",
                "The family macro ASR 50.0%, family macro confirmed 25.0%, and mean risk 53.3 are reported.",
                "The control matrix completes 2/2 rows with zero attack success and zero confirmed compromise.",
                "The current pack contains 2 unique successful cases represented by 2 attack rows.",
            ]
        ),
    )
    _write(
        root / "docs/paper_artifact_evaluation_readme.md",
        "The gate reports 3/3 attack rows and 2/2 control rows with zero `attack_success` and zero confirmed rows.\n",
    )
    return attack, control, tables, evidence


def test_check_paper_numbers_accepts_current_fixture(tmp_path: Path):
    attack, control, tables, evidence = _write_fixture(tmp_path)

    report = check_paper_numbers.build_number_report(
        root=tmp_path,
        attack_dirs=[attack],
        control_dirs=[control],
        table_dir=tables,
        case_evidence_dir=evidence,
    )

    assert report["ok"] is True
    assert report["issues"] == []
    assert report["numbers"]["attack"]["attack_success"] == 2
    assert report["numbers"]["case_evidence"]["attack_row_count"] == 2


def test_check_paper_numbers_rejects_stale_doc_number(tmp_path: Path):
    attack, control, tables, evidence = _write_fixture(tmp_path)
    stale = (tmp_path / "docs/paper_draft.md").read_text(encoding="utf-8").replace(
        "2/3 attack successes",
        "1/3 attack successes",
    )
    _write(tmp_path / "docs/paper_draft.md", stale)

    report = check_paper_numbers.build_number_report(
        root=tmp_path,
        attack_dirs=[attack],
        control_dirs=[control],
        table_dir=tables,
        case_evidence_dir=evidence,
    )

    assert report["ok"] is False
    assert any(item["detail"].get("phrase") == "2/3 attack successes" for item in report["issues"])


def test_number_check_keeps_n_minus_one_out_of_ladder_and_asr():
    rows = [
        {
            "paper_family": "F2.01",
            "case_dir": "case_a",
            "has_oracle": True,
            "run_valid": True,
            "result_class": "scored",
            "display_node": "",
            "model_protocol_status": "completed",
            "terminal_outcome": True,
            "retry_eligible": False,
            "asr_eligible": True,
            "attack_success_metric_excluded": False,
            "attack_success": True,
            "confirmed_compromise": False,
            "progress_node": "N5a",
            "risk_score": 60,
        },
        {
            "paper_family": "F2.01",
            "case_dir": "case_b",
            "has_run": True,
            "has_oracle": True,
            "run_validity_source": "run_validity",
            "run_validity_schema_version": 2,
            "run_valid": False,
            "result_class": "model_protocol_deviation",
            "display_node": "N-1",
            "model_protocol_status": "deviated",
            "model_protocol_failure_kind": "required_artifact_path_mismatch",
            "model_protocol_failure_stage": "boundary",
            "model_protocol_evidence": "[{\"attribution\":\"model_tool_argument\",\"failure_kind\":\"required_artifact_path_mismatch\",\"stage_name\":\"boundary\",\"stage_index\":1,\"expected_path\":\"expected.md\",\"observed_path\":\"expectd.md\",\"observed_path_normalized\":\"expectd.md\",\"filename_edit_distance\":1,\"tool_name\":\"Write\",\"tool_use_id\":\"tool-1\",\"tool_result_success\":true}]",
            "terminal_outcome": True,
            "retry_eligible": False,
            "asr_eligible": False,
            "formal_asr_eligible": False,
            "attack_success": False,
            "confirmed_compromise": False,
            # Diagnostic progress must not enter the N0-N5b distribution.
            "progress_node": "N5b",
            "risk_score": 100,
        },
        {
            "paper_family": "F2.01",
            "case_dir": "case_malformed",
            "has_oracle": True,
            "run_valid": True,
            "result_class": "scored",
            "display_node": "N-1",
            "model_protocol_status": "deviated",
            "terminal_outcome": False,
            "retry_eligible": True,
            "asr_eligible": True,
            "attack_success_metric_excluded": False,
            "attack_success": True,
            "progress_node": "N5b",
            "risk_score": 100,
        },
    ]

    summary = check_paper_numbers.summarize_rows(rows)
    assert summary["scored_rows"] == 1
    assert summary["n_minus_1_rows"] == 1
    assert summary["accounted_terminal_rows"] == 2
    assert summary["protocol_denominator_rows"] == 2
    assert summary["invalid_rows"] == 1
    assert summary["asr_eligible_rows"] == 1
    assert summary["conditional_asr"] == 1.0
    assert summary["end_to_end_attack_rate"] == 0.5
    assert summary["node_counts"]["N5a"] == 1
    assert summary["node_counts"]["N5b"] == 0

    table = {
        "Scored Families": "1/1",
        "All Scored": "1",
        "ASR Eligible (S)": "1",
        "N-1 (M)": "1",
        "Coverage Accounted (T)": "2",
        "Protocol Denominator (D)": "2",
        "Attack Success (A)": "1",
        "Protocol Completion (S/D)": "50.0%",
        "Model Nonconformance (M/D)": "50.0%",
        "Conditional ASR (A/S) [95% CI]": "100.0% [20.7%-100.0%]",
        "End-to-End Attack Rate (A/D)": "50.0%",
        "Timeouts": "0",
    }
    assert check_paper_numbers.check_table_consistency(
        table=table, attack=summary
    ) == []


def test_percentage_renders_zero_denominator_as_unavailable():
    assert check_paper_numbers.percentage(0, 0) == "n/a"
    assert check_paper_numbers.percentage(0, 1) == "0.0%"


def test_zero_eligible_rows_require_unavailable_risk():
    summary = check_paper_numbers.summarize_rows(
        [
            {
                "has_oracle": True,
                "run_valid": True,
                "result_class": "scored",
                "display_node": "N5b",
                "model_protocol_status": "completed",
                "terminal_outcome": True,
                "retry_eligible": False,
                "asr_eligible": False,
                "attack_success_metric_excluded": True,
                "attack_success": False,
                "confirmed_compromise": False,
                "progress_node": "N5b",
                "risk_score": 100,
            }
        ]
    )
    summary["macro_risk"] = None
    assert summary["asr_eligible_rows"] == 0
    assert summary["mean_risk"] is None

    table = {
        "Scored Families": "0/0",
        "All Scored": "1",
        "ASR Eligible (S)": "0",
        "N-1 (M)": "0",
        "Coverage Accounted (T)": "1",
        "Protocol Denominator (D)": "0",
        "Attack Success (A)": "0",
        "Protocol Completion (S/D)": "n/a",
        "Model Nonconformance (M/D)": "n/a",
        "Conditional ASR (A/S) [95% CI]": "n/a",
        "End-to-End Attack Rate (A/D)": "n/a",
        "Risk": "n/a",
        "Timeouts": "0",
    }
    assert check_paper_numbers.check_table_consistency(table=table, attack=summary) == []
    table["Risk"] = "0.0"
    issues = check_paper_numbers.check_table_consistency(table=table, attack=summary)
    assert any("risk must be n/a" in item["message"] for item in issues)
    assert check_paper_numbers.rounded_one_or_na(None) == "n/a"


def test_number_summary_keeps_ineligible_scored_rows_in_coverage_only():
    eligible = {
        "has_oracle": True,
        "run_valid": True,
        "result_class": "scored",
        "display_node": "N1",
        "model_protocol_status": "completed",
        "terminal_outcome": True,
        "retry_eligible": False,
        "asr_eligible": True,
        "attack_success_metric_excluded": False,
        "attack_success": False,
        "confirmed_compromise": False,
        "progress_node": "N1",
        "risk_score": 20,
    }
    excluded = {
        **eligible,
        "asr_eligible": False,
        "attack_success_metric_excluded": True,
        "attack_success": True,
        "confirmed_compromise": True,
        "progress_node": "N5b",
        "risk_score": 100,
    }

    summary = check_paper_numbers.summarize_rows([eligible, excluded])

    assert summary["scored_rows"] == 2
    assert summary["accounted_terminal_rows"] == 2
    assert summary["asr_eligible_rows"] == 1
    assert summary["protocol_denominator_rows"] == 1
    assert summary["attack_success"] == 0
    assert summary["factual_attack_success"] == 1
    assert summary["node_counts"]["N1"] == 1
    assert summary["node_counts"]["N5b"] == 0
    assert summary["factual_node_counts"]["N5b"] == 1
    assert summary["mean_risk"] == 20
    assert summary["factual_mean_risk"] == 60
