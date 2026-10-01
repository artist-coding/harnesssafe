import json
from pathlib import Path

from infra import plan_external_validity_calibration as plan


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _case(
    case_dir: str,
    *,
    suite: str,
    family: str,
    case_set: str = "extended",
    oracle_strength: str = "hard_trace_oracle",
    excluded: bool = False,
    runtime_metric_eligible: bool | None = None,
) -> dict:
    case = {
        "suite": suite,
        "canonical_suite": suite,
        "case_dir": case_dir,
        "paper_family": family,
        "case_sets": [case_set, "all"],
        "reporting_track": f"{case_set}_benchmark",
        "oracle_strength": oracle_strength,
        "violation_oracle_status": "exact",
        "paper_priority": "P2",
        "main_table_eligible": oracle_strength == "hard_trace_oracle" and not excluded,
        "attack_success_metric_excluded": excluded,
        "case_study_representative": False,
        "case_id": Path(case_dir).name,
        "variant": "variant",
        "frame": {
            "entry": "entry",
            "carrier": "carrier",
            "boundary": "boundary",
            "trigger": "trigger",
            "violation": "violation",
        },
        "hard_violation_oracles": ["O_local_marker"] if oracle_strength == "hard_trace_oracle" else [],
        "control_suite": [{"control_type": item} for item in plan.CONTROL_TYPES],
    }
    if runtime_metric_eligible is not None:
        case["boundary_runtime_contract"] = {
            "status": "diagnostic_pending_session_provenance",
            "metric_eligible": runtime_metric_eligible,
        }
    return case


def test_external_validity_plan_selects_extended_hard_cases_by_suite_and_family(tmp_path: Path):
    root = tmp_path
    lock = {
        "schema_version": 1,
        "active_case_count": 12,
        "case_set_sha256": "abc123",
        "cases": [
            _case("active/F2/f01/case_a", suite="v2_skill_runtime", family="F2.01"),
            _case("active/F2/f01/case_b", suite="v2_skill_runtime", family="F2.01"),
            _case("active/F2/f02/case_c", suite="v2_skill_runtime", family="F2.02"),
            _case("active/F2/f03/case_d", suite="v2_skill_runtime", family="F2.03"),
            _case("active/F3/f01/case_e", suite="v2_tool_mcp_runtime", family="F3.01"),
            _case("active/F3/f02/case_f", suite="v2_tool_mcp_runtime", family="F3.02"),
            _case("active/F3/f02/case_g", suite="v2_tool_mcp_runtime", family="F3.02"),
            _case("active/F3/f03/case_h", suite="v2_tool_mcp_runtime", family="F3.03"),
            _case("active/F1/soft/case_i", suite="F1_memory_runtime", family="F1.01", oracle_strength="soft_semantic_oracle"),
            _case(
                "active/F2/excluded/case_j",
                suite="v2_skill_runtime",
                family="F2.99",
                excluded=True,
                runtime_metric_eligible=False,
            ),
            _case("active/F2/core/case_k", suite="v2_skill_runtime", family="F2.00", case_set="core"),
            _case("active/T3/exploratory/case_l", suite="T3_subagent_poisoning", family="T3.01", case_set="exploratory"),
        ],
    }
    _write(root / "docs/generated_artifacts/paper_suite_lock.json", json.dumps(lock))

    report = plan.build_report(
        root=root,
        suite_lock=Path("docs/generated_artifacts/paper_suite_lock.json"),
        per_suite=2,
        run_label="ev",
    )
    markdown = plan.render_markdown(report)

    assert report["summary"]["active_cases"] == 12
    assert report["summary"]["formal_cases"] == 10
    assert report["summary"]["diagnostic_cases"] == 2
    assert report["summary"]["runnable_matrix_rows"] == 84
    assert report["summary"]["formal_main_table_rows"] == 70
    assert report["summary"]["diagnostic_matrix_rows"] == 14
    assert report["summary"]["candidate_cases"] == 8
    assert report["summary"]["selected_cases"] == 4
    assert report["summary"]["selected_by_suite"] == {
        "v2_skill_runtime": 2,
        "v2_tool_mcp_runtime": 2,
    }
    selected_dirs = [row["case_dir"] for row in report["selected_cases"]]
    assert selected_dirs == [
        "active/F2/f01/case_a",
        "active/F2/f02/case_c",
        "active/F3/f01/case_e",
        "active/F3/f02/case_f",
    ]
    assert "10-case metric-eligible subset" in report["summary"]["main_asr_boundary"]
    assert "12-case runnable hard-oracle coverage" in report["summary"]["main_asr_boundary"]
    assert "does not run benchmark cases" in report["selection_policy"]["execution_policy"]
    assert "run_harness_case.ps1" in report["analysis_protocol"]["runner_policy"]
    assert "do not change membership of the 10-case planned metric-eligible scope" in report["analysis_protocol"]["denominator_policy"]
    assert "12-case runnable coverage" in report["analysis_protocol"]["denominator_policy"]
    assert "check_paper_results.py" in report["analysis_protocol"]["completion_gate"]
    assert ".\\infra\\run_harness_case.ps1" in report["commands"]["attack_commands_powershell"]
    assert "-CaseDirFilter $externalCases" in report["commands"]["control_commands_powershell"]
    assert "# External-Validity Calibration Plan" in markdown
    assert "does not replace the complete main matrix" in markdown
    assert "## Appendix Analysis Protocol" in markdown
    assert "F3 multi-stage metadata" in markdown
    assert "`active/F2/f01/case_a`" in markdown


def test_external_validity_cli_writes_outputs(tmp_path: Path, monkeypatch):
    root = tmp_path
    lock = {
        "schema_version": 1,
        "active_case_count": 1,
        "case_set_sha256": "abc123",
        "cases": [
            _case("active/F2/f01/case_a", suite="v2_skill_runtime", family="F2.01"),
        ],
    }
    _write(root / "docs/generated_artifacts/paper_suite_lock.json", json.dumps(lock))
    monkeypatch.setattr(plan, "ROOT", root)
    monkeypatch.setattr(
        "sys.argv",
        [
            "plan_external_validity_calibration.py",
            "--suite-lock",
            "docs/generated_artifacts/paper_suite_lock.json",
            "--out-json",
            "docs/external.json",
            "--out-md",
            "docs/external.md",
            "--per-suite",
            "1",
            "--run-label",
            "ev",
        ],
    )

    assert plan.main() == 0
    assert (root / "docs/external.json").is_file()
    assert "External-Validity Calibration Plan" in (root / "docs/external.md").read_text(encoding="utf-8")
