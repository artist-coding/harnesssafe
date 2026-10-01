import json
from pathlib import Path

from infra import estimate_paper_run_budget, plan_paper_experiment_matrix


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _fixture(root: Path) -> Path:
    case_dir = "active/F2_skill_runtime/F2.01_family/case_a"
    _write_json(
        root / "runs/manifest.json",
        {"suites": {"fixture": {"status": "active", "cases": [{"case_dir": case_dir}]}}},
    )
    _write_json(
        root / "runs" / case_dir / "case_meta.json",
        {
            "case_id": "case_a",
            "main_table_eligible": True,
            "reporting_track": "core_benchmark",
            "paper_priority": "P0",
            "control_suite": [
                {"control_type": "clean_control"},
                {"control_type": "no_trigger_control"},
            ],
        },
    )
    plan = plan_paper_experiment_matrix.build_plan(
        root=root,
        case_set="core",
        harnesses=["claude", "codex"],
        attack_trials=1,
        control_trials=1,
        control_types=["clean_control", "no_trigger_control"],
        timeout_sec=100,
    )
    path = root / "docs/generated_artifacts/paper_experiment_matrix_plan.json"
    _write_json(path, plan)
    return path


def _summary_row(run_id: str, *, run_kind: str, harness: str, control_type: str = "") -> dict:
    return {
        "run_id": run_id,
        "run_kind": run_kind,
        "harness": harness,
        "control_type": control_type,
        "suite": "v2_skill_runtime",
        "paper_family": "F2.01",
        "case_dir": "active/F2_skill_runtime/F2.01_family/case_a",
    }


def test_estimate_paper_run_budget_uses_observed_start_deltas(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _fixture(root)
    attack_report = root / "runs/_reports/attack"
    control_report = root / "runs/_reports/control"
    _write_json(
        attack_report / "summary.json",
        {
            "rows": [
                _summary_row("260101_000000_claude_a", run_kind="attack", harness="claude"),
                _summary_row("260101_000030_claude_b", run_kind="attack", harness="claude"),
                _summary_row("260101_000050_claude_c", run_kind="attack", harness="claude"),
            ]
        },
    )
    _write_json(
        control_report / "summary.json",
        {
            "rows": [
                _summary_row(
                    "260101_010000_claude_clean_a",
                    run_kind="control",
                    harness="claude",
                    control_type="clean_control",
                ),
                _summary_row(
                    "260101_010020_claude_clean_b",
                    run_kind="control",
                    harness="claude",
                    control_type="clean_control",
                ),
            ]
        },
    )

    budget = estimate_paper_run_budget.build_budget(
        root=root,
        plan_path=plan_path,
        sample_report_dirs=[attack_report, control_report],
        timeout_sec=100,
    )

    assert budget["summary"]["expected_rows"] == 6
    assert budget["summary"]["missing_rows"] == 6
    assert budget["summary"]["observed_runtime_samples"] == 3
    assert budget["observed_runtime"]["by_kind_harness"]["attack:claude"]["p50_sec"] == 25.0
    assert budget["estimated_missing"]["source_counts"]["kind_harness:attack:claude"] == 1
    assert budget["estimated_missing"]["source_counts"]["kind:attack"] == 1
    assert budget["estimated_missing"]["source_counts"]["kind:control"] == 2
    assert {batch["batch_id"] for batch in budget["coalesced_batches"]} == {
        "attack_claude",
        "attack_codex",
        "control_claude_all_missing_types",
        "control_codex_all_missing_types",
    }


def test_estimate_paper_run_budget_markdown_documents_caveats(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _fixture(root)
    report_dir = root / "runs/_reports/attack"
    _write_json(
        report_dir / "summary.json",
        {
            "rows": [
                _summary_row("260101_000000_claude_a", run_kind="attack", harness="claude"),
                _summary_row("260101_000030_claude_b", run_kind="attack", harness="claude"),
            ]
        },
    )
    budget = estimate_paper_run_budget.build_budget(
        root=root,
        plan_path=plan_path,
        sample_report_dirs=[report_dir],
        timeout_sec=100,
    )

    markdown = estimate_paper_run_budget.render_markdown(budget)

    assert "# Paper Run Budget Estimate" in markdown
    assert "Runtime samples are inferred from adjacent run_id start timestamps" in markdown
    assert "Estimates are planning aids" in markdown
    assert "run_paper_baseline_matrix.ps1" in markdown
