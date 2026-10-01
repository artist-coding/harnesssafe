import json
from pathlib import Path

from infra import generate_full_suite_eligibility_appendix as eligibility


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _case(
    case_dir: str,
    *,
    suite: str,
    family: str,
    case_set: str,
    oracle_strength: str = "hard_trace_oracle",
    reporting_track: str = "",
    main: bool = False,
    excluded: bool = False,
    violation_status: str = "exact",
    representative: bool = False,
    runtime_metric_eligible: bool | None = None,
) -> dict:
    if not reporting_track:
        reporting_track = {
            "core": "core_benchmark",
            "extended": "extended_benchmark",
            "exploratory": "exploratory_case_study",
        }[case_set]
    case = {
        "suite": suite,
        "canonical_suite": suite,
        "case_dir": case_dir,
        "paper_family": family,
        "case_sets": [case_set, "all"],
        "reporting_track": reporting_track,
        "oracle_strength": oracle_strength,
        "violation_oracle_status": violation_status,
        "paper_priority": "P0" if main else "P2",
        "main_table_eligible": main,
        "attack_success_metric_excluded": excluded,
        "case_study_representative": representative,
        "frame": {
            "entry": "entry",
            "carrier": "carrier",
            "boundary": "boundary",
            "trigger": "trigger",
            "violation": "violation",
            "recovery": "recovery",
        },
        "oracles": ["O_local_marker"],
        "hard_violation_oracles": ["O_local_marker"] if oracle_strength == "hard_trace_oracle" else [],
        "control_suite": [],
    }
    if runtime_metric_eligible is not None:
        case["boundary_runtime_contract"] = {
            "status": "diagnostic_pending_session_provenance",
            "metric_eligible": runtime_metric_eligible,
            "metric_exclusion_reason": "Hard session provenance is not implemented.",
        }
    return case


def test_full_suite_eligibility_appendix_summarizes_case_sets(tmp_path: Path):
    root = tmp_path
    lock = {
        "schema_version": 2,
        "suite_content_sha256": "full-content-abc123",
        "case_set_sha256": "legacy-membership-abc123",
        "attestation_sha256": "attestation-abc123",
        "git_commit_sha": "0123456789abcdef",
        "git_worktree_dirty": False,
        "cases": [
            _case(
                "active/F2/core/case_a",
                suite="v2_skill_runtime",
                family="F2.01",
                case_set="core",
                main=True,
            ),
            _case(
                "active/F1/soft/case_b",
                suite="F1_memory_runtime",
                family="F1E.01",
                case_set="extended",
                oracle_strength="soft_semantic_oracle",
            ),
            _case(
                "active/F3/propagation/case_c",
                suite="v2_tool_mcp_runtime",
                family="F3.02",
                case_set="extended",
                oracle_strength="propagation_only",
                excluded=True,
                violation_status="",
            ),
            _case(
                "active/F2/resource/case_d",
                suite="v2_skill_runtime",
                family="F2.18",
                case_set="extended",
                excluded=True,
                violation_status="missing_analyzer",
            ),
            _case(
                "active/T3/subagent/case_e",
                suite="T3_subagent_poisoning",
                family="SA.01",
                case_set="exploratory",
                representative=True,
            ),
            _case(
                "active/T3/compaction/case_f",
                suite="T3_compaction_resume_poisoning",
                family="CR.01",
                case_set="exploratory",
                excluded=True,
                runtime_metric_eligible=False,
            ),
        ],
    }
    _write(root / "docs/generated_artifacts/paper_suite_lock.json", json.dumps(lock))

    report = eligibility.build_report(root=root, suite_lock=Path("docs/generated_artifacts/paper_suite_lock.json"))
    markdown = eligibility.render_markdown(report)

    assert report["suite_lock_digest"] == "full-content-abc123"
    assert report["suite_lock_attestation_sha256"] == "attestation-abc123"
    assert report["suite_lock_git_commit_sha"] == "0123456789abcdef"
    assert report["suite_lock_git_worktree_dirty"] is False
    assert report["summary"]["active_cases"] == 6
    assert report["summary"]["main_asr_cases"] == 1
    assert report["summary"]["diagnostic_cases"] == 5
    assert report["summary"]["runnable_matrix_rows"] == 42
    assert report["summary"]["formal_main_table_rows"] == 7
    assert report["summary"]["diagnostic_matrix_rows"] == 35
    assert report["summary"]["extended_cases"] == 3
    assert report["summary"]["exploratory_cases"] == 2
    assert report["summary"]["attack_success_metric_excluded_cases"] == 3
    assert "planned/design-time case scope" in report["summary"]["claim_boundary"]
    assert "Realized conditional ASR uses only ASR-eligible N0-N5b scored attack rows" in report["summary"]["claim_boundary"]
    core_row = next(row for row in report["case_sets"] if row["case_set"] == "core")
    extended_row = next(row for row in report["case_sets"] if row["case_set"] == "extended")
    assert core_row["main_asr_cases"] == 1
    assert extended_row["soft_semantic_oracle"] == 1
    assert extended_row["propagation_only"] == 1
    assert any("semantic/judgment-based" in row["eligibility_reason"] for row in report["cases"])
    assert any("resource/limit raw analyzer signal" in row["eligibility_reason"] for row in report["cases"])
    assert any("carrier propagation/persistence" in row["eligibility_reason"] for row in report["cases"])
    assert any("hard session provenance" in row["eligibility_reason"].lower() for row in report["cases"])
    assert "# Full-Suite Eligibility Appendix" in markdown
    assert "suite_lock_attestation: `attestation-abc" in markdown
    assert "full runnable coverage (6 cases; 42 rows)" in markdown
    assert "formal main table (1 cases; 7 rows)" in markdown
    assert "diagnostics (5 cases; 35 rows)" in markdown
    assert "## Per-Case Eligibility Table" in markdown
    assert "| `active/F2/core/case_a` | v2_skill_runtime | F2.01 | core | hard_trace_oracle | `true` | `false` |" in markdown


def test_full_suite_eligibility_cli_writes_outputs(tmp_path: Path, monkeypatch):
    root = tmp_path
    lock = {
        "schema_version": 1,
        "case_set_sha256": "abc123",
        "cases": [
            _case(
                "active/F2/core/case_a",
                suite="v2_skill_runtime",
                family="F2.01",
                case_set="core",
                main=True,
            )
        ],
    }
    _write(root / "docs/generated_artifacts/paper_suite_lock.json", json.dumps(lock))
    monkeypatch.setattr(eligibility, "ROOT", root)
    monkeypatch.setattr(
        "sys.argv",
        [
            "generate_full_suite_eligibility_appendix.py",
            "--suite-lock",
            "docs/generated_artifacts/paper_suite_lock.json",
            "--out-json",
            "docs/eligibility.json",
            "--out-md",
            "docs/eligibility.md",
        ],
    )

    assert eligibility.main() == 0
    assert (root / "docs/eligibility.json").is_file()
    assert "Full-Suite Eligibility Appendix" in (root / "docs/eligibility.md").read_text(encoding="utf-8")


def test_full_suite_eligibility_uses_null_fraction_for_empty_case_sets(
    tmp_path: Path,
):
    root = tmp_path
    lock = {
        "schema_version": 2,
        "suite_content_sha256": "empty-suite",
        "cases": [],
    }
    _write(root / "docs/generated_artifacts/paper_suite_lock.json", json.dumps(lock))

    report = eligibility.build_report(
        root=root,
        suite_lock=Path("docs/generated_artifacts/paper_suite_lock.json"),
    )
    markdown = eligibility.render_markdown(report)

    assert all(row["main_asr_fraction"] is None for row in report["case_sets"])
    assert "| core | 0 | 0 | n/a |" in markdown
    assert "0.0%" not in markdown
