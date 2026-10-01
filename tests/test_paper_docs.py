from pathlib import Path
import subprocess


CURRENT_ENTRY_DOCS = [
    Path("README.md"),
    Path("RUNBOOK.md"),
    Path("AGENTS.md"),
    Path("docs/README.md"),
    Path("docs/idea_v2.md"),
    Path("docs/evaluation_metrics_reference.md"),
    Path("docs/run_and_evaluation_contract.md"),
    Path("docs/formal_experiment_execution_policy.md"),
    Path("docs/paper_experiment_protocol.md"),
    Path("docs/paper_current_status.md"),
    Path("docs/paper_artifact_evaluation_readme.md"),
    Path("docs/paper_draft.md"),
]

REMOVED_REDUNDANT_DOCS = [
    Path("docs/paper_submission_manuscript.md"),
    Path("docs/paper_manuscript_outline.md"),
    Path("docs/paper_outline_zh.md"),
    Path("docs/paper_related_work.md"),
    Path("docs/paper_results_claude_core.md"),
    Path("docs/paper_results_claude_kimi_358_reaudit.md"),
    Path("docs/benchmark_card.md"),
    Path("docs/paper_statistical_analysis.md"),
    Path("docs/active_task_catalog_and_scoring.md"),
    Path("docs/task_expansion_matrix.md"),
]


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def test_current_entry_docs_exist_and_use_manifest_driven_328_scope():
    for path in CURRENT_ENTRY_DOCS:
        assert path.is_file(), path

    protocol = _text(Path("docs/paper_experiment_protocol.md"))
    assert "7 个 active suites" in protocol
    assert "328 个 cases" in protocol
    assert "328 x 1 = 328" in protocol
    assert "1 次" in protocol and "attack trial" in protocol
    assert "Evaluation Record v3" in protocol
    assert "不需要重新审查全部 328 cases" in protocol
    assert "2,296" not in protocol


def test_normative_docs_use_v3_and_treat_source_schema_as_audit_only():
    for path in [
        Path("docs/evaluation_record_schema_v3.md"),
        Path("docs/evaluation_metrics_reference.md"),
        Path("docs/run_and_evaluation_contract.md"),
        Path("docs/paper_experiment_protocol.md"),
        Path("AGENTS.md"),
        Path("README.md"),
    ]:
        text = _text(path)
        assert "Evaluation Record v3" in text, path
        assert "schema v1/v2" in text, path
        assert "审计" in text or "audit" in text.lower(), path


def test_core_is_documented_only_as_all_scope_alias():
    for path in CURRENT_ENTRY_DOCS:
        text = _text(path)
        if "CaseSet=core" in text or "-CaseSet core" in text:
            assert "alias" in text.lower() or "同义别名" in text or "兼容别名" in text, path


def test_formal_scope_is_hard_oracle_only():
    for path in [
        Path("AGENTS.md"),
        Path("docs/idea_v2.md"),
        Path("docs/paper_experiment_protocol.md"),
        Path("docs/paper_current_status.md"),
        Path("docs/paper_artifact_evaluation_readme.md"),
    ]:
        text = _text(path)
        assert "hard" in text.lower(), path
        assert "328" in text, path


def test_redundant_and_historical_writing_docs_are_removed():
    for path in REMOVED_REDUNDANT_DOCS:
        assert not path.exists(), path


def test_f3_formal_docs_use_unified_runner():
    for path in [Path("CLAUDE.md"), Path("RUNBOOK.md"), Path("docs/paper_experiment_protocol.md")]:
        text = _text(path)
        assert "run_harness_case.ps1" in text, path
        if "run_mcp_multiphase.ps1" in text:
            assert "历史" in text or "historical" in text.lower(), path


def test_operator_docs_explain_terminal_nminus1_without_extending_progress_ladder():
    for path in [Path("CLAUDE.md"), Path("RUNBOOK.md"), Path("runs/README.md")]:
        text = _text(path)
        assert "N-1" in text, path
        assert "model_protocol_deviation" in text, path
        assert "non-retryable" in text or "不可重试" in text, path
        assert "N0" in text and "N5b" in text, path


def test_current_docs_do_not_advertise_removed_case_trees():
    for path in [Path("AGENTS.md"), Path("README.md"), Path("runs/README.md"), Path("docs/idea_v2.md")]:
        text = _text(path)
        assert "runs/reference/v2_skill_runtime_direct/" not in text, path
        assert "runs/archive/legacy_v2_memory_evolution/" not in text, path
        assert "runs/archive/prototype_memory2skill/" not in text, path


def test_curated_f2_composition_is_17_plus_67():
    for path in [Path("AGENTS.md"), Path("runs/README.md"), Path("docs/idea_v2.md")]:
        text = _text(path)
        assert "17" in text and "67" in text, path
        assert "18 direct baseline + 66" not in text, path


def test_generated_paper_state_is_not_tracked_as_current_truth():
    tracked = subprocess.run(
        ["git", "ls-files", "--", "docs/generated_artifacts"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert tracked == []


def test_single_manuscript_has_no_citation_placeholders():
    manuscript = _text(Path("docs/paper_draft.md"))
    assert "[CITE]" not in manuscript
    assert "RESULTS_PENDING_FORMAL_MATRIX" not in manuscript
    assert "Evaluation Record v3" in manuscript
    assert "Claude Code + Kimi K2.6" in manuscript
    assert "Claude Code + MiniMax M2.5" in manuscript
    assert "53.37%" in manuscript and "53.97%" in manuscript


def test_manuscript_citation_keys_exist_in_bibliography():
    manuscript = _text(Path("docs/paper_draft.md"))
    bibliography = _text(Path("docs/paper_bibliography.bib"))
    for key in [
        "greshake2023indirect",
        "liu2024formalizing",
        "zhan2024injecagent",
        "debenedetti2024agentdojo",
        "ruan2024toolemu",
        "yao2024taubench",
        "dash2026memorypoisoning",
        "modelcontextprotocol2025spec",
    ]:
        assert key in manuscript
        assert f"{{{key}," in bibliography
