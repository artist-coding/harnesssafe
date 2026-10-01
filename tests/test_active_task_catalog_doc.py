import json
from collections import Counter
from pathlib import Path

from infra.f2_oracle_profiles import get_f2_oracle_profile
from infra.generate_active_task_catalog import generate_markdown, load_active_cases


MANIFEST = Path("runs/manifest.json")
MATRIX = Path("docs/task_expansion_matrix.json")


def active_manifest_total() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
    return sum(
        len(suite.get("cases", []))
        for suite in manifest.get("suites", {}).values()
        if suite.get("status") == "active"
    )


def case_catalog_rows(markdown: str) -> list[str]:
    catalog = markdown.split("## Per-Case Catalog", 1)[1]
    return [line for line in catalog.splitlines() if line.startswith("| `")]


def find_case_row(markdown: str, case_id: str) -> str:
    matches = [line for line in case_catalog_rows(markdown) if line.startswith(f"| `{case_id}` |")]
    assert len(matches) == 1
    return matches[0]


def test_active_task_catalog_markdown_dry_run_covers_active_manifest():
    markdown = generate_markdown(MANIFEST, MATRIX)
    cases = load_active_cases(MANIFEST, MATRIX)

    assert active_manifest_total() == 328
    assert len(cases) == 328
    assert "Active cases: `328`" in markdown
    assert len(case_catalog_rows(markdown)) == len(cases)

    suites = {case.suite_name for case in cases}
    for suite in suites:
        assert f"`{suite}`" in markdown

    for case in cases:
        assert markdown.count(f"| `{case.meta['case_id']}` |") == 1


def test_active_task_catalog_documents_scoring_terms_and_oracles():
    markdown = generate_markdown(MANIFEST, MATRIX)

    for token in [
        "N0",
        "N1",
        "N2",
        "N3",
        "N4",
        "N5a",
        "N5b",
        "attack_success",
        "confirmed_compromise",
        "risk_score",
        "legacy_unsafe",
        "O_unsafe_recommendation",
        "O_local_marker",
        "O_mcp_canary_arg",
        "core_benchmark",
        "extended_benchmark",
        "exploratory_case_study",
        "Payload track",
        "explicit_defense",
        "subtle_persistence",
        "hard_trace_oracle",
        "preseeded_carrier_eval",
        "O_stage_propagation_before_trigger",
        "O_trigger_reconsumed_carrier",
        "O_trigger_achievement",
        "O_trigger_canary",
        "evaluation_schema_version=2.1.0",
        "Oracle status",
        "Oracle specificity",
        "current_proxy=",
        "desired=",
        "phase3=[",
        "attack-success-rate reporting",
        "N-1 / MODEL_PROTOCOL_INCOMPLETE",
        "model_protocol_deviation",
        "protocol completion rate",
        "model nonconformance rate",
        "conditional ASR",
        "end-to-end attack rate",
    ]:
        assert token in markdown


def test_active_task_catalog_does_not_treat_propagation_as_success_checkpoint():
    markdown = generate_markdown(MANIFEST, MATRIX)

    assert "key violation oracles: O_memory_write" not in markdown
    assert "key violation oracles: O_workspace_write" not in markdown
    assert "key violation oracles: O_schema_cache_hit" not in markdown
    assert "not declared (single-stage task)" not in markdown


def test_active_task_catalog_uses_f2_profiles_and_generic_scoring():
    markdown = generate_markdown(MANIFEST, MATRIX)
    cases = load_active_cases(MANIFEST, MATRIX)

    f2_case = next(case for case in cases if case.suite_name == "v2_skill_runtime")
    f2_profile = get_f2_oracle_profile(f2_case.meta)
    assert f2_profile is not None
    f2_row = find_case_row(markdown, f2_case.meta["case_id"])
    assert f"`{f2_profile.ladder_type}`" in f2_row
    assert f"`{f2_profile.success_threshold}`" in f2_row
    assert f"`{f2_profile.violation_oracle_status}`" in f2_row
    assert "current_proxy=" in f2_row
    assert "desired=" in f2_row

    memory_case = next(case for case in cases if case.suite_name == "F1_memory_runtime")
    memory_row = find_case_row(markdown, memory_case.meta["case_id"])
    assert "`memory_evolution`" in memory_row
    assert "`N5a`" in memory_row


def test_active_task_catalog_renders_f2_and_t2_stage_shapes():
    markdown = generate_markdown(MANIFEST, MATRIX)
    cases = load_active_cases(MANIFEST, MATRIX)

    f2_case = next(case for case in cases if case.suite_name == "v2_skill_runtime")
    f2_row = find_case_row(markdown, f2_case.meta["case_id"])
    assert "phase 0:clean_harness_baseline" in f2_row
    assert "F2 profile's case-specific achievement contract" in f2_row

    t2_case = next(case for case in cases if case.suite_name == "T2_memory_to_skill")
    t2_row = find_case_row(markdown, t2_case.meta["case_id"])
    assert "`memory_to_skill`" in t2_row
    assert "memory seed + generated skill artifact + benign skill invocation" in t2_row
    assert "phase2=[O_workspace_write]" in t2_row
    assert "phase3=[" in t2_row
    assert "progression=" in t2_row
    assert "violation_attempt=" in t2_row


def test_active_task_catalog_renders_t3_payload_tracks():
    markdown = generate_markdown(MANIFEST, MATRIX)
    cases = load_active_cases(MANIFEST, MATRIX)

    t3_cases = [case for case in cases if case.suite_name.startswith("T3_")]
    assert len(t3_cases) == 66
    assert {case.payload_track for case in t3_cases} == {
        "explicit_defense",
        "subtle_persistence",
    }

    subtle_case = next(case for case in t3_cases if case.payload_track == "subtle_persistence")
    subtle_row = find_case_row(markdown, subtle_case.meta["case_id"])
    assert "`subtle_persistence`" in subtle_row

    explicit_case = next(case for case in t3_cases if case.payload_track == "explicit_defense")
    explicit_row = find_case_row(markdown, explicit_case.meta["case_id"])
    assert "`explicit_defense`" in explicit_row


def test_active_task_catalog_has_exact_pre_registered_session_diagnostics():
    cases = load_active_cases(MANIFEST, MATRIX)

    excluded = [case for case in cases if case.meta.get("attack_success_metric_excluded")]
    eligible = [
        case
        for case in cases
        if case.meta.get("main_table_eligible")
        and case.meta.get("oracle_strength") == "hard_trace_oracle"
        and not case.meta.get("attack_success_metric_excluded")
    ]

    assert len(eligible) == 328
    assert len(excluded) == 0

    assert not any(case.meta.get("violation_oracle_status") == "missing_analyzer" for case in cases)
    assert not any(case.oracle_strength == "propagation_only" for case in cases)
    assert not any(case.oracle_strength == "soft_semantic_oracle" for case in cases)
