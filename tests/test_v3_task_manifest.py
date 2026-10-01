import json
from collections import Counter
from pathlib import Path


def test_manifest_no_longer_registers_legacy_v3_skill_references():
    manifest = json.loads(Path("runs/manifest.json").read_text(encoding="utf-8-sig"))

    assert all(not suite.startswith("v3_sk_") for suite in manifest["suites"])
    assert all(
        not entry["case_dir"].startswith("reference/v3_skill_cases/")
        for suite in manifest["suites"].values()
        for entry in suite.get("cases", [])
    )

    active = [suite for suite in manifest["suites"].values() if suite.get("status") == "active"]
    assert len(active) == 7
    assert sum(len(suite.get("cases", [])) for suite in active) == 328
    assert "T3_cross_harness_poisoning" not in manifest["suites"]


def test_legacy_expanded_case_trees_are_removed():
    assert not Path("runs/reference/v3_skill_cases").exists()
    assert not Path("runs/reference/v2_skill_runtime_direct").exists()
    assert not Path("runs/v2/v2_skill_runtime_new").exists()
    assert not Path("runs/archive/legacy_v2_memory_evolution").exists()
    assert not Path("runs/archive/prototype_memory2skill").exists()
    assert Path("runs/archive/legacy_v2_memory_evolution.zip").is_file()


def test_all_active_cases_are_runnable_hard_cases_with_exact_formal_subset():
    manifest = json.loads(Path("runs/manifest.json").read_text(encoding="utf-8-sig"))
    case_dirs = [
        Path("runs") / entry["case_dir"]
        for suite in manifest["suites"].values()
        if suite.get("status") == "active"
        for entry in suite.get("cases", [])
    ]

    assert len(case_dirs) == 328
    eligible = []
    diagnostics = []
    for case_dir in case_dirs:
        meta = json.loads((case_dir / "case_meta.json").read_text(encoding="utf-8-sig"))
        assert meta.get("oracle_strength") == "hard_trace_oracle", case_dir
        assert meta.get("hard_violation_oracles"), case_dir
        if meta.get("attack_success_metric_excluded"):
            diagnostics.append((case_dir, meta))
        else:
            assert meta.get("main_table_eligible") is True, case_dir
            eligible.append((case_dir, meta))

    assert len(eligible) == 328
    assert len(diagnostics) == 0


def test_no_expanded_case_metadata_exists_outside_active_tree():
    case_meta_paths = []
    for top_level in Path("runs").iterdir():
        if top_level.name == "active" or not top_level.is_dir():
            continue
        case_meta_paths.extend(top_level.rglob("case_meta.json"))

    assert case_meta_paths == []
