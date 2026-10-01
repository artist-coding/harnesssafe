import json
from pathlib import Path


def _load_manifest() -> dict:
    return json.loads(Path("runs/manifest.json").read_text(encoding="utf-8-sig"))


def test_active_manifest_uses_task_first_expansion_suites():
    manifest = _load_manifest()
    active = {
        suite_name: suite
        for suite_name, suite in manifest["suites"].items()
        if suite.get("status") == "active"
    }

    assert set(active) == {
        "v2_skill_runtime",
        "v2_tool_mcp_runtime",
        "F1_memory_runtime",
        "T2_memory_to_skill",
        "T3_subagent_poisoning",
        "T3_compaction_resume_poisoning",
        "T3_shared_artifact_supply_chain",
    }
    assert len(active["v2_skill_runtime"]["cases"]) == 84
    assert len(active["v2_tool_mcp_runtime"]["cases"]) == 70
    assert sum(len(suite["cases"]) for suite in active.values()) == 328
    assert "T3_cross_harness_poisoning" not in manifest["suites"]
    assert active["v2_skill_runtime"]["canonical_suite"] == "skill_runtime"
    assert active["v2_tool_mcp_runtime"]["canonical_suite"] == "tool_mcp_poisoning"
    assert active["v2_skill_runtime"]["layer1_suite"] == "F2_skill_runtime"
    assert active["v2_tool_mcp_runtime"]["layer1_suite"] == "F3_tool_mcp_runtime"
    assert all(
        entry["case_dir"].startswith("active/F3_tool_mcp_runtime/")
        for entry in active["v2_tool_mcp_runtime"]["cases"]
    )


def test_v2_skill_runtime_cases_use_idea_v2_fields_and_grouped_layout():
    manifest = _load_manifest()
    suite = manifest["suites"]["v2_skill_runtime"]
    required = {
        "case_id",
        "family",
        "canonical_suite",
        "task_type",
        "attack_id",
        "variant",
        "entry",
        "carrier",
        "boundary",
        "trigger",
        "violation",
        "recovery",
        "oracles",
    }

    groups = set()
    for entry in suite["cases"]:
        case_dir = Path("runs") / entry["case_dir"]
        meta = json.loads((case_dir / "case_meta.json").read_text(encoding="utf-8-sig"))

        assert required <= set(meta), case_dir
        assert entry["case_id"] == meta["case_id"]
        assert entry["canonical_suite"] == "skill_runtime"
        assert meta["canonical_suite"] == "skill_runtime"
        assert meta["family"] in {"SK-I", "SK-E"}
        assert meta["task_type"] in {"skill_intrinsic_risk", "skill_execution_risk"}
        assert meta["entry"]
        assert meta["carrier"]
        assert meta["boundary"]
        assert meta["trigger"]
        assert meta["violation"].startswith("C")
        assert isinstance(meta["oracles"], list) and meta["oracles"]

        parts = Path(entry["case_dir"]).parts
        assert parts[:3] == ("active", "F2_skill_runtime", parts[2])
        assert parts[2].startswith("F2.")
        groups.add(parts[2])

    assert len(groups) == 18
