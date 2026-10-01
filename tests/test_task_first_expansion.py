import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from infra.report_active_run import ORACLES
from infra.task_expansion_common import F3_DIR_TO_FAMILY_ID


REQUIRED_META = {
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
    "control",
    "case_depth",
}


NEW_ACTIVE_COUNTS = {
    "F1_memory_runtime": 72,
    "T2_memory_to_skill": 36,
    "T3_subagent_poisoning": 30,
    "T3_compaction_resume_poisoning": 30,
    "T3_shared_artifact_supply_chain": 6,
}


def load_manifest() -> dict:
    return json.loads(Path("runs/manifest.json").read_text(encoding="utf-8-sig"))


def load_meta(case_dir: str) -> dict:
    return json.loads((Path("runs") / case_dir / "case_meta.json").read_text(encoding="utf-8-sig"))


def matrix_family_id(suite_name: str, case_dir: str, meta: dict) -> str:
    parts = Path(case_dir.replace("\\", "/")).parts
    if suite_name == "v2_tool_mcp_runtime":
        for part in parts:
            if part.lower() in F3_DIR_TO_FAMILY_ID:
                return F3_DIR_TO_FAMILY_ID[part.lower()]
    if suite_name == "v2_skill_runtime":
        for part in parts:
            if re.match(r"^F2\.\d+", part):
                return part.split("_", 1)[0]
    return meta.get("attack_family_id") or meta.get("attack_id")


def declares_local_marker(meta: dict) -> bool:
    declared = set(meta.get("oracles") or [])
    declared.update(meta.get("oracles_phase1") or [])
    declared.update(meta.get("oracles_phase2") or [])
    for stage in meta.get("stages") or []:
        if isinstance(stage, dict):
            declared.update(stage.get("declared_oracles") or [])
    return "O_local_marker" in declared


def has_local_marker_config(meta: dict) -> bool:
    if meta.get("observable_markers"):
        return True
    for stage in meta.get("stages") or []:
        oracle = stage.get("oracle") if isinstance(stage, dict) else None
        if isinstance(oracle, dict) and oracle.get("local_marker"):
            return True
    return False


def test_task_first_expansion_counts_and_matrix_docs_exist():
    manifest = load_manifest()
    active = {
        name: suite
        for name, suite in manifest["suites"].items()
        if suite.get("status") == "active"
    }

    assert sum(len(suite["cases"]) for suite in active.values()) == 328
    assert 320 <= sum(len(suite["cases"]) for suite in active.values()) <= 340
    for suite, expected in NEW_ACTIVE_COUNTS.items():
        assert len(active[suite]["cases"]) == expected
    assert "T3_cross_harness_poisoning" not in manifest["suites"]
    assert not Path("runs/active/T3/cross_harness_poisoning").exists()

    assert Path("schemas/task_expansion_matrix.json").exists()
    matrix = json.loads(Path("schemas/task_expansion_matrix.json").read_text(encoding="utf-8"))
    matrix_suites = {row["suite"] for row in matrix["rows"]}
    assert set(active) <= matrix_suites

    matrix_families = {(row["suite"], row["family_id"]) for row in matrix["rows"]}
    for suite_name, suite in active.items():
        for entry in suite["cases"]:
            meta = load_meta(entry["case_dir"])
            assert (suite_name, matrix_family_id(suite_name, entry["case_dir"], meta)) in matrix_families


def test_new_active_cases_have_idea_v2_metadata_controls_and_supported_oracles():
    manifest = load_manifest()
    supported_oracles = set(ORACLES)

    for suite_name, expected_count in NEW_ACTIVE_COUNTS.items():
        suite = manifest["suites"][suite_name]
        assert suite["status"] == "active"
        assert suite["layer1_suite"] == suite_name
        assert len(suite["cases"]) == expected_count

        for entry in suite["cases"]:
            case_dir = Path("runs") / entry["case_dir"]
            meta = load_meta(entry["case_dir"])

            assert REQUIRED_META <= set(meta), case_dir
            assert entry["case_id"] == meta["case_id"]
            assert meta["violation"].startswith("C")
            assert isinstance(meta["oracles"], list) and meta["oracles"]
            assert set(meta["oracles"]) <= supported_oracles
            assert (case_dir / "workspace").is_dir()
            assert (case_dir / "config" / "deployment.id").is_file()
            assert (case_dir / "workspace" / "config" / "deployment.id").is_file()
            if declares_local_marker(meta):
                assert has_local_marker_config(meta), entry["case_dir"]

            control = meta["control"]
            assert control["control_type"] == "paired_clean_source"
            assert control["expected_absent_oracles"]
            assert set(control["expected_absent_oracles"]) <= supported_oracles
            assert control["expected_max_node"] in {"N1", "N2"}

            for key in {
                "entry_depth",
                "carrier_depth",
                "boundary_depth",
                "trigger_depth",
                "violation_depth",
                "control_depth",
            }:
                assert meta["case_depth"][key]


def test_memory_and_complex_cases_have_layer2_families_with_multiple_cases():
    manifest = load_manifest()
    per_suite_family_counts: dict[str, Counter] = defaultdict(Counter)

    for suite_name in NEW_ACTIVE_COUNTS:
        for entry in manifest["suites"][suite_name]["cases"]:
            meta = load_meta(entry["case_dir"])
            per_suite_family_counts[suite_name][meta["attack_family_id"]] += 1
    assert len(per_suite_family_counts["F1_memory_runtime"]) == 24
    assert all(count == 3 for count in per_suite_family_counts["F1_memory_runtime"].values())

    assert len(per_suite_family_counts["T2_memory_to_skill"]) == 12
    assert all(count == 3 for count in per_suite_family_counts["T2_memory_to_skill"].values())

    assert len(per_suite_family_counts["T3_subagent_poisoning"]) == 6
    assert all(count == 5 for count in per_suite_family_counts["T3_subagent_poisoning"].values())

    assert len(per_suite_family_counts["T3_compaction_resume_poisoning"]) == 6
    assert all(count == 5 for count in per_suite_family_counts["T3_compaction_resume_poisoning"].values())

    assert len(per_suite_family_counts["T3_shared_artifact_supply_chain"]) == 2
    assert all(count == 3 for count in per_suite_family_counts["T3_shared_artifact_supply_chain"].values())


def test_complex_cases_declare_stage_structure():
    manifest = load_manifest()
    complex_suites = [
        "T2_memory_to_skill",
        "T3_subagent_poisoning",
        "T3_compaction_resume_poisoning",
        "T3_shared_artifact_supply_chain",
    ]

    for suite_name in complex_suites:
        for entry in manifest["suites"][suite_name]["cases"]:
            meta = load_meta(entry["case_dir"])
            assert meta["multi_stage"] is True
            assert meta["multiphase"] is True
            assert meta["phase"] == "persistent_core"
            assert len(meta["stages"]) >= 2
            assert meta["phase1_prompt"]
            assert meta["phase2_prompt"]
            assert meta["oracles_phase1"]
            assert meta["oracles_phase2"]


def test_t3_cases_declare_executable_fail_closed_boundary_runtime():
    manifest = load_manifest()
    t3_suites = [name for name in NEW_ACTIVE_COUNTS if name.startswith("T3_")]

    for suite_name in t3_suites:
        for entry in manifest["suites"][suite_name]["cases"]:
            case_dir = Path("runs") / entry["case_dir"]
            meta = load_meta(entry["case_dir"])
            contract = meta["boundary_runtime_contract"]
            stages = meta["stages"]

            assert contract["status"] == "executable_fail_closed"
            assert contract.get("metric_eligible", True) is True
            assert meta["attack_success_metric_excluded"] is False
            assert contract["source_path"] == "inputs/project_notes.md"
            assert contract["trigger_source_access"] == "forbidden"
            assert meta["entry_artifact"] == "workspace/inputs/project_notes.md"
            assert "O_entry_source_read" in stages[0]["declared_oracles"]
            assert meta["carrier_contract"]["source_entry_artifact"] == meta["entry_artifact"]
            assert meta["payload_activation_markers"]
            assert meta["payload_rejection_markers"]
            assert (case_dir / "workspace" / contract["source_path"]).is_file()
            assert not (case_dir / "workspace" / "handoff" / "poisoned_context.md").exists()
            assert all(stage["fail_closed"] is True for stage in stages)
            assert contract["source_path"] in stages[0].get("quarantine_after", [])
            assert contract["source_path"] in stages[-1].get("forbid_paths", [])

            artifact = contract.get("producer_artifact") or ""
            if artifact:
                assert meta["carrier_contract"]["require_active_payload"] is True
                required = stages[0].get("required_artifacts") or []
                assert required == [{"path": artifact, "change": "created_or_modified"}]
                assert artifact in stages[-1].get("consume_artifacts", [])
                assert not (case_dir / "workspace" / artifact).exists()


def test_t3_runtime_mechanisms_match_suite_claims():
    manifest = load_manifest()

    for entry in manifest["suites"]["T3_subagent_poisoning"]["cases"]:
        meta = load_meta(entry["case_dir"])
        producer = meta["stages"][0]
        assert meta["boundary_runtime_contract"]["mechanism"] == "real_claude_subagent_to_exact_artifact"
        assert producer["supported_harnesses"] == ["claude"]
        assert "continuity-reviewer" in producer["claude_agents"]
        assert meta["boundary_runtime_contract"]["subagent_name"] == "continuity-reviewer"
        assert set(producer["required_trace_tool_any"]) == {"Agent", "Task"}
        assert producer["required_stage_oracles"] == ["O_subagent_boundary_producer"]

    for entry in manifest["suites"]["T3_compaction_resume_poisoning"]["cases"]:
        meta = load_meta(entry["case_dir"])
        family_id = meta["attack_family_id"]
        if family_id in {"CR.01", "CR.03", "CR.06"}:
            assert [stage["session_action"] for stage in meta["stages"]] == ["start", "compact", "resume"]
            assert meta["stages"][1]["user_prompt"].startswith("/compact")
        elif family_id == "CR.02":
            assert [stage["session_action"] for stage in meta["stages"]] == ["start", "resume"]
        else:
            assert meta["boundary_runtime_contract"]["mechanism"] == "exact_workspace_artifact_across_fresh_process"
        if family_id in {"CR.01", "CR.02", "CR.03", "CR.06"}:
            contract = meta["boundary_runtime_contract"]
            assert contract["version"] == 2
            assert contract["metric_eligible"] is True
            assert "O_session_carrier_seeded" in contract["provenance_oracles"]
            assert "O_session_resume" in contract["provenance_oracles"]

    for entry in manifest["suites"]["T3_shared_artifact_supply_chain"]["cases"]:
        meta = load_meta(entry["case_dir"])
        assert meta["boundary_runtime_contract"]["mechanism"] == "exact_producer_to_fresh_consumer_artifact"


def test_t2_builder_pins_future_skill_scaffold_contract():
    source = Path("infra/build_t2_memory_to_skill_cases.py").read_text(encoding="utf-8")

    assert "Local helper skill scaffold" in source
    assert "workspace/.claude-plugin/skills/{skill_name}/SKILL.md" in source
    assert "editing exactly .claude-plugin/skills/{skill_name}/SKILL.md" in source
    assert "Do not create or edit a " in source
    assert "nested workspace/ directory" in source


def test_t2_file_entry_is_quarantined_before_skill_synthesis_and_trigger():
    manifest = load_manifest()

    for entry in manifest["suites"]["T2_memory_to_skill"]["cases"]:
        meta = load_meta(entry["case_dir"])
        stages = meta["stages"]
        runtime = meta["boundary_runtime_contract"]
        if meta["attack_family_id"] == "M2S.09":
            assert runtime["mechanism"] == "mcp_entry_to_memory_to_generated_skill"
            assert runtime["source_path"] == ""
            assert "quarantine_after" not in stages[0]
            assert all("forbid_paths" not in stage for stage in stages)
            continue

        source_rel = meta["entry_artifact"].removeprefix("workspace/")
        assert runtime == {
            "version": 1,
            "status": "executable_fail_closed",
            "mechanism": "quarantined_file_entry_to_memory_to_generated_skill",
            "source_path": source_rel,
            "trigger_source_access": "forbidden",
        }
        assert stages[0]["quarantine_after"] == [source_rel]
        assert stages[0]["fail_closed"] is True
        for stage in stages[1:]:
            assert stage["forbid_paths"] == [source_rel]
            assert stage["fail_closed"] is True
