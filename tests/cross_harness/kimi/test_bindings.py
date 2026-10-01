from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft7Validator

from infra.cross_harness.bindings.kimi import load_kimi_common_bindings


REPO_ROOT = Path(__file__).resolve().parents[3]
INVENTORY_PATH = REPO_ROOT / "docs" / "codex_conformance_smoke_v1.json"


def test_all_kimi_bindings_validate_against_shared_v1_schema() -> None:
    schema = json.loads(
        (REPO_ROOT / "docs" / "cross_harness_binding_schema_v1.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft7Validator(schema)
    for path in sorted(
        (
            REPO_ROOT
            / "infra"
            / "cross_harness"
            / "bindings"
            / "kimi"
            / "common_surface_v1"
        ).glob("*.json")
    ):
        validator.validate(json.loads(path.read_text(encoding="utf-8")))


def test_kimi_bindings_match_common_case_selection_and_hashes() -> None:
    bindings = load_kimi_common_bindings(repo_root=REPO_ROOT)
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    common = [case for case in inventory["cases"] if case["surface_class"] == "common"]

    assert len(bindings) == 11
    assert {case["case_id"] for case in common} == set(bindings)
    assert sum(case["selection_status"] == "selected" for case in common) == 8
    assert all(
        binding["supported_harnesses"]["kimi"]["status"] == "unvalidated"
        for binding in bindings.values()
    )
    assert all(
        "Codex inventory supplies only the common-case selection"
        in binding["notes"]
        for binding in bindings.values()
    )


def test_kimi_binding_classes_and_native_neutral_variants_are_explicit() -> None:
    bindings = load_kimi_common_bindings(repo_root=REPO_ROOT)
    summary: dict[str, int] = {"D": 0, "M": 0, "N/A": 0}
    variants: dict[str, str | None] = {}
    for case_id, binding in bindings.items():
        native = binding["harness_native_binding"].get("kimi")
        if native is None:
            summary["N/A"] += 1
            variants[case_id] = None
        else:
            summary[native["config"]["binding_class"]] += 1
            variants[case_id] = native["variant_kind"]

    assert summary == {"D": 7, "M": 3, "N/A": 1}
    assert variants[
        "F1_memory_evolution_001_customerservice_01_refund_case_overgeneralization_round1"
    ] == "neutral"
    assert variants[
        "SK_I_sk_i_case_101_permission_claim_spoofing_v1"
    ] == "native"
    assert variants[
        "F3_mcp_result_instruction_same_session_001"
    ] is None
    assert variants["F3_mcp_schema_hidden_parameter_002"] == "neutral"
    assert variants[
        "T3_compaction_resume_poisoning_016_saved_plan_poisoning_audit"
    ] == "neutral"
    assert variants[
        "T3_shared_artifact_supply_chain_001_shared_decision_artifact_decision"
    ] == "neutral"


def test_each_kimi_common_case_has_the_reviewed_selection_class_and_variant() -> None:
    bindings = load_kimi_common_bindings(repo_root=REPO_ROOT)
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    source_selection = {
        case["case_id"]: case["selection_status"]
        for case in inventory["cases"]
        if case["surface_class"] == "common"
    }
    expected = {
        "F1_memory_evolution_001_customerservice_01_"
        "refund_case_overgeneralization_round1": ("selected", "D", "neutral"),
        "F1_memory_evolution_002_customerservice_01_"
        "refund_case_overgeneralization_round2": ("selected", "D", "neutral"),
        "SK_I_sk_i_case_101_permission_claim_spoofing_v1": (
            "selected",
            "D",
            "native",
        ),
        "SK_I_sk_i_case_402_metadata_tampering_v2_hash_forgery_persist": (
            "conditional",
            "M",
            "native",
        ),
        "SK_E_sk_e_case_703_local_memory_state_attack_v3_prepoisoned_claudemd": (
            "conditional",
            "M",
            "native",
        ),
        "F3_mcp_result_instruction_same_session_001": ("conditional", "N/A", None),
        "F3_mcp_schema_hidden_parameter_002": ("selected", "M", "neutral"),
        "F3_mcp_resource_runbook_005": ("selected", "D", "native"),
        "F3_tool_result_data_poisoning_012": ("selected", "D", "native"),
        "T3_compaction_resume_poisoning_016_saved_plan_poisoning_audit": (
            "selected",
            "D",
            "neutral",
        ),
        "T3_shared_artifact_supply_chain_001_shared_decision_artifact_decision": (
            "selected",
            "D",
            "neutral",
        ),
    }

    observed = {}
    for case_id, binding in bindings.items():
        native = binding["harness_native_binding"].get("kimi")
        if native is None:
            observed[case_id] = (source_selection[case_id], "N/A", None)
        else:
            observed[case_id] = (
                native["config"]["source_selection_status"],
                native["config"]["binding_class"],
                native["variant_kind"],
            )
    assert observed == expected


def test_schema_cache_binding_strengthens_codex_source_minimum_locally() -> None:
    bindings = load_kimi_common_bindings(repo_root=REPO_ROOT)
    binding = bindings["F3_mcp_schema_hidden_parameter_002"]
    native = binding["harness_native_binding"]["kimi"]

    assert native["config"]["binding_class"] == "M"
    assert native["config"]["component_surfaces"] == {
        "mcp": "kimi_native_mcp",
        "carrier": "neutral_workspace_schema_cache",
        "consumer": "direct_kimi_prompt",
    }
    assert "artifact_hash_provenance" in binding["required_capabilities"]
    assert set(native["expected_event_types"]) == {
        "mcp.server_initialized",
        "mcp.tool_requested",
        "mcp.tool_result",
        "file.write",
        "file.read",
    }
