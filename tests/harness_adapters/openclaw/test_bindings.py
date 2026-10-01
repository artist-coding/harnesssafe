import json
from pathlib import Path

import pytest

from infra.harness_adapters.openclaw.bindings import (
    case_contract_sha256,
    load_inventory,
    resolve_binding,
)
from infra.harness_adapters.openclaw.inventory import main as inventory_main
from infra.harness_adapters.openclaw.model import BindingDisposition


REPO_ROOT = Path(__file__).resolve().parents[3]
INVENTORY_PATH = REPO_ROOT / "infra/harness_bindings/openclaw/inventory.json"
READY_CASES = {
    "active/F1_memory_runtime/F1E.01_customerservice_01_refund_case_overgeneralization/case_001",
    "active/F1_memory_runtime/F1E.02_customerservice_02_complaint_tactic_normalization/case_004",
    "active/F2_skill_runtime/F2.01_perm_claim_spoofing/sk_i_case_101",
    "active/F2_skill_runtime/F2.02_scope_overflow/sk_i_case_201",
    "active/F2_skill_runtime/F2.10_execution_output_ipi/sk_e_case_401",
    "active/F3_tool_mcp_runtime/f301_rii/case_001",
    "active/F3_tool_mcp_runtime/f304_hpae/case_002",
    "active/F3_tool_mcp_runtime/f306_tcs/case_003",
    "active/T2_memory_to_skill/M2S.01_runbook_to_skill_provenance/case_001",
    "active/T2_memory_to_skill/M2S.02_compliance_memory_artifact_leak/case_004",
    "active/T3/subagent_poisoning/SA.01_subagent_output_poisoning/case_001",
    "active/T3/subagent_poisoning/SA.02_delegated_review_poisoning/case_006",
    "active/T3/subagent_poisoning/SA.03_subagent_tool_choice_poisoning/case_011",
    "active/T3/compaction_resume_poisoning/CR.01_session_summary_poisoning/case_001",
    "active/T3/compaction_resume_poisoning/CR.02_resume_context_poisoning/case_006",
    "active/T3/compaction_resume_poisoning/CR.03_compressed_task_note/case_011",
    "active/T3/shared_artifact_supply_chain/SAF.01_shared_decision_artifact/case_001",
    "active/T3/shared_artifact_supply_chain/SAF.01_shared_decision_artifact/case_002",
    "active/T3/shared_artifact_supply_chain/SAF.02_shared_template_artifact/case_004",
}


def active_case_paths(manifest_path: Path) -> list[str]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    return [
        entry["case_dir"]
        for suite in manifest["suites"].values()
        if suite.get("status") == "active"
        for entry in suite.get("cases", [])
    ]


def test_inventory_covers_manifest_exactly() -> None:
    expected = active_case_paths(REPO_ROOT / "runs/manifest.json")
    actual = load_inventory(INVENTORY_PATH, repo_root=REPO_ROOT)
    assert set(actual) == set(expected)
    assert len(actual) == 328


def test_inventory_hashes_match_canonical_cases() -> None:
    for case_dir, binding in load_inventory(
        INVENTORY_PATH, repo_root=REPO_ROOT
    ).items():
        assert binding.case_meta_sha256 == case_contract_sha256(
            REPO_ROOT / "runs" / case_dir / "case_meta.json"
        )


def test_only_provider_smoked_representatives_are_ready() -> None:
    inventory = load_inventory(INVENTORY_PATH, repo_root=REPO_ROOT)
    ready = {
        case_dir
        for case_dir, binding in inventory.items()
        if binding.disposition is BindingDisposition.READY
    }
    assert ready == READY_CASES
    assert all(not inventory[case_dir].blocking_reasons for case_dir in ready)
    assert sum(
        binding.disposition is BindingDisposition.NOT_RUN
        for binding in inventory.values()
    ) == 309


def test_inventory_rejects_unknown_fields(tmp_path: Path) -> None:
    payload = {
        "binding_version": "openclaw-binding-v1",
        "bindings": [{
            "case_dir": "active/example",
            "case_meta_sha256": "0" * 64,
            "semantic_surface": "instruction",
            "comparison_group": "openclaw-native",
            "required_capabilities": ["instruction"],
            "stage_runtime_modes": ["fresh"],
            "expected_normalized_events": [],
            "disposition": "BLOCKED",
            "blocking_reasons": ["test"],
            "unexpected": True,
        }],
    }
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown"):
        load_inventory(path, repo_root=REPO_ROOT, require_manifest_match=False)


def test_resolve_binding_fails_closed_for_stale_hash(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "case_meta.json").write_text("{}", encoding="utf-8")
    binding = next(iter(load_inventory(INVENTORY_PATH, repo_root=REPO_ROOT).values()))
    with pytest.raises(ValueError, match="hash"):
        resolve_binding(binding, case_dir)


def test_dispositions_are_adapter_states_not_scores() -> None:
    assert {item.value for item in BindingDisposition} == {
        "READY", "NOT_RUN", "BLOCKED"
    }


def test_claude_modes_are_mapped_without_changing_cases() -> None:
    binding = load_inventory(INVENTORY_PATH, repo_root=REPO_ROOT)[
        "active/T3/compaction_resume_poisoning/CR.01_session_summary_poisoning/case_001"
    ]
    assert binding.stage_runtime_modes == (
        "openclaw_session_seed",
        "openclaw_compaction",
        "openclaw_session_resume",
    )


def test_inventory_check_writes_machine_readable_summary(tmp_path: Path) -> None:
    summary_path = tmp_path / "summary.json"
    assert inventory_main([
        "--repo-root", str(REPO_ROOT), "--check",
        "--summary-json", str(summary_path),
    ]) == 0
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["accounted"] == 328
    assert summary["missing"] == 0
    assert summary["stale_hashes"] == 0
    assert summary["dispositions"] == {"NOT_RUN": 309, "READY": 19}
