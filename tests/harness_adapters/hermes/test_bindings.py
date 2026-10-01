import json
from pathlib import Path

import pytest

from infra.harness_adapters.hermes.bindings import (
    case_contract_sha256,
    load_inventory,
    resolve_binding,
)
from infra.harness_adapters.hermes.model import BindingDisposition
from infra.harness_adapters.hermes.inventory import main as inventory_main


REPO_ROOT = Path(__file__).resolve().parents[3]
INVENTORY_PATH = REPO_ROOT / "infra/harness_bindings/hermes/inventory.json"


def active_case_paths(manifest_path: Path) -> list[str]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    return [
        entry["case_dir"]
        for suite in manifest["suites"].values()
        if suite.get("status") == "active"
        for entry in suite.get("cases", [])
    ]


def test_inventory_covers_manifest_exactly() -> None:
    manifest_paths = active_case_paths(REPO_ROOT / "runs/manifest.json")
    bindings = load_inventory(INVENTORY_PATH, repo_root=REPO_ROOT)

    assert set(bindings) == set(manifest_paths)
    assert len(bindings) == 328


def test_binding_hash_matches_canonical_case() -> None:
    bindings = load_inventory(INVENTORY_PATH, repo_root=REPO_ROOT)

    for case_dir, binding in bindings.items():
        assert binding.case_meta_sha256 == case_contract_sha256(
            REPO_ROOT / "runs" / case_dir / "case_meta.json"
        )


def test_inventory_rejects_paths_outside_active_tree(tmp_path: Path) -> None:
    inventory = {
        "binding_version": "hermes-binding-v1",
        "bindings": [
            {
                "case_dir": "archive/not-runnable",
                "case_meta_sha256": "0" * 64,
                "semantic_surface": "instruction",
                "required_capabilities": ["instruction"],
                "stage_runtime_modes": ["fresh"],
                "expected_normalized_events": ["session.start"],
                "disposition": "BLOCKED",
                "blocking_reasons": ["outside active tree"],
            }
        ],
    }
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(inventory), encoding="utf-8")

    with pytest.raises(ValueError, match="runs/active"):
        load_inventory(path, repo_root=REPO_ROOT, require_manifest_match=False)


def test_resolve_binding_is_fail_closed_for_stale_case_hash(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "case_meta.json").write_text('{"case_id":"changed"}', encoding="utf-8")
    canonical_case = next(iter(load_inventory(INVENTORY_PATH, repo_root=REPO_ROOT).values()))

    with pytest.raises(ValueError, match="hash"):
        resolve_binding(canonical_case, case_dir)


def test_dispositions_are_adapter_states_not_scores() -> None:
    assert {item.value for item in BindingDisposition} == {
        "READY",
        "NOT_RUN",
        "BLOCKED",
    }


def test_claude_session_modes_are_mapped_without_changing_cases() -> None:
    bindings = load_inventory(INVENTORY_PATH, repo_root=REPO_ROOT)
    binding = bindings[
        "active/T3/compaction_resume_poisoning/CR.01_session_summary_poisoning/case_001"
    ]

    assert binding.stage_runtime_modes == (
        "hermes_session_seed",
        "hermes_compaction",
        "hermes_session_resume",
    )


def test_inventory_check_writes_machine_readable_summary(tmp_path: Path) -> None:
    summary_path = tmp_path / "summary.json"

    exit_code = inventory_main(
        [
            "--repo-root",
            str(REPO_ROOT),
            "--check",
            "--summary-json",
            str(summary_path),
        ]
    )

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert summary["accounted"] == 328
    assert summary["missing"] == 0
    assert summary["stale_hashes"] == 0


def test_explicit_binding_mode_overrides_claude_only_case_restriction() -> None:
    """Generic mapped stages are as explicit as Hermes-prefixed native modes."""
    binding = load_inventory(INVENTORY_PATH, repo_root=REPO_ROOT)[
        "active/T3/subagent_poisoning/SA.01_subagent_output_poisoning/case_001"
    ]
    assert binding.stage_runtime_modes == (
        "hermes_subagent_producer",
        "fresh_main_consumer",
    )

    runner = (REPO_ROOT / "infra/run_harness_case.ps1").read_text(encoding="utf-8")
    assert '-and $preflightHermesMode -like "hermes_*"' not in runner
    assert '-and $boundRuntimeMode -like "hermes_*"' not in runner
