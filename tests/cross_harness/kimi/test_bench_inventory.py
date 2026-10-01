from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path

import pytest

from infra.check_paper_suite_lock import canonical_json_sha256
from infra.cross_harness.adapters.kimi.bench_inventory import (
    EXPECTED_CASE_COUNT,
    EXPECTED_STAGE_COUNT,
    EXPECTED_SUITE_COUNTS,
    KimiBenchInventoryDriftError,
    KimiBenchInventoryError,
    build_active_inventory,
    load_frozen_inventory,
    resolve_manifest_case_dir,
    write_frozen_inventory,
)
from infra.cross_harness.contract import CAPABILITIES

REPO_ROOT = Path(__file__).resolve().parents[3]
SNAPSHOT = (
    REPO_ROOT
    / "infra"
    / "cross_harness"
    / "bindings"
    / "kimi"
    / "active_328_v1.json"
)

EXPECTED_PROFILE_COUNTS = {
    "neutral_shared_artifact": 6,
    "neutral_workspace_memory_snapshot": 72,
    "neutral_workspace_saved_state": 10,
    "requires_kimi_native_compaction_resume": 15,
    "requires_kimi_native_mcp_memory": 19,
    "requires_kimi_native_mcp_memory_to_skill": 3,
    "requires_kimi_native_mcp_workspace_carrier": 51,
    "requires_kimi_native_memory_to_skill": 33,
    "requires_kimi_native_session_resume": 5,
    "requires_kimi_native_skill_direct": 17,
    "requires_kimi_native_skill_persistence": 67,
    "requires_kimi_native_subagent": 30,
}


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_frozen_inventory_matches_live_canonical_inputs() -> None:
    frozen = load_frozen_inventory(REPO_ROOT, snapshot_path=SNAPSHOT)
    live = build_active_inventory(REPO_ROOT)

    assert frozen == live
    assert frozen["case_count"] == EXPECTED_CASE_COUNT
    assert frozen["stage_count"] == EXPECTED_STAGE_COUNT
    assert frozen["suite_counts"] == EXPECTED_SUITE_COUNTS
    assert frozen["manifest"]["file_sha256"] == _file_sha256(
        REPO_ROOT / "runs" / "manifest.json"
    )
    assert all(len(case["case_meta_file_sha256"]) == 64 for case in frozen["cases"])
    assert all(len(case["case_meta_canonical_sha256"]) == 64 for case in frozen["cases"])
    assert all(len(case["runtime_inputs_tree_sha256"]) == 64 for case in frozen["cases"])
    assert all(len(case["case_content_sha256"]) == 64 for case in frozen["cases"])


def test_inventory_covers_328_cases_and_690_stage_invocations() -> None:
    inventory = load_frozen_inventory(REPO_ROOT, snapshot_path=SNAPSHOT)
    cases = inventory["cases"]

    assert len(cases) == 328
    assert sum(case["stage_count"] for case in cases) == 690
    assert sum(inventory["suite_counts"].values()) == 328
    assert inventory["execution_profile_counts"] == EXPECTED_PROFILE_COUNTS
    assert sum(EXPECTED_PROFILE_COUNTS.values()) == 328
    assert len({case["case_id"] for case in cases}) == 328
    assert len({case["manifest_case_dir"] for case in cases}) == 328


def test_f3_manifest_ids_are_derived_from_case_metadata() -> None:
    manifest = json.loads(
        (REPO_ROOT / "runs" / "manifest.json").read_text(encoding="utf-8-sig")
    )
    f3_entries = manifest["suites"]["v2_tool_mcp_runtime"]["cases"]
    assert len(f3_entries) == 70
    assert all("case_id" not in entry for entry in f3_entries)

    inventory = load_frozen_inventory(REPO_ROOT, snapshot_path=SNAPSHOT)
    f3_records = [
        case for case in inventory["cases"] if case["suite"] == "v2_tool_mcp_runtime"
    ]
    assert len(f3_records) == 70
    assert all(case["case_id_source"] == "case_meta" for case in f3_records)
    for case in f3_records:
        meta = json.loads(
            (REPO_ROOT / case["case_dir"] / "case_meta.json").read_text(
                encoding="utf-8-sig"
            )
        )
        assert case["case_id"] == meta["case_id"]


def test_required_capabilities_are_contract_values_and_fail_closed() -> None:
    inventory = load_frozen_inventory(REPO_ROOT, snapshot_path=SNAPSHOT)
    cases = inventory["cases"]

    assert all(case["conformance_status"] == "UNVALIDATED" for case in cases)
    assert all(set(case["required_capabilities"]) <= CAPABILITIES for case in cases)
    assert "control_isolation" in CAPABILITIES
    assert all(
        "control_isolation" not in case["required_capabilities"] for case in cases
    )
    assert all(
        case["requires_semantic_translation"] == (case["binding_kind"] != "neutral")
        for case in cases
    )
    restricted = [case for case in cases if case["canonical_harness_restrictions"]]
    assert len(restricted) == 50
    assert all(case["canonical_harness_restrictions"] == ["claude"] for case in restricted)
    assert all(not case["canonical_binding_usable_by_kimi"] for case in restricted)


def test_50_reviewed_native_m_bindings_do_not_broaden_canonical_rows() -> None:
    inventory = load_frozen_inventory(REPO_ROOT, snapshot_path=SNAPSHOT)
    variants = [
        case for case in inventory["cases"] if case["kimi_semantic_binding"] is not None
    ]

    assert len(variants) == 50
    assert Counter(case["suite"] for case in variants) == {
        "T3_subagent_poisoning": 30,
        "T3_compaction_resume_poisoning": 20,
    }
    assert Counter(
        case["kimi_semantic_binding"]["translation"] for case in variants
    ) == {
        "kimi_agent_coder_exact_artifact_v1": 30,
        "kimi_exact_native_session_resume_v1": 5,
        "kimi_acp_exact_manual_compaction_resume_v1": 15,
    }
    assert all(case["kimi_semantic_binding"]["binding_class"] == "M" for case in variants)
    assert all(case["kimi_semantic_binding"]["variant_kind"] == "native" for case in variants)
    assert all(case["kimi_binding_usable_by_kimi"] for case in variants)
    assert all(not case["canonical_binding_usable_by_kimi"] for case in variants)
    assert all(case["conformance_status"] == "UNVALIDATED" for case in variants)


def test_sa03_and_cr_native_capability_requirements_are_frozen() -> None:
    inventory = load_frozen_inventory(REPO_ROOT, snapshot_path=SNAPSHOT)
    cases = inventory["cases"]
    sa03 = [
        case
        for case in cases
        if "/SA.03_subagent_tool_choice_poisoning/" in case["case_dir"]
    ]
    assert len(sa03) == 5
    assert all(
        {
            "mcp_configuration",
            "mcp_health_trace",
            "mcp_tool_trace",
            "subagent_delegation",
            "fresh_process",
            "artifact_hash_provenance",
        }
        <= set(case["required_capabilities"])
        for case in sa03
    )

    compaction_suite = [
        case
        for case in cases
        if case["suite"] == "T3_compaction_resume_poisoning"
    ]
    assert len(compaction_suite) == 30
    assert all("fresh_process" in case["required_capabilities"] for case in compaction_suite)
    exact_resume = [
        case
        for case in compaction_suite
        if case["execution_class"] == "requires_kimi_native_session_resume"
    ]
    assert len(exact_resume) == 5
    assert all("session_compaction" not in case["required_capabilities"] for case in exact_resume)

    native_memory = [
        case
        for case in cases
        if case["execution_class"] == "requires_kimi_native_mcp_memory"
    ]
    assert len(native_memory) == 19
    assert all(
        {"durable_memory_write", "durable_memory_retrieval"}
        <= set(case["required_capabilities"])
        for case in native_memory
    )
    assert all(case["kimi_semantic_binding"] is None for case in native_memory)


def test_inventory_build_does_not_modify_manifest_or_case_metadata() -> None:
    frozen = load_frozen_inventory(REPO_ROOT, snapshot_path=SNAPSHOT, verify_live=False)
    paths = [REPO_ROOT / "runs" / "manifest.json"] + [
        REPO_ROOT / case["case_dir"] / "case_meta.json" for case in frozen["cases"]
    ]
    before = {path: _file_sha256(path) for path in paths}

    build_active_inventory(REPO_ROOT)

    after = {path: _file_sha256(path) for path in paths}
    assert after == before


@pytest.mark.parametrize(
    "unsafe",
    [
        "../active/case",
        "/absolute/case",
        "active/../case",
        "active//case",
        "active\\case",
        "archive/case",
        " active/case",
        "active/case ",
    ],
)
def test_manifest_case_paths_fail_closed_on_unsafe_values(
    tmp_path: Path, unsafe: str
) -> None:
    (tmp_path / "runs" / "active").mkdir(parents=True)
    with pytest.raises(KimiBenchInventoryError):
        resolve_manifest_case_dir(tmp_path, unsafe)


def test_manifest_case_paths_reject_symlinked_components(tmp_path: Path) -> None:
    active = tmp_path / "runs" / "active"
    outside = tmp_path / "outside"
    active.mkdir(parents=True)
    outside.mkdir()
    link = active / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform policy fallback
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(KimiBenchInventoryError, match="symlink|reparse"):
        resolve_manifest_case_dir(tmp_path, "active/linked")


def test_valid_manifest_case_path_resolves_inside_active_tree(tmp_path: Path) -> None:
    case_dir = tmp_path / "runs" / "active" / "suite" / "case_001"
    case_dir.mkdir(parents=True)
    assert resolve_manifest_case_dir(tmp_path, "active/suite/case_001") == case_dir


def test_live_drift_is_rejected_even_when_snapshot_self_digest_is_valid(
    tmp_path: Path,
) -> None:
    frozen = load_frozen_inventory(REPO_ROOT, snapshot_path=SNAPSHOT, verify_live=False)
    frozen["cases"][0]["case_content_sha256"] = "0" * 64
    body = dict(frozen)
    body.pop("inventory_content_sha256")
    frozen["inventory_content_sha256"] = canonical_json_sha256(body)
    altered = tmp_path / "altered_inventory.json"
    altered.write_text(json.dumps(frozen), encoding="utf-8")

    with pytest.raises(KimiBenchInventoryDriftError, match="case record 0 changed"):
        load_frozen_inventory(REPO_ROOT, snapshot_path=altered, verify_live=True)


def test_malformed_snapshot_self_digest_fails_closed(tmp_path: Path) -> None:
    frozen = load_frozen_inventory(REPO_ROOT, snapshot_path=SNAPSHOT, verify_live=False)
    frozen["inventory_content_sha256"] = "f" * 64
    altered = tmp_path / "malformed_inventory.json"
    altered.write_text(json.dumps(frozen), encoding="utf-8")

    with pytest.raises(KimiBenchInventoryError, match="self-digest"):
        load_frozen_inventory(REPO_ROOT, snapshot_path=altered, verify_live=False)


def test_snapshot_writer_cannot_target_canonical_or_non_kimi_paths() -> None:
    forbidden = REPO_ROOT / "runs" / "active" / "active_328_v1.json"
    with pytest.raises(KimiBenchInventoryError, match="bindings/kimi"):
        write_frozen_inventory(REPO_ROOT, snapshot_path=forbidden)
    assert not forbidden.exists()
