from __future__ import annotations

import hashlib
import json
from pathlib import Path

from infra.cross_harness.adapters.gemini.bench_inventory import (
    EXPECTED_BINDING_CLASS_COUNTS,
    EXPECTED_BINDING_KIND_COUNTS,
    EXPECTED_DISPOSITION_COUNTS,
    EXPECTED_SURFACE_COUNTS,
    build_inventory,
    load_inventory,
)


REPO_ROOT = Path(__file__).resolve().parents[3]


def test_checked_in_328_inventory_matches_live_canonical_suite() -> None:
    document = load_inventory(repo_root=REPO_ROOT, verify_live=True)
    summary = document["summary"]
    assert summary["case_count"] == 328
    assert summary["stage_count"] == 690
    assert summary["surface_class_counts"] == EXPECTED_SURFACE_COUNTS
    assert summary["binding_class_counts"] == EXPECTED_BINDING_CLASS_COUNTS
    assert summary["binding_kind_counts"] == EXPECTED_BINDING_KIND_COUNTS
    assert summary["disposition_counts"] == EXPECTED_DISPOSITION_COUNTS
    assert summary["execution_outcome_counts"] == {"NOT_RUN": 328}
    assert summary["smoke_binding_count"] == 16
    assert summary["expanded_binding_count"] == 312
    assert summary["materializable_binding_count"] == 328
    assert summary["formal_external_model_runs"] == 0
    assert summary["scoring_status"] == "NOT_PRODUCED"


def test_every_inventory_row_has_required_binding_fields_and_no_score() -> None:
    rows = load_inventory(repo_root=REPO_ROOT, verify_live=False)["cases"]
    required = {
        "semantic_surface",
        "surface_class",
        "required_capabilities",
        "supported_harnesses",
        "harness_native_binding",
        "comparison_group",
        "binding_version",
        "case_meta_sha256",
        "expected_normalized_events",
        "disposition",
        "blocking_reasons",
    }
    for row in rows:
        assert required <= set(row)
        assert row["execution_outcome"] == "NOT_RUN"
        assert row["scoring_status"] == "NOT_PRODUCED"
        assert row["blocking_reasons"]
        serialized = json.dumps(row, sort_keys=True)
        assert "SAFE" not in serialized
        assert '"N0"' not in serialized


def test_m2s_08_compaction_rows_are_binding_mapped_not_blocked() -> None:
    rows = {
        row["case_id"]: row
        for row in load_inventory(repo_root=REPO_ROOT, verify_live=False)["cases"]
    }
    case_ids = {
        "T2_m2s_022_summary_compaction_skill_seed_workspace_note",
        "T2_m2s_023_summary_compaction_skill_seed_operator_note",
        "T2_m2s_024_summary_compaction_skill_seed_handoff_note",
    }
    for case_id in case_ids:
        row = rows[case_id]
        assert row["disposition"] == "NOT_RUN"
        assert "session_compaction" in row["required_capabilities"]
        assert "session_resume" in row["required_capabilities"]
        assert row["comparison_group"] == "native_compaction_memory_to_skill"


def test_inventory_generation_is_read_only_for_all_canonical_case_metadata() -> None:
    before = {
        path: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (REPO_ROOT / "runs/active").rglob("case_meta.json")
    }
    rebuilt = build_inventory(REPO_ROOT)
    after = {
        path: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in before
    }
    assert before == after
    assert rebuilt == load_inventory(repo_root=REPO_ROOT, verify_live=False)
