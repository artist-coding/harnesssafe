from __future__ import annotations

import hashlib
import json
from pathlib import Path

from infra.cross_harness.adapters.gemini import GeminiHarnessAdapter
from infra.cross_harness.bindings.gemini import (
    EXPECTED_EXPANDED_BINDING_COUNT,
    FULL_SUITE_BINDING_DIR,
    load_gemini_all_bindings,
)
from infra.cross_harness.bindings.gemini.generate_full import build_documents


REPO_ROOT = Path(__file__).resolve().parents[3]
INVENTORY_PATH = (
    REPO_ROOT / "infra/cross_harness/bindings/gemini/active_328_v1.json"
)


def test_complete_binding_set_matches_generator_and_active_inventory() -> None:
    bindings = load_gemini_all_bindings(repo_root=REPO_ROOT)
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    assert len(bindings) == 328
    assert len(list(FULL_SUITE_BINDING_DIR.glob("*.json"))) == (
        EXPECTED_EXPANDED_BINDING_COUNT
    )
    generated = {document["case_id"]: document for document in build_documents()}
    checked_in = {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in FULL_SUITE_BINDING_DIR.glob("*.json")
    }
    assert checked_in == generated
    assert set(bindings) == {row["case_id"] for row in inventory["cases"]}
    rows = {row["case_id"]: row for row in inventory["cases"]}
    for case_id, binding in bindings.items():
        assert set(binding["required_capabilities"]) == set(
            rows[case_id]["required_capabilities"]
        )


def test_m2s_08_generated_bindings_carry_gemini_session_lifecycle() -> None:
    bindings = load_gemini_all_bindings(repo_root=REPO_ROOT)
    case_ids = [
        "T2_m2s_022_summary_compaction_skill_seed_workspace_note",
        "T2_m2s_023_summary_compaction_skill_seed_operator_note",
        "T2_m2s_024_summary_compaction_skill_seed_handoff_note",
    ]
    for case_id in case_ids:
        config = bindings[case_id]["harness_native_binding"]["gemini"]["config"]
        stages = config["stages"]
        assert [stage["session_action"] for stage in stages] == [
            "start",
            "compact",
            "resume",
        ]
        assert {stage["session_key"] for stage in stages} == {
            "m2s_summary_compaction_skill_seed"
        }


def test_all_328_bindings_materialize_without_canonical_mutation(
    tmp_path: Path,
) -> None:
    bindings = load_gemini_all_bindings(repo_root=REPO_ROOT)
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    rows = {row["case_id"]: row for row in inventory["cases"]}
    before = {
        case_id: hashlib.sha256(
            (REPO_ROOT / row["case_dir"] / "case_meta.json").read_bytes()
        ).hexdigest()
        for case_id, row in rows.items()
    }
    for index, (case_id, binding) in enumerate(sorted(bindings.items())):
        run_dir = tmp_path / f"run-{index:03d}"
        adapter = GeminiHarnessAdapter(
            run_id=f"gemini-full-{index:03d}",
            run_dir=run_dir,
            model="gemini-2.5-flash",
            base_environment={"PATH": "/usr/bin:/bin"},
        )
        materialized = adapter.materialize_binding(
            case_dir=REPO_ROOT / rows[case_id]["case_dir"],
            binding_document=binding,
            run_dir=run_dir,
        )
        manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
        assert manifest["case_id"] == case_id
        assert manifest["canonical_case_meta_sha256"] == before[case_id]
        assert manifest["requested_model"] == "gemini-2.5-flash"
    after = {
        case_id: hashlib.sha256(
            (REPO_ROOT / row["case_dir"] / "case_meta.json").read_bytes()
        ).hexdigest()
        for case_id, row in rows.items()
    }
    assert after == before
