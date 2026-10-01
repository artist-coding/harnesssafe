from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from infra.cross_harness.adapters.kimi import KimiMaterializationError
from infra.cross_harness.adapters.kimi.materializer import (
    materialize_kimi_binding,
    sha256_file,
    tree_sha256,
    validate_prelaunch_artifacts,
)
from infra.cross_harness.bindings.kimi import load_kimi_common_bindings


REPO_ROOT = Path(__file__).resolve().parents[3]


def _resign_manifest(document: dict) -> None:
    payload = {
        key: value
        for key, value in document.items()
        if key != "manifest_payload_sha256"
    }
    document["manifest_payload_sha256"] = hashlib.sha256(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


def _case_paths() -> dict[str, Path]:
    inventory = json.loads(
        (REPO_ROOT / "docs" / "codex_conformance_smoke_v1.json").read_text(
            encoding="utf-8"
        )
    )
    return {
        case["case_id"]: REPO_ROOT / case["case_dir"]
        for case in inventory["cases"]
        if case["surface_class"] == "common"
    }


def _materialize(tmp_path: Path, case_id: str, run_id: str):
    bindings = load_kimi_common_bindings(repo_root=REPO_ROOT)
    return materialize_kimi_binding(
        run_id=run_id,
        case_dir=_case_paths()[case_id],
        binding_document=bindings[case_id],
        run_dir=tmp_path / f"run-kimi-{run_id}",
        callback_port=52031,
    )


def test_all_common_candidates_materialize_without_changing_canonical_cases(
    tmp_path: Path,
) -> None:
    bindings = load_kimi_common_bindings(repo_root=REPO_ROOT)
    case_paths = _case_paths()
    before = {case_id: tree_sha256(path) for case_id, path in case_paths.items()}

    variants: set[str] = set()
    for index, case_id in enumerate(sorted(bindings)):
        if "kimi" not in bindings[case_id]["harness_native_binding"]:
            with pytest.raises(KimiMaterializationError, match="select kimi.adapter_v1"):
                materialize_kimi_binding(
                    run_id=f"all-{index:02d}",
                    case_dir=case_paths[case_id],
                    binding_document=bindings[case_id],
                    run_dir=tmp_path / f"run-kimi-all-{index:02d}",
                    callback_port=52100 + index,
                )
            continue
        materialized = materialize_kimi_binding(
            run_id=f"all-{index:02d}",
            case_dir=case_paths[case_id],
            binding_document=bindings[case_id],
            run_dir=tmp_path / f"run-kimi-all-{index:02d}",
            callback_port=52100 + index,
        )
        manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
        variants.add(manifest["variant_kind"])
        assert manifest["canonical"]["tree_sha256_before"] == before[case_id]
        assert manifest["canonical"]["tree_sha256_after"] == before[case_id]
        assert manifest["materialized"]["artifacts"]
        for stage in manifest["stages"]:
            for key in (
                "home_dir",
                "kimi_home",
                "skills_dir",
                "mcp_fixture_dir",
                "cache_dir",
                "temp_dir",
                "result_dir",
                "session_dir",
                "artifact_dir",
                "trace_path",
                "event_ir_path",
                "pid_record",
            ):
                assert "kimi" in stage[key].lower()
                assert manifest["run_id"] in stage[key]
        workspace = Path(manifest["materialized"]["workspace_dir"])
        boundary = workspace / ".git"
        assert boundary.is_dir()
        assert subprocess.run(
            ["git", "-C", str(workspace), "rev-parse", "--show-toplevel"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip() == str(workspace)

    assert variants == {"native", "neutral"}
    assert {case_id: tree_sha256(path) for case_id, path in case_paths.items()} == before


def test_instruction_materialization_is_semantic_not_a_claudemd_rename(
    tmp_path: Path,
) -> None:
    case_id = "SK_E_sk_e_case_703_local_memory_state_attack_v3_prepoisoned_claudemd"
    canonical = _case_paths()[case_id]
    source_instruction = canonical / "workspace" / "CLAUDE.md"
    source_digest = sha256_file(source_instruction)

    materialized = _materialize(tmp_path, case_id, "instruction-001")
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    workspace = Path(manifest["materialized"]["workspace_dir"])
    target = workspace / ".kimi-code" / "AGENTS.md"

    assert target.is_file()
    translated = target.read_text(encoding="utf-8")
    assert "Kimi Code session scoped to this run-local case workspace" in translated
    assert "Claude Code session" not in translated
    assert "kimi_project_instruction_v1" in translated
    assert not (workspace / "CLAUDE.md").exists()
    assert source_instruction.is_file()
    assert sha256_file(source_instruction) == source_digest
    record = next(
        item
        for item in manifest["materialized"]["artifacts"]
        if item["kind"] == "instruction_translation"
    )
    assert record["canonical_sha256"] == source_digest
    assert record["materialized_sha256"] == sha256_file(target)


def test_skill_materialization_uses_kimi_frontmatter_and_no_claude_wrapper(
    tmp_path: Path,
) -> None:
    case_id = "SK_I_sk_i_case_402_metadata_tampering_v2_hash_forgery_persist"
    materialized = _materialize(tmp_path, case_id, "skill-001")
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    stage = manifest["stages"][0]
    skill = Path(stage["skills_dir"]) / "api-client" / "SKILL.md"

    text = skill.read_text(encoding="utf-8")
    assert "type: prompt" in text
    assert "when-to-use:" in text
    assert "disable-model-invocation: false" in text
    assert "allowed-tools:" not in text
    assert ".claude-plugin" not in text
    assert "${KIMI_SKILL_DIR}/dependency_lock.json" in text
    assert (skill.parent / "dependency_lock.json").is_file()
    assert not (materialized.case_dir / ".claude-plugin").exists()
    assert not (
        Path(manifest["materialized"]["workspace_dir"]) / ".claude-plugin"
    ).exists()
    support_record = next(
        item
        for item in manifest["materialized"]["artifacts"]
        if item["kind"] == "skill_support_translation"
    )
    assert support_record["materialized_sha256"] == sha256_file(
        skill.parent / "dependency_lock.json"
    )


def test_mcp_and_schema_prompt_are_run_local_kimi_variants(tmp_path: Path) -> None:
    case_id = "F3_mcp_schema_hidden_parameter_002"
    materialized = _materialize(tmp_path, case_id, "mcp-001")
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))

    first = manifest["stages"][0]
    mcp = json.loads(Path(first["mcp_config"]).read_text(encoding="utf-8"))
    server = mcp["mcpServers"]["deployment-health"]
    assert server["command"] == sys.executable
    assert server["cwd"] == first["mcp_fixture_dir"]
    assert any("mcp-server-kimi-mcp-001-mcp_server.py" in arg for arg in server["args"])
    serialized = json.dumps(mcp)
    assert "127.0.0.1:52031" in serialized
    assert "127.0.0.1:18765" not in serialized
    assert server["env"] == {
        "SAFETY_BENCH_HARNESS": "kimi",
        "SAFETY_BENCH_RUN_ID": "mcp-001",
    }

    second_prompt = Path(manifest["stages"][1]["prompt_path"]).read_text(
        encoding="utf-8"
    )
    assert "/argument-schema-cache-002:" not in second_prompt
    assert "Base directory for this skill" not in second_prompt
    assert "Read that exact workspace file" in second_prompt
    clean_server = json.loads(
        Path(manifest["stages"][1]["mcp_config"]).read_text(encoding="utf-8")
    )["mcpServers"]["deployment-health"]
    fixture_arg = next(arg for arg in clean_server["args"] if arg.endswith(".json"))
    assert "mcp-fixture-kimi-mcp-001-mcp_clean_fixture.json" in fixture_arg
    assert Path(fixture_arg).is_file()


def test_callback_rendering_records_canonical_and_materialized_hashes(
    tmp_path: Path,
) -> None:
    case_id = "T3_shared_artifact_supply_chain_001_shared_decision_artifact_decision"
    canonical_source = _case_paths()[case_id] / "workspace" / "inputs" / "project_notes.md"
    canonical_digest = sha256_file(canonical_source)
    materialized = _materialize(tmp_path, case_id, "handoff-001")
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    target = (
        Path(manifest["materialized"]["workspace_dir"])
        / "inputs"
        / "project_notes.md"
    )

    assert "{{CALLBACK_URL}}" not in target.read_text(encoding="utf-8")
    assert "http://127.0.0.1:52031/" in target.read_text(encoding="utf-8")
    assert sha256_file(canonical_source) == canonical_digest
    record = next(
        item
        for item in manifest["materialized"]["artifacts"]
        if item["kind"] == "callback_materialization"
    )
    assert record["canonical_sha256"] == canonical_digest
    assert record["materialized_sha256"] == sha256_file(target)


def test_multistage_artifact_bindings_record_quarantine_and_fresh_boundary(
    tmp_path: Path,
) -> None:
    for case_id, run_id in (
        (
            "T3_compaction_resume_poisoning_016_saved_plan_poisoning_audit",
            "saved-plan-001",
        ),
        (
            "T3_shared_artifact_supply_chain_001_shared_decision_artifact_decision",
            "shared-handoff-001",
        ),
    ):
        materialized = _materialize(tmp_path, case_id, run_id)
        manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
        producer = manifest["stages"][0]["transition_requirements"]
        consumer = manifest["stages"][1]["transition_requirements"]

        assert producer["session_action"] == "fresh"
        assert producer["quarantine_after"] == ["inputs/project_notes.md"]
        assert consumer["session_action"] == "fresh"
        assert consumer["forbid_paths"] == ["inputs/project_notes.md"]
        assert producer["boundary_kind"] == consumer["boundary_kind"]


def test_materialized_manifests_do_not_reference_user_claude_or_codex_state(
    tmp_path: Path,
) -> None:
    case_id = "F3_mcp_resource_runbook_005"
    materialized = _materialize(tmp_path, case_id, "isolation-001")
    serialized = materialized.manifest_path.read_text(encoding="utf-8").lower()

    assert "/root/.claude" not in serialized
    assert "/root/.codex" not in serialized
    assert "claude_config_dir" not in serialized
    assert "codex_home" not in serialized
    assert "api_key" not in serialized
    assert "authorization" not in serialized


def test_prelaunch_validation_rejects_materialized_mcp_hash_drift(
    tmp_path: Path,
) -> None:
    materialized = _materialize(
        tmp_path, "F3_mcp_schema_hidden_parameter_002", "mcp-drift-001"
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    trusted_manifest = copy.deepcopy(manifest)
    validate_prelaunch_artifacts(
        manifest,
        stage_index=0,
        trusted_manifest_document=trusted_manifest,
    )
    mcp_path = Path(manifest["stages"][0]["mcp_config"])
    mcp_path.write_text('{"mcpServers": {}}\n', encoding="utf-8")

    with pytest.raises(KimiMaterializationError, match="hash drift before launch"):
        validate_prelaunch_artifacts(
            manifest,
            stage_index=0,
            trusted_manifest_document=trusted_manifest,
        )


def test_resigned_manifest_cannot_reanchor_modified_artifact_hash(
    tmp_path: Path,
) -> None:
    materialized = _materialize(
        tmp_path, "F3_mcp_schema_hidden_parameter_002", "mcp-reanchor-001"
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    trusted_manifest = copy.deepcopy(manifest)
    mcp_path = Path(manifest["stages"][0]["mcp_config"])
    mcp_path.write_text('{"mcpServers": {"attacker": {}}}\n', encoding="utf-8")
    target = mcp_path.resolve().relative_to(materialized.run_dir.resolve()).as_posix()
    record = next(
        artifact
        for artifact in manifest["materialized"]["artifacts"]
        if artifact["target"] == target
    )
    record["materialized_sha256"] = sha256_file(mcp_path)
    _resign_manifest(manifest)
    materialized.manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
    )

    with pytest.raises(KimiMaterializationError, match="adapter-owned snapshot"):
        validate_prelaunch_artifacts(
            manifest,
            stage_index=0,
            trusted_manifest_document=trusted_manifest,
        )


def test_consumer_prelaunch_requires_canonical_quarantine(
    tmp_path: Path,
) -> None:
    materialized = _materialize(
        tmp_path,
        "T3_shared_artifact_supply_chain_001_shared_decision_artifact_decision",
        "quarantine-001",
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    trusted_manifest = copy.deepcopy(manifest)
    source = Path(manifest["materialized"]["workspace_dir"]) / "inputs" / "project_notes.md"

    with pytest.raises(KimiMaterializationError, match="quarantined source"):
        validate_prelaunch_artifacts(
            manifest,
            stage_index=1,
            trusted_manifest_document=trusted_manifest,
        )

    source.unlink()
    validate_prelaunch_artifacts(
        manifest,
        stage_index=1,
        trusted_manifest_document=trusted_manifest,
    )


def test_resigned_manifest_cannot_remove_consumer_forbid_paths(
    tmp_path: Path,
) -> None:
    materialized = _materialize(
        tmp_path,
        "T3_shared_artifact_supply_chain_001_shared_decision_artifact_decision",
        "quarantine-reanchor-001",
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    trusted_manifest = copy.deepcopy(manifest)
    transition = manifest["stages"][1]["transition_requirements"]
    assert transition["forbid_paths"] == ["inputs/project_notes.md"]
    transition["forbid_paths"] = []
    _resign_manifest(manifest)
    materialized.manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
    )

    with pytest.raises(KimiMaterializationError, match="adapter-owned snapshot"):
        validate_prelaunch_artifacts(
            manifest,
            stage_index=1,
            trusted_manifest_document=trusted_manifest,
        )


def test_initial_prelaunch_detects_unrecorded_workspace_snapshot_drift(
    tmp_path: Path,
) -> None:
    case_id = (
        "F1_memory_evolution_001_customerservice_01_"
        "refund_case_overgeneralization_round1"
    )
    materialized = _materialize(tmp_path, case_id, "workspace-tree-drift-001")
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    trusted_manifest = copy.deepcopy(manifest)
    snapshot = (
        Path(manifest["materialized"]["workspace_dir"])
        / ".evolution_memory"
        / "memory_pool_r0.json"
    )
    snapshot.write_text('{"tampered": true}\n', encoding="utf-8")

    with pytest.raises(KimiMaterializationError, match="workspace tree drift"):
        validate_prelaunch_artifacts(
            manifest,
            stage_index=0,
            trusted_manifest_document=trusted_manifest,
        )
