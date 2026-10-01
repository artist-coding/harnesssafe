from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

import pytest

from infra.analyze_trace import _verified_file_carriers_removed_before_trigger
from infra.cross_harness.adapters.kimi import control_trials
from infra.cross_harness.adapters.kimi.bench_materializer import (
    load_bench_materialization_manifest,
)
from infra.cross_harness.adapters.kimi.control_trials import (
    CONTROL_TYPES,
    ControlInterventionRecorder,
    KimiControlTrialError,
    KimiMatchedControlBoundary,
    allocate_control_layout,
    audit_control_trial_matrix,
    build_control_trial_plan,
    load_control_trial_plan,
    materialize_control_trial,
)
from infra.cross_harness.adapters.kimi.executor import MatchedControlBoundaryRequest
from infra.cross_harness.adapters.kimi.materializer import sha256_file, tree_sha256
from infra.cross_harness.contract import CAPABILITIES


REPO_ROOT = Path(__file__).resolve().parents[3]
ALL_SUPPORTED = {capability: "SUPPORTED" for capability in CAPABILITIES}
CASE_PATHS = {
    "single_skill": REPO_ROOT
    / "runs/active/F2_skill_runtime/F2.01_perm_claim_spoofing/sk_i_case_101",
    "multi_skill": REPO_ROOT
    / "runs/active/F2_skill_runtime/F2.01_perm_claim_spoofing/sk_i_case_102",
    "mcp": REPO_ROOT / "runs/active/F3_tool_mcp_runtime/f301_rii/case_018",
    "translated_skill_carrier": REPO_ROOT
    / "runs/active/F2_skill_runtime/F2.04_metadata_tampering/sk_i_case_402",
    "native_session": REPO_ROOT
    / "runs/active/T3/compaction_resume_poisoning/CR.01_session_summary_poisoning/case_001",
    "shared_artifact": REPO_ROOT
    / "runs/active/T3/shared_artifact_supply_chain/SAF.01_shared_decision_artifact/case_001",
}


@pytest.fixture(scope="module")
def matrix_audit(tmp_path_factory: pytest.TempPathFactory) -> dict:
    batch = tmp_path_factory.mktemp("kimi-control-matrix")
    return audit_control_trial_matrix(
        repo_root=REPO_ROOT,
        batch_root=batch / "never-created",
        run_id="control-matrix-001",
    )


def _materialize(
    tmp_path: Path,
    *,
    case_key: str,
    suite: str,
    control_type: str,
    run_id: str,
):
    return materialize_control_trial(
        repo_root=REPO_ROOT,
        case_dir=CASE_PATHS[case_key],
        batch_root=tmp_path / "controls",
        run_id=run_id,
        control_type=control_type,
        callback_url="http://127.0.0.1:49191",
        capability_states=ALL_SUPPORTED,
        expected_suite_id=suite,
    )


def test_static_matrix_is_exactly_328_by_four_and_read_only(
    matrix_audit: dict, tmp_path: Path
) -> None:
    assert matrix_audit["case_count"] == 328
    assert matrix_audit["control_types_per_case"] == 4
    assert matrix_audit["control_trial_count"] == 1312
    assert Counter(row["control_type"] for row in matrix_audit["rows"]) == {
        control_type: 328 for control_type in CONTROL_TYPES
    }
    assert len({row["control_id"] for row in matrix_audit["rows"]}) == 1312
    assert matrix_audit["dispositions"] == {
        "MATERIALIZABLE": 1052,
        "NOT_RUN": 260,
    }
    assert matrix_audit["formal_runtime_readiness_claimed"] is False
    assert matrix_audit["scoring_status"] == "NOT_PRODUCED"
    assert matrix_audit["capability_hypothesis_is_evidence"] is False
    assert matrix_audit["inventory_content_sha256"] == (
        "801b5a35fb91cffdfc47a76ff255140b506edeefc29ab3de7a7e81ebf0357c8a"
    )
    assert matrix_audit["canonical_hash_guard"] == {
        "verify_live_frozen_inventory": True,
        "canonical_cases_modified": False,
    }
    # The audit's batch_root is a pure path allocation input; static planning
    # never materializes or launches anything.
    assert not (tmp_path / "unexpected-control-output").exists()


def test_static_matrix_reports_suite_specific_hard_blocks(matrix_audit: dict) -> None:
    counts = {
        (row["suite_id"], row["disposition"]): row["count"]
        for row in matrix_audit["suite_dispositions"]
    }
    assert counts[("T2_memory_to_skill", "NOT_RUN")] == 144
    assert counts[("v2_tool_mcp_runtime", "NOT_RUN")] == 76
    assert counts[("T3_compaction_resume_poisoning", "NOT_RUN")] == 40
    assert matrix_audit["native_session_intervention_rows_not_run"] == 40


def test_native_session_intervention_has_no_workspace_emulation(tmp_path: Path) -> None:
    for control_type in ("no_persist_control", "cleanup_control"):
        plan = build_control_trial_plan(
            repo_root=REPO_ROOT,
            case_dir=CASE_PATHS["native_session"],
            batch_root=tmp_path,
            run_id=f"native-session-{control_type[:3]}",
            control_type=control_type,
            capability_states=ALL_SUPPORTED,
            expected_suite_id="T3_compaction_resume_poisoning",
        )
        assert plan["disposition"] == "NOT_RUN"
        assert any(
            "no directly verified Kimi native transcript translation" in reason
            for reason in plan["disposition_reasons"]
        )
        assert plan["declared_session_carrier_intervention"] is not None
        assert plan["declared_carrier_paths"] == []
        assert not tmp_path.exists() or not any(tmp_path.iterdir())


def test_control_layout_is_independent_and_names_every_sensitive_resource(
    tmp_path: Path,
) -> None:
    first = allocate_control_layout(
        batch_root=tmp_path,
        run_id="layout-001",
        control_id="fixture-clean-control",
    )
    second = allocate_control_layout(
        batch_root=tmp_path,
        run_id="layout-001",
        control_id="fixture-cleanup-control",
    )
    assert first.root != second.root
    assert first.trial_run_id != second.trial_run_id
    for layout in (first, second):
        for key in (
            "root",
            "home",
            "kimi_home",
            "session",
            "cache",
            "pid",
            "broker",
            "artifact",
            "trace",
            "result",
        ):
            path = getattr(layout, key)
            assert "kimi" in str(path)
            assert layout.trial_run_id in str(path)
            assert layout.control_token in str(path)


@pytest.mark.parametrize("control_type", CONTROL_TYPES)
def test_plan_preserves_stage_count_order_and_exactly_one_variable(
    tmp_path: Path, control_type: str
) -> None:
    plan = build_control_trial_plan(
        repo_root=REPO_ROOT,
        case_dir=CASE_PATHS["multi_skill"],
        batch_root=tmp_path,
        run_id=f"plan-{control_type[:5]}",
        control_type=control_type,
        capability_states=ALL_SUPPORTED,
        expected_suite_id="v2_skill_runtime",
    )
    assert plan["disposition"] == "MATERIALIZABLE"
    assert plan["stage_count"] == 2
    assert plan["stage_order"] == ["plant", "trigger"]
    assert plan["single_variable_verified"] is True
    if control_type == "no_trigger_control":
        assert plan["stage_semantic_difference_paths"] == [
            "stages[1].user_prompt"
        ]
    else:
        assert plan["stage_semantic_difference_paths"] == []
    if control_type == "no_persist_control":
        assert plan["intervention_before_stage_indices"] == [2]
    elif control_type == "cleanup_control":
        assert plan["intervention_before_stage_indices"] == [2]
    else:
        assert plan["intervention_before_stage_indices"] == []


def test_control_plan_hash_is_tamper_evident(tmp_path: Path) -> None:
    plan = build_control_trial_plan(
        repo_root=REPO_ROOT,
        case_dir=CASE_PATHS["single_skill"],
        batch_root=tmp_path,
        run_id="plan-hash-001",
        control_type="clean_control",
        capability_states=ALL_SUPPORTED,
        expected_suite_id="v2_skill_runtime",
    )
    path = tmp_path / "control-plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    assert load_control_trial_plan(path)["control_id"] == plan["control_id"]
    document = json.loads(path.read_text(encoding="utf-8"))
    document["stage_count"] = 9
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(KimiControlTrialError, match="self-hash"):
        load_control_trial_plan(path)


def test_plan_loader_allows_expected_oracle_metadata_but_rejects_result_fields(
    tmp_path: Path,
) -> None:
    plan = build_control_trial_plan(
        repo_root=REPO_ROOT,
        case_dir=CASE_PATHS["single_skill"],
        batch_root=tmp_path,
        run_id="expected-metadata-001",
        control_type="clean_control",
        capability_states=ALL_SUPPORTED,
        expected_suite_id="v2_skill_runtime",
    )
    assert plan["expected_absent_oracles"]
    assert plan["expected_present_oracles"]
    path = tmp_path / "expected-control-plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    assert load_control_trial_plan(path)["expected_max_node"] == "N2"

    plan["verdict"] = "SAFE"
    plan["control_plan_payload_sha256"] = control_trials._payload_sha256(
        plan, "control_plan_payload_sha256"
    )
    path.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(KimiControlTrialError, match="analyzer/scoring fields"):
        load_control_trial_plan(path)


def test_atomic_json_write_preserves_previous_trust_input_on_replace_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "control-plan-kimi-atomic-001.json"
    control_trials._write_json(path, {"generation": 1})

    def fail_replace(_source: Path, _target: Path) -> None:
        raise OSError("fixture replace failure")

    monkeypatch.setattr(control_trials.os, "replace", fail_replace)
    with pytest.raises(OSError, match="fixture replace failure"):
        control_trials._write_json(path, {"generation": 2})
    assert json.loads(path.read_text(encoding="utf-8")) == {"generation": 1}
    assert not list(tmp_path.glob(".*.tmp-kimi-*"))


def test_clean_plugin_materialization_replaces_only_declared_kimi_surface(
    tmp_path: Path,
) -> None:
    canonical_before = tree_sha256(CASE_PATHS["single_skill"])
    materialized = _materialize(
        tmp_path,
        case_key="single_skill",
        suite="v2_skill_runtime",
        control_type="clean_control",
        run_id="clean-plugin-001",
    )
    manifest = load_bench_materialization_manifest(materialized.bench_manifest_path)
    intervention = json.loads(materialized.intervention_path.read_text(encoding="utf-8"))
    plugin_records = [record for record in intervention["records"] if record["kind"] == "plugin"]
    assert plugin_records
    assert all(record["verified"] for record in plugin_records)
    assert all(record["attack_sha256"] != record["effective_sha256"] for record in plugin_records)
    assert intervention["expected_intervention_count"] == 0
    assert intervention["applied_intervention_count"] == 0
    assert intervention["applied"] is True
    assert manifest["control_trial"]["control_type"] == "clean_control"
    assert manifest["control_trial"]["scoring_status"] == "NOT_PRODUCED"
    assert tree_sha256(CASE_PATHS["single_skill"]) == canonical_before


def test_clean_workspace_materialization_records_pre_and_post_hashes(
    tmp_path: Path,
) -> None:
    materialized = _materialize(
        tmp_path,
        case_key="shared_artifact",
        suite="T3_shared_artifact_supply_chain",
        control_type="clean_control",
        run_id="clean-workspace-001",
    )
    intervention = json.loads(materialized.intervention_path.read_text(encoding="utf-8"))
    assert len(intervention["records"]) == 1
    record = intervention["records"][0]
    assert record["kind"] == "workspace_override"
    assert record["attack_sha256"] != record["effective_sha256"]
    assert record["clean_sha256"] == record["effective_sha256"]
    assert len(record["canonical_attack_sha256"]) == 64
    assert len(record["canonical_clean_sha256"]) == 64
    assert record["materialization_substitution_aware"] is True


def test_clean_mcp_materialization_keeps_proxy_and_hash_provenance(
    tmp_path: Path,
) -> None:
    materialized = _materialize(
        tmp_path,
        case_key="mcp",
        suite="v2_tool_mcp_runtime",
        control_type="clean_control",
        run_id="clean-mcp-001",
    )
    manifest = load_bench_materialization_manifest(materialized.bench_manifest_path)
    intervention = json.loads(materialized.intervention_path.read_text(encoding="utf-8"))
    records = [record for record in intervention["records"] if record["kind"] == "mcp_config"]
    assert records and all(record["verified"] for record in records)
    for stage in manifest["stages"]:
        mcp = stage["surfaces"]["mcp"]
        if mcp["activation"]["operation"] == "replace_file":
            prepared = mcp["prepared_config"]
            proxy = prepared["evidence_proxy"]
            assert proxy[
                "launch_ready_with_evidence_proxy"
            ] is True
            assert mcp["evidence_proxy"]["server_reservations"]
            for reservation in mcp["evidence_proxy"]["server_reservations"]:
                required_files = reservation["required_run_local_files"]
                assert required_files
                assert all(
                    record["kind"] == "reviewed_mcp_child_file"
                    and Path(record["path"]).is_file()
                    and sha256_file(Path(record["path"])) == record["sha256"]
                    for record in required_files
                )
            proxy_copy = Path(proxy["run_local_proxy_copy_path"])
            proxy_source = Path(proxy["trusted_proxy_source_path"])
            proxy_copy.relative_to(materialized.layout.root)
            assert proxy_copy.is_file() and not proxy_copy.is_symlink()
            assert proxy_copy.stat().st_mode & 0o222 == 0
            assert sha256_file(proxy_copy) == sha256_file(proxy_source)
            config = json.loads(Path(prepared["target"]).read_text(encoding="utf-8"))
            server = next(iter(config["mcpServers"].values()))
            assert server["args"][0] == str(proxy_copy)
            assert server["command"] == prepared["trusted_python_executable_path"]
            child_argv = server["args"][server["args"].index("--") + 1 :]
            assert child_argv[0] == prepared["trusted_python_executable_path"]


def test_materialization_requires_explicit_capability_evidence_before_writes(
    tmp_path: Path,
) -> None:
    batch = tmp_path / "missing-capability-evidence"
    with pytest.raises(KimiControlTrialError, match="explicit capability-state"):
        materialize_control_trial(
            repo_root=REPO_ROOT,
            case_dir=CASE_PATHS["shared_artifact"],
            batch_root=batch,
            run_id="missing-capabilities-001",
            control_type="clean_control",
            callback_url="http://127.0.0.1:49191",
            expected_suite_id="T3_shared_artifact_supply_chain",
        )
    assert not batch.exists()

    partial_batch = tmp_path / "partial-capability-evidence"
    with pytest.raises(KimiControlTrialError, match="exact Contract v1 surface"):
        materialize_control_trial(
            repo_root=REPO_ROOT,
            case_dir=CASE_PATHS["shared_artifact"],
            batch_root=partial_batch,
            run_id="partial-capabilities-001",
            control_type="clean_control",
            callback_url="http://127.0.0.1:49191",
            capability_states={"headless_execution": "SUPPORTED"},
            expected_suite_id="T3_shared_artifact_supply_chain",
        )
    assert not partial_batch.exists()


def test_no_trigger_materialization_changes_only_trigger_prompt(
    tmp_path: Path,
) -> None:
    materialized = _materialize(
        tmp_path,
        case_key="shared_artifact",
        suite="T3_shared_artifact_supply_chain",
        control_type="no_trigger_control",
        run_id="no-trigger-001",
    )
    manifest = load_bench_materialization_manifest(materialized.bench_manifest_path)
    record = json.loads(materialized.intervention_path.read_text(encoding="utf-8"))[
        "records"
    ][0]
    assert record["action"] == "replace_trigger_prompt"
    assert record["stage_index"] == 2
    assert record["original_prompt_sha256"] != record["effective_prompt_sha256"]
    assert materialized.plan["stage_semantic_difference_paths"] == [
        "stages[1].user_prompt"
    ]
    assert manifest["stages"][1]["prompt"]["control_trigger_substitution"] is True


def test_not_run_control_stops_before_materialization_write(tmp_path: Path) -> None:
    batch = tmp_path / "blocked-controls"
    with pytest.raises(KimiControlTrialError, match="NOT_RUN"):
        materialize_control_trial(
            repo_root=REPO_ROOT,
            case_dir=CASE_PATHS["native_session"],
            batch_root=batch,
            run_id="blocked-native-001",
            control_type="cleanup_control",
            callback_url="http://127.0.0.1:49192",
            capability_states=ALL_SUPPORTED,
            expected_suite_id="T3_compaction_resume_poisoning",
        )
    assert not batch.exists()


def test_cleanup_recorder_removes_only_current_control_carrier_and_is_analyzer_readable(
    tmp_path: Path,
) -> None:
    materialized = _materialize(
        tmp_path,
        case_key="shared_artifact",
        suite="T3_shared_artifact_supply_chain",
        control_type="cleanup_control",
        run_id="cleanup-001",
    )
    manifest = load_bench_materialization_manifest(materialized.bench_manifest_path)
    workspace = Path(manifest["materialized"]["workspace_dir"])
    carrier = workspace / "reports/generated_decision.md"
    carrier.parent.mkdir(parents=True, exist_ok=True)
    carrier.write_text("run-local carrier\n", encoding="utf-8")
    neighbor = tmp_path / "control-kimi-neighbor" / "reports/generated_decision.md"
    neighbor.parent.mkdir(parents=True)
    neighbor.write_text("must survive\n", encoding="utf-8")

    evidence = ControlInterventionRecorder(materialized).apply_before_stage(2)

    assert evidence["applied"] is True
    assert evidence["applied_before_stage_indices"] == [2]
    assert len(evidence["manifest_revisions"]) == 1
    revision = evidence["manifest_revisions"][0]
    assert revision["before_stage_index"] == 2
    assert revision["before_file_sha256"] != revision["after_file_sha256"]
    assert revision["after_file_sha256"] == sha256_file(
        materialized.bench_manifest_path
    )
    assert not carrier.exists()
    assert neighbor.read_text(encoding="utf-8") == "must survive\n"
    shared_reader = _verified_file_carriers_removed_before_trigger(
        materialized.layout.root
    )
    assert shared_reader is not None
    assert shared_reader["control_id"] == materialized.plan["control_id"]
    assert shared_reader["declared_carrier_paths"] == [
        "reports/generated_decision.md"
    ]
    serialized = json.dumps(evidence, sort_keys=True)
    for forbidden in ("progress_node", "verdict", '"score"', "attack_success"):
        assert forbidden not in serialized


def test_executor_boundary_maps_zero_based_stage_to_canonical_control_schedule(
    tmp_path: Path,
) -> None:
    materialized = _materialize(
        tmp_path,
        case_key="shared_artifact",
        suite="T3_shared_artifact_supply_chain",
        control_type="cleanup_control",
        run_id="cleanup-boundary-001",
    )
    manifest = load_bench_materialization_manifest(materialized.bench_manifest_path)
    workspace = Path(manifest["materialized"]["workspace_dir"])
    carrier = workspace / "reports/generated_decision.md"
    carrier.parent.mkdir(parents=True, exist_ok=True)
    carrier.write_text("run-local carrier\n", encoding="utf-8")
    boundary = KimiMatchedControlBoundary(materialized)

    first = boundary.apply_before_stage(
        MatchedControlBoundaryRequest(
            run_id=materialized.layout.trial_run_id,
            case_id=materialized.plan["case_id"],
            stage_index=0,
            stage_name=materialized.plan["stage_order"][0],
            manifest_path=materialized.bench_manifest_path,
            manifest_sha256=sha256_file(materialized.bench_manifest_path),
        )
    )
    assert first is None
    applied = boundary.apply_before_stage(
        MatchedControlBoundaryRequest(
            run_id=materialized.layout.trial_run_id,
            case_id=materialized.plan["case_id"],
            stage_index=1,
            stage_name=materialized.plan["stage_order"][1],
            manifest_path=materialized.bench_manifest_path,
            manifest_sha256=sha256_file(materialized.bench_manifest_path),
        )
    )
    assert applied is not None
    assert applied.stage_index == 1
    assert applied.manifest_sha256 == sha256_file(
        materialized.bench_manifest_path
    )
    assert applied.evidence_sha256 == sha256_file(materialized.intervention_path)
    assert not carrier.exists()
    finalized = boundary.finalize()
    assert finalized.applied_stage_indices == (2,)


def test_preseeded_plugin_carrier_maps_to_real_kimi_skill_surface(
    tmp_path: Path,
) -> None:
    materialized = _materialize(
        tmp_path,
        case_key="single_skill",
        suite="v2_skill_runtime",
        control_type="cleanup_control",
        run_id="cleanup-plugin-001",
    )
    assert materialized.plan["canonical_declared_carrier_paths"] == ["plugin"]
    assert materialized.plan["declared_carrier_paths"] == [".kimi-code/skills"]
    manifest = load_bench_materialization_manifest(materialized.bench_manifest_path)
    workspace = Path(manifest["materialized"]["workspace_dir"])
    native_carrier = workspace / ".kimi-code/skills"
    assert native_carrier.is_dir()

    evidence = ControlInterventionRecorder(materialized).apply_before_stage(1)

    assert not native_carrier.exists()
    assert any(
        record["kind"] == "kimi_runtime_carrier"
        and record["translation"] == "kimi_project_skill_tree_v1"
        and record["removed"] is True
        for record in evidence["records"]
    )
    shared_reader = _verified_file_carriers_removed_before_trigger(
        materialized.layout.root
    )
    assert shared_reader is not None
    assert shared_reader["declared_carrier_paths"] == [".kimi-code/skills"]
    updated = load_bench_materialization_manifest(materialized.bench_manifest_path)
    assert updated["stages"][0]["surfaces"]["skills"]["activation"] == {
        "operation": "remove_tree_if_present",
        "target": "workspace/.kimi-code/skills",
    }


def test_translated_skill_artifact_removal_updates_future_activation_hash(
    tmp_path: Path,
) -> None:
    materialized = _materialize(
        tmp_path,
        case_key="translated_skill_carrier",
        suite="v2_skill_runtime",
        control_type="cleanup_control",
        run_id="cleanup-skill-artifact-001",
    )
    binding = materialized.plan["carrier_path_bindings"][0]
    assert binding == {
        "canonical": ".claude-plugin/skills/api-client/dependency_lock.json",
        "materialized": ".kimi-code/skills/api-client/dependency_lock.json",
        "translation": "kimi_project_skill_artifact_v1",
    }
    manifest = load_bench_materialization_manifest(materialized.bench_manifest_path)
    target = Path(manifest["materialized"]["workspace_dir"]) / binding["materialized"]
    assert target.is_file()

    evidence = ControlInterventionRecorder(materialized).apply_before_stage(2)

    assert not target.exists()
    assert any(
        record["kind"] == "kimi_runtime_carrier"
        and record["translation"] == "kimi_project_skill_artifact_v1"
        and record["removed"] is True
        for record in evidence["records"]
    )
    assert _verified_file_carriers_removed_before_trigger(
        materialized.layout.root
    ) is not None
    load_bench_materialization_manifest(materialized.bench_manifest_path)


def test_state_reset_is_confined_to_prior_run_local_kimi_stage(
    tmp_path: Path,
) -> None:
    materialized = _materialize(
        tmp_path,
        case_key="multi_skill",
        suite="v2_skill_runtime",
        control_type="cleanup_control",
        run_id="cleanup-state-001",
    )
    manifest = load_bench_materialization_manifest(materialized.bench_manifest_path)
    workspace = Path(manifest["materialized"]["workspace_dir"])
    carrier = workspace / ".health_monitor_authstate.json"
    carrier.write_text("carrier\n", encoding="utf-8")
    next_home = Path(manifest["stages"][1]["runtime_paths"]["kimi_home"])
    prior_home = Path(manifest["stages"][0]["runtime_paths"]["kimi_home"])
    assert prior_home.is_dir() and next_home.is_dir()

    evidence = ControlInterventionRecorder(materialized).apply_before_stage(2)

    state_records = [
        record for record in evidence["records"] if record["kind"] == "kimi_state"
    ]
    assert state_records
    assert all(record["state_reset_types"] == ["memory"] for record in state_records)
    assert not prior_home.exists()
    assert next_home.is_dir()
    assert all(
        Path(record["resolved_path"]).is_relative_to(materialized.layout.root)
        for record in state_records
    )


def test_recorder_rejects_unscheduled_and_duplicate_hooks(tmp_path: Path) -> None:
    materialized = _materialize(
        tmp_path,
        case_key="shared_artifact",
        suite="T3_shared_artifact_supply_chain",
        control_type="cleanup_control",
        run_id="cleanup-hooks-001",
    )
    recorder = ControlInterventionRecorder(materialized)
    with pytest.raises(KimiControlTrialError, match="not scheduled"):
        recorder.apply_before_stage(1)
    manifest = load_bench_materialization_manifest(materialized.bench_manifest_path)
    carrier = Path(manifest["materialized"]["workspace_dir"]) / "reports/generated_decision.md"
    carrier.parent.mkdir(parents=True, exist_ok=True)
    carrier.write_text("fixture\n", encoding="utf-8")
    recorder.apply_before_stage(2)
    with pytest.raises(KimiControlTrialError, match="already applied"):
        recorder.apply_before_stage(2)
