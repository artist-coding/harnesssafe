import json
import hashlib
import os
from pathlib import Path
import time

from infra import check_paper_matrix_progress, export_paper_run_queue, plan_paper_experiment_matrix


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_case(root: Path, case_dir: str) -> None:
    _write_json(
        root / "runs" / case_dir / "case_meta.json",
        {
            "case_id": "case_a",
            "main_table_eligible": True,
            "reporting_track": "core_benchmark",
            "paper_priority": "P0",
            "control_suite": [{"control_type": "clean_control"}],
        },
    )


def _write_fixture_plan(root: Path) -> Path:
    case_dir = "active/F2_skill_runtime/F2.01_family/case_a"
    _write_json(
        root / "runs/manifest.json",
        {
            "suites": {
                "active_suite": {
                    "status": "active",
                    "cases": [{"case_dir": case_dir}],
                }
            }
        },
    )
    _write_case(root, case_dir)
    plan = plan_paper_experiment_matrix.build_plan(
        root=root,
        case_set="core",
        harnesses=["claude"],
        attack_trials=1,
        control_trials=1,
        control_types=["clean_control"],
    )
    plan_path = root / "docs/generated_artifacts/paper_experiment_matrix_plan.json"
    _write_json(plan_path, plan)
    return plan_path


def _write_two_harness_plan(root: Path) -> Path:
    case_dir = "active/F2_skill_runtime/F2.01_family/case_a"
    _write_json(
        root / "runs/manifest.json",
        {
            "suites": {
                "active_suite": {
                    "status": "active",
                    "cases": [{"case_dir": case_dir}],
                }
            }
        },
    )
    _write_case(root, case_dir)
    plan = plan_paper_experiment_matrix.build_plan(
        root=root,
        case_set="core",
        harnesses=["claude", "codex"],
        attack_trials=1,
        control_trials=1,
        control_types=["clean_control"],
    )
    plan_path = root / "docs/generated_artifacts/paper_experiment_matrix_plan.json"
    _write_json(plan_path, plan)
    return plan_path


def _write_result(
    root: Path,
    *,
    case_dir: str,
    run_dir_name: str,
    run_label: str,
    kind: str,
    harness: str = "claude",
    control_type: str = "",
    oracle: bool = True,
    valid: bool = True,
    expected: dict | None = None,
) -> None:
    run_dir = root / "runs" / case_dir / "results" / run_dir_name
    _write_json(
        run_dir / "case.json",
        {
            "harness": harness,
            "run_label": run_label,
            "case_dir": case_dir,
            "is_control_run": kind == "control",
            "control_type": control_type,
            "formal_row_id": str((expected or {}).get("expected_row_id") or ""),
            "formal_attempt": 1,
            "formal_isolated_home_id": str((expected or {}).get("isolated_home_id") or ""),
            "canary_token": str((expected or {}).get("canary_token") or ""),
            "canary_token_sha256": hashlib.sha256(
                str((expected or {}).get("canary_token") or "").encode("utf-8")
            ).hexdigest(),
            "model": str((expected or {}).get("runtime_model") or ""),
            "permission_profile": str((expected or {}).get("permission_profile") or ""),
            "isolation_mode": str((expected or {}).get("isolation_mode") or ""),
            "timeout_sec": int((expected or {}).get("timeout_sec") or 0),
        },
    )
    if oracle:
        _write_json(run_dir / "oracle.json", {"evaluation": {"progress_node": "N0"}})
        _write_json(run_dir / "run_validity.json", {"valid": valid, "status": "completed" if valid else "invalid"})


def _model_protocol_validity(*, expected_path: str = "expected.md") -> dict:
    stage_name = "producer"
    failure_reason = "boundary_artifact_missing"
    return {
        "schema_version": 2,
        "valid": False,
        "status": "model_protocol_incomplete",
        "result_class": "model_protocol_deviation",
        "display_node": "N-1",
        "model_protocol_status": "deviated",
        "model_protocol_failure_kind": "required_artifact_path_mismatch",
        "model_protocol_failure_stage": stage_name,
        "model_protocol_evidence": [
            {
                "attribution": "model_tool_argument",
                "failure_kind": "required_artifact_path_mismatch",
                "stage_name": stage_name,
                "stage_index": 1,
                "expected_path": expected_path,
                "observed_path": expected_path.replace("expected", "expectd").replace(
                    "produced", "proced"
                ),
                "observed_path_normalized": expected_path.replace(
                    "expected", "expectd"
                ).replace("produced", "proced").lower(),
                "tool_name": "Write",
                "tool_use_id": "tool-1",
                "tool_result_success": True,
                "filename_edit_distance": 1 if "expected" in expected_path else 2,
            }
        ],
        "terminal_outcome": True,
        "retry_eligible": False,
        "safety_score_eligible": False,
        "formal_asr_eligible": False,
        "failure_reasons": [failure_reason],
        "expected_stage_count": 1,
        "completed_stage_count": 1,
        "fixture_health": {"valid": True},
        "global_config_touched": False,
        "global_config_external_drift": False,
        "global_config_inventory_complete": True,
        "control_intervention_execution_valid": True,
        "mcp_runtime_health": {"valid": True},
        "analyzer_exit_code": 0,
        "oracle_present": True,
        "oracle_valid": True,
        "materialization_attestation_untampered": True,
        "runner_error": "",
        "stages": [
            {
                "stage_name": stage_name,
                "stage_index": 1,
                "valid": False,
                "exit_code": 0,
                "timed_out": False,
                "failure_reasons": [failure_reason],
                "required_artifact_paths": [expected_path],
                "trace_result_error": False,
                "unknown_command": False,
                "trace_error_event": False,
                "trace_result_success": True,
                "trace_api_error": False,
                "trace_terminal_completed": True,
                "trace_stderr_empty": True,
                "mcp_runtime_health": {"valid": True},
            }
        ],
    }


def _mark_plan_formal_locked(plan_path: Path) -> dict:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["plan_status"] = "formal_locked"
    plan["formal_execution_eligible"] = True
    _write_json(plan_path, plan)
    return plan


def _write_strict_formal_result(root: Path, row: dict) -> Path:
    plan = json.loads(
        (root / "docs/generated_artifacts/paper_experiment_matrix_plan.json").read_text(
            encoding="utf-8"
        )
    )
    matrix_id = str(plan["matrix_id"])
    ledger_path = export_paper_run_queue.formal_attempt_ledger_path(root, matrix_id)
    rows_by_position = {int(item["queue_position"]): item for item in plan["rows"]}
    for position in range(1, int(row["queue_position"])):
        skipped = rows_by_position[position]
        export_paper_run_queue.append_formal_launch_event(
            ledger_path,
            matrix_id=matrix_id,
            expected_row_id=skipped["expected_row_id"],
            isolated_home_id=skipped["isolated_home_id"],
            queue_position=position,
            attempt_number=1,
            command_sha256=hashlib.sha256(f"seed-command:{position}".encode()).hexdigest(),
            launch_nonce=hashlib.sha256(f"seed-nonce:{position}".encode()).hexdigest(),
        )
    launch_nonce = hashlib.sha256(
        f"strict-nonce:{row['expected_row_id']}".encode()
    ).hexdigest()
    command_sha256 = hashlib.sha256(
        f"strict-command:{row['expected_row_id']}".encode()
    ).hexdigest()
    launch = export_paper_run_queue.append_formal_launch_event(
        ledger_path,
        matrix_id=matrix_id,
        expected_row_id=row["expected_row_id"],
        isolated_home_id=row["isolated_home_id"],
        queue_position=int(row["queue_position"]),
        attempt_number=1,
        command_sha256=command_sha256,
        launch_nonce=launch_nonce,
    )
    launch_binding = {
        "formal_matrix_id": matrix_id,
        "formal_queue_position": int(row["queue_position"]),
        "formal_launch_nonce": launch_nonce,
        "formal_launch_command_sha256": command_sha256,
        "formal_launch_event_sha256": launch["event_sha256"],
    }
    case_dir = str(row["case_dir"])
    label = str(row["label"])
    harness = str(row["harness"])
    control_type = str(row.get("control_type") or "")
    canary = str(row["canary_token"])
    run_dir = root / "runs" / case_dir / "results" / f"strict_{harness}_{label[:20]}"
    formal_digests = {
        "formal_case_content_sha256": row["case_content_digest"],
        "formal_case_contract_sha256": row["case_contract_digest"],
        "formal_control_contract_sha256": row["control_contract_digest"],
        "formal_runtime_inputs_sha256": row["case_runtime_input_digest"],
        "formal_source_manifest_sha256": row["source_manifest_digest"],
        "formal_source_manifest_canonical_sha256": row[
            "source_manifest_canonical_digest"
        ],
        "formal_runtime_code_sha256": row["runtime_code_revision_digest"],
        "formal_protocol_sha256": row["protocol_revision_digest"],
        "formal_runtime_input_policy_sha256": row["runtime_input_policy_digest"],
        "formal_runtime_revision_sha256": row["runtime_revision_digest"],
        "formal_suite_content_sha256": row["suite_content_digest"],
    }
    attestation_path = (run_dir / "materialization_attestation.json").resolve()
    case_projection = {
        "case_meta_canonical_sha256": row["case_contract_digest"],
        "control_contracts_canonical_sha256": row["case_control_contract_digest"],
        "runtime_inputs_tree_sha256": row["case_runtime_input_digest"],
        "case_content_sha256": row["case_content_digest"],
    }
    runtime_projection = {
        "runtime_code_sha256": row["runtime_code_revision_digest"],
        "protocol_sha256": row["protocol_revision_digest"],
        "runtime_input_policy_sha256": row["runtime_input_policy_digest"],
        "runtime_revision_sha256": row["runtime_revision_digest"],
    }
    expected_attestation = {
        "case_content_sha256": row["case_content_digest"],
        "case_contract_digest": row["case_contract_digest"],
        "control_contract_digest": row["control_contract_digest"],
        "runtime_inputs_sha256": row["case_runtime_input_digest"],
        "source_manifest_sha256": row["source_manifest_digest"],
        "source_manifest_canonical_sha256": row["source_manifest_canonical_digest"],
        "runtime_code_sha256": row["runtime_code_revision_digest"],
        "protocol_sha256": row["protocol_revision_digest"],
        "runtime_input_policy_sha256": row["runtime_input_policy_digest"],
        "runtime_revision_sha256": row["runtime_revision_digest"],
        "suite_content_sha256": row["suite_content_digest"],
    }
    attestation = {
        "schema_version": "1.0.0",
        "generated_at": "2026-07-13T00:00:00",
        "formal_row_id": row["expected_row_id"],
        "attestation_mode": "formal_suite_lock",
        "formal_attempt": 1,
        "formal_isolated_home_id": row["isolated_home_id"],
        **launch_binding,
        "all_verified": True,
        "paths": {"attestation": str(attestation_path), "repo_root": str(root.resolve())},
        "expected": expected_attestation,
        "observed": {
            "source_before": case_projection,
            "copied_pre_injection": case_projection,
            "source_after": case_projection,
            "runtime_before": runtime_projection,
            "runtime_after": runtime_projection,
            "suite_lock_content_sha256": row["suite_content_digest"],
        },
    }
    attestation["attestation_sha256"] = (
        plan_paper_experiment_matrix.check_paper_suite_lock.canonical_json_sha256(
            attestation
        )
    )
    _write_json(attestation_path, attestation)
    attestation_file_sha256 = hashlib.sha256(attestation_path.read_bytes()).hexdigest()
    provenance = {
        **formal_digests,
        **launch_binding,
        "formal_attempt": 1,
        "formal_attestation_mode": "formal_suite_lock",
        "materialization_attestation_path": str(attestation_path),
        "materialization_all_verified": True,
        "materialization_attestation_sha256": attestation["attestation_sha256"],
        "materialization_attestation_initial_file_sha256": attestation_file_sha256,
        "materialization_attestation_final_file_sha256": attestation_file_sha256,
        "materialization_attestation_untampered": True,
    }
    _write_json(
        run_dir / "case.json",
        {
            "run_label": label,
            "harness": harness,
            "is_control_run": bool(control_type),
            "control_type": control_type,
            "formal_row_id": row["expected_row_id"],
            "formal_isolated_home_id": row["isolated_home_id"],
            "formal_attempt": 1,
            "canary_token": canary,
            "canary_token_sha256": hashlib.sha256(canary.encode("utf-8")).hexdigest(),
            "model": row["runtime_model"],
            "permission_profile": row["permission_profile"],
            "isolation_mode": row["isolation_mode"],
            "timeout_sec": row["timeout_sec"],
            **provenance,
        },
    )
    _write_json(run_dir / "oracle.json", {"evaluation": {"progress_node": "N0"}})
    _write_json(
        run_dir / "run_validity.json",
        {
            "schema_version": 2,
            "valid": True,
            "status": "completed",
            "result_class": "scored",
            "display_node": "",
            "model_protocol_status": "completed",
            "model_protocol_failure_kind": "",
            "model_protocol_failure_stage": "",
            "model_protocol_evidence": [],
            "terminal_outcome": True,
            "retry_eligible": False,
            "safety_score_eligible": True,
            "failure_reasons": [],
            "expected_stage_count": 1,
            "completed_stage_count": 1,
            "fixture_health": {"valid": True},
            "global_config_touched": False,
            "global_config_external_drift": False,
            "global_config_inventory_complete": True,
            "control_intervention_execution_valid": True,
            "mcp_runtime_health": {"valid": True},
            "analyzer_exit_code": 0,
            "oracle_present": True,
            "oracle_valid": True,
            "runner_error": "",
            "stages": [
                {
                    "stage_name": "single",
                    "stage_index": 1,
                    "valid": True,
                    "exit_code": 0,
                    "timed_out": False,
                    "failure_reasons": [],
                    "trace_result_error": False,
                    "unknown_command": False,
                    "trace_error_event": False,
                    "trace_result_success": True,
                    "trace_api_error": False,
                    "trace_terminal_completed": True,
                    "trace_stderr_empty": True,
                    "mcp_runtime_health": {"valid": True},
                }
            ],
            **provenance,
        },
    )
    return run_dir


def test_matrix_progress_reports_completed_and_missing_rows(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _write_fixture_plan(root)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    attack = next(row for row in plan["rows"] if row["kind"] == "attack")
    control = next(row for row in plan["rows"] if row["kind"] == "control")
    _write_result(
        root,
        case_dir=attack["case_dir"],
        run_dir_name="260626_claude_attack",
        run_label=attack["label"],
        kind="attack",
        expected=attack,
    )
    _write_result(
        root,
        case_dir=control["case_dir"],
        run_dir_name="260626_claude_control_no_oracle",
        run_label=control["label"],
        kind="control",
        control_type="clean_control",
        oracle=False,
        expected=control,
    )
    stale_time = time.time() - 7200
    stale_dir = root / "runs" / control["case_dir"] / "results" / "260626_claude_control_no_oracle"
    os.utime(stale_dir, (stale_time, stale_time))
    os.utime(stale_dir / "case.json", (stale_time, stale_time))

    report = check_paper_matrix_progress.build_progress_report(root=root, plan_path=plan_path)

    assert report["summary"]["expected_rows"] == 2
    assert report["summary"]["completed_rows"] == 1
    assert report["summary"]["matched_without_oracle_rows"] == 1
    assert report["summary"]["in_progress_without_oracle_rows"] == 0
    assert report["summary"]["stale_without_oracle_rows"] == 1
    assert report["summary"]["unmatched_rows"] == 0
    assert report["complete"] is False
    assert report["missing_preview"][0]["kind"] == "control"
    assert any(item["message"] == "some matching result directories do not have oracle.json" for item in report["issues"])


def test_matrix_progress_treats_recent_missing_oracle_as_in_progress(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _write_fixture_plan(root)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    control = next(row for row in plan["rows"] if row["kind"] == "control")
    _write_result(
        root,
        case_dir=control["case_dir"],
        run_dir_name="260626_claude_control_recent_no_oracle",
        run_label=control["label"],
        kind="control",
        control_type="clean_control",
        oracle=False,
        expected=control,
    )

    report = check_paper_matrix_progress.build_progress_report(root=root, plan_path=plan_path)

    assert report["summary"]["matched_without_oracle_rows"] == 1
    assert report["summary"]["in_progress_without_oracle_rows"] == 1
    assert report["summary"]["stale_without_oracle_rows"] == 0
    recent_row = next(row for row in report["rows"] if "recent_no_oracle" in row["selected_run_dir"])
    assert recent_row["selected_in_progress"] is True
    assert not any(item["message"] == "some matching result directories do not have oracle.json" for item in report["issues"])


def test_matrix_progress_reports_unmatched_rows(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _write_fixture_plan(root)

    report = check_paper_matrix_progress.build_progress_report(root=root, plan_path=plan_path)

    assert report["summary"]["expected_rows"] == 2
    assert report["summary"]["completed_rows"] == 0
    assert report["summary"]["unmatched_rows"] == 2
    assert report["missing_preview"][0]["label"].startswith("paper_all_row_")


def test_formal_progress_rejects_legacy_result_without_exact_row_binding(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _write_fixture_plan(root)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    attack = next(row for row in plan["rows"] if row["kind"] == "attack")
    _write_result(
        root,
        case_dir=attack["case_dir"],
        run_dir_name="260626_claude_legacy_same_label",
        run_label=attack["label"],
        kind="attack",
        expected=None,
    )

    report = check_paper_matrix_progress.build_progress_report(root=root, plan_path=plan_path)

    attack_row = next(row for row in report["rows"] if row["kind"] == "attack")
    assert attack_row["matched_runs"] == 0
    assert attack_row["completed"] is False


def test_formal_locked_progress_rejects_missing_materialization_attestation(
    tmp_path: Path, monkeypatch
):
    root = tmp_path / "bench"
    plan_path = _write_fixture_plan(root)
    plan = _mark_plan_formal_locked(plan_path)
    attack = next(row for row in plan["rows"] if row["kind"] == "attack")
    _write_result(
        root,
        case_dir=attack["case_dir"],
        run_dir_name="260626_claude_formal_missing_attestation",
        run_label=attack["label"],
        kind="attack",
        expected=attack,
    )
    monkeypatch.setattr(
        check_paper_matrix_progress.plan_paper_experiment_matrix,
        "validate_plan",
        lambda *args, **kwargs: [],
    )

    report = check_paper_matrix_progress.build_progress_report(
        root=root, plan_path=plan_path
    )

    attack_row = next(row for row in report["rows"] if row["kind"] == "attack")
    assert attack_row["matched_runs"] == 0
    assert attack_row["completed"] is False


def test_formal_locked_progress_rejects_tampered_materialization_attestation(
    tmp_path: Path, monkeypatch
):
    root = tmp_path / "bench"
    plan_path = _write_fixture_plan(root)
    plan = _mark_plan_formal_locked(plan_path)
    attack = next(row for row in plan["rows"] if row["kind"] == "attack")
    run_dir = _write_strict_formal_result(root, attack)
    monkeypatch.setattr(
        check_paper_matrix_progress.plan_paper_experiment_matrix,
        "validate_plan",
        lambda *args, **kwargs: [],
    )

    before = check_paper_matrix_progress.build_progress_report(
        root=root, plan_path=plan_path
    )
    before_attack = next(row for row in before["rows"] if row["kind"] == "attack")
    assert before_attack["matched_runs"] == 1
    assert before_attack["completed"] is True

    attestation_path = run_dir / "materialization_attestation.json"
    attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    attestation["observed"]["runtime_after"]["protocol_sha256"] = "0" * 64
    _write_json(attestation_path, attestation)

    after = check_paper_matrix_progress.build_progress_report(
        root=root, plan_path=plan_path
    )
    after_attack = next(row for row in after["rows"] if row["kind"] == "attack")
    assert after_attack["matched_runs"] == 0
    assert after_attack["completed"] is False


def test_matrix_progress_does_not_complete_an_oracle_with_invalid_run_validity(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _write_fixture_plan(root)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    attack = next(row for row in plan["rows"] if row["kind"] == "attack")
    _write_result(
        root,
        case_dir=attack["case_dir"],
        run_dir_name="260626_claude_attack_invalid",
        run_label=attack["label"],
        kind="attack",
        valid=False,
        expected=attack,
    )

    report = check_paper_matrix_progress.build_progress_report(root=root, plan_path=plan_path)

    assert report["summary"]["oracle_completed_rows"] == 1
    assert report["summary"]["completed_rows"] == 0
    assert report["summary"]["execution_invalid_or_unvalidated_rows"] == 2
    assert report["complete"] is False
    invalid_row = next(row for row in report["rows"] if row["kind"] == "attack")
    assert invalid_row["completed"] is False
    assert invalid_row["execution_valid_completed"] is False


def test_matrix_progress_accounts_for_terminal_model_protocol_outcome(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _write_fixture_plan(root)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    attack = next(row for row in plan["rows"] if row["kind"] == "attack")
    run_name = "260626_claude_attack_model_protocol"
    _write_result(
        root,
        case_dir=attack["case_dir"],
        run_dir_name=run_name,
        run_label=attack["label"],
        kind="attack",
        valid=False,
        expected=attack,
    )
    validity_path = root / "runs" / attack["case_dir"] / "results" / run_name / "run_validity.json"
    _write_json(
        validity_path,
        _model_protocol_validity(expected_path="handoff/produced_context.md"),
    )

    report = check_paper_matrix_progress.build_progress_report(root=root, plan_path=plan_path)

    assert report["summary"]["completed_rows"] == 1
    assert report["summary"]["model_protocol_terminal_rows"] == 1
    assert report["summary"]["execution_valid_completed_rows"] == 0
    assert report["summary"]["execution_invalid_or_unvalidated_rows"] == 1
    attack_row = next(row for row in report["rows"] if row["kind"] == "attack")
    assert attack_row["completed"] is True
    assert attack_row["model_protocol_terminal"] is True
    assert attack_row["execution_valid_completed"] is False


def test_matrix_progress_warns_on_duplicate_matching_runs(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _write_fixture_plan(root)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    attack = next(row for row in plan["rows"] if row["kind"] == "attack")
    for suffix in ["a", "b"]:
        _write_result(
            root,
            case_dir=attack["case_dir"],
            run_dir_name=f"260626_claude_attack_{suffix}",
            run_label=attack["label"],
            kind="attack",
            expected=attack,
        )
    duplicate_protocol_path = (
        root
        / "runs"
        / attack["case_dir"]
        / "results"
        / "260626_claude_attack_b"
        / "run_validity.json"
    )
    _write_json(
        duplicate_protocol_path,
        _model_protocol_validity(),
    )

    report = check_paper_matrix_progress.build_progress_report(root=root, plan_path=plan_path)

    assert report["summary"]["duplicate_expected_rows"] == 1
    assert report["summary"]["extra_matching_runs"] == 1
    assert report["summary"]["duplicate_accounted_expected_rows"] == 1
    assert report["summary"]["execution_invalid_or_unvalidated_rows"] == 2
    assert report["complete"] is False
    assert any(item["message"] == "multiple result directories match at least one expected row" for item in report["issues"])


def test_matrix_progress_can_filter_to_one_harness(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _write_two_harness_plan(root)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    for row in [item for item in plan["rows"] if item["harness"] == "claude"]:
        _write_result(
            root,
            case_dir=row["case_dir"],
            run_dir_name=f"260626_claude_{row['kind']}_{row.get('control_type') or 'attack'}",
            run_label=row["label"],
            kind=row["kind"],
            harness="claude",
            control_type=row.get("control_type", ""),
            expected=row,
        )

    full = check_paper_matrix_progress.build_progress_report(root=root, plan_path=plan_path)
    claude = check_paper_matrix_progress.build_progress_report(
        root=root,
        plan_path=plan_path,
        harnesses=["claude"],
    )

    assert full["summary"]["expected_rows"] == 4
    assert full["summary"]["completed_rows"] == 2
    assert full["complete"] is False
    assert claude["summary"]["expected_rows"] == 2
    assert claude["summary"]["completed_rows"] == 2
    assert claude["complete"] is True
    assert claude["filtered"] is True
    assert claude["harnesses"] == ["claude"]


def test_matrix_progress_markdown_contains_summary(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _write_fixture_plan(root)
    report = check_paper_matrix_progress.build_progress_report(root=root, plan_path=plan_path)

    markdown = check_paper_matrix_progress.render_markdown(report)

    assert "# Paper Matrix Progress" in markdown
    assert "expected_rows: `2`" in markdown
    assert "harnesses: `claude`" in markdown
    assert "## Missing Preview" in markdown


def test_matrix_progress_uses_null_rate_for_empty_filtered_population(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _write_fixture_plan(root)

    report = check_paper_matrix_progress.build_progress_report(
        root=root,
        plan_path=plan_path,
        harnesses=["not-in-plan"],
    )
    markdown = check_paper_matrix_progress.render_markdown(report)

    assert report["summary"]["expected_rows"] == 0
    assert report["summary"]["completion_rate"] is None
    assert "completion_rate: `n/a`" in markdown
    assert "completion_rate: `0.000`" not in markdown
