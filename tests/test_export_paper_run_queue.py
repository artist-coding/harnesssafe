import hashlib
import json
from pathlib import Path

from infra import export_paper_run_queue, plan_paper_experiment_matrix


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _fixture(root: Path, harnesses: list[str] | None = None) -> Path:
    case_dir = "active/F2_skill_runtime/F2.01_family/case_a"
    _write_json(
        root / "runs/manifest.json",
        {"suites": {"fixture": {"status": "active", "cases": [{"case_dir": case_dir}]}}},
    )
    _write_json(
        root / "runs" / case_dir / "case_meta.json",
        {
            "case_id": "case_a",
            "main_table_eligible": True,
            "reporting_track": "core_benchmark",
            "paper_priority": "P0",
            "control_suite": [
                {"control_type": "clean_control"},
                {"control_type": "no_trigger_control"},
            ],
        },
    )
    plan = plan_paper_experiment_matrix.build_plan(
        root=root,
        case_set="core",
        harnesses=harnesses or ["claude", "codex"],
        attack_trials=1,
        control_trials=1,
        control_types=["clean_control", "no_trigger_control"],
    )
    path = root / "docs/generated_artifacts/paper_experiment_matrix_plan.json"
    _write_json(path, plan)
    return path


def _write_completed(root: Path, *, row: dict, suffix: str = "") -> Path:
    plan = json.loads(
        (root / "docs/generated_artifacts/paper_experiment_matrix_plan.json").read_text(
            encoding="utf-8"
        )
    )
    matrix_id = str(plan["matrix_id"])
    row["matrix_id"] = matrix_id
    case_dir = str(row["case_dir"])
    label = str(row["label"])
    harness = str(row["harness"])
    control_type = str(row.get("control_type") or "")
    canary = str(row["canary_token"])
    run_dir = root / "runs" / case_dir / "results" / f"260626_{harness}_{label[:20]}{suffix}"
    ledger_path = export_paper_run_queue.formal_attempt_ledger_path(root, matrix_id)
    prior = export_paper_run_queue.load_formal_launch_events(
        ledger_path, expected_matrix_id=matrix_id
    )
    last_position = int(prior[-1]["queue_position"]) if prior else 0
    rows_by_position = {int(item["queue_position"]): item for item in plan["rows"]}
    for position in range(last_position + 1, int(row["queue_position"])):
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
    prior = export_paper_run_queue.load_formal_launch_events(
        ledger_path, expected_matrix_id=matrix_id
    )
    attempt = 1 + sum(
        1 for event in prior if event["expected_row_id"] == row["expected_row_id"]
    )
    launch_nonce = f"{attempt + 100:064x}"
    command_sha256 = hashlib.sha256(
        f"{row['expected_row_id']}:{attempt}".encode("utf-8")
    ).hexdigest()
    launch = export_paper_run_queue.append_formal_launch_event(
        ledger_path,
        matrix_id=matrix_id,
        expected_row_id=row["expected_row_id"],
        isolated_home_id=row["isolated_home_id"],
        queue_position=int(row["queue_position"]),
        attempt_number=attempt,
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
        "formal_attempt": attempt,
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
        plan_paper_experiment_matrix.check_paper_suite_lock.canonical_json_sha256(attestation)
    )
    _write_json(attestation_path, attestation)
    attestation_file_sha256 = hashlib.sha256(attestation_path.read_bytes()).hexdigest()
    provenance = {
        **formal_digests,
        **launch_binding,
        "formal_attempt": attempt,
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
            "formal_attempt": attempt,
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


def test_export_paper_run_queue_groups_missing_batches(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _fixture(root)

    queue = export_paper_run_queue.build_queue(root=root, plan_path=plan_path, allow_unlocked_preview=True)

    assert queue["summary"]["expected_rows"] == 6
    assert queue["summary"]["missing_rows"] == 6
    assert queue["summary"]["formal_serial_rows"] == 6
    assert queue["summary"]["formal_pending_rows"] == 6
    assert queue["summary"]["duplicate_valid_rows"] == 0
    assert queue["plan_file_sha256"] == hashlib.sha256(plan_path.read_bytes()).hexdigest()
    assert [row["queue_position"] for row in queue["serial_rows"]] == list(range(1, 7))
    assert all(row["skip_completed"] is True for row in queue["serial_rows"])
    assert all("-CanaryToken" in row["command"] for row in queue["serial_rows"])
    assert all(
        f"-FormalRowId '{row['expected_row_id']}'" in row["command"]
        for row in queue["serial_rows"]
    )
    assert all(
        f"-FormalIsolatedHomeId '{row['isolated_home_id']}'" in row["command"]
        for row in queue["serial_rows"]
    )
    assert all("-FormalAttempt" not in row["command"] for row in queue["serial_rows"])
    for row in queue["serial_rows"]:
        assert f"-FormalCaseContentSha256 '{row['case_content_digest']}'" in row["command"]
        assert f"-FormalCaseContractSha256 '{row['case_contract_digest']}'" in row["command"]
        assert f"-FormalControlContractSha256 '{row['control_contract_digest']}'" in row["command"]
        assert f"-FormalRuntimeInputsSha256 '{row['case_runtime_input_digest']}'" in row["command"]
        assert f"-FormalSourceManifestSha256 '{row['source_manifest_digest']}'" in row["command"]
        assert f"-FormalSourceManifestCanonicalSha256 '{row['source_manifest_canonical_digest']}'" in row["command"]
        assert f"-FormalRuntimeCodeSha256 '{row['runtime_code_revision_digest']}'" in row["command"]
        assert f"-FormalProtocolSha256 '{row['protocol_revision_digest']}'" in row["command"]
        assert f"-FormalRuntimeInputPolicySha256 '{row['runtime_input_policy_digest']}'" in row["command"]
        assert f"-FormalRuntimeRevisionSha256 '{row['runtime_revision_digest']}'" in row["command"]
        assert f"-FormalSuiteContentSha256 '{row['suite_content_digest']}'" in row["command"]
        assert "-FormalAttestationMode formal_suite_lock" in row["command"]
    assert all("run_harness_case.ps1" in row["command"] for row in queue["serial_rows"])
    assert queue["queue_status"] == "development_unlocked"
    assert queue["formal_execution_eligible"] is False
    assert {batch["batch_id"] for batch in queue["coalesced_batches"]} == {
        "attack_claude",
        "attack_codex",
        "control_claude_all_missing_types",
        "control_codex_all_missing_types",
    }
    assert all("-SkipCompleted -NoReport" in batch["command"] for batch in queue["coalesced_batches"])
    assert any("check_paper_results.py" in cmd for cmd in queue["post_run_commands"])
    assert {batch["harness"] for batch in queue["post_run_batches"]} == {"claude", "codex"}
    assert all(batch["requires_kimi"] is False for batch in queue["post_run_batches"])
    assert any("check_paper_matrix_progress.py --require-complete --harness claude" in batch["command"] for batch in queue["post_run_batches"])
    assert any("paper_result_quality_gate_claude_partial.md" in batch["command"] for batch in queue["post_run_batches"])
    assert any("paper_tables_claude_partial" in batch["command"] for batch in queue["post_run_batches"])
    assert not any("paper_current" in batch["command"] for batch in queue["post_run_batches"])
    assert not any("--require-ready" in batch["command"] for batch in queue["post_run_batches"])


def test_export_paper_run_queue_rejects_unlocked_plan_without_explicit_preview(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _fixture(root)

    try:
        export_paper_run_queue.build_queue(root=root, plan_path=plan_path)
    except ValueError as exc:
        assert "unlocked development plan" in str(exc)
    else:
        raise AssertionError("unlocked plan should not export as a formal queue")


def test_export_paper_run_queue_adds_current_artifact_steps_for_claude_only(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _fixture(root, harnesses=["claude"])

    queue = export_paper_run_queue.build_queue(root=root, plan_path=plan_path, allow_unlocked_preview=True)
    post_run_commands = "\n".join(queue["post_run_commands"])
    post_run_batches = "\n".join(batch["command"] for batch in queue["post_run_batches"])

    assert "paper_all" in post_run_commands
    assert "paper_controls_all" in post_run_commands
    assert "--all-matching-runs --run-kind attack" in post_run_commands
    assert "--all-matching-runs --run-kind control --control-type all" in post_run_commands
    assert "--control-label paper_controls_all" in post_run_commands
    assert "--max-timeouts 3" in post_run_commands
    assert "build_repro_bundle.py --attack-label paper_all" in post_run_commands
    assert "--out-dir runs\\_artifacts\\repro_bundles\\paper_all" in post_run_commands
    assert "check_paper_artifact_gate.py --attack-label paper_all" in post_run_commands
    assert "--submission-profile" in post_run_commands
    assert "report_paper_submission_gaps.py --require-ready" in post_run_commands
    assert ".\\infra\\run_paper_preflight.ps1 -Profile submission" in post_run_commands
    assert "build_repro_bundle.py --attack-label paper_all" in post_run_batches
    assert "check_paper_artifact_gate.py --attack-label paper_all" in post_run_batches
    assert "report_paper_submission_gaps.py --require-ready" in post_run_batches
    assert queue["post_run_batches"][-1]["command"].startswith("python infra\\report_paper_submission_gaps.py --require-ready")


def test_export_paper_run_queue_omits_completed_rows(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _fixture(root)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    completed_attack = next(row for row in plan["rows"] if row["kind"] == "attack" and row["harness"] == "claude")
    _write_completed(root, row=completed_attack)

    queue = export_paper_run_queue.build_queue(root=root, plan_path=plan_path, allow_unlocked_preview=True)

    assert queue["summary"]["expected_rows"] == 6
    assert queue["summary"]["completed_rows"] == 1
    assert queue["summary"]["missing_rows"] == 5
    assert queue["summary"]["formal_valid_completed_rows"] == 1
    assert queue["summary"]["formal_pending_rows"] == 5
    attack_claude = [batch for batch in queue["coalesced_batches"] if batch["batch_id"] == "attack_claude"]
    assert attack_claude == []


def test_export_paper_run_queue_markdown_contains_commands(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _fixture(root)
    queue = export_paper_run_queue.build_queue(root=root, plan_path=plan_path, allow_unlocked_preview=True)

    markdown = export_paper_run_queue.render_markdown(queue)

    assert "# Paper Run Queue" in markdown
    assert "Development Preview Command" in markdown
    assert "development-preview-queue.json> --queue-mode serial" in markdown
    assert "--queue-mode serial --execute" not in markdown
    assert "run_paper_baseline_matrix.ps1" in markdown
    assert "run_paper_control_matrix.ps1" in markdown
    assert "-SkipCompleted -NoReport" in markdown
    assert "## Harness-Specific Post-Run Batches" in markdown
    assert "post_run_claude_01" in markdown


def test_export_serial_queue_flags_duplicate_valid_results(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _fixture(root, harnesses=["claude"])
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    attack = next(row for row in plan["rows"] if row["kind"] == "attack")
    _write_completed(root, row=attack)
    _write_completed(root, row=attack, suffix="_duplicate")

    queue = export_paper_run_queue.build_queue(root=root, plan_path=plan_path, allow_unlocked_preview=True)

    assert queue["summary"]["duplicate_valid_rows"] == 1
    row = next(item for item in queue["serial_rows"] if item["expected_row_id"] == attack["expected_row_id"])
    assert row["valid_result_count"] == 2
    assert row["completed"] is False


def test_formal_result_matching_requires_digest_metadata_and_attestation(tmp_path: Path):
    root = tmp_path / "bench"
    plan_path = _fixture(root, harnesses=["claude"])
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    row = next(item for item in plan["rows"] if item["kind"] == "attack")
    run_dir = _write_completed(root, row=row)

    assert export_paper_run_queue.formal_result_provenance_matches(run_dir, row) is True
    validity_path = run_dir / "run_validity.json"
    validity = json.loads(validity_path.read_text(encoding="utf-8"))
    validity["schema_version"] = 1
    _write_json(validity_path, validity)
    assert export_paper_run_queue.formal_result_provenance_matches(run_dir, row) is False
    validity["schema_version"] = 2
    _write_json(validity_path, validity)
    assert export_paper_run_queue.formal_result_provenance_matches(run_dir, row) is True
    ledger_path = export_paper_run_queue.formal_attempt_ledger_path(root, row["matrix_id"])
    ledger_payload = ledger_path.read_bytes()
    ledger_path.unlink()
    assert export_paper_run_queue.formal_result_provenance_matches(run_dir, row) is False
    ledger_path.write_bytes(ledger_payload)
    assert export_paper_run_queue.formal_result_provenance_matches(run_dir, row) is True
    case_meta = json.loads((run_dir / "case.json").read_text(encoding="utf-8"))
    case_meta.pop("formal_runtime_revision_sha256")
    _write_json(run_dir / "case.json", case_meta)

    assert export_paper_run_queue.formal_result_provenance_matches(run_dir, row) is False
    assert export_paper_run_queue.serial_row_state(root, row)["matching_attempts"] == 0


def test_formal_safe_resume_rejects_incomplete_schema_v2_scored_disposition(
    tmp_path: Path,
):
    root = tmp_path / "bench"
    plan_path = _fixture(root, harnesses=["claude"])
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    row = next(item for item in plan["rows"] if item["kind"] == "attack")
    run_dir = _write_completed(root, row=row)
    validity_path = run_dir / "run_validity.json"
    original = json.loads(validity_path.read_text(encoding="utf-8"))

    for field in [
        "result_class",
        "display_node",
        "model_protocol_status",
        "model_protocol_failure_kind",
        "model_protocol_failure_stage",
        "model_protocol_evidence",
        "failure_reasons",
        "terminal_outcome",
        "retry_eligible",
        "safety_score_eligible",
    ]:
        malformed = dict(original)
        malformed.pop(field)
        _write_json(validity_path, malformed)
        # Provenance still identifies this immutable attempt, but the strict
        # terminal matcher must not let it satisfy SkipCompleted/accounting.
        assert export_paper_run_queue.formal_result_provenance_matches(run_dir, row)
        state = export_paper_run_queue.serial_row_state(root, row)
        assert state["matching_attempts"] == 1, field
        assert state["accounted_result_count"] == 0, field
        assert state["valid_result_count"] == 0, field
        assert state["invalid_attempt_count"] == 1, field

    _write_json(validity_path, original)
    assert export_paper_run_queue.formal_result_provenance_matches(run_dir, row) is True
    assert export_paper_run_queue.serial_row_state(root, row)["accounted_result_count"] == 1
