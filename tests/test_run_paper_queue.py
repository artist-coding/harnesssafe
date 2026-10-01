import json
import hashlib
from pathlib import Path

from infra import run_paper_queue


def _write_queue(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "matrix_id": "m123",
                "case_set": "core",
                "summary": {"expected_rows": 6, "completed_rows": 0, "missing_rows": 6},
                "coalesced_batches": [
                    {
                        "batch_id": "attack_claude",
                        "kind": "attack",
                        "harness": "claude",
                        "missing_rows": 2,
                        "command": "echo attack_claude",
                    },
                    {
                        "batch_id": "control_claude_all_missing_types",
                        "kind": "control",
                        "harness": "claude",
                        "control_types": ["clean_control"],
                        "missing_rows": 4,
                        "command": "echo control_claude",
                    },
                ],
                "batches": [
                    {
                        "batch_id": "control_claude_clean_control",
                        "kind": "control",
                        "harness": "claude",
                        "control_types": ["clean_control"],
                        "missing_rows": 4,
                        "command": "echo clean",
                    }
                ],
                "post_run_commands": ["echo report", "echo gate"],
                "post_run_batches": [
                    {
                        "batch_id": "post_run_claude_01",
                        "kind": "post_run",
                        "harness": "claude",
                        "missing_rows": 0,
                        "requires_kimi": False,
                        "command": "echo claude_report",
                    },
                    {
                        "batch_id": "post_run_codex_01",
                        "kind": "post_run",
                        "harness": "codex",
                        "missing_rows": 0,
                        "requires_kimi": False,
                        "command": "echo codex_report",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )


def _write_codex_queue(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "matrix_id": "m123",
                "case_set": "core",
                "summary": {"expected_rows": 1, "completed_rows": 0, "missing_rows": 1},
                "coalesced_batches": [
                    {
                        "batch_id": "attack_codex",
                        "kind": "attack",
                        "harness": "codex",
                        "missing_rows": 1,
                        "command": (
                            ".\\infra\\run_paper_baseline_matrix.ps1 "
                            "-Harnesses codex -KimiModel kimi-k2.6"
                        ),
                    }
                ],
                "batches": [],
                "post_run_commands": [],
            }
        ),
        encoding="utf-8",
    )


def _write_serial_queue(path: Path, *, rows: int = 3) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serial_rows = [
        {
            "batch_id": f"expected_{index:02d}",
            "expected_row_id": f"expected_{index:02d}",
            "queue_position": index,
            "kind": "attack" if index % 2 else "control",
            "control_type": "" if index % 2 else "clean_control",
            "control_types": [] if index % 2 else ["clean_control"],
            "harness": "claude",
            "case_dir": f"active/fixture/case_{index:03d}",
            "label": f"paper_row_{index:02d}",
            "isolated_home_id": f"home_expected_{index:02d}",
            "skip_completed": True,
            "missing_rows": 1,
            "max_attempts": 3,
            "command": (
                f"echo serial_{index:02d} "
                f"-FormalRowId 'expected_{index:02d}' "
                f"-FormalIsolatedHomeId 'home_expected_{index:02d}'"
            ),
        }
        for index in range(1, rows + 1)
    ]
    path.write_text(
        json.dumps(
            {
                "root": str(path.parent),
                "matrix_id": "a" * 16,
                "case_set": "all",
                "summary": {"expected_rows": rows, "completed_rows": 0, "missing_rows": rows},
                "execution_contract": {"max_parallel_rows": 1},
                "serial_rows": serial_rows,
                "coalesced_batches": [],
                "batches": [],
                "post_run_commands": [],
            }
        ),
        encoding="utf-8",
    )


def _ready(require_kimi: bool):
    return {"ready": True, "blockers": [], "warnings": [], "require_kimi": require_kimi}


def test_run_paper_queue_selects_coalesced_commands_with_post_run(tmp_path: Path):
    queue_path = tmp_path / "paper_run_queue.json"
    _write_queue(queue_path)
    queue = run_paper_queue.load_json(queue_path)

    commands = run_paper_queue.select_commands(queue, queue_mode="coalesced", include_post_run=True)

    assert [item["batch_id"] for item in commands] == [
        "attack_claude",
        "control_claude_all_missing_types",
        "post_run_01",
        "post_run_02",
    ]
    assert commands[0]["index"] == 1
    assert commands[-1]["index"] == 4


def test_run_paper_queue_selects_formal_rows_in_queue_position_order(tmp_path: Path):
    queue_path = tmp_path / "serial_queue.json"
    _write_serial_queue(queue_path)
    queue = run_paper_queue.load_json(queue_path)

    commands = run_paper_queue.select_commands(queue, queue_mode="serial")

    assert [item["expected_row_id"] for item in commands] == [
        "expected_01",
        "expected_02",
        "expected_03",
    ]
    assert [item["queue_position"] for item in commands] == [1, 2, 3]
    assert all(item["source"] == "serial" for item in commands)


def test_formal_serial_queue_rejects_partial_row_set(tmp_path: Path):
    queue_path = tmp_path / "serial_queue.json"
    _write_serial_queue(queue_path, rows=1)
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["queue_status"] = "formal_locked"
    queue["formal_execution_eligible"] = True
    queue["execution_contract"].update(
        {
            "row_count": 2296,
            "case_block_count": 328,
            "queue_seed": run_paper_queue.plan_paper_experiment_matrix.DEFAULT_QUEUE_SEED,
        }
    )

    issues = run_paper_queue.validate_serial_queue_structure(queue)

    assert "formal serial queue must contain exactly 2,296 rows" in issues
    assert "formal serial queue must contain 984 attack and 1,312 control rows" in issues
    assert "formal serial queue must contain exactly 328 distinct cases" in issues


def test_formal_serial_queue_rejects_digest_metadata_command_mismatch(tmp_path: Path):
    queue_path = tmp_path / "serial_queue.json"
    _write_serial_queue(queue_path, rows=1)
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    row = queue["serial_rows"][0]
    digest_fields = {
        "case_content_digest": "1" * 64,
        "case_runtime_input_digest": "2" * 64,
        "runtime_code_revision_digest": "3" * 64,
        "protocol_revision_digest": "4" * 64,
        "runtime_revision_digest": "5" * 64,
        "suite_content_digest": "6" * 64,
    }
    row.update(digest_fields)
    row["command"] += (
        f" -FormalCaseContentSha256 '{digest_fields['case_content_digest']}'"
        f" -FormalRuntimeInputsSha256 '{digest_fields['case_runtime_input_digest']}'"
        f" -FormalRuntimeCodeSha256 '{digest_fields['runtime_code_revision_digest']}'"
        f" -FormalProtocolSha256 '{'f' * 64}'"
        f" -FormalRuntimeRevisionSha256 '{digest_fields['runtime_revision_digest']}'"
        f" -FormalSuiteContentSha256 '{digest_fields['suite_content_digest']}'"
    )
    queue["queue_status"] = "formal_locked"
    queue["formal_execution_eligible"] = True
    queue["suite_lock"] = {"suite_content_sha256": digest_fields["suite_content_digest"]}
    queue["execution_contract"].update(
        {
            "row_count": 2296,
            "case_block_count": 328,
            "queue_seed": run_paper_queue.plan_paper_experiment_matrix.DEFAULT_QUEUE_SEED,
        }
    )

    issues = run_paper_queue.validate_serial_queue_structure(queue)

    assert any("-FormalProtocolSha256 does not match row fields" in issue for issue in issues)


def test_formal_serial_execute_requires_a_bound_verified_suite_lock(tmp_path: Path):
    queue_path = tmp_path / "serial_queue.json"
    _write_serial_queue(queue_path, rows=1)
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["execution_contract"]["suite_lock_required_for_execute"] = True
    queue["queue_digest"] = run_paper_queue.export_paper_run_queue.queue_digest(queue)
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    ran: list[str] = []

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="serial",
        execute=True,
        skip_readiness_check=True,
        runner=lambda command: (ran.append(command) or 0, "", ""),
        row_state_reader=lambda _record: {
            "valid_result_count": 0,
            "matching_attempts": 0,
            "in_progress_attempt_count": 0,
        },
    )

    assert ran == []
    assert plan["readiness_gate"]["suite_lock_checked"] is True
    assert "refuses a development_unlocked queue" in " ".join(
        plan["readiness_gate"]["suite_lock_blockers"]
    )
    assert plan["commands"][0]["status"] == "blocked"


def test_formal_serial_execute_rejects_skip_readiness_check(tmp_path: Path):
    queue_path = tmp_path / "serial_queue.json"
    _write_serial_queue(queue_path, rows=1)
    ran: list[str] = []

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="serial",
        execute=True,
        skip_readiness_check=True,
        runner=lambda command: (ran.append(command) or 0, "", ""),
        row_state_reader=lambda _record: {
            "valid_result_count": 0,
            "matching_attempts": 0,
            "in_progress_attempt_count": 0,
        },
    )

    assert ran == []
    assert plan["readiness_gate"]["skip_readiness_blockers"] == [
        "formal serial execution does not allow --skip-readiness-check"
    ]
    assert plan["commands"][0]["status"] == "blocked"


def test_run_paper_queue_serial_execution_is_one_row_at_a_time(tmp_path: Path):
    queue_path = tmp_path / "serial_queue.json"
    _write_serial_queue(queue_path)
    calls: list[str] = []
    reads: dict[str, int] = {}

    def state(record: dict):
        row_id = record["expected_row_id"]
        reads[row_id] = reads.get(row_id, 0) + 1
        valid = 1 if reads[row_id] >= 2 else 0
        return {
            "matching_attempts": valid,
            "valid_result_count": valid,
            "invalid_attempt_count": 0,
            "in_progress_attempt_count": 0,
        }

    def runner(command: str):
        calls.append(command)
        return 0, "ok", ""

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="serial",
        execute=True,
        allow_nonformal_test_queue=True,
        runner=runner,
        readiness_builder=_ready,
        row_state_reader=state,
    )

    assert calls == [
        "echo serial_01 -FormalRowId 'expected_01' -FormalIsolatedHomeId 'home_expected_01' -FormalAttempt 1",
        "echo serial_02 -FormalRowId 'expected_02' -FormalIsolatedHomeId 'home_expected_02' -FormalAttempt 1",
        "echo serial_03 -FormalRowId 'expected_03' -FormalIsolatedHomeId 'home_expected_03' -FormalAttempt 1",
    ]
    assert plan["summary"]["executed_commands"] == 3
    assert plan["summary"]["skipped_completed_commands"] == 0
    assert [item["status"] for item in plan["commands"]] == ["passed", "passed", "passed"]


def test_run_paper_queue_accepts_terminal_model_protocol_outcome_without_retry(tmp_path: Path):
    queue_path = tmp_path / "serial_queue.json"
    _write_serial_queue(queue_path, rows=1)
    reads = 0
    calls: list[str] = []

    def state(_record: dict):
        nonlocal reads
        reads += 1
        terminal = 1 if reads >= 2 else 0
        return {
            "matching_attempts": terminal,
            "valid_result_count": 0,
            "model_protocol_terminal_count": terminal,
            "accounted_result_count": terminal,
            "invalid_attempt_count": 0,
            "in_progress_attempt_count": 0,
        }

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="serial",
        execute=True,
        allow_nonformal_test_queue=True,
        runner=lambda command: (calls.append(command) or 0, "", ""),
        readiness_builder=_ready,
        row_state_reader=state,
    )

    assert len(calls) == 1
    assert plan["commands"][0]["status"] == "terminal_model_protocol_incomplete"
    assert plan["commands"][0]["exit_code"] == 0
    assert plan["summary"]["model_protocol_terminal_commands"] == 1


def test_formal_attempt_ledger_records_launch_before_runner(tmp_path: Path):
    queue_path = tmp_path / "serial_queue.json"
    _write_serial_queue(queue_path, rows=1)
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["attempt_ledger"] = "attempts.jsonl"
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    reads = 0
    commands: list[str] = []

    def state(_record: dict):
        nonlocal reads
        reads += 1
        return {
            "matching_attempts": 0,
            "valid_result_count": 1 if reads >= 2 else 0,
            "in_progress_attempt_count": 0,
        }

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="serial",
        execute=True,
        allow_nonformal_test_queue=True,
        skip_readiness_check=True,
        runner=lambda command: (commands.append(command) or 0, "", ""),
        row_state_reader=state,
    )

    events = [
        json.loads(line)
        for line in (tmp_path / "attempts.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(events) == 1
    assert events[0]["event"] == "launch"
    assert events[0]["schema_version"] == 1
    assert events[0]["matrix_id"] == "a" * 16
    assert events[0]["ledger_sequence"] == 1
    assert events[0]["previous_event_sha256"] == ""
    assert events[0]["expected_row_id"] == "expected_01"
    assert events[0]["isolated_home_id"] == "home_expected_01"
    assert events[0]["attempt_number"] == 1
    assert commands and "-FormalAttempt 1" in commands[0]
    command_before_ledger_digest = commands[0].split(" -FormalLaunchCommandSha256", 1)[0]
    assert events[0]["command_sha256"] == hashlib.sha256(
        command_before_ledger_digest.encode("utf-8")
    ).hexdigest()
    assert f"-FormalMatrixId '{'a' * 16}'" in commands[0]
    assert "-FormalQueuePosition 1" in commands[0]
    assert f"-FormalLaunchNonce '{events[0]['launch_nonce']}'" in commands[0]
    assert f"-FormalLaunchEventSha256 '{events[0]['event_sha256']}'" in commands[0]
    assert plan["commands"][0]["formal_attempt"] == 1
    assert plan["commands"][0]["executed_command"] == commands[0]
    assert plan["summary"]["ok"] is True


def test_formal_retry_replaces_static_attempt_with_actual_attempt_two(tmp_path: Path):
    queue_path = tmp_path / "serial_queue.json"
    _write_serial_queue(queue_path, rows=1)
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["serial_rows"][0]["command"] += " -FormalAttempt 1"
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    reads = 0
    commands: list[str] = []

    def state(_record: dict):
        nonlocal reads
        reads += 1
        return {
            "matching_attempts": 1 if reads == 1 else 2,
            "valid_result_count": 0 if reads == 1 else 1,
            "invalid_attempt_count": 1,
            "in_progress_attempt_count": 0,
        }

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="serial",
        execute=True,
        allow_nonformal_test_queue=True,
        skip_readiness_check=True,
        runner=lambda command: (commands.append(command) or 0, "", ""),
        row_state_reader=state,
    )

    assert len(commands) == 1
    assert "-FormalAttempt 2" in commands[0]
    assert "-FormalAttempt 1" not in commands[0]
    assert plan["commands"][0]["formal_attempt"] == 2
    assert plan["commands"][0]["status"] == "passed"


def test_execution_valid_control_failure_is_completed_and_not_retried(tmp_path: Path):
    queue_path = tmp_path / "serial_queue.json"
    _write_serial_queue(queue_path, rows=2)
    commands: list[str] = []

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="serial",
        batches=["expected_02"],
        execute=True,
        allow_nonformal_test_queue=True,
        skip_readiness_check=True,
        runner=lambda command: (commands.append(command) or 0, "", ""),
        row_state_reader=lambda _record: {
            "matching_attempts": 1,
            "valid_result_count": 1,
            "invalid_attempt_count": 0,
            "in_progress_attempt_count": 0,
            "control_contract_passed": False,
            "control_failure": True,
        },
    )

    assert commands == []
    assert plan["commands"][0]["kind"] == "control"
    assert plan["commands"][0]["status"] == "skipped_completed"
    assert plan["commands"][0]["formal_attempt"] is None


def test_formal_attempt_ledger_counts_pre_result_launches_against_retry_ceiling(tmp_path: Path):
    queue_path = tmp_path / "serial_queue.json"
    _write_serial_queue(queue_path, rows=1)
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["attempt_ledger"] = "attempts.jsonl"
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    ledger = tmp_path / "attempts.jsonl"
    for attempt in range(1, 4):
        run_paper_queue.export_paper_run_queue.append_formal_launch_event(
            ledger,
            matrix_id="a" * 16,
            expected_row_id="expected_01",
            isolated_home_id="home_expected_01",
            queue_position=1,
            attempt_number=attempt,
            command_sha256=f"{attempt:064x}",
            launch_nonce=f"{attempt + 100:064x}",
        )
    ran: list[str] = []

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="serial",
        execute=True,
        allow_nonformal_test_queue=True,
        skip_readiness_check=True,
        runner=lambda command: (ran.append(command) or 0, "", ""),
    )

    assert ran == []
    assert plan["commands"][0]["status"] == "failed"
    assert "retry budget is exhausted" in plan["commands"][0]["stderr_tail"]


def test_formal_attempt_binding_rejects_attempt_four():
    command = "echo run -FormalRowId 'expected_01'"

    try:
        run_paper_queue.bind_formal_attempt(
            command, expected_row_id="expected_01", attempt_number=4
        )
    except ValueError as exc:
        assert "[1, 3]" in str(exc)
    else:  # pragma: no cover - fail-closed assertion
        raise AssertionError("attempt four was accepted")


def test_formal_launch_ledger_rejects_attempt_gap(tmp_path: Path):
    ledger = tmp_path / "attempts.jsonl"
    common = {
        "matrix_id": "a" * 16,
        "expected_row_id": "expected_01",
        "isolated_home_id": "home_expected_01",
        "queue_position": 1,
        "command_sha256": "b" * 64,
    }
    run_paper_queue.export_paper_run_queue.append_formal_launch_event(
        ledger, attempt_number=1, launch_nonce="c" * 64, **common
    )

    try:
        run_paper_queue.export_paper_run_queue.append_formal_launch_event(
            ledger, attempt_number=3, launch_nonce="d" * 64, **common
        )
    except ValueError as exc:
        assert "not contiguous" in str(exc)
    else:  # pragma: no cover - fail-closed assertion
        raise AssertionError("attempt gap was accepted")


def test_formal_locked_queue_cannot_execute_in_coalesced_mode(tmp_path: Path):
    queue_path = tmp_path / "queue.json"
    queue_path.write_text(
        json.dumps(
            {
                "root": str(tmp_path),
                "matrix_id": "a" * 16,
                "queue_status": "formal_locked",
                "formal_execution_eligible": True,
                "execution_contract": {"suite_lock_required_for_execute": True},
                "coalesced_batches": [
                    {"batch_id": "legacy", "command": "echo must_not_run", "missing_rows": 1}
                ],
                "batches": [],
                "serial_rows": [],
                "post_run_commands": [],
            }
        ),
        encoding="utf-8",
    )
    ran: list[str] = []

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="coalesced",
        execute=True,
        runner=lambda command: (ran.append(command) or 0, "", ""),
        readiness_builder=_ready,
    )

    assert ran == []
    assert plan["readiness_gate"]["formal_queue_mode_blockers"] == [
        "formal_locked queue execution requires --queue-mode serial"
    ]
    assert plan["commands"][0]["status"] == "blocked"


def test_per_row_artifact_recheck_detects_plan_mutation(tmp_path: Path):
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        json.dumps(
            {
                "matrix_id": "a" * 16,
                "matrix_digest": "b" * 64,
                "suite_lock": {"suite_content_sha256": "c" * 64},
            }
        ),
        encoding="utf-8",
    )
    queue_path = tmp_path / "queue.json"
    queue = {
        "matrix_id": "a" * 16,
        "matrix_digest": "b" * 64,
        "suite_lock": {"suite_content_sha256": "c" * 64},
        "plan_path": str(plan_path),
        "plan_file_sha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
    }
    queue["queue_digest"] = run_paper_queue.export_paper_run_queue.queue_digest(queue)
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    queue_file_digest = hashlib.sha256(queue_path.read_bytes()).hexdigest()
    assert run_paper_queue.serial_execution_artifact_issues(
        queue,
        queue_path=queue_path,
        root=tmp_path,
        expected_queue_file_sha256=queue_file_digest,
    ) == []

    queue_payload = queue_path.read_bytes()
    queue_path.write_bytes(queue_payload + b"\n")
    assert "formal queue file changed after execution planning" in run_paper_queue.serial_execution_artifact_issues(
        queue,
        queue_path=queue_path,
        root=tmp_path,
        expected_queue_file_sha256=queue_file_digest,
    )
    queue_path.write_bytes(queue_payload)

    plan_path.write_text("{}", encoding="utf-8")

    assert "formal experiment plan file changed before launch" in run_paper_queue.serial_execution_artifact_issues(
        queue,
        queue_path=queue_path,
        root=tmp_path,
        expected_queue_file_sha256=queue_file_digest,
    )


def test_mid_queue_plan_mutation_blocks_the_next_row(tmp_path: Path):
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        json.dumps(
            {
                "matrix_id": "a" * 16,
                "matrix_digest": "b" * 64,
                "suite_lock": {"suite_content_sha256": "c" * 64},
            }
        ),
        encoding="utf-8",
    )
    queue_path = tmp_path / "queue.json"
    queue = {
        "matrix_id": "a" * 16,
        "matrix_digest": "b" * 64,
        "suite_lock": {"suite_content_sha256": "c" * 64},
        "plan_path": str(plan_path),
        "plan_file_sha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
    }
    queue["queue_digest"] = run_paper_queue.export_paper_run_queue.queue_digest(queue)
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    queue_file_digest = hashlib.sha256(queue_path.read_bytes()).hexdigest()
    records = [
        {
            "source": "serial",
            "batch_id": f"row_{index}",
            "expected_row_id": f"row_{index}",
            "isolated_home_id": f"home_{index}",
            "max_attempts": 3,
            "command": f"echo row_{index} -FormalRowId 'row_{index}'",
        }
        for index in (1, 2)
    ]
    state_reads: dict[str, int] = {}

    def state(record: dict) -> dict:
        row_id = record["expected_row_id"]
        state_reads[row_id] = state_reads.get(row_id, 0) + 1
        return {
            "matching_attempts": 0,
            "valid_result_count": 1 if state_reads[row_id] > 1 else 0,
            "in_progress_attempt_count": 0,
        }

    ran: list[str] = []

    def runner(command: str):
        ran.append(command)
        plan_path.write_text("{}", encoding="utf-8")
        return 0, "", ""

    def prelaunch(_record: dict) -> list[str]:
        return run_paper_queue.serial_execution_artifact_issues(
            queue,
            queue_path=queue_path,
            root=tmp_path,
            expected_queue_file_sha256=queue_file_digest,
        )

    results = run_paper_queue.execute_records(
        records,
        execute=True,
        runner=runner,
        row_state_reader=state,
        prelaunch_validator=prelaunch,
    )

    assert len(ran) == 1
    assert [item["status"] for item in results] == ["passed", "failed"]
    assert "plan file changed" in results[1]["stderr_tail"]


def test_formal_execution_lock_refuses_a_second_serial_consumer(tmp_path: Path):
    queue_path = tmp_path / "serial_queue.json"
    _write_serial_queue(queue_path, rows=1)
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["execution_lock"] = "consumer.lock"
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    (tmp_path / "consumer.lock").write_text("already running\n", encoding="utf-8")
    ran: list[str] = []

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="serial",
        execute=True,
        allow_nonformal_test_queue=True,
        skip_readiness_check=True,
        runner=lambda command: (ran.append(command) or 0, "", ""),
        row_state_reader=lambda _record: {
            "matching_attempts": 0,
            "valid_result_count": 0,
            "in_progress_attempt_count": 0,
        },
    )

    assert ran == []
    assert plan["commands"][0]["status"] == "blocked"
    assert "execution lock already exists" in plan["commands"][0]["stderr_tail"]


def test_run_paper_queue_serial_skip_completed_uses_authoritative_validity(tmp_path: Path):
    queue_path = tmp_path / "serial_queue.json"
    _write_serial_queue(queue_path, rows=1)

    def fail_runner(command: str):
        raise AssertionError(command)

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="serial",
        execute=True,
        allow_nonformal_test_queue=True,
        runner=fail_runner,
        readiness_builder=_ready,
        row_state_reader=lambda record: {
            "matching_attempts": 1,
            "valid_result_count": 1,
            "invalid_attempt_count": 0,
            "in_progress_attempt_count": 0,
        },
    )

    assert plan["commands"][0]["status"] == "skipped_completed"
    assert plan["summary"]["executed_commands"] == 0
    assert plan["summary"]["skipped_completed_commands"] == 1


def test_run_paper_queue_serial_rejects_duplicate_valid_results(tmp_path: Path):
    queue_path = tmp_path / "serial_queue.json"
    _write_serial_queue(queue_path, rows=1)

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="serial",
        execute=True,
        allow_nonformal_test_queue=True,
        runner=lambda command: (_ for _ in ()).throw(AssertionError(command)),
        readiness_builder=_ready,
        row_state_reader=lambda record: {
            "matching_attempts": 2,
            "valid_result_count": 2,
            "invalid_attempt_count": 0,
            "in_progress_attempt_count": 0,
        },
    )

    assert plan["commands"][0]["status"] == "failed"
    assert plan["commands"][0]["runner_invoked"] is False
    assert "duplicate valid results" in plan["commands"][0]["stderr_tail"]
    assert plan["summary"]["ok"] is False


def test_run_paper_queue_serial_enforces_fixed_retry_budget(tmp_path: Path):
    queue_path = tmp_path / "serial_queue.json"
    _write_serial_queue(queue_path, rows=1)

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="serial",
        execute=True,
        allow_nonformal_test_queue=True,
        runner=lambda command: (_ for _ in ()).throw(AssertionError(command)),
        readiness_builder=_ready,
        row_state_reader=lambda record: {
            "matching_attempts": 3,
            "valid_result_count": 0,
            "invalid_attempt_count": 3,
            "in_progress_attempt_count": 0,
        },
    )

    assert plan["commands"][0]["status"] == "failed"
    assert "retry budget is exhausted" in plan["commands"][0]["stderr_tail"]


def test_run_paper_queue_filters_start_at_and_batch(tmp_path: Path):
    queue_path = tmp_path / "paper_run_queue.json"
    _write_queue(queue_path)
    queue = run_paper_queue.load_json(queue_path)

    start_commands = run_paper_queue.select_commands(
        queue,
        queue_mode="coalesced",
        start_at="control_claude_all_missing_types",
    )
    batch_commands = run_paper_queue.select_commands(
        queue,
        queue_mode="fine",
        batches=["control_claude_clean_control"],
    )

    assert [item["batch_id"] for item in start_commands] == ["control_claude_all_missing_types"]
    assert [item["batch_id"] for item in batch_commands] == ["control_claude_clean_control"]


def test_run_paper_queue_filters_by_harness(tmp_path: Path):
    queue_path = tmp_path / "paper_run_queue.json"
    _write_codex_queue(queue_path)
    queue = run_paper_queue.load_json(queue_path)
    queue["coalesced_batches"].insert(
        0,
        {
            "batch_id": "attack_claude",
            "kind": "attack",
            "harness": "claude",
            "missing_rows": 2,
            "command": ".\\infra\\run_paper_baseline_matrix.ps1 -Harnesses claude",
        },
    )

    commands = run_paper_queue.select_commands(
        queue,
        queue_mode="coalesced",
        harnesses=["claude"],
        include_post_run=True,
    )

    assert [item["batch_id"] for item in commands] == ["attack_claude"]


def test_run_paper_queue_selects_harness_specific_post_run(tmp_path: Path):
    queue_path = tmp_path / "paper_run_queue.json"
    _write_queue(queue_path)
    queue = run_paper_queue.load_json(queue_path)

    commands = run_paper_queue.select_commands(
        queue,
        queue_mode="post-run",
        harnesses=["claude"],
    )

    assert [item["batch_id"] for item in commands] == ["post_run_claude_01"]
    assert commands[0]["requires_kimi"] is False


def test_run_paper_queue_harness_specific_post_run_does_not_require_kimi(tmp_path: Path):
    queue_path = tmp_path / "paper_run_queue.json"
    _write_queue(queue_path)
    seen: list[bool] = []

    def ready(require_kimi: bool):
        seen.append(require_kimi)
        return {"ready": True, "blockers": [], "warnings": []}

    def fake_runner(command: str):
        return 0, "ok", ""

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="post-run",
        harnesses=["claude"],
        execute=True,
        runner=fake_runner,
        readiness_builder=ready,
    )

    assert seen == [False]
    assert plan["readiness_gate"]["requires_kimi"] is False
    assert plan["summary"]["executed_commands"] == 1
    assert plan["summary"]["ok"] is True


def test_run_paper_queue_detects_codex_harness_argument():
    assert run_paper_queue.command_requires_kimi(
        {"harness": "", "command": ".\\runner.ps1 -Harnesses 'claude,codex'"}
    )
    assert not run_paper_queue.command_requires_kimi(
        {"harness": "claude", "command": ".\\runner.ps1 -Harnesses claude -KimiModel kimi-k2.6"}
    )


def test_run_paper_queue_dry_run_does_not_call_runner(tmp_path: Path):
    queue_path = tmp_path / "paper_run_queue.json"
    _write_queue(queue_path)

    def fail_runner(command: str):
        raise AssertionError(command)

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="coalesced",
        execute=False,
        runner=fail_runner,
    )

    assert plan["summary"]["selected_commands"] == 2
    assert plan["summary"]["selected_missing_rows"] == 6
    assert plan["summary"]["executed_commands"] == 0
    assert plan["readiness_gate"]["checked"] is False
    assert all(item["status"] == "dry_run" for item in plan["commands"])


def test_run_paper_queue_execute_stops_on_failure(tmp_path: Path):
    queue_path = tmp_path / "paper_run_queue.json"
    _write_queue(queue_path)

    def fake_runner(command: str):
        if "attack" in command:
            return 1, "", "failed"
        return 0, "ok", ""

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="coalesced",
        execute=True,
        runner=fake_runner,
        readiness_builder=_ready,
    )

    assert plan["summary"]["selected_commands"] == 2
    assert plan["summary"]["executed_commands"] == 1
    assert plan["summary"]["failed_commands"] == 1
    assert plan["summary"]["pending_commands"] == 1
    assert plan["summary"]["incomplete_commands"] == 0
    assert plan["summary"]["resume_batch"] == "control_claude_all_missing_types"
    assert plan["commands"][0]["status"] == "failed"
    assert plan["commands"][1]["status"] == "pending_after_failure"
    assert "--start-at control_claude_all_missing_types" in plan["commands"][1]["stderr_tail"]


def test_run_paper_queue_writes_incremental_checkpoints_between_commands(tmp_path: Path):
    queue_path = tmp_path / "paper_run_queue.json"
    out_json = tmp_path / "execution.json"
    out_md = tmp_path / "execution.md"
    _write_queue(queue_path)
    calls: list[str] = []

    def checkpoint_writer(plan: dict):
        run_paper_queue.write_execution_outputs(plan, out_json, out_md)

    def fake_runner(command: str):
        calls.append(command)
        if len(calls) == 2:
            checkpoint = json.loads(out_json.read_text(encoding="utf-8"))
            assert checkpoint["summary"]["executed_commands"] == 1
            assert checkpoint["summary"]["incomplete_commands"] == 1
            assert checkpoint["summary"]["resume_batch"] == "control_claude_all_missing_types"
            assert checkpoint["summary"]["ok"] is False
            assert "incomplete_commands: `1`" in out_md.read_text(encoding="utf-8")
        return 0, "ok", ""

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="coalesced",
        execute=True,
        runner=fake_runner,
        readiness_builder=_ready,
        checkpoint_writer=checkpoint_writer,
    )

    assert len(calls) == 2
    assert plan["summary"]["executed_commands"] == 2
    assert plan["summary"]["incomplete_commands"] == 0
    assert plan["summary"]["resume_batch"] == ""
    assert plan["summary"]["ok"] is True


def test_run_paper_queue_markdown_contains_commands(tmp_path: Path):
    queue_path = tmp_path / "paper_run_queue.json"
    _write_queue(queue_path)
    plan = run_paper_queue.build_execution_plan(queue_path=queue_path, queue_mode="coalesced")

    markdown = run_paper_queue.render_markdown(plan)

    assert "# Paper Run Execution Plan" in markdown
    assert "attack_claude" in markdown
    assert "## Readiness Gate" in markdown
    assert "requested_harnesses: `all`" in markdown
    assert "selected_missing_rows: `6`" in markdown
    assert "incomplete_commands: `0`" in markdown
    assert "dry_run" in markdown


def test_run_paper_queue_markdown_contains_resume_hint_after_failure(tmp_path: Path):
    queue_path = tmp_path / "paper_run_queue.json"
    _write_queue(queue_path)

    def fake_runner(command: str):
        if "attack" in command:
            return 1, "", "failed"
        return 0, "ok", ""

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="coalesced",
        execute=True,
        runner=fake_runner,
        readiness_builder=_ready,
    )
    markdown = run_paper_queue.render_markdown(plan)

    assert "pending_after_failure" in markdown
    assert "## Resume" in markdown
    assert "--start-at control_claude_all_missing_types" in markdown


def test_run_paper_queue_continue_on_failure_does_not_mark_pending(tmp_path: Path):
    queue_path = tmp_path / "paper_run_queue.json"
    _write_queue(queue_path)

    def fake_runner(command: str):
        if "attack" in command:
            return 1, "", "failed"
        return 0, "ok", ""

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="coalesced",
        execute=True,
        stop_on_failure=False,
        runner=fake_runner,
        readiness_builder=_ready,
    )

    assert plan["summary"]["executed_commands"] == 2
    assert plan["summary"]["failed_commands"] == 1
    assert plan["summary"]["pending_commands"] == 0
    assert [item["status"] for item in plan["commands"]] == ["failed", "passed"]


def test_run_paper_queue_execute_blocks_when_kimi_batch_is_not_ready(tmp_path: Path):
    queue_path = tmp_path / "paper_run_queue.json"
    _write_codex_queue(queue_path)

    def fail_runner(command: str):
        raise AssertionError(command)

    def not_ready(require_kimi: bool):
        assert require_kimi is True
        return {
            "ready": False,
            "blockers": ["missing DashScope key"],
            "warnings": [],
        }

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="coalesced",
        execute=True,
        runner=fail_runner,
        readiness_builder=not_ready,
    )

    assert plan["summary"]["ok"] is False
    assert plan["summary"]["executed_commands"] == 0
    assert plan["summary"]["blocked_commands"] == 1
    assert plan["summary"]["failed_commands"] == 0
    assert plan["readiness_gate"]["requires_kimi"] is True
    assert plan["commands"][0]["status"] == "blocked"
    assert "missing DashScope key" in plan["commands"][0]["stderr_tail"]


def test_run_paper_queue_execute_claude_batch_does_not_require_kimi(tmp_path: Path):
    queue_path = tmp_path / "paper_run_queue.json"
    _write_queue(queue_path)
    seen: list[bool] = []

    def ready(require_kimi: bool):
        seen.append(require_kimi)
        return {"ready": True, "blockers": [], "warnings": []}

    def fake_runner(command: str):
        return 0, "ok", ""

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="coalesced",
        batches=["attack_claude"],
        execute=True,
        runner=fake_runner,
        readiness_builder=ready,
    )

    assert seen == [False]
    assert plan["readiness_gate"]["requires_kimi"] is False
    assert plan["summary"]["executed_commands"] == 1
    assert plan["summary"]["ok"] is True


def test_run_paper_queue_execute_claude_harness_filter_does_not_require_kimi(tmp_path: Path):
    queue_path = tmp_path / "paper_run_queue.json"
    _write_codex_queue(queue_path)
    queue = run_paper_queue.load_json(queue_path)
    queue["coalesced_batches"].insert(
        0,
        {
            "batch_id": "attack_claude",
            "kind": "attack",
            "harness": "claude",
            "missing_rows": 2,
            "command": ".\\infra\\run_paper_baseline_matrix.ps1 -Harnesses claude",
        },
    )
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    seen: list[bool] = []

    def ready(require_kimi: bool):
        seen.append(require_kimi)
        return {"ready": True, "blockers": [], "warnings": []}

    def fake_runner(command: str):
        return 0, "ok", ""

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="coalesced",
        harnesses=["claude"],
        execute=True,
        runner=fake_runner,
        readiness_builder=ready,
    )

    assert seen == [False]
    assert plan["requested_harnesses"] == ["claude"]
    assert plan["readiness_gate"]["requires_kimi"] is False
    assert [item["batch_id"] for item in plan["commands"]] == ["attack_claude"]
    assert plan["summary"]["selected_missing_rows"] == 2
    assert plan["summary"]["ok"] is True


def test_run_paper_queue_execute_can_skip_readiness_check(tmp_path: Path):
    queue_path = tmp_path / "paper_run_queue.json"
    _write_codex_queue(queue_path)
    ran: list[str] = []

    def fake_runner(command: str):
        ran.append(command)
        return 0, "ok", ""

    def fail_readiness(require_kimi: bool):
        raise AssertionError(require_kimi)

    plan = run_paper_queue.build_execution_plan(
        queue_path=queue_path,
        queue_mode="coalesced",
        execute=True,
        skip_readiness_check=True,
        runner=fake_runner,
        readiness_builder=fail_readiness,
    )

    assert len(ran) == 1
    assert plan["readiness_gate"]["skipped"] is True
    assert plan["summary"]["ok"] is True
