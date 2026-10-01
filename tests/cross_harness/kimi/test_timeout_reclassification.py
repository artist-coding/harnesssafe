from __future__ import annotations

import hashlib
import json
from pathlib import Path

from infra.cross_harness.adapters.kimi.timeout_reclassification import (
    apply_timeout_reclassification,
    prepare_timeout_reclassification,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, document: dict) -> None:
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    run_id = "timeout-migration-fixture"
    stdout = tmp_path / f"trace-kimi-{run_id}.jsonl"
    wire = tmp_path / f"wire-kimi-{run_id}.jsonl"
    stdout.write_text('{"role":"assistant","type":"fixture"}\n', encoding="utf-8")
    wire.write_text('{"role":"assistant","type":"fixture"}\n', encoding="utf-8")
    result = tmp_path / f"result-kimi-{run_id}.json"
    stage = {
        "schema_name": "safety_bench_kimi_stage_execution",
        "schema_version": 1,
        "harness_id": "kimi",
        "run_id": run_id,
        "case_id": "case-timeout",
        "stage": {"index": 0, "name": "attack"},
        "argv": ["/usr/local/bin/kimi", "--prompt", "<sha256:fixture>"],
        "return_code": -15,
        "timed_out": True,
        "stdout": {
            "path": str(stdout),
            "sha256": _sha256(stdout),
            "line_count": 1,
        },
        "wire": {
            "main_path": str(wire),
            "main_sha256": _sha256(wire),
            "captures": [],
        },
    }
    _write_json(result, stage)
    state = {
        "schema_name": "safety_bench_kimi_run_state",
        "schema_version": 2,
        "harness_id": "kimi",
        "run_id": run_id,
        "updated_at": "2026-07-25T00:00:00+00:00",
        "case_order": ["case-timeout"],
        "cases": {
            "case-timeout": {
                "case_id": "case-timeout",
                "suite": "v2_skill_runtime",
                "attempt": 2,
                "status": "EXECUTION_INVALID",
                "reason": "fixture timeout",
                "failure_category": "PROVIDER_TIMEOUT",
                "retry_eligible": True,
                "history": [],
                "evidence": {
                    "outcome": "EXECUTION_INVALID",
                    "return_code": -15,
                    "raw_stdout_path": str(stdout),
                    "raw_wire_path": str(wire),
                    "event_ir_path": None,
                    "failure_category": "PROVIDER_TIMEOUT",
                    "retry_eligible": True,
                    "metadata": {
                        "schema_name": "safety_bench_kimi_execution_evidence",
                        "schema_version": 1,
                        "run_id": run_id,
                        "case_id": "case-timeout",
                        "execution_disposition": {
                            "outcome": "EXECUTION_INVALID",
                            "failure_category": "PROVIDER_TIMEOUT",
                            "retry_eligible": True,
                            "reason": "Kimi stage exceeded the explicit timeout",
                        },
                        "stages": [
                            {
                                "index": 0,
                                "name": "attack",
                                "return_code": -15,
                                "stdout_path": str(stdout),
                                "stdout_sha256": _sha256(stdout),
                                "main_wire_path": str(wire),
                                "main_wire_sha256": _sha256(wire),
                                "result_path": str(result),
                            }
                        ],
                    },
                },
            }
        },
    }
    state_path = tmp_path / f"state-{run_id}.json"
    _write_json(state_path, state)
    launcher_log = tmp_path / f"launcher-resume-{run_id}.log"
    launcher_log.write_text(
        "started_at=2026-07-25T00:00:00Z\n"
        "pid=12345\n"
        f"run_id={run_id}\n"
        f"result_root={tmp_path.parent}\n"
        "command=resume\n"
        "timeout_seconds=1200\n",
        encoding="utf-8",
    )
    return state_path, launcher_log


def test_prepare_timeout_reclassification_is_read_only(tmp_path: Path) -> None:
    state_path, launcher_log = _fixture(tmp_path)
    before = state_path.read_bytes()

    migrated, attestation, source = prepare_timeout_reclassification(
        state_path=state_path,
        launcher_log_path=launcher_log,
    )

    assert source == before
    assert state_path.read_bytes() == before
    record = migrated["cases"]["case-timeout"]
    assert record["status"] == "MODEL_PROTOCOL_INCOMPLETE"
    assert record["failure_category"] == "MODEL_STAGE_TIMEOUT"
    assert record["retry_eligible"] is False
    assert record["evidence"]["metadata"]["stages"][0]["timed_out"] is True
    assert record["evidence"]["metadata"]["stages"][0]["timeout_seconds"] == 1200
    assert attestation["case_count"] == 1
    assert attestation["cases"][0]["stage_result_sha256"] == _sha256(
        Path(attestation["cases"][0]["stage_result_path"])
    )


def test_apply_timeout_reclassification_preserves_source_state(
    tmp_path: Path,
) -> None:
    state_path, launcher_log = _fixture(tmp_path)
    before = state_path.read_bytes()

    result = apply_timeout_reclassification(
        state_path=state_path,
        launcher_log_path=launcher_log,
    )

    migrated = json.loads(state_path.read_text(encoding="utf-8"))
    assert migrated["cases"]["case-timeout"]["status"] == (
        "MODEL_PROTOCOL_INCOMPLETE"
    )
    backup = Path(result["source_state_backup_path"])
    attestation = Path(result["attestation_path"])
    assert backup.read_bytes() == before
    assert attestation.is_file()
    assert result["case_ids"] == ["case-timeout"]
