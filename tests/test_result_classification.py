from __future__ import annotations

import base64
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from infra.result_classification import (
    RESULT_CLASS_EXECUTION_INVALID,
    RESULT_CLASS_MODEL_PROTOCOL_DEVIATION,
    RESULT_CLASS_SCORED,
    is_accounted_terminal_result,
    is_scored_run_validity,
    is_terminal_model_protocol_deviation,
    normalized_result_class,
)


def model_protocol_payload(**overrides):
    payload = {
        "schema_version": 2,
        "valid": False,
        "status": "model_protocol_incomplete",
        "result_class": "model_protocol_deviation",
        "display_node": "N-1",
        "model_protocol_status": "deviated",
        "model_protocol_failure_kind": "required_artifact_path_mismatch",
        "model_protocol_failure_stage": "phase1_subagent_producer",
        "model_protocol_evidence": [
            {
                "attribution": "model_tool_argument",
                "failure_kind": "required_artifact_path_mismatch",
                "stage_name": "phase1_subagent_producer",
                "stage_index": 1,
                "expected_path": "handoff/produced_context.md",
                "observed_path": "handoff/proced_context.md",
                "observed_path_normalized": "handoff/proced_context.md",
                "tool_name": "Write",
                "tool_use_id": "tool-1",
                "tool_result_success": True,
                "filename_edit_distance": 2,
            }
        ],
        "terminal_outcome": True,
        "retry_eligible": False,
        "safety_score_eligible": False,
        "formal_asr_eligible": False,
        "failure_reasons": ["boundary_artifact_missing"],
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
                "stage_name": "phase1_subagent_producer",
                "stage_index": 1,
                "valid": False,
                "exit_code": 0,
                "timed_out": False,
                "failure_reasons": ["boundary_artifact_missing"],
                "required_artifact_paths": ["handoff/produced_context.md"],
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
    payload.update(overrides)
    return payload


def scored_payload(**overrides):
    payload = {
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
        "mcp_runtime_health": {"valid": True},
        "analyzer_exit_code": 0,
        "oracle_present": True,
        "oracle_valid": True,
        "global_config_touched": False,
        "global_config_external_drift": False,
        "global_config_inventory_complete": True,
        "control_intervention_execution_valid": True,
        "materialization_attestation_untampered": True,
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
    }
    payload.update(overrides)
    return payload


def test_scored_and_model_protocol_results_are_both_terminal() -> None:
    scored = {"schema_version": 1, "valid": True, "status": "completed"}
    deviated = model_protocol_payload()

    assert normalized_result_class(scored) == RESULT_CLASS_SCORED
    assert normalized_result_class(deviated) == RESULT_CLASS_MODEL_PROTOCOL_DEVIATION
    assert is_accounted_terminal_result(scored) is True
    assert is_accounted_terminal_result(deviated) is True


def test_schema_v2_scored_result_requires_complete_canonical_disposition() -> None:
    assert is_scored_run_validity(scored_payload()) is True
    assert normalized_result_class(scored_payload()) == RESULT_CLASS_SCORED

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
        payload = scored_payload()
        payload.pop(field)
        assert is_scored_run_validity(payload) is False, field
        assert normalized_result_class(payload) == RESULT_CLASS_EXECUTION_INVALID, field

    for malformed_evidence in ({}, None):
        payload = scored_payload()
        payload["model_protocol_evidence"] = malformed_evidence
        assert is_scored_run_validity(payload) is False
        assert normalized_result_class(payload) == RESULT_CLASS_EXECUTION_INVALID

    # Historical schema-v1 rows retain compatibility display semantics, but
    # formal queue/progress gates reject them separately.
    assert is_scored_run_validity(
        {"schema_version": 1, "valid": True, "status": "completed"}
    ) is True
    for invalid_schema in (0, -1):
        payload = {"schema_version": invalid_schema, "valid": True, "status": "completed"}
        assert is_scored_run_validity(payload) is False
        assert normalized_result_class(payload) == RESULT_CLASS_EXECUTION_INVALID


def test_incomplete_nminus1_claim_is_fail_closed() -> None:
    for field, replacement in [
        ("schema_version", 1),
        ("valid", True),
        ("status", "completed_with_stage_failure"),
        ("result_class", "execution_invalid"),
        ("display_node", "N0"),
        ("model_protocol_status", "not_assessable"),
        ("model_protocol_failure_kind", ""),
        ("model_protocol_failure_stage", ""),
        ("model_protocol_evidence", []),
        ("terminal_outcome", False),
        ("retry_eligible", True),
        ("safety_score_eligible", True),
        ("formal_asr_eligible", True),
        ("failure_reasons", ["timeout"]),
    ]:
        payload = model_protocol_payload(**{field: replacement})
        assert is_terminal_model_protocol_deviation(payload) is False, field
        assert normalized_result_class(payload) == RESULT_CLASS_EXECUTION_INVALID
        assert is_accounted_terminal_result(payload) is False


def test_plain_runner_or_transport_failure_is_not_nminus1() -> None:
    payload = {
        "schema_version": 2,
        "valid": False,
        "status": "completed_with_stage_failure",
        "failure_reasons": ["timeout"],
        "result_class": "execution_invalid",
        "terminal_outcome": False,
        "retry_eligible": True,
    }

    assert is_terminal_model_protocol_deviation(payload) is False
    assert normalized_result_class(payload) == RESULT_CLASS_EXECUTION_INVALID
    assert is_accounted_terminal_result(payload) is False


def test_model_protocol_claim_requires_real_path_and_stage_mismatch() -> None:
    same_path = model_protocol_payload()
    same_path["model_protocol_evidence"][0]["observed_path"] = (
        same_path["model_protocol_evidence"][0]["expected_path"]
    )
    assert is_terminal_model_protocol_deviation(same_path) is False

    unknown_stage = model_protocol_payload()
    unknown_stage["model_protocol_failure_stage"] = "not_executed"
    unknown_stage["model_protocol_evidence"][0]["stage_name"] = "not_executed"
    assert is_terminal_model_protocol_deviation(unknown_stage) is False


def test_model_protocol_claim_rechecks_frozen_close_sibling_contract() -> None:
    distant = model_protocol_payload()
    distant["model_protocol_evidence"][0].update(
        {
            "observed_path": "elsewhere/completely-different.txt",
            "observed_path_normalized": "elsewhere/completely-different.txt",
            "filename_edit_distance": 99,
        }
    )
    assert is_terminal_model_protocol_deviation(distant) is False

    not_frozen = model_protocol_payload()
    not_frozen["stages"][0]["required_artifact_paths"] = ["handoff/other.md"]
    assert is_terminal_model_protocol_deviation(not_frozen) is False

    forged_distance = model_protocol_payload()
    forged_distance["model_protocol_evidence"][0]["filename_edit_distance"] = 1
    assert is_terminal_model_protocol_deviation(forged_distance) is False


def test_model_protocol_claim_binds_failure_reason_to_failure_stage() -> None:
    cross_stage = model_protocol_payload(expected_stage_count=2, completed_stage_count=2)
    cross_stage["stages"] = [
        {
            **cross_stage["stages"][0],
            "failure_reasons": [],
        },
        {
            **cross_stage["stages"][0],
            "stage_name": "later_stage",
            "stage_index": 2,
            "failure_reasons": ["boundary_artifact_missing"],
        },
    ]
    assert is_terminal_model_protocol_deviation(cross_stage) is False

    oracle_only = model_protocol_payload(
        failure_reasons=[
            "boundary_required_oracle_missing:O_subagent_boundary_producer"
        ]
    )
    oracle_only["stages"][0]["failure_reasons"] = list(
        oracle_only["failure_reasons"]
    )
    assert is_terminal_model_protocol_deviation(oracle_only) is False

    failure_marked_valid = model_protocol_payload()
    failure_marked_valid["stages"][0]["valid"] = True
    assert is_terminal_model_protocol_deviation(failure_marked_valid) is False

    healthy_marked_invalid = model_protocol_payload(
        expected_stage_count=2, completed_stage_count=2
    )
    healthy_stage = {
        **healthy_marked_invalid["stages"][0],
        "stage_name": "healthy_stage",
        "stage_index": 1,
        "valid": False,
        "failure_reasons": [],
        "required_artifact_paths": [],
    }
    failed_stage = {
        **healthy_marked_invalid["stages"][0],
        "stage_index": 2,
    }
    healthy_marked_invalid["stages"] = [healthy_stage, failed_stage]
    healthy_marked_invalid["model_protocol_evidence"][0]["stage_index"] = 2
    assert is_terminal_model_protocol_deviation(healthy_marked_invalid) is False


def test_model_protocol_claim_requires_analyzer_and_oracle_health() -> None:
    for field, value in [
        ("analyzer_exit_code", 1),
        ("oracle_present", False),
        ("oracle_valid", False),
    ]:
        assert not is_terminal_model_protocol_deviation(
            model_protocol_payload(**{field: value})
        )


def test_result_classification_rejects_coercive_types_and_contradictory_scored_claim() -> None:
    for field, value in [
        ("valid", 0),
        ("status", "MODEL_PROTOCOL_INCOMPLETE"),
        ("model_protocol_evidence", model_protocol_payload()["model_protocol_evidence"][0]),
        ("failure_reasons", "boundary_artifact_missing"),
        ("stages", model_protocol_payload()["stages"][0]),
        ("terminal_outcome", 1),
        ("retry_eligible", 0),
        ("runner_error", "   "),
    ]:
        assert not is_terminal_model_protocol_deviation(
            model_protocol_payload(**{field: value})
        ), field

    contradictory = {
        "valid": True,
        "status": "completed",
        "result_class": "model_protocol_deviation",
        "display_node": "N-1",
        "model_protocol_status": "deviated",
    }
    assert normalized_result_class(contradictory) == RESULT_CLASS_EXECUTION_INVALID
    assert is_accounted_terminal_result(contradictory) is False

    scored_with_failure = {
        "valid": True,
        "status": "completed",
        "failure_reasons": ["timeout"],
    }
    assert normalized_result_class(scored_with_failure) == RESULT_CLASS_EXECUTION_INVALID
    assert is_accounted_terminal_result(scored_with_failure) is False


def _powershell_classification(tmp_path: Path, payload: dict) -> dict:
    executable = shutil.which("pwsh") or shutil.which("powershell")
    if not executable:
        pytest.skip("PowerShell is not installed")
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    tmp_path.mkdir(parents=True, exist_ok=True)
    helper = (
        Path("infra/result_classification.ps1").resolve().as_posix().replace("'", "''")
    )
    probe = tmp_path / "classification_parity.ps1"
    probe.write_text(
        f"""
. '{helper}'
$json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'))
$payload = $json | ConvertFrom-Json
$disposition = Get-SbRunValidityDisposition -Payload $payload
[pscustomobject]@{{
    terminal = [bool](Test-SbTerminalModelProtocolPayload -Payload $payload)
    accounted = [bool]$disposition.Accounted
    result_class = [string]$disposition.ResultClass
}} | ConvertTo-Json -Compress
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [executable, "-NoProfile", "-File", str(probe)],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return json.loads(completed.stdout)


def test_python_and_powershell_classifiers_reject_same_malformed_vectors(
    tmp_path: Path,
) -> None:
    vectors = [model_protocol_payload()]
    for field, value in [
        ("status", "MODEL_PROTOCOL_INCOMPLETE"),
        ("valid", 0),
        ("model_protocol_evidence", model_protocol_payload()["model_protocol_evidence"][0]),
        ("failure_reasons", "boundary_artifact_missing"),
        ("stages", model_protocol_payload()["stages"][0]),
        ("oracle_present", 1),
        ("runner_error", "   "),
    ]:
        vectors.append(model_protocol_payload(**{field: value}))
    whitespace_tool_id = model_protocol_payload()
    whitespace_tool_id["model_protocol_evidence"][0]["tool_use_id"] = "   "
    vectors.append(whitespace_tool_id)
    whitespace_stage = model_protocol_payload(model_protocol_failure_stage="   ")
    whitespace_stage["model_protocol_evidence"][0]["stage_name"] = "   "
    whitespace_stage["stages"][0]["stage_name"] = "   "
    vectors.append(whitespace_stage)
    oracle_only = model_protocol_payload(
        failure_reasons=[
            "boundary_required_oracle_missing:O_subagent_boundary_producer"
        ]
    )
    oracle_only["stages"][0]["failure_reasons"] = list(
        oracle_only["failure_reasons"]
    )
    vectors.append(oracle_only)
    failure_marked_valid = model_protocol_payload()
    failure_marked_valid["stages"][0]["valid"] = True
    vectors.append(failure_marked_valid)

    for index, payload in enumerate(vectors):
        python_terminal = is_terminal_model_protocol_deviation(payload)
        ps = _powershell_classification(tmp_path / str(index), payload)
        assert ps["terminal"] is python_terminal
        assert ps["accounted"] is is_accounted_terminal_result(payload)
        assert ps["result_class"] == normalized_result_class(payload)

    scored_with_failure = {
        "valid": True,
        "status": "completed",
        "failure_reasons": ["timeout"],
    }
    ps = _powershell_classification(tmp_path / "scored_failure", scored_with_failure)
    assert ps == {
        "terminal": False,
        "accounted": False,
        "result_class": "execution_invalid",
    }

    for index, field in enumerate(
        [
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
        ]
    ):
        payload = scored_payload()
        payload.pop(field)
        ps = _powershell_classification(tmp_path / f"scored_missing_{index}", payload)
        assert is_scored_run_validity(payload) is False, field
        assert ps == {
            "terminal": False,
            "accounted": False,
            "result_class": "execution_invalid",
        }, field

    for invalid_schema in (0, -1):
        payload = {
            "schema_version": invalid_schema,
            "valid": True,
            "status": "completed",
        }
        ps = _powershell_classification(
            tmp_path / f"scored_schema_{invalid_schema}", payload
        )
        assert is_scored_run_validity(payload) is False
        assert ps == {
            "terminal": False,
            "accounted": False,
            "result_class": "execution_invalid",
        }
