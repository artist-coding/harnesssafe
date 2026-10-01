from __future__ import annotations

import base64
import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from infra import result_classification


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "infra" / "run_harness_case.ps1"


def _classification_function_chunk() -> str:
    script = RUNNER.read_text(encoding="utf-8-sig")
    start = script.index("function Get-TraceValidity")
    end = script.index("function Get-McpServerDeclarations")
    return script[start:end]


def _trace(*, include_exact_write: bool = False) -> str:
    events: list[dict[str, object]] = [
        {
            "type": "assistant",
            "parent_tool_use_id": "agent-call",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "wrong-write",
                        "name": "Write",
                        "input": {"file_path": "W:/handoff/proced_context.md"},
                    }
                ]
            },
        },
        {
            "type": "user",
            "message": {
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "wrong-write",
                        "content": "File created successfully",
                    }
                ]
            },
        },
    ]
    if include_exact_write:
        events.extend(
            [
                {
                    "type": "assistant",
                    "parent_tool_use_id": "agent-call",
                    "message": {
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "exact-write",
                                "name": "Write",
                                "input": {
                                    "file_path": "W:/handoff/produced_context.md"
                                },
                            }
                        ]
                    },
                },
                {
                    "type": "user",
                    "message": {
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": "exact-write",
                                "content": "File created successfully",
                            }
                        ]
                    },
                },
            ]
        )
    events.append(
        {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "api_error_status": None,
            "terminal_reason": "completed",
        }
    )
    return "\n".join(json.dumps(event) for event in events)


def _run_powershell_probe(tmp_path: Path, trace: str) -> dict[str, object]:
    executable = shutil.which("pwsh") or shutil.which("powershell")
    if not executable:
        pytest.skip("PowerShell is not installed")
    encoded = base64.b64encode(trace.encode("utf-8")).decode("ascii")
    helper = str(ROOT / "infra" / "result_classification.ps1").replace("'", "''")
    probe = tmp_path / "model_protocol_probe.ps1"
    probe.write_text(
        _classification_function_chunk()
        + f"""
. '{helper}'
$trace = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'))
$validity = Get-TraceValidity -TraceContent $trace
$evidence = @(Get-ModelProtocolArtifactPathEvidence `
    -TraceContent $trace `
    -RequiredArtifacts @('handoff/produced_context.md') `
    -StageName 'phase1_subagent_producer' `
    -StageIndex 1 `
    -Harness 'claude' `
    -Model 'test-model')
$stage = [pscustomobject]@{{
    StageName = 'phase1_subagent_producer'
    StageIndex = 1
    ExitCode = 0
    TimedOut = $false
    FailureReasons = @('boundary_artifact_missing')
    RequiredArtifactPaths = @('handoff/produced_context.md')
    TraceResultError = $false
    UnknownCommand = $false
    TraceErrorEvent = $false
    TraceApiError = $false
    TraceResultSuccess = $true
    TraceTerminalCompleted = $true
    TraceStderrEmpty = $true
    McpRuntimeHealth = [pscustomobject]@{{ valid = $true }}
}}
$hard = Test-ModelProtocolHardAttribution `
    -StageResults @($stage) `
    -RunFailureReasons @('boundary_artifact_missing') `
    -Evidence @($evidence) `
    -FixtureHealthValid $true `
    -RunnerHealthy $true `
    -GlobalConfigHealthy $true `
    -MaterializationHealthy $true `
    -ControlRuntimeHealthy $true
$stage.TraceApiError = $true
$hardApiError = Test-ModelProtocolHardAttribution `
    -StageResults @($stage) `
    -RunFailureReasons @('boundary_artifact_missing') `
    -Evidence @($evidence) `
    -FixtureHealthValid $true `
    -RunnerHealthy $true `
    -GlobalConfigHealthy $true `
    -MaterializationHealthy $true `
    -ControlRuntimeHealthy $true
$stage.TraceApiError = $false
$hardRunnerError = Test-ModelProtocolHardAttribution `
    -StageResults @($stage) `
    -RunFailureReasons @('boundary_artifact_missing', 'runner_exception') `
    -Evidence @($evidence) `
    -FixtureHealthValid $true `
    -RunnerHealthy $true `
    -GlobalConfigHealthy $true `
    -MaterializationHealthy $true `
    -ControlRuntimeHealthy $true
$stagePayload = [ordered]@{{
    stage_name = 'phase1_subagent_producer'
    stage_index = 1
    valid = $false
    exit_code = 0
    timed_out = $false
    failure_reasons = @('boundary_artifact_missing')
    required_artifact_paths = @('handoff/produced_context.md')
    trace_result_error = $false
    unknown_command = $false
    trace_error_event = $false
    trace_result_success = $true
    trace_api_error = $false
    trace_terminal_completed = $true
    trace_stderr_empty = $true
    mcp_runtime_health = [ordered]@{{ valid = $true }}
}}
$payload = [ordered]@{{
    schema_version = 2
    valid = $false
    status = 'model_protocol_incomplete'
    result_class = 'model_protocol_deviation'
    display_node = 'N-1'
    model_protocol_status = 'deviated'
    model_protocol_failure_kind = 'required_artifact_path_mismatch'
    model_protocol_failure_stage = 'phase1_subagent_producer'
    model_protocol_evidence = @($evidence)
    terminal_outcome = $true
    retry_eligible = $false
    safety_score_eligible = $false
    formal_asr_eligible = $false
    failure_reasons = @('boundary_artifact_missing')
    expected_stage_count = 1
    completed_stage_count = 1
    fixture_health = [ordered]@{{ valid = $true }}
    global_config_touched = $false
    global_config_external_drift = $false
    global_config_inventory_complete = $true
    control_intervention_execution_valid = $true
    mcp_runtime_health = [ordered]@{{ valid = $true }}
    analyzer_exit_code = 0
    oracle_present = $true
    oracle_valid = $true
    materialization_attestation_untampered = $true
    runner_error = ''
    stages = @($stagePayload)
}}
$terminalPayload = Test-SbTerminalModelProtocolPayload -Payload $payload
$payload.failure_reasons = @('timeout')
$terminalTimeoutPayload = Test-SbTerminalModelProtocolPayload -Payload $payload
[pscustomobject]@{{
    validity = $validity
    evidence = @($evidence)
    hard = [bool]$hard
    hard_api_error = [bool]$hardApiError
    hard_runner_error = [bool]$hardRunnerError
    terminal_payload = [bool]$terminalPayload
    terminal_timeout_payload = [bool]$terminalTimeoutPayload
}} | ConvertTo-Json -Depth 12 -Compress
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            executable,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(probe),
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return json.loads(completed.stdout.strip())


def test_runner_emits_schema_v2_terminal_nminus1_contract() -> None:
    script = RUNNER.read_text(encoding="utf-8-sig")
    assert '$ResultClassificationHelper = Join-Path $PSScriptRoot "result_classification.ps1"' in script
    assert "schema_version = 2" in script
    assert 'result_class = $resultClass' in script
    assert 'display_node = if ($modelProtocolHardEligible) { "N-1" } else { "" }' in script
    assert 'model_protocol_status = $modelProtocolStatus' in script
    assert 'model_protocol_failure_kind = $modelProtocolFailureKind' in script
    assert 'model_protocol_failure_stage = $modelProtocolStage' in script
    assert 'terminal_outcome = [bool]($runValid -or $modelProtocolHardEligible)' in script
    assert 'retry_eligible = [bool](-not $runValid -and -not $modelProtocolHardEligible)' in script
    assert 'safety_score_eligible = [bool]$runValid' in script
    assert 'formal_asr_eligible = if ($runValid) { $null } else { $false }' in script
    assert 'analyzer_exit_code = $null' in script
    assert '$runValidity.oracle_present = [bool]$combinedOraclePresent' in script
    assert '$runValidity.oracle_valid = [bool]$combinedOracleValid' in script
    assert "if (-not $runValid -and -not $terminalModelProtocolOutcome)" in script
    assert "Test-SbTerminalModelProtocolPayload -Payload ([pscustomobject]$runValidity)" in script


def test_runner_model_protocol_evidence_round_trips_as_json_array(tmp_path: Path) -> None:
    executable = shutil.which("pwsh") or shutil.which("powershell")
    if not executable:
        pytest.skip("PowerShell is not installed")

    script = RUNNER.read_text(encoding="utf-8-sig")
    match = re.search(
        r"^\s*model_protocol_evidence\s*=\s*(.+)$",
        script,
        flags=re.MULTILINE,
    )
    assert match is not None
    assignment_expression = match.group(1).strip()

    probe = tmp_path / "model_protocol_evidence_json_round_trip.ps1"
    probe.write_text(
        f"""
function New-ScoredPayload {{
    param([bool]$Eligible, [array]$Evidence)
    $modelProtocolHardEligible = $Eligible
    $modelProtocolEvidence = @($Evidence)
    return [ordered]@{{
        schema_version = 2
        valid = $true
        status = 'completed'
        result_class = 'scored'
        display_node = ''
        model_protocol_status = 'completed'
        model_protocol_failure_kind = ''
        model_protocol_failure_stage = ''
        model_protocol_evidence = {assignment_expression}
        terminal_outcome = $true
        retry_eligible = $false
        safety_score_eligible = $true
        failure_reasons = @()
        expected_stage_count = 1
        completed_stage_count = 1
        fixture_health = [ordered]@{{ valid = $true }}
        mcp_runtime_health = [ordered]@{{ valid = $true }}
        analyzer_exit_code = 0
        oracle_present = $true
        oracle_valid = $true
        global_config_touched = $false
        global_config_external_drift = $false
        global_config_inventory_complete = $true
        control_intervention_execution_valid = $true
        materialization_attestation_untampered = $true
        runner_error = ''
        stages = @(
            [ordered]@{{
                stage_name = 'single'
                stage_index = 1
                valid = $true
                exit_code = 0
                timed_out = $false
                failure_reasons = @()
                trace_result_error = $false
                unknown_command = $false
                trace_error_event = $false
                trace_result_success = $true
                trace_api_error = $false
                trace_terminal_completed = $true
                trace_stderr_empty = $true
                mcp_runtime_health = [ordered]@{{ valid = $true }}
            }}
        )
    }}
}}

$emptyPayload = New-ScoredPayload -Eligible $false -Evidence @()
$singlePayload = New-ScoredPayload -Eligible $true -Evidence @(
    [ordered]@{{ attribution = 'model_tool_argument'; tool_use_id = 'tool-1' }}
)
$multiplePayload = New-ScoredPayload -Eligible $true -Evidence @(
    [ordered]@{{ attribution = 'model_tool_argument'; tool_use_id = 'tool-1' }},
    [ordered]@{{ attribution = 'model_tool_argument'; tool_use_id = 'tool-2' }}
)
$malformedPayload = New-ScoredPayload -Eligible $false -Evidence @()
$malformedPayload.model_protocol_evidence = [ordered]@{{}}

[ordered]@{{
    empty_json = ($emptyPayload | ConvertTo-Json -Depth 8 -Compress)
    single_json = ($singlePayload | ConvertTo-Json -Depth 8 -Compress)
    multiple_json = ($multiplePayload | ConvertTo-Json -Depth 8 -Compress)
    malformed_json = ($malformedPayload | ConvertTo-Json -Depth 8 -Compress)
}} | ConvertTo-Json -Depth 8 -Compress
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            executable,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(probe),
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    serialized = json.loads(completed.stdout.strip())
    empty = json.loads(serialized["empty_json"])
    single = json.loads(serialized["single_json"])
    multiple = json.loads(serialized["multiple_json"])
    malformed = json.loads(serialized["malformed_json"])

    assert empty["model_protocol_evidence"] == []
    assert single["model_protocol_evidence"] == [
        {"attribution": "model_tool_argument", "tool_use_id": "tool-1"}
    ]
    assert multiple["model_protocol_evidence"] == [
        {"attribution": "model_tool_argument", "tool_use_id": "tool-1"},
        {"attribution": "model_tool_argument", "tool_use_id": "tool-2"},
    ]
    assert result_classification.is_scored_run_validity(empty) is True
    assert result_classification.is_scored_run_validity(single) is False
    assert result_classification.is_scored_run_validity(multiple) is False
    assert malformed["model_protocol_evidence"] == {}
    assert result_classification.is_scored_run_validity(malformed) is False


def test_hard_attribution_accepts_successful_near_path_write(tmp_path: Path) -> None:
    result = _run_powershell_probe(tmp_path, _trace())
    assert result["validity"]["ResultSuccess"] is True
    assert result["validity"]["ApiError"] is False
    assert result["validity"]["TerminalCompleted"] is True
    assert result["hard"] is True
    assert result["hard_api_error"] is False
    assert result["hard_runner_error"] is False
    assert result["terminal_payload"] is True
    assert result["terminal_timeout_payload"] is False
    assert result["evidence"] == [
        {
            "attribution": "model_tool_argument",
            "failure_kind": "required_artifact_path_mismatch",
            "stage_name": "phase1_subagent_producer",
            "stage_index": 1,
            "harness": "claude",
            "model": "test-model",
            "expected_path": "handoff/produced_context.md",
            "observed_path": "W:/handoff/proced_context.md",
            "observed_path_normalized": "handoff/proced_context.md",
            "tool_name": "Write",
            "tool_use_id": "wrong-write",
            "parent_tool_use_id": "agent-call",
            "tool_result_success": True,
            "filename_edit_distance": 2,
        }
    ]


def test_successful_exact_write_suppresses_path_mismatch(tmp_path: Path) -> None:
    result = _run_powershell_probe(tmp_path, _trace(include_exact_write=True))
    assert result["evidence"] is None or result["evidence"] == []
    assert result["hard"] is False
