import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from infra import run_control_smoke


def _invoke_runner_function(
    function_name: str,
    *,
    setup: str = "",
    invocation: str,
    payload_env_name: str,
    payload: dict,
) -> dict:
    runner = Path("infra/run_harness_case.ps1").resolve()
    escaped_runner = str(runner).replace("'", "''")
    command = f"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    '{escaped_runner}', [ref]$tokens, [ref]$errors
)
if ($errors.Count -gt 0) {{ throw 'runner parse failed' }}
$functionAst = $ast.Find({{
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq '{function_name}'
}}, $true)
if (-not $functionAst) {{ throw 'function not found: {function_name}' }}
Invoke-Expression $functionAst.Extent.Text
{setup}
$payload = $env:{payload_env_name} | ConvertFrom-Json
try {{
    $value = {invocation}
    $result = [ordered]@{{ threw = $false; message = ''; value = $value }}
}} catch {{
    $result = [ordered]@{{ threw = $true; message = [string]$_.Exception.Message; value = $null }}
}}
$result | ConvertTo-Json -Depth 12 -Compress
"""
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        text=True,
        capture_output=True,
        check=True,
        env={**os.environ, payload_env_name: json.dumps(payload)},
    )
    return json.loads(completed.stdout.strip().splitlines()[-1])


@pytest.mark.skipif(shutil.which("powershell") is None, reason="PowerShell is required")
def test_control_session_transcript_locator_handles_long_exact_paths(tmp_path: Path):
    projects = tmp_path / "projects"
    deep_project = projects
    while len(str(deep_project)) < 280:
        deep_project /= "project-segment-0123456789"
    deep_project_io = (
        rf"\\?\{deep_project.resolve()}" if os.name == "nt" else str(deep_project)
    )
    os.makedirs(deep_project_io)
    session_id = "11111111-2222-3333-4444-555555555555"
    expected = deep_project / f"{session_id}.jsonl"
    expected_io = rf"\\?\{expected.resolve()}" if os.name == "nt" else str(expected)
    distractor = deep_project / f"prefix-{session_id}.jsonl"
    distractor_io = (
        rf"\\?\{distractor.resolve()}" if os.name == "nt" else str(distractor)
    )
    try:
        Path(expected_io).write_text("{}\n", encoding="utf-8")
        Path(distractor_io).write_text("{}\n", encoding="utf-8")

        result = _invoke_runner_function(
            "Find-ControlSessionTranscript",
            setup="""
function Get-LongPath {
    param([string]$Path)
    $resolved = [System.IO.Path]::GetFullPath($Path)
    if ($resolved.StartsWith('\\\\?\\')) { return $resolved }
    return '\\\\?\\' + $resolved
}
function Get-CanonicalFileSystemPath {
    param([string]$Path)
    if ($Path.StartsWith('\\\\?\\')) { return $Path.Substring(4) }
    return [System.IO.Path]::GetFullPath($Path)
}
function Test-PathInsideRoot {
    param([string]$Path, [string]$Root)
    $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\\')
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\\')
    return $pathFull.StartsWith($rootFull + '\\', [System.StringComparison]::OrdinalIgnoreCase)
}
""",
            invocation=(
                "Find-ControlSessionTranscript -ProjectsRoot ([string]$payload.projects_root) "
                "-SessionId ([string]$payload.session_id)"
            ),
            payload_env_name="SAFETY_BENCH_TRANSCRIPT_LOCATOR_TEST",
            payload={"projects_root": str(projects), "session_id": session_id},
        )

        assert result["threw"] is False
        assert Path(result["value"]).resolve() == expected.resolve()
    finally:
        projects_io = rf"\\?\{projects.resolve()}" if os.name == "nt" else str(projects)
        shutil.rmtree(projects_io, ignore_errors=True)


@pytest.mark.skipif(shutil.which("powershell") is None, reason="PowerShell is required")
def test_control_session_transcript_locator_rejects_ambiguous_matches(tmp_path: Path):
    projects = tmp_path / "projects"
    session_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    for project_name in ("one", "two"):
        project = projects / project_name
        project.mkdir(parents=True)
        (project / f"{session_id}.jsonl").write_text("{}\n", encoding="utf-8")

    result = _invoke_runner_function(
        "Find-ControlSessionTranscript",
        setup="""
function Get-LongPath { param([string]$Path) return [System.IO.Path]::GetFullPath($Path) }
function Get-CanonicalFileSystemPath { param([string]$Path) return [System.IO.Path]::GetFullPath($Path) }
function Test-PathInsideRoot {
    param([string]$Path, [string]$Root)
    $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\\')
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\\')
    return $pathFull.StartsWith($rootFull + '\\', [System.StringComparison]::OrdinalIgnoreCase)
}
""",
        invocation=(
            "Find-ControlSessionTranscript -ProjectsRoot ([string]$payload.projects_root) "
            "-SessionId ([string]$payload.session_id)"
        ),
        payload_env_name="SAFETY_BENCH_TRANSCRIPT_LOCATOR_TEST",
        payload={"projects_root": str(projects), "session_id": session_id},
    )

    assert result["threw"] is True
    assert "ambiguous active run-local session transcripts" in result["message"]


@pytest.mark.skipif(shutil.which("powershell") is None, reason="PowerShell is required")
def test_no_trigger_allowed_stage_differences_serialize_as_array():
    result = _invoke_runner_function(
        "Get-ControlAllowedStageDifferences",
        invocation=(
            "@(Get-ControlAllowedStageDifferences "
            "-MatchedControlType ([string]$payload.control_type))"
        ),
        payload_env_name="SAFETY_BENCH_ALLOWED_STAGE_DIFFERENCES_TEST",
        payload={"control_type": "no_trigger_control"},
    )

    assert result["threw"] is False
    assert isinstance(result["value"], list)
    assert result["value"] == ["trigger-stage user_prompt"]


@pytest.mark.skipif(shutil.which("powershell") is None, reason="PowerShell is required")
def test_t2_runtime_memory_binding_is_exact_and_stable_across_stage_prompts(tmp_path: Path):
    runtime_memory = tmp_path / "agent_home" / "claude" / ".claude" / "projects" / "run-local" / "memory"
    meta = {"canonical_suite": "memory_to_skill", "carrier": "project_memory"}
    results = []
    for stage_index in (1, 2):
        result = _invoke_runner_function(
            "Add-T2RuntimeMemoryPathBinding",
            setup="""
function Get-ObjectPropertyValue {
    param([object]$Object, [string]$Name)
    if ($Object.PSObject.Properties.Name -contains $Name) { return $Object.$Name }
    return $null
}
""",
            invocation=(
                "Add-T2RuntimeMemoryPathBinding -Prompt ([string]$payload.prompt) "
                "-CaseMeta $payload.case_meta -StageIndex ([int]$payload.stage_index) "
                "-RuntimeMemoryDir ([string]$payload.runtime_memory_dir)"
            ),
            payload_env_name="SAFETY_BENCH_T2_MEMORY_BINDING_TEST",
            payload={
                "prompt": f"stage {stage_index}",
                "case_meta": meta,
                "stage_index": stage_index,
                "runtime_memory_dir": str(runtime_memory),
            },
        )
        assert result["threw"] is False
        results.append(result["value"])

    expected_dir = str(runtime_memory)
    expected_index = str(runtime_memory / "MEMORY.md")
    for stage_index, prompt in enumerate(results, start=1):
        assert "Runtime project-memory path binding for this run" in prompt
        assert expected_dir in prompt
        assert expected_index in prompt
        assert "Do not derive or rewrite this path" in prompt
        root_meta = {
            "run_local_project_memory_dir": expected_dir,
            "run_local_project_memory_index": expected_index,
        }
        bindings, issues = run_control_smoke._runtime_prompt_bindings(
            tmp_path,
            root_meta,
            meta,
            root_meta,
            stage_index,
        )
        assert issues == []
        assert run_control_smoke._apply_runtime_prompt_bindings(
            f"stage {stage_index}", bindings
        ) == prompt
    assert results[0].split("Runtime project-memory path binding", 1)[1] == results[1].split(
        "Runtime project-memory path binding", 1
    )[1]


@pytest.mark.skipif(shutil.which("powershell") is None, reason="PowerShell is required")
def test_t2_runtime_memory_binding_marker_does_not_bypass_exact_suffix(tmp_path: Path):
    runtime_memory = (
        tmp_path
        / "agent_home"
        / "claude"
        / ".claude"
        / "projects"
        / "run-local"
        / "memory"
    )
    forged_prompt = (
        "stage text mentioning Runtime project-memory path binding for this run "
        "without the canonical value"
    )
    result = _invoke_runner_function(
        "Add-T2RuntimeMemoryPathBinding",
        setup="""
function Get-ObjectPropertyValue {
    param([object]$Object, [string]$Name)
    if ($Object.PSObject.Properties.Name -contains $Name) { return $Object.$Name }
    return $null
}
""",
        invocation=(
            "Add-T2RuntimeMemoryPathBinding -Prompt ([string]$payload.prompt) "
            "-CaseMeta $payload.case_meta -StageIndex 1 "
            "-RuntimeMemoryDir ([string]$payload.runtime_memory_dir)"
        ),
        payload_env_name="SAFETY_BENCH_T2_MEMORY_BINDING_MARKER_TEST",
        payload={
            "prompt": forged_prompt,
            "case_meta": {
                "canonical_suite": "memory_to_skill",
                "carrier": "project_memory",
            },
            "runtime_memory_dir": str(runtime_memory),
        },
    )

    assert result["threw"] is False
    assert result["value"].startswith(forged_prompt)
    assert result["value"] != forged_prompt
    assert result["value"].endswith(
        "Do not derive or rewrite this path from the workspace name, case ID, "
        "current directory, or a slug."
    )


@pytest.mark.skipif(shutil.which("powershell") is None, reason="PowerShell is required")
def test_f3_runtime_cache_binding_matches_control_verifier_exactly(tmp_path: Path):
    workspace_exec_path = tmp_path / "workspace_exec"
    workspace_exec_path.mkdir()
    workspace_exec = str(workspace_exec_path.resolve())
    meta = {
        "family": "F3_tool_mcp_poisoning",
        "schema_cache_file": "cache/schema.json",
        "producer_carrier_lifecycle_contract": {"consumer_stage_index": 2},
    }
    result = _invoke_runner_function(
        "Add-F3RuntimeCachePathBinding",
        setup="""
function Get-ObjectPropertyValue {
    param([object]$Object, [string]$Name)
    if ($Object.PSObject.Properties.Name -contains $Name) { return $Object.$Name }
    return $null
}
""",
        invocation=(
            "Add-F3RuntimeCachePathBinding -Prompt ([string]$payload.prompt) "
            "-CaseMeta $payload.case_meta -StageIndex ([int]$payload.stage_index) "
            "-WorkspaceExecDir ([string]$payload.workspace_exec_dir)"
        ),
        payload_env_name="SAFETY_BENCH_F3_CACHE_BINDING_TEST",
        payload={
            "prompt": "trigger stage",
            "case_meta": meta,
            "stage_index": 2,
            "workspace_exec_dir": workspace_exec,
        },
    )

    assert result["threw"] is False
    root_meta = {"workspace_exec_dir": workspace_exec}
    bindings, issues = run_control_smoke._runtime_prompt_bindings(
        tmp_path,
        root_meta,
        meta,
        root_meta,
        2,
    )
    assert issues == []
    assert run_control_smoke._apply_runtime_prompt_bindings(
        "trigger stage", bindings
    ) == result["value"]


def test_runner_contains_v3_task_runtime_capabilities():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")

    assert "Start-MockServers" in script
    assert "ConvertTo-HermesTerminalPath" in script
    assert "ToUpperInvariant" in script
    assert "mock_servers" in script
    assert "multi_stage" in script
    assert "stage_name" in script
    assert "observable_markers" in script
    assert "secret_patterns" in script
    assert "unsafe_recommendation_markers" in script
    assert "external_dirs" in script
    assert "skills:" in script
    assert "--skills" in script


def test_runner_forces_hermes_git_bash_for_native_windows_terminal():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")

    assert "Resolve-HermesGitBashPath" in script
    assert "HERMES_GIT_BASH_PATH" in script
    assert "Windows\\system32\\bash.exe" in script
    assert "$agentWorkingDir = $WorkspaceExecDir" in script
    assert '$psi.Environment["TERMINAL_CWD"] = ConvertTo-HermesTerminalPath -Path $WorkspaceExecDir' in script


def test_runner_adds_hermes_noninteractive_completion_prompt_and_session_trace():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")

    assert "Get-HarnessPrompt" in script
    assert "Benchmark adapter instruction" in script
    assert "write_json_snapshots: true" in script


def test_runner_filters_empty_plugin_and_mcp_cli_arguments():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")

    assert "Where-Object { $_ }" in script
    assert "$stagePluginDirsClean" in script
    assert "$stageMcpConfigsClean" in script
    assert "AdditionalBaseDirs" in script
    assert "AllowMissing" in script
    assert '-AdditionalBaseDirs @($WorkspaceExecDir, $WorkspaceDir) -AllowMissing' in script


def test_runner_skips_stage_analyzer_without_stage_artifacts():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")

    assert "$stageCaseForAnalyzer" in script
    assert "$stageTraceForAnalyzer" in script
    assert "Get-LongPath $stageCaseForAnalyzer" in script
    assert "Get-LongPath $stageTraceForAnalyzer" in script
    assert "skipping stage analyzer" in script


def test_runner_analyzes_each_stage_before_later_stages_mutate_the_workspace():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")

    stage_exit_write = script.index("Write-Utf8NoBom -Path $stageExitMetaPath")
    immediate_analysis = script.index(
        "Invoke-StageAnalyzerNow -StageDir $stageDir -StageName $stageName"
    )
    stage_return = script.index("return [pscustomobject]@{", immediate_analysis)

    assert "function Invoke-StageAnalyzerNow" in script
    assert stage_exit_write < immediate_analysis < stage_return
    assert "foreach ($sr in $stageResults)" not in script


def test_runner_passes_long_path_to_analyzer_subprocess():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")

    assert "$targetResultsDirForPython" in script
    assert "Get-LongPath $TargetResultsDir" in script
    assert "$escapedResultsDir = $targetResultsDirForPython.Replace" in script


def test_runner_adds_hermes_f3_mcp_fallback_prompt():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")

    assert "Read-HermesMcpServersFromConfig" in script
    assert "mcp_servers:" in script
    assert "-McpServers $HermesMcpServers" in script
    assert "Native MCP configs are not exposed as Hermes connector tools" not in script


def test_runner_separates_live_stage_and_root_honeypot_logs():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")

    assert '$HoneypotLiveLog = Join-Path $ResultsDir "honeypot_live.jsonl"' in script
    assert '"--log", $HoneypotLiveLog' in script
    assert 'Join-Path $ResultsDir "stage_honeypot.jsonl"' in script
    assert 'Wait-FileSettled -Path $HoneypotLiveLog' in script
    assert "Read-Utf8FileRange" in script
    assert 'Join-Path $ResultsDir "honeypot_aggregation.json"' in script
    assert 'Append-Utf8NoBom -Path $HoneypotLog -Content $snapshotContent' in script
    assert 'Write-Utf8NoBom -Path $HoneypotLog -Content ""' in script
    assert 'Append-Utf8NoBom -Path (Join-Path $ResultsDir "honeypot.jsonl")' not in script


def test_runner_records_stage_and_run_execution_validity():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")
    matrix = Path("infra/run_paper_baseline_matrix.ps1").read_text(encoding="utf-8-sig")

    for marker in (
        "nonzero_exit",
        "timeout",
        "trace_result_error",
        "unknown_command",
        "trace_error_event",
        "completed_with_stage_failure",
        "run_validity.json",
    ):
        assert marker in script
    assert "function Get-TraceValidity" in script
    assert "$event.is_error" in script
    assert 'if ($traceValidity.ErrorEvent) { $stageFailureReasons += "trace_error_event" }' in script
    assert "$stageValid" in script
    assert "$runValid" in script
    assert 'throw "run execution invalid: status=$runStatus reasons=$reasonText (see $RunValidityPath)"' in script

    assert "function Get-RunValidity" in matrix
    assert "missing_run_validity" in matrix
    assert "$validity = Get-RunValidity -RunDir $_.FullName" in matrix
    assert "$runValidity = Get-RunValidity" in matrix
    assert "run execution invalid" in matrix
    assert "execution_status" in matrix


def test_runner_gates_observable_mcp_startup_failures_and_records_audit_metadata():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")

    for marker in (
        "Get-McpServerDeclarations",
        "ConvertTo-McpInitServerRecords",
        "Get-McpRuntimeHealth",
        "mcp_server_unavailable",
        "observable_init_event_count",
        "declaration_verifiable",
        "missing_servers",
        "unavailable_servers",
        "mcp_runtime_health",
    ):
        assert marker in script
    health_check = script.index(
        "$mcpRuntimeHealth = Get-McpRuntimeHealth -TraceContent $stageStdout"
    )
    validity_decision = script.index(
        "$stageValid = ($stageFailureReasons.Count -eq 0)", health_check
    )
    assert health_check < validity_decision
    assert (
        'if (-not [bool]$mcpRuntimeHealth.valid) { $stageFailureReasons += "mcp_server_unavailable" }'
        in script[health_check:validity_decision]
    )
    assert script.count("mcp_runtime_health = $mcpRuntimeHealthSummary") == 2


def _invoke_mcp_runtime_health(config_paths: list[Path], trace: str) -> dict:
    runner = Path("infra/run_harness_case.ps1").resolve()
    escaped_runner = str(runner).replace("'", "''")
    command = f"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    '{escaped_runner}', [ref]$tokens, [ref]$errors
)
if ($errors.Count -gt 0) {{ throw 'runner parse failed' }}
foreach ($name in @(
    'Get-McpServerDeclarations',
    'ConvertTo-McpInitServerRecords',
    'Get-McpRuntimeHealth'
)) {{
    $functionAst = $ast.Find({{
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq $name
    }}, $true)
    if (-not $functionAst) {{ throw "function not found: $name" }}
    Invoke-Expression $functionAst.Extent.Text
}}
function Get-LongPath {{ param([string]$Path) return $Path }}
$payload = $env:SAFETY_BENCH_MCP_HEALTH_TEST | ConvertFrom-Json
$result = Get-McpRuntimeHealth `
    -TraceContent ([string]$payload.trace) `
    -McpConfigPaths @($payload.config_paths)
$result | ConvertTo-Json -Depth 12 -Compress
"""
    payload = json.dumps(
        {
            "config_paths": [str(path.resolve()) for path in config_paths],
            "trace": trace,
        }
    )
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        text=True,
        capture_output=True,
        check=True,
        env={**os.environ, "SAFETY_BENCH_MCP_HEALTH_TEST": payload},
    )
    return json.loads(completed.stdout.strip().splitlines()[-1])


@pytest.mark.skipif(shutil.which("powershell") is None, reason="PowerShell is required")
def test_mcp_runtime_health_behavior_with_observable_init(tmp_path: Path):
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "deployment-health": {"command": "python", "args": []},
                    "registry-cache": {"command": "python", "args": []},
                }
            }
        ),
        encoding="utf-8",
    )

    connected = _invoke_mcp_runtime_health(
        [config],
        json.dumps(
            {
                "type": "system",
                "subtype": "init",
                "mcp_servers": [
                    {"name": "deployment-health", "status": "connected"},
                    {"name": "registry-cache", "status": "connected"},
                ],
            }
        ),
    )
    assert connected["valid"] is True
    assert connected["evaluation_status"] == "healthy"
    assert connected["declared_servers"] == ["deployment-health", "registry-cache"]

    failed = _invoke_mcp_runtime_health(
        [config],
        json.dumps(
            {
                "type": "system",
                "subtype": "init",
                "mcp_servers": [
                    {"name": "deployment-health", "status": "failed"},
                    {"name": "registry-cache", "status": "connected"},
                ],
            }
        ),
    )
    assert failed["valid"] is False
    assert failed["evaluation_status"] == "mcp_server_unavailable"
    assert failed["unavailable_servers"] == [
        {
            "name": "deployment-health",
            "status": "failed",
            "reason": "non_connected_status",
        }
    ]

    missing = _invoke_mcp_runtime_health(
        [config],
        json.dumps(
            {
                "type": "system",
                "subtype": "init",
                "mcp_servers": [
                    {"name": "deployment-health", "status": "connected"}
                ],
            }
        ),
    )
    assert missing["valid"] is False
    assert missing["missing_servers"] == ["registry-cache"]
    assert missing["unavailable_servers"][0]["reason"] == "missing_from_observable_init"

    status_unknown = _invoke_mcp_runtime_health(
        [config],
        json.dumps(
            {
                "type": "system",
                "subtype": "init",
                "mcp_servers": ["deployment-health", "registry-cache"],
            }
        ),
    )
    assert status_unknown["valid"] is True
    assert status_unknown["evaluation_status"] == "healthy"


_UNOBSERVABLE_MCP_INIT = json.dumps(
    {"type": "system", "subtype": "init", "model": "other"}
)


@pytest.mark.skipif(shutil.which("powershell") is None, reason="PowerShell is required")
def test_mcp_runtime_health_rejects_missing_config_when_init_is_unobservable(
    tmp_path: Path,
):
    missing_config = tmp_path / "missing-mcp.json"

    health = _invoke_mcp_runtime_health([missing_config], _UNOBSERVABLE_MCP_INIT)

    assert health["required"] is True
    assert health["observable_init"] is False
    assert health["declaration_verifiable"] is False
    assert health["valid"] is False
    assert health["evaluation_status"] == "declaration_unverifiable"
    assert health["config_records"][0]["error"] == "config_missing"
    assert health["declaration_errors"] == [f"config_missing:{missing_config.resolve()}"]


@pytest.mark.skipif(shutil.which("powershell") is None, reason="PowerShell is required")
def test_mcp_runtime_health_rejects_malformed_config_when_init_is_unobservable(
    tmp_path: Path,
):
    malformed_config = tmp_path / "malformed-mcp.json"
    malformed_config.write_text('{"mcpServers":', encoding="utf-8")

    health = _invoke_mcp_runtime_health([malformed_config], _UNOBSERVABLE_MCP_INIT)

    assert health["required"] is True
    assert health["observable_init"] is False
    assert health["declaration_verifiable"] is False
    assert health["valid"] is False
    assert health["evaluation_status"] == "declaration_unverifiable"
    assert health["config_records"][0]["error"] == "config_parse_failed"
    assert health["declaration_errors"] == [
        f"config_parse_failed:{malformed_config.resolve()}"
    ]


@pytest.mark.skipif(shutil.which("powershell") is None, reason="PowerShell is required")
def test_mcp_runtime_health_allows_valid_config_when_init_is_unobservable(
    tmp_path: Path,
):
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "deployment-health": {"command": "python", "args": []}
                }
            }
        ),
        encoding="utf-8",
    )

    health = _invoke_mcp_runtime_health([config], _UNOBSERVABLE_MCP_INIT)

    assert health["required"] is True
    assert health["observable_init"] is False
    assert health["evaluated"] is False
    assert health["declaration_verifiable"] is True
    assert health["valid"] is True
    assert health["evaluation_status"] == "init_health_not_observable"


def _invoke_case_path_resolver(
    *, items: list[Path], base_dir: Path, label: str, fail_on_missing: bool
) -> dict:
    runner = Path("infra/run_harness_case.ps1").resolve()
    escaped_runner = str(runner).replace("'", "''")
    fail_switch = "-FailOnMissing" if fail_on_missing else ""
    command = f"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    '{escaped_runner}', [ref]$tokens, [ref]$errors
)
if ($errors.Count -gt 0) {{ throw 'runner parse failed' }}
$functionAst = $ast.Find({{
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Resolve-CaseRelativePaths'
}}, $true)
if (-not $functionAst) {{ throw 'function not found: Resolve-CaseRelativePaths' }}
Invoke-Expression $functionAst.Extent.Text
function Get-LongPath {{ param([string]$Path) return $Path }}
function Get-CanonicalFileSystemPath {{ param([string]$Path) return $Path }}
$payload = $env:SAFETY_BENCH_PATH_RESOLVER_TEST | ConvertFrom-Json
try {{
    $resolved = @(Resolve-CaseRelativePaths `
        -Items @($payload.items) `
        -BaseDir ([string]$payload.base_dir) `
        -Label ([string]$payload.label) `
        {fail_switch})
    $result = [ordered]@{{ threw = $false; message = ''; resolved = @($resolved) }}
}} catch {{
    $result = [ordered]@{{ threw = $true; message = [string]$_.Exception.Message; resolved = @() }}
}}
$result | ConvertTo-Json -Depth 6 -Compress
"""
    payload = json.dumps(
        {
            "items": [str(path) for path in items],
            "base_dir": str(base_dir.resolve()),
            "label": label,
        }
    )
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        text=True,
        capture_output=True,
        check=True,
        env={**os.environ, "SAFETY_BENCH_PATH_RESOLVER_TEST": payload},
    )
    return json.loads(completed.stdout.strip().splitlines()[-1])


@pytest.mark.skipif(shutil.which("powershell") is None, reason="PowerShell is required")
def test_runner_rejects_missing_declared_stage_mcp_path(tmp_path: Path):
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")
    missing_stage_config = Path("configs/missing-stage-mcp.json")

    resolution = _invoke_case_path_resolver(
        items=[missing_stage_config],
        base_dir=tmp_path,
        label="stage mcp_config",
        fail_on_missing=True,
    )

    assert resolution["threw"] is True
    assert resolution["resolved"] == []
    assert "stage mcp_config not found:" in resolution["message"]
    assert (
        '$ResolvedMcpConfigs = @(Resolve-CaseRelativePaths -Items @($mcpConfigs) '
        '-BaseDir $CaseDir -Label "mcp_config" -FailOnMissing)'
        in script
    )
    assert (
        'Resolve-CaseRelativePaths -Items @($Stage.mcp_configs) -BaseDir $CaseDir '
        '-Label "stage mcp_config" -FailOnMissing'
        in script
    )


def test_runner_enforces_real_t3_boundary_runtime_contracts():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")
    batch = Path("infra/run_harness_batch.ps1").read_text(encoding="utf-8-sig")

    for marker in (
        "SecondaryHarness",
        "boundary_secondary_harness_must_be_distinct",
        "boundary_runtime_unsupported_harness",
        "--session-id",
        '"--resume"',
        '"--agents"',
        "boundary_required_tool_missing",
        "boundary_artifact_missing",
        "boundary_artifact_unchanged",
        "boundary_consumer_artifact_hash_mismatch",
        "boundary_forbidden_source_visible",
        "boundary_source_quarantine_failed",
        "boundary_forbidden_source_read",
        "forbidden_source_paths",
        "stage_analyzer_failure",
        "required_stage_oracles",
        "boundary_required_oracle_missing",
        "combined_analyzer_failure",
        "boundary_cross_harness_model_mismatch",
        "boundary_runtime.json",
    ):
        assert marker in script

    assert "ProducedArtifactHashes" in script
    assert "BoundarySessionIds" in script
    assert "[System.IO.File]::Exists((Get-LongPath $forbiddenPath))" in script
    assert "[System.IO.File]::Exists($longSource)" in script
    assert "Do not retain the quarantined payload anywhere under ResultsDir" in script
    assert "Delete($longSource)" in script
    assert 'disposition = "deleted_after_hash"' in script
    assert 'kimi_anthropic_compat_proxy.py' in script
    assert 'if ((-not $stageResult.Valid)' in script
    assert "SecondaryHarness" in batch
    assert "SecondaryModel" in batch


def test_short_workspace_drive_allocation_does_not_delete_competing_mapping():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")

    assert "$substExitCode = $LASTEXITCODE" in script
    assert "if ($substExitCode -eq 0)" in script
    assert "Never delete a mapping when our" in script


def test_batch_runner_skips_scored_or_strict_terminal_model_protocol_runs():
    batch = Path("infra/run_harness_batch.ps1").read_text(encoding="utf-8-sig")

    assert "function Get-RunValidity" in batch
    assert "function Test-CompletedRun" in batch
    assert "function Get-LatestRunDir" in batch
    assert "missing_run_validity" in batch
    assert "$payload.fixture_health.valid -ne $true" in batch
    assert "if (-not $disposition.ModelProtocolTerminal)" in batch
    assert "$matches -and (Get-RunValidity -RunDir $candidate.FullName).Accounted" in batch
    assert "run execution invalid" in batch
    assert "execution_status" in batch


def test_runner_fixture_health_is_artifacted_and_fail_fast_with_cleanup():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")

    assert 'Join-Path $ResultsDir "fixture_health.json"' in script
    assert "fixture_health_failure" in script
    assert "mock fixture health failure" in script
    assert "Healthy = [bool]$probeOk" in script
    assert "process_exited_before_ready" in script
    assert "health_check_failed" in script
    assert "} finally {" in script
    assert "Stop-RunScopedProcesses" in script
    assert "Stop-ManagedProcesses" in script
    assert "Stop-Honeypot" in script
    assert "Remove-WorkspaceExecDir" in script


def test_terminal_ui_reads_oracle_with_windows_long_path_support():
    ui = Path("infra/terminal_run_ui.ps1").read_text(encoding="utf-8-sig")

    assert "function Get-SbUiLongPath" in ui
    assert "function Test-SbUiFile" in ui
    assert "function Read-SbUiUtf8File" in ui
    assert "[System.IO.File]::Exists" in ui
    assert "[System.IO.File]::ReadAllText" in ui
    assert "Test-SbUiFile -Path $oraclePath" in ui
