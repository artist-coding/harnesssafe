import json
from pathlib import Path
import shutil
import subprocess

import pytest


def test_runner_global_config_guard_ignores_volatile_lock_files():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")

    assert "Test-ConfigInventoryIgnoredFile" in script
    assert "*.lock" in script
    assert "ide/*.lock" in script
    assert "hermes_sessions" in script


def test_runner_global_config_guard_is_fail_closed_and_classifies_external_drift():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")

    assert "selected_harness_attributed" in script
    assert "trace_attributed_cross_harness" in script
    assert "unattributed_external_drift" in script
    assert 'if ($globalConfigTouched) { $runFailureReasons += "global_config_side_effect" }' in script
    assert 'if ($globalConfigExternalDrift) { $runFailureReasons += "global_config_external_drift" }' in script
    assert "global_config_observed_changes" in script
    assert "global_config_external_drift" in script
    assert script.index("$GlobalConfigAfter = Get-ConfigInventory") < script.index(
        "$runValid = ($runFailureReasons.Count -eq 0)"
    )


def test_runner_global_config_inventory_hash_failure_is_explicit_and_invalid():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")

    assert 'operation = "hash"' in script
    assert 'error_type = "hash_read_failure"' in script
    assert "if ($null -eq $hash)" in script
    assert "$inventoryComplete = $false" in script
    assert 'if (-not $globalConfigInventoryComplete) { $runFailureReasons += "global_config_inventory_failure" }' in script


def test_runner_global_config_inventory_enumeration_failure_is_not_silenced():
    script = Path("infra/run_harness_case.ps1").read_text(encoding="utf-8-sig")

    assert "Get-ChildItem -LiteralPath $path -Recurse -File -ErrorAction Stop" in script
    assert 'operation = "enumerate"' in script
    assert 'error_type = "enumeration_failure"' in script
    assert "global_config_inventory_complete" in script
    assert "global_config_inventory_errors" in script
    assert "Get-ChildItem -LiteralPath $path -Recurse -File -ErrorAction SilentlyContinue" not in script


def _invoke_inventory_function(root: Path, mocks: str) -> dict:
    runner = Path("infra/run_harness_case.ps1").resolve()
    command = f"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    '{runner}', [ref]$tokens, [ref]$errors
)
if ($errors.Count -gt 0) {{ throw 'runner parse failed' }}
$functionAst = $ast.Find({{
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Get-ConfigInventory'
}}, $true)
if (-not $functionAst) {{ throw 'Get-ConfigInventory not found' }}
Invoke-Expression $functionAst.Extent.Text
function Test-ConfigInventoryIgnoredFile {{ param($RootName, $RelativePath) return $false }}
{mocks}
$result = Get-ConfigInventory -Roots @([ordered]@{{
    name = 'fixture'
    path = '{root}'
    recursive = $true
}})
$result | ConvertTo-Json -Depth 10 -Compress
"""
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(completed.stdout.strip().splitlines()[-1])


@pytest.mark.skipif(shutil.which("powershell") is None, reason="PowerShell is required")
def test_global_config_inventory_behavior_marks_hash_read_failure_incomplete(tmp_path: Path):
    (tmp_path / "settings.json").write_text("{}", encoding="utf-8")
    result = _invoke_inventory_function(
        tmp_path,
        "function Get-Sha256Hex { param($Path) return $null }",
    )

    assert result["complete"] is False
    assert result["errors"][0]["operation"] == "hash"
    assert result["errors"][0]["error_type"] == "hash_read_failure"


@pytest.mark.skipif(shutil.which("powershell") is None, reason="PowerShell is required")
def test_global_config_inventory_behavior_marks_enumeration_failure_incomplete(tmp_path: Path):
    result = _invoke_inventory_function(
        tmp_path,
        "function Get-Sha256Hex { param($Path) return 'hash' }\n"
        "function Get-ChildItem { param($LiteralPath, [switch]$Recurse, [switch]$File, $ErrorAction) throw 'blocked' }",
    )

    assert result["complete"] is False
    assert result["errors"][0]["operation"] == "enumerate"
    assert result["errors"][0]["error_type"] == "enumeration_failure"
