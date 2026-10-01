<#
.SYNOPSIS
  Run every active manifest suite against one selected harness.
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("claude", "codex", "hermes")]
    [string]$Harness,

    [string]$RunLabel = "",
    [string]$Model = "",
    [int]$TimeoutSec = 240,
    [switch]$SkipCompleted,
    [switch]$NoReport
)

$ErrorActionPreference = "Stop"

$BenchRoot = Split-Path -Parent $PSScriptRoot
$ManifestPath = Join-Path $BenchRoot "runs\manifest.json"
$RunHarnessBatch = Join-Path $PSScriptRoot "run_harness_batch.ps1"
$ReportActiveRun = Join-Path $PSScriptRoot "report_active_run.py"

$manifest = Get-Content -Raw $ManifestPath -Encoding UTF8 | ConvertFrom-Json
$activeSuites = @(
    $manifest.suites.PSObject.Properties |
        Where-Object { $_.Value.status -eq "active" } |
        ForEach-Object { $_.Name }
)

if ($activeSuites.Count -eq 0) {
    throw "no active suites found in manifest"
}

$label = if ($RunLabel) { $RunLabel } else { "active_$(Get-Date -Format 'yyyyMMdd_HHmmss')" }

foreach ($suite in $activeSuites) {
    Write-Host ""
    Write-Host ("#" * 80)
    Write-Host "[run_active_suites] harness=$Harness suite=$suite label=$label"
    Write-Host ("#" * 80)
    $batchArgs = @{
        Harness = $Harness
        Suite = $suite
        PermissionProfile = "max_permission"
        IsolationMode = "isolated_home"
        RunLabel = $label
        TimeoutSec = $TimeoutSec
        SkipCompleted = $SkipCompleted
    }
    if ($Model) { $batchArgs["Model"] = $Model }
    & $RunHarnessBatch @batchArgs
}

if (-not $NoReport) {
    Write-Host ""
    Write-Host ("#" * 80)
    Write-Host "[run_active_suites] generating unified report label=$label harness=$Harness"
    Write-Host ("#" * 80)
    & python $ReportActiveRun --label $label --harness $Harness
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "[run_active_suites] report generation exited with $LASTEXITCODE"
    }
}
