<#
.SYNOPSIS
  Run paper-oriented Safety Bench control experiments.

.DESCRIPTION
  This runner executes the per-case control_suite entries that support causal
  claims in the paper: clean source, no persist, no trigger, and cleanup. It
  reuses run_harness_case.ps1 so controls keep the same materialization,
  isolation, honeypot, and oracle pipeline as attack runs.
#>
param(
    [ValidateSet("core", "extended", "exploratory", "all")]
    [string]$CaseSet = "all",

    [ValidateSet("claude", "codex", "hermes")]
    [string[]]$Harnesses = @("claude"),

    [ValidateSet("clean_control", "no_persist_control", "no_trigger_control", "cleanup_control", "all")]
    [string[]]$ControlTypes = @("clean_control", "no_persist_control", "no_trigger_control", "cleanup_control"),

    [string]$RunLabel = "",
    [int]$Trials = 1,
    [int]$TimeoutSec = 300,
    [string]$KimiModel = "kimi-k2.6",
    [string]$ClaudeModel = "",
    [string[]]$ClaudeModels = @(),
    [string]$ClaudeBaseUrl = "",
    [string]$ClaudeApiKeyEnv = "",
    [string]$ClaudeApiKeyPath = "",
    [string]$ClaudeAuthTokenEnv = "",
    [ValidateSet("max_permission", "default_permission")]
    [string]$PermissionProfile = "max_permission",
    [switch]$SkipCompleted,
    [switch]$NoReport,
    [switch]$StopOnFailure,
    [switch]$SkipKimiPreflight,
    [string[]]$CaseDirFilter = @(),
    [string]$CaseListPath = "",
    [int]$CaseLimit = 0
)

$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$SecretsHelper = Join-Path $PSScriptRoot "secrets.ps1"
if (Test-Path -LiteralPath $SecretsHelper) { . $SecretsHelper }
$ResultClassification = Join-Path $PSScriptRoot "result_classification.ps1"
if (Test-Path -LiteralPath $ResultClassification) { . $ResultClassification }
$AllPaperControlTypes = @("clean_control", "no_persist_control", "no_trigger_control", "cleanup_control")
if ($ControlTypes -contains "all") {
    $ControlTypes = $AllPaperControlTypes
}

function Get-SafeName {
    param([string]$Name)
    if (-not $Name) { return "default" }
    return ($Name -replace '[^A-Za-z0-9_.-]', '_')
}

function Expand-ModelValues {
    param([string[]]$Values)
    $out = @()
    foreach ($value in @($Values)) {
        foreach ($part in ([string]$value).Split(",")) {
            $token = $part.Trim()
            if ($token -and $out -notcontains $token) { $out += $token }
        }
    }
    return $out
}

function Read-JsonFile {
    param([string]$Path)
    return Get-Content -Raw -Encoding UTF8 -LiteralPath $Path | ConvertFrom-Json
}

function Get-ControlRunValidity {
    param([string]$RunDir)
    $fallback = [pscustomobject]@{
        Valid = $false
        Accounted = $false
        Scored = $false
        ResultClass = "execution_invalid"
        DisplayNode = ""
        TerminalOutcome = $false
        RetryEligible = $true
        Status = "missing_run_validity"
        FailureReasons = @("missing_run_validity")
        Path = ""
    }
    if (-not $RunDir) { return $fallback }
    $validityPath = Join-Path $RunDir "run_validity.json"
    $fallback.Path = $validityPath
    if (-not (Test-Path -LiteralPath $validityPath)) { return $fallback }
    try {
        $payload = Read-JsonFile -Path $validityPath
        $disposition = Get-SbRunValidityDisposition -Payload $payload
        $failureReasons = if ($payload.PSObject.Properties.Name -contains "failure_reasons") {
            @($payload.failure_reasons | ForEach-Object { [string]$_ })
        } else {
            @()
        }
        return [pscustomobject]@{
            Valid = [bool]$disposition.Scored
            Accounted = [bool]$disposition.Accounted
            Scored = [bool]$disposition.Scored
            ResultClass = [string]$disposition.ResultClass
            DisplayNode = [string]$disposition.DisplayNode
            TerminalOutcome = [bool]$disposition.TerminalOutcome
            RetryEligible = [bool]$disposition.RetryEligible
            Status = [string]$payload.status
            FailureReasons = @($failureReasons)
            Path = $validityPath
        }
    } catch {
        $fallback.Status = "invalid_run_validity"
        $fallback.FailureReasons = @("invalid_run_validity")
        return $fallback
    }
}

function Get-LatestControlRunDir {
    param([string]$CaseDir, [string]$Harness, [string]$Label, [string]$ControlType)
    $resultsDir = Join-Path $CaseDir "results"
    if (-not (Test-Path $resultsDir)) { return $null }
    foreach ($candidate in @(Get-ChildItem -Path $resultsDir -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)) {
        $caseJson = Join-Path $candidate.FullName "case.json"
        if (-not (Test-Path -LiteralPath $caseJson)) { continue }
        try {
            $meta = Read-JsonFile -Path $caseJson
            if (
                [string]$meta.harness -eq $Harness -and
                [string]$meta.run_label -eq $Label -and
                [string]$meta.control_type -eq $ControlType
            ) {
                return $candidate
            }
        } catch {}
    }
    return $null
}

function Test-CaseSet {
    param([object]$Meta, [string]$SelectedCaseSet)
    if ($SelectedCaseSet -in @("all", "core")) { return $true }
    if ($SelectedCaseSet -eq "extended") { return [string]$Meta.reporting_track -eq "extended_benchmark" }
    if ($SelectedCaseSet -eq "exploratory") { return [string]$Meta.reporting_track -eq "exploratory_case_study" }
    return $false
}

function Normalize-CaseDirFilter {
    param([string]$Value)
    if (-not $Value) { return "" }
    return (($Value -replace '\\', '/').Trim().TrimStart('/'))
}

function Get-CaseDirFilters {
    param([string[]]$InlineFilters, [string]$ListPath)
    $filters = @()
    foreach ($item in @($InlineFilters)) {
        $normalized = Normalize-CaseDirFilter -Value $item
        if ($normalized) { $filters += $normalized }
    }
    if ($ListPath) {
        if (-not (Test-Path -LiteralPath $ListPath)) {
            throw "case list file not found: $ListPath"
        }
        foreach ($line in Get-Content -Encoding UTF8 -LiteralPath $ListPath) {
            $trimmed = $line.Trim()
            if (-not $trimmed -or $trimmed.StartsWith("#")) { continue }
            $normalized = Normalize-CaseDirFilter -Value $trimmed
            if ($normalized) { $filters += $normalized }
        }
    }
    return @($filters | Select-Object -Unique)
}

function Test-CaseDirSelected {
    param([string]$EntryCaseDir, [string[]]$Filters)
    if (-not $Filters -or $Filters.Count -eq 0) { return $true }
    $normalized = Normalize-CaseDirFilter -Value $EntryCaseDir
    return @($Filters) -contains $normalized
}

function Get-HarnessModels {
    param([string]$Harness)
    if ($Harness -eq "claude") {
        $models = Expand-ModelValues -Values $ClaudeModels
        if ($models.Count -eq 0 -and $ClaudeModel) { $models = @($ClaudeModel) }
        if ($models.Count -eq 0) { $models = @("") }
        return $models
    }
    return @($KimiModel)
}

function Get-DashScopeCodingKeyStrict {
    param([string]$BenchRoot)
    if (Get-Command Get-SafetyBenchProviderCredential -ErrorAction SilentlyContinue) {
        $secret = Get-SafetyBenchProviderCredential `
            -BenchRoot $BenchRoot `
            -Provider "dashscope" `
            -AuthTarget "DASHSCOPE_CODING_API_KEY" `
            -EnvCandidates @("DASHSCOPE_CODING_API_KEY", "DASHSCOPE_API_KEY")
        if ($secret.Value) {
            return [pscustomobject]@{ Key = $secret.Value; Source = $secret.Source }
        }
    }
    $secretPath = Join-Path $BenchRoot "bench_state\secrets\codex\api_key.txt"
    if (Test-Path $secretPath) {
        $value = (Get-Content -Raw -Encoding UTF8 -LiteralPath $secretPath).Trim()
        if ($value) {
            return [pscustomobject]@{ Key = $value; Source = "bench_state\secrets\codex\api_key.txt" }
        }
    }
    $envValue = [Environment]::GetEnvironmentVariable("DASHSCOPE_CODING_API_KEY")
    if ($envValue) {
        return [pscustomobject]@{ Key = $envValue.Trim(); Source = "DASHSCOPE_CODING_API_KEY" }
    }
    return [pscustomobject]@{ Key = ""; Source = "" }
}

function Get-ControlTypesForCase {
    param([object]$Meta)
    $controls = @()
    foreach ($control in @($Meta.control_suite)) {
        if ($control.control_type) {
            $controls += [string]$control.control_type
        }
    }
    return $controls
}

function Test-CompletedControlRun {
    param(
        [string]$CaseDir,
        [string]$Harness,
        [string]$Label,
        [string]$ControlType
    )
    $resultsDir = Join-Path $CaseDir "results"
    if (-not (Test-Path $resultsDir)) { return $false }
    $matches = Get-ChildItem -Path $resultsDir -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            if (-not (Test-Path (Join-Path $_.FullName "oracle.json"))) { return $false }
            $caseJson = Join-Path $_.FullName "case.json"
            if (-not (Test-Path $caseJson)) { return $false }
            try {
                $meta = Read-JsonFile -Path $caseJson
                $labelMatches = $_.Name -like "*_${Harness}_*$Label*" -or [string]$meta.run_label -eq $Label
                if (-not ($labelMatches -and [string]$meta.harness -eq $Harness -and [string]$meta.control_type -eq $ControlType)) {
                    return $false
                }
                $validityPath = Join-Path $_.FullName "run_validity.json"
                if (-not (Test-Path -LiteralPath $validityPath)) { return $false }
                $validityPayload = Read-JsonFile -Path $validityPath
                return [bool](Get-SbRunValidityDisposition -Payload $validityPayload).Accounted
            } catch {
                return $false
            }
        }
    return [bool]@($matches).Count
}

$BenchRoot = Split-Path -Parent $PSScriptRoot
$RunsDir = Join-Path $BenchRoot "runs"
$ManifestPath = Join-Path $RunsDir "manifest.json"
$RunHarnessCase = Join-Path $PSScriptRoot "run_harness_case.ps1"
$ReportActiveRun = Join-Path $PSScriptRoot "report_active_run.py"
$labelRoot = if ($RunLabel) { $RunLabel } else { "paper_controls_$(Get-Date -Format 'yyyyMMdd_HHmmss')" }
$nonClaudeHarnesses = @($Harnesses | Where-Object { $_ -ne "claude" })
$dashscopeCredential = Get-DashScopeCodingKeyStrict -BenchRoot $BenchRoot
if ($nonClaudeHarnesses.Count -gt 0 -and $KimiModel -and -not $SkipKimiPreflight) {
    if (-not $dashscopeCredential.Key) {
        throw "Kimi control baseline requested for harness(es) $($nonClaudeHarnesses -join ',') with model '$KimiModel', but no DashScope coding key was found. Set providers.dashscope.coding_api_key in bench_state\secrets\api_keys.json, or use DASHSCOPE_CODING_API_KEY / bench_state\secrets\codex\api_key.txt. OPENAI_API_KEY is intentionally not accepted for this baseline."
    }
    Write-Host "[run_paper_control_matrix] Kimi/DashScope credential source: $($dashscopeCredential.Source)"
}

$manifest = Read-JsonFile -Path $ManifestPath
$selectedCaseDirFilters = Get-CaseDirFilters -InlineFilters $CaseDirFilter -ListPath $CaseListPath
$caseRows = @()
foreach ($suiteProp in @($manifest.suites.PSObject.Properties)) {
    $suiteName = $suiteProp.Name
    $suiteObj = $suiteProp.Value
    if ($suiteObj.status -ne "active") { continue }
    foreach ($entry in @($suiteObj.cases)) {
        if (-not (Test-CaseDirSelected -EntryCaseDir ([string]$entry.case_dir) -Filters $selectedCaseDirFilters)) { continue }
        $caseDir = Join-Path $RunsDir ([string]$entry.case_dir)
        $metaPath = Join-Path $caseDir "case_meta.json"
        if (-not (Test-Path $metaPath)) {
            Write-Warning "[run_paper_control_matrix] missing case_meta.json: $caseDir"
            continue
        }
        $meta = Read-JsonFile -Path $metaPath
        if (-not (Test-CaseSet -Meta $meta -SelectedCaseSet $CaseSet)) { continue }
        $availableControls = @(Get-ControlTypesForCase -Meta $meta)
        $selectedControls = @($ControlTypes | Where-Object { $availableControls -contains $_ })
        if ($selectedControls.Count -eq 0) {
            Write-Warning "[run_paper_control_matrix] no selected controls in case: $($entry.case_dir)"
            continue
        }
        $caseRows += [pscustomobject]@{
            suite = $suiteName
            case_dir = $caseDir
            case_dir_rel = [string]$entry.case_dir
            case_id = [string]$meta.case_id
            reporting_track = [string]$meta.reporting_track
            paper_priority = [string]$meta.paper_priority
            controls = $selectedControls
        }
    }
}

if ($CaseLimit -gt 0) {
    $caseRows = @($caseRows | Select-Object -First $CaseLimit)
}
if ($caseRows.Count -eq 0) {
    throw "no cases selected for CaseSet=$CaseSet and ControlTypes=$($ControlTypes -join ',')"
}

Write-Host "[run_paper_control_matrix] label=$labelRoot case_set=$CaseSet cases=$($caseRows.Count) controls=$($ControlTypes -join ',') trials=$Trials harnesses=$($Harnesses -join ',')"
if ($selectedCaseDirFilters.Count -gt 0) {
    Write-Host "[run_paper_control_matrix] case_dir_filter=$($selectedCaseDirFilters -join ',')"
}

$summary = @()
for ($trial = 1; $trial -le $Trials; $trial++) {
    foreach ($harness in $Harnesses) {
        foreach ($model in @(Get-HarnessModels -Harness $harness)) {
            $modelSlug = Get-SafeName $model
            foreach ($controlType in $ControlTypes) {
                $trialLabel = "{0}_trial{1:D2}_{2}_{3}_{4}" -f $labelRoot, $trial, $harness, $modelSlug, $controlType
                foreach ($case in $caseRows) {
                    if (@($case.controls) -notcontains $controlType) { continue }
                    if ($SkipCompleted -and (Test-CompletedControlRun -CaseDir $case.case_dir -Harness $harness -Label $trialLabel -ControlType $controlType)) {
                        Write-Host "[run_paper_control_matrix] skip completed harness=$harness control=$controlType label=$trialLabel case=$($case.case_dir_rel)"
                        continue
                    }

                    Write-Host ""
                    Write-Host ("=" * 80)
                    Write-Host "[run_paper_control_matrix] trial=$trial harness=$harness model=$model control=$controlType case=$($case.case_dir_rel)"
                    Write-Host ("=" * 80)

                    $runArgs = @{
                        Harness = $harness
                        CaseDir = $case.case_dir
                        PermissionProfile = $PermissionProfile
                        IsolationMode = "isolated_home"
                        RunLabel = $trialLabel
                        TimeoutSec = $TimeoutSec
                        ControlType = $controlType
                    }
                    if ($model) { $runArgs["Model"] = $model }
                    if ($harness -eq "claude") {
                        if ($ClaudeBaseUrl) { $runArgs["ClaudeBaseUrl"] = $ClaudeBaseUrl }
                        if ($ClaudeApiKeyEnv) { $runArgs["ClaudeApiKeyEnv"] = $ClaudeApiKeyEnv }
                        if ($ClaudeApiKeyPath) { $runArgs["ClaudeApiKeyPath"] = $ClaudeApiKeyPath }
                        if ($ClaudeAuthTokenEnv) { $runArgs["ClaudeAuthTokenEnv"] = $ClaudeAuthTokenEnv }
                    }

                    $ok = $true
                    $message = ""
                    $oldOpenAIKey = [Environment]::GetEnvironmentVariable("OPENAI_API_KEY")
                    try {
                        if ($harness -eq "hermes" -and $model -and $model -eq $KimiModel -and $dashscopeCredential.Key) {
                            $env:OPENAI_API_KEY = $dashscopeCredential.Key
                        }
                        & $RunHarnessCase @runArgs
                    } catch {
                        $ok = $false
                        $message = [string]$_.Exception.Message
                        Write-Warning "[run_paper_control_matrix] failed harness=$harness control=$controlType case=$($case.case_dir_rel): $message"
                        if ($message -match "FATAL_CREDENTIAL_MISSING") { throw }
                        if ($StopOnFailure) { throw }
                    } finally {
                        if ($harness -eq "hermes" -and $model -and $model -eq $KimiModel) {
                            if ($null -eq $oldOpenAIKey) {
                                Remove-Item Env:\OPENAI_API_KEY -ErrorAction SilentlyContinue
                            } else {
                                $env:OPENAI_API_KEY = $oldOpenAIKey
                            }
                        }
                    }
                    $latestRunDir = Get-LatestControlRunDir -CaseDir $case.case_dir -Harness $harness -Label $trialLabel -ControlType $controlType
                    $runValidity = Get-ControlRunValidity -RunDir $(if ($latestRunDir) { $latestRunDir.FullName } else { "" })
                    $controlStatus = "not_evaluated"
                    $controlPass = $false
                    if ($latestRunDir) {
                        $controlContractPath = Join-Path $latestRunDir.FullName "control_contract.json"
                        if (Test-Path -LiteralPath $controlContractPath) {
                            try {
                                $controlContract = Read-JsonFile -Path $controlContractPath
                                $controlStatus = [string]$controlContract.status
                                $controlPass = [bool](
                                    $runValidity.Scored -and
                                    -not [bool]$controlContract.control_failure -and
                                    $controlStatus -eq "pass"
                                )
                            } catch {
                                $controlStatus = "invalid_control_contract"
                            }
                        }
                    }
                    if ($ok -and -not $runValidity.Accounted) {
                        $ok = $false
                        $reasonText = @($runValidity.FailureReasons) -join ","
                        $message = "run execution invalid: status=$($runValidity.Status) reasons=$reasonText"
                    } elseif ($ok -and $runValidity.ResultClass -eq "model_protocol_deviation") {
                        $message = "terminal N-1 model protocol deviation (accounted, non-scorable, non-pass, non-retryable)"
                        $controlStatus = "model_protocol_incomplete"
                        $controlPass = $false
                    }
                    $summary += [pscustomobject]@{
                        trial = $trial
                        harness = $harness
                        model = $model
                        control_type = $controlType
                        label = $trialLabel
                        suite = $case.suite
                        case_dir = $case.case_dir_rel
                        ok = $ok
                        valid = [bool]$runValidity.Valid
                        accounted = [bool]$runValidity.Accounted
                        scored = [bool]$runValidity.Scored
                        scorable = [bool]$runValidity.Scored
                        result_class = [string]$runValidity.ResultClass
                        display_node = [string]$runValidity.DisplayNode
                        terminal_outcome = [bool]$runValidity.TerminalOutcome
                        retry_eligible = [bool]$runValidity.RetryEligible
                        execution_status = [string]$runValidity.Status
                        failure_reasons = @($runValidity.FailureReasons)
                        control_status = $controlStatus
                        control_pass = [bool]$controlPass
                        results_dir = if ($latestRunDir) { $latestRunDir.FullName } else { "" }
                        validity_path = [string]$runValidity.Path
                        message = $message
                    }
                }
            }
        }
    }
}

$summaryDir = Join-Path $RunsDir "_artifacts\batch_summaries"
New-Item -ItemType Directory -Force -Path $summaryDir | Out-Null
$summaryPath = Join-Path $summaryDir "$(Get-SafeName $labelRoot)_paper_control_summary.json"
[System.IO.File]::WriteAllText(
    $summaryPath,
    ($summary | ConvertTo-Json -Depth 8),
    [System.Text.UTF8Encoding]::new($false)
)
Write-Host "[run_paper_control_matrix] summary -> $summaryPath"

if (-not $NoReport) {
    $reportArgs = @($ReportActiveRun, "--label", $labelRoot, "--case-set", $CaseSet, "--all-matching-runs", "--run-kind", "control")
    foreach ($controlType in $ControlTypes) {
        $reportArgs += @("--control-type", $controlType)
    }
    foreach ($harness in $Harnesses) {
        $reportArgs += @("--harness", $harness)
    }
    Write-Host "[run_paper_control_matrix] generating report for label prefix=$labelRoot"
    & python @reportArgs
}
