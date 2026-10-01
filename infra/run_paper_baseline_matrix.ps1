<#
.SYNOPSIS
  Run the paper-oriented Safety Bench baseline matrix.

.DESCRIPTION
  This runner covers all 328 active cases, explicit trials, fixed model names,
  and a final multi-run report. All 328 active hard-oracle cases define the
  planned/design-time case scope; runtime S and D denominators are result-derived.
  CaseSet=core is a compatibility alias for CaseSet=all;
  both select all active manifest cases.
#>
param(
    [ValidateSet("core", "extended", "exploratory", "all")]
    [string]$CaseSet = "all",

    [ValidateSet("claude", "codex", "hermes")]
    [string[]]$Harnesses = @("claude"),

    [string]$RunLabel = "",
    [int]$Trials = 1,
    [int]$TimeoutSec = 300,
    [int]$HoneypotPort = 18765,
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
    [int]$CaseLimit = 0,
    [ValidateSet("", "minimal", "detailed")]
    [string]$OutputMode = ""
)

$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$TerminalRunUi = Join-Path $PSScriptRoot "terminal_run_ui.ps1"
if (Test-Path -LiteralPath $TerminalRunUi) { . $TerminalRunUi }
if (Get-Command Initialize-SbUiMode -ErrorAction SilentlyContinue) {
    Initialize-SbUiMode -Mode $OutputMode
}
$SecretsHelper = Join-Path $PSScriptRoot "secrets.ps1"
if (Test-Path -LiteralPath $SecretsHelper) { . $SecretsHelper }
$ResultClassification = Join-Path $PSScriptRoot "result_classification.ps1"
if (Test-Path -LiteralPath $ResultClassification) { . $ResultClassification }

function Test-RunnerMinimalOutput {
    if (Get-Command Test-SbUiMinimalMode -ErrorAction SilentlyContinue) {
        return [bool](Test-SbUiMinimalMode)
    }
    return $false
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

function Get-MatrixLongPath {
    param([string]$Path)
    $resolved = [System.IO.Path]::GetFullPath($Path)
    if ($env:OS -ne "Windows_NT" -or $resolved.StartsWith("\\?\")) { return $resolved }
    if ($resolved.StartsWith("\\")) { return "\\?\UNC\" + $resolved.TrimStart("\") }
    return "\\?\" + $resolved
}

function Read-JsonFile {
    param([string]$Path)
    return [System.IO.File]::ReadAllText((Get-MatrixLongPath $Path), [System.Text.Encoding]::UTF8) | ConvertFrom-Json
}

function Get-RunValidity {
    param([string]$RunDir)
    if (-not $RunDir) {
        return [pscustomobject]@{ Valid = $false; Accounted = $false; ResultClass = "execution_invalid"; DisplayNode = ""; TerminalOutcome = $false; RetryEligible = $true; Status = "missing_run_directory"; FailureReasons = @("missing_run_directory"); Path = "" }
    }
    $path = Join-Path $RunDir "run_validity.json"
    if (-not [System.IO.File]::Exists((Get-MatrixLongPath $path))) {
        return [pscustomobject]@{ Valid = $false; Accounted = $false; ResultClass = "execution_invalid"; DisplayNode = ""; TerminalOutcome = $false; RetryEligible = $true; Status = "missing_run_validity"; FailureReasons = @("missing_run_validity"); Path = $path }
    }
    try {
        $payload = Read-JsonFile -Path $path
    } catch {
        return [pscustomobject]@{ Valid = $false; Accounted = $false; ResultClass = "execution_invalid"; DisplayNode = ""; TerminalOutcome = $false; RetryEligible = $true; Status = "invalid_run_validity"; FailureReasons = @("invalid_run_validity"); Path = $path }
    }
    $status = if ($payload.status) { [string]$payload.status } else { "" }
    $disposition = Get-SbRunValidityDisposition -Payload $payload
    $declaredValid = [bool]$disposition.Scored
    $failureReasons = if ($payload.PSObject.Properties.Name -contains "failure_reasons") { @($payload.failure_reasons | ForEach-Object { [string]$_ }) } else { @() }
    $stageRecords = if ($payload.PSObject.Properties.Name -contains "stages") { @($payload.stages) } else { @() }
    if (-not $disposition.ModelProtocolTerminal) {
        if (@($stageRecords | Where-Object { $_.valid -ne $true }).Count -gt 0) {
            $failureReasons += "invalid_stage_record"
        }
        if (($payload.PSObject.Properties.Name -contains "expected_stage_count") -and
            ($payload.PSObject.Properties.Name -contains "completed_stage_count") -and
            [int]$payload.expected_stage_count -ne [int]$payload.completed_stage_count) {
            $failureReasons += "incomplete_stage_set"
        }
        if (($payload.PSObject.Properties.Name -contains "fixture_health") -and
            $payload.fixture_health -and $payload.fixture_health.valid -ne $true) {
            $failureReasons += "fixture_health_failure"
        }
        if ($status -ne "completed") { $failureReasons += "non_completed_status" }
    }
    $failureReasons = @($failureReasons | Where-Object { $_ } | Select-Object -Unique)
    $explicitValid = [bool]($disposition.Scored -and $failureReasons.Count -eq 0)
    if (-not $explicitValid -and $failureReasons.Count -eq 0) { $failureReasons = @("run_marked_invalid") }
    return [pscustomobject]@{
        Valid = $explicitValid
        Accounted = [bool]($explicitValid -or $disposition.ModelProtocolTerminal)
        ResultClass = [string]$disposition.ResultClass
        DisplayNode = [string]$disposition.DisplayNode
        TerminalOutcome = [bool]($explicitValid -or $disposition.ModelProtocolTerminal)
        RetryEligible = [bool](-not ($explicitValid -or $disposition.ModelProtocolTerminal))
        Status = if ($status) { $status } else { if ($explicitValid) { "completed" } else { "invalid" } }
        FailureReasons = @($failureReasons)
        Path = $path
    }
}

function Test-CaseSet {
    param([object]$Meta, [string]$SelectedCaseSet)
    if ($SelectedCaseSet -in @("all", "core")) { return $true }
    if ($SelectedCaseSet -eq "extended") { return [string]$Meta.reporting_track -eq "extended_benchmark" }
    if ($SelectedCaseSet -eq "exploratory") { return [string]$Meta.reporting_track -eq "exploratory_case_study" }
    return $false
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

function Test-CompletedRun {
    param([string]$CaseDir, [string]$Harness, [string]$Label)
    $resultsDir = Join-Path $CaseDir "results"
    if (-not (Test-Path $resultsDir)) { return $false }
    $matches = Get-ChildItem -Path $resultsDir -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            if (-not [System.IO.File]::Exists((Get-MatrixLongPath (Join-Path $_.FullName "oracle.json")))) { return $false }
            $runMatches = $false
            if ($_.Name -like "*_${Harness}_*$Label*") { $runMatches = $true }
            $caseJson = Join-Path $_.FullName "case.json"
            if (-not $runMatches -and [System.IO.File]::Exists((Get-MatrixLongPath $caseJson))) {
                try {
                    $meta = Read-JsonFile -Path $caseJson
                    $runMatches = [string]$meta.harness -eq $Harness -and [string]$meta.run_label -eq $Label
                } catch {}
            }
            if (-not $runMatches) { return $false }
            $validity = Get-RunValidity -RunDir $_.FullName
            return [bool]$validity.Accounted
        }
    return [bool]@($matches).Count
}

function Get-LatestRunDir {
    param([string]$CaseDir, [string]$Harness, [string]$Label)
    $resultsDir = Join-Path $CaseDir "results"
    if (-not (Test-Path $resultsDir)) { return $null }
    foreach ($candidate in @(Get-ChildItem -Path $resultsDir -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)) {
        if ($candidate.Name -like "*_${Harness}_*$Label*") { return $candidate }
        $caseJson = Join-Path $candidate.FullName "case.json"
        if (-not [System.IO.File]::Exists((Get-MatrixLongPath $caseJson))) { continue }
        try {
            $meta = Read-JsonFile -Path $caseJson
            if ([string]$meta.harness -eq $Harness -and [string]$meta.run_label -eq $Label) {
                return $candidate
            }
        } catch {}
    }
    return $null
}

$BenchRoot = Split-Path -Parent $PSScriptRoot
$RunsDir = Join-Path $BenchRoot "runs"
$ManifestPath = Join-Path $RunsDir "manifest.json"
$RunHarnessCase = Join-Path $PSScriptRoot "run_harness_case.ps1"
$ReportActiveRun = Join-Path $PSScriptRoot "report_active_run.py"
$labelRoot = if ($RunLabel) { $RunLabel } else { "paper_$(Get-Date -Format 'yyyyMMdd_HHmmss')" }
$nonClaudeHarnesses = @($Harnesses | Where-Object { $_ -ne "claude" })
$dashscopeCredential = Get-DashScopeCodingKeyStrict -BenchRoot $BenchRoot
if ($nonClaudeHarnesses.Count -gt 0 -and $KimiModel -and -not $SkipKimiPreflight) {
    if (-not $dashscopeCredential.Key) {
        throw "Kimi baseline requested for harness(es) $($nonClaudeHarnesses -join ',') with model '$KimiModel', but no DashScope coding key was found. Set providers.dashscope.coding_api_key in bench_state\secrets\api_keys.json, or use DASHSCOPE_CODING_API_KEY / bench_state\secrets\codex\api_key.txt. OPENAI_API_KEY is intentionally not accepted for this baseline."
    }
    if (-not (Test-RunnerMinimalOutput)) {
        Write-Host "[run_paper_baseline_matrix] Kimi/DashScope credential source: $($dashscopeCredential.Source)"
    }
}

$manifest = Read-JsonFile -Path $ManifestPath
$caseRows = @()
foreach ($suiteProp in @($manifest.suites.PSObject.Properties)) {
    $suiteName = $suiteProp.Name
    $suiteObj = $suiteProp.Value
    if ($suiteObj.status -ne "active") { continue }
    foreach ($entry in @($suiteObj.cases)) {
        $caseDir = Join-Path $RunsDir ([string]$entry.case_dir)
        $metaPath = Join-Path $caseDir "case_meta.json"
        if (-not (Test-Path $metaPath)) {
            Write-Warning "[run_paper_baseline_matrix] missing case_meta.json: $caseDir"
            continue
        }
        $meta = Read-JsonFile -Path $metaPath
        if (-not (Test-CaseSet -Meta $meta -SelectedCaseSet $CaseSet)) { continue }
        $caseRows += [pscustomobject]@{
            suite = $suiteName
            case_dir = $caseDir
            case_dir_rel = [string]$entry.case_dir
            case_id = [string]$meta.case_id
            reporting_track = [string]$meta.reporting_track
            paper_priority = [string]$meta.paper_priority
        }
    }
}

if ($CaseLimit -gt 0) {
    $caseRows = @($caseRows | Select-Object -First $CaseLimit)
}
if ($caseRows.Count -eq 0) {
    throw "no cases selected for CaseSet=$CaseSet"
}

$plannedRuns = 0
foreach ($harness in $Harnesses) {
    $plannedRuns += $Trials * $caseRows.Count * @((Get-HarnessModels -Harness $harness)).Count
}
$matrixStartedAt = Get-Date
$matrixOrdinal = 0
$matrixCompleted = 0
$matrixSkipped = 0
$matrixFailed = 0

if (-not (Test-RunnerMinimalOutput)) {
    Write-Host "[run_paper_baseline_matrix] label=$labelRoot case_set=$CaseSet cases=$($caseRows.Count) trials=$Trials harnesses=$($Harnesses -join ',')"
}
if (Get-Command Write-SbUiMatrixStart -ErrorAction SilentlyContinue) {
    Write-SbUiMatrixStart -Label $labelRoot -CaseSet $CaseSet -Cases $caseRows.Count -Trials $Trials -Harnesses $Harnesses -TotalRuns $plannedRuns
}

$summary = @()
for ($trial = 1; $trial -le $Trials; $trial++) {
    foreach ($harness in $Harnesses) {
        foreach ($model in @(Get-HarnessModels -Harness $harness)) {
            $modelSlug = Get-SafeName $model
            $trialLabel = "{0}_trial{1:D2}_{2}_{3}" -f $labelRoot, $trial, $harness, $modelSlug
            foreach ($case in $caseRows) {
                $matrixOrdinal += 1
                if ($SkipCompleted -and (Test-CompletedRun -CaseDir $case.case_dir -Harness $harness -Label $trialLabel)) {
                    $matrixSkipped += 1
                    if (Get-Command Write-SbUiMatrixCaseSkip -ErrorAction SilentlyContinue) {
                        Write-SbUiMatrixCaseSkip -Current $matrixOrdinal -Total $plannedRuns -Harness $harness -CaseDirRel $case.case_dir_rel -Label $trialLabel
                    }
                    if (-not (Test-RunnerMinimalOutput)) {
                        Write-Host "[run_paper_baseline_matrix] skip completed harness=$harness label=$trialLabel case=$($case.case_dir_rel)"
                    }
                    continue
                }

                $caseStartedAt = Get-Date
                if (Get-Command Write-SbUiMatrixCaseStart -ErrorAction SilentlyContinue) {
                    Write-SbUiMatrixCaseStart `
                        -Current $matrixOrdinal `
                        -Total $plannedRuns `
                        -Trial $trial `
                        -Trials $Trials `
                        -Harness $harness `
                        -Model $model `
                        -Suite $case.suite `
                        -CaseDirRel $case.case_dir_rel `
                        -Label $trialLabel
                }
                if (-not (Test-RunnerMinimalOutput)) {
                    Write-Host ""
                    Write-Host "[run_paper_baseline_matrix] trial=$trial harness=$harness model=$model case=$($case.case_dir_rel)"
                }

                $runArgs = @{
                    Harness = $harness
                    CaseDir = $case.case_dir
                    PermissionProfile = $PermissionProfile
                    IsolationMode = "isolated_home"
                    RunLabel = $trialLabel
                    TimeoutSec = $TimeoutSec
                    HoneypotPort = $HoneypotPort
                    OutputMode = $(if ($OutputMode) { $OutputMode } else { Get-SbUiMode })
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
                    Write-Warning "[run_paper_baseline_matrix] failed harness=$harness case=$($case.case_dir_rel): $message"
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
                $latestRunDir = Get-LatestRunDir -CaseDir $case.case_dir -Harness $harness -Label $trialLabel
                $runValidity = Get-RunValidity -RunDir $(if ($latestRunDir) { $latestRunDir.FullName } else { "" })
                if ($ok -and -not $runValidity.Accounted) {
                    $ok = $false
                    $reasonText = @($runValidity.FailureReasons) -join ","
                    $message = "run execution invalid: status=$($runValidity.Status) reasons=$reasonText"
                    Write-Warning "[run_paper_baseline_matrix] invalid harness=$harness case=$($case.case_dir_rel): $message"
                } elseif ($ok -and $runValidity.ResultClass -eq "model_protocol_deviation") {
                    $message = "terminal N-1 model protocol deviation (accounted, non-scorable, non-retryable)"
                }
                if ($ok) {
                    $matrixCompleted += 1
                } else {
                    $matrixFailed += 1
                }
                if (Get-Command Write-SbUiMatrixCaseEnd -ErrorAction SilentlyContinue) {
                    Write-SbUiMatrixCaseEnd `
                        -Current $matrixOrdinal `
                        -Total $plannedRuns `
                        -Ok $ok `
                        -CaseDirRel $case.case_dir_rel `
                        -Message $message `
                        -ResultsDir $(if ($latestRunDir) { $latestRunDir.FullName } else { "" }) `
                        -StartedAt $caseStartedAt
                }
                $summary += [pscustomobject]@{
                    trial = $trial
                    harness = $harness
                    model = $model
                    label = $trialLabel
                    suite = $case.suite
                    case_dir = $case.case_dir_rel
                    ok = $ok
                    valid = [bool]$runValidity.Valid
                    accounted = [bool]$runValidity.Accounted
                    result_class = [string]$runValidity.ResultClass
                    display_node = [string]$runValidity.DisplayNode
                    terminal_outcome = [bool]$runValidity.TerminalOutcome
                    retry_eligible = [bool]$runValidity.RetryEligible
                    execution_status = [string]$runValidity.Status
                    failure_reasons = @($runValidity.FailureReasons)
                    results_dir = if ($latestRunDir) { $latestRunDir.FullName } else { "" }
                    validity_path = [string]$runValidity.Path
                    message = $message
                }
                if (-not $ok -and $StopOnFailure) {
                    throw "matrix stopped after invalid run: harness=$harness case=$($case.case_dir_rel) status=$($runValidity.Status)"
                }
            }
        }
    }
}

$summaryDir = Join-Path $RunsDir "_artifacts\batch_summaries"
New-Item -ItemType Directory -Force -Path $summaryDir | Out-Null
$summaryPath = Join-Path $summaryDir "$(Get-SafeName $labelRoot)_paper_matrix_summary.json"
[System.IO.File]::WriteAllText(
    $summaryPath,
    ($summary | ConvertTo-Json -Depth 8),
    [System.Text.UTF8Encoding]::new($false)
)
if (-not (Test-RunnerMinimalOutput)) {
    Write-Host "[run_paper_baseline_matrix] summary -> $summaryPath"
}
if (Get-Command Write-SbUiMatrixSummary -ErrorAction SilentlyContinue) {
    Write-SbUiMatrixSummary `
        -Label $labelRoot `
        -Total $plannedRuns `
        -Completed $matrixCompleted `
        -Skipped $matrixSkipped `
        -Failed $matrixFailed `
        -SummaryPath $summaryPath `
        -StartedAt $matrixStartedAt
}

if (-not $NoReport) {
    $reportArgs = @($ReportActiveRun, "--label", $labelRoot, "--case-set", $CaseSet, "--all-matching-runs", "--run-kind", "attack")
    foreach ($harness in $Harnesses) {
        $reportArgs += @("--harness", $harness)
    }
    if (-not (Test-RunnerMinimalOutput)) {
        Write-Host "[run_paper_baseline_matrix] generating report for label prefix=$labelRoot"
    }
    & python @reportArgs
}
