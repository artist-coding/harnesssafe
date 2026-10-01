function Initialize-SbUiMode {
    param([string]$Mode = "")
    $candidate = (ConvertTo-SbUiText $Mode).ToLowerInvariant()
    if (-not $candidate) {
        $candidate = (ConvertTo-SbUiText $env:SAFETY_BENCH_OUTPUT_MODE).ToLowerInvariant()
    }
    if (-not $candidate) {
        $candidate = (ConvertTo-SbUiText $env:SAFETY_BENCH_UI_MODE).ToLowerInvariant()
    }
    if ($candidate -notin @("minimal", "detailed")) {
        $candidate = "detailed"
    }
    $script:SbUiMode = $candidate
    $env:SAFETY_BENCH_OUTPUT_MODE = $candidate
    $env:SAFETY_BENCH_UI_MODE = $candidate
}

function Get-SbUiMode {
    if (-not $script:SbUiMode) {
        Initialize-SbUiMode
    }
    return $script:SbUiMode
}

function Test-SbUiMinimalMode {
    return (Get-SbUiMode) -eq "minimal"
}

function Test-SbUiDetailedMode {
    return (Get-SbUiMode) -eq "detailed"
}

function ConvertTo-SbUiText {
    param($Value)
    if ($null -eq $Value) { return "" }
    if ($Value -is [System.Array]) {
        return (@($Value) | ForEach-Object { ConvertTo-SbUiText $_ }) -join ", "
    }
    $text = [string]$Value
    return (($text -replace "\r?\n", " ").Trim())
}

function Get-SbUiLongPath {
    param([string]$Path)
    if (-not $Path) { return "" }
    $resolved = [System.IO.Path]::GetFullPath($Path)
    if ($env:OS -ne "Windows_NT" -or $resolved.StartsWith("\\?\")) { return $resolved }
    if ($resolved.StartsWith("\\")) { return "\\?\UNC\" + $resolved.TrimStart("\") }
    return "\\?\" + $resolved
}

function Test-SbUiFile {
    param([string]$Path)
    if (-not $Path) { return $false }
    return [System.IO.File]::Exists((Get-SbUiLongPath $Path))
}

function Read-SbUiUtf8File {
    param([string]$Path)
    return [System.IO.File]::ReadAllText((Get-SbUiLongPath $Path), [System.Text.Encoding]::UTF8)
}

function Split-SbUiText {
    param(
        [string]$Text,
        [int]$Width
    )
    $value = ConvertTo-SbUiText $Text
    if ($Width -le 0) { return @($value) }
    if ($value.Length -le $Width) { return @($value) }

    $lines = @()
    $remaining = $value
    while ($remaining.Length -gt $Width) {
        $head = $remaining.Substring(0, $Width)
        $cut = $head.LastIndexOf(" ")
        if ($cut -lt [Math]::Min(24, $Width - 1)) {
            $cut = $Width
        }
        $lines += $remaining.Substring(0, $cut).TrimEnd()
        $remaining = $remaining.Substring($cut).TrimStart()
    }
    if ($remaining) { $lines += $remaining }
    return $lines
}

function Format-SbUiPair {
    param(
        [string]$Name,
        $Value
    )
    return ("{0,-16} {1}" -f "${Name}:", (ConvertTo-SbUiText $Value))
}

function Get-SbUiDisplayPath {
    param(
        [string]$Path,
        [int]$MaxLength = 92
    )
    $text = ConvertTo-SbUiText $Path
    if (-not $text -or $text.Length -le $MaxLength) { return $text }
    $separator = if ($text.Contains("\")) { "\" } else { "/" }
    $parts = $text -split [regex]::Escape($separator)
    if ($parts.Count -gt 6) {
        $head = $parts[0]
        if ($head -match "^[A-Za-z]:$") {
            $head = "$head$separator"
        }
        foreach ($tailCount in @(6, 5, 4, 3, 2)) {
            $tail = (@($parts) | Select-Object -Last $tailCount) -join $separator
            $candidate = "$head...$separator$tail"
            if ($candidate.Length -le $MaxLength) { return $candidate }
        }
    }
    if ($MaxLength -le 3) { return $text.Substring(0, $MaxLength) }
    return "..." + $text.Substring($text.Length - ($MaxLength - 3))
}

function Get-SbUiElapsedText {
    param([datetime]$StartedAt)
    if ($null -eq $StartedAt -or $StartedAt -eq [datetime]::MinValue) { return "" }
    $elapsed = (Get-Date) - $StartedAt
    if ($elapsed.TotalHours -ge 1) { return $elapsed.ToString("hh\:mm\:ss") }
    return $elapsed.ToString("mm\:ss")
}

function Get-SbUiPercent {
    param(
        [int]$Current,
        [int]$Total
    )
    if ($Total -le 0) { return 0 }
    return [Math]::Min(100, [Math]::Max(0, [int][Math]::Floor(($Current * 100.0) / $Total)))
}

function New-SbUiProgressBar {
    param(
        [int]$Current,
        [int]$Total,
        [int]$Width = 28
    )
    $percent = Get-SbUiPercent -Current $Current -Total $Total
    $filled = if ($Total -le 0) { 0 } else { [int][Math]::Round(($percent / 100.0) * $Width) }
    $filled = [Math]::Min($Width, [Math]::Max(0, $filled))
    $empty = $Width - $filled
    return "[{0}{1}] {2,3}%" -f ("#" * $filled), ("-" * $empty), $percent
}

function Update-SbUiNativeProgress {
    param(
        [string]$Activity,
        [string]$Status = "",
        [int]$PercentComplete = 0,
        [switch]$Completed
    )
    if ($env:SAFETY_BENCH_NATIVE_PROGRESS -ne "1") { return }
    if ($Completed) {
        Write-Progress -Activity $Activity -Completed
        return
    }
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
}

function Write-SbUiBox {
    param(
        [string]$Title,
        [string[]]$Rows,
        [string]$Color = "Cyan",
        [int]$Width = 100
    )
    $innerWidth = [Math]::Max(20, $Width - 4)
    $top = "+" + ("-" * ($Width - 2)) + "+"
    Write-Host $top -ForegroundColor $Color
    foreach ($rawLine in @($Title)) {
        foreach ($line in Split-SbUiText -Text $rawLine -Width $innerWidth) {
            Write-Host ("| {0,-$innerWidth} |" -f $line) -ForegroundColor $Color
        }
    }
    Write-Host ("|" + ("-" * ($Width - 2)) + "|") -ForegroundColor $Color
    foreach ($rawLine in @($Rows)) {
        foreach ($line in Split-SbUiText -Text $rawLine -Width $innerWidth) {
            Write-Host ("| {0,-$innerWidth} |" -f $line) -ForegroundColor $Color
        }
    }
    Write-Host $top -ForegroundColor $Color
}

function Write-SbUiStep {
    param(
        [string]$Step,
        [string]$Status,
        [string]$Detail = "",
        [string]$Color = "DarkCyan"
    )
    $stamp = Get-Date -Format "HH:mm:ss"
    $line = "[case-ui] {0}  {1,-14} {2,-9} {3}" -f $stamp, $Step, $Status, $Detail
    Write-Host $line -ForegroundColor $Color
}

function Get-SbUiTerminalModelProtocolResult {
    param([string]$ResultsDir)
    $validityPath = Join-Path $ResultsDir "run_validity.json"
    if (-not (Test-SbUiFile -Path $validityPath)) { return $null }
    if (-not (Get-Command Test-SbTerminalModelProtocolPayload -ErrorAction SilentlyContinue)) {
        return $null
    }
    try {
        $payload = Read-SbUiUtf8File -Path $validityPath | ConvertFrom-Json
        if (Test-SbTerminalModelProtocolPayload -Payload $payload) { return $payload }
    } catch {}
    return $null
}

function Get-SbUiOracleResultSummary {
    param([string]$ResultsDir)
    $oraclePath = Join-Path $ResultsDir "oracle.json"
    if (-not (Test-SbUiFile -Path $oraclePath)) { return $null }
    try {
        $verdict = Read-SbUiUtf8File -Path $oraclePath | ConvertFrom-Json
    } catch {
        return $null
    }
    $evaluation = $verdict.evaluation
    if (-not $evaluation) { return $null }
    $modelProtocolResult = Get-SbUiTerminalModelProtocolResult -ResultsDir $ResultsDir
    return [pscustomobject]@{
        ProgressNode = ConvertTo-SbUiText $evaluation.progress_node
        Verdict = ConvertTo-SbUiText $evaluation.verdict
        RiskScore = ConvertTo-SbUiText $evaluation.risk_score
        AttackSuccess = ConvertTo-SbUiText $evaluation.attack_success
        Confirmed = ConvertTo-SbUiText $evaluation.confirmed_compromise
        ModelProtocolTerminal = [bool]$modelProtocolResult
        ResultClass = if ($modelProtocolResult) { "model_protocol_deviation" } else { "scored" }
        DisplayNode = if ($modelProtocolResult) { "N-1" } else { ConvertTo-SbUiText $evaluation.progress_node }
    }
}

function Get-SbUiOracleColor {
    param($Evaluation)
    $node = ConvertTo-SbUiText $Evaluation.progress_node
    $attackSuccess = [bool]$Evaluation.attack_success
    $confirmed = [bool]$Evaluation.confirmed_compromise
    if ($confirmed -or $attackSuccess -or $node -in @("N4", "N5", "N5a", "N5b")) { return "Red" }
    if ($node -in @("N2", "N3")) { return "Yellow" }
    if ($node -eq "N1") { return "DarkYellow" }
    if ($node -eq "N0") { return "Green" }
    return "Cyan"
}

function Get-SbUiEvidenceCount {
    param(
        $Evidence,
        [string]$Name
    )
    if (-not $Evidence) { return 0 }
    if ($Evidence.PSObject.Properties.Name -notcontains $Name) { return 0 }
    $value = $Evidence.$Name
    if ($null -eq $value) { return 0 }
    if ($value -is [System.Array]) { return @($value).Count }
    if ($value -is [bool]) {
        if ($value) { return 1 }
        return 0
    }
    if ($value -is [string]) {
        if ($value) { return 1 }
        return 0
    }
    if ($value.PSObject.Properties) { return @($value.PSObject.Properties).Count }
    return 1
}

function Write-SbUiCaseStart {
    param(
        [string]$Harness,
        [string]$CaseDir,
        [string]$CaseId,
        [string]$RunId,
        [string]$RunLabel,
        [string]$PermissionMode,
        [string]$Model,
        [string]$Entry,
        [string]$Carrier,
        [string]$Boundary,
        [string]$Trigger,
        [string]$Violation,
        [string]$ResultsDir
    )
    $caseText = if ($CaseId) { $CaseId } else { Split-Path -Leaf $CaseDir }
    if (Test-SbUiMinimalMode) {
        $detail = "case={0} harness={1} model={2} run={3} results={4}" -f $caseText, $Harness, $(if ($Model) { $Model } else { "default" }), $RunId, (Get-SbUiDisplayPath -Path $ResultsDir -MaxLength 60)
        Write-SbUiStep -Step "case" -Status "START" -Detail $detail -Color "Cyan"
        return
    }
    $rows = @(
        (Format-SbUiPair "case" $caseText),
        (Format-SbUiPair "harness" $Harness),
        (Format-SbUiPair "model" $(if ($Model) { $Model } else { "default" })),
        (Format-SbUiPair "mode" $PermissionMode),
        (Format-SbUiPair "run" $RunId),
        (Format-SbUiPair "label" $RunLabel),
        (Format-SbUiPair "frame" "$Entry -> $Carrier -> $Boundary -> $Trigger -> $Violation"),
        (Format-SbUiPair "results" (Get-SbUiDisplayPath -Path $ResultsDir -MaxLength 76))
    )
    Write-SbUiBox -Title "Safety Bench case run" -Rows $rows -Color "Cyan"
}

function Write-SbUiStageStart {
    param(
        [string]$Harness,
        [string]$StageName,
        [int]$StageIndex,
        [int]$StageTotal,
        [int]$TimeoutSec
    )
    $detail = "{0} stage={1} ({2}/{3}) timeout={4}s" -f $Harness, $StageName, $StageIndex, $StageTotal, $TimeoutSec
    Write-SbUiStep -Step "stage" -Status "RUNNING" -Detail $detail -Color "Cyan"
}

function Write-SbUiStageEnd {
    param(
        [string]$Harness,
        [string]$StageName,
        $ExitCode,
        [bool]$TimedOut,
        [bool]$Valid = $true,
        [string[]]$FailureReasons = @(),
        [datetime]$StartedAt
    )
    $status = if ($TimedOut) { "TIMEOUT" } elseif (-not $Valid) { "INVALID" } elseif ($ExitCode -eq 0) { "OK" } else { "EXIT" }
    $color = if ($TimedOut -or -not $Valid -or $ExitCode -ne 0) { "Yellow" } else { "Green" }
    $elapsed = Get-SbUiElapsedText -StartedAt $StartedAt
    $reasonText = if (@($FailureReasons).Count -gt 0) { @($FailureReasons) -join "," } else { "none" }
    $detail = "{0} stage={1} exit={2} timed_out={3} valid={4} reasons={5} elapsed={6}" -f $Harness, $StageName, $ExitCode, $TimedOut, $Valid, $reasonText, $elapsed
    Write-SbUiStep -Step "stage" -Status $status -Detail $detail -Color $color
}

function Write-SbUiOracleSummary {
    param(
        [string]$ResultsDir,
        [string]$CaseDirRel = "",
        [datetime]$StartedAt = [datetime]::MinValue
    )
    $oraclePath = Join-Path $ResultsDir "oracle.json"
    $oracleMdPath = Join-Path $ResultsDir "oracle.md"
    $tracePath = Join-Path $ResultsDir "trace.jsonl"
    if (-not (Test-SbUiFile -Path $oraclePath)) {
        Write-SbUiBox -Title "Case effect unavailable" -Rows @(
            (Format-SbUiPair "reason" "oracle.json not found"),
            (Format-SbUiPair "results" (Get-SbUiDisplayPath -Path $ResultsDir -MaxLength 76)),
            (Format-SbUiPair "trace" (Get-SbUiDisplayPath -Path $tracePath -MaxLength 76))
        ) -Color "Yellow"
        return
    }

    try {
        $verdict = Read-SbUiUtf8File -Path $oraclePath | ConvertFrom-Json
    } catch {
        Write-SbUiBox -Title "Case effect unavailable" -Rows @(
            (Format-SbUiPair "reason" "oracle.json failed to parse: $($_.Exception.Message)"),
            (Format-SbUiPair "results" (Get-SbUiDisplayPath -Path $ResultsDir -MaxLength 76))
        ) -Color "Yellow"
        return
    }

    $evaluation = $verdict.evaluation
    $oracles = $verdict.oracles
    $evidence = $verdict.evidence
    $hitOracles = @()
    if ($oracles) {
        foreach ($prop in @($oracles.PSObject.Properties)) {
            if ($prop.Value -eq $true) { $hitOracles += $prop.Name }
        }
    }
    $evidenceOracles = @()
    if ($evaluation -and $evaluation.PSObject.Properties.Name -contains "evidence_oracles") {
        $evidenceOracles = @($evaluation.evidence_oracles | ForEach-Object { [string]$_ })
    }
    $hitText = if ($hitOracles.Count -gt 0) { ($hitOracles | Select-Object -First 12) -join ", " } else { "(none)" }
    if ($hitOracles.Count -gt 12) { $hitText = "$hitText, +$($hitOracles.Count - 12) more" }
    $evidenceText = if ($evidenceOracles.Count -gt 0) { $evidenceOracles -join ", " } else { "(none)" }
    $elapsed = Get-SbUiElapsedText -StartedAt $StartedAt
    $node = ConvertTo-SbUiText $evaluation.progress_node
    $verdictText = ConvertTo-SbUiText $evaluation.verdict
    $modelProtocolResult = Get-SbUiTerminalModelProtocolResult -ResultsDir $ResultsDir
    $effectColor = Get-SbUiOracleColor -Evaluation $evaluation
    $title = "Case effect: $node $verdictText"
    if ($modelProtocolResult) {
        $title = "Case result: N-1 MODEL_PROTOCOL_INCOMPLETE | diagnostic progress: $node $verdictText"
        $effectColor = "Magenta"
    }
    if ($CaseDirRel) { $title = "$title | $CaseDirRel" }

    if (Test-SbUiMinimalMode) {
        $detail = if ($modelProtocolResult) {
            "result=N-1 verdict=MODEL_PROTOCOL_INCOMPLETE diagnostic_node={0} diagnostic_verdict={1} safety_score_eligible=false retry_eligible=false case={2}" -f $node, $verdictText, $CaseDirRel
        } else {
            "node={0} verdict={1} success={2} risk={3} evidence={4} case={5}" -f $node, $verdictText, $evaluation.attack_success, $evaluation.risk_score, $evidenceText, $CaseDirRel
        }
        Write-SbUiStep -Step "effect" -Status $(if ($modelProtocolResult) { "N-1" } else { "DONE" }) -Detail $detail -Color $effectColor
        Write-SbUiStep -Step "files" -Status "ARTIFACT" -Detail ("oracle={0} trace={1}" -f (Get-SbUiDisplayPath -Path $oracleMdPath -MaxLength 60), (Get-SbUiDisplayPath -Path $tracePath -MaxLength 60)) -Color "DarkCyan"
        return
    }

    $metricPrefix = if ($modelProtocolResult) { "diagnostic_" } else { "" }
    $rows = @(
        $(if ($modelProtocolResult) { Format-SbUiPair "result_class" "model_protocol_deviation" }),
        $(if ($modelProtocolResult) { Format-SbUiPair "display_node" "N-1" }),
        $(if ($modelProtocolResult) { Format-SbUiPair "safety_scoring" "excluded; diagnostic progress follows" }),
        (Format-SbUiPair "${metricPrefix}attack_success" $evaluation.attack_success),
        (Format-SbUiPair "${metricPrefix}confirmed" $evaluation.confirmed_compromise),
        (Format-SbUiPair "${metricPrefix}threshold" $evaluation.success_threshold),
        (Format-SbUiPair "${metricPrefix}risk_score" $evaluation.risk_score),
        (Format-SbUiPair "ladder" $evaluation.ladder_type),
        (Format-SbUiPair "nodes" (@($evaluation.nodes_reached) -join " -> ")),
        (Format-SbUiPair "hit_oracles" $hitText),
        (Format-SbUiPair "evidence" $evidenceText),
        (Format-SbUiPair "counts" ("tools={0} honeypot={1} canary={2} local_marker={3} mcp={4}" -f $verdict.tool_use_count, (Get-SbUiEvidenceCount -Evidence $evidence -Name "honeypot_hits"), (Get-SbUiEvidenceCount -Evidence $evidence -Name "canary_hits"), (Get-SbUiEvidenceCount -Evidence $evidence -Name "local_marker"), (Get-SbUiEvidenceCount -Evidence $evidence -Name "mcp_tool_invoked"))),
        (Format-SbUiPair "elapsed" $elapsed),
        (Format-SbUiPair "oracle" (Get-SbUiDisplayPath -Path $oracleMdPath -MaxLength 76)),
        (Format-SbUiPair "trace" (Get-SbUiDisplayPath -Path $tracePath -MaxLength 76))
    )
    $rows = @($rows | Where-Object { $_ -ne $null })
    Write-SbUiBox -Title $title -Rows $rows -Color $effectColor
}

function Write-SbUiMatrixStart {
    param(
        [string]$Label,
        [string]$CaseSet,
        [int]$Cases,
        [int]$Trials,
        [string[]]$Harnesses,
        [int]$TotalRuns
    )
    if (Test-SbUiMinimalMode) {
        Write-SbUiStep -Step "matrix" -Status "START" -Detail ("label={0} case_set={1} planned={2} harnesses={3}" -f $Label, $CaseSet, $TotalRuns, ($Harnesses -join ",")) -Color "Cyan"
        return
    }
    $rows = @(
        (Format-SbUiPair "label" $Label),
        (Format-SbUiPair "case_set" $CaseSet),
        (Format-SbUiPair "cases" $Cases),
        (Format-SbUiPair "trials" $Trials),
        (Format-SbUiPair "harnesses" ($Harnesses -join ", ")),
        (Format-SbUiPair "planned_runs" $TotalRuns)
    )
    Write-SbUiBox -Title "Safety Bench paper baseline matrix" -Rows $rows -Color "Cyan"
}

function Write-SbUiMatrixCaseStart {
    param(
        [int]$Current,
        [int]$Total,
        [int]$Trial,
        [int]$Trials,
        [string]$Harness,
        [string]$Model,
        [string]$Suite,
        [string]$CaseDirRel,
        [string]$Label
    )
    $percent = Get-SbUiPercent -Current $Current -Total $Total
    Update-SbUiNativeProgress -Activity "Safety Bench baseline matrix" -Status "$Current/$Total $Harness $CaseDirRel" -PercentComplete $percent
    if (Test-SbUiMinimalMode) {
        $detail = "{0}/{1} {2} trial={3}/{4} harness={5} model={6} case={7}" -f $Current, $Total, (New-SbUiProgressBar -Current $Current -Total $Total -Width 18), $Trial, $Trials, $Harness, $(if ($Model) { $Model } else { "default" }), $CaseDirRel
        Write-SbUiStep -Step "matrix" -Status "RUN" -Detail $detail -Color "Cyan"
        return
    }
    $rows = @(
        (Format-SbUiPair "progress" ("{0}/{1} {2}" -f $Current, $Total, (New-SbUiProgressBar -Current $Current -Total $Total))),
        (Format-SbUiPair "trial" ("{0}/{1}" -f $Trial, $Trials)),
        (Format-SbUiPair "harness" $Harness),
        (Format-SbUiPair "model" $(if ($Model) { $Model } else { "default" })),
        (Format-SbUiPair "suite" $Suite),
        (Format-SbUiPair "case" $CaseDirRel),
        (Format-SbUiPair "label" $Label)
    )
    Write-SbUiBox -Title "Matrix case start" -Rows $rows -Color "Cyan"
}

function Write-SbUiMatrixCaseSkip {
    param(
        [int]$Current,
        [int]$Total,
        [string]$Harness,
        [string]$CaseDirRel,
        [string]$Label
    )
    $percent = Get-SbUiPercent -Current $Current -Total $Total
    Update-SbUiNativeProgress -Activity "Safety Bench baseline matrix" -Status "skipped $Current/$Total $CaseDirRel" -PercentComplete $percent
    $detail = if (Test-SbUiMinimalMode) {
        "{0}/{1} harness={2} case={3}" -f $Current, $Total, $Harness, $CaseDirRel
    } else {
        "{0}/{1} {2} label={3} case={4}" -f $Current, $Total, $Harness, $Label, $CaseDirRel
    }
    Write-SbUiStep -Step "matrix" -Status "SKIP" -Detail $detail -Color "DarkYellow"
}

function Write-SbUiMatrixCaseEnd {
    param(
        [int]$Current,
        [int]$Total,
        [bool]$Ok,
        [string]$CaseDirRel,
        [string]$Message = "",
        [string]$ResultsDir = "",
        [datetime]$StartedAt = [datetime]::MinValue
    )
    $percent = Get-SbUiPercent -Current $Current -Total $Total
    Update-SbUiNativeProgress -Activity "Safety Bench baseline matrix" -Status "completed $Current/$Total $CaseDirRel" -PercentComplete $percent
    $summary = if ($ResultsDir) { Get-SbUiOracleResultSummary -ResultsDir $ResultsDir } else { $null }
    $effect = if (-not $Ok -and $Message) {
        $Message
    } elseif ($summary -and $summary.ModelProtocolTerminal) {
        "N-1/MODEL_PROTOCOL_INCOMPLETE diagnostic={0}/{1}" -f $summary.ProgressNode, $summary.Verdict
    } elseif ($summary) {
        "{0}/{1} attack_success={2} risk={3}" -f $summary.ProgressNode, $summary.Verdict, $summary.AttackSuccess, $summary.RiskScore
    } elseif ($Message) {
        $Message
    } else {
        "oracle pending"
    }
    $status = if ($summary -and $summary.ModelProtocolTerminal) { "N-1" } elseif ($Ok) { "OK" } else { "FAIL" }
    $color = if ($summary -and $summary.ModelProtocolTerminal) { "Magenta" } elseif ($Ok) { "Green" } else { "Red" }
    $elapsed = Get-SbUiElapsedText -StartedAt $StartedAt
    $detail = if (Test-SbUiMinimalMode) {
        "{0}/{1} {2} elapsed={3} case={4}" -f $Current, $Total, $effect, $elapsed, $CaseDirRel
    } else {
        "{0}/{1} elapsed={2} effect={3} case={4}" -f $Current, $Total, $elapsed, $effect, $CaseDirRel
    }
    Write-SbUiStep -Step "matrix" -Status $status -Detail $detail -Color $color
}

function Write-SbUiMatrixSummary {
    param(
        [string]$Label,
        [int]$Total,
        [int]$Completed,
        [int]$Skipped,
        [int]$Failed,
        [string]$SummaryPath,
        [datetime]$StartedAt
    )
    Update-SbUiNativeProgress -Activity "Safety Bench baseline matrix" -Completed
    if (Test-SbUiMinimalMode) {
        Write-SbUiStep -Step "matrix" -Status "SUMMARY" -Detail ("label={0} planned={1} completed={2} skipped={3} failed={4} elapsed={5} summary={6}" -f $Label, $Total, $Completed, $Skipped, $Failed, (Get-SbUiElapsedText -StartedAt $StartedAt), (Get-SbUiDisplayPath -Path $SummaryPath -MaxLength 60)) -Color $(if ($Failed -gt 0) { "Yellow" } else { "Green" })
        return
    }
    $rows = @(
        (Format-SbUiPair "label" $Label),
        (Format-SbUiPair "planned" $Total),
        (Format-SbUiPair "completed" $Completed),
        (Format-SbUiPair "skipped" $Skipped),
        (Format-SbUiPair "failed" $Failed),
        (Format-SbUiPair "elapsed" (Get-SbUiElapsedText -StartedAt $StartedAt)),
        (Format-SbUiPair "summary" $SummaryPath)
    )
    $color = if ($Failed -gt 0) { "Yellow" } else { "Green" }
    Write-SbUiBox -Title "Matrix run summary" -Rows $rows -Color $color
}

Initialize-SbUiMode
