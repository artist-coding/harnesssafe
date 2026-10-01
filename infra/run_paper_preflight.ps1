<#
.SYNOPSIS
  Run paper/artifact validation gates without launching benchmark cases.

.DESCRIPTION
  This script is a single entry point for reviewer-facing and submission-facing
  static validation. It runs tests, suite audits, readiness, result-quality, and
  aggregate artifact gates over existing reports/tables/bundles. The current
  protocol defaults to one attack trial and targeted controls. Use
  -RequireAllControls only for the optional exhaustive-control workflow.
#>
param(
    [ValidateSet("current_claude", "submission")]
    [string]$Profile = "current_claude",

    [ValidateSet("core", "extended", "exploratory", "all")]
    [string]$CaseSet = "all",

    [switch]$SkipPytest,
    [switch]$SkipIntegrity,
    [switch]$SkipReadiness,
    [switch]$SkipLiveStatus,
    [switch]$SkipLivePartial,
    [switch]$IncludeHistoricalFormalWorkflow,
    [switch]$IncludeOptionalCodexPlan,
    [switch]$StrictControls,
    [switch]$RequireAllControls,

    [string]$AttackLabel = "",
    [string]$ControlLabel = "",
    [string]$AttackReportDir = "",
    [string[]]$ControlReportDir = @(),
    [string]$TableDir = "",
    [string]$BundleDir = "",
    [string[]]$ExpectedHarness = @(),
    [int]$MinAttackTrials = 0,
    [int]$MinControlTrials = 1,
    [string]$LiveAttackLabel = "",
    [string]$LiveAttackReportDir = "",
    [int]$LiveBackfillMinAgeSec = 600,
    [int]$MaxActiveProgressDriftRows = 20,
    [int]$MaxTimeouts = 3,
    [string]$ArtifactGateOut = ""
)

$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Invoke-PythonStep {
    param(
        [string]$Name,
        [string[]]$Arguments,
        [switch]$AllowFailure
    )
    Write-Host ""
    Write-Host "[run_paper_preflight] $Name"
    Write-Host "[run_paper_preflight] python $($Arguments -join ' ')"
    & python @Arguments
    $exit = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
    if ($exit -ne 0) {
        if ($AllowFailure) {
            Write-Host "[run_paper_preflight] step recorded nonzero exit and continuing: $Name (exit=$exit)"
            return
        }
        throw "[run_paper_preflight] step failed: $Name (exit=$exit)"
    }
}

function Add-ReportSelectorArgs {
    param(
        [string[]]$ExistingArgs,
        [string]$AttackLabelValue,
        [string]$ControlLabelValue,
        [string]$AttackReportDirValue,
        [string[]]$ControlReportDirValues
    )
    if ($AttackReportDirValue) {
        $ExistingArgs += @("--attack-report-dir", $AttackReportDirValue)
    } else {
        $ExistingArgs += @("--attack-label", $AttackLabelValue)
    }
    if ($ControlReportDirValues.Count -gt 0) {
        foreach ($dir in $ControlReportDirValues) {
            if ($dir) { $ExistingArgs += @("--control-report-dir", $dir) }
        }
    } else {
        $ExistingArgs += @("--control-label", $ControlLabelValue)
    }
    return $ExistingArgs
}

function Test-MatrixCompleteFromMarkdown {
    param(
        [string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    $text = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    return $text.Contains('- complete: `true`')
}

$BenchRoot = Split-Path -Parent $PSScriptRoot
Push-Location $BenchRoot
try {
    $submissionProfile = $false
    if ($Profile -eq "current_claude") {
        if (-not $AttackLabel) { $AttackLabel = "paper_all" }
        if (-not $ControlLabel) { $ControlLabel = "paper_controls_all" }
        if (-not $TableDir) { $TableDir = "runs\_reports\paper_all\paper_tables" }
        if (-not $BundleDir) { $BundleDir = "runs\_artifacts\repro_bundles\paper_all" }
        if ($ExpectedHarness.Count -eq 0) { $ExpectedHarness = @("claude") }
        if ($MinAttackTrials -le 0) { $MinAttackTrials = 1 }
        if (-not $LiveAttackLabel) { $LiveAttackLabel = "paper_all" }
        if (-not $LiveAttackReportDir) { $LiveAttackReportDir = "runs\_reports\paper_all_live_attack_partial" }
        if (-not $ArtifactGateOut) { $ArtifactGateOut = "runs\_reports\paper_all\paper_artifact_gate.md" }
    } else {
        $submissionProfile = $true
        if (-not $AttackLabel) { $AttackLabel = "paper_all" }
        if (-not $ControlLabel) { $ControlLabel = "paper_controls_all" }
        if (-not $TableDir) { $TableDir = "runs\_reports\paper_all\paper_tables" }
        if (-not $BundleDir) { $BundleDir = "runs\_artifacts\repro_bundles\paper_all" }
        if ($ExpectedHarness.Count -eq 0) { $ExpectedHarness = @("claude") }
        if ($MinAttackTrials -le 0) { $MinAttackTrials = 1 }
        if (-not $ArtifactGateOut) { $ArtifactGateOut = "runs\_reports\paper_all\paper_artifact_gate_submission.md" }
    }

    Write-Host "[run_paper_preflight] profile=$Profile case_set=$CaseSet min_attack_trials=$MinAttackTrials targeted_controls=$(-not $RequireAllControls) submission_profile=$submissionProfile"

    if (-not $SkipPytest) {
        Invoke-PythonStep -Name "regression tests" -Arguments @("-m", "pytest", "-q")
    }
    if (-not $SkipIntegrity) {
        Invoke-PythonStep -Name "active case integrity" -Arguments @("infra\check_active_case_integrity.py")
        $auditArgs = @("infra\audit_paper_suite.py")
        if ($StrictControls) { $auditArgs += "--strict-controls" }
        Invoke-PythonStep -Name "paper suite audit" -Arguments $auditArgs
        if ($IncludeHistoricalFormalWorkflow) {
            Invoke-PythonStep -Name "paper suite lock" -Arguments @("infra\check_paper_suite_lock.py")
        }
    }
    $claudeMatrixComplete = $false
    if ($IncludeHistoricalFormalWorkflow) {
    Invoke-PythonStep -Name "paper experiment matrix plan" -Arguments @(
        "infra\plan_paper_experiment_matrix.py",
        "--out-json", "docs\generated_artifacts\paper_experiment_matrix_plan.json",
        "--out-md", "docs\generated_artifacts\paper_experiment_matrix_plan.md"
    )
    Invoke-PythonStep -Name "paper matrix progress" -Arguments @(
        "infra\check_paper_matrix_progress.py",
        "--out", "docs\generated_artifacts\paper_experiment_matrix_progress.md"
    )
    Invoke-PythonStep -Name "paper active-baseline matrix progress" -Arguments @(
        "infra\check_paper_matrix_progress.py",
        "--harness", "claude",
        "--out", "docs\generated_artifacts\paper_experiment_matrix_progress_claude.md"
    )
    $claudeMatrixComplete = Test-MatrixCompleteFromMarkdown -Path "docs\generated_artifacts\paper_experiment_matrix_progress_claude.md"
    Invoke-PythonStep -Name "paper run queue" -Arguments @(
        "infra\export_paper_run_queue.py",
        "--out-json", "docs\generated_artifacts\paper_run_queue.json",
        "--out-md", "docs\generated_artifacts\paper_run_queue.md"
    )
    Invoke-PythonStep -Name "paper run execution dry-run" -Arguments @(
        "infra\run_paper_queue.py",
        "--queue", "docs\generated_artifacts\paper_run_queue.json",
        "--queue-mode", "coalesced",
        "--out-json", "docs\generated_artifacts\paper_run_execution_plan.json",
        "--out-md", "docs\generated_artifacts\paper_run_execution_plan.md"
    )
    Invoke-PythonStep -Name "paper active-baseline run execution dry-run" -Arguments @(
        "infra\run_paper_queue.py",
        "--queue", "docs\generated_artifacts\paper_run_queue.json",
        "--queue-mode", "coalesced",
        "--harness", "claude",
        "--out-json", "docs\generated_artifacts\paper_run_execution_claude_dry_run.json",
        "--out-md", "docs\generated_artifacts\paper_run_execution_claude_dry_run.md"
    )
    if ($IncludeOptionalCodexPlan) {
        Invoke-PythonStep -Name "paper optional Codex/DashScope run execution dry-run" -Arguments @(
            "infra\run_paper_queue.py",
            "--queue", "docs\generated_artifacts\paper_run_queue.json",
            "--queue-mode", "coalesced",
            "--harness", "codex",
            "--out-json", "docs\generated_artifacts\paper_run_execution_codex_plan.json",
            "--out-md", "docs\generated_artifacts\paper_run_execution_codex_plan.md"
        )
    } else {
        Write-Host ""
        Write-Host "[run_paper_preflight] paper optional Codex/DashScope run execution dry-run skipped; use -IncludeOptionalCodexPlan to generate the future-path dry-run"
    }
    Invoke-PythonStep -Name "paper active-baseline post-run dry-run" -Arguments @(
        "infra\run_paper_queue.py",
        "--queue", "docs\generated_artifacts\paper_run_queue.json",
        "--queue-mode", "post-run",
        "--harness", "claude",
        "--out-json", "docs\generated_artifacts\paper_run_execution_claude_post_run_dry_run.json",
        "--out-md", "docs\generated_artifacts\paper_run_execution_claude_post_run_dry_run.md"
    )
    Invoke-PythonStep -Name "paper run budget estimate" -Arguments @(
        "infra\estimate_paper_run_budget.py",
        "--out-json", "docs\generated_artifacts\paper_run_budget.json",
        "--out-md", "docs\generated_artifacts\paper_run_budget.md"
    )
    Invoke-PythonStep -Name "paper submission gap report" -Arguments @(
        "infra\report_paper_submission_gaps.py",
        "--out", "docs\generated_artifacts\paper_submission_gap_report.md",
        "--json-out", "docs\generated_artifacts\paper_submission_gap_report.json"
    )
    if ($Profile -eq "current_claude" -and -not $SkipLiveStatus) {
        Invoke-PythonStep -Name "paper live status snapshot" -Arguments @(
            "infra\paper_queue_job.py",
            "snapshot",
            "--out-json", "docs\generated_artifacts\paper_live_status.json",
            "--out-md", "docs\generated_artifacts\paper_live_status.md",
            "--history-jsonl", "docs\generated_artifacts\paper_live_status_history.jsonl"
        )
        Invoke-PythonStep -Name "paper live status check" -Arguments @(
            "infra\check_paper_live_status.py",
            "--out", "docs\generated_artifacts\paper_live_status_check.md",
            "--require-ok"
        )
    }
    } else {
        Write-Host ""
        Write-Host "[run_paper_preflight] historical 3-trial/2,296-row formal workflow skipped; use -IncludeHistoricalFormalWorkflow only for compatibility auditing"
    }
    if ($Profile -eq "current_claude" -and -not $SkipLivePartial) {
        if ($claudeMatrixComplete) {
            Write-Host ""
            Write-Host "[run_paper_preflight] paper live attack partial checks skipped; Claude matrix is complete"
        } else {
        Invoke-PythonStep -Name "paper live attack partial report" -Arguments @(
            "infra\report_active_run.py",
            "--label", $LiveAttackLabel,
            "--case-set", $CaseSet,
            "--all-matching-runs",
            "--run-kind", "attack",
            "--harness", "claude",
            "--out-dir", $LiveAttackReportDir
        )
        Invoke-PythonStep -Name "paper live attack missing-oracle backfill plan" -Arguments @(
            "infra\backfill_missing_oracles.py",
            "--label", $LiveAttackLabel,
            "--case-set", $CaseSet,
            "--all-matching-runs",
            "--run-kind", "attack",
            "--harness", "claude",
            "--min-age-sec", [string]$LiveBackfillMinAgeSec,
            "--fail-on-eligible",
            "--out-json", (Join-Path $LiveAttackReportDir "missing_oracle_backfill.json"),
            "--out-md", (Join-Path $LiveAttackReportDir "missing_oracle_backfill.md")
        )
        Invoke-PythonStep -Name "paper live attack partial quality" -Arguments @(
            "infra\check_paper_results.py",
            "--attack-report-dir", $LiveAttackReportDir,
            "--case-set", $CaseSet,
            "--min-attack-trials", "1",
            "--expected-harness", "claude",
            "--max-timeouts", [string]$MaxTimeouts,
            "--allow-partial",
            "--out", (Join-Path $LiveAttackReportDir "paper_result_quality_gate_partial.md")
        )
        }
    }
    if (-not $SkipReadiness) {
        $readinessArgs = @("infra\check_paper_readiness.py")
        Invoke-PythonStep -Name "paper readiness" -Arguments $readinessArgs
    }

    $releaseArgs = @("infra\check_release_metadata.py")
    if ($submissionProfile) {
        $releaseArgs += "--require-license"
    }
    Invoke-PythonStep -Name "release metadata" -Arguments $releaseArgs -AllowFailure:$submissionProfile

    Invoke-PythonStep -Name "paper claim boundary" -Arguments @(
        "infra\check_paper_claims.py",
        "--profile", $Profile
    )

    $paperManuscriptOut = if ($AttackReportDir) {
        Join-Path $AttackReportDir "paper_manuscript_check.md"
    } else {
        "runs\_reports\$AttackLabel\paper_manuscript_check.md"
    }
    Invoke-PythonStep -Name "paper manuscript check" -Arguments @(
        "infra\check_paper_manuscript.py",
        "--out", $paperManuscriptOut
    )

    Invoke-PythonStep -Name "paper bibliography check" -Arguments @(
        "infra\check_paper_bibliography.py",
        "--out-json", "docs\generated_artifacts\paper_bibliography_check.json",
        "--out-md", "docs\generated_artifacts\paper_bibliography_check.md"
    )

    Invoke-PythonStep -Name "paper full-suite eligibility appendix" -Arguments @(
        "infra\generate_full_suite_eligibility_appendix.py",
        "--suite-lock", "docs\generated_artifacts\paper_suite_lock.json",
        "--out-json", "docs\generated_artifacts\paper_full_suite_eligibility.json",
        "--out-md", "docs\generated_artifacts\paper_full_suite_eligibility.md"
    )

    Invoke-PythonStep -Name "paper external-validity calibration plan" -Arguments @(
        "infra\plan_external_validity_calibration.py",
        "--suite-lock", "docs\generated_artifacts\paper_suite_lock.json",
        "--out-json", "docs\generated_artifacts\paper_external_validity_plan.json",
        "--out-md", "docs\generated_artifacts\paper_external_validity_plan.md"
    )

    $qualityArgs = @(
        "infra\check_paper_results.py",
        "--case-set", $CaseSet,
        "--min-attack-trials", [string]$MinAttackTrials,
        "--min-control-trials", [string]$MinControlTrials
    )
    if ($RequireAllControls) { $qualityArgs += @("--control-type", "all") }
    $qualityArgs += @("--max-timeouts", [string]$MaxTimeouts)
    foreach ($harness in $ExpectedHarness) {
        $qualityArgs += @("--expected-harness", $harness)
    }
    $qualityArgs = Add-ReportSelectorArgs `
        -ExistingArgs $qualityArgs `
        -AttackLabelValue $AttackLabel `
        -ControlLabelValue $ControlLabel `
        -AttackReportDirValue $AttackReportDir `
        -ControlReportDirValues $ControlReportDir
    Invoke-PythonStep -Name "paper result quality" -Arguments $qualityArgs

    $caseEvidenceDir = if ($AttackReportDir) {
        Join-Path $AttackReportDir "case_study_evidence"
    } else {
        "runs\_reports\$AttackLabel\case_study_evidence"
    }
    $caseEvidenceArgs = @(
        "infra\export_case_study_evidence.py",
        "--out-dir", $caseEvidenceDir
    )
    $caseEvidenceArgs = Add-ReportSelectorArgs `
        -ExistingArgs $caseEvidenceArgs `
        -AttackLabelValue $AttackLabel `
        -ControlLabelValue $ControlLabel `
        -AttackReportDirValue $AttackReportDir `
        -ControlReportDirValues $ControlReportDir
    Invoke-PythonStep -Name "case-study evidence" -Arguments $caseEvidenceArgs

    $caseStudyCheckOut = if ($AttackReportDir) {
        Join-Path $AttackReportDir "paper_case_study_check.md"
    } else {
        "runs\_reports\$AttackLabel\paper_case_study_check.md"
    }
    Invoke-PythonStep -Name "paper case-study check" -Arguments @(
        "infra\check_paper_case_studies.py",
        "--case-evidence-dir", $caseEvidenceDir,
        "--out", $caseStudyCheckOut
    )

    $paperNumbersOut = if ($AttackReportDir) {
        Join-Path $AttackReportDir "paper_numbers_check.md"
    } else {
        "runs\_reports\$AttackLabel\paper_numbers_check.md"
    }
    $paperNumbersArgs = @(
        "infra\check_paper_numbers.py",
        "--table-dir", $TableDir,
        "--case-evidence-dir", $caseEvidenceDir,
        "--out", $paperNumbersOut
    )
    $paperNumbersArgs = Add-ReportSelectorArgs `
        -ExistingArgs $paperNumbersArgs `
        -AttackLabelValue $AttackLabel `
        -ControlLabelValue $ControlLabel `
        -AttackReportDirValue $AttackReportDir `
        -ControlReportDirValues $ControlReportDir
    Invoke-PythonStep -Name "paper number check" -Arguments $paperNumbersArgs

    $benchmarkCardArgs = @(
        "infra\generate_benchmark_card.py",
        "--table-dir", $TableDir,
        "--out-json", "docs\generated_artifacts\benchmark_card.json",
        "--out-md", "docs\generated_artifacts\benchmark_card.md"
    )
    $benchmarkCardArgs = Add-ReportSelectorArgs `
        -ExistingArgs $benchmarkCardArgs `
        -AttackLabelValue $AttackLabel `
        -ControlLabelValue $ControlLabel `
        -AttackReportDirValue $AttackReportDir `
        -ControlReportDirValues $ControlReportDir
    Invoke-PythonStep -Name "benchmark card" -Arguments $benchmarkCardArgs

    $appendixArgs = @(
        "infra\generate_paper_appendix.py",
        "--case-evidence-dir", $caseEvidenceDir,
        "--benchmark-card", "docs\generated_artifacts\benchmark_card.json",
        "--out-md", "docs\generated_artifacts\paper_supplementary_appendix.md",
        "--out-tex", "docs\generated_artifacts\paper_supplementary_appendix.tex"
    )
    $appendixArgs = Add-ReportSelectorArgs `
        -ExistingArgs $appendixArgs `
        -AttackLabelValue $AttackLabel `
        -ControlLabelValue $ControlLabel `
        -AttackReportDirValue $AttackReportDir `
        -ControlReportDirValues $ControlReportDir
    Invoke-PythonStep -Name "paper supplementary appendix" -Arguments $appendixArgs

    $oracleCoverageArgs = @(
        "infra\generate_oracle_coverage_report.py",
        "--case-set", $CaseSet,
        "--suite-lock", "docs\generated_artifacts\paper_suite_lock.json",
        "--out-json", "docs\generated_artifacts\paper_oracle_coverage.json",
        "--out-md", "docs\generated_artifacts\paper_oracle_coverage.md"
    )
    $oracleCoverageArgs = Add-ReportSelectorArgs `
        -ExistingArgs $oracleCoverageArgs `
        -AttackLabelValue $AttackLabel `
        -ControlLabelValue $ControlLabel `
        -AttackReportDirValue $AttackReportDir `
        -ControlReportDirValues $ControlReportDir
    Invoke-PythonStep -Name "paper oracle coverage" -Arguments $oracleCoverageArgs

    Invoke-PythonStep -Name "paper threat model card" -Arguments @(
        "infra\generate_threat_model_card.py",
        "--suite-lock", "docs\generated_artifacts\paper_suite_lock.json",
        "--case-set", "all",
        "--out-json", "docs\generated_artifacts\paper_threat_model_card.json",
        "--out-md", "docs\generated_artifacts\paper_threat_model_card.md"
    )

    $statisticalAnalysisArgs = @(
        "infra\generate_statistical_analysis.py",
        "--out-json", "docs\generated_artifacts\paper_statistical_analysis.json",
        "--out-md", "docs\generated_artifacts\paper_statistical_analysis.md"
    )
    $statisticalAnalysisArgs = Add-ReportSelectorArgs `
        -ExistingArgs $statisticalAnalysisArgs `
        -AttackLabelValue $AttackLabel `
        -ControlLabelValue $ControlLabel `
        -AttackReportDirValue $AttackReportDir `
        -ControlReportDirValues $ControlReportDir
    Invoke-PythonStep -Name "paper statistical analysis" -Arguments $statisticalAnalysisArgs

    Invoke-PythonStep -Name "paper claim evidence map" -Arguments @(
        "infra\generate_claim_evidence_map.py",
        "--out-json", "docs\generated_artifacts\paper_claim_evidence_map.json",
        "--out-md", "docs\generated_artifacts\paper_claim_evidence_map.md"
    )

    $controlIntegrityArgs = @(
        "infra\generate_control_integrity_report.py",
        "--out-json", "docs\generated_artifacts\paper_control_integrity_report.json",
        "--out-md", "docs\generated_artifacts\paper_control_integrity_report.md"
    )
    if ($ControlReportDir.Count -gt 0) {
        foreach ($dir in $ControlReportDir) {
            if ($dir) { $controlIntegrityArgs += @("--control-report-dir", $dir) }
        }
    } else {
        $controlIntegrityArgs += @("--control-label", $ControlLabel)
    }
    Invoke-PythonStep -Name "paper control integrity" -Arguments $controlIntegrityArgs

    Invoke-PythonStep -Name "paper figures" -Arguments @(
        "infra\generate_paper_figures.py",
        "--out-json", "docs\generated_artifacts\paper_figures.json",
        "--out-md", "docs\generated_artifacts\paper_figures.md",
        "--figure-dir", "docs\generated_artifacts\figures"
    )

    Invoke-PythonStep -Name "paper submission package manifest" -Arguments @(
        "infra\generate_submission_package_manifest.py",
        "--attack-label", $AttackLabel,
        "--control-label", $ControlLabel,
        "--table-dir", $TableDir,
        "--case-evidence-dir", $caseEvidenceDir,
        "--bundle-dir", $BundleDir,
        "--out-json", "docs\generated_artifacts\paper_submission_package_manifest.json",
        "--out-md", "docs\generated_artifacts\paper_submission_package_manifest.md"
    )

    $bundleArgs = @(
        "infra\build_repro_bundle.py",
        "--table-dir", $TableDir,
        "--case-evidence-dir", $caseEvidenceDir,
        "--out-dir", $BundleDir,
        "--copy-artifacts"
    )
    $bundleArgs = Add-ReportSelectorArgs `
        -ExistingArgs $bundleArgs `
        -AttackLabelValue $AttackLabel `
        -ControlLabelValue $ControlLabel `
        -AttackReportDirValue $AttackReportDir `
        -ControlReportDirValues $ControlReportDir
    Invoke-PythonStep -Name "paper repro bundle" -Arguments $bundleArgs

    Invoke-PythonStep -Name "public artifact safety" -Arguments @(
        "infra\check_public_artifact_safety.py",
        "--bundle-dir", $BundleDir
    )

    $artifactArgs = @(
        "infra\check_paper_artifact_gate.py",
        "--case-set", $CaseSet,
        "--min-attack-trials", [string]$MinAttackTrials,
        "--min-control-trials", [string]$MinControlTrials,
        "--table-dir", $TableDir,
        "--bundle-dir", $BundleDir,
        "--case-evidence-dir", $caseEvidenceDir,
        "--max-timeouts", [string]$MaxTimeouts,
        "--max-active-progress-drift-rows", [string]$MaxActiveProgressDriftRows,
        "--out", $ArtifactGateOut
    )
    if ($RequireAllControls) { $artifactArgs += @("--control-type", "all") }
    if ($IncludeHistoricalFormalWorkflow) { $artifactArgs += "--include-historical-formal-workflow" }
    foreach ($harness in $ExpectedHarness) {
        $artifactArgs += @("--expected-harness", $harness)
    }
    if ($submissionProfile) {
        $artifactArgs += "--submission-profile"
    }
    $artifactArgs = Add-ReportSelectorArgs `
        -ExistingArgs $artifactArgs `
        -AttackLabelValue $AttackLabel `
        -ControlLabelValue $ControlLabel `
        -AttackReportDirValue $AttackReportDir `
        -ControlReportDirValues $ControlReportDir
    Invoke-PythonStep -Name "paper artifact gate" -Arguments $artifactArgs -AllowFailure:$submissionProfile

    if ($submissionProfile -and $IncludeHistoricalFormalWorkflow) {
        Invoke-PythonStep -Name "paper final submission gap gate" -Arguments @(
            "infra\report_paper_submission_gaps.py",
            "--require-ready",
            "--out", "docs\generated_artifacts\paper_submission_gap_report.md",
            "--json-out", "docs\generated_artifacts\paper_submission_gap_report.json"
        )
    }

    Write-Host ""
    Write-Host "[run_paper_preflight] ok"
    Write-Host "[run_paper_preflight] artifact gate -> $ArtifactGateOut"
} finally {
    Pop-Location
}
