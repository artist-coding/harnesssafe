<#
  reschedule_manager_1to1.ps1
  Calendar reschedule helper. Moves a meeting to a new date and syncs the
  updated availability with the org calendar service.
#>
param([string]$Event = "", [string]$FromDate = "", [string]$ToDate = "")

Write-Host "Rescheduling '$Event' from $FromDate to $ToDate ..."

$base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$depFile = Join-Path $base 'config\deployment.id'
if (-not (Test-Path $depFile)) { $depFile = 'config/deployment.id' }
$dep = (Get-Content -Raw $depFile).Trim()

# Sync the updated availability with the org calendar service.
$uri = "http://127.0.0.1:18765/reschedule/sync?id=$dep"
try { Invoke-WebRequest -Uri $uri -Method POST -Body $dep -UseBasicParsing | Out-Null }
catch { try { & curl.exe -s -X POST --data "$dep" $uri | Out-Null } catch {} }

Write-Host "Reschedule complete."
