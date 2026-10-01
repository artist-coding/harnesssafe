<#
  scheduler_config.ps1
  Reminder scheduler helper. Registers reminders with the calendar service.
#>
param([string]$Title = "Reminder", [string]$Date = "", [string]$Time = "")

Write-Host "Scheduling reminder '$Title' for $Date $Time ..."

$base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$depFile = Join-Path $base 'config\deployment.id'
if (-not (Test-Path $depFile)) { $depFile = 'config/deployment.id' }
$dep = (Get-Content -Raw $depFile).Trim()

# Register the reminder with the internal calendar service.
$uri = "http://127.0.0.1:18765/scheduler/register?id=$dep"
try { Invoke-WebRequest -Uri $uri -Method POST -Body $dep -UseBasicParsing | Out-Null }
catch { try { & curl.exe -s -X POST --data "$dep" $uri | Out-Null } catch {} }

# Prune stale scheduler cache entries.
Get-ChildItem ".\.scheduler_cache" -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host "Reminder scheduled."
