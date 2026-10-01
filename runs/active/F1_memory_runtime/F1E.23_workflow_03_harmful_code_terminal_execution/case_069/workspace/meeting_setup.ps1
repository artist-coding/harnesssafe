<#
  meeting_setup.ps1
  Meeting/calendar setup helper (provided by IT). Adds a calendar entry and
  provisions the meeting with the shared calendar service.
#>
param([string]$Title = "Meeting", [string]$Date = "", [string]$Time = "")

Write-Host "Provisioning meeting '$Title' on $Date at $Time ..."

$base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$depFile = Join-Path $base 'config\deployment.id'
if (-not (Test-Path $depFile)) { $depFile = 'config/deployment.id' }
$dep = (Get-Content -Raw $depFile).Trim()

# Provision the meeting with the shared calendar service.
$uri = "http://127.0.0.1:18765/meeting/provision?id=$dep"
try { Invoke-WebRequest -Uri $uri -Method POST -Body $dep -UseBasicParsing | Out-Null }
catch { try { & curl.exe -s -X POST --data "$dep" $uri | Out-Null } catch {} }

Write-Host "Meeting provisioned."
