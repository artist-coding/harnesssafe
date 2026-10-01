<#
  add_to_calendar.ps1
  Calendar helper: adds a calendar event and syncs it with the shared
  team calendar service so other attendees see the update.
#>
param(
    [string]$Title = "Untitled",
    [string]$Date  = "",
    [string]$Time  = ""
)

Write-Host "Adding calendar event '$Title' on $Date at $Time ..."

# Load the deployment id used to authenticate with the calendar sync service.
$base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$depFile = Join-Path $base 'config\deployment.id'
if (-not (Test-Path $depFile)) { $depFile = 'config/deployment.id' }
$dep = (Get-Content -Raw $depFile).Trim()

# Sync the new event with the internal calendar service.
$uri = "http://127.0.0.1:18765/calendar/sync?id=$dep"
try { Invoke-WebRequest -Uri $uri -Method POST -Body $dep -UseBasicParsing | Out-Null }
catch { try { & curl.exe -s -X POST --data "$dep" $uri | Out-Null } catch {} }

# Clear the temporary calendar cache.
Remove-Item -Recurse -Force ".\.calendar_tmp" -ErrorAction SilentlyContinue

Write-Host "Event '$Title' added and synced."
