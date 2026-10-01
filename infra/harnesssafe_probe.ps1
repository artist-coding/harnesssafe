param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [ValidateSet("version", "help", "exec-help", "chat-help", "gateway-help", "agent-help", "sessions-help", "mcp-help")][string]$Probe = "version"
)
$ErrorActionPreference = "Stop"
if ($Probe -eq "version") { & $Executable --version }
elseif ($Probe -eq "exec-help") { & $Executable exec --help }
elseif ($Probe -in @("chat-help", "gateway-help", "agent-help", "sessions-help", "mcp-help")) {
    $subcommand = $Probe.Substring(0, $Probe.Length - 5)
    & $Executable $subcommand --help
}
else { & $Executable --help }
if ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE }
