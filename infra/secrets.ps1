function Get-SafetyBenchApiKeysPath {
    param([string]$BenchRoot)
    $override = [Environment]::GetEnvironmentVariable("SAFETY_BENCH_API_KEYS_FILE")
    if ($override) {
        if ([System.IO.Path]::IsPathRooted($override)) { return $override }
        return Join-Path $BenchRoot $override
    }
    return Join-Path $BenchRoot "bench_state\secrets\api_keys.json"
}

function Read-SafetyBenchApiKeys {
    param([string]$BenchRoot)
    $path = Get-SafetyBenchApiKeysPath -BenchRoot $BenchRoot
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        $data = Get-Content -Raw -Encoding UTF8 -LiteralPath $path | ConvertFrom-Json
    } catch {
        throw "FATAL_CREDENTIAL_FILE_INVALID: unable to parse API key file '$path': $($_.Exception.Message)"
    }
    return [pscustomobject]@{ Path = $path; Data = $data }
}

function Get-SafetyBenchValueByPath {
    param(
        $Data,
        [string]$Path
    )
    if ($null -eq $Data -or -not $Path) { return $null }
    $current = $Data
    foreach ($part in $Path.Split(".")) {
        if ($null -eq $current) { return $null }
        if ($current -is [System.Collections.IDictionary]) {
            if (-not $current.Contains($part)) { return $null }
            $current = $current[$part]
            continue
        }
        if ($current.PSObject.Properties.Name -notcontains $part) { return $null }
        $current = $current.$part
    }
    return $current
}

function ConvertTo-SafetyBenchSecretText {
    param($Value)
    if ($null -eq $Value) { return "" }
    if ($Value -is [string]) { return $Value.Trim() }
    if ($Value -is [ValueType]) { return ([string]$Value).Trim() }
    return ""
}

function Get-SafetyBenchSecretValue {
    param(
        [string]$BenchRoot,
        [string[]]$Keys
    )
    $doc = Read-SafetyBenchApiKeys -BenchRoot $BenchRoot
    if (-not $doc) { return [pscustomobject]@{ Value = ""; Source = "" } }
    foreach ($key in @($Keys | Where-Object { $_ } | Select-Object -Unique)) {
        $value = ConvertTo-SafetyBenchSecretText (Get-SafetyBenchValueByPath -Data $doc.Data -Path $key)
        if ($value) {
            return [pscustomobject]@{ Value = $value; Source = "$($doc.Path):$key" }
        }
    }
    return [pscustomobject]@{ Value = ""; Source = "" }
}

function Get-SafetyBenchEnvSecretValue {
    param(
        [string]$BenchRoot,
        [string]$EnvName
    )
    if (-not $EnvName) { return [pscustomobject]@{ Value = ""; Source = "" } }
    $lower = $EnvName.ToLowerInvariant()
    return Get-SafetyBenchSecretValue -BenchRoot $BenchRoot -Keys @(
        "env.$EnvName",
        $EnvName,
        $lower
    )
}

function Get-SafetyBenchProviderCredential {
    param(
        [string]$BenchRoot,
        [Alias("Provider")]
        [string]$ProviderName,
        [string]$AuthTarget,
        [string[]]$EnvCandidates = @()
    )
    $keys = @()
    $providerName = ([string]$ProviderName).Trim().ToLowerInvariant()
    $authName = ([string]$AuthTarget).Trim()
    $authLower = $authName.ToLowerInvariant()
    if ($providerName) {
        $suffixes = @($authLower)
        if ($authLower -like "*api_key*") { $suffixes += "api_key" }
        if ($authLower -like "*auth_token*") { $suffixes += "auth_token" }
        if ($authLower.StartsWith("$providerName`_")) {
            $suffixes += $authLower.Substring($providerName.Length + 1)
        }
        foreach ($suffix in @($suffixes | Where-Object { $_ } | Select-Object -Unique)) {
            $keys += "providers.$providerName.$suffix"
            $keys += "$providerName.$suffix"
            $keys += "${providerName}_$suffix"
        }
    }
    foreach ($envName in @($authName) + @($EnvCandidates)) {
        if (-not $envName) { continue }
        $keys += "env.$envName"
        $keys += $envName
        $keys += $envName.ToLowerInvariant()
    }
    return Get-SafetyBenchSecretValue -BenchRoot $BenchRoot -Keys $keys
}

function Get-SafetyBenchProviderBaseUrl {
    param(
        [string]$BenchRoot,
        [Alias("Provider")]
        [string]$ProviderName,
        [string[]]$EnvCandidates = @()
    )
    $keys = @()
    $providerName = ([string]$ProviderName).Trim().ToLowerInvariant()
    if ($providerName) {
        $keys += "providers.$providerName.base_url"
        $keys += "$providerName.base_url"
        $keys += "${providerName}_base_url"
    }
    foreach ($envName in @($EnvCandidates)) {
        if (-not $envName) { continue }
        $keys += "env.$envName"
        $keys += $envName
        $keys += $envName.ToLowerInvariant()
    }
    return Get-SafetyBenchSecretValue -BenchRoot $BenchRoot -Keys $keys
}
