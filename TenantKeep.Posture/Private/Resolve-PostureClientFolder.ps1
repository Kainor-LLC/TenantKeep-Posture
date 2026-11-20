# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Resolve-PostureClientFolder {
    <#
    .SYNOPSIS
        The client folder for a tenant: -Client when given, otherwise the one folder under ~/tenantkeep/clients whose
        profile.json names the tenant id. Lets a command copied from the report carry the tenant id and no path.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string] $Client,
        [string] $TenantId,
        [string] $ClientsRoot = (Join-Path $HOME 'tenantkeep' 'clients')
    )

    $ErrorActionPreference = 'Stop'
    if ($Client) {
        $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Client)
        if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw "Client folder not found: $path" }
        return $path
    }
    if (-not $TenantId) { throw 'Give -TenantId (the report header shows it) or -Client with the client folder.' }
    $found = @()
    if (Test-Path -LiteralPath $ClientsRoot -PathType Container) {
        foreach ($dir in Get-ChildItem -LiteralPath $ClientsRoot -Directory) {
            $profilePath = Join-Path $dir.FullName 'profile.json'
            if (-not (Test-Path -LiteralPath $profilePath -PathType Leaf)) { continue }
            try { $p = Get-Content -Raw -LiteralPath $profilePath | ConvertFrom-Json -AsHashtable -Depth 10 } catch { continue }
            if ($p -is [System.Collections.IDictionary] -and [string]$p['tenantId'] -eq $TenantId) { $found += $dir.FullName }
        }
    }
    if ($found.Count -eq 1) { return $found[0] }
    if ($found.Count -eq 0) { throw "No client folder under $ClientsRoot has a profile.json for tenant $TenantId. Pass -Client with the folder Start-PostureRun used." }
    throw "More than one client folder is for tenant ${TenantId}: $($found -join ', '). Pass -Client with the one to use."
}

function Find-PostureRunFolder {
    <#
    .SYNOPSIS
        The newest run folder (yyyyMMdd-HHmm, with checks.json) for a tenant under the output root: -OutRoot, else the
        profile's outputRoot, else ~/tenantkeep/evidence. Returns $null when there is none.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Client,
        [string] $TenantId,
        [string] $OutRoot
    )

    $ErrorActionPreference = 'Stop'
    $root = Get-PostureOutputRoot -Client $Client -OutRoot $OutRoot
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return $null }
    $runs = @(Get-ChildItem -LiteralPath $root -Directory | Where-Object { $_.Name -match '^\d{8}-\d{4}$' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'checks.json')) } | Sort-Object Name -Descending)
    foreach ($run in $runs) {
        if (-not $TenantId) { return $run.FullName }
        $collection = Join-Path $run.FullName 'collection.json'
        if (-not (Test-Path -LiteralPath $collection)) { continue }
        try { $c = Get-Content -Raw -LiteralPath $collection | ConvertFrom-Json -AsHashtable -Depth 5 } catch { continue }
        if ([string]$c['tenantId'] -eq $TenantId) { return $run.FullName }
    }
    return $null
}

function Get-PostureOutputRoot {
    <#
    .SYNOPSIS
        Where run folders go: -OutRoot when given, else outputRoot in the client's profile.json, else ~/tenantkeep/evidence.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string] $Client,
        [string] $OutRoot
    )

    $ErrorActionPreference = 'Stop'
    $value = $OutRoot
    if (-not $value -and $Client) {
        $profilePath = Join-Path $Client 'profile.json'
        if (Test-Path -LiteralPath $profilePath -PathType Leaf) {
            try { $p = Get-Content -Raw -LiteralPath $profilePath | ConvertFrom-Json -AsHashtable -Depth 10 } catch { $p = $null }
            if ($p -is [System.Collections.IDictionary] -and $p['outputRoot']) { $value = [string]$p['outputRoot'] }
        }
    }
    if (-not $value) { $value = Join-Path $HOME 'tenantkeep' 'evidence' }
    if ($value -like '~*') { $value = $HOME + $value.Substring(1) }
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($value)
}

function Save-PostureJsonFile {
    <#
    .SYNOPSIS
        Writes JSON to a file through a temporary file in the same folder, so a failure never leaves half a file.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [object] $InputObject
    )

    $ErrorActionPreference = 'Stop'
    if (-not $PSCmdlet.ShouldProcess($Path, 'Write')) { return }
    $json = ConvertTo-Json -InputObject $InputObject -Depth 20
    $tmp = "$Path.tmp-$([guid]::NewGuid().ToString('n'))"
    try {
        Set-Content -LiteralPath $tmp -Value $json -Encoding utf8
        Move-Item -LiteralPath $tmp -Destination $Path -Force
    }
    finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force } }
}

function Update-PostureRunReport {
    <#
    .SYNOPSIS
        Rebuilds a run's report and findings.csv from its evidence, with the client folder's current exceptions and
        profile and the trend against the run before it. Reads the evidence only; nothing is collected again.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Run,
        [Parameter(Mandatory)] [string] $Client
    )

    $ErrorActionPreference = 'Stop'
    if (-not $PSCmdlet.ShouldProcess($Run, 'Rebuild the report')) { return $null }
    $parent = Split-Path $Run -Parent; $name = Split-Path $Run -Leaf
    $previous = @(Get-ChildItem -LiteralPath $parent -Directory | Where-Object { $_.Name -match '^\d{8}-\d{4}$' -and $_.Name -lt $name -and (Test-Path -LiteralPath (Join-Path $_.FullName 'checks.json')) } | Sort-Object Name | Select-Object -Last 1)
    $reportArgs = @{ Evidence = $Run; Client = $Client; PassThru = $true }
    if ($previous.Count -gt 0) { $reportArgs.Previous = $previous[0].FullName }
    $report = New-PostureReport @reportArgs
    $null = Export-PostureFindings -Path $Run -OutputPath (Join-Path $Run 'findings.csv')
    return @($report.Files | Where-Object { $_ -like '*.html' })[0]
}
