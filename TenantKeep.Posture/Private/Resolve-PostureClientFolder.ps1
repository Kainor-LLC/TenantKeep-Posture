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
        The newest run folder with results (checks.json) for a tenant under the output root: -OutRoot, else the
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
    foreach ($run in Get-PostureRunInfo -Root $root) {
        if (-not $run.checks) { continue }
        if (-not $TenantId -or $run.tenantId -eq $TenantId) { return $run.path }
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
    $layout = Get-PostureRunLayout -Folder $Run
    $previous = Get-PosturePreviousRun -Run $layout.root
    $reportArgs = @{ Evidence = $layout.evidence; Client = $Client; PassThru = $true }
    if ($previous) { $reportArgs.Previous = $previous }
    $report = New-PostureReport @reportArgs
    $null = Export-PostureFindings -Path $layout.root -OutputPath (Join-Path $layout.root 'findings.csv')
    return @($report.Files | Where-Object { $_ -like '*.html' })[0]
}

function Find-PostureLatestRun {
    <#
    .SYNOPSIS
        The newest run Start-PostureRun made (a dated folder with run.json), for one client (-Client, a folder or the
        name of one under ~/tenantkeep/clients; or -TenantId) or across every client. Looks in each client's output
        root and in ~/tenantkeep/evidence. Returns $null when there is none.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string] $Client,
        [string] $TenantId,
        [string] $ClientsRoot = (Join-Path $HOME 'tenantkeep' 'clients')
    )

    $ErrorActionPreference = 'Stop'
    $clients = @()
    if ($Client) {
        $path = $(if (Test-Path -LiteralPath $Client -PathType Container) { $Client } else { Join-Path $ClientsRoot $Client })
        if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw "No client folder named $Client (looked for $path)." }
        $clients = @((Resolve-Path -LiteralPath $path).Path)
    }
    elseif ($TenantId) { $clients = @(Resolve-PostureClientFolder -TenantId $TenantId -ClientsRoot $ClientsRoot) }
    elseif (Test-Path -LiteralPath $ClientsRoot -PathType Container) { $clients = @(Get-ChildItem -LiteralPath $ClientsRoot -Directory | ForEach-Object { $_.FullName }) }

    $roots = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($c in $clients) { $null = $roots.Add((Get-PostureOutputRoot -Client $c)) }
    if (-not $Client -and -not $TenantId) { $null = $roots.Add((Get-PostureOutputRoot)) }
    $best = $null
    foreach ($root in $roots) {
        foreach ($run in Get-PostureRunInfo -Root $root) {
            if (-not $run.plan) { continue }
            if ($clients.Count -gt 0 -and ($Client -or $TenantId) -and $run.client -ne $clients[0] -and -not ($TenantId -and $run.tenantId -eq $TenantId)) { continue }
            if (-not $best -or $run.started -gt $best.started) { $best = $run }
        }
    }
    return $(if ($best) { $best.path } else { $null })
}

function Get-PosturePreviousRun {
    <#
    .SYNOPSIS
        The checks.json of the newest run before -Run in the same output folder, of the same tenant when both say,
        for the report's trend. $null when there is none.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Run)

    $ErrorActionPreference = 'Stop'
    $root = (Get-PostureRunLayout -Folder $Run).root
    $all = @(Get-PostureRunInfo -Root (Split-Path $root -Parent))
    $me = @($all | Where-Object { $_.path -eq $root })[0]
    foreach ($r in $all) {
        if ($r.path -eq $root -or -not $r.checks) { continue }
        if ($me -and $r.started -ge $me.started) { continue }
        if ($me -and $me.tenantId -and $r.tenantId -and $r.tenantId -ne $me.tenantId) { continue }
        return $r.checks
    }
    return $null
}

function Get-PostureScoreHistory {
    <#
    .SYNOPSIS
        The posture score of each earlier run of the same tenant in the same output folder, oldest first, up to
        -Last of them, scored from their checks.json with the report's weights (Critical 4, High 3, Medium 2, Low 1;
        accepted risk counts as a pass). For the trend line; the current run is the caller's to add.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [string] $Run, [int] $Last = 11)

    $ErrorActionPreference = 'Stop'
    $root = (Get-PostureRunLayout -Folder $Run).root
    $parent = Split-Path $root -Parent
    if (-not $parent -or -not (Test-Path -LiteralPath $parent -PathType Container)) { return @() }
    $all = @(Get-PostureRunInfo -Root $parent)
    $me = @($all | Where-Object { $_.path -eq $root })[0]
    $weight = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }
    $earlier = @($all | Where-Object { $_.path -ne $root -and $_.checks -and (-not $me -or $_.started -lt $me.started) -and (-not $me -or -not $me.tenantId -or -not $_.tenantId -or $_.tenantId -eq $me.tenantId) } | Select-Object -First $Last)
    $points = foreach ($r in $earlier) {
        $doc = $(try { Get-Content -Raw -LiteralPath $r.checks | ConvertFrom-Json -AsHashtable -Depth 20 } catch { $null })
        if (-not $doc -or -not $doc.Contains('results')) { continue }
        $e = 0; $p = 0
        foreach ($x in @($doc['results'] | Where-Object { $_ -and [string]$_['status'] -in 'pass', 'fail', 'acceptedRisk' })) { $w = $weight[[string]$x['severity']]; if (-not $w) { $w = 1 }; $p += $w; if ([string]$x['status'] -ne 'fail') { $e += $w } }
        if ($p -gt 0) { [ordered]@{ label = $(if ($r.started) { ([datetime]$r.started).ToString('yyyy-MM-dd') } else { Split-Path $r.path -Leaf }); value = [Math]::Round(100.0 * $e / $p) } }
    }
    return @(@($points) | Sort-Object { $_.label })
}
