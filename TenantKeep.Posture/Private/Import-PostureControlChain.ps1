# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Import-PostureControlChain {
    <#
    .SYNOPSIS
        Loads checks/chains.json: control chains, each an ordered list of checks that protect only together.
        Every link must name a check in the catalog, so a chain ships with its checks.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Catalog,
        [string] $Path
    )

    $ErrorActionPreference = 'Stop'
    if (-not $Path) {
        if (-not $Catalog.Contains('path') -or -not $Catalog['path']) { return @() }
        $Path = Join-Path ([string]$Catalog['path']) 'chains.json'
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    $doc = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -AsHashtable -Depth 10
    $known = @{}; foreach ($c in $Catalog.checks) { $known[[string]$c['id']] = $true }
    $seen = @{}
    $chains = foreach ($ch in @($doc['chains'])) {
        $id = [string]$ch['id']
        if ($id -notmatch '^CH-\d{3}$') { throw "chains.json: chain id '$id' must look like CH-001" }
        if ($seen.ContainsKey($id)) { throw "chains.json: duplicate chain id '$id'" }
        $seen[$id] = $true
        foreach ($k in 'name', 'why') { if ([string]::IsNullOrWhiteSpace([string]$ch[$k])) { throw "chains.json: chain '$id' has no $k" } }
        $links = @($ch['links'])
        if ($links.Count -lt 2) { throw "chains.json: chain '$id' needs at least two links" }
        foreach ($l in $links) {
            if (-not $known.ContainsKey([string]$l['check'])) { throw "chains.json: chain '$id' links to '$($l['check'])', which is not in the catalog" }
            if ([string]::IsNullOrWhiteSpace([string]$l['role'])) { throw "chains.json: chain '$id' link '$($l['check'])' has no role" }
        }
        [ordered]@{ id = $id; name = [string]$ch['name']; why = [string]$ch['why']; links = @($links | ForEach-Object { [ordered]@{ check = [string]$_['check']; role = [string]$_['role'] } }) }
    }
    return @($chains)
}

function Get-PostureControlChainResult {
    <#
    .SYNOPSIS
        Judges each chain against a run's results: pass when every link holds (pass, accepted risk, covered by a
        third party), broken at the first failing link, not evaluated while a link could not be judged or was not
        in the run. A chain none of whose links applies to this run (not applicable, or outside the baseline) is
        left out.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Chain,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Result
    )

    $ErrorActionPreference = 'Stop'
    $byId = @{}; foreach ($r in $Result) { $byId[[string]$r.id] = $r }
    $holds = 'pass', 'acceptedRisk', 'coveredBy'
    $out = foreach ($ch in $Chain) {
        $links = @($ch.links | ForEach-Object {
                $r = $byId[$_.check]
                [ordered]@{ check = $_.check; role = $_.role; title = $(if ($r) { [string]$r.title } else { $_.check }); status = $(if ($r) { [string]$r.status } else { 'notEvaluated' }); severity = $(if ($r) { [string]$r.severity } else { $null }) }
            })
        if (@($ch.links | Where-Object { $byId.ContainsKey($_.check) -and [string]$byId[$_.check].status -ne 'notApplicable' }).Count -eq 0) { continue }
        $broken = @($links | Where-Object { $_.status -eq 'fail' } | Select-Object -First 1)
        $open = @($links | Where-Object { $_.status -notin $holds -and $_.status -ne 'fail' })
        $status = $(if ($broken.Count) { 'broken' } elseif ($open.Count) { 'notEvaluated' } else { 'pass' })
        [ordered]@{
            id = $ch.id; name = $ch.name; why = $ch.why; status = $status; links = $links
            brokenAt = $(if ($broken.Count) { $broken[0].check } else { $null })
            held = @($links | Where-Object { $_.status -in $holds }).Count
        }
    }
    return @($out)
}
