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

function Import-PostureLayerSet {
    <#
    .SYNOPSIS
        Loads checks/layers.json: defence-in-depth sets, each an ordered stack of layers made of catalog checks.
        Every check named must be in the catalog.
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
        $Path = Join-Path ([string]$Catalog['path']) 'layers.json'
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    $doc = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -AsHashtable -Depth 10
    $known = @{}; foreach ($c in $Catalog.checks) { $known[[string]$c['id']] = $true }
    $sets = foreach ($set in @($doc['sets'])) {
        $id = [string]$set['id']
        if ($id -notmatch '^LY-\d{3}$') { throw "layers.json: set id '$id' must look like LY-001" }
        if (@($set['layers']).Count -lt 2) { throw "layers.json: set '$id' needs at least two layers" }
        foreach ($l in @($set['layers'])) {
            if (@($l['checks']).Count -eq 0) { throw "layers.json: set '$id' layer '$($l['name'])' names no checks" }
            foreach ($c in @($l['checks'])) { if (-not $known.ContainsKey([string]$c)) { throw "layers.json: set '$id' names '$c', which is not in the catalog" } }
        }
        [ordered]@{ id = $id; name = [string]$set['name']; domain = [string]$set['domain']; layers = @($set['layers'] | ForEach-Object { [ordered]@{ name = [string]$_['name']; checks = @($_['checks'] | ForEach-Object { [string]$_ }) } }) }
    }
    return @($sets)
}

function Get-PostureLayerSetResult {
    <#
    .SYNOPSIS
        Judges each layer from a run's results: passed and total count the evaluated checks (pass, accepted or
        covered hold; fail does not); holds, partial, missing, or not applicable when none could be judged. A set
        with no layer that applies is left out.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $LayerSet,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Result
    )

    $ErrorActionPreference = 'Stop'
    $byId = @{}; foreach ($r in $Result) { $byId[[string]$r.id] = $r }
    $holds = 'pass', 'acceptedRisk', 'coveredBy'
    $out = foreach ($set in $LayerSet) {
        $layers = @($set.layers | ForEach-Object {
                $judged = @($_.checks | Where-Object { $byId.ContainsKey($_) -and [string]$byId[$_].status -in @($holds + 'fail') })
                $passed = @($judged | Where-Object { [string]$byId[$_].status -in $holds }).Count
                $status = $(if ($judged.Count -eq 0) { 'na' } elseif ($passed -eq $judged.Count) { 'pass' } elseif ($passed -eq 0) { 'fail' } else { 'partial' })
                [ordered]@{ label = $_.name; passed = $passed; total = $judged.Count; status = $status; checks = @($_.checks) }
            })
        $live = @($layers | Where-Object { $_.status -ne 'na' })
        if ($live.Count -eq 0) { continue }
        $hold = @($live | Where-Object { $_.status -eq 'pass' }).Count
        $worst = @($live | Where-Object { $_.status -eq 'fail' } | Select-Object -First 1)
        [ordered]@{
            id = $set.id; name = $set.name; domain = $set.domain; layers = $layers
            takeaway = "$hold of $($live.Count) layers hold$(if ($worst.Count) { "; the $($worst[0].label.Split(':')[0].ToLowerInvariant()) layer is missing" })."
        }
    }
    return @($out)
}
