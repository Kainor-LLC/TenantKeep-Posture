# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureAttackTechnique {
    <#
    .SYNOPSIS
        A check's MITRE ATT&CK technique ids with the name, tactic names and link from checks/attack.json. An id the
        file lacks (a custom check) comes back with the id as its name and MITRE's link.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Catalog,
        [Parameter()] [AllowNull()] [System.Collections.IDictionary] $Check
    )

    $ErrorActionPreference = 'Stop'
    if (-not $Check -or -not $Check.Contains('attack')) { return }
    $known = @{}; $tacticName = @{}
    if ($Catalog.Contains('attack') -and $Catalog['attack']) {
        $known = $Catalog['attack']['techniques']
        foreach ($ta in @($Catalog['attack']['tactics'])) { $tacticName[[string]$ta['key']] = [string]$ta['name'] }
    }
    foreach ($id in @($Check['attack'])) {
        $id = [string]$id
        $t = $(if ($known.Contains($id)) { $known[$id] } else { $null })
        [ordered]@{
            id      = $id
            name    = $(if ($t) { [string]$t['name'] } else { $id })
            tactics = @($(if ($t) { @($t['tactics']) | ForEach-Object { $(if ($tacticName.ContainsKey([string]$_)) { $tacticName[[string]$_] } else { [string]$_ }) } }))
            url     = $(if ($t) { [string]$t['url'] } else { "https://attack.mitre.org/techniques/$($id.Replace('.', '/'))/" })
        }
    }
}

function Get-PostureAttackCoverage {
    <#
    .SYNOPSIS
        The run seen through MITRE ATT&CK: for each tactic, the techniques the evaluated checks address and how they
        stand. A technique is a gap when a check for it fails, accepted when the only misses are accepted risks,
        covered when its checks pass (or another product covers them per the profile) and unchecked when none was
        evaluated. Checks the profile rules out (notApplicable: no on-premises AD, no Azure) are left out, so a
        cloud-only tenant is not shown Kerberos techniques. A technique under several tactics appears under each, as in
        MITRE's matrix.
    .OUTPUTS
        $null when the catalog has no attack.json or no evaluated check names a technique.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Catalog,
        [Parameter()] [AllowEmptyCollection()] [object[]] $Result = @()
    )

    $ErrorActionPreference = 'Stop'
    if (-not $Catalog.Contains('attack') -or -not $Catalog['attack']) { return $null }
    $attack = $Catalog['attack']
    $byId = @{}; foreach ($c in $Catalog.checks) { $byId[[string]$c['id']] = $c }

    # Technique id to the checks that name it, in check order.
    $checksOf = [ordered]@{}
    foreach ($r in @($Result | Where-Object { $_.status -ne 'notApplicable' } | Sort-Object { $_.id })) {
        foreach ($t in @(Get-PostureAttackTechnique -Catalog $Catalog -Check $byId[[string]$r.id])) {
            if (-not $checksOf.Contains($t.id)) { $checksOf[$t.id] = [System.Collections.Generic.List[object]]::new() }
            $checksOf[$t.id].Add([ordered]@{ id = [string]$r.id; title = [string]$r.title; status = [string]$r.status; severity = [string]$r.severity })
        }
    }

    $standing = {
        param($checks)
        $s = @($checks | ForEach-Object { $_.status })
        if ($s -contains 'fail') { 'gap' } elseif ($s -contains 'acceptedRisk') { 'accepted' } elseif (@($s | Where-Object { $_ -in 'pass', 'coveredBy' }).Count) { 'covered' } else { 'unchecked' }
    }
    $technique = @{}
    # A technique attack.json lacks (a custom check's) has no tactic to sit under, so the matrix leaves it out.
    foreach ($id in @($checksOf.Keys | Where-Object { $attack['techniques'].Contains($_) })) {
        $t = $attack['techniques'][$id]
        $list = @($checksOf[$id])
        $technique[$id] = [ordered]@{
            id = $id; name = [string]$t['name']; url = [string]$t['url']
            status = (& $standing $list); pass = @($list | Where-Object { $_.status -in 'pass', 'coveredBy' }).Count; checks = $list
        }
    }
    if ($technique.Count -eq 0) { return $null }
    $rank = @{ gap = 0; accepted = 1; covered = 2; unchecked = 3 }
    $tactics = foreach ($ta in @($attack['tactics'])) {
        $here = @($technique.Values | Where-Object { @($attack['techniques'][$_.id]['tactics']) -contains [string]$ta['key'] } | Sort-Object { $rank[$_.status] }, { $_.id })
        if (-not $here.Count) { continue }
        $counts = [ordered]@{}; foreach ($k in 'covered', 'accepted', 'gap', 'unchecked') { $counts[$k] = @($here | Where-Object { $_.status -eq $k }).Count }
        [ordered]@{ id = [string]$ta['id']; key = [string]$ta['key']; name = [string]$ta['name']; counts = $counts; techniques = $here }
    }
    $totals = [ordered]@{}; foreach ($k in 'covered', 'accepted', 'gap', 'unchecked') { $totals[$k] = @($technique.Values | Where-Object { $_.status -eq $k }).Count }
    return [ordered]@{
        version    = [string]$attack['version']
        notice     = [string]$attack['notice']
        techniques = $technique.Count
        totals     = $totals
        tactics    = @($tactics)
    }
}
