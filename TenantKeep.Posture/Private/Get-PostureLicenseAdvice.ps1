# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureLicenseAdvice {
    <#
    .SYNOPSIS
        The licensing advisor: every feature owned, partly assigned or missing; every goal met or what it lacks; and
        for the chosen goals, the fewest add-ons on top of what the tenant owns and the one bundle that covers it.
    .DESCRIPTION
        Reads licensing/features.json, bundles.json and goals.json (Get-PostureLicensingData). No prices: the answer
        is a starting point to take to a Microsoft partner. Goals: the profile's, else the core goals. Seats: the
        enabled licensed users. A bundle with a seat cap below that is not offered. Add-ons are searched exactly up
        to three at a time, which covers every goal set in goals.json.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Owned,
        [string[]] $Goal = @(),
        [int] $Seats = 0,
        [System.Collections.IDictionary] $UsersByPlan = @{},
        [int] $LicensedUsers = 0
    )

    $ErrorActionPreference = 'Stop'
    $data = Get-PostureLicensingData
    $have = [System.Collections.Generic.HashSet[string]]::new([string[]]@($Owned))

    # Features: owned, partly assigned (bought but switched on for only some licensed users), or missing.
    $featureRows = foreach ($f in $data.features.Values) {
        $users = $null
        if ($LicensedUsers -gt 0 -and @($f.plans).Count) { $users = [int](@($f.plans | ForEach-Object { if ($UsersByPlan.Contains([string]$_)) { [int]$UsersByPlan[[string]$_] } else { 0 } }) | Measure-Object -Maximum).Maximum }
        $status = $(if (-not $have.Contains([string]$f.id)) { 'missing' } elseif ($null -ne $users -and $users -lt $LicensedUsers) { 'partial' } else { 'owned' })
        [ordered]@{ id = $f.id; name = $f.name; what = $f.what; status = $status; users = $users; licensedUsers = $(if ($LicensedUsers -gt 0) { $LicensedUsers } else { $null }) }
    }

    # Goals: met when every group has a feature the tenant owns.
    $goalRows = foreach ($g in $data.goals) {
        $gaps = @(@($g.needs) | Where-Object { @($_ | Where-Object { $have.Contains([string]$_) }).Count -eq 0 })
        [ordered]@{ id = $g.id; name = $g.name; what = $g.what; core = [bool]$g.core; met = ($gaps.Count -eq 0); missing = @($gaps | ForEach-Object { , @($_ | ForEach-Object { $data.features[[string]$_].name }) }) }
    }

    $chosen = @($(if ($Goal.Count) { $data.goals | Where-Object { $_.id -in $Goal } } else { $data.goals | Where-Object { $_.core } }))
    $groups = @($chosen | ForEach-Object { @($_.needs) } | Where-Object { @($_ | Where-Object { $have.Contains([string]$_) }).Count -eq 0 })
    $fits = { param($b) -not ($b.Contains('seatCap') -and $Seats -gt [int]$b.seatCap) }
    $covers = {
        param([string[]] $extra)
        $all = [System.Collections.Generic.HashSet[string]]::new([string[]]@(@($Owned) + @($extra)))
        @($groups | Where-Object { @($_ | Where-Object { $all.Contains([string]$_) }).Count -eq 0 }).Count -eq 0
    }
    $addOns = @(); $upgrade = $null
    if ($groups.Count) {
        $cands = @($data.bundles | Where-Object { $_.kind -eq 'addon' -and (& $fits $_) -and @($_.features | Where-Object { -not $have.Contains([string]$_) }).Count })
        $best = $null
        :search foreach ($size in 1..3) {
            # @( ) keeps a lone pair a pair; $( ) would unroll it into two add-ons.
            $combos = @(switch ($size) {
                    1 { foreach ($a in $cands) { , @($a) } }
                    2 { for ($i = 0; $i -lt $cands.Count; $i++) { for ($j = $i + 1; $j -lt $cands.Count; $j++) { , @($cands[$i], $cands[$j]) } } }
                    3 { for ($i = 0; $i -lt $cands.Count; $i++) { for ($j = $i + 1; $j -lt $cands.Count; $j++) { for ($k = $j + 1; $k -lt $cands.Count; $k++) { , @($cands[$i], $cands[$j], $cands[$k]) } } } }
                })
            # Among the sets that cover, the one adding the fewest features: the smallest purchase that does the job.
            # On a tie, the bundle made for a business of this size (it has a seat cap the tenant fits under).
            $ok = @($combos | Where-Object { & $covers @($_ | ForEach-Object { $_.features }) } | Sort-Object { @($_ | ForEach-Object { $_.features } | Sort-Object -Unique).Count }, { @($_ | Where-Object { -not $_.Contains('seatCap') }).Count })
            if ($ok.Count) { $best = $ok[0]; break search }
        }
        if ($best) { $addOns = @($best | ForEach-Object { [ordered]@{ sku = $_.sku; name = $_.name; adds = @($_.features | Where-Object { -not $have.Contains([string]$_) } | ForEach-Object { $data.features[[string]$_].name }); verify = $(if ($_.Contains('verify')) { $_.verify } else { $null }) } }) }
        # An upgrade replaces the current suite, so it must cover the chosen goals on its own.
        $allGroups = @($chosen | ForEach-Object { @($_.needs) })
        $suites = @($data.bundles | Where-Object { $_.kind -eq 'suite' -and (& $fits $_) } | Where-Object { $sf = @($_.features); @($allGroups | Where-Object { @($_ | Where-Object { $_ -in $sf }).Count -eq 0 }).Count -eq 0 } | Sort-Object { @($_.features).Count })
        if ($suites.Count) { $upgrade = [ordered]@{ sku = $suites[0].sku; name = $suites[0].name } }
    }
    # A feature an add-on brings that needs another the tenant lacks (ID Governance needs Entra ID P1).
    $prereq = @($addOns | ForEach-Object { $_ } | ForEach-Object { $b = $_; @($data.bundles | Where-Object { $_.sku -eq $b.sku })[0].features } | ForEach-Object { $f = $data.features[[string]$_]; if ($f.Contains('requires')) { @($f.requires | Where-Object { -not $have.Contains([string]$_) } | ForEach-Object { "$($f.name) needs $($data.features[[string]$_].name)." }) } } | Sort-Object -Unique)

    return [ordered]@{
        features = @($featureRows)
        goals    = @($goalRows)
        advice   = [ordered]@{
            goals        = @($chosen | ForEach-Object { $_.id })
            goalSource   = $(if ($Goal.Count) { 'profile' } else { 'core' })
            met          = ($groups.Count -eq 0)
            missing      = @($groups | ForEach-Object { , @($_ | ForEach-Object { $data.features[[string]$_].name }) })
            addOns       = $addOns
            upgrade      = $upgrade
            prerequisite = $prereq
            seats        = $Seats
            note         = 'A starting point to take to your Microsoft partner, not licensing advice: eligibility, prices and bundles change, and some add-ons need a base licence.'
        }
        reviewed = $data.reviewed
    }
}
