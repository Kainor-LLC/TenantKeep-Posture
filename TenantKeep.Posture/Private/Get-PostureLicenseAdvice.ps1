# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureLicenseAdvice {
    <#
    .SYNOPSIS
        The licensing advisor: every feature owned, partly assigned or missing; every goal met or what it lacks; and
        for the chosen goals, options side by side: add-ons on top of what the tenant owns, and suite upgrades with
        the fewest add-ons they still need, each with what it adds, what is redundant (a vendor already covers it) and
        what else it includes (Power BI, Teams Phone).
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
        [int] $LicensedUsers = 0,
        # The profile's thirdParty: category to vendor ('none' or empty means none). A feature whose coveredBy names a
        # category with a vendor counts as covered for goals and as redundant in a bundle.
        [System.Collections.IDictionary] $ThirdParty = @{}
    )

    $ErrorActionPreference = 'Stop'
    $data = Get-PostureLicensingData
    $owned = [System.Collections.Generic.HashSet[string]]::new([string[]]@($Owned))
    $vendorOf = @{}
    foreach ($f in $data.features.Values) {
        if ($f.Contains('coveredBy') -and $ThirdParty.Contains([string]$f.coveredBy)) { $vn = [string]$ThirdParty[[string]$f.coveredBy]; if ($vn -and $vn -ne 'none') { $vendorOf[[string]$f.id] = $vn } }
    }
    $have = [System.Collections.Generic.HashSet[string]]::new([string[]]@(@($Owned) + @($vendorOf.Keys)))
    $nameOf = { param([string] $id) [string]$data.features[$id].name }
    $isSecurity = { param([string] $id) $f = $data.features[$id]; -not $f.Contains('kind') -or [string]$f.kind -ne 'value' }

    # Features: owned, partly assigned (bought but switched on for fewer people than hold a licence), covered by a
    # vendor, or missing.
    $featureRows = foreach ($f in $data.features.Values) {
        $users = $null
        if ($LicensedUsers -gt 0 -and @($f.plans).Count) { $users = [int](@($f.plans | ForEach-Object { if ($UsersByPlan.Contains([string]$_)) { [int]$UsersByPlan[[string]$_] } else { 0 } }) | Measure-Object -Maximum).Maximum }
        $status = $(if ($owned.Contains([string]$f.id)) { if ($null -ne $users -and $users -lt $LicensedUsers) { 'partial' } else { 'owned' } } elseif ($vendorOf.ContainsKey([string]$f.id)) { 'covered' } else { 'missing' })
        [ordered]@{ id = $f.id; name = $f.name; what = $f.what; kind = $(if (& $isSecurity $f.id) { 'security' } else { 'value' }); status = $status; vendor = $(if ($vendorOf.ContainsKey([string]$f.id)) { $vendorOf[[string]$f.id] } else { $null }); users = $users; licensedUsers = $(if ($LicensedUsers -gt 0) { $LicensedUsers } else { $null }) }
    }

    # Goals: met when every group has a feature owned or covered by a vendor.
    # The leading comma keeps a list of groups a list: with one unmet group, a plain return would unroll it into that
    # group's features.
    $unmetOf = { param($g, $set) , @(@($g.needs) | Where-Object { @($_ | Where-Object { $set.Contains([string]$_) }).Count -eq 0 }) }
    $goalRows = foreach ($g in $data.goals) {
        $gaps = & $unmetOf $g $have
        [ordered]@{ id = $g.id; name = $g.name; what = $g.what; core = [bool]$g.core; met = ($gaps.Count -eq 0); missing = @($gaps | ForEach-Object { , @($_ | ForEach-Object { & $nameOf $_ }) }) }
    }

    $chosen = @($(if ($Goal.Count) { $data.goals | Where-Object { $_.id -in $Goal } } else { $data.goals | Where-Object { $_.core } }))
    # A loop, not a pipeline: each group is itself a list, and the pipeline would either flatten it or nest it.
    $groupList = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $chosen) { foreach ($grp in (& $unmetOf $g $have)) { $groupList.Add(@($grp)) } }
    $groups = $groupList.ToArray()
    $fits = { param($b) -not ($b.Contains('seatCap') -and $Seats -gt [int]$b.seatCap) }
    # Every chosen goal's groups, met or not: a suite replaces the current one, so it must cover them all itself.
    $allList = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $chosen) { foreach ($grp in @($g.needs)) { $allList.Add(@($grp)) } }
    $allGroups = $allList.ToArray()
    $coversAll = {
        param($base, $bundles, $need)
        $set = [System.Collections.Generic.HashSet[string]]::new([string[]]@(@($base) + @($bundles | ForEach-Object { @($_.features) })))
        @($need | Where-Object { @($_ | Where-Object { $set.Contains([string]$_) }).Count -eq 0 }).Count -eq 0
    }
    # The fewest add-ons (0 to -Max) that close every gap on top of -Base; on a tie the smallest purchase, then the
    # bundle made for a business of this size.
    $search = {
        param($base, [int] $max, [bool] $noRedundant = $false, $need = $groups)
        $baseSet = [System.Collections.Generic.HashSet[string]]::new([string[]]@($base))
        $cands = @($data.bundles | Where-Object { $_.kind -eq 'addon' -and (& $fits $_) -and @($_.features | Where-Object { -not $baseSet.Contains([string]$_) -and (& $isSecurity $_) }).Count })
        # Optionally only add-ons that bring nothing a vendor already covers (P2 and ID Governance rather than Entra
        # Suite when another product does Global Secure Access's job).
        if ($noRedundant) { $cands = @($cands | Where-Object { @($_.features | Where-Object { $vendorOf.ContainsKey([string]$_) -and -not $owned.Contains([string]$_) }).Count -eq 0 }) }
        if (& $coversAll $base @() $need) { return , @() }
        foreach ($size in 1..$max) {
            # @( ) keeps a lone pair a pair; $( ) would unroll it.
            $combos = @(switch ($size) {
                    1 { foreach ($a in $cands) { , @($a) } }
                    2 { for ($i = 0; $i -lt $cands.Count; $i++) { for ($j = $i + 1; $j -lt $cands.Count; $j++) { , @($cands[$i], $cands[$j]) } } }
                    3 { for ($i = 0; $i -lt $cands.Count; $i++) { for ($j = $i + 1; $j -lt $cands.Count; $j++) { for ($k = $j + 1; $k -lt $cands.Count; $k++) { , @($cands[$i], $cands[$j], $cands[$k]) } } } }
                })
            $ok = @($combos | Where-Object { & $coversAll $base $_ $need } | Sort-Object { @($_ | ForEach-Object { $_.features } | Sort-Object -Unique).Count }, { @($_ | Where-Object { -not $_.Contains('seatCap') }).Count }, { (@($_ | ForEach-Object { $_.sku }) -join ',') })
            if ($ok.Count) { return , @($ok[0]) }
        }
        return $null
    }
    $describe = {
        param([string] $Kind, [string] $Title, $Skus)
        $brought = [System.Collections.Generic.HashSet[string]]::new([string[]]@($Skus | ForEach-Object { @($_.features) }))
        [ordered]@{
            kind         = $Kind
            title        = $Title
            skus         = @($Skus | ForEach-Object { [ordered]@{ sku = $_.sku; name = $_.name; verify = $(if ($_.Contains('verify')) { $_.verify } else { $null }) } })
            adds         = @($data.features.Keys | Where-Object { $brought.Contains($_) -and -not $owned.Contains($_) -and -not $vendorOf.ContainsKey($_) -and (& $isSecurity $_) } | ForEach-Object { & $nameOf $_ })
            redundant    = @($data.features.Keys | Where-Object { $brought.Contains($_) -and -not $owned.Contains($_) -and $vendorOf.ContainsKey($_) } | ForEach-Object { [ordered]@{ name = (& $nameOf $_); vendor = $vendorOf[$_] } })
            alsoIncludes = @($data.features.Keys | Where-Object { $brought.Contains($_) -and -not $owned.Contains($_) -and -not (& $isSecurity $_) } | ForEach-Object { & $nameOf $_ })
        }
    }
    $options = [System.Collections.Generic.List[object]]::new()
    if ($groups.Count) {
        $addOnly = & $search @($have) 3
        if ($addOnly) { $options.Add((& $describe 'addons' 'Add to what you have' @($addOnly))) }
        if ($vendorOf.Count) {
            $lean = & $search @($have) 3 $true
            if ($lean -and ((@($lean | ForEach-Object { $_.sku }) -join ',') -ne (@($addOnly | ForEach-Object { $_.sku }) -join ','))) { $options.Add((& $describe 'addons' 'Add only what your other products do not already cover' @($lean))) }
        }
        # A suite in place of the current one, with the fewest add-ons it still needs (E5 + ID Governance). Suites
        # that bring nothing the tenant lacks are not upgrades.
        $suiteOpts = foreach ($s in @($data.bundles | Where-Object { $_.kind -eq 'suite' -and (& $fits $_) })) {
            if (@($s.features | Where-Object { -not $owned.Contains([string]$_) -and (& $isSecurity $_) }).Count -eq 0) { continue }
            $base = @(@($s.features) + @($vendorOf.Keys))
            $extra = & $search $base 2 $false $allGroups
            if ($null -eq $extra) { continue }
            @{ suite = $s; extra = @($extra); n = @($extra).Count; size = @($s.features).Count }
        }
        foreach ($so in @($suiteOpts | Sort-Object { $_.n }, { $_.size } | Select-Object -First 2)) {
            $title = 'Move to ' + $so.suite.name + $(if ($so.n) { ' with ' + (@($so.extra | ForEach-Object { $_.name }) -join ' and ') } else { '' })
            $options.Add((& $describe 'suite' $title @(@($so.suite) + @($so.extra))))
        }
    }
    # A feature an option brings that needs another the tenant lacks (ID Governance needs Entra ID P1).
    $prereq = @($options | ForEach-Object { $_.skus } | ForEach-Object { $sk = $_.sku; @($data.bundles | Where-Object { $_.sku -eq $sk })[0].features } | ForEach-Object { $f = $data.features[[string]$_]; if ($f.Contains('requires')) { @($f.requires | Where-Object { -not $have.Contains([string]$_) } | ForEach-Object { "$($f.name) needs $(& $nameOf $_)." }) } } | Sort-Object -Unique)

    return [ordered]@{
        features = @($featureRows)
        goals    = @($goalRows)
        advice   = [ordered]@{
            goals        = @($chosen | ForEach-Object { $_.id })
            goalSource   = $(if ($Goal.Count) { 'profile' } else { 'core' })
            met          = ($groups.Count -eq 0)
            missing      = @($groups | ForEach-Object { , @($_ | ForEach-Object { & $nameOf $_ }) })
            options      = @($options)
            vendors      = $vendorOf
            prerequisite = $prereq
            seats        = $Seats
            note         = 'Licences and bundles to compare, not licensing advice and not prices: take the options to your Microsoft partner. Eligibility and bundles change, and some add-ons need a base licence.'
        }
        reviewed = $data.reviewed
    }
}
