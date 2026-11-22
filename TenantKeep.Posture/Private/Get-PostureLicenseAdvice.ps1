# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureLicenseAdvice {
    <#
    .SYNOPSIS
        The licensing advisor: every feature owned, partly assigned or missing; every goal met or what it lacks; and
        for the chosen goals one recommended combination of licences, with the reason each licence is in it, what it
        replaces, what overlaps with a product the tenant already uses, and which licences held today overlap.
    .DESCRIPTION
        Reads licensing/features.json, bundles.json and goals.json (Get-PostureLicensingData): what each licence
        includes, what it needs first, and what each goal needs. Goals: the profile's, else the core goals. Seats:
        the enabled licensed users. A bundle with a seat cap below that is not considered.

        Two steps. First every combination that works is built from the rules alone: add-ons on top of what the
        tenant holds (and, when another product covers a category, add-ons that bring nothing that product already
        does), and each suite that could take the current one's place with the add-ons it still needs. A combination
        works when it covers every chosen goal, brings what its own licences need first (ID Governance needs Entra ID
        P1), and takes away no goal the tenant meets today. Then one is chosen:

        - Without -Price, on function alone: the fewest licences, then keeping the suite the tenant holds, then the
          least overlap with other products, then the order of bundles.json.
        - With -Price (a price for a user per licence, from the report owner's own price file), the lowest total,
          then the same order. Only when every licence in the comparison has a price; one missing puts the whole
          choice back on function, so a recommendation never rests on half a comparison.

        Nothing about price leaves this function. The answer names licences and what they cover; it carries no
        price, no total, no rank and no other combination. -Record receives how the choice was made (which of the
        two ways, and the licences that had no price), for the person running the report and never for the report.
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
        # category with a vendor counts as covered for goals and as overlapping in a combination.
        [System.Collections.IDictionary] $ThirdParty = @{},
        # The SKU part numbers the tenant holds: an add-on sold only on top of a base (the business suites on
        # Business Premium) is considered only when the base is held or is in the same combination.
        [string[]] $OwnedSku = @(),
        # SKU part number to the price for one user (Read-PosturePriceFile). Used to choose, never returned.
        [System.Collections.IDictionary] $Price = @{},
        # Filled with how the choice was made. For the console and a local file; the report never reads it.
        [System.Collections.IDictionary] $Record
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
    # Every chosen goal's groups, met or not, and those of every goal the tenant meets today: a suite replaces the
    # current one, so it must cover the chosen goals itself and must not take away a goal that is met now.
    $allList = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $chosen) { foreach ($grp in @($g.needs)) { $allList.Add(@($grp)) } }
    foreach ($g in $data.goals) { if ($g.id -notin @($chosen | ForEach-Object { $_.id }) -and (& $unmetOf $g $have).Count -eq 0) { foreach ($grp in @($g.needs)) { $allList.Add(@($grp)) } } }
    $allGroups = $allList.ToArray()

    # What the tenant holds now, as the advisor's own SKUs. The suite a move would replace is the one with the most
    # features; a companion suite (EMS beside Office 365) goes with it only when the new suite includes all of it.
    $isCompanion = { param($b) $b.Contains('companion') -and [bool]$b.companion }
    $heldBundles = @($data.bundles | Where-Object { [string]$_.sku -in $OwnedSku })
    $heldSuites = @($heldBundles | Where-Object { $_.kind -eq 'suite' -and -not (& $isCompanion $_) })
    $heldCompanions = @($heldBundles | Where-Object { $_.kind -eq 'suite' -and (& $isCompanion $_) })
    $heldAddons = @($heldBundles | Where-Object { $_.kind -eq 'addon' })
    $mainSuite = $null
    foreach ($b in $heldSuites) { if ($null -eq $mainSuite -or @($b.features).Count -gt @($mainSuite.features).Count) { $mainSuite = $b } }
    $candidateSuites = @($data.bundles | Where-Object { $_.kind -eq 'suite' -and -not (& $isCompanion $_) -and (& $fits $_) -and [string]$_.sku -notin $OwnedSku -and @($_.features | Where-Object { -not $owned.Contains([string]$_) -and (& $isSecurity $_) }).Count -gt 0 })

    # Is there a price for every licence the comparison can touch? The add-ons that could close a gap (or supply what
    # such an add-on needs first), the suites that could take the current one's place, and what the tenant holds.
    $usePrice = $false
    $withoutPrice = @()
    if ($groups.Count -and $null -ne $Price -and $Price.get_Count() -gt 0) {
        $wanted = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($grp in $allGroups) { foreach ($x in @($grp)) { $null = $wanted.Add([string]$x) } }
        $reach = @()
        do {
            $before = $wanted.Count
            # An add-on sold only on a base counts when that base is held or is a suite the tenant could move to.
            $bases = @(@($OwnedSku) + @($candidateSuites | ForEach-Object { [string]$_.sku }))
            $reach = @($data.bundles | Where-Object { $_.kind -eq 'addon' -and (& $fits $_) -and (-not $_.Contains('requiresBase') -or @($_.requiresBase | Where-Object { $_ -in $bases }).Count -gt 0) -and @($_.features | Where-Object { $wanted.Contains([string]$_) }).Count -gt 0 })
            foreach ($b in $reach) { foreach ($x in @($b.features)) { $f = $data.features[[string]$x]; if ($f.Contains('requires')) { foreach ($r in @($f.requires)) { $null = $wanted.Add([string]$r) } } } }
        } while ($wanted.Count -gt $before)
        $inPlay = @(@($reach) + @($candidateSuites) + @($heldBundles) | Where-Object { $_ })
        $withoutPrice = @($inPlay | Where-Object { -not $Price.Contains([string]$_.sku) -or $null -eq $Price[[string]$_.sku] } | ForEach-Object { [string]$_.name } | Select-Object -Unique)
        $usePrice = ($withoutPrice.Count -eq 0)
    }
    $priceOf = { param($b) if ($usePrice) { [decimal]$Price[[string]$b.sku] } else { [decimal]0 } }

    # Is cover $a better than $b? With prices the lower total; then, always: fewer licences, the smaller purchase,
    # the bundle made for a business of this size, the order of bundles.json. Spelt out, not sorted:
    # templates/licensing.js makes the same choice in the page, without the first line.
    $betterCover = {
        param($a, $b)
        if ($null -eq $b) { return $true }
        if ($usePrice -and $a.cost -ne $b.cost) { return $a.cost -lt $b.cost }
        if ($a.idx.Count -ne $b.idx.Count) { return $a.idx.Count -lt $b.idx.Count }
        if ($a.brings -ne $b.brings) { return $a.brings -lt $b.brings }
        if ($a.uncapped -ne $b.uncapped) { return $a.uncapped -lt $b.uncapped }
        for ($i = 0; $i -lt $a.idx.Count; $i++) { if ($a.idx[$i] -ne $b.idx[$i]) { return $a.idx[$i] -lt $b.idx[$i] } }
        return $false
    }
    # The add-ons that close every gap in -Need on top of -Base. Every way of covering the first open group is tried
    # in turn, so the answer is the best one and not the first found, however many add-ons it takes.
    $cover = {
        param($base, $need, [string[]] $skusHeld, [bool] $noRedundant = $false)
        $baseSet = [System.Collections.Generic.HashSet[string]]::new([string[]]@($base))
        $open = [System.Collections.Generic.List[object]]::new()
        foreach ($grp in $need) { $met = $false; foreach ($x in @($grp)) { if ($baseSet.Contains([string]$x)) { $met = $true; break } }; if (-not $met) { $open.Add(@($grp)) } }
        if ($open.Count -eq 0) { return @{ items = @(); cost = [decimal]0 } }
        $cands = [System.Collections.Generic.List[object]]::new()
        foreach ($b in $data.bundles) {
            if ($b.kind -ne 'addon' -or -not (& $fits $b)) { continue }
            if ($b.Contains('requiresBase') -and @($b.requiresBase | Where-Object { $_ -in $skusHeld }).Count -eq 0) { continue }
            if ($noRedundant -and @($b.features | Where-Object { $vendorOf.ContainsKey([string]$_) -and -not $owned.Contains([string]$_) }).Count) { continue }
            $hits = [bool[]]::new($open.Count); $any = $false
            for ($g = 0; $g -lt $open.Count; $g++) { foreach ($x in $open[$g]) { if (@($b.features) -contains [string]$x) { $hits[$g] = $true; $any = $true; break } } }
            if ($any) { $cands.Add(@{ bundle = $b; hits = $hits; price = (& $priceOf $b) }) }
        }
        $best = $null
        $seen = [System.Collections.Generic.HashSet[string]]::new()
        $stack = [System.Collections.Generic.Stack[object]]::new()
        $stack.Push(@{ idx = [int[]]@(); covered = [bool[]]::new($open.Count); cost = [decimal]0 })
        while ($stack.Count -gt 0) {
            $n = $stack.Pop()
            if ($best) { if ($usePrice) { if ($n.cost -gt $best.cost) { continue } } elseif ($n.idx.Count -gt $best.idx.Count) { continue } }
            $g = -1; for ($i = 0; $i -lt $open.Count; $i++) { if (-not $n.covered[$i]) { $g = $i; break } }
            if ($g -lt 0) {
                $n.brings = @($n.idx | ForEach-Object { @($cands[$_].bundle.features) } | Select-Object -Unique).Count
                $n.uncapped = @($n.idx | Where-Object { -not $cands[$_].bundle.Contains('seatCap') }).Count
                if (& $betterCover $n $best) { $best = $n }
                continue
            }
            for ($c = $cands.Count - 1; $c -ge 0; $c--) {
                if (-not $cands[$c].hits[$g] -or $n.idx -contains $c) { continue }
                $idx = [int[]]@(@($n.idx) + $c | Sort-Object)
                if (-not $seen.Add(($idx -join ','))) { continue }
                $covered = [bool[]]$n.covered.Clone()
                for ($i = 0; $i -lt $open.Count; $i++) { if ($cands[$c].hits[$i]) { $covered[$i] = $true } }
                $stack.Push(@{ idx = $idx; covered = $covered; cost = $n.cost + $cands[$c].price })
            }
        }
        if ($null -eq $best) { return $null }
        return @{ items = @($best.idx | ForEach-Object { $cands[$_].bundle }); cost = $best.cost }
    }
    # The same, with what the add-ons themselves need: a feature that requires another (ID Governance needs Entra ID
    # P1, the Intune Suite needs Intune) adds that to the gaps, and the search runs again.
    $coverAll = {
        param($base, $need, [string[]] $skusHeld, [bool] $noRedundant = $false)
        $needList = [System.Collections.Generic.List[object]]::new()
        foreach ($grp in $need) { $needList.Add(@($grp)) }
        $found = $null
        foreach ($round in 1..4) {
            $found = & $cover $base $needList.ToArray() $skusHeld $noRedundant
            if ($null -eq $found) { return $null }
            $set = [System.Collections.Generic.HashSet[string]]::new([string[]]@(@($base) + @($found.items | ForEach-Object { @($_.features) })))
            $lacking = [string[]]@($found.items | ForEach-Object { @($_.features) } | ForEach-Object { $f = $data.features[[string]$_]; if ($f.Contains('requires')) { @($f.requires) } } | Where-Object { $_ -and -not $set.Contains([string]$_) } | Select-Object -Unique)
            if ($lacking.Count -eq 0) { return $found }
            [Array]::Sort($lacking, [System.StringComparer]::Ordinal)
            foreach ($x in $lacking) { $needList.Add(@([string]$x)) }
        }
        return $found
    }
    $names = { param($list) $n = @($list | ForEach-Object { [string]$_.name }); if ($n.Count -le 1) { return ($n -join '') }; return (($n[0..($n.Count - 2)] -join ', ') + ' and ' + $n[-1]) }
    $overlapCount = { param($list) @($list | ForEach-Object { @($_.features) } | Select-Object -Unique | Where-Object { $vendorOf.ContainsKey([string]$_) -and -not $owned.Contains([string]$_) }).Count }

    # Step one: every combination that works. Step two: the one to recommend.
    $made = [System.Collections.Generic.List[object]]::new()
    $addPlan = {
        param([string] $Kind, $Suite, $Items, $Replaced, $Kept, [decimal] $Cost)
        $all = @(@($Suite) + @($Items) | Where-Object { $_ })
        $made.Add(@{ kind = $Kind; suite = $Suite; items = @($Items); replaced = @($Replaced | Where-Object { $_ }); kept = @($Kept | Where-Object { $_ }); cost = $Cost; count = $all.Count; kindOrder = $(if ($Kind -eq 'suite') { 1 } else { 0 }); overlap = (& $overlapCount $all); order = $made.Count })
    }
    if ($groups.Count) {
        $addOnly = & $coverAll @($have) $groups $OwnedSku $false
        if ($addOnly -and @($addOnly.items).Count) { & $addPlan 'addons' $null @($addOnly.items) @() @() $addOnly.cost }
        if ($vendorOf.Count) {
            $lean = & $coverAll @($have) $groups $OwnedSku $true
            if ($lean -and @($lean.items).Count -and ((@($lean.items | ForEach-Object { $_.sku }) -join ',') -ne (@($(if ($addOnly) { $addOnly.items }) | ForEach-Object { $_.sku }) -join ','))) { & $addPlan 'addons' $null @($lean.items) @() @() $lean.cost }
        }
        # A suite in place of the current one, with the add-ons it still needs.
        foreach ($s in $candidateSuites) {
            $suiteSet = [System.Collections.Generic.HashSet[string]]::new([string[]]@($s.features))
            # Held add-ons stay when the new suite still sells them and does not already include all they bring;
            # a held companion suite stays unless the new suite includes all of it.
            $kept = @($heldAddons | Where-Object { (-not $_.Contains('requiresBase') -or [string]$s.sku -in @($_.requiresBase)) -and @($_.features | Where-Object { -not $suiteSet.Contains([string]$_) }).Count -gt 0 })
            $keptCompanions = @($heldCompanions | Where-Object { @($_.features | Where-Object { -not $suiteSet.Contains([string]$_) }).Count -gt 0 })
            $replaced = @(@($mainSuite) + @($heldCompanions | Where-Object { $_ -notin $keptCompanions }) + @($heldAddons | Where-Object { $_ -notin $kept }) | Where-Object { $_ })
            $base = @(@($s.features) + @($vendorOf.Keys) + @($kept | ForEach-Object { @($_.features) }) + @($keptCompanions | ForEach-Object { @($_.features) }))
            $extra = & $coverAll $base $allGroups @(@([string]$s.sku) + @($kept | ForEach-Object { [string]$_.sku })) $false
            if ($null -eq $extra) { continue }
            $credit = [decimal]0; foreach ($r in $replaced) { $credit += (& $priceOf $r) }
            & $addPlan 'suite' $s @($extra.items) $replaced @(@($kept) + @($keptCompanions)) ((& $priceOf $s) + $extra.cost - $credit)
        }
    }
    $top = $null
    foreach ($m in $made) {
        $better = $(
            if ($null -eq $top) { $true }
            elseif ($usePrice -and $m.cost -ne $top.cost) { $m.cost -lt $top.cost }
            elseif ($m.count -ne $top.count) { $m.count -lt $top.count }
            elseif ($m.kindOrder -ne $top.kindOrder) { $m.kindOrder -lt $top.kindOrder }
            elseif ($m.overlap -ne $top.overlap) { $m.overlap -lt $top.overlap }
            else { $false })
        if ($better) { $top = $m }
    }

    # The recommendation, in terms of function only: each licence with the goals it is there for and what it brings.
    $recommended = $null
    $prereq = @()
    if ($top) {
        $all = @(@($top.suite) + @($top.items) | Where-Object { $_ })
        $brought = [System.Collections.Generic.HashSet[string]]::new([string[]]@($all | ForEach-Object { @($_.features) }))
        $licences = foreach ($b in $all) {
            $mine = [System.Collections.Generic.HashSet[string]]::new([string[]]@($b.features))
            $covers = @($chosen | Where-Object { @((& $unmetOf $_ $have) | Where-Object { @($_ | Where-Object { $mine.Contains([string]$_) }).Count -gt 0 }).Count -gt 0 } | ForEach-Object { [string]$_.name })
            # What another licence in the combination needs first and this one supplies.
            $neededBy = @($data.features.Values | Where-Object { $_.Contains('requires') -and $brought.Contains([string]$_.id) -and -not $mine.Contains([string]$_.id) -and @($_.requires | Where-Object { $mine.Contains([string]$_) -and -not $have.Contains([string]$_) }).Count -gt 0 } | ForEach-Object { [string]$_.name })
            [ordered]@{
                sku      = $b.sku
                name     = $b.name
                role     = $(if ($top.suite -and $b -eq $top.suite) { 'moveTo' } else { 'add' })
                verify   = $(if ($b.Contains('verify')) { $b.verify } else { $null })
                covers   = $covers
                brings   = @($data.features.Keys | Where-Object { $mine.Contains($_) -and -not $owned.Contains($_) -and -not $vendorOf.ContainsKey($_) -and (& $isSecurity $_) } | ForEach-Object { & $nameOf $_ })
                neededBy = $neededBy
            }
        }
        # What a move would leave behind: features of the licences it replaces that nothing in the new set brings.
        $after = [System.Collections.Generic.HashSet[string]]::new([string[]]@(@($brought) + @($top.kept | ForEach-Object { @($_.features) }) + @($heldBundles | Where-Object { $_ -notin $top.replaced } | ForEach-Object { @($_.features) })))
        $recommended = [ordered]@{
            kind         = $top.kind
            title        = $(if ($top.kind -eq 'suite') { 'Move to ' + [string]$top.suite.name + $(if (@($top.items).Count) { ' with ' + (& $names $top.items) } else { '' }) } else { 'Add ' + (& $names $top.items) + $(if ($mainSuite) { ' to ' + [string]$mainSuite.name } else { ' to what you have' }) })
            licences     = @($licences)
            replaces     = @($top.replaced | ForEach-Object { [ordered]@{ name = [string]$_.name; by = [string]$top.suite.name } })
            keeps        = @($top.kept | ForEach-Object { [string]$_.name })
            noLonger     = @($data.features.Keys | Where-Object { $id = $_; -not $after.Contains($id) -and @($top.replaced | Where-Object { @($_.features) -contains $id }).Count -gt 0 } | ForEach-Object { & $nameOf $_ })
            redundant    = @($data.features.Keys | Where-Object { $brought.Contains($_) -and -not $owned.Contains($_) -and $vendorOf.ContainsKey($_) } | ForEach-Object { [ordered]@{ name = (& $nameOf $_); vendor = $vendorOf[$_] } })
            alsoIncludes = @($data.features.Keys | Where-Object { $brought.Contains($_) -and -not $owned.Contains($_) -and -not (& $isSecurity $_) } | ForEach-Object { & $nameOf $_ })
        }
        # A feature the combination brings that needs another it does not bring and the tenant lacks.
        $prereq = @($brought | ForEach-Object { $f = $data.features[[string]$_]; if ($f.Contains('requires')) { @($f.requires | Where-Object { -not $have.Contains([string]$_) -and -not $brought.Contains([string]$_) } | ForEach-Object { "$($f.name) needs $(& $nameOf $_)." }) } } | Select-Object -Unique)
    }

    # Licences the tenant holds today that overlap: everything one brings is also in another it holds.
    $heldOverlap = [System.Collections.Generic.List[object]]::new()
    foreach ($small in $heldBundles) {
        if (@($small.features).Count -eq 0) { continue }
        foreach ($big in @($heldBundles | Where-Object { $_.kind -eq 'suite' })) {
            if ($big -eq $small -or @($big.features).Count -le @($small.features).Count) { continue }
            if (@($small.features | Where-Object { @($big.features) -notcontains [string]$_ }).Count -eq 0) { $heldOverlap.Add([ordered]@{ licence = [string]$small.name; includedIn = [string]$big.name }); break }
        }
    }

    $missingOnce = [System.Collections.Generic.List[object]]::new()
    $missingSeen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($grp in $groups) { if ($missingSeen.Add((@($grp) -join '|'))) { $missingOnce.Add(@($grp | ForEach-Object { & $nameOf $_ })) } }

    if ($null -ne $Record) {
        $Record['mode'] = $(if ($groups.Count -eq 0) { 'none' } elseif ($usePrice) { 'priced' } else { 'function' })
        $Record['why'] = $(if ($groups.Count -eq 0) { 'the goals are covered; nothing to choose' } elseif ($usePrice) { 'every licence in the comparison has a price' } elseif ($null -eq $Price -or $Price.get_Count() -eq 0) { 'no price file' } else { "$($withoutPrice.Count) licence(s) in the comparison have no price" })
        $Record['withoutPrice'] = @($withoutPrice)
        $Record['combinations'] = $made.Count
    }

    return [ordered]@{
        features = @($featureRows)
        goals    = @($goalRows)
        advice   = [ordered]@{
            goals        = @($chosen | ForEach-Object { $_.id })
            goalSource   = $(if ($Goal.Count) { 'profile' } else { 'core' })
            met          = ($groups.Count -eq 0)
            # Each gap once, in the order met: two goals that lack the same feature are one thing to buy.
            missing      = $missingOnce.ToArray()
            # One combination, or nothing when the goals are covered or no licence in the data covers them.
            recommended  = $recommended
            heldOverlap  = $heldOverlap.ToArray()
            vendors      = $vendorOf
            prerequisite = @($prereq)
            seats        = $Seats
            note         = 'A starting point to take to your Microsoft partner, not licensing advice. Each licence is named for what it covers. Eligibility and terms are your partner''s to confirm, and some add-ons need a base licence.'
        }
        reviewed = $data.reviewed
    }
}

function Get-PostureLicensePageData {
    <#
    .SYNOPSIS
        What templates/licensing.js needs to run the advisor in the page: the licensing data in the order the
        PowerShell reads it, the features owned, the vendors, the seats and the profile's goals. No price is in it:
        the page chooses on function alone.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Owned,
        [System.Collections.IDictionary] $ThirdParty = @{},
        [int] $Seats = 0,
        [string[]] $Goal = @(),
        [string[]] $OwnedSku = @()
    )
    $ld = Get-PostureLicensingData
    return [ordered]@{
        features   = @($ld.features.Values | ForEach-Object { [ordered]@{ id = $_.id; name = $_.name; kind = $(if ($_.Contains('kind')) { $_.kind } else { 'security' }); coveredBy = $(if ($_.Contains('coveredBy')) { $_.coveredBy } else { $null }); requires = @($(if ($_.Contains('requires')) { $_.requires })) } })
        bundles    = @($ld.bundles | ForEach-Object { [ordered]@{ sku = $_.sku; name = $_.name; kind = $_.kind; features = @($_.features); companion = [bool]($_.Contains('companion') -and $_.companion); seatCap = $(if ($_.Contains('seatCap')) { [int]$_.seatCap } else { $null }); verify = $(if ($_.Contains('verify')) { $_.verify } else { $null }); requiresBase = @($(if ($_.Contains('requiresBase')) { $_.requiresBase })) } })
        goals      = @($ld.goals | ForEach-Object { [ordered]@{ id = $_.id; name = $_.name; core = [bool]$_.core; needs = @($_.needs | ForEach-Object { , @($_) }) } })
        owned      = @($Owned)
        thirdParty = $ThirdParty
        seats      = $Seats
        goalIds    = @($Goal)
        ownedSkus  = @($OwnedSku)
    }
}
