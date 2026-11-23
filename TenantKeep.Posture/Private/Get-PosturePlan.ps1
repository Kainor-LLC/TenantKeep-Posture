# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Import-PostureProject {
    <#
    .SYNOPSIS
        checks/projects.json: the catalog's checks grouped into projects, and what each project waits on.
    .DESCRIPTION
        A project is a piece of work an administrator would plan ("Bring devices under management"). needs names
        projects that have to be finished first, because this one causes harm or cannot work without them; after
        names a recommended order. Each carries the reason in why.

        Refused: a project without an id (PJ-001), a name, a description or checks; an id used twice; a check the
        catalog does not have, or one in two projects; a built-in check in no project (a new check has to be given
        one, so the plan stays complete); a dependency on a project that is not there, on itself, or without a
        reason; the same project under both needs and after; and a loop.
        A catalog folder without the file gives an empty list.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Catalog)

    $ErrorActionPreference = 'Stop'
    if (-not $Catalog.Contains('path') -or -not $Catalog['path']) { return @() }
    $path = Join-Path ([string]$Catalog['path']) 'projects.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return @() }
    $doc = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json -AsHashtable -Depth 10
    $projects = @($doc['projects'])
    $builtIn = @{}
    foreach ($c in @($Catalog['checks'])) { if ($c -and -not ($c.Contains('custom') -and $c['custom'])) { $builtIn[[string]$c['id']] = $true } }
    $byId = @{}
    $owner = @{}
    foreach ($p in $projects) {
        $id = [string]$p['id']
        if ($id -notmatch '^PJ-\d{3}$') { throw "projects.json: '$id' is not a project id like PJ-001" }
        if ($byId.ContainsKey($id)) { throw "projects.json: $id is there twice" }
        if ([string]::IsNullOrWhiteSpace([string]$p['name']) -or [string]::IsNullOrWhiteSpace([string]$p['what'])) { throw "projects.json: $id needs a name and a line on what it is" }
        if (@($p['checks']).Count -eq 0) { throw "projects.json: $id has no checks" }
        foreach ($c in @($p['checks'])) {
            $check = [string]$c
            if (-not $builtIn.ContainsKey($check)) { throw "projects.json: $id names '$check', which is not in the catalog" }
            if ($owner.ContainsKey($check)) { throw "projects.json: $check is in $($owner[$check]) and in $id; a check belongs to one project" }
            $owner[$check] = $id
        }
        $byId[$id] = $p
    }
    $homeless = @($builtIn.get_Keys() | Where-Object { -not $owner.ContainsKey($_) } | Sort-Object)
    if ($homeless.Count -gt 0) { throw "projects.json: no project holds $($homeless -join ', '). Every check belongs to one project, so the plan leaves nothing out." }
    foreach ($p in $projects) {
        $id = [string]$p['id']
        $seen = @{}
        foreach ($kind in 'needs', 'after') {
            foreach ($edge in @($(if ($p.Contains($kind)) { $p[$kind] }))) {
                $other = [string]$edge['project']
                if (-not $byId.ContainsKey($other)) { throw "projects.json: $id $kind '$other', which is not a project" }
                if ($other -eq $id) { throw "projects.json: $id $kind itself" }
                if ([string]::IsNullOrWhiteSpace([string]$edge['why'])) { throw "projects.json: $id $kind $other without saying why" }
                if ($seen.ContainsKey($other)) { throw "projects.json: $id names $other twice; needs or after, not both" }
                $seen[$other] = $true
            }
        }
    }
    # No loops: following what each project waits on must end.
    $state = @{}
    $visit = {
        param([string] $id, [string[]] $trail)
        if ($state[$id] -eq 'done') { return }
        if ($state[$id] -eq 'open') { throw "projects.json: a loop, $(@($trail + $id) -join ' waits on ')" }
        $state[$id] = 'open'
        foreach ($kind in 'needs', 'after') { foreach ($edge in @($(if ($byId[$id].Contains($kind)) { $byId[$id][$kind] }))) { & $visit ([string]$edge['project']) @($trail + $id) } }
        $state[$id] = 'done'
    }
    foreach ($p in $projects) { & $visit ([string]$p['id']) @() }
    return $projects
}

function Get-PosturePlan {
    <#
    .SYNOPSIS
        The remediation plan for one run: the projects with something to fix, in the order they can start.
    .DESCRIPTION
        Each project of checks/projects.json is judged from the run's results. needed: a check of it fails. done:
        nothing fails and something was judged good. unknown: nothing fails, nothing was judged good and something
        could not be evaluated. notApplicable: none of its checks has an answer in this run.

        The needed projects are put in columns. A project starts in the first column when nothing it waits on is
        itself needed, and otherwise one column after the last of those. Projects in one column do not wait on each
        other and can run side by side. A project that waits on one that could not be judged is not held back; it
        says which to check first, because missing data is never read as done.

        The first column would hold every project with no prerequisite, which on a new tenant is most of them. It
        keeps the ones another project waits on and then the highest risk, up to -StartLimit; the rest are returned
        as whenever: ready to start, lower risk, nothing waits on them.

        Returns $null when the catalog has no projects file. Otherwise: counts; columns (inPlace, start, then,
        after, later), each a list of projects with id, name, what, state, risk, points, size, toFix, notJudged,
        improvementsOnly, checks (the failing ones), waitsOn (name, kind, why, state) and checkFirst; edges between
        projects in neighbouring columns (from, to, kind); and whenever.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Catalog,
        [AllowEmptyCollection()] [object[]] $Result = @(),
        [ValidateRange(1, 50)] [int] $StartLimit = 8
    )

    $ErrorActionPreference = 'Stop'
    $projects = @(Import-PostureProject -Catalog $Catalog)
    if ($projects.Count -eq 0) { return $null }
    $weight = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }
    $effortRank = @{ S = 1; M = 2; L = 3 }
    $check = @{}
    foreach ($c in @($Catalog['checks'])) { $check[[string]$c['id']] = $c }
    $answer = @{}
    foreach ($r in $Result) { if ($r) { $answer[[string]$r.id] = $r } }

    # 1. Each project's state in this run.
    $info = [ordered]@{}
    foreach ($p in $projects) {
        $id = [string]$p['id']
        $failing = [System.Collections.Generic.List[object]]::new()
        $good = 0; $notJudged = 0
        foreach ($c in @($p['checks'])) {
            $r = $answer[[string]$c]
            if (-not $r) { continue }
            switch ([string]$r.status) {
                'fail' {
                    $entry = $check[[string]$c]
                    $failing.Add([ordered]@{ id = [string]$c; title = [string]$r.title; severity = [string]$r.severity; effort = [string]$entry['effort']; category = [string]$entry['category'] })
                }
                'notEvaluated' { $notJudged++ }
                { $_ -in 'pass', 'acceptedRisk', 'coveredBy' } { $good++ }
            }
        }
        $state = $(if ($failing.Count -gt 0) { 'needed' } elseif ($good -gt 0) { 'done' } elseif ($notJudged -gt 0) { 'unknown' } else { 'notApplicable' })
        $ranked = @($failing | Sort-Object { - [int]$weight[[string]$_.severity] }, { $_.id })
        $risk = $(if ($ranked.Count -gt 0 -and $weight.ContainsKey([string]$ranked[0].severity)) { [string]$ranked[0].severity } else { '' })
        $points = 0; foreach ($f in $failing) { $w = $weight[[string]$f.severity]; $points += $(if ($w) { $w } else { 1 }) }
        $size = 'S'; foreach ($f in $failing) { if ($effortRank.ContainsKey([string]$f.effort) -and $effortRank[[string]$f.effort] -gt $effortRank[$size]) { $size = [string]$f.effort } }
        $info[$id] = [ordered]@{
            id = $id; name = [string]$p['name']; what = [string]$p['what']; state = $state; risk = $risk; points = $points
            size = $(if ($failing.Count -gt 0) { $size } else { '' }); toFix = $failing.Count; notJudged = $notJudged
            improvementsOnly = [bool]($failing.Count -gt 0 -and @($failing | Where-Object { $_.category -ne 'improve' }).Count -eq 0)
            checks = $ranked; waitsOn = @(); checkFirst = @(); wave = -1
        }
    }

    # 2. What each needed project waits on, and its column: one after the last needed project it waits on.
    $edgesOf = @{}
    foreach ($p in $projects) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($kind in 'needs', 'after') { foreach ($e in @($(if ($p.Contains($kind)) { $p[$kind] }))) { $list.Add([ordered]@{ project = [string]$e['project']; kind = $kind; why = [string]$e['why'] }) } }
        $edgesOf[[string]$p['id']] = $list
    }
    $waveOf = {
        param([string] $id)
        if ($info[$id].wave -ge 0) { return $info[$id].wave }
        $w = 0
        foreach ($e in $edgesOf[$id]) { if ($info[$e.project].state -eq 'needed') { $w = [Math]::Max($w, 1 + (& $waveOf $e.project)) } }
        $info[$id].wave = $w
        $w
    }
    $needed = @($info.Values | Where-Object { $_.state -eq 'needed' })
    foreach ($n in $needed) {
        $null = & $waveOf $n.id
        $n.waitsOn = @($edgesOf[$n.id] | ForEach-Object { [ordered]@{ id = $_.project; name = $info[$_.project].name; kind = $_.kind; why = $_.why; state = $info[$_.project].state } } | Where-Object { $_.state -ne 'notApplicable' })
        $n.checkFirst = @($n.waitsOn | Where-Object { $_.state -eq 'unknown' } | ForEach-Object { $_.name })
    }

    # 3. The first column: what unlocks other work, then the highest risk; the rest can start whenever.
    $unlocks = @{}
    foreach ($n in $needed) { foreach ($w in $n.waitsOn) { if ($w.state -eq 'needed') { $unlocks[$w.id] = $true } } }
    $byRisk = { param($list) @($list | Sort-Object { - [int]$weight[[string]$_.risk] }, { - $_.points }, { $_.name }) }
    $first = @(& $byRisk @($needed | Where-Object { $_.wave -eq 0 }))
    $start = [System.Collections.Generic.List[object]]::new()
    foreach ($x in $first) { if ($unlocks.ContainsKey($x.id)) { $start.Add($x) } }
    foreach ($x in $first) { if ($start.Count -ge $StartLimit) { break }; if (-not $unlocks.ContainsKey($x.id)) { $start.Add($x) } }
    $startIds = @{}; foreach ($x in $start) { $startIds[$x.id] = $true }
    $whenever = @($first | Where-Object { -not $startIds.ContainsKey($_.id) })
    $startList = @(& $byRisk $start)

    # 4. Columns. A later column is ordered by where its projects' prerequisites sit in the one before, so the
    # arrows between neighbours cross as little as a simple ordering allows.
    $rowOf = @{}
    for ($i = 0; $i -lt $startList.Count; $i++) { $rowOf[$startList[$i].id] = $i }
    $laterKeys = @(@(1, 'then', 'Then'), @(2, 'after', 'After that'), @(3, 'later', 'Later'))
    $columns = [System.Collections.Generic.List[object]]::new()
    $previous = $startList
    $laterColumns = foreach ($spec in $laterKeys) {
        $wave = $spec[0]
        $members = @($needed | Where-Object { [Math]::Min($_.wave, 3) -eq $wave })
        if ($members.Count -eq 0) { continue }
        $prevIds = @{}; foreach ($x in $previous) { $prevIds[$x.id] = $true }
        $place = {
            param($m)
            $rows = @($m.waitsOn | Where-Object { $prevIds.ContainsKey($_.id) } | ForEach-Object { $rowOf[$_.id] })
            if ($rows.Count -gt 0) { [double]($rows | Measure-Object -Average).Average } else { 999 }
        }
        $ordered = @($members | Sort-Object { & $place $_ }, { - $_.points }, { $_.name })
        for ($i = 0; $i -lt $ordered.Count; $i++) { $rowOf[$ordered[$i].id] = $i }
        $previous = $ordered
        [ordered]@{ key = $spec[1]; title = $spec[2]; projects = $ordered }
    }
    # What the plan builds on: finished projects that a first-column project waits on.
    $inPlaceIds = [ordered]@{}
    foreach ($s in $startList) { foreach ($w in $s.waitsOn) { if ($w.state -eq 'done') { $inPlaceIds[$w.id] = $true } } }
    $firstRowNeeding = { param([string] $id) $rows = @($startList | Where-Object { @($_.waitsOn | Where-Object { $_.id -eq $id }).Count -gt 0 } | ForEach-Object { $rowOf[$_.id] }); if ($rows.Count) { ($rows | Measure-Object -Minimum).Minimum } else { 999 } }
    $inPlace = @($inPlaceIds.get_Keys() | ForEach-Object { $info[$_] } | Sort-Object { & $firstRowNeeding $_.id }, { $_.name })
    if ($inPlace.Count -gt 0) { $columns.Add([ordered]@{ key = 'inPlace'; title = 'Already in place'; projects = $inPlace }) }
    if ($startList.Count -gt 0) { $columns.Add([ordered]@{ key = 'start'; title = 'Start now'; projects = $startList }) }
    foreach ($c in @($laterColumns)) { $columns.Add($c) }

    # 5. Arrows, between neighbouring columns only; a longer wait is said in words on the project.
    $columnOf = @{}
    for ($i = 0; $i -lt $columns.Count; $i++) { foreach ($x in $columns[$i].projects) { $columnOf[$x.id] = $i } }
    $edges = [System.Collections.Generic.List[object]]::new()
    foreach ($col in $columns) {
        if ($col.key -eq 'inPlace') { continue }
        foreach ($x in $col.projects) {
            foreach ($w in $x.waitsOn) { if ($columnOf.ContainsKey($w.id) -and $columnOf[$w.id] -eq $columnOf[$x.id] - 1) { $edges.Add([ordered]@{ from = $w.id; to = $x.id; kind = $w.kind }) } }
        }
    }

    $count = { param([string] $s) @($info.Values | Where-Object { $_.state -eq $s }).Count }
    [ordered]@{
        counts = [ordered]@{ projects = $info.Count; needed = (& $count 'needed'); done = (& $count 'done'); unknown = (& $count 'unknown'); notApplicable = (& $count 'notApplicable') }
        columns = @($columns)
        edges = @($edges)
        whenever = $whenever
        notJudged = @($info.Values | Where-Object { $_.state -eq 'unknown' } | ForEach-Object { [ordered]@{ id = $_.id; name = $_.name; notJudged = $_.notJudged } })
    }
}
