# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureCompletion {
    <#
    .SYNOPSIS
        What an assessment still lacks, as rows someone can act on: each missing piece with how many checks wait for
        it, who can add it, where, the command, and the command that brings it back.
    .DESCRIPTION
        The rows come from the completion block of checks/catalog.json, matched by evidence name, so a new check
        or a new collector adds data there and nothing here or in the renderers. A piece is listed when checks are
        not evaluated because evidence it provides is not in the run:
          - a piece collected elsewhere (Active Directory, the SharePoint admin read, the site permissions
            report), whenever a check waits for its files;
          - one of the module's own collectors, only when it did not run at all (skipped when the run started, not
            finished, or none of its files are there). A step that failed inside a collector that ran is Run
            Health's to explain, and gets one row here that points to it.
        A check that is not evaluated for want of a licence waits for nothing that can be collected and is not
        counted. {run}, {client} and {imports} in the catalog's commands become this run's paths.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Catalog,
        [AllowEmptyCollection()] [object[]] $Result = @(),
        [Parameter(Mandatory)] [string] $Evidence,
        [System.Collections.IDictionary] $Plan,
        [System.Collections.IDictionary] $Collection,
        [AllowEmptyCollection()] [object[]] $Failure = @()
    )

    $entries = @($(if ($Catalog.Contains('completion')) { $Catalog['completion'] }) | Where-Object { $_ })
    if ($entries.Count -eq 0) { return @() }
    $layout = Get-PostureRunLayout -Folder $Evidence
    $present = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($f in @(Get-ChildItem -LiteralPath $layout.evidence -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.json', '.csv' })) { $null = $present.Add($f.BaseName) }
    foreach ($n in @(Get-PostureStaleEvidence -Folder $Evidence)) { $null = $present.Remove($n) }
    $provides = { param([System.Collections.IDictionary] $Entry, [string] $Name) foreach ($pattern in @($Entry['evidence'])) { $p = [string]$pattern; if (($p.EndsWith('-') -and $Name.StartsWith($p, [System.StringComparison]::OrdinalIgnoreCase)) -or $Name -eq $p) { return $true } }; return $false }
    $entryFor = { param([string] $Name) foreach ($e in $entries) { if (& $provides $e $Name) { return $e } } }

    # The checks that wait for each piece: not evaluated, not for a licence, and naming a file that is not there.
    $byId = @{}; foreach ($c in @($Catalog.checks)) { $byId[[string]$c['id']] = $c }
    $waiting = @{}
    foreach ($r in $Result) {
        if ([string]$r.status -ne 'notEvaluated' -or [string]$r.reason -match '^Requires ') { continue }
        $check = $byId[[string]$r.id]
        if (-not $check) { continue }
        $optional = @($(if ($check.Contains('evidenceOptional')) { $check['evidenceOptional'] }) | ForEach-Object { ([string]$_) -replace '\.(json|csv)$', '' })
        foreach ($file in @($check['evidence'])) {
            $name = ([string]$file) -replace '\.(json|csv)$', ''
            if (-not $name -or $name -in $optional -or $present.Contains($name)) { continue }
            $entry = & $entryFor $name
            if (-not $entry) { continue }
            $id = [string]$entry['id']
            if (-not $waiting.ContainsKey($id)) { $waiting[$id] = [System.Collections.Generic.HashSet[string]]::new() }
            $null = $waiting[$id].Add([string]$r.id)
        }
    }

    $quote = { param([string] $Text) "'" + $Text.Replace("'", "''") + "'" }
    $client = [string]$(if ($Plan -and $Plan.Contains('client') -and $Plan['client']) { $Plan['client'] })
    $fill = {
        param([string] $Text)
        $Text.Replace('{run}', (& $quote ([string]$layout.root))).Replace('{client}', $(if ($client) { & $quote $client } else { '<the client folder>' })).Replace('{imports}', $(if ($client) { Join-Path $client 'imports' } else { 'the client folder''s imports folder' }))
    }
    $skipped = $(if ($Plan -and $Plan.Contains('skipped') -and $Plan['skipped'] -is [System.Collections.IDictionary]) { $Plan['skipped'] } else { @{} })
    $finished = @($(try { Get-PostureFinishedCollector -Folder $Evidence -Manifest @($(if ($Collection -and $Collection.Contains('collectors')) { $Collection['collectors'] })) } catch { @() }))

    $rows = [System.Collections.Generic.List[object]]::new()
    $order = 0
    foreach ($e in $entries) {
        $order++
        $id = [string]$e['id']
        $count = $(if ($waiting.ContainsKey($id)) { $waiting[$id].Count } else { 0 })
        $collector = [string]$(if ($e.Contains('collector')) { $e['collector'] })
        $note = ''
        if ($collector) {
            # One of the module's own collectors: a row only when it did not run at all.
            $wasSkipped = $skipped.Contains($collector)
            $anyFile = @($present | Where-Object { & $provides $e $_ }).Count -gt 0
            if (-not $wasSkipped -and ($collector -in $finished -or $anyFile)) { continue }
            if ($wasSkipped) { $note = "Skipped when the run started: $([string]$skipped[$collector])" } elseif ($count -eq 0) { continue } else { $note = 'Not collected in this run.' }
        }
        elseif ($count -eq 0) { continue }
        $rows.Add([ordered]@{ id = $id; title = [string]$e['title']; checks = $count; who = [string]$e['who']; where = [string]$e['where']; get = (& $fill ([string]$e['get'])); bring = (& $fill ([string]$(if ($e.Contains('bring')) { $e['bring'] }))); note = $note; order = $order })
    }

    # Steps that failed inside a collector that ran: one row, and Run Health has the detail. Permissions the
    # sign-in does not carry are named, since granting them is the whole of the fix.
    $failed = @($Failure | Where-Object { $_ -and [string]$_['cause'] -in 'permission', 'token', 'throttled', 'network', 'module', 'unknown' })
    if ($failed.Count -gt 0) {
        $granted = @($(if ($Collection -and $Collection.Contains('scopes')) { $Collection['scopes'] }) | ForEach-Object { [string]$_ })
        $missing = @($failed | Where-Object { [string]$_['cause'] -eq 'permission' } | ForEach-Object { @($_['scopes']) } | Where-Object { $_ -and [string]$_ -notin $granted } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
        $appOnly = $Collection -and $Collection.Contains('authType') -and (Test-PostureAppOnlySignIn -AuthType ([string]$Collection['authType']))
        $resume = "Resume-PostureRun -Path $(& $quote ([string]$layout.root))"
        $rows.Add([ordered]@{
                id = 'failed-steps'; title = "$($failed.Count) step$(if ($failed.Count -ne 1) { 's' }) that could not be read"; checks = $null
                who = $(if ($missing.Count -gt 0) { 'A Global Administrator, for the permissions; then the admin who ran the assessment' } else { 'The admin who ran the assessment, once Run Health''s advice is followed' })
                where = 'Run Health in this report says what each step needs'
                get = $(if ($missing.Count -eq 0) { $resume } elseif ($appOnly) { "Grant the identity $($missing -join ', ') (deploy/automation/Grant-ManagedIdentityGraphRole.ps1 -IncludePosture), then start the job again" } else { "Consent again so the sign-in carries $($missing -join ', '), then: $resume" })
                bring = 'Nothing to bring back: it collects into the run and rebuilds the report.'
                note = $(if ($missing.Count -gt 0) { "The sign-in does not carry: $($missing -join ', ')." } else { '' }); order = 1000
            })
    }
    return @($rows | Sort-Object { - [int]$_.checks }, { $_.order } | ForEach-Object { $_.Remove('order'); $_ })
}

function Get-PostureSourceStatus {
    <#
    .SYNOPSIS
        Every source an assessment can draw on and where this run stands with each: collected, not collected, or
        not needed here. Run Health shows the rows whether or not anything is missing.
    .DESCRIPTION
        "To complete this assessment" lists a piece only when a check waits for it. A run that lacks nothing then
        says nothing, and a reader cannot tell "not needed for this tenant" from "nobody told me". This lists every
        entry of the completion block of checks/catalog.json, so the rows are data like the rest:
          - not collected, when the completion rows name it (with what they say);
          - collected, when the run holds evidence it provides (how many files, and how many of its steps could not
            be read);
          - not needed here, when neither: no check in this run waits for it. neededBy in the catalog says which
            tenants would need it.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Catalog,
        [Parameter(Mandatory)] [string] $Evidence,
        [AllowEmptyCollection()] [object[]] $Completion = @(),
        [AllowEmptyCollection()] [object[]] $Failure = @()
    )

    $entries = @($(if ($Catalog.Contains('completion')) { $Catalog['completion'] }) | Where-Object { $_ })
    if ($entries.Count -eq 0) { return @() }
    $layout = Get-PostureRunLayout -Folder $Evidence
    $present = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($f in @(Get-ChildItem -LiteralPath $layout.evidence -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.json', '.csv' })) { $null = $present.Add($f.BaseName) }
    foreach ($n in @(Get-PostureStaleEvidence -Folder $Evidence)) { $null = $present.Remove($n) }
    $provides = { param([System.Collections.IDictionary] $Entry, [string] $Name) foreach ($pattern in @($Entry['evidence'])) { $p = [string]$pattern; if (($p.EndsWith('-') -and $Name.StartsWith($p, [System.StringComparison]::OrdinalIgnoreCase)) -or $Name -eq $p) { return $true } }; return $false }
    $lacking = @{}; foreach ($row in @($Completion | Where-Object { $_ })) { $lacking[[string]$row['id']] = $row }
    $rank = @{ collected = 0; notCollected = 1; notNeeded = 2 }

    $rows = [System.Collections.Generic.List[object]]::new()
    # The catalog lists what is collected apart from the run first; read the other way round, the run's own domains
    # come first, which is the order a reader looks for them in.
    $order = 0
    for ($i = $entries.Count - 1; $i -ge 0; $i--) {
        $e = $entries[$i]
        $order++
        $id = [string]$e['id']
        $collector = [string]$(if ($e.Contains('collector')) { $e['collector'] })
        $files = @($present | Where-Object { & $provides $e $_ }).Count
        $failed = $(if ($collector) { @($Failure | Where-Object { $_ -and [string]$_['collector'] -eq $collector }).Count } else { 0 })
        if ($lacking.ContainsKey($id)) {
            $row = $lacking[$id]
            $waits = [int]$(if ($null -ne $row['checks']) { $row['checks'] } else { 0 })
            $note = ([string]$row['note']).Trim(); if ($note -and $note -notmatch '[.!?]$') { $note += '.' }
            $detail = @($note, $(if ($waits -gt 0) { "$waits check$(if ($waits -ne 1) { 's wait' } else { ' waits' }) for it." }), '"To Complete This Assessment" on the Overview says who can add it and how.' | Where-Object { $_ }) -join ' '
            $state = 'notCollected'
        }
        elseif ($files -gt 0) {
            $detail = "$files file$(if ($files -ne 1) { 's' })." + $(if ($failed -gt 0) { " $failed step$(if ($failed -ne 1) { 's' }) could not be read; the list on this page says why." } else { '' })
            $state = 'collected'
        }
        else {
            $neededBy = [string]$(if ($e.Contains('neededBy')) { $e['neededBy'] })
            $detail = 'No check in this run waits for it.' + $(if ($neededBy) { " Needed by: $neededBy" } else { '' })
            $state = 'notNeeded'
        }
        $rows.Add([ordered]@{ id = $id; title = [string]$e['title']; state = $state; files = $files; detail = $detail; order = $order })
    }
    return @($rows | Sort-Object { $rank[[string]$_.state] }, { $_.order } | ForEach-Object { $_.Remove('order'); $_ })
}

