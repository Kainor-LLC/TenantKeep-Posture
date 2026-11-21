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
        $appOnly = $Collection -and $Collection.Contains('authType') -and [string]$Collection['authType'] -and [string]$Collection['authType'] -ne 'Delegated'
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
