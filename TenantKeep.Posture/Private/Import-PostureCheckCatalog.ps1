# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Import-PostureCheckCatalog {
    <#
    .SYNOPSIS
        Loads and validates the check catalog: every checks/*.json plus optional custom check folders.
    .DESCRIPTION
        Each file holds { "domain": "ca", "checks": [ ... ] }. Every check must carry the fields CLAUDE.md lists;
        a bad check fails the load with the file, id and missing field named, so a broken catalog never ships.
        catalog.json in the folder gives the catalog version, chains.json the control chains
        (Import-PostureControlChain), facts.json the plain labels for facts and thresholds (returned as labels) and
        attack.json the MITRE ATT&CK techniques the checks name, with names and tactics (returned as attack, generated
        by build.ps1 -Task AttackData); none is a domain file. Custom checks are tagged custom = true.

        remediation is a string or an array of steps. Every check comes back with both: steps (one or more) and
        remediation as one string, so a reader that wants text (CSV, the CA document, the public catalog) never
        sees an array. effort (S, M, L) is optional; category is fix or improve, fix when absent; userImpact is
        what users notice when the fix lands: a level (none, low, medium, high) and a sentence. attack is optional: the
        ATT&CK technique ids (T1078.004) the check helps stop or detect.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [string] $Path,
        [string[]] $CustomPath = @()
    )

    $ErrorActionPreference = 'Stop'
    if (-not $Path) { $Path = Get-PostureDataFolder -Name 'checks' }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Check catalog folder not found: $Path" }

    $version = 'unversioned'
    $domainList = [ordered]@{}
    $versionFile = Join-Path $Path 'catalog.json'
    if (Test-Path -LiteralPath $versionFile) {
        $cj = Get-Content -Raw -LiteralPath $versionFile | ConvertFrom-Json -AsHashtable
        $version = [string]$cj.version
        foreach ($d in @($(if ($cj.Contains('domains')) { $cj['domains'] }))) { $domainList[[string]$d['key']] = [string]$d['label'] }
    }

    $required = 'id', 'domain', 'title', 'severityDefault', 'license', 'applicableWhen', 'coveredBy', 'thresholds', 'evidence', 'pass', 'remediation', 'learn', 'deepLink', 'narrative', 'frameworks'
    $severities = 'Critical', 'High', 'Medium', 'Low'
    $efforts = 'S', 'M', 'L'
    $categories = 'fix', 'improve'
    $userImpacts = 'none', 'low', 'medium', 'high'
    $checks = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    $files = @()

    $load = {
        param([string] $Folder, [bool] $Custom)
        foreach ($file in (Get-ChildItem -LiteralPath $Folder -Filter '*.json' | Where-Object { $_.Name -notin 'attack.json', 'catalog.json', 'chains.json', 'facts.json', 'journeys.json', 'layers.json', 'outcomes.json' })) {
            $doc = Get-Content -Raw -LiteralPath $file.FullName | ConvertFrom-Json -AsHashtable -Depth 20
            $domain = [string](Get-PostureValue $doc 'domain')
            $list = if ($doc -is [System.Collections.IDictionary]) { @($doc['checks']) } else { @($doc) }
            foreach ($c in $list) {
                if (-not ($c -is [System.Collections.IDictionary])) { throw "$($file.Name): a check is not an object." }
                $missing = @($required | Where-Object { -not $c.Contains($_) })
                if ($missing.Count -gt 0) { throw "$($file.Name): check '$(Get-PostureValue $c 'id')' is missing: $($missing -join ', ')" }
                if (-not $c['domain'] -and $domain) { $c['domain'] = $domain }
                if ([string]$c['severityDefault'] -notin $severities) { throw "$($file.Name): check '$($c['id'])' has severityDefault '$($c['severityDefault'])'; expected $($severities -join ', ')" }
                if ([string]::IsNullOrWhiteSpace([string]$c['pass'])) { throw "$($file.Name): check '$($c['id'])' has an empty pass expression" }
                if ($c['id'] -notmatch '^[A-Z]{2,6}-\d{3}$') { throw "$($file.Name): check id '$($c['id'])' must look like CA-001" }
                $steps = @($c['remediation'] | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
                if ($steps.Count -eq 0) { throw "$($file.Name): check '$($c['id'])' has no remediation" }
                $c['steps'] = $steps
                $c['remediation'] = $steps -join ' '
                # The evidence contract (Invoke-PostureCheckEvaluation): evidenceOptional and evidenceAnyOf only name files the evidence list has.
                $evidenceNames = @($c['evidence'] | ForEach-Object { ([string]$_) -replace '\.(json|csv)$', '' })
                foreach ($n in @($(if ($c.Contains('evidenceOptional')) { $c['evidenceOptional'] }))) { if ((([string]$n) -replace '\.(json|csv)$', '') -notin $evidenceNames) { throw "$($file.Name): check '$($c['id'])' lists '$n' in evidenceOptional but not in evidence" } }
                # Read without a subexpression: one group in the list would be unrolled into its file names.
                $anyOf = @(); if ($c.Contains('evidenceAnyOf') -and $null -ne $c['evidenceAnyOf']) { $anyOf = [object[]]$c['evidenceAnyOf'] }
                foreach ($g in $anyOf) {
                    if (@($g).Count -lt 2) { throw "$($file.Name): check '$($c['id'])' has an evidenceAnyOf group with fewer than two files" }
                    foreach ($n in @($g)) { if ((([string]$n) -replace '\.(json|csv)$', '') -notin $evidenceNames) { throw "$($file.Name): check '$($c['id'])' lists '$n' in evidenceAnyOf but not in evidence" } }
                }
                if ($c.Contains('effort') -and [string]$c['effort'] -notin $efforts) { throw "$($file.Name): check '$($c['id'])' has effort '$($c['effort'])'; expected $($efforts -join ', ')" }
                if ($c.Contains('impact')) { throw "$($file.Name): check '$($c['id'])' has impact, which became userImpact (level and text) on 2026-11-20" }
                if ($c.Contains('userImpact')) {
                    $ui = $c['userImpact']
                    if (-not ($ui -is [System.Collections.IDictionary]) -or [string]$ui['level'] -notin $userImpacts -or [string]::IsNullOrWhiteSpace([string]$ui['text'])) { throw "$($file.Name): check '$($c['id'])' userImpact needs a level ($($userImpacts -join ', ')) and text" }
                }
                if ($c.Contains('attack')) {
                    $bad = @(@($c['attack']) | Where-Object { -not ($_ -is [string]) -or $_ -notmatch '^T\d{4}(\.\d{3})?$' })
                    if (-not ($c['attack'] -is [array]) -or $bad.Count) { throw "$($file.Name): check '$($c['id'])' attack must be a list of ATT&CK technique ids like T1078.004" }
                }
                if (-not $c.Contains('category') -or -not $c['category']) { $c['category'] = 'fix' }
                elseif ([string]$c['category'] -notin $categories) { throw "$($file.Name): check '$($c['id'])' has category '$($c['category'])'; expected $($categories -join ', ')" }
                if ($seen.ContainsKey($c['id'])) { throw "Duplicate check id '$($c['id'])' in $($file.Name) and $($seen[$c['id']])" }
                $seen[$c['id']] = $file.Name
                $c['custom'] = $Custom
                $c['source'] = $file.Name
                $checks.Add($c)
            }
            $files += $file.FullName
        }
    }
    & $load $Path $false
    foreach ($cp in $CustomPath) {
        if (-not (Test-Path -LiteralPath $cp -PathType Container)) { throw "Custom check folder not found: $cp" }
        & $load $cp $true
    }

    $labels = @{ facts = @{}; thresholds = @{} }
    $labelFile = Join-Path $Path 'facts.json'
    if (Test-Path -LiteralPath $labelFile) {
        $doc = Get-Content -Raw -LiteralPath $labelFile | ConvertFrom-Json -AsHashtable
        foreach ($k in 'facts', 'thresholds') { if ($doc[$k]) { $labels[$k] = $doc[$k] } }
    }

    # The ATT&CK techniques by id, in tactic order; a custom check may name one the file lacks and shows the id alone.
    $attack = $null
    $attackFile = Join-Path $Path 'attack.json'
    if (Test-Path -LiteralPath $attackFile) {
        $doc = Get-Content -Raw -LiteralPath $attackFile | ConvertFrom-Json -AsHashtable
        $byId = [ordered]@{}; foreach ($t in @($doc['techniques'])) { $byId[[string]$t['id']] = $t }
        $attack = [ordered]@{ version = [string]$doc['version']; tactics = @($doc['tactics']); techniques = $byId; notice = [string]$doc['notice'] }
    }

    return [ordered]@{
        version = $version
        domains = $domainList
        labels  = $labels
        attack  = $attack
        path    = $Path
        checks  = @($checks | Sort-Object { $_['id'] })
    }
}
