# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Import-PostureCheckCatalog {
    <#
    .SYNOPSIS
        Loads and validates the check catalog: every checks/*.json plus optional custom check folders.
    .DESCRIPTION
        Each file holds { "domain": "ca", "checks": [ ... ] }. Every check must carry the fields CLAUDE.md lists;
        a bad check fails the load with the file, id and missing field named, so a broken catalog never ships.
        catalog.json in the folder gives the catalog version, chains.json the control chains
        (Import-PostureControlChain) and facts.json the plain labels for facts and thresholds (returned as labels);
        none is a domain file. Custom checks are tagged custom = true.

        remediation is a string or an array of steps. Every check comes back with both: steps (one or more) and
        remediation as one string, so a reader that wants text (CSV, the CA document, the public catalog) never
        sees an array. effort (S, M, L) is optional; category is fix or improve, fix when absent; userImpact is
        what users notice when the fix lands: a level (none, low, medium, high) and a sentence.
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
    $versionFile = Join-Path $Path 'catalog.json'
    if (Test-Path -LiteralPath $versionFile) { $version = [string](Get-Content -Raw -LiteralPath $versionFile | ConvertFrom-Json -AsHashtable).version }

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
        foreach ($file in (Get-ChildItem -LiteralPath $Folder -Filter '*.json' | Where-Object { $_.Name -notin 'catalog.json', 'chains.json', 'facts.json', 'layers.json' })) {
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
                if ($c.Contains('effort') -and [string]$c['effort'] -notin $efforts) { throw "$($file.Name): check '$($c['id'])' has effort '$($c['effort'])'; expected $($efforts -join ', ')" }
                if ($c.Contains('impact')) { throw "$($file.Name): check '$($c['id'])' has impact, which became userImpact (level and text) on 2026-11-20" }
                if ($c.Contains('userImpact')) {
                    $ui = $c['userImpact']
                    if (-not ($ui -is [System.Collections.IDictionary]) -or [string]$ui['level'] -notin $userImpacts -or [string]::IsNullOrWhiteSpace([string]$ui['text'])) { throw "$($file.Name): check '$($c['id'])' userImpact needs a level ($($userImpacts -join ', ')) and text" }
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

    return [ordered]@{
        version = $version
        labels  = $labels
        path    = $Path
        checks  = @($checks | Sort-Object { $_['id'] })
    }
}
