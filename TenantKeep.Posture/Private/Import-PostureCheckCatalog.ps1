# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Import-PostureCheckCatalog {
    <#
    .SYNOPSIS
        Loads and validates the check catalog: every checks/*.json plus optional custom check folders.
    .DESCRIPTION
        Each file holds { "domain": "ca", "checks": [ ... ] }. Every check must carry the fields CLAUDE.md lists;
        a bad check fails the load with the file, id and missing field named, so a broken catalog never ships.
        catalog.json in the folder gives the catalog version. Custom checks are tagged custom = true.
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
    $checks = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    $files = @()

    $load = {
        param([string] $Folder, [bool] $Custom)
        foreach ($file in (Get-ChildItem -LiteralPath $Folder -Filter '*.json' | Where-Object { $_.Name -ne 'catalog.json' })) {
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

    return [ordered]@{
        version = $version
        path    = $Path
        checks  = @($checks | Sort-Object { $_['id'] })
    }
}
