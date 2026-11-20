# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# The SharePoint Advanced Management "Site permissions across your organization" report, downloaded by the admin from
# the SharePoint admin center (no Graph, REST or PnP surface reads it, and starting one is a service-side job, so the
# module never does). Column names from Microsoft Learn, data-access-governance-site-permissions-report (verify
# against a real export; matched case-insensitively).
$script:PostureSharingColumns = [ordered]@{
    url        = 'Site URL'
    anyone     = 'Anyone link count'
    org        = 'People In Your Org link count'
    eeeu       = 'EEEU permission count'
    everyone   = 'Everyone permission count'
    name       = 'Site Name'
    label      = 'Site Sensitivity'
    reportDate = 'Report Date'
    tenant     = 'TenantID'
}

function Test-PostureSharingReport {
    <#
    .SYNOPSIS
        Reads a CSV's header and first row: whether it is a site permissions report, its report date and tenant id.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Path)

    $ErrorActionPreference = 'Stop'
    $first = @(Import-Csv -LiteralPath $Path | Select-Object -First 1)
    $header = @((Get-Content -LiteralPath $Path -TotalCount 1) -split ',' | ForEach-Object { $_.Trim().Trim('"') })
    $missing = @('url', 'anyone', 'org', 'eeeu', 'everyone' | Where-Object { $script:PostureSharingColumns[$_] -notin $header })
    $date = $null; $tenant = $null
    if ($first.Count -gt 0) {
        $col = { param($k) $n = $script:PostureSharingColumns[$k]; $p = $first[0].PSObject.Properties | Where-Object { $_.Name -eq $n } | Select-Object -First 1; if ($p) { [string]$p.Value } }
        $date = ConvertTo-PostureUtcDateTime (& $col 'reportDate')
        $tenant = & $col 'tenant'
    }
    return @{ valid = $missing.Count -eq 0; missing = $missing; reportDate = $date; tenantId = $tenant; empty = $first.Count -eq 0 }
}

function Write-PostureSharingSummary {
    <#
    .SYNOPSIS
        Summarises the site permissions reports in the client folder's imports/sam-dag into the run folder as
        spo-dag-site-permissions.json: totals for Anyone links, organization-wide links, Everyone except external
        users and Everyone grants, and the most exposed sites. Returns the summary, or $null when there is no report.
    .DESCRIPTION
        SharePoint and OneDrive are separate reports; every site permissions CSV is read, a site that appears in
        more than one keeps the row from the newest report. Rows are streamed, so a large tenant's file is not
        held in memory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Collections.IDictionary])]
    param(
        [Parameter(Mandatory)] [string] $Client,
        [Parameter(Mandatory)] [string] $Folder,
        [int] $Top = 20,
        [int] $MaxListed = 500
    )

    $ErrorActionPreference = 'Stop'
    $imports = Join-Path $Client 'imports' 'sam-dag'
    if (-not (Test-Path -LiteralPath $imports -PathType Container)) { return $null }
    $reports = @(Get-ChildItem -LiteralPath $imports -Filter '*.csv' -File | ForEach-Object { $t = Test-PostureSharingReport -Path $_.FullName; if ($t.valid -and -not $t.empty) { @{ file = $_; info = $t } } } | Sort-Object { $(if ($_.info.reportDate) { $_.info.reportDate } else { $_.file.LastWriteTimeUtc }) } -Descending)
    if ($reports.Count -eq 0) { return $null }

    $c = $script:PostureSharingColumns
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $totals = [ordered]@{ sites = 0; oneDriveSites = 0; sitesWithAnyoneLinks = 0; anyoneLinks = 0; sitesWithOrgLinks = 0; orgLinks = 0; sitesWithEeeu = 0; eeeuGrants = 0; sitesWithEveryone = 0; everyoneGrants = 0 }
    $exposed = [System.Collections.Generic.List[object]]::new()
    $count = @{ exposed = 0 }
    $num = { param($row, [string] $name) $raw = [string]$row.$name; $n = 0; if ([int]::TryParse(($raw -replace '[^0-9-]', ''), [ref]$n)) { $n } else { 0 } }
    foreach ($r in $reports) {
        Import-Csv -LiteralPath $r.file.FullName | ForEach-Object {
            $url = [string]$_.($c.url)
            if (-not $url -or -not $seen.Add($url)) { return }
            $anyone = & $num $_ $c.anyone; $org = & $num $_ $c.org; $eeeu = & $num $_ $c.eeeu; $everyone = & $num $_ $c.everyone
            $totals.sites++
            if ($url -match '-my\.sharepoint\.') { $totals.oneDriveSites++ }
            if ($anyone -gt 0) { $totals.sitesWithAnyoneLinks++; $totals.anyoneLinks += $anyone }
            if ($org -gt 0) { $totals.sitesWithOrgLinks++; $totals.orgLinks += $org }
            if ($eeeu -gt 0) { $totals.sitesWithEeeu++; $totals.eeeuGrants += $eeeu }
            if ($everyone -gt 0) { $totals.sitesWithEveryone++; $totals.everyoneGrants += $everyone }
            $score = $anyone + $org + $eeeu + $everyone
            if ($score -gt 0) {
                $count.exposed++
                $exposed.Add([ordered]@{ url = $url; name = [string]$_.($c.name); label = [string]$_.($c.label); anyone = $anyone; org = $org; eeeu = $eeeu; everyone = $everyone; score = $score })
                # Keep the list bounded on very large tenants: sort and trim once it doubles.
                if ($exposed.Count -ge 2 * $MaxListed) { $keep = @($exposed | Sort-Object { $_.score } -Descending | Select-Object -First $MaxListed); $exposed.Clear(); foreach ($k in $keep) { $exposed.Add($k) } }
            }
        }
    }
    $ranked = @($exposed | Sort-Object { $_.score } -Descending)
    $summary = [ordered]@{
        source        = 'SharePoint Advanced Management, Site permissions across your organization'
        reportDateUtc = $(if ($reports[0].info.reportDate) { $reports[0].info.reportDate.ToString('o') } else { $reports[0].file.LastWriteTimeUtc.ToString('o') })
        files         = @($reports | ForEach-Object { $_.file.Name })
        totals        = $totals
        exposedSites  = $count.exposed
        top           = @($ranked | Select-Object -First $Top)
        listed        = @($ranked | Select-Object -First $MaxListed)
    }
    if ($PSCmdlet.ShouldProcess($Folder, 'Write spo-dag-site-permissions.json')) { $null = Write-PostureEvidence -Folder $Folder -Name 'spo-dag-site-permissions' -InputObject $summary }
    return $summary
}
