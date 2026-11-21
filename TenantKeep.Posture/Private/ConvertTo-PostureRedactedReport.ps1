# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function ConvertTo-PostureRedactedReport {
    <#
    .SYNOPSIS
        A copy of the report model with the tenant's people and places replaced by stable placeholders, for a report
        that goes to an AI service or a third party: the tenant id and name, every email address and sign-in name,
        SharePoint and OneDrive addresses, IP addresses, administrators' names and the name of every affected object.
        Returns the redacted model and the key (value, placeholder, kind) to keep private.
    .DESCRIPTION
        Best effort, by pattern and by the names the report itself lists: a name typed into free text the report
        does not list as an object can survive. Read a redacted report before sending it. The same value always gets
        the same placeholder within one report, so the findings still read as a whole ("user-003 appears in three
        checks").
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Report)

    $ErrorActionPreference = 'Stop'
    $json = ConvertTo-Json -InputObject $Report -Depth 40 -Compress
    $map = [ordered]@{}
    $count = @{}
    # A name the catalog's own words use (a role such as Global Administrator, a product term) is not the tenant's to
    # hide, and replacing it would rewrite check titles: only names the report alone knows are replaced.
    $corpus = (@($Report.catalogText.Values | ForEach-Object { "$($_.narrative) $($_.remediation)" }) + @($Report.results | ForEach-Object { [string]$_.title })) -join ' '
    $add = {
        param([string] $Value, [string] $Kind)
        if (-not $Value -or $Value.Length -lt 3 -or $map.Contains($Value)) { return }
        if ($Kind -in 'person', 'object' -and $corpus.IndexOf($Value, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return }
        $count[$Kind] = 1 + $(if ($count.ContainsKey($Kind)) { $count[$Kind] } else { 0 })
        $map[$Value] = @{ placeholder = '{0}-{1:000}' -f $Kind, $count[$Kind]; kind = $Kind }
    }
    if ($Report.tenantId) { $map[[string]$Report.tenantId] = @{ placeholder = '00000000-0000-0000-0000-000000000000'; kind = 'tenant' } }
    foreach ($n in @($Report.tenantName, $Report.clientName, (Get-PostureValue $Report 'brand.client.name')) | Where-Object { $_ } | Sort-Object -Unique) {
        if (-not $map.Contains([string]$n)) { $map[[string]$n] = @{ placeholder = 'Tenant'; kind = 'tenant' } }
    }
    foreach ($m in [regex]::Matches($json, '[A-Za-z0-9._%+''-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')) { & $add $m.Value 'user' }
    foreach ($m in [regex]::Matches($json, 'https?://[A-Za-z0-9-]+(-my)?\.sharepoint\.(com|us|cn|de)[^"\s<>\\]*')) { & $add $m.Value 'site' }
    foreach ($m in [regex]::Matches($json, '(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])')) {
        if (@(1..4 | Where-Object { [int]$m.Groups[$_].Value -gt 255 }).Count -eq 0) { & $add $m.Value 'ip' }
    }
    foreach ($a in @($Report.admins)) { if ($a) { & $add ([string]$a.name) 'person' } }
    foreach ($r in @($Report.results)) {
        foreach ($o in @($r.affected)) {
            $n = $(if ($o -is [System.Collections.IDictionary]) { [string]$o['name'] } else { [string]$o })
            if ($n -and -not $map.Contains($n)) { & $add $n 'object' }
        }
    }
    # Site names on the overexposure chart (from the SharePoint Advanced Management import) are the tenant's own.
    if ($Report.Contains('charts') -and $Report.charts -and $Report.charts.Contains('topExposed')) { foreach ($s in @($Report.charts.topExposed.sites)) { & $add ([string]$s.name) 'site' } }
    # Longest first, so a name inside an email or an address inside a longer one is replaced as a whole.
    foreach ($value in @($map.get_Keys() | Sort-Object { - $_.Length })) {
        $escaped = (ConvertTo-Json -InputObject ([string]$value) -Compress).Trim('"')
        $pattern = $(if ($map[$value].kind -in 'person', 'object', 'tenant' -and $value -notmatch '^[0-9a-fA-F-]{36}$') { "(?<![A-Za-z0-9])$([regex]::Escape($escaped))(?![A-Za-z0-9])" } else { [regex]::Escape($escaped) })
        $json = [regex]::Replace($json, $pattern, [System.Text.RegularExpressions.MatchEvaluator] { param($m) $map[$value].placeholder })
    }
    $key = @($map.get_Keys() | ForEach-Object { [pscustomobject]@{ Placeholder = $map[$_].placeholder; Kind = $map[$_].kind; Value = $_ } })
    return @{ report = ($json | ConvertFrom-Json -AsHashtable -Depth 40); key = $key }
}
