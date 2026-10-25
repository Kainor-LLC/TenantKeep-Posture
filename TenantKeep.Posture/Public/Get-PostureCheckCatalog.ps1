# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureCheckCatalog {
    <#
    .SYNOPSIS
        Lists the checks in the catalog with their ids, domains, severities, licenses, evidence sources and framework tags.
    .DESCRIPTION
        The same list is published on the website by a build step; this is the in-module view. Add -Full for the
        narrative, remediation and pass expression as well.
    .PARAMETER Domain
        Only checks in these domains.
    .PARAMETER Id
        Only these check ids.
    .PARAMETER Full
        Include narrative, remediation, learn link, pass expression and thresholds.
    .PARAMETER CustomChecks
        Extra folders with org-specific checks.
    .EXAMPLE
        Get-PostureCheckCatalog -Domain ca | Format-Table Id, Severity, License, Title
    .EXAMPLE
        Get-PostureCheckCatalog -Id CA-003 -Full
    .OUTPUTS
        PSCustomObject per check.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string[]] $Domain,
        [string[]] $Id,
        [switch] $Full,
        [string[]] $CustomChecks = @()
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $catalog = Import-PostureCheckCatalog -CustomPath $CustomChecks
    $checks = @($catalog.checks)
    if ($Domain) { $checks = @($checks | Where-Object { [string]$_['domain'] -in $Domain }) }
    if ($Id) { $checks = @($checks | Where-Object { [string]$_['id'] -in $Id }) }

    foreach ($c in $checks) {
        $o = [ordered]@{
            Id             = [string]$c['id']
            Domain         = [string]$c['domain']
            Title          = [string]$c['title']
            Severity       = [string]$c['severityDefault']
            License        = @($c['license'])
            Evidence       = @($c['evidence'])
            Frameworks     = $c['frameworks']
            Custom         = [bool]$c['custom']
            CatalogVersion = $catalog.version
        }
        if ($Full) {
            $o.Narrative = [string]$c['narrative']
            $o.Remediation = [string]$c['remediation']
            $o.Learn = [string]$c['learn']
            $o.DeepLink = $c['deepLink']
            $o.Pass = [string]$c['pass']
            $o.Thresholds = $c['thresholds']
            $o.ApplicableWhen = $c['applicableWhen']
            $o.CoveredBy = @($c['coveredBy'])
            $o.Gate = $(if ($c.Contains('gate')) { $c['gate'] } else { $null })
        }
        [pscustomobject]$o
    }
}
