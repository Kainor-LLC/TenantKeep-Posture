# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureSecureScoreCheck {
    <#
    .SYNOPSIS
        The catalog checks that judge the same setting as a Microsoft Secure Score action, with this run's answer.
    .DESCRIPTION
        A check names the Secure Score actions it overlaps in references.secureScore, by Microsoft's control id.
        Returns a map from control id (case ignored) to the checks that name it, each with id, title and status.
        A check with no result in this run (outside the licence tier, or not in the baseline) is left out, so a
        link in the report always has a check to open.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Catalog,
        [object[]] $Result = @()
    )

    $ErrorActionPreference = 'Stop'
    $statusOf = @{}
    foreach ($r in $Result) { if ($r) { $statusOf[[string]$r.id] = [string]$r.status } }
    $map = @{}
    foreach ($check in @($Catalog['checks'])) {
        if (-not $check -or -not $check.Contains('references') -or -not $check['references']) { continue }
        $references = $check['references']
        if (-not ($references -is [System.Collections.IDictionary]) -or -not $references.Contains('secureScore')) { continue }
        $id = [string]$check['id']
        if (-not $statusOf.ContainsKey($id)) { continue }
        foreach ($control in @($references['secureScore'])) {
            $key = [string]$control
            if (-not $key) { continue }
            if (-not $map.ContainsKey($key)) { $map[$key] = [System.Collections.Generic.List[object]]::new() }
            $map[$key].Add([ordered]@{ id = $id; title = [string]$check['title']; status = $statusOf[$id] })
        }
    }
    $map
}

function Get-PostureSecureScoreProduct {
    <#
    .SYNOPSIS
        The product a Secure Score action belongs to, as a name a reader knows.
    .DESCRIPTION
        Microsoft names the product with a short code in the action's service field (verify: the codes below are
        the ones seen; a code not listed is shown as Microsoft wrote it). Evidence collected before the field was
        saved has none, and the action's category stands in.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string] $Service, [string] $Category)

    $names = @{
        'AzureAD' = 'Microsoft Entra ID'; 'AAD' = 'Microsoft Entra ID'; 'Entra' = 'Microsoft Entra ID'
        'MDO' = 'Defender for Office 365'; 'EXO' = 'Exchange Online'; 'SPO' = 'SharePoint and OneDrive'
        'MDE' = 'Defender for Endpoint'; 'MDATP' = 'Defender for Endpoint'
        'MDI' = 'Defender for Identity'; 'AATP' = 'Defender for Identity'; 'Azure ATP' = 'Defender for Identity'
        'MCAS' = 'Defender for Cloud Apps'; 'MDA' = 'Defender for Cloud Apps'
        'MIP' = 'Microsoft Purview'; 'MS Teams' = 'Microsoft Teams'; 'MSTeams' = 'Microsoft Teams'; 'Teams' = 'Microsoft Teams'
        'AppG' = 'App governance'
    }
    $code = ([string]$Service).Trim()
    if ($code) { if ($names.ContainsKey($code)) { return $names[$code] } else { return $code } }
    $fallback = ([string]$Category).Trim()
    if ($fallback) { return $fallback }
    'Other'
}
