# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureNetworkFact {
    <#
    .SYNOPSIS
        Fact provider for the network domain: Global Secure Access (Entra Internet Access and Private Access). Which
        traffic forwarding profiles are on, whether internet traffic is filtered, and whether Conditional Access sees
        the original source address.
    .DESCRIPTION
        The Entra collector reads Global Secure Access only where the tenant holds Internet Access or Private Access,
        so a tenant without either has no evidence here; the checks then read as needing the licence, or as covered
        when the profile names another secure web gateway (swg) or ZTNA vendor.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [Parameter()] [System.Collections.IDictionary] $OrgProfile = @{},
        [Parameter()] [System.Collections.IDictionary] $Thresholds = @{}
    )

    $ErrorActionPreference = 'Stop'
    $load = { param([string] $Name) Read-PostureEvidenceFile -Folder $Evidence -Name $Name }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $fp = & $load 'gsa-01-forwarding-profiles'
    if ($null -eq $fp) { return @{ available = $false; reason = 'Global Secure Access was not read: the tenant holds no Internet Access or Private Access licence, or NetworkAccess.Read.All was not consented.' } }
    $facts = [ordered]@{}; $notEvaluated = @{}
    $on = { param([string] $type) @($fp | Where-Object { $_ -and [string](& $v $_ 'TrafficForwardingType') -eq $type -and [string](& $v $_ 'State') -eq 'enabled' }).Count -gt 0 }
    $facts.microsoftProfileEnabled = & $on 'm365'
    $facts.internetProfileEnabled = & $on 'internet'
    $facts.privateProfileEnabled = & $on 'private'
    $fprof = & $load 'gsa-02-filtering-profiles'
    if ($null -eq $fprof) { $notEvaluated['NET-002'] = 'gsa-02-filtering-profiles.json was not collected (check errors.txt).' }
    else { $facts.webFilteringPolicies = [int](@($fprof | Where-Object { $_ -and [string](& $v $_ 'State') -eq 'enabled' } | ForEach-Object { [int](& $v $_ 'Policies') }) + 0 | Measure-Object -Sum).Sum }
    $st = & $load 'gsa-03-settings'
    if ($null -eq $st -or $null -eq (& $v $st 'SignalingStatus')) { $notEvaluated['NET-004'] = 'The Global Secure Access signaling setting was not read (check errors.txt).' }
    else { $facts.signalingEnabled = [string](& $v $st 'SignalingStatus') -eq 'enabled' }
    return @{ available = $true; facts = $facts; affected = [ordered]@{}; notEvaluated = $notEvaluated; evidence = @('gsa-01-forwarding-profiles.json', 'gsa-02-filtering-profiles.json', 'gsa-03-settings.json') }
}
