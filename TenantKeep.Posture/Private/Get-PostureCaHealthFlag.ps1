# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureCaHealthFlag {
    <#
    .SYNOPSIS
        Health flags for one policy model, spec 5.2: report-only age, disabled age, deleted references,
        oversized exclusion groups, empty included groups, naming mismatch. Plus an empty assignment flag.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Policy,
        [Parameter(Mandatory)] [datetime] $AsOf,
        [int] $ExclusionGroupThreshold = 25,
        [int] $ReportOnlyDays = 90,
        [int] $DisabledDays = 90,
        [string] $NamePattern
    )

    $ErrorActionPreference = 'Stop'
    $flags = [System.Collections.Generic.List[object]]::new()
    $flag = { param([string] $Code, [string] $Severity, [string] $Message) $flags.Add([ordered]@{ code = $Code; severity = $Severity; message = $Message }) }

    $ageDays = if ($Policy.modified) { [int][Math]::Floor(($AsOf - $Policy.modified).TotalDays) } else { $null }

    if ($Policy.state -eq 'reportOnly' -and $null -ne $ageDays -and $ageDays -gt $ReportOnlyDays) {
        & $flag 'reportOnlyAge' 'warning' "In report-only for $ageDays days (threshold $ReportOnlyDays). Decide: enforce or delete."
    }
    if ($Policy.state -eq 'disabled' -and $null -ne $ageDays -and $ageDays -gt $DisabledDays) {
        & $flag 'disabledAge' 'warning' "Disabled for $ageDays days (threshold $DisabledDays). Delete it or document why it stays."
    }

    $allRefs = @()
    # includeGuestsOrExternal and excludeGuestsOrExternal hold the guest type object, not references.
    foreach ($k in @($Policy.assignments.Keys | Where-Object { $_ -notmatch 'GuestsOrExternal' })) { $allRefs += @($Policy.assignments[$k] | Where-Object { $_ -is [System.Collections.IDictionary] }) }
    foreach ($k in 'includeApplications', 'excludeApplications', 'userActions', 'authenticationContexts') { $allRefs += @($Policy.targets[$k]) }
    foreach ($k in 'includeLocations', 'excludeLocations') { $allRefs += @($Policy.conditions[$k]) }
    if ($Policy.grant.authenticationStrength) { $allRefs += @($Policy.grant.authenticationStrength) }
    # Some entries are plain values rather than resolved refs (a filter string, a built-in value); Get-PostureValue is safe on those.
    $deleted = @($allRefs | Where-Object { $_ -and (Get-PostureValue $_ 'deleted') -eq $true })
    foreach ($d in $deleted) {
        & $flag 'deletedReference' 'error' "References a deleted $($d.type): $($d.id). The policy silently no longer covers or excludes it."
    }

    foreach ($g in @($Policy.assignments.excludeGroups)) {
        if ($null -ne $g.memberCount -and $g.memberCount -gt $ExclusionGroupThreshold) {
            & $flag 'exclusionGroupSize' 'warning' "Exclusion group $($g.name) has $($g.memberCount) members (threshold $ExclusionGroupThreshold)."
        }
    }
    foreach ($g in @($Policy.assignments.includeGroups)) {
        if ($null -ne $g.memberCount -and $g.memberCount -eq 0) {
            & $flag 'emptyIncludedGroup' 'warning' "Included group $($g.name) is empty; the policy applies to nobody through it."
        }
    }
    foreach ($g in @($Policy.assignments.excludeGroups)) {
        if ($null -ne $g.memberCount -and $g.memberCount -eq 0) {
            & $flag 'emptyExcludedGroup' 'info' "Excluded group $($g.name) is empty; the exclusion does nothing today."
        }
    }

    $a = $Policy.assignments
    $hasAssignment = (@($a.includeUsers).Count + @($a.includeGroups).Count + @($a.includeRoles).Count + @($a.includeServicePrincipals).Count) -gt 0 -or $a.includeGuestsOrExternal
    if (-not $hasAssignment) {
        & $flag 'emptyAssignment' 'warning' 'No users, groups, roles or workload identities are included; the policy applies to nobody.'
    }

    if ($NamePattern -and $Policy.name -notmatch $NamePattern) {
        & $flag 'namingMismatch' 'info' "Name does not match the pattern $NamePattern."
    }

    return $flags.ToArray()
}
