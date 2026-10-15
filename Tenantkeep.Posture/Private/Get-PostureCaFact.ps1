# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureCaFact {
    <#
    .SYNOPSIS
        Fact provider for the Conditional Access domain (spec 4.3). Reads an Export-PostureCaSnapshot folder.
    .DESCRIPTION
        Called once per run by the check engine. Returns facts (numbers, booleans, lists) that the checks/ca.json pass
        expressions compare against thresholds, plus the affected-object lists behind them. Thresholds read:
        maxExclusionGroupMembers, reportOnlyMaxDays, disabledMaxDays, namePattern. Profile read: breakGlass (UPNs or
        display names), platforms, thresholds.namePattern.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [Parameter()] [System.Collections.IDictionary] $OrgProfile = @{},
        [Parameter()] [System.Collections.IDictionary] $Thresholds = @{}
    )

    $ErrorActionPreference = 'Stop'

    $required = 'policies', 'metadata', 'resolved-names'
    if (@($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $Evidence "$_.json")) }).Count -gt 0) {
        return @{ available = $false; reason = "No Conditional Access snapshot in $Evidence (run Export-PostureCaSnapshot)." }
    }
    $snap = Import-PostureCaSnapshot -Path $Evidence
    $t = @{ maxExclusionGroupMembers = 25; reportOnlyMaxDays = 90; disabledMaxDays = 90; namePattern = $null }
    foreach ($k in @($Thresholds.Keys)) { $t[$k] = $Thresholds[$k] }
    $namePattern = $t.namePattern
    if (-not $namePattern -and $OrgProfile.Contains('thresholds') -and $OrgProfile.thresholds -and $OrgProfile.thresholds.Contains('namePattern')) { $namePattern = $OrgProfile.thresholds.namePattern }
    $modelParams = @{ Snapshot = $snap; ExclusionGroupThreshold = [int]$t.maxExclusionGroupMembers; ReportOnlyDays = [int]$t.reportOnlyMaxDays; DisabledDays = [int]$t.disabledMaxDays }
    if ($namePattern) { $modelParams.NamePattern = [string]$namePattern }
    $policies = @(ConvertTo-PostureCaPolicyModel @modelParams)
    $enabled = @($policies | Where-Object { $_.state -eq 'enabled' })

    # Break-glass accounts: from the profile, else any excluded user or group whose name says so.
    $bgNames = @($OrgProfile['breakGlass'] | Where-Object { $_ })
    $isBreakGlass = {
        param($Ref)
        if ($bgNames.Count -gt 0) { return [bool]($bgNames | Where-Object { $_ -eq $Ref.name -or $_ -eq (Get-PostureValue $Ref 'userPrincipalName') }) }
        return ([string]$Ref.name -match '(?i)break.?glass|emergency') -or ([string](Get-PostureValue $Ref 'userPrincipalName') -match '(?i)break.?glass|emergency')
    }
    $bgFound = @{}
    foreach ($p in $policies) { foreach ($r in @($p.assignments.excludeUsers) + @($p.assignments.excludeGroups)) { if (& $isBreakGlass $r) { $bgFound[$r.id] = $r.name } } }
    $breakGlassIdentified = ($bgNames.Count -gt 0) -or ($bgFound.Count -gt 0)

    $has = { param($Refs, [string] $Id) [bool]@(@($Refs) | Where-Object { $_ -and $_.id -eq $Id }) }
    $allUsers = { param($p) & $has $p.assignments.includeUsers 'All' }
    $allApps = { param($p) & $has $p.targets.includeApplications 'All' }
    $office365OrAll = { param($p) (& $has $p.targets.includeApplications 'All') -or (& $has $p.targets.includeApplications 'Office365') }
    $legacyOnly = { param($p) $types = @($p.conditions.clientAppTypes); $types.Count -gt 0 -and @($types | Where-Object { $_ -notin @('exchangeActiveSync', 'other') }).Count -eq 0 }
    $blocks = { param($p) @($p.grant.builtInControls) -contains 'block' }
    $mfaLevel = { param($p) Get-PostureCaStrengthLevel -Policy $p }
    $groupsNarrow = { param($p) @(@($p.assignments.excludeGroups) | Where-Object { $null -ne $_.memberCount -and $_.memberCount -gt [int]$t.maxExclusionGroupMembers }).Count -eq 0 }
    $breakGlassOnly = {
        param($p)
        $users = @($p.assignments.excludeUsers); $groups = @($p.assignments.excludeGroups)
        @($p.assignments.excludeRoles).Count -eq 0 -and
        @($users | Where-Object { -not (& $isBreakGlass $_) }).Count -eq 0 -and
        @($groups | Where-Object { -not (& $isBreakGlass $_) }).Count -eq 0
    }
    $label = { param($p, [string] $detail) [ordered]@{ name = $p.name; id = $p.id; detail = $detail } }

    $facts = [ordered]@{}
    $affected = [ordered]@{}
    $notEvaluated = @{}

    # CA-001 legacy auth
    $legacyBlock = @($enabled | Where-Object { (& $blocks $_) -and (& $legacyOnly $_) -and (& $allUsers $_) })
    $facts.legacyAuthBlockPolicies = @($legacyBlock | Where-Object { & $groupsNarrow $_ }).Count
    $affected.legacyAuthBroadExclusions = @($legacyBlock | Where-Object { -not (& $groupsNarrow $_) } | ForEach-Object { & $label $_ 'blocks legacy auth but excludes a group over the threshold' })

    # CA-002 MFA for all users
    $mfaAll = @($enabled | Where-Object { (& $allUsers $_) -and (& $allApps $_) -and (& $mfaLevel $_) -ge 1 })
    $facts.mfaAllUsersPolicies = @($mfaAll | Where-Object { & $breakGlassOnly $_ }).Count
    $affected.mfaAllUsersWithExtraExclusions = @($mfaAll | Where-Object { -not (& $breakGlassOnly $_) } | ForEach-Object { & $label $_ "excludes more than break-glass: $(@(@($_.assignments.excludeUsers) + @($_.assignments.excludeGroups) + @($_.assignments.excludeRoles) | Where-Object { -not (& $isBreakGlass $_) } | ForEach-Object { $_.name }) -join ', ')" })

    # CA-003 phishing-resistant for admin roles (verify: Microsoft's recommended 14 roles)
    $adminRoles = @('Global Administrator', 'Application Administrator', 'Authentication Administrator', 'Billing Administrator', 'Cloud Application Administrator',
        'Conditional Access Administrator', 'Exchange Administrator', 'Helpdesk Administrator', 'Password Administrator', 'Privileged Authentication Administrator',
        'Privileged Role Administrator', 'Security Administrator', 'SharePoint Administrator', 'User Administrator')
    $phish = @($enabled | Where-Object { (& $mfaLevel $_) -ge 3 -and (& $allApps $_) })
    $coveredRoles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $phish) {
        if ((& $allUsers $p) -and @($p.assignments.excludeRoles).Count -eq 0) { foreach ($r in $adminRoles) { $null = $coveredRoles.Add($r) } }
        foreach ($r in @($p.assignments.includeRoles)) { $null = $coveredRoles.Add([string]$r.name) }
    }
    $facts.adminRolesTotal = $adminRoles.Count
    $facts.adminRolesPhishingResistant = @($adminRoles | Where-Object { $coveredRoles.Contains($_) }).Count
    $affected.adminRolesWithoutPhishingResistant = @($adminRoles | Where-Object { -not $coveredRoles.Contains($_) } | ForEach-Object { [ordered]@{ name = $_; detail = 'no enabled policy requires phishing-resistant MFA for this role' } })

    # CA-004 risk policies
    $facts.signInRiskPolicies = @($enabled | Where-Object { @($_.conditions.signInRiskLevels).Count -gt 0 -and ((& $mfaLevel $_) -ge 1 -or (& $blocks $_)) }).Count
    $facts.userRiskPolicies = @($enabled | Where-Object { @($_.conditions.userRiskLevels).Count -gt 0 -and ((& $mfaLevel $_) -ge 1 -or (& $blocks $_) -or @($_.grant.builtInControls) -contains 'passwordChange') }).Count

    # CA-005 device compliance for Office 365 on the desktop platforms in scope
    $platformsInScope = @($OrgProfile['platforms'] | Where-Object { $_ -in @('windows', 'macOS') })
    if ($platformsInScope.Count -eq 0) { $platformsInScope = @('windows', 'macOS') }
    $compliance = @($enabled | Where-Object { @($_.grant.builtInControls | Where-Object { $_ -in @('compliantDevice', 'domainJoinedDevice') }).Count -gt 0 -and (& $office365OrAll $_) -and (& $allUsers $_) })
    $coveredPlatforms = @($platformsInScope | Where-Object { $plat = $_; @($compliance | Where-Object { @($_.conditions.includePlatforms).Count -eq 0 -or @($_.conditions.includePlatforms) -contains 'all' -or @($_.conditions.includePlatforms) -contains $plat }).Count -gt 0 })
    $facts.devicePlatformsRequired = $platformsInScope.Count
    $facts.devicePlatformsWithCompliance = $coveredPlatforms.Count
    $affected.devicePlatformsWithoutCompliance = @($platformsInScope | Where-Object { $_ -notin $coveredPlatforms } | ForEach-Object { [ordered]@{ name = $_; detail = 'no enabled policy requires a compliant device for Office 365 on this platform' } })

    # CA-006, CA-014 pileups from the model's health flags
    $affected.reportOnlyOverThreshold = @($policies | Where-Object { $_.healthFlags | Where-Object { $_.code -eq 'reportOnlyAge' } } | ForEach-Object { & $label $_ (($_.healthFlags | Where-Object { $_.code -eq 'reportOnlyAge' }).message) })
    $facts.reportOnlyOverThreshold = $affected.reportOnlyOverThreshold.Count
    $affected.disabledOverThreshold = @($policies | Where-Object { $_.healthFlags | Where-Object { $_.code -eq 'disabledAge' } } | ForEach-Object { & $label $_ (($_.healthFlags | Where-Object { $_.code -eq 'disabledAge' }).message) })
    $facts.disabledOverThreshold = $affected.disabledOverThreshold.Count

    # CA-007 exclusion groups over the threshold, de-duplicated by group
    $big = @{}
    foreach ($p in $policies) {
        foreach ($g in @($p.assignments.excludeGroups)) {
            if ($null -ne $g.memberCount -and $g.memberCount -gt [int]$t.maxExclusionGroupMembers) {
                if (-not $big.ContainsKey($g.id)) { $big[$g.id] = [ordered]@{ name = $g.name; id = $g.id; memberCount = $g.memberCount; policies = @() } }
                $big[$g.id].policies += $p.name
            }
        }
    }
    $affected.exclusionGroupsOverThreshold = @($big.Values | ForEach-Object { $_.detail = "$($_.memberCount) members, excluded from: $($_.policies -join ', ')"; $_ } | Sort-Object { $_.name })
    $facts.exclusionGroupsOverThreshold = $affected.exclusionGroupsOverThreshold.Count

    # CA-008 trusted-location bypass on MFA policies
    $trustedIds = @($snap.NamedLocations | Where-Object { Get-PostureValue $_ 'isTrusted' } | ForEach-Object { [string]$_.id })
    $bypass = @($enabled | Where-Object { (& $mfaLevel $_) -ge 1 -and @(@($_.conditions.excludeLocations) | Where-Object { $_.id -eq 'AllTrusted' -or $_.id -in $trustedIds }).Count -gt 0 })
    $affected.trustedLocationMfaBypass = @($bypass | ForEach-Object { & $label $_ "skips MFA from: $(@($_.conditions.excludeLocations | ForEach-Object { $_.name }) -join ', ')" })
    $facts.trustedLocationMfaBypass = $affected.trustedLocationMfaBypass.Count

    # CA-009 admin session controls
    $facts.adminSessionControlPolicies = @($enabled | Where-Object {
            @($_.assignments.includeRoles).Count -gt 0 -and $_.session.signInFrequency -and (Get-PostureValue $_.session.signInFrequency 'isEnabled') -and
            $_.session.persistentBrowser -and (Get-PostureValue $_.session.persistentBrowser 'isEnabled') -and (Get-PostureValue $_.session.persistentBrowser 'mode') -eq 'never'
        }).Count

    # CA-010 token protection
    $facts.tokenProtectionPolicies = @($policies | Where-Object { $_.state -in @('enabled', 'reportOnly') -and $_.session.secureSignInSession -and (Get-PostureValue $_.session.secureSignInSession 'isEnabled') }).Count

    # CA-011 Microsoft-managed policies
    $managed = @($policies | Where-Object { $_.name -like 'Microsoft-managed:*' })
    $facts.microsoftManagedPolicies = $managed.Count
    $affected.microsoftManagedDisabled = @($managed | Where-Object { $_.state -eq 'disabled' } | ForEach-Object { & $label $_ 'Microsoft-managed policy is disabled' })
    $facts.microsoftManagedDisabled = $affected.microsoftManagedDisabled.Count

    # CA-012 break-glass excluded from every blocking policy
    $facts.breakGlassIdentified = $breakGlassIdentified
    $blocking = @($enabled | Where-Object { & $blocks $_ })
    $affected.blockPoliciesMissingBreakGlass = @($blocking | Where-Object { @(@($_.assignments.excludeUsers) + @($_.assignments.excludeGroups) | Where-Object { & $isBreakGlass $_ }).Count -eq 0 } | ForEach-Object { & $label $_ 'blocks access without excluding a break-glass account or group' })
    $facts.blockPoliciesMissingBreakGlass = $affected.blockPoliciesMissingBreakGlass.Count
    $facts.blockPolicies = $blocking.Count

    # CA-013 deleted references
    $affected.policiesWithDeletedReferences = @($policies | Where-Object { $_.healthFlags | Where-Object { $_.code -eq 'deletedReference' } } | ForEach-Object { & $label $_ ((@($_.healthFlags | Where-Object { $_.code -eq 'deletedReference' } | ForEach-Object { $_.message })) -join ' ') })
    $facts.policiesWithDeletedReferences = $affected.policiesWithDeletedReferences.Count

    # CA-015 naming
    $facts.namingPatternConfigured = [bool]$namePattern
    if ($namePattern) {
        $affected.namingNonConforming = @($policies | Where-Object { $_.healthFlags | Where-Object { $_.code -eq 'namingMismatch' } } | ForEach-Object { & $label $_ "does not match $namePattern" })
        $facts.namingNonConforming = $affected.namingNonConforming.Count
    }
    else {
        # No pattern configured: look for a convention in the names themselves. A structured name starts with a short
        # prefix and a number, or an upper-case tag, followed by a separator (CA-001-..., CA01 ..., GRANT-...). Eight in ten
        # or more names structured counts as a convention; the rest are the finding either way. Connor, 2026-10-15: a
        # tenant without a convention is a finding, not an unevaluated check.
        $structured = '^([A-Za-z]{1,8}[-_ ]?\d{1,4}[-_ :]|[A-Z]{2,8}[-_:])'
        $named = @($policies | Where-Object { $_.name -cmatch $structured })   # case-sensitive: an upper-case tag, not a word like Sign-in
        $facts.namingConventionDetected = ($policies.Count -ge 3 -and $named.Count -ge [Math]::Ceiling(0.8 * $policies.Count))
        $affected.namingNonConforming = @($policies | Where-Object { $_.name -cnotmatch $structured } | ForEach-Object { & $label $_ $(if ($facts.namingConventionDetected) { 'does not follow the convention most policies use' } else { 'no naming convention: free text name' }) })
        $facts.namingNonConforming = $affected.namingNonConforming.Count
    }

    $facts.policyCount = $policies.Count
    $facts.enabledPolicyCount = $enabled.Count

    return @{
        available    = $true
        facts        = $facts
        affected     = $affected
        notEvaluated = $notEvaluated
        evidence     = @('policies.json', 'named-locations.json', 'auth-strengths.json', 'resolved-names.json', 'group-scope.json')
    }
}
