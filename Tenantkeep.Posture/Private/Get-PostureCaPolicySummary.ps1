# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureCaPolicySummary {
    <#
    .SYNOPSIS
        One plain-English sentence for a policy model, spec 5.2:
        "Require phishing-resistant MFA for users in Global Administrator and 2 other roles, all cloud apps, any platform. Excludes BreakGlass-01, BreakGlass-02."
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Policy
    )

    $ErrorActionPreference = 'Stop'

    $listOf = {
        param([object[]] $Items, [string] $Singular, [string] $Plural)
        $names = @($Items | ForEach-Object { $_.name })
        switch ($names.Count) {
            0 { return $null }
            1 { return "$Singular $($names[0])" }
            2 { return "$Singular $($names[0]) and $($names[1])" }
            default { return "$Singular $($names[0]) and $($names.Count - 1) other $Plural" }
        }
    }
    $isBuiltIn = { param($Ref, [string] $Value) $Ref.id -eq $Value }

    # Who
    $a = $Policy.assignments
    $who = [System.Collections.Generic.List[string]]::new()
    $incUsers = @($a.includeUsers)
    if ($incUsers | Where-Object { & $isBuiltIn $_ 'All' }) { $who.Add('all users') }
    elseif ($incUsers | Where-Object { & $isBuiltIn $_ 'GuestsOrExternalUsers' }) { $who.Add('guests and external users') }
    elseif ($a.includeGuestsOrExternal) { $who.Add('guests and external users') }
    $namedUsers = @($incUsers | Where-Object { $_.type -ne 'builtIn' })
    if ($namedUsers.Count -gt 0) { $who.Add((& $listOf $namedUsers 'user' 'users')) }
    if (@($a.includeGroups).Count -gt 0) { $who.Add((& $listOf $a.includeGroups 'members of' 'groups')) }
    if (@($a.includeRoles).Count -gt 0) { $who.Add((& $listOf $a.includeRoles 'users in' 'roles')) }
    $sps = @($a.includeServicePrincipals)
    if ($sps | Where-Object { & $isBuiltIn $_ 'ServicePrincipalsInMyTenant' }) { $who.Add('all workload identities in the tenant') }
    elseif ($sps.Count -gt 0) { $who.Add((& $listOf $sps 'workload identity' 'workload identities')) }
    $whoText = if ($who.Count -gt 0) { $who -join ', ' } else { 'no one (empty assignment)' }

    # What (apps, actions, contexts)
    $t = $Policy.targets
    $what = [System.Collections.Generic.List[string]]::new()
    $incApps = @($t.includeApplications)
    if ($incApps | Where-Object { & $isBuiltIn $_ 'All' }) { $what.Add('all cloud apps') }
    if ($incApps | Where-Object { & $isBuiltIn $_ 'Office365' }) { $what.Add('Office 365') }
    if ($incApps | Where-Object { & $isBuiltIn $_ 'MicrosoftAdminPortals' }) { $what.Add('Microsoft admin portals') }
    $namedApps = @($incApps | Where-Object { $_.type -ne 'builtIn' -and $_.id -ne 'None' })
    if ($namedApps.Count -gt 0) { $what.Add((& $listOf $namedApps '' 'apps').Trim()) }
    if (@($t.userActions).Count -gt 0) { $what.Add("the action '$(@($t.userActions | ForEach-Object { $_.name.ToLowerInvariant() }) -join "', '")'") }
    if (@($t.authenticationContexts).Count -gt 0) { $what.Add("authentication context $(@($t.authenticationContexts | ForEach-Object { $_.name }) -join ', ')") }
    $whatText = if ($what.Count -gt 0) { $what -join ', ' } else { 'no target resources' }
    $excApps = @($t.excludeApplications)
    if ($excApps.Count -gt 0) { $whatText += " except $(@($excApps | ForEach-Object { $_.name }) -join ', ')" }

    # Where and how
    $c = $Policy.conditions
    $tail = [System.Collections.Generic.List[string]]::new()
    if (@($c.includePlatforms).Count -eq 0) { $tail.Add('any platform') }
    else {
        $plat = "on $(@($c.includePlatforms) -join ', ')"
        if (@($c.excludePlatforms).Count -gt 0) { $plat += " except $(@($c.excludePlatforms) -join ', ')" }
        $tail.Add($plat)
    }
    $incLoc = @($c.includeLocations); $excLoc = @($c.excludeLocations)
    if ($incLoc.Count -gt 0) {
        $loc = if ($incLoc | Where-Object { & $isBuiltIn $_ 'All' }) { 'from any location' } else { "from $(@($incLoc | ForEach-Object { $_.name }) -join ', ')" }
        if ($excLoc.Count -gt 0) {
            $excNames = @($excLoc | ForEach-Object { if (& $isBuiltIn $_ 'AllTrusted') { 'trusted locations' } else { $_.name } })
            $loc += " except $($excNames -join ', ')"
        }
        $tail.Add($loc)
    }
    $clientTypes = @($c.clientAppTypes | Where-Object { $_ })
    $legacy = @('exchangeActiveSync', 'other')
    if ($clientTypes.Count -gt 0 -and $clientTypes -notcontains 'all') {
        if (@($clientTypes | Where-Object { $_ -notin $legacy }).Count -eq 0) { $tail.Add('for legacy authentication clients') }
        elseif (@($clientTypes | Where-Object { $_ -in $legacy }).Count -eq 0) { $tail.Add('for browsers and modern clients') }
        else { $tail.Add("for client types $($clientTypes -join ', ')") }
    }
    if (@($c.signInRiskLevels).Count -gt 0) { $tail.Add("when sign-in risk is $(@($c.signInRiskLevels) -join ' or ')") }
    if (@($c.userRiskLevels).Count -gt 0) { $tail.Add("when user risk is $(@($c.userRiskLevels) -join ' or ')") }
    if ($c.deviceFilter) { $tail.Add("with a device filter ($($c.deviceFilter.mode))") }

    # Action
    $g = $Policy.grant
    $controlLabel = @{
        block = 'Block access'; mfa = 'Require MFA'; compliantDevice = 'Require a compliant device'
        domainJoinedDevice = 'Require a hybrid-joined device'; approvedApplication = 'Require an approved client app'
        compliantApplication = 'Require an app protection policy'; passwordChange = 'Require a password change'
        unknownFutureValue = 'Require an unknown control'
    }
    $actions = [System.Collections.Generic.List[string]]::new()
    foreach ($ctl in @($g.builtInControls)) { $actions.Add($(if ($controlLabel.ContainsKey($ctl)) { $controlLabel[$ctl] } else { "Require $ctl" })) }
    if ($g.authenticationStrength) { $actions.Add("Require $($g.authenticationStrength.name)") }
    if (@($g.termsOfUse).Count -gt 0) { $actions.Add('Require terms of use') }
    $joiner = if ($g.operator -eq 'AND') { ' and ' } else { ' or ' }
    $action = if ($actions.Count -gt 0) {
        if ($actions.Count -eq 1) { $actions[0] }
        else { $actions[0] + $joiner + (@($actions | Select-Object -Skip 1 | ForEach-Object { $_.Substring(0, 1).ToLowerInvariant() + $_.Substring(1) }) -join $joiner) }
    }
    elseif ($Policy.session.signInFrequency -or $Policy.session.persistentBrowser -or $Policy.session.applicationEnforcedRestrictions -or $Policy.session.cloudAppSecurity) { 'Apply session controls' }
    else { 'Grant access with no controls' }

    $sentence = "$action for $whoText, $whatText, $($tail -join ', ')."

    # Exclusions
    $excl = [System.Collections.Generic.List[string]]::new()
    foreach ($u in @($a.excludeUsers)) { $excl.Add($u.name) }
    foreach ($gr in @($a.excludeGroups)) { $excl.Add($(if ($null -ne $gr.memberCount) { "$($gr.name) ($($gr.memberCount) members)" } else { $gr.name })) }
    foreach ($r in @($a.excludeRoles)) { $excl.Add("role $($r.name)") }
    foreach ($sp in @($a.excludeServicePrincipals)) { $excl.Add($sp.name) }
    if ($excl.Count -gt 0) { $sentence += " Excludes $($excl -join ', ')." }

    $prefix = switch ($Policy.state) { 'reportOnly' { 'Report-only: ' } 'disabled' { 'Disabled: ' } default { '' } }
    return $prefix + $sentence
}
