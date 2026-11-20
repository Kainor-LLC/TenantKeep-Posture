# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureExperienceFact {
    <#
    .SYNOPSIS
        Fact provider for the user experience domain: how smoothly people sign in, get a new device and find their
        files, and whether the directory reads the way they expect. Improvements, not security gaps.
    .DESCRIPTION
        Reads the Intune settings catalog (OneDrive, Edge), the enrollment configurations (Enrollment Status Page,
        Windows settings restore), Autopilot profiles, company branding, the Conditional Access snapshot, the
        registration report and the user list. Thresholds read: minSsprEnabledPct, minSignInFrequencyHours.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [Parameter()] [System.Collections.IDictionary] $OrgProfile = @{},
        [Parameter()] [System.Collections.IDictionary] $Thresholds = @{}
    )

    $ErrorActionPreference = 'Stop'
    $t = @{ minSsprEnabledPct = 95; minSignInFrequencyHours = 24 }
    foreach ($k in @($Thresholds.Keys)) { $t[$k] = $Thresholds[$k] }
    $load = { param([string] $Name) Read-PostureEvidenceFile -Folder $Evidence -Name $Name }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $rows = { param($o) @($o | Where-Object { $_ }) }
    $has = { param($o, [string] $k) if ($o -is [System.Collections.IDictionary]) { $o.Contains($k) } elseif ($o) { $null -ne $o.PSObject.Properties[$k] } else { $false } }
    # The domain is about people and devices: without the user, registration, Intune or branding evidence, a CA
    # snapshot alone is not an experience assessment.
    if (@('06-users', '05-auth-registration', '09-intune-policy-settings', '01-company-branding' | Where-Object { Test-Path -LiteralPath (Join-Path $Evidence "$_.json") }).Count -eq 0) {
        return @{ available = $false; reason = 'No Entra or Intune evidence in the folder (Invoke-PostureCollection -Collector Entra, Intune).' }
    }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    $before = { param([string[]] $Ids, [string] $File, [string] $Collector) foreach ($id in $Ids) { $notEvaluated[$id] = "$File.json was collected before TenantKeep read what this check needs. Collect $Collector again (Resume-PostureRun -Collector $Collector)." } }
    $missing = { param([string[]] $Ids, [string] $File, [string] $Collector) foreach ($id in $Ids) { $notEvaluated[$id] = "$File.json was not collected (the $Collector collector; check errors.txt)." } }

    # OneDrive and Edge from the settings catalog: a setting counts when its policy is assigned and its choice is on.
    $settings = & $load '09-intune-policy-settings'; $catalog = & $load '09-intune-config-profiles-settings-catalog'
    if ($null -eq $settings -or $null -eq $catalog) { & $missing @('UX-001', 'UX-002') '09-intune-policy-settings' 'Intune' }
    else {
        $assigned = @{}; foreach ($p in & $rows $catalog) { if ([int](& $v $p 'Assignments') -gt 0) { $assigned[[string](& $v $p 'Id')] = $true } }
        $live = @(& $rows $settings | Where-Object { $assigned.ContainsKey([string](& $v $_ 'PolicyId')) })
        $on = { param([string] $pattern) @($live | Where-Object { [string](& $v $_ 'SettingDefinitionId') -match $pattern -and [string](& $v $_ 'Value') -match '_1$' }).Count -gt 0 }
        $facts.onedriveSilentSignIn = & $on 'onedrivengsc_silentaccountconfig$'
        $facts.onedriveSilentFolderMove = & $on 'onedrivengsc_(kfmsilentoptin|kfmoptinnowizard)$'
        $disabledEdge = @($live | Where-Object { [string](& $v $_ 'SettingDefinitionId') -match 'microsoft_edge.*_browsersignin$' -and [string](& $v $_ 'Value') -match '_0$' })
        $facts.edgeSignInDisabledPolicies = $disabledEdge.Count
        $affected.edgeSignInDisabledPolicies = @($disabledEdge | ForEach-Object { [ordered]@{ name = [string](& $v $_ 'PolicyName'); detail = 'Browser sign-in is disabled' } })
    }

    # The Enrollment Status Page and Windows settings restore, from the enrollment configurations.
    $enroll = & $load '09-intune-enrollment-restrictions'
    if ($null -eq $enroll) { & $missing @('UX-003', 'UX-004') '09-intune-enrollment-restrictions' 'Intune' }
    else {
        $esp = @(& $rows $enroll | Where-Object { [string](& $v $_ 'Type') -eq 'windows10EnrollmentCompletionPageConfiguration' -and [int](& $v $_ 'Assignments') -gt 0 })
        if ($esp.Count -and -not (& $has $esp[0] 'ShowInstallationProgress')) { & $before @('UX-003') '09-intune-enrollment-restrictions' 'Intune' }
        else { $facts.espShowsProgress = @($esp | Where-Object { (& $v $_ 'ShowInstallationProgress') -eq $true }).Count -gt 0 }
        $restore = @(& $rows $enroll | Where-Object { [string](& $v $_ 'Type') -eq 'windowsRestoreDeviceEnrollmentConfiguration' })
        if ($restore.Count -and -not (& $has $restore[0] 'State')) { & $before @('UX-004') '09-intune-enrollment-restrictions' 'Intune' }
        else { $facts.windowsRestoreOn = @($restore | Where-Object { [string](& $v $_ 'State') -eq 'enabled' }).Count -gt 0 }
    }

    # Autopilot profiles: every assigned one names devices by a template.
    $ap = & $load '09-autopilot-profiles'
    if ($null -eq $ap) { & $missing @('UX-005') '09-autopilot-profiles' 'Intune' }
    else {
        $noName = @(& $rows $ap | Where-Object { [int](& $v $_ 'Assignments') -gt 0 -and -not [string](& $v $_ 'DeviceNameTemplate') })
        $facts.autopilotProfilesWithoutNameTemplate = $noName.Count
        $affected.autopilotProfilesWithoutNameTemplate = @($noName | ForEach-Object { [ordered]@{ name = [string](& $v $_ 'DisplayName'); detail = 'no device name template' } })
    }

    # Company branding: the logo and a line of text on the sign-in page.
    $brand = & $load '01-company-branding'
    if ($null -eq $brand) { & $missing @('UX-006') '01-company-branding' 'Entra' }
    else { $facts.signInPageBranded = [bool]((& $v $brand 'Present') -eq $true -and ((& $v $brand 'HasBannerLogo') -eq $true -or (& $v $brand 'HasSquareLogo') -eq $true) -and (& $v $brand 'HasSignInText') -eq $true) }

    # Sign-in frequency on policies for everyone, all the time, for every app: shorter than a working day means
    # prompts all day. Left out because short is right there: admin roles, sign-in and user risk (Microsoft recommends
    # every time), user actions and authentication contexts, and policies on particular apps.
    $pol = & $load 'policies'
    if ($null -eq $pol) { & $missing @('UX-007') 'policies' 'Conditional Access snapshot' }
    else {
        $items = @($(if ($pol -is [System.Collections.IDictionary] -and $pol.Contains('value')) { $pol['value'] } else { $pol }) | Where-Object { $_ })
        $short = @($items | Where-Object {
                $f = & $v $_ 'sessionControls.signInFrequency'
                [string](& $v $_ 'state') -eq 'enabled' -and $f -and (& $v $f 'isEnabled') -eq $true -and
                @(& $v $_ 'conditions.users.includeUsers') -contains 'All' -and @(& $v $_ 'conditions.users.includeRoles' | Where-Object { $_ }).Count -eq 0 -and
                @(& $v $_ 'conditions.signInRiskLevels' | Where-Object { $_ }).Count -eq 0 -and @(& $v $_ 'conditions.userRiskLevels' | Where-Object { $_ }).Count -eq 0 -and
                @(& $v $_ 'conditions.applications.includeUserActions' | Where-Object { $_ }).Count -eq 0 -and @(& $v $_ 'conditions.applications.includeAuthenticationContextClassReferences' | Where-Object { $_ }).Count -eq 0 -and
                @(& $v $_ 'conditions.applications.includeApplications') -contains 'All' -and
                ([string](& $v $f 'frequencyInterval') -eq 'everyTime' -or ([string](& $v $f 'type') -eq 'hours' -and [int](& $v $f 'value') -lt [int]$t.minSignInFrequencyHours))
            })
        $facts.shortSignInFrequencyPolicies = $short.Count
        $affected.shortSignInFrequencyPolicies = @($short | ForEach-Object { $f = & $v $_ 'sessionControls.signInFrequency'; [ordered]@{ name = [string](& $v $_ 'displayName'); detail = $(if ([string](& $v $f 'frequencyInterval') -eq 'everyTime') { 'every time' } else { "every $(& $v $f 'value') hours" }) } })
    }

    # Self-service password reset: members the policy lets reset their own password.
    $reg = & $load '05-auth-registration'
    if ($null -eq $reg) { & $missing @('UX-008') '05-auth-registration' 'Entra' }
    else {
        $members = @(& $rows $reg | Where-Object { [string](& $v $_ 'UserType') -ne 'guest' })
        $enabled = @($members | Where-Object { Test-PostureTrue (& $v $_ 'IsSsprEnabled') }).Count
        $facts.ssprEnabledPct = $(if ($members.Count) { [Math]::Round(100.0 * $enabled / $members.Count, 1) } else { 100 })
    }

    # The directory as people read it: sign-in name and email the same, display names First Last. A row at a time.
    $upn = [System.Collections.Generic.List[object]]::new(); $lastFirst = [System.Collections.Generic.List[object]]::new()
    $state = @{ hasMail = $null; members = 0; upnCount = 0; nameCount = 0 }
    $read = Read-PostureEvidenceRow -Folder $Evidence -Name '06-users' -OnRow {
        param($u)
        if ($null -eq $state.hasMail) { $state.hasMail = (& $has $u 'Mail') }
        if (-not $state.hasMail) { return }
        if ([string](& $v $u 'UserType') -ne 'Member' -or -not (Test-PostureTrue (& $v $u 'AccountEnabled'))) { return }
        $state.members++
        $name = [string](& $v $u 'UserPrincipalName'); $mail = [string](& $v $u 'Mail')
        if ($mail -and -not [string]::Equals($mail, $name, [System.StringComparison]::OrdinalIgnoreCase)) { $state.upnCount++; if ($upn.Count -lt 500) { $upn.Add([ordered]@{ name = $name; detail = "email $mail" }) } }
        $dn = [string](& $v $u 'DisplayName'); $sn = [string](& $v $u 'Surname')
        $reversed = $(if ($sn) { $dn -match ('^\s*' + [regex]::Escape($sn) + '\s*,') } else { $dn -match '^[^\s,]+,\s*\S' })
        if ($reversed) { $state.nameCount++; if ($lastFirst.Count -lt 500) { $lastFirst.Add([ordered]@{ name = $dn; detail = $name }) } }
    }
    if (-not $read) { & $missing @('UX-009', 'UX-010') '06-users' 'Entra' }
    elseif ($state.hasMail -eq $false) { & $before @('UX-009', 'UX-010') '06-users' 'Entra' }
    else {
        $facts.upnEmailMismatches = $state.upnCount; $affected.upnEmailMismatches = @($upn)
        $facts.lastFirstDisplayNames = $state.nameCount; $affected.lastFirstDisplayNames = @($lastFirst)
    }

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('09-intune-policy-settings.json', '09-intune-enrollment-restrictions.json', '01-company-branding.json', '06-users.json') }
}
