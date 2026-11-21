# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureExperienceFact {
    <#
    .SYNOPSIS
        Fact provider for the user experience domain: how smoothly people sign in, get a new device and find their
        files, and whether the directory reads the way they expect. Improvements, not security gaps.
    .DESCRIPTION
        Reads the Intune settings catalog (OneDrive, Edge), the enrollment configurations (Enrollment Status Page,
        Windows settings restore), Autopilot profiles, company branding, the Conditional Access snapshot, the
        registration report and the user list, the authentication methods policy, update rings, app protection, groups
        and Exchange Online's mail settings. Thresholds read: minSsprEnabledPct, minSignInFrequencyHours,
        minProfileCompletePct, minUpdateGraceDays.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [Parameter()] [System.Collections.IDictionary] $OrgProfile = @{},
        [Parameter()] [System.Collections.IDictionary] $Thresholds = @{}
    )

    $ErrorActionPreference = 'Stop'
    $t = @{ minSsprEnabledPct = 95; minSignInFrequencyHours = 24; minProfileCompletePct = 80; minUpdateGraceDays = 1 }
    foreach ($k in @($Thresholds.Keys)) { $t[$k] = $Thresholds[$k] }
    $load = { param([string] $Name) Read-PostureEvidenceFile -Folder $Evidence -Name $Name }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $rows = { param($o) @($o | Where-Object { $_ }) }
    $has = { param($o, [string] $k) if ($o -is [System.Collections.IDictionary]) { $o.Contains($k) } elseif ($o) { $null -ne $o.PSObject.Properties[$k] } else { $false } }
    # The domain is about people and devices: without the user, registration, Intune or branding evidence, a CA
    # snapshot alone is not an experience assessment.
    if (@('06-users', '05-auth-registration', '09-intune-policy-settings', '01-company-branding', 'exo-01-orgconfig' | Where-Object { (Test-Path -LiteralPath (Join-Path $Evidence "$_.json")) -or (Test-Path -LiteralPath (Join-Path $Evidence "$_.csv")) }).Count -eq 0) {
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
        $facts.ssprEnabledPct = $(if ($members.Count) { [Math]::Round(100.0 * $enabled / $members.Count, 1) } else { $null })
        if (-not $members.Count) { $notEvaluated['UX-008'] = 'The registration report lists no members, so there is no rate to judge.' }
    }

    # The directory as people read it: sign-in name and email the same, display names First Last. A row at a time.
    $upn = [System.Collections.Generic.List[object]]::new(); $lastFirst = [System.Collections.Generic.List[object]]::new()
    $state = @{ hasMail = $null; members = 0; upnCount = 0; nameCount = 0; profileComplete = 0; hasProfile = $null }
    $read = Read-PostureEvidenceRow -Folder $Evidence -Name '06-users' -OnRow {
        param($u)
        if ($null -eq $state.hasMail) { $state.hasMail = (& $has $u 'Mail') }
        if (-not $state.hasMail) { return }
        if ([string](& $v $u 'UserType') -ne 'Member' -or -not (Test-PostureTrue (& $v $u 'AccountEnabled'))) { return }
        $state.members++
        if ($null -eq $state.hasProfile) { $state.hasProfile = (& $has $u 'JobTitle') }
        if ([string](& $v $u 'Department') -and [string](& $v $u 'JobTitle')) { $state.profileComplete++ }
        $name = [string](& $v $u 'UserPrincipalName'); $mail = [string](& $v $u 'Mail')
        if ($mail -and -not [string]::Equals($mail, $name, [System.StringComparison]::OrdinalIgnoreCase)) { $state.upnCount++; if ($upn.Count -lt 500) { $upn.Add([ordered]@{ name = $name; detail = "email $mail" }) } }
        $dn = [string](& $v $u 'DisplayName'); $sn = [string](& $v $u 'Surname')
        $reversed = $(if ($sn) { $dn -match ('^\s*' + [regex]::Escape($sn) + '\s*,') } else { $dn -match '^[^\s,]+,\s*\S' })
        if ($reversed) { $state.nameCount++; if ($lastFirst.Count -lt 500) { $lastFirst.Add([ordered]@{ name = $dn; detail = $name }) } }
    }
    if (-not $read) { & $missing @('UX-009', 'UX-010') '06-users' 'Entra' }
    elseif ($state.hasMail -eq $false) { & $before @('UX-009', 'UX-010', 'UX-020') '06-users' 'Entra' }
    else {
        $facts.upnEmailMismatches = $state.upnCount; $affected.upnEmailMismatches = @($upn)
        $facts.lastFirstDisplayNames = $state.nameCount; $affected.lastFirstDisplayNames = @($lastFirst)
        if ($state.hasProfile) { $facts.profileCompletePct = $(if ($state.members -gt 0) { [Math]::Round(100.0 * $state.profileComplete / $state.members, 1) } else { 100 }) }
        else { & $before @('UX-020') '06-users' 'Entra' }
    }
    if (-not $read) { & $missing @('UX-020') '06-users' 'Entra' }

    # Sign-in without passwords and with fewer choices (UX-011 to UX-013), from the authentication methods policy.
    $amp = & $load '02-authentication-methods-policy'
    if ($null -eq $amp) { & $missing @('UX-011', 'UX-013') '02-authentication-methods-policy' 'Entra' }
    else {
        $a = @(@(& $v $amp 'authenticationMethodConfigurations') | Where-Object { [string](& $v $_ 'id') -eq 'MicrosoftAuthenticator' })
        $facts.phoneSignInAvailable = [bool]($a.Count -and [string](& $v $a[0] 'state') -eq 'enabled' -and @(@(& $v $a[0] 'includeTargets') | Where-Object { [string](& $v $_ 'authenticationMode') -in 'any', 'deviceBasedPush' }).Count -gt 0)
        # Microsoft-managed (default) counts as on: Microsoft runs the campaign for people still on SMS or voice (verify).
        $facts.registrationCampaignOn = [string](& $v $amp 'registrationEnforcement.authenticationMethodsRegistrationCampaign.state') -in 'enabled', 'default'
    }
    $spm = & $load '02-auth-system-preferred'
    if ($null -eq $spm) { & $missing @('UX-012') '02-auth-system-preferred' 'Entra' }
    else { $facts.systemPreferredMfaOn = [string](& $v $spm 'State') -in 'enabled', 'default' }

    # Windows sign-in and reset (UX-014, UX-015), and the Apple single sign-on extension (UX-016), from the settings catalog.
    if ($null -ne $settings -and $null -ne $catalog) {
        $facts.windowsPasswordlessExperience = & $on 'authentication_enablepasswordlessexperience$'
        $facts.passwordResetFromSignInScreen = & $on 'authentication_allowaadpasswordreset$'
        $sso = @($live | Where-Object { [string](& $v $_ 'SettingDefinitionId') -match 'extensiblesso.*extensionidentifier$' -and [string](& $v $_ 'Value') -match '(?i)com\.microsoft\.(azureauthenticator|companyportalmac)\.ssoextension' })
        $facts.appleSsoExtension = $sso.Count -gt 0
    }
    else { & $missing @('UX-014', 'UX-015', 'UX-016') '09-intune-policy-settings' 'Intune' }
    $syncFeatures = & $load '01-onprem-sync-features'
    $hybridModel = [string]$(if ($OrgProfile.Contains('identityModel')) { $OrgProfile['identityModel'] }) -like 'hybrid*'
    $facts.passwordWritebackNeeded = $hybridModel
    # Unknown when the sync features were not collected; it only matters to a hybrid tenant.
    $facts.passwordWritebackOn = $(if ($null -eq $syncFeatures) { $null } else { @(& $rows $syncFeatures | Where-Object { (& $v $_ 'features.passwordWritebackEnabled') -eq $true }).Count -gt 0 })

    # Restarts people can plan around (UX-017): every update ring gives at least a day's grace after the deadline.
    $cfgRows = & $load '09-intune-config-profile-settings'
    if ($null -eq $cfgRows) { & $missing @('UX-017') '09-intune-config-profile-settings' 'Intune' }
    else {
        $rings = @(& $rows $cfgRows | Where-Object { [string](& $v $_ 'Type') -eq 'windowsUpdateForBusinessConfiguration' })
        $ringIds = @($rings | ForEach-Object { [string](& $v $_ 'PolicyId') } | Sort-Object -Unique)
        $short = @($ringIds | Where-Object { $id = $_; $g = @($rings | Where-Object { [string](& $v $_ 'PolicyId') -eq $id -and [string](& $v $_ 'Setting') -eq 'deadlineGracePeriodInDays' }); -not $g.Count -or [int](& $v $g[0] 'Value') -lt [int]$t.minUpdateGraceDays })
        $facts.updateRingsWithoutGrace = $short.Count
        $affected.updateRingsWithoutGrace = @($short | ForEach-Object { $id = $_; $nm = @($rings | Where-Object { [string](& $v $_ 'PolicyId') -eq $id } | ForEach-Object { [string](& $v $_ 'PolicyName') } | Where-Object { $_ } | Select-Object -First 1); [ordered]@{ name = $(if ($nm.Count) { $nm[0] } else { $id }); detail = 'grace period after the deadline under a day' } })
    }

    # Work apps on phones unlocked with Face ID or a fingerprint (UX-018).
    $app = & $load '09-intune-app-protection-policies'
    if ($null -eq $app) { & $missing @('UX-018') '09-intune-app-protection-policies' 'Intune' }
    else {
        $mobile = @(& $rows $app | Where-Object { [string](& $v $_ 'Type') -match '(?i)(ios|android)ManagedAppProtection' -and (& $v $_ 'IsAssigned') -eq $true })
        if ($mobile.Count -and -not (& $has $mobile[0] 'PinRequired')) { & $before @('UX-018') '09-intune-app-protection-policies' 'Intune' }
        else {
            $typed = @($mobile | Where-Object { (& $v $_ 'PinRequired') -eq $true -and ((& $v $_ 'FingerprintBlocked') -eq $true -or (& $v $_ 'FaceIdBlocked') -eq $true) })
            $facts.appProtectionWithoutBiometrics = $typed.Count
            $affected.appProtectionWithoutBiometrics = @($typed | ForEach-Object { [ordered]@{ name = [string](& $v $_ 'DisplayName'); detail = 'PIN required, Face ID or fingerprint blocked' } })
        }
    }

    # Licences that follow people's groups (UX-019).
    $groupsSeen = @{ any = $false; licensed = 0; withColumn = $false }
    $haveGroups = Read-PostureEvidenceRow -Folder $Evidence -Name '07-groups' -OnRow { param($g) $groupsSeen.any = $true; if (& $has $g 'Licensed') { $groupsSeen.withColumn = $true }; if (Test-PostureTrue (& $v $g 'Licensed')) { $groupsSeen.licensed++ } }
    if (-not $haveGroups) { & $missing @('UX-019') '07-groups' 'Entra' }
    elseif ($groupsSeen.any -and -not $groupsSeen.withColumn) { & $before @('UX-019') '07-groups' 'Entra' }
    else { $facts.licensedGroups = $groupsSeen.licensed }

    # Mail that helps people decide (UX-021 to UX-024), from Exchange Online.
    $ext = & $load 'exo-13-external-in-outlook'
    if ($null -eq $ext) { & $missing @('UX-021') 'exo-13-external-in-outlook' 'Exchange' }
    else { $facts.externalSenderTagOn = @(& $rows $ext | Where-Object { (& $v $_ 'Enabled') -eq $true }).Count -gt 0 }
    $org = & $load 'exo-01-orgconfig'; $org1 = @(& $rows $org | Select-Object -First 1)
    if ($org1.Count -eq 0) { & $missing @('UX-022', 'UX-024') 'exo-01-orgconfig' 'Exchange' }
    else {
        if (& $has $org1[0] 'MailTipsExternalRecipientsTipsEnabled') { $facts.mailTipsExternalOn = (& $v $org1[0] 'MailTipsAllTipsEnabled') -eq $true -and (& $v $org1[0] 'MailTipsExternalRecipientsTipsEnabled') -eq $true } else { & $before @('UX-022') 'exo-01-orgconfig' 'Exchange' }
        if (& $has $org1[0] 'AutoExpandingArchiveEnabled') { $facts.autoExpandingArchiveOn = (& $v $org1[0] 'AutoExpandingArchiveEnabled') -eq $true } else { & $before @('UX-024') 'exo-01-orgconfig' 'Exchange' }
    }
    $rsp = & $load 'exo-13-report-submission'
    if ($null -eq $rsp) { & $missing @('UX-023') 'exo-13-report-submission' 'Exchange' }
    else { $facts.reportButtonOn = @(& $rows $rsp | Where-Object { (& $v $_ 'EnableReportToMicrosoft') -eq $true -or (& $v $_ 'ReportPhishToCustomizedAddress') -eq $true -or (& $v $_ 'ReportJunkToCustomizedAddress') -eq $true }).Count -gt 0 }

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('09-intune-policy-settings.json', '09-intune-enrollment-restrictions.json', '01-company-branding.json', '06-users.json') }
}
