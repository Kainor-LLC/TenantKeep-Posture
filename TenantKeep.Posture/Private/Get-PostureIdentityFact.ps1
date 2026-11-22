# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureIdentityFact {
    <#
    .SYNOPSIS
        Fact provider for the identity and privileged access domain (spec 4.1). Reads the A.1 files in a collection folder.
    .DESCRIPTION
        Files read: 04-role-assignments-active, 04-role-assignments-pim-eligible, 06-users, 06-users-summary,
        02-authorization-policy, 02-admin-consent-request-policy, 02-cross-tenant-access-defaults,
        10-app-registrations, 10-graph-app-permissions, 11-risky-users. A check whose file is missing is marked
        not evaluated with the file named. Thresholds read: minGlobalAdmins, maxGlobalAdmins,
        credentialExpiryWarningDays, riskyUserMaxAgeDays, inactiveGuestDays. Profile read: breakGlass.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [Parameter()] [System.Collections.IDictionary] $OrgProfile = @{},
        [Parameter()] [System.Collections.IDictionary] $Thresholds = @{},
        [datetime] $AsOf = [datetime]::UtcNow
    )

    $ErrorActionPreference = 'Stop'
    $t = @{ minGlobalAdmins = 2; maxGlobalAdmins = 5; credentialExpiryWarningDays = 30; riskyUserMaxAgeDays = 7; inactiveGuestDays = 90; maxActivationHours = 8; unusedAppDays = 90 }
    foreach ($k in @($Thresholds.Keys)) { $t[$k] = $Thresholds[$k] }

    # Parsed once per evaluation and shared with the other domains (Read-PostureEvidenceFile); a missing file is
    # $null, an empty one an empty array.
    $load = {
        param([string] $Name)
        $parsed = Read-PostureEvidenceFile -Folder $Evidence -Name $Name
        if ($null -eq $parsed) { return $null }
        if ($parsed -is [array] -and $parsed.Count -eq 0) { return , @() }
        return $parsed
    }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}; $notes = @{}
    # A list of affected objects holds 500 at most; affectedCounts carries how many there are.
    $affectedCounts = @{}
    $missing = { param([string] $Id, [string] $File) $notEvaluated[$Id] = "$File.json was not collected (run Invoke-PostureCollection, check errors.txt and the scopes)." }

    $active = & $load '04-role-assignments-active'
    $eligible = & $load '04-role-assignments-pim-eligible'
    $usersSummary = & $load '06-users-summary'
    # The collector's slim files (admins, break-glass candidates, guests) instead of every user; the full list only for
    # runs made before them.
    $adminRows = Get-PostureAdminRow -Folder $Evidence -List Users
    $bgRows = & $load '06-users-breakglass-candidates'
    $usersByUpn = @{}
    foreach ($u in @($adminRows | Where-Object { $_ })) { if ($u.UserPrincipalName) { $usersByUpn[[string]$u.UserPrincipalName] = $u } }

    # Break-glass accounts: profile list first, else name heuristic over users.
    $bgNames = @($OrgProfile['breakGlass'] | Where-Object { $_ })
    $isBreakGlassUser = {
        param($upn, $name)
        if ($bgNames.Count -gt 0) { return [bool]($bgNames | Where-Object { $_ -eq $upn -or $_ -eq $name }) }
        return ([string]$upn -match '(?i)break.?glass|emergency') -or ([string]$name -match '(?i)break.?glass|emergency')
    }
    # A run from before the break-glass candidates file: the accounts that read as break-glass out of all users, a row at a time.
    if ($null -eq $bgRows) {
        $found = [System.Collections.Generic.List[object]]::new()
        if (Read-PostureEvidenceRow -Folder $Evidence -Name '06-users' -OnRow { param($u) if (& $isBreakGlassUser ([string](& $v $u 'UserPrincipalName')) ([string](& $v $u 'DisplayName'))) { $found.Add($u) } }) { $bgRows = $found.ToArray() }
    }
    $privilegedRoles = @('Global Administrator', 'Application Administrator', 'Authentication Administrator', 'Billing Administrator', 'Cloud Application Administrator',
        'Conditional Access Administrator', 'Exchange Administrator', 'Helpdesk Administrator', 'Password Administrator', 'Privileged Authentication Administrator',
        'Privileged Role Administrator', 'Security Administrator', 'SharePoint Administrator', 'User Administrator', 'Intune Administrator', 'Hybrid Identity Administrator')

    if ($null -eq $active) {
        foreach ($id in 'ID-001', 'ID-002', 'ID-003', 'ID-004', 'ID-007') { & $missing $id '04-role-assignments-active' }
    }
    else {
        # People, not assignment rows: someone holds a role when it is assigned to them or to a group they are in
        # (04-role-holders). "Standing" is held now and for good: Direct or Group, and not a PIM activation that
        # ends by itself. A group whose members were not read is not a person, and the checks below say so.
        $holders = Get-PostureRoleHolder -Folder $Evidence
        # One entry per person and role; held directly wins over held through a group as well.
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $standing = @(foreach ($person in $holders.people.get_Values()) {
                foreach ($r in @($person.roles | Sort-Object { $_.held -ne 'Direct' })) {
                    if ($r.held -in 'Direct', 'Group' -and $r.assignmentType -ne 'Activated' -and $seen.Add("$($person.upn)|$($r.role)")) { @{ person = $person; role = $r.role; group = $r.groupName; assignmentType = $r.assignmentType } }
                }
            })
        $how = { param($x) if ($x.group) { "through the group $($x.group)" } else { [string]$x.assignmentType } }
        $permanent = @($active | Where-Object { $_.AssignmentType -ne 'Activated' })
        # A role held by something that is neither a person nor a group (a service principal) counts as before.
        $others = @($permanent | Where-Object { $_.PrincipalType -notin 'user', 'group' })
        $partial = {
            param([string] $Id, [int] $Gaps, [string] $What, [string[]] $Role = @())
            $gap = Get-PostureRoleHolderGap -Holder $holders -Role $Role -Standing
            if (-not $gap) { return }
            if ($Gaps -gt 0) { $notes[$Id] = "Judged on the role holders that were read; $gap." }
            else { $notEvaluated[$Id] = "No $What among the role holders that were read, but $gap. Collect Entra again (Resume-PostureRun -Collector Entra)." }
        }

        $gaPeople = @($standing | Where-Object { $_.role -eq 'Global Administrator' })
        $gaOthers = @($others | Where-Object { $_.Role -eq 'Global Administrator' })
        $facts.globalAdmins = $gaPeople.Count + $gaOthers.Count
        $affected.globalAdmins = @(@($gaPeople | ForEach-Object { [ordered]@{ name = "$($_.person.name)"; detail = "user $($_.person.upn) ($(& $how $_))" } }) +
            @($gaOthers | ForEach-Object { [ordered]@{ name = "$($_.PrincipalName)"; detail = "$($_.PrincipalType) $($_.PrincipalUpn) ($($_.AssignmentType))" } }))
        # The count is a floor while a group that holds the role is unopened: over the limit already is a finding,
        # anything else has no answer.
        $gaGap = Get-PostureRoleHolderGap -Holder $holders -Role 'Global Administrator' -Standing
        if ($gaGap -and $facts.globalAdmins -gt [int]$t.maxGlobalAdmins) { $notes['ID-001'] = "At least $($facts.globalAdmins): $gaGap." }
        elseif ($gaGap) { $notEvaluated['ID-001'] = "$($facts.globalAdmins) Global Administrator(s) among the role holders that were read, but $gaGap, so the number is not known. Collect Entra again (Resume-PostureRun -Collector Entra)." }

        $outside = @($standing | Where-Object { $_.role -in $privilegedRoles -and -not (& $isBreakGlassUser $_.person.upn $_.person.name) })
        $facts.permanentPrivilegedOutsideBreakGlass = $outside.Count
        # Unknown, not zero, when the eligible assignments were not collected.
        $facts.eligiblePrivileged = $(if ($null -eq $eligible) { $null } else { @($eligible | Where-Object { $_ -and $_.Role -in $privilegedRoles }).Count })
        $affected.permanentPrivilegedOutsideBreakGlass = @($outside | ForEach-Object { [ordered]@{ name = "$($_.person.name): $($_.role)"; detail = "permanent $($_.role) for $($_.person.upn)$(if ($_.group) { " through the group $($_.group)" })" } })
        & $partial 'ID-002' $outside.Count 'permanent privileged assignment outside break-glass' $privilegedRoles

        $syncedPeople = @($standing | Where-Object { $_.person.synced -eq $true })
        $syncedOthers = @($permanent | Where-Object { $_.PrincipalType -ne 'user' -and $_.PrincipalSynced -eq $true })
        $facts.adminsSyncedFromOnPrem = $syncedPeople.Count + $syncedOthers.Count
        $affected.adminsSyncedFromOnPrem = @(@($syncedPeople | ForEach-Object { [ordered]@{ name = "$($_.person.name): $($_.role)"; detail = "synced from on-premises AD$(if ($_.group) { ", holds the role through the group $($_.group)" })" } }) +
            @($syncedOthers | ForEach-Object { [ordered]@{ name = "$($_.PrincipalName): $($_.Role)"; detail = 'synced from on-premises AD' } }))
        & $partial 'ID-003' $facts.adminsSyncedFromOnPrem 'administrator synced from on-premises AD'

        $adminUsers = @($standing | ForEach-Object { [string]$_.person.upn } | Where-Object { $_ } | Sort-Object -Unique)
        if ($null -eq $adminRows) { & $missing 'ID-004' '06-users' }
        else {
            $licensed = @($adminUsers | Where-Object { $usersByUpn.ContainsKey($_) -and [int]$usersByUpn[$_].LicenseCount -gt 0 -and -not (& $isBreakGlassUser $_ $usersByUpn[$_].DisplayName) })
            $facts.adminsWithLicenses = $licensed.Count
            $affected.adminsWithLicenses = @($licensed | ForEach-Object { [ordered]@{ name = $_; detail = "$($usersByUpn[$_].LicenseCount) license(s); an admin account should be a separate, unlicensed identity" } })
            & $partial 'ID-004' $licensed.Count 'licensed administrator account'
        }

        $spRoles = @($permanent | Where-Object { $_.PrincipalType -eq 'servicePrincipal' })
        $facts.servicePrincipalsWithRoles = $spRoles.Count
        $facts.servicePrincipalsWithGlobalAdmin = @($spRoles | Where-Object { $_.Role -eq 'Global Administrator' }).Count
        $affected.servicePrincipalsWithRoles = @($spRoles | ForEach-Object { [ordered]@{ name = "$($_.PrincipalName): $($_.Role)"; detail = 'service principal holding a directory role' } })
    }

    if ($null -eq $bgRows) { & $missing 'ID-005' '06-users' }
    else {
        $bg = @($bgRows | Where-Object { $_ -and (& $isBreakGlassUser $_.UserPrincipalName $_.DisplayName) })
        $facts.breakGlassAccounts = $bg.Count
        $facts.breakGlassSynced = @($bg | Where-Object { $_.OnPremisesSyncEnabled -eq $true }).Count
        $facts.breakGlassDisabled = @($bg | Where-Object { $_.AccountEnabled -eq $false }).Count
        $affected.breakGlassProblems = @(@($bg | Where-Object { $_.OnPremisesSyncEnabled -eq $true } | ForEach-Object { [ordered]@{ name = $_.UserPrincipalName; detail = 'break-glass account is synced from on-premises AD' } }) +
            @($bg | Where-Object { $_.AccountEnabled -eq $false } | ForEach-Object { [ordered]@{ name = $_.UserPrincipalName; detail = 'break-glass account is disabled' } }))
    }

    $pim = & $load '04-pim-role-policies'
    if ($null -eq $pim) { & $missing 'ID-006' '04-pim-role-policies' }
    elseif (@($pim).Count -eq 0) { $notEvaluated['ID-006'] = 'No PIM role management policies were returned (Entra ID P2 and PIM needed).' }
    else {
        $topRoles = @('Global Administrator', 'Privileged Role Administrator', 'Security Administrator', 'Conditional Access Administrator')
        $maxHours = [double]$(if ($t.ContainsKey('maxActivationHours')) { $t.maxActivationHours } else { 8 })
        $checked = @($pim | Where-Object { $_.Role -in $topRoles })
        $problems = foreach ($pol in $checked) {
            $issues = @()
            if (-not $pol.ActivationMfaRequired) { $issues += 'no MFA on activation' }
            if (-not $pol.ActivationJustificationRequired) { $issues += 'no justification' }
            if ($null -eq $pol.MaxActivationHours -or [double]$pol.MaxActivationHours -gt $maxHours) { $issues += "activation up to $(if ($null -ne $pol.MaxActivationHours) { "$($pol.MaxActivationHours)h" } else { 'unlimited' }) (max $($maxHours)h)" }
            if ($pol.Role -eq 'Global Administrator' -and -not $pol.ApprovalRequired) { $issues += 'no approval' }
            if ($issues.Count -gt 0) { [ordered]@{ name = $pol.Role; detail = ($issues -join ', ') } }
        }
        $facts.pimPolicyRolesChecked = $checked.Count
        $facts.pimPolicyCompliantRoles = $checked.Count - @($problems).Count
        $affected.pimPolicyProblems = @($problems)
        if ($checked.Count -eq 0) { $notEvaluated['ID-006'] = 'None of the four top roles has a PIM policy in the collection.' }
    }
    # ID-014: the Entra diagnostic settings (microsoft.aadiam) from the Azure collector; sign-in and audit logs to a workspace or event hub.
    $diag = & $load 'az-09-entra-diagnostic-settings'
    if ($null -eq $diag) { $notEvaluated['ID-014'] = 'az-09-entra-diagnostic-settings.json was not collected (Invoke-PostureCollection -Collector Azure; needs a Connect-AzAccount session).' }
    else {
        $exports = @($diag | Where-Object { $_ -and ($_.WorkspaceId -or $_.EventHub) })
        $cats = @($exports | ForEach-Object { @($_.Categories) } | ForEach-Object { [string]$_ })
        $facts.logExportConfigured = ($exports.Count -gt 0) -and ($cats -contains 'SignInLogs') -and ($cats -contains 'AuditLogs')
        $facts.logExportCategories = @($cats | Sort-Object -Unique)
    }

    $authz = & $load '02-authorization-policy'
    if ($null -eq $authz) { & $missing 'ID-008' '02-authorization-policy' }
    else {
        $grants = @(& $v $authz 'defaultUserRolePermissions.permissionGrantPoliciesAssigned')
        $facts.userConsentMode = if ($grants.Count -eq 0) { 'none' } elseif ($grants -match 'microsoft-user-default-low') { 'low' } else { 'all' }
        $facts.userConsentPolicies = ($grants -join ', ')
    }
    if ($null -eq $authz) { & $missing 'ID-020' '02-authorization-policy'; & $missing 'ID-021' '02-authorization-policy' }
    else {
        # Who can invite guests, and what guests can see: guests inviting guests, and guests with member access, are
        # the two settings that open the directory.
        $facts.guestInviteSetting = [string](& $v $authz 'allowInvitesFrom')
        $facts.guestsCanInviteGuests = $facts.guestInviteSetting -eq 'everyone'
        $roleOf = @{ '2af84b1e-32c8-42b7-82bc-daa82404023b' = 'restricted'; '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'limited'; 'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'same as members' }
        $gr = [string](& $v $authz 'guestUserRoleId')
        $facts.guestAccessLevel = $(if ($roleOf.ContainsKey($gr)) { $roleOf[$gr] } else { 'unknown' })
        $facts.guestAccessAsMembers = $facts.guestAccessLevel -eq 'same as members'
    }

    # NIST SP 800-63B: no periodic password change. Each managed verified domain's expiry, 2147483647 meaning never.
    $doms = & $load '01-domains'
    if ($null -eq $doms) { & $missing 'ID-017' '01-domains' }
    elseif (@($doms | Where-Object { $_ }).Count -and @($doms | Where-Object { $_ -and (& $v $_ 'IsVerified') -eq $true -and ($_ -is [System.Collections.IDictionary]) -and $_.Contains('PasswordValidityPeriodInDays') }).Count -eq 0) { $notEvaluated['ID-017'] = '01-domains.json was collected before TenantKeep read password expiry. Collect Entra again (Resume-PostureRun -Collector Entra).' }
    else {
        $expiring = @($doms | Where-Object { $_ -and (& $v $_ 'IsVerified') -eq $true -and [string](& $v $_ 'AuthenticationType') -ne 'Federated' -and $null -ne (& $v $_ 'PasswordValidityPeriodInDays') -and [long](& $v $_ 'PasswordValidityPeriodInDays') -lt 2147483647 })
        $facts.domainsWithPasswordExpiry = $expiring.Count
        $affected.domainsWithPasswordExpiry = @($expiring | ForEach-Object { [ordered]@{ name = [string](& $v $_ 'Id'); detail = "passwords expire every $(& $v $_ 'PasswordValidityPeriodInDays') days" } })
    }
    # Entra Password Protection: the custom banned list, and enforcement on-premises for hybrid identity.
    $dirSettings = & $load '02-directory-settings'
    if ($null -eq $dirSettings) { & $missing 'ID-018' '02-directory-settings'; & $missing 'ID-019' '02-directory-settings' }
    else {
        $pr = @($dirSettings | Where-Object { $_ -and [string](& $v $_ 'TemplateId') -eq '5cf42378-d67d-4f36-ba46-e8b86229381d' })
        $pv = $(if ($pr.Count) { & $v $pr[0] 'Values' } else { $null })
        $facts.bannedPasswordCheckEnabled = [bool]($pv -and [string](& $v $pv 'EnableBannedPasswordCheck') -eq 'True')
        $facts.bannedPasswordCount = $(if ($pv) { [int](& $v $pv 'BannedPasswordCount') } else { 0 })
        $facts.bannedPasswordOnPremEnforced = [bool]($pv -and [string](& $v $pv 'EnableBannedPasswordCheckOnPremises') -eq 'True' -and [string](& $v $pv 'BannedPasswordCheckOnPremisesMode') -eq 'Enforce')
    }

    $consent = & $load '02-admin-consent-request-policy'
    if ($null -eq $consent) { & $missing 'ID-009' '02-admin-consent-request-policy' }
    else {
        $facts.adminConsentWorkflowEnabled = [bool](& $v $consent 'isEnabled')
        $facts.adminConsentReviewers = @(& $v $consent 'reviewers').Count
    }

    $apps = & $load '10-app-registrations'
    if ($null -eq $apps) { & $missing 'ID-010' '10-app-registrations' }
    else {
        $warn = $AsOf.AddDays([int]$t.credentialExpiryWarningDays)
        $expired = @($apps | Where-Object { [int]$_.ExpiredCredentials -gt 0 })
        $soon = @($apps | Where-Object { $_.EarliestExpiry -and [int]$_.ExpiredCredentials -eq 0 -and (ConvertTo-PostureUtcDateTime $_.EarliestExpiry) -lt $warn })
        $facts.appCredentialsExpired = $expired.Count
        $facts.appCredentialsExpiringSoon = $soon.Count
        $affected.appCredentialProblems = @(@($expired | ForEach-Object { [ordered]@{ name = $_.DisplayName; detail = "$($_.ExpiredCredentials) expired credential(s)" } }) +
            @($soon | ForEach-Object { [ordered]@{ name = $_.DisplayName; detail = "credential expires $((ConvertTo-PostureUtcDateTime $_.EarliestExpiry).ToString('yyyy-MM-dd'))" } }))
    }

    $perms = & $load '10-graph-app-permissions'
    if ($null -eq $perms) { & $missing 'ID-011' '10-graph-app-permissions' }
    else {
        $high = @('Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Directory.AccessAsUser.All',
            'Mail.ReadWrite', 'Mail.Send', 'Mail.Read', 'MailboxSettings.ReadWrite', 'Files.ReadWrite.All', 'Files.Read.All', 'Sites.FullControl.All', 'Sites.ReadWrite.All', 'Sites.Read.All',
            'User.ReadWrite.All', 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Policy.ReadWrite.ConditionalAccess', 'Policy.ReadWrite.AuthenticationMethod',
            'UserAuthenticationMethod.ReadWrite.All', 'Exchange.ManageAsApp', 'full_access_as_app', 'DeviceManagementConfiguration.ReadWrite.All', 'PrivilegedAccess.ReadWrite.AzureAD')
        $hits = @($perms | Where-Object { $_.Permission -in $high })
        $facts.highPrivilegeAppPermissions = $hits.Count
        $affected.highPrivilegeAppPermissions = @($hits | ForEach-Object { [ordered]@{ name = "$($_.PrincipalDisplayName): $($_.Permission)"; detail = "application permission granted $((& $v $_ 'CreatedDateTime'))" } })
    }

    # ID-024: applications that hold Graph application permissions and have not signed in for unusedAppDays. The
    # permissions are from 10-graph-app-permissions; who each holder is, and when it was made, from the service
    # principals (looked up by id, never loaded whole); its last sign-in from 10-app-signin-activity, which has a
    # row for each application Entra has seen sign in. An application made inside the window is too new to judge.
    if ($null -eq $perms) { & $missing 'ID-024' '10-graph-app-permissions' }
    else {
        $holderIds = @($perms | Where-Object { $_ -and [string](& $v $_ 'PrincipalType') -ne 'User' } | ForEach-Object { [string](& $v $_ 'PrincipalId') } | Where-Object { $_ } | Sort-Object -Unique)
        $holders = Find-PostureEvidenceRow -Folder $Evidence -Name '10-service-principals' -Key 'Id' -Value $holderIds
        $appIds = @($(if ($null -ne $holders) { $holders.get_Values() | ForEach-Object { [string](& $v $_ 'AppId') } | Where-Object { $_ } }))
        $activity = Find-PostureEvidenceRow -Folder $Evidence -Name '10-app-signin-activity' -Key 'AppId' -Value $appIds
        if ($null -eq $holders) { & $missing 'ID-024' '10-service-principals' }
        elseif ($null -eq $activity) { $notEvaluated['ID-024'] = '10-app-signin-activity.json was not collected (the Entra collector; needs AuditLog.Read.All, and Entra ID P1 for the sign-in record).' }
        else {
            $unusedCutoff = $AsOf.AddDays(-[int]$t.unusedAppDays)
            $unused = [System.Collections.Generic.List[object]]::new()
            $notFound = 0
            foreach ($id in $holderIds) {
                # A holder that is not in this run's service principal list cannot be judged: counted, never taken as in use.
                if (-not $holders.ContainsKey($id)) { $notFound++; continue }
                $sp = $holders[$id]
                $made = ConvertTo-PostureUtcDateTime (& $v $sp 'CreatedDateTime')
                if ($made -and $made -gt $unusedCutoff) { continue }
                $appId = [string](& $v $sp 'AppId')
                $last = $(if ($appId -and $activity.ContainsKey($appId)) { ConvertTo-PostureUtcDateTime (& $v $activity[$appId] 'LastSignIn') } else { $null })
                if ($last -and $last -ge $unusedCutoff) { continue }
                $held = @($perms | Where-Object { [string](& $v $_ 'PrincipalId') -eq $id } | ForEach-Object { [string](& $v $_ 'Permission') } | Where-Object { $_ } | Sort-Object -Unique)
                $unused.Add([ordered]@{ name = [string](& $v $sp 'DisplayName'); detail = "$($held.Count) Graph permission(s): $(@($held | Select-Object -First 3) -join ', ')$(if ($held.Count -gt 3) { ' and more' }); $(if ($last) { "last sign-in $($last.ToString('yyyy-MM-dd'))" } else { 'no sign-in on record' })" })
            }
            $facts.appsWithGraphPermissions = $holderIds.Count
            $facts.unusedAppsWithPermissions = $unused.Count
            $affected.unusedAppsWithPermissions = @($unused | Sort-Object { $_.name })
            if ($notFound -gt 0 -and $unused.Count -eq 0) { $notEvaluated['ID-024'] = "$notFound of the $($holderIds.Count) applications that hold Graph permissions are not in this run's service principal list, so whether they still sign in is not known." }
            elseif ($notFound -gt 0) { $notes['ID-024'] = "Judged on $($holderIds.Count - $notFound) of the $($holderIds.Count) applications that hold Graph permissions; the other $notFound are not in this run's service principal list." }
        }
    }

    # Guests a row at a time: all counted, the first 500 inactive ones kept for the report. A run from before the
    # guests file reads the guests among all users, still a row at a time.
    $guestState = @{ n = 0; inactive = 0 }; $inactiveGuests = [System.Collections.Generic.List[object]]::new()
    $guestCutoff = $AsOf.AddDays(-[int]$t.inactiveGuestDays)
    $onGuest = {
        param($g)
        $guestState.n++
        $last = & $v $g 'LastInteractiveSignIn'
        $when = $(if ($last) { ConvertTo-PostureUtcDateTime $last })
        if ($when -and $when -ge $guestCutoff) { return }
        $guestState.inactive++
        if ($inactiveGuests.Count -lt 500) { $inactiveGuests.Add([ordered]@{ name = [string](& $v $g 'UserPrincipalName'); detail = $(if ($when) { "last sign-in $($when.ToString('yyyy-MM-dd'))" } else { 'never signed in' }) }) }
    }
    $haveGuests = Read-PostureEvidenceRow -Folder $Evidence -Name '06-users-guests' -OnRow $onGuest
    if (-not $haveGuests) { $haveGuests = Read-PostureEvidenceRow -Folder $Evidence -Name '06-users' -OnRow { param($u) if ([string](& $v $u 'UserType') -eq 'Guest') { & $onGuest $u } } }
    if ($null -eq $usersSummary) { & $missing 'ID-012' '06-users-summary' }
    elseif (-not $haveGuests) { & $missing 'ID-012' '06-users' }
    elseif (-not (& $v $usersSummary 'SignInActivityAvailable')) { $notEvaluated['ID-012'] = 'Sign-in activity was not available (AuditLog.Read.All), so guest inactivity cannot be measured.' }
    else {
        $facts.inactiveGuests = $guestState.inactive
        $facts.guests = $guestState.n
        $affected.inactiveGuests = @($inactiveGuests); $affectedCounts.inactiveGuests = $guestState.inactive
    }

    $xtap = & $load '02-cross-tenant-access-defaults'
    if ($null -eq $xtap) { & $missing 'ID-013' '02-cross-tenant-access-defaults' }
    else {
        $usersIn = & $v $xtap 'b2bCollaborationInbound.usersAndGroups'
        $appsIn = & $v $xtap 'b2bCollaborationInbound.applications'
        $allUsersAllowed = ((& $v $usersIn 'accessType') -eq 'allowed') -and [bool](@(& $v $usersIn 'targets') | Where-Object { (& $v $_ 'target') -eq 'AllUsers' })
        $allAppsAllowed = ((& $v $appsIn 'accessType') -eq 'allowed') -and [bool](@(& $v $appsIn 'targets') | Where-Object { (& $v $_ 'target') -eq 'AllApplications' })
        $facts.crossTenantInboundDefaultOpen = ($allUsersAllowed -and $allAppsAllowed)
        $facts.crossTenantInboundTrustMfa = [bool](& $v $xtap 'inboundTrust.isMfaAccepted')
        # Outbound: whether everyone may accept guest invitations to any other tenant, for any app.
        $usersOut = & $v $xtap 'b2bCollaborationOutbound.usersAndGroups'; $appsOut = & $v $xtap 'b2bCollaborationOutbound.applications'
        $facts.crossTenantOutboundDefaultOpen = (((& $v $usersOut 'accessType') -eq 'allowed') -and [bool](@(& $v $usersOut 'targets') | Where-Object { (& $v $_ 'target') -eq 'AllUsers' })) -and (((& $v $appsOut 'accessType') -eq 'allowed') -and [bool](@(& $v $appsOut 'targets') | Where-Object { (& $v $_ 'target') -eq 'AllApplications' }))
    }
    if ($null -eq $xtap) { & $missing 'ID-022' '02-cross-tenant-access-defaults' }

    # Risky users a row at a time: only those at high risk for longer than the threshold are kept.
    $riskState = @{ stale = 0 }; $staleRisk = [System.Collections.Generic.List[object]]::new()
    $riskOld = $AsOf.AddDays(-[int]$t.riskyUserMaxAgeDays)
    $haveRisky = Read-PostureEvidenceRow -Folder $Evidence -Name '11-risky-users' -OnRow {
        param($r)
        if ([string](& $v $r 'RiskLevel') -ne 'high' -or [string](& $v $r 'RiskState') -ne 'atRisk') { return }
        $updated = & $v $r 'RiskLastUpdatedDateTime'
        if (-not $updated) { return }
        $when = ConvertTo-PostureUtcDateTime $updated
        if ($when -ge $riskOld) { return }
        $riskState.stale++
        if ($staleRisk.Count -lt 500) { $staleRisk.Add([ordered]@{ name = [string](& $v $r 'UserPrincipalName'); detail = "high risk since $($when.ToString('yyyy-MM-dd'))" }) }
    }
    if (-not $haveRisky) { $notEvaluated['ID-015'] = '11-risky-users.json was not collected (needs Entra ID P2 and IdentityRiskyUser.Read.All).' }
    else {
        $facts.highRiskUsersUnaddressed = $riskState.stale
        $affected.highRiskUsersUnaddressed = @($staleRisk); $affectedCounts.highRiskUsersUnaddressed = $riskState.stale
    }

    # ID-016 from the sign-in log (SignIns collector): who still signs in over a legacy protocol.
    $signIns = & $load '06-signins-summary'
    if ($null -eq $signIns) { $notEvaluated['ID-016'] = 'The sign-in log was not read (the SignIns collector needs AuditLog.Read.All with Reports Reader or Global Reader, and Entra ID P1).' }
    else {
        $facts.legacySignIns = [long](Get-PostureValue $signIns 'LegacySignIns')
        $facts.legacySignInUsers = [int](Get-PostureValue $signIns 'LegacyUsers')
        $facts.signInDays = [int](Get-PostureValue $signIns 'Days')
        $affected.legacySignInUsers = @(@(& $load '06-signins-legacy-users') | Where-Object { $_ } | ForEach-Object { [ordered]@{ name = [string]$_.UserPrincipalName; detail = "$($_.SignIns) sign-in(s) over $(([string]$_.ClientApps) -replace ';', ', '), last $($_.LastSignIn)" } })
    }

    # ID-023: Microsoft's admin command-line tools open only to the people who need them (Get-PostureAdminToolRestriction).
    $tools = Get-PostureAdminToolRestriction -Evidence $Evidence
    if ($null -eq $tools) { $notEvaluated['ID-023'] = '10-service-principals.json was not collected (the Entra collector).' }
    else {
        $open = @($tools | Where-Object { $_.restricted -eq $false })
        $unknownTools = @($tools | Where-Object { $null -eq $_.restricted })
        if ($unknownTools.Count -gt 0) {
            $facts.adminToolsOpenToEveryone = $null
            $notEvaluated['ID-023'] = "policies.json (the Conditional Access snapshot) was not collected, so whether a policy blocks $($unknownTools.Count) of the admin tools is unknown: $(@($unknownTools | ForEach-Object { $_.name }) -join ', ')."
        }
        else {
            $facts.adminToolsOpenToEveryone = $open.Count
            $affected.adminToolsOpenToEveryone = @($open | ForEach-Object { [ordered]@{ name = $_.name; detail = $_.detail } })
        }
    }

    return @{ available = $true; facts = $facts; affected = $affected; affectedCounts = $affectedCounts; notEvaluated = $notEvaluated; notes = $notes; evidence = @('04-role-assignments-active.json', '06-users.json', '06-signins-summary.json', '02-authorization-policy.json', '10-app-registrations.json', '10-graph-app-permissions.json') }
}
