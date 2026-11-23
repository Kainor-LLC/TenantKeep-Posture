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
    # ID-026 and ID-027: who is told when a privileged role is handed out, and when one is activated. A role's
    # settings carry three alerts: someone was made eligible, was made active, activated the role. Each goes to the
    # administrators Microsoft sends it to by default, to further addresses, or to nobody. thresholds.alertRecipients
    # 'named' (CISA's baseline) counts only a further address, a mailbox someone watches; 'any' counts either.
    if ($null -eq $pim) { & $missing 'ID-026' '04-pim-role-policies'; & $missing 'ID-027' '04-pim-role-policies' }
    elseif (@($pim).Count -eq 0) { foreach ($id in 'ID-026', 'ID-027') { $notEvaluated[$id] = 'No PIM role management policies were returned (Entra ID P2 and PIM needed).' } }
    else {
        $alertRoles = @($pim | Where-Object { $_ -and $_.Role -in $privilegedRoles })
        $carries = { param($x, [string] $Name) if ($x -is [System.Collections.IDictionary]) { $x.Contains($Name) } else { $null -ne $x.PSObject.Properties[$Name] } }
        if ($alertRoles.Count -eq 0) { foreach ($id in 'ID-026', 'ID-027') { $notEvaluated[$id] = 'None of the privileged roles has a PIM policy in the collection.' } }
        elseif (@($alertRoles | Where-Object { & $carries $_ 'ActivationAlertToAdmins' }).Count -eq 0) {
            foreach ($id in 'ID-026', 'ID-027') { $notEvaluated[$id] = '04-pim-role-policies was collected before TenantKeep read the alert rules. Collect Entra again (Resume-PostureRun -Collector Entra).' }
        }
        else {
            $named = [string]$t['alertRecipients'] -eq 'named'
            # $true someone is told, $false nobody is (or nobody that counts), $null the rule did not come back.
            $told = { param($Admins, $Others) if ($null -eq $Admins -and $null -eq $Others) { return $null }; if ($named) { [int]$Others -gt 0 } else { ($Admins -eq $true) -or ([int]$Others -gt 0) } }
            $goesTo = { param($Admins) if ($named -and $Admins -eq $true) { 'goes only to the administrators Microsoft sends it to by default' } else { 'goes to nobody' } }
            $assignGaps = [System.Collections.Generic.List[object]]::new(); $activateGaps = [System.Collections.Generic.List[object]]::new()
            $assignKnown = 0; $activateKnown = 0
            foreach ($pol in $alertRoles) {
                $ea = Get-PostureValue $pol 'EligibleAlertToAdmins'; $aa = Get-PostureValue $pol 'ActiveAlertToAdmins'; $xa = Get-PostureValue $pol 'ActivationAlertToAdmins'
                $e = & $told $ea (Get-PostureValue $pol 'EligibleAlertOtherRecipients')
                $a = & $told $aa (Get-PostureValue $pol 'ActiveAlertOtherRecipients')
                $x = & $told $xa (Get-PostureValue $pol 'ActivationAlertOtherRecipients')
                if ($null -ne $e -and $null -ne $a) {
                    $assignKnown++
                    $gaps = @($(if (-not $e) { "the alert that someone was made eligible $(& $goesTo $ea)" }), $(if (-not $a) { "the alert that someone was made active $(& $goesTo $aa)" })) | Where-Object { $_ }
                    if (@($gaps).Count -gt 0) { $assignGaps.Add([ordered]@{ name = [string]$pol.Role; detail = (@($gaps) -join '; ') }) }
                }
                if ($null -ne $x) {
                    $activateKnown++
                    if (-not $x) { $activateGaps.Add([ordered]@{ name = [string]$pol.Role; detail = "the alert that someone activated the role $(& $goesTo $xa)" }) }
                }
            }
            if ($assignKnown -eq 0) { $notEvaluated['ID-026'] = 'The role settings came back without their assignment alert rules.' }
            else { $facts.pimAssignmentAlertRolesChecked = $assignKnown; $facts.pimAssignmentAlertGaps = $assignGaps.Count; $affected.pimAssignmentAlertGaps = $assignGaps.ToArray() }
            if ($activateKnown -eq 0) { $notEvaluated['ID-027'] = 'The role settings came back without their activation alert rule.' }
            else { $facts.pimActivationAlertRolesChecked = $activateKnown; $facts.pimActivationAlertGaps = $activateGaps.Count; $affected.pimActivationAlertGaps = $activateGaps.ToArray() }
        }
    }
    # ID-028 and ID-029: the tenant's app management policy, which can refuse a new client secret on any application
    # and cap how long a secret or a certificate lives. A restriction counts when the policy is on and the restriction
    # is. CISA's baseline says 180 and 365 days and its instructions say to enter 181 and 366; the default thresholds
    # follow the instructions, so a tenant set up from them passes (verify what the portal stores).
    $appPolicy = & $load '02-app-management-policy'
    if ($null -eq $appPolicy) { & $missing 'ID-028' '02-app-management-policy'; & $missing 'ID-029' '02-app-management-policy' }
    elseif ($null -eq (& $v $appPolicy 'isEnabled')) { foreach ($id in 'ID-028', 'ID-029') { $notEvaluated[$id] = 'The app management policy did not say whether it is on.' } }
    else {
        $policyOn = (& $v $appPolicy 'isEnabled') -eq $true
        $restriction = {
            param([string] $Kind, [string] $Type)
            @(& $v $appPolicy "applicationRestrictions.$Kind" | Where-Object { $_ -and [string](& $v $_ 'restrictionType') -eq $Type -and [string](& $v $_ 'state') -eq 'enabled' }) | Select-Object -First 1
        }
        $days = { param($r) $d = [string](& $v $r 'maxLifetime'); if (-not $d) { return $null }; try { [math]::Round([System.Xml.XmlConvert]::ToTimeSpan($d).TotalDays) } catch { $null } }
        $noNewSecrets = $(if ($policyOn) { & $restriction 'passwordCredentials' 'passwordAddition' })
        $facts.appManagementPolicyOn = [bool]$policyOn
        $facts.appSecretAdditionBlocked = [bool]($null -ne $noNewSecrets)
        # A restriction dated in the future, or dated at all, leaves the applications created before that day free of it.
        # The evidence reader hands a date back as a date; year 1 is how Graph writes "no date".
        $from = & $v $noNewSecrets 'restrictForAppsCreatedAfterDateTime'
        if ($from -is [datetime]) { if ($from.Year -gt 1) { $facts.appSecretAdditionAppliesFrom = $from.ToUniversalTime().ToString('yyyy-MM-dd') } }
        elseif ([string]$from -and [string]$from -notmatch '^0001-') { $facts.appSecretAdditionAppliesFrom = [string]$from }
        $maxSecret = [double]$(if ($t.ContainsKey('maxAppSecretDays')) { $t.maxAppSecretDays } else { 181 })
        $maxCertificate = [double]$(if ($t.ContainsKey('maxAppCertificateDays')) { $t.maxAppCertificateDays } else { 366 })
        $secretLife = $(if ($policyOn) { & $restriction 'passwordCredentials' 'passwordLifetime' }); $certificateLife = $(if ($policyOn) { & $restriction 'keyCredentials' 'asymmetricKeyLifetime' })
        $secretDays = $(if ($secretLife) { & $days $secretLife }); $certificateDays = $(if ($certificateLife) { & $days $certificateLife })
        $facts.appSecretMaxDays = $secretDays; $facts.appCertificateMaxDays = $certificateDays
        $lifetimeGaps = [System.Collections.Generic.List[object]]::new()
        # A tenant that refuses new secrets has nothing left to cap on that side.
        if (-not $facts.appSecretAdditionBlocked) {
            if ($null -eq $secretDays) { $lifetimeGaps.Add([ordered]@{ name = 'Client secrets'; detail = 'no maximum lifetime' }) }
            elseif ($secretDays -gt $maxSecret) { $lifetimeGaps.Add([ordered]@{ name = 'Client secrets'; detail = "may live $secretDays days (limit $maxSecret)" }) }
        }
        if ($null -eq $certificateDays) { $lifetimeGaps.Add([ordered]@{ name = 'Certificates'; detail = 'no maximum lifetime' }) }
        elseif ($certificateDays -gt $maxCertificate) { $lifetimeGaps.Add([ordered]@{ name = 'Certificates'; detail = "may live $certificateDays days (limit $maxCertificate)" }) }
        $facts.appCredentialLifetimeGaps = $lifetimeGaps.Count
        $affected.appCredentialLifetimeGaps = $lifetimeGaps.ToArray()
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
    # ID-025: whether an ordinary user may register an application, which is how a consent-phishing app or a
    # forgotten test app with a secret comes to exist.
    if ($null -eq $authz) { & $missing 'ID-025' '02-authorization-policy' }
    else {
        $mayRegister = & $v $authz 'defaultUserRolePermissions.allowedToCreateApps'
        if ($null -eq $mayRegister) { $notEvaluated['ID-025'] = 'The authorization policy did not say whether users may register applications.' }
        else { $facts.usersCanRegisterApps = [bool]($mayRegister -eq $true) }
    }
    # ID-030, ID-031, ID-033, ID-034: more switches of the authorization policy. Each is its own question, and one the
    # policy did not answer has no answer.
    if ($null -eq $authz) { foreach ($id in 'ID-030', 'ID-031', 'ID-033', 'ID-034', 'ID-040', 'ID-041') { & $missing $id '02-authorization-policy' } }
    else {
        $switch = {
            param([string] $Id, [string] $Path, [string] $Fact, [string] $What)
            $value = & $v $authz $Path
            if ($null -eq $value) { $notEvaluated[$Id] = "The authorization policy did not say whether $What." } else { $facts[$Fact] = [bool]($value -eq $true) }
        }
        & $switch 'ID-030' 'defaultUserRolePermissions.allowedToCreateTenants' 'usersCanCreateTenants' 'users may create tenants'
        & $switch 'ID-031' 'defaultUserRolePermissions.allowedToCreateSecurityGroups' 'usersCanCreateSecurityGroups' 'users may create security groups'
        & $switch 'ID-034' 'allowedToUseSSPR' 'adminsCanSelfServiceReset' 'administrators may reset their own password by self-service'
        # ID-040: the MSOnline PowerShell module, retired by Microsoft and still a way in for old scripts and old tooling.
        & $switch 'ID-040' 'blockMsolPowerShell' 'msolPowerShellBlocked' 'the MSOnline PowerShell module is blocked'
        # ID-041: whether a person can read the BitLocker recovery keys of the devices they own, from their own account.
        & $switch 'ID-041' 'defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice' 'usersCanReadOwnBitLockerKeys' 'people may read the BitLocker keys of their own devices'
        # ID-033: two ways into the directory with nothing but an email address: signing up for a self-service
        # subscription, and joining the tenant by proving ownership of a mailbox in one of its domains.
        $signUp = & $v $authz 'allowedToSignUpEmailBasedSubscriptions'; $joinByEmail = & $v $authz 'allowEmailVerifiedUsersToJoinOrganization'
        if ($null -eq $signUp -or $null -eq $joinByEmail) { $notEvaluated['ID-033'] = 'The authorization policy did not say whether people may join the tenant with an email address alone.' }
        else {
            $open = @($(if ($signUp -eq $true) { [ordered]@{ name = 'Email-based subscriptions'; detail = 'anyone with a mailbox in one of the tenant''s domains can sign up for a self-service subscription and get an account' } }), $(if ($joinByEmail -eq $true) { [ordered]@{ name = 'Join by email validation'; detail = 'anyone who proves they own a mailbox in one of the tenant''s domains gets an account in the directory' } })) | Where-Object { $_ }
            $facts.emailSelfJoinWays = @($open).Count
            $affected.emailSelfJoinWays = @($open)
        }
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
    # More directory settings. A tenant that never changed a group of settings has no object for it, and Microsoft's
    # defaults apply: that is an answer where the default is documented, and no answer where it is not.
    if ($null -eq $dirSettings) { foreach ($id in 'ID-032', 'ID-036', 'ID-038', 'ID-039') { & $missing $id '02-directory-settings' } }
    else {
        $settingsOf = { param([string] $TemplateId) $o = @($dirSettings | Where-Object { $_ -and [string](& $v $_ 'TemplateId') -eq $TemplateId }) | Select-Object -First 1; if ($o) { & $v $o 'Values' } }
        $isTrue = { param($x) [string]$x -match '(?i)^true$' }
        # ID-038: smart lockout. Microsoft's defaults are ten failed sign-ins and sixty seconds.
        $lockout = & $settingsOf '5cf42378-d67d-4f36-ba46-e8b86229381d'
        $threshold = $(if ($lockout -and [string](& $v $lockout 'LockoutThreshold') -match '^\d+$') { [int](& $v $lockout 'LockoutThreshold') } else { 10 })
        $seconds = $(if ($lockout -and [string](& $v $lockout 'LockoutDurationInSeconds') -match '^\d+$') { [int](& $v $lockout 'LockoutDurationInSeconds') } else { 60 })
        $maxThreshold = [int]$(if ($t.ContainsKey('maxLockoutThreshold')) { $t.maxLockoutThreshold } else { 10 }); $minSeconds = [int]$(if ($t.ContainsKey('minLockoutSeconds')) { $t.minLockoutSeconds } else { 60 })
        $facts.lockoutThreshold = $threshold; $facts.lockoutSeconds = $seconds
        $facts.smartLockoutOk = [bool]($threshold -le $maxThreshold -and $seconds -ge $minSeconds)
        # ID-032 and ID-039: Microsoft 365 groups. With no settings object everyone may create a group and no guest may own one.
        $unified = & $settingsOf '62375ab9-6b52-47ed-826b-58e47e0e304b'
        $facts.groupCreationOpenToAll = [bool](-not $unified -or [string](& $v $unified 'EnableGroupCreation') -eq '' -or (& $isTrue (& $v $unified 'EnableGroupCreation')))
        $facts.guestsCanOwnGroups = [bool]($unified -and (& $isTrue (& $v $unified 'AllowGuestsToBeGroupOwner')))
        # ID-036: a group or team owner agreeing to an app that reads the group's data. The default for a tenant with
        # no consent settings object is not one this check can state (verify), so it has no answer there.
        $consentSettings = & $settingsOf 'dffd5d46-495d-40a9-8e21-954ff55e198a'
        $ownerConsent = $(if ($consentSettings) { [string](& $v $consentSettings 'EnableGroupSpecificConsent') } else { '' })
        if (-not $ownerConsent) { $notEvaluated['ID-036'] = 'The tenant has no consent settings object, so Microsoft''s default for group owner consent applies, and the collection does not say what that is.' }
        else { $facts.groupOwnersCanConsent = [bool](& $isTrue $ownerConsent) }
    }
    # ID-035: a consent request Microsoft judges risky (an unverified publisher asking for more than basic permissions)
    # goes to an administrator. Two places say it: the authorization policy, and the consent settings object where
    # the tenant has one. Either saying "allowed" fails; neither saying anything is Microsoft's default, which blocks
    # (verify). Both files are needed: one alone could pass a tenant the other would fail.
    if ($null -eq $authz) { & $missing 'ID-035' '02-authorization-policy' }
    elseif ($null -eq $dirSettings) { & $missing 'ID-035' '02-directory-settings' }
    else {
        $riskyAllowed = & $v $authz 'allowUserConsentForRiskyApps'
        $blockSetting = ''
        $cs = @($dirSettings | Where-Object { $_ -and [string](& $v $_ 'TemplateId') -eq 'dffd5d46-495d-40a9-8e21-954ff55e198a' }) | Select-Object -First 1
        if ($cs) { $blockSetting = [string](& $v $cs 'Values.BlockUserConsentForRiskyApps') }
        $facts.riskyConsentAllowed = [bool]($riskyAllowed -eq $true -or $blockSetting -match '(?i)^false$')
        $facts.riskyConsentSetting = $(if ($null -ne $riskyAllowed -or $blockSetting) { 'set' } else { 'Microsoft default' })
    }

    $consent = & $load '02-admin-consent-request-policy'
    if ($null -eq $consent) { & $missing 'ID-009' '02-admin-consent-request-policy' }
    else {
        $facts.adminConsentWorkflowEnabled = [bool](& $v $consent 'isEnabled')
        $facts.adminConsentReviewers = @(& $v $consent 'reviewers').Count
    }
    # ID-037: a request nobody is told about waits until it expires. Judged only where the workflow is on (ID-009).
    if ($null -eq $consent) { & $missing 'ID-037' '02-admin-consent-request-policy' }
    elseif (-not $facts.adminConsentWorkflowEnabled) { $notEvaluated['ID-037'] = 'The admin consent workflow is off, so there are no requests to send a notice about. ID-009 comes first.' }
    elseif ($null -eq (& $v $consent 'notifyReviewers') -or $null -eq (& $v $consent 'requestDurationInDays')) { $notEvaluated['ID-037'] = 'The admin consent request policy did not say whether reviewers are notified or how long a request lasts.' }
    else {
        $maxDays = [int]$(if ($t.ContainsKey('maxConsentRequestDays')) { $t.maxConsentRequestDays } else { 30 })
        $days = [int](& $v $consent 'requestDurationInDays')
        $gaps = @($(if ((& $v $consent 'notifyReviewers') -ne $true) { [ordered]@{ name = 'New requests'; detail = 'reviewers are not emailed when someone asks' } }),
            $(if ((& $v $consent 'remindersEnabled') -ne $true) { [ordered]@{ name = 'Reminders'; detail = 'reviewers are not reminded before a request expires' } }),
            $(if ($days -gt $maxDays) { [ordered]@{ name = 'Expiry'; detail = "a request stays open $days days (limit $maxDays)" } })) | Where-Object { $_ }
        $facts.consentRequestDays = $days
        $facts.consentRequestGaps = @($gaps).Count
        $affected.consentRequestGaps = @($gaps)
    }

    $apps = & $load '10-app-registrations'
    if ($null -eq $apps) { foreach ($id in 'ID-010', 'ID-043', 'ID-044') { & $missing $id '10-app-registrations' } }
    else {
        # ID-043: app registrations that sign in with a client secret. ID-044: a certificate valid for longer than the
        # threshold, start to end; evidence from before the lifetime was saved cannot say.
        $rowsOfApps = @($apps | Where-Object { $_ })
        $withSecrets = @($rowsOfApps | Where-Object { [int]$_.Secrets -gt 0 })
        $facts.appsWithSecrets = $withSecrets.Count
        $affected.appsWithSecrets = @($withSecrets | ForEach-Object { [ordered]@{ name = [string]$_.DisplayName; detail = "$([int]$_.Secrets) client secret(s)" } })
        if ($rowsOfApps.Count -gt 0 -and @($rowsOfApps | Where-Object { $_.Contains('LongestCertDays') }).Count -eq 0) { $notEvaluated['ID-044'] = '10-app-registrations.json was collected before certificate lifetimes were saved. Collect Entra again (Resume-PostureRun -Collector Entra).' }
        else {
            $maxDays = [int]$(if ($t.ContainsKey('maxCertificateLifetimeDays')) { $t.maxCertificateLifetimeDays } else { 180 })
            $longLived = @($rowsOfApps | Where-Object { [int]$_.LongestCertDays -gt $maxDays })
            $facts.appsWithLongCertificates = $longLived.Count
            $affected.appsWithLongCertificates = @($longLived | ForEach-Object { [ordered]@{ name = [string]$_.DisplayName; detail = "a certificate valid for $([int]$_.LongestCertDays) days (limit $maxDays)" } })
        }
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

    # ID-045 and ID-046: credentials on a service principal itself. Any application's secret or certificate belongs
    # on its registration, where owners and expiry are looked after; one added to the service principal lets its
    # holder sign in as the application from outside it. On a Microsoft application it is a known way to keep access.
    $spRows = & $load '10-service-principals'
    if ($null -eq $spRows) { foreach ($id in 'ID-045', 'ID-046') { & $missing $id '10-service-principals' } }
    else {
        $allSps = @($spRows | Where-Object { $_ })
        if ($allSps.Count -gt 0 -and @($allSps | Where-Object { $_.Contains('Secrets') }).Count -eq 0) { foreach ($id in 'ID-045', 'ID-046') { $notEvaluated[$id] = '10-service-principals.json was collected before the credentials of a service principal were counted. Collect Entra again (Resume-PostureRun -Collector Entra).' } }
        else {
            $microsoftTenant = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
            $holding = @($allSps | Where-Object { [int]$_.Secrets + [int]$_.Certs -gt 0 })
            $describe = { param($row) [ordered]@{ name = [string]$row.DisplayName; detail = "$([int]$row.Secrets) secret(s), $([int]$row.Certs) certificate(s) on the service principal" } }
            $own = @($holding | Where-Object { [string]$_.AppOwnerOrganizationId -ne $microsoftTenant })
            $microsoft = @($holding | Where-Object { [string]$_.AppOwnerOrganizationId -eq $microsoftTenant })
            $facts.servicePrincipalsWithCredentials = $own.Count
            $affected.servicePrincipalsWithCredentials = @($own | ForEach-Object { & $describe $_ })
            $facts.microsoftAppsWithCredentials = $microsoft.Count
            $affected.microsoftAppsWithCredentials = @($microsoft | ForEach-Object { & $describe $_ })
        }
    }

    $xtap = & $load '02-cross-tenant-access-defaults'
    if ($null -eq $xtap) { & $missing 'ID-013' '02-cross-tenant-access-defaults'; & $missing 'ID-042' '02-cross-tenant-access-defaults' }
    else {
        # ID-042: the tenant restrictions policy blocks other organisations by default, for all users and all
        # applications. The policy says what is allowed; something has to enforce it on the device or the network
        # (NET-017 asks about Global Secure Access doing so).
        $restrictions = & $v $xtap 'tenantRestrictions'
        if ($null -eq $restrictions) { $notEvaluated['ID-042'] = 'The cross-tenant access defaults did not carry the tenant restrictions policy.' }
        else {
            $blocksAll = { param($part, [string] $target) ((& $v $part 'accessType') -eq 'blocked') -and [bool](@(& $v $part 'targets') | Where-Object { (& $v $_ 'target') -eq $target }) }
            $facts.tenantRestrictionsDefaultBlocks = (& $blocksAll (& $v $restrictions 'usersAndGroups') 'AllUsers') -and (& $blocksAll (& $v $restrictions 'applications') 'AllApplications')
        }
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
