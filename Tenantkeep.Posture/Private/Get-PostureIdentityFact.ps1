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
    $t = @{ minGlobalAdmins = 2; maxGlobalAdmins = 5; credentialExpiryWarningDays = 30; riskyUserMaxAgeDays = 7; inactiveGuestDays = 90 }
    foreach ($k in @($Thresholds.Keys)) { $t[$k] = $Thresholds[$k] }

    $load = {
        param([string] $Name)
        $f = Join-Path $Evidence "$Name.json"
        if (-not (Test-Path -LiteralPath $f)) { return $null }
        $text = Get-Content -Raw -LiteralPath $f
        if ([string]::IsNullOrWhiteSpace($text)) { return , @() }
        $parsed = ConvertFrom-Json -InputObject $text -AsHashtable -Depth 20
        # An empty JSON array parses to nothing; keep it distinct from a missing file.
        if ($null -eq $parsed) { return , @() }
        return $parsed
    }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    $missing = { param([string] $Id, [string] $File) $notEvaluated[$Id] = "$File.json was not collected (run Invoke-PostureCollection, check errors.txt and the scopes)." }

    $active = & $load '04-role-assignments-active'
    $eligible = & $load '04-role-assignments-pim-eligible'
    $users = & $load '06-users'
    $usersSummary = & $load '06-users-summary'
    $usersByUpn = @{}; $usersById = @{}
    foreach ($u in @($users | Where-Object { $_ })) { if ($u.UserPrincipalName) { $usersByUpn[[string]$u.UserPrincipalName] = $u }; if ($u.Id) { $usersById[[string]$u.Id] = $u } }

    # Break-glass accounts: profile list first, else name heuristic over users.
    $bgNames = @($OrgProfile['breakGlass'] | Where-Object { $_ })
    $isBreakGlassUser = {
        param($upn, $name)
        if ($bgNames.Count -gt 0) { return [bool]($bgNames | Where-Object { $_ -eq $upn -or $_ -eq $name }) }
        return ([string]$upn -match '(?i)break.?glass|emergency') -or ([string]$name -match '(?i)break.?glass|emergency')
    }
    $privilegedRoles = @('Global Administrator', 'Application Administrator', 'Authentication Administrator', 'Billing Administrator', 'Cloud Application Administrator',
        'Conditional Access Administrator', 'Exchange Administrator', 'Helpdesk Administrator', 'Password Administrator', 'Privileged Authentication Administrator',
        'Privileged Role Administrator', 'Security Administrator', 'SharePoint Administrator', 'User Administrator', 'Intune Administrator', 'Hybrid Identity Administrator')

    if ($null -eq $active) {
        foreach ($id in 'ID-001', 'ID-002', 'ID-003', 'ID-004', 'ID-007') { & $missing $id '04-role-assignments-active' }
    }
    else {
        $permanent = @($active | Where-Object { $_.AssignmentType -ne 'Activated' })
        $ga = @($permanent | Where-Object { $_.Role -eq 'Global Administrator' })
        $facts.globalAdmins = $ga.Count
        $affected.globalAdmins = @($ga | ForEach-Object { [ordered]@{ name = "$($_.PrincipalName)"; detail = "$($_.PrincipalType) $($_.PrincipalUpn) ($($_.AssignmentType))" } })

        $outside = @($permanent | Where-Object { $_.Role -in $privilegedRoles -and $_.PrincipalType -eq 'user' -and -not (& $isBreakGlassUser $_.PrincipalUpn $_.PrincipalName) })
        $facts.permanentPrivilegedOutsideBreakGlass = $outside.Count
        $facts.eligiblePrivileged = @(@($eligible) | Where-Object { $_.Role -in $privilegedRoles }).Count
        $affected.permanentPrivilegedOutsideBreakGlass = @($outside | ForEach-Object { [ordered]@{ name = "$($_.PrincipalName): $($_.Role)"; detail = "permanent $($_.Role) for $($_.PrincipalUpn)" } })

        $synced = @($permanent | Where-Object { $_.PrincipalSynced -eq $true })
        $facts.adminsSyncedFromOnPrem = $synced.Count
        $affected.adminsSyncedFromOnPrem = @($synced | ForEach-Object { [ordered]@{ name = "$($_.PrincipalName): $($_.Role)"; detail = 'synced from on-premises AD' } })

        $adminUsers = @($permanent | Where-Object { $_.PrincipalType -eq 'user' -and $_.PrincipalUpn } | ForEach-Object { $_.PrincipalUpn } | Sort-Object -Unique)
        if ($null -eq $users) { & $missing 'ID-004' '06-users' }
        else {
            $licensed = @($adminUsers | Where-Object { $usersByUpn.ContainsKey($_) -and [int]$usersByUpn[$_].LicenseCount -gt 0 -and -not (& $isBreakGlassUser $_ $usersByUpn[$_].DisplayName) })
            $facts.adminsWithLicenses = $licensed.Count
            $affected.adminsWithLicenses = @($licensed | ForEach-Object { [ordered]@{ name = $_; detail = "$($usersByUpn[$_].LicenseCount) license(s); an admin account should be a separate, unlicensed identity" } })
        }

        $spRoles = @($permanent | Where-Object { $_.PrincipalType -eq 'servicePrincipal' })
        $facts.servicePrincipalsWithRoles = $spRoles.Count
        $facts.servicePrincipalsWithGlobalAdmin = @($spRoles | Where-Object { $_.Role -eq 'Global Administrator' }).Count
        $affected.servicePrincipalsWithRoles = @($spRoles | ForEach-Object { [ordered]@{ name = "$($_.PrincipalName): $($_.Role)"; detail = 'service principal holding a directory role' } })
    }

    if ($null -eq $users) { & $missing 'ID-005' '06-users' }
    else {
        $bg = @($users | Where-Object { & $isBreakGlassUser $_.UserPrincipalName $_.DisplayName })
        $facts.breakGlassAccounts = $bg.Count
        $facts.breakGlassSynced = @($bg | Where-Object { $_.OnPremisesSyncEnabled -eq $true }).Count
        $facts.breakGlassDisabled = @($bg | Where-Object { $_.AccountEnabled -eq $false }).Count
        $affected.breakGlassProblems = @(@($bg | Where-Object { $_.OnPremisesSyncEnabled -eq $true } | ForEach-Object { [ordered]@{ name = $_.UserPrincipalName; detail = 'break-glass account is synced from on-premises AD' } }) +
            @($bg | Where-Object { $_.AccountEnabled -eq $false } | ForEach-Object { [ordered]@{ name = $_.UserPrincipalName; detail = 'break-glass account is disabled' } }))
    }

    $notEvaluated['ID-006'] = 'PIM role management policies are not collected yet (planned A.1 addition).'
    $notEvaluated['ID-014'] = 'Azure diagnostic settings are not collected yet (Azure collector, spec 4.13).'

    $authz = & $load '02-authorization-policy'
    if ($null -eq $authz) { & $missing 'ID-008' '02-authorization-policy' }
    else {
        $grants = @(& $v $authz 'defaultUserRolePermissions.permissionGrantPoliciesAssigned')
        $facts.userConsentMode = if ($grants.Count -eq 0) { 'none' } elseif ($grants -match 'microsoft-user-default-low') { 'low' } else { 'all' }
        $facts.userConsentPolicies = ($grants -join ', ')
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

    if ($null -eq $usersSummary -or $null -eq $users) { & $missing 'ID-012' '06-users-summary' }
    elseif (-not (& $v $usersSummary 'SignInActivityAvailable')) { $notEvaluated['ID-012'] = 'Sign-in activity was not available (AuditLog.Read.All), so guest inactivity cannot be measured.' }
    else {
        $cutoff = $AsOf.AddDays(-[int]$t.inactiveGuestDays)
        $inactive = @($users | Where-Object { $_.UserType -eq 'Guest' -and (-not $_.LastInteractiveSignIn -or (ConvertTo-PostureUtcDateTime $_.LastInteractiveSignIn) -lt $cutoff) })
        $facts.inactiveGuests = $inactive.Count
        $facts.guests = @($users | Where-Object { $_.UserType -eq 'Guest' }).Count
        $affected.inactiveGuests = @($inactive | ForEach-Object { [ordered]@{ name = $_.UserPrincipalName; detail = $(if ($_.LastInteractiveSignIn) { "last sign-in $((ConvertTo-PostureUtcDateTime $_.LastInteractiveSignIn).ToString('yyyy-MM-dd'))" } else { 'never signed in' }) } })
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
    }

    $risky = & $load '11-risky-users'
    if ($null -eq $risky) { $notEvaluated['ID-015'] = '11-risky-users.json was not collected (needs Entra ID P2 and IdentityRiskyUser.Read.All).' }
    else {
        $old = $AsOf.AddDays(-[int]$t.riskyUserMaxAgeDays)
        $stale = @($risky | Where-Object { $_.RiskLevel -eq 'high' -and $_.RiskState -eq 'atRisk' -and $_.RiskLastUpdatedDateTime -and (ConvertTo-PostureUtcDateTime $_.RiskLastUpdatedDateTime) -lt $old })
        $facts.highRiskUsersUnaddressed = $stale.Count
        $affected.highRiskUsersUnaddressed = @($stale | ForEach-Object { [ordered]@{ name = $_.UserPrincipalName; detail = "high risk since $((ConvertTo-PostureUtcDateTime $_.RiskLastUpdatedDateTime).ToString('yyyy-MM-dd'))" } })
    }

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('04-role-assignments-active.json', '06-users.json', '02-authorization-policy.json', '10-app-registrations.json', '10-graph-app-permissions.json') }
}
