# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Initialize-CollectionFixture {
    <#
    .SYNOPSIS
        Writes a small synthetic A.1 collection folder (identity and auth files) under -Root. Every value is made up.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Root)

    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    $w = { param([string] $Name, $Data) ConvertTo-Json -InputObject $Data -Depth 20 | Set-Content -LiteralPath (Join-Path $Root "$Name.json") }

    & $w '04-role-assignments-active' @(
        @{ Role = 'Global Administrator'; AssignmentType = 'Assigned'; PrincipalType = 'user'; PrincipalName = 'BreakGlass-01'; PrincipalUpn = 'breakglass01@contoso.example'; PrincipalSynced = $false; PrincipalId = 'bg1' }
        @{ Role = 'Global Administrator'; AssignmentType = 'Assigned'; PrincipalType = 'user'; PrincipalName = 'Admin One'; PrincipalUpn = 'admin1@contoso.example'; PrincipalSynced = $false; PrincipalId = 'u1' }
        @{ Role = 'Global Administrator'; AssignmentType = 'Assigned'; PrincipalType = 'user'; PrincipalName = 'Admin Two'; PrincipalUpn = 'admin2@contoso.example'; PrincipalSynced = $true; PrincipalId = 'u2' }
        @{ Role = 'Security Administrator'; AssignmentType = 'Activated'; PrincipalType = 'user'; PrincipalName = 'Admin Three'; PrincipalUpn = 'admin3@contoso.example'; PrincipalSynced = $false; PrincipalId = 'u3' }
        @{ Role = 'Global Administrator'; AssignmentType = 'Assigned'; PrincipalType = 'servicePrincipal'; PrincipalName = 'Legacy Sync App'; PrincipalUpn = $null; PrincipalSynced = $null; PrincipalId = 'sp9' }
        @{ Role = 'Global Reader'; AssignmentType = 'Assigned'; PrincipalType = 'user'; PrincipalName = 'Auditor'; PrincipalUpn = 'auditor@contoso.example'; PrincipalSynced = $false; PrincipalId = 'u5' }
    )
    & $w '04-role-assignments-pim-eligible' @(@{ Role = 'Security Administrator'; AssignmentType = 'Eligible'; PrincipalType = 'user'; PrincipalName = 'Admin Three'; PrincipalUpn = 'admin3@contoso.example'; PrincipalId = 'u3' })
    & $w '06-users' @(
        @{ Id = 'bg1'; UserPrincipalName = 'breakglass01@contoso.example'; DisplayName = 'BreakGlass-01'; AccountEnabled = $true; UserType = 'Member'; OnPremisesSyncEnabled = $false; LicenseCount = 0; LastInteractiveSignIn = '2026-01-01T00:00:00Z' }
        @{ Id = 'u1'; UserPrincipalName = 'admin1@contoso.example'; DisplayName = 'Admin One'; AccountEnabled = $true; UserType = 'Member'; OnPremisesSyncEnabled = $false; LicenseCount = 2; LastInteractiveSignIn = '2026-10-01T00:00:00Z' }
        @{ Id = 'u2'; UserPrincipalName = 'admin2@contoso.example'; DisplayName = 'Admin Two'; AccountEnabled = $true; UserType = 'Member'; OnPremisesSyncEnabled = $true; LicenseCount = 0; LastInteractiveSignIn = '2026-10-01T00:00:00Z' }
        @{ Id = 'u3'; UserPrincipalName = 'admin3@contoso.example'; DisplayName = 'Admin Three'; AccountEnabled = $true; UserType = 'Member'; OnPremisesSyncEnabled = $false; LicenseCount = 1; LastInteractiveSignIn = '2026-10-01T00:00:00Z' }
        @{ Id = 'g1'; UserPrincipalName = 'old_guest#EXT#@contoso.example'; DisplayName = 'Old Guest'; AccountEnabled = $true; UserType = 'Guest'; OnPremisesSyncEnabled = $false; LicenseCount = 0; LastInteractiveSignIn = '2025-01-01T00:00:00Z' }
        @{ Id = 'g2'; UserPrincipalName = 'new_guest#EXT#@contoso.example'; DisplayName = 'New Guest'; AccountEnabled = $true; UserType = 'Guest'; OnPremisesSyncEnabled = $false; LicenseCount = 0; LastInteractiveSignIn = '2026-10-10T00:00:00Z' }
        @{ Id = 'g3'; UserPrincipalName = 'never_guest#EXT#@contoso.example'; DisplayName = 'Never Guest'; AccountEnabled = $true; UserType = 'Guest'; OnPremisesSyncEnabled = $false; LicenseCount = 0; LastInteractiveSignIn = $null }
    )
    & $w '06-users-summary' @{ Total = 7; Members = 4; Guests = 3; SignInActivityAvailable = $true; StaleDays = 90 }
    & $w '02-authorization-policy' @{ id = 'authorizationPolicy'; defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy') } }
    & $w '02-admin-consent-request-policy' @{ isEnabled = $false; reviewers = @() }
    & $w '02-cross-tenant-access-defaults' @{ b2bCollaborationInbound = @{ usersAndGroups = @{ accessType = 'allowed'; targets = @(@{ target = 'AllUsers'; targetType = 'user' }) }; applications = @{ accessType = 'allowed'; targets = @(@{ target = 'AllApplications'; targetType = 'application' }) } }; inboundTrust = @{ isMfaAccepted = $false } }
    & $w '10-app-registrations' @(
        @{ DisplayName = 'Old App'; AppId = 'a1'; Secrets = 2; Certs = 0; EarliestExpiry = '2024-01-01T00:00:00Z'; ExpiredCredentials = 1 }
        @{ DisplayName = 'Soon App'; AppId = 'a2'; Secrets = 1; Certs = 0; EarliestExpiry = '2026-10-25T00:00:00Z'; ExpiredCredentials = 0 }
        @{ DisplayName = 'Fine App'; AppId = 'a3'; Secrets = 0; Certs = 1; EarliestExpiry = '2028-01-01T00:00:00Z'; ExpiredCredentials = 0 }
    )
    & $w '10-graph-app-permissions' @(
        @{ PrincipalDisplayName = 'Backup Tool'; PrincipalId = 'sp1'; PrincipalType = 'ServicePrincipal'; Permission = 'Mail.ReadWrite'; CreatedDateTime = '2025-01-01T00:00:00Z' }
        @{ PrincipalDisplayName = 'Reporter'; PrincipalId = 'sp2'; PrincipalType = 'ServicePrincipal'; Permission = 'Reports.Read.All'; CreatedDateTime = '2025-01-01T00:00:00Z' }
    )
    & $w '11-risky-users' @(
        @{ UserPrincipalName = 'admin1@contoso.example'; RiskLevel = 'high'; RiskState = 'atRisk'; RiskLastUpdatedDateTime = '2026-09-01T00:00:00Z' }
        @{ UserPrincipalName = 'admin3@contoso.example'; RiskLevel = 'high'; RiskState = 'atRisk'; RiskLastUpdatedDateTime = '2026-10-13T00:00:00Z' }
        @{ UserPrincipalName = 'auditor@contoso.example'; RiskLevel = 'low'; RiskState = 'remediated'; RiskLastUpdatedDateTime = '2026-01-01T00:00:00Z' }
    )
    & $w '02-authentication-methods-policy' @{
        policyMigrationState = 'migrationInProgress'
        authenticationMethodConfigurations = @(
            @{ id = 'Sms'; state = 'enabled'; includeTargets = @(@{ id = 'all_users'; targetType = 'group' }) }
            @{ id = 'Voice'; state = 'disabled'; includeTargets = @() }
            @{ id = 'MicrosoftAuthenticator'; state = 'enabled'; includeTargets = @(@{ id = 'all_users' }); featureSettings = @{ displayAppInformationRequiredState = @{ state = 'default' }; displayLocationInformationRequiredState = @{ state = 'enabled' } } }
            @{ id = 'Fido2'; state = 'enabled'; includeTargets = @(@{ id = 'all_users' }); isAttestationEnforced = $false; keyRestrictions = @{ isEnforced = $false } }
            @{ id = 'TemporaryAccessPass'; state = 'enabled'; isUsableOnce = $false; includeTargets = @(@{ id = 'all_users' }) }
        )
    }
    & $w '05-auth-registration-summary' @{ TotalMembers = 4; MfaRegisteredPct = 75; PasswordlessCapablePct = 50; SsprRegisteredPct = 25; Admins = 3 }
    & $w '05-auth-registration' @(
        @{ UserPrincipalName = 'breakglass01@contoso.example'; UserType = 'member'; IsAdmin = $true; MethodsRegistered = 'fido2' }
        @{ UserPrincipalName = 'admin1@contoso.example'; UserType = 'member'; IsAdmin = $true; MethodsRegistered = 'microsoftAuthenticatorPush;mobilePhone' }
        @{ UserPrincipalName = 'admin2@contoso.example'; UserType = 'member'; IsAdmin = $true; MethodsRegistered = 'passKeyDeviceBound' }
        @{ UserPrincipalName = 'admin3@contoso.example'; UserType = 'member'; IsAdmin = $false; MethodsRegistered = 'microsoftAuthenticatorPush' }
        @{ UserPrincipalName = 'auditor@contoso.example'; UserType = 'member'; IsAdmin = $false; MethodsRegistered = '' }
    )
    return $Root
}
