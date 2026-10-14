# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-CollaborationFixtureObject {
    <#
    .SYNOPSIS
        Synthetic PnP.PowerShell and MicrosoftTeams cmdlet output by cmdlet name, for mocking the two entry points. Every value is made up.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name)

    $o = { param([hashtable] $h) [pscustomobject]$h }
    switch ($Name) {
        'Get-PnPTenant' {
            & $o @{
                SharingCapability = 'ExternalUserAndGuestSharing'; DefaultSharingLinkType = 'Internal'; DefaultLinkPermission = 'Edit'; RequireAnonymousLinksExpireInDays = -1
                FileAnonymousLinkType = 'Edit'; FolderAnonymousLinkType = 'Edit'; OneDriveSharingCapability = 'ExternalUserSharingOnly'; SharingDomainRestrictionMode = 'None'
                SharingAllowedDomainList = ''; SharingBlockedDomainList = ''; ExternalUserExpirationRequired = $true; ExternalUserExpireInDays = 60; ShowEveryoneClaim = $false
                ShowEveryoneExceptExternalUsersClaim = $true; ShowAllUsersClaim = $false; LegacyAuthProtocolsEnabled = $false; ConditionalAccessPolicy = 'AllowFullAccess'
                EnableRestrictedAccessControl = $false; EnableAzureADB2BIntegration = $true; PreventExternalUsersFromResharing = $true; NotifyOwnersWhenItemsReshared = $true
                RequireAcceptingAccountMatchInvitedAccount = $true; DisallowInfectedFileDownload = $true; Identity = 'https://contoso-admin.sharepoint.example'
            }
        }
        'Get-PnPTenantSite' {
            & $o @{ Url = 'https://contoso.sharepoint.example/sites/Finance'; Title = 'Finance'; Template = 'GROUP#0'; SharingCapability = 'ExternalUserSharingOnly'; StorageUsageCurrent = 1200; LastContentModifiedDate = [datetime]'2026-10-01'; Owner = 'finance-owners@contoso.example'; GroupId = 'g-fin'; SensitivityLabel = 'Confidential'; LockState = 'Unlock'; RestrictedAccessControl = $true; DenyAddAndCustomizePages = 'Enabled' }
            & $o @{ Url = 'https://contoso.sharepoint.example/sites/OldProject'; Title = 'Old Project'; Template = 'STS#3'; SharingCapability = 'ExternalUserAndGuestSharing'; StorageUsageCurrent = 30; LastContentModifiedDate = [datetime]'2024-01-01'; Owner = ''; GroupId = $null; SensitivityLabel = ''; LockState = 'Unlock'; RestrictedAccessControl = $false; DenyAddAndCustomizePages = 'Enabled' }
            & $o @{ Url = 'https://contoso-my.sharepoint.example/personal/admin1'; Title = 'Admin One'; Template = 'SPSPERS#10'; SharingCapability = 'ExternalUserSharingOnly'; StorageUsageCurrent = 500; LastContentModifiedDate = [datetime]'2026-10-10'; Owner = 'admin1@contoso.example'; GroupId = $null; SensitivityLabel = ''; LockState = 'Unlock'; RestrictedAccessControl = $false; DenyAddAndCustomizePages = 'Enabled' }
        }
        'Get-CsTenantFederationConfiguration' { & $o @{ Identity = 'Global'; AllowFederatedUsers = $true; AllowedDomains = 'AllowAllKnownDomains'; BlockedDomains = @(); AllowTeamsConsumer = $true; AllowPublicUsers = $false; AllowTeamsConsumerInbound = $true } }
        'Get-CsTeamsClientConfiguration' { & $o @{ Identity = 'Global'; AllowGuestUser = $true; AllowDropBox = $false; AllowBox = $false; AllowGoogleDrive = $false; AllowEmailIntoChannel = $true } }
        'Get-CsTeamsMeetingPolicy' { & $o @{ Identity = 'Global'; AllowAnonymousUsersToJoinMeeting = $true; AllowAnonymousUsersToStartMeeting = $false; AutoAdmittedUsers = 'EveryoneInCompanyExcludingGuests'; AllowExternalParticipantGiveRequestControl = $false } }
        'Get-CsExternalAccessPolicy' { & $o @{ Identity = 'Global'; EnableFederationAccess = $true; EnablePublicCloudAccess = $false; EnableTeamsConsumerAccess = $true } }
        'Get-CsTeamsAppPermissionPolicy' { & $o @{ Identity = 'Global'; DefaultCatalogAppsType = 'BlockedAppList'; GlobalCatalogAppsType = 'BlockedAppList'; PrivateCatalogAppsType = 'BlockedAppList'; GlobalCatalogApps = @() } }
        'Get-CsTeamsGuestMessagingConfiguration' { & $o @{ Identity = 'Global'; AllowUserEditMessage = $true; AllowUserDeleteMessage = $true; AllowGiphy = $true } }
        'Get-CsTeamsMessagingPolicy' { & $o @{ Identity = 'Global'; AllowUrlPreviews = $true; AllowUserChat = $true } }
        default { throw "Fixture has no output for $Name" }
    }
}
