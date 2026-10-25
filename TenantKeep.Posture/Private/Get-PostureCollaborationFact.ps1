# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureCollaborationFact {
    <#
    .SYNOPSIS
        Fact provider for the collaboration domain (spec 4.6): SharePoint tenant sharing settings, site ownership,
        restricted access control, the Microsoft 365 group expiration policy, and Teams federation, guest access,
        meeting lobby and app permission settings.
    .DESCRIPTION
        Reads spo-tenant-settings, spo-sites-summary, 07-groups-ownerless, 02-group-lifecycle-policy and the
        teams-* files. Thresholds read: maxAnonymousLinkDays, maxGuestExpireDays. Profile read: externalCollaboration.
        The oversharing views that need SharePoint Advanced Management reports (Everyone-except-external sites, active
        anonymous links, inactive sites) are not collected yet.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [Parameter()] [System.Collections.IDictionary] $OrgProfile = @{},
        [Parameter()] [System.Collections.IDictionary] $Thresholds = @{}
    )

    $ErrorActionPreference = 'Stop'
    $t = @{ maxAnonymousLinkDays = 30; maxGuestExpireDays = 60 }
    foreach ($k in @($Thresholds.Keys)) { $t[$k] = $Thresholds[$k] }
    $load = {
        param([string] $Name)
        $f = Join-Path $Evidence "$Name.json"
        if (-not (Test-Path -LiteralPath $f)) { return $null }
        $text = Get-Content -Raw -LiteralPath $f
        if ([string]::IsNullOrWhiteSpace($text)) { return , @() }
        $parsed = ConvertFrom-Json -InputObject $text -AsHashtable -Depth 20
        if ($null -eq $parsed) { return , @() }
        return $parsed
    }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $rows = { param($o) @($o | Where-Object { $_ }) }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    $missing = { param([string[]] $Ids, [string] $File, [string] $Collector) foreach ($id in $Ids) { $notEvaluated[$id] = "$File.json was not collected (Invoke-PostureCollection -Collector $Collector; check errors.txt)." } }

    $spo = & $load 'spo-tenant-settings'
    $teamsFed = & $load 'teams-federation'
    if ($null -eq $spo -and $null -eq $teamsFed) { return @{ available = $false; reason = 'No SharePoint or Teams evidence in the folder (Invoke-PostureCollection -Collector SharePoint, Teams needs Connect-PnPOnline and Connect-MicrosoftTeams sessions).' } }

    # SharePoint tenant settings (CL-001 to CL-006, CL-008)
    if ($null -eq $spo) { & $missing @('CL-001', 'CL-002', 'CL-003', 'CL-004', 'CL-005', 'CL-006', 'CL-008') 'spo-tenant-settings' 'SharePoint' }
    else {
        $cap = [string](& $v $spo 'SharingCapability')
        $facts.sharingCapability = $cap
        $facts.anyoneLinksAllowed = $cap -eq 'ExternalUserAndGuestSharing'
        $facts.tenantSharingLevelOk = $cap -in @('Disabled', 'ExternalUserSharingOnly', 'ExistingExternalUserSharingOnly')
        $days = & $v $spo 'RequireAnonymousLinksExpireInDays'
        $facts.anonymousLinkExpireDays = $(if ($null -ne $days) { [int]$days } else { -1 })
        $facts.anonymousLinksControlled = (-not $facts.anyoneLinksAllowed) -or ($facts.anonymousLinkExpireDays -ge 1 -and $facts.anonymousLinkExpireDays -le [int]$t.maxAnonymousLinkDays)
        $facts.defaultSharingLinkType = [string](& $v $spo 'DefaultSharingLinkType')
        $facts.defaultLinkPermission = [string](& $v $spo 'DefaultLinkPermission')
        $facts.defaultLinkSpecificPeopleView = $facts.defaultSharingLinkType -eq 'Direct' -and $facts.defaultLinkPermission -eq 'View'
        $facts.sharingDomainRestrictionMode = [string](& $v $spo 'SharingDomainRestrictionMode')
        $facts.sharingDomainRestricted = $facts.sharingDomainRestrictionMode -in @('AllowList', 'BlockList')
        $facts.everyoneClaimsHidden = (& $v $spo 'ShowEveryoneClaim') -ne $true -and (& $v $spo 'ShowEveryoneExceptExternalUsersClaim') -ne $true -and (& $v $spo 'ShowAllUsersClaim') -ne $true
        $affected.everyoneClaimsShown = @(@(@('Everyone', (& $v $spo 'ShowEveryoneClaim')), @('Everyone except external users', (& $v $spo 'ShowEveryoneExceptExternalUsersClaim')), @('All Users', (& $v $spo 'ShowAllUsersClaim'))) | Where-Object { $_[1] -eq $true } | ForEach-Object { [ordered]@{ name = $_[0]; detail = 'shown in the people picker' } })
        $exp = & $v $spo 'ExternalUserExpireInDays'
        $facts.guestExpirationRequired = (& $v $spo 'ExternalUserExpirationRequired') -eq $true
        $facts.guestExpireDays = $(if ($null -ne $exp) { [int]$exp } else { -1 })
        $facts.guestExpirationOk = $facts.guestExpirationRequired -and $facts.guestExpireDays -ge 1 -and $facts.guestExpireDays -le [int]$t.maxGuestExpireDays
        $facts.restrictedAccessControlEnabled = (& $v $spo 'EnableRestrictedAccessControl') -eq $true
        $facts.legacyAuthProtocolsEnabled = (& $v $spo 'LegacyAuthProtocolsEnabled') -eq $true
    }

    # Ownerless sites and teams (CL-007)
    $sites = & $load 'spo-sites-summary'; $groups = & $load '07-groups-ownerless'; $groupSummary = & $load '07-groups-ownerless-summary'
    if ($null -eq $sites) { $notEvaluated['CL-007'] = 'spo-sites-summary.json was not collected (Invoke-PostureCollection -Collector SharePoint without -SkipSiteEnumeration).' }
    elseif ($null -eq $groups) { & $missing @('CL-007') '07-groups-ownerless' 'Entra' }
    else {
        $siteRows = & $load 'spo-sites'
        $facts.ownerlessSites = [int](& $v $sites 'Ownerless')
        $facts.ownerlessGroups = @(& $rows $groups).Count
        $facts.unifiedGroups = $(if ($null -ne $groupSummary) { [int](& $v $groupSummary 'UnifiedGroups') } else { $null })
        $affected.ownerless = @(@(@(& $rows $siteRows) | Where-Object { $_.Ownerless -eq $true } | ForEach-Object { [ordered]@{ name = [string]$_.Url; detail = "site ($($_.Template)) with no owner" } }) +
            @(& $rows $groups | ForEach-Object { [ordered]@{ name = [string]$_.DisplayName; detail = "Microsoft 365 group with no owner, created $([string]$_.CreatedDateTime)" } }))
        $facts.sitesAnonymousSharingAllowed = [int](& $v $sites 'AnonymousSharingAllowed')
    }

    # Group expiration policy (CL-009)
    $lifecycle = & $load '02-group-lifecycle-policy'
    if ($null -eq $lifecycle) { & $missing @('CL-009') '02-group-lifecycle-policy' 'Entra' }
    else {
        $facts.groupExpirationPolicy = (& $v $lifecycle 'Present') -eq $true -and [string](& $v $lifecycle 'ManagedGroupTypes') -in @('All', 'Selected')
        $facts.groupExpirationDays = & $v $lifecycle 'GroupLifetimeInDays'
    }

    # Teams (CL-010 to CL-014)
    if ($null -eq $teamsFed) { & $missing @('CL-010', 'CL-011') 'teams-federation' 'Teams' }
    else {
        $allowed = [string](& $v $teamsFed 'AllowedDomains')
        $facts.teamsFederationEnabled = (& $v $teamsFed 'AllowFederatedUsers') -eq $true
        $facts.teamsFederationAllowList = $facts.teamsFederationEnabled -and $allowed -notmatch 'AllowAllKnownDomains' -and $allowed -ne ''
        $facts.teamsFederationOpen = $facts.teamsFederationEnabled -and -not $facts.teamsFederationAllowList
        $facts.teamsConsumerBlocked = (& $v $teamsFed 'AllowTeamsConsumer') -ne $true -and (& $v $teamsFed 'AllowPublicUsers') -ne $true
    }
    $client = & $load 'teams-client-config'
    if ($null -eq $client) { & $missing @('CL-012') 'teams-client-config' 'Teams' }
    else {
        $facts.teamsGuestAccess = (& $v $client 'AllowGuestUser') -eq $true
        $facts.teamsGuestAccessGoverned = (-not $facts.teamsGuestAccess) -or [bool]($facts.Contains('guestExpirationOk') -and $facts.guestExpirationOk)
    }
    $meeting = & $load 'teams-meeting-policy-global'
    if ($null -eq $meeting) { & $missing @('CL-013') 'teams-meeting-policy-global' 'Teams' }
    else {
        $facts.anonymousMeetingJoin = (& $v $meeting 'AllowAnonymousUsersToJoinMeeting') -eq $true
        $facts.anonymousCanStartMeeting = (& $v $meeting 'AllowAnonymousUsersToStartMeeting') -eq $true
        $facts.autoAdmittedUsers = [string](& $v $meeting 'AutoAdmittedUsers')
        $facts.lobbyForExternal = $facts.autoAdmittedUsers -in @('EveryoneInCompany', 'EveryoneInCompanyExcludingGuests', 'OrganizerOnly', 'InvitedUsers')
    }
    $apps = & $load 'teams-app-permission-policies'
    if ($null -eq $apps) { & $missing @('CL-014') 'teams-app-permission-policies' 'Teams' }
    else {
        # (verify) app permission policies are being replaced by app centric management; the Global policy still reports the catalog types.
        $global = @(& $rows $apps | Where-Object { [string]$_.Identity -match 'Global$' } | Select-Object -First 1)
        $facts.thirdPartyAppsRestricted = [bool]($global.Count -gt 0 -and [string](& $v $global[0] 'GlobalCatalogAppsType') -eq 'AllowedAppList')
    }

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('spo-tenant-settings.json', 'teams-federation.json') }
}
