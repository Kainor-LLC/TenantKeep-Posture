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
    $t = @{ maxAnonymousLinkDays = 30; maxGuestExpireDays = 60; minOneDriveRetentionDays = 30; maxIdleSignOutMinutes = 480; maxVerificationCodeReauthDays = 30 }
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
    $rows = { param($o) @($o | Where-Object { $_ }) }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    $missing = { param([string[]] $Ids, [string] $File, [string] $Collector) foreach ($id in $Ids) { $notEvaluated[$id] = "$File.json was not collected (Invoke-PostureCollection -Collector $Collector; check errors.txt)." } }

    # The SharePoint admin read when it was collected, otherwise the part Graph returns (Read-PostureSharePointSetting).
    $spoRead = Read-PostureSharePointSetting -Evidence $Evidence
    $spo = $(if ($spoRead) { $spoRead.settings } else { $null })
    $graphOnly = $null -ne $spoRead -and $spoRead.source -eq 'graph'
    $adminOnly = { param([string] $Id, [string] $What) $notEvaluated[$Id] = "Graph's SharePoint settings do not include $What. It needs the SharePoint admin read: the TenantKeep SharePoint app for named admins (deploy/setup/Grant-PostureSharePointAccess.ps1), or the Windows collector, Get-SpoBaseline.ps1 (Export-PostureCollector -Kind SharePoint writes it with its instructions), brought in with Import-PostureEvidence." }
    $teamsFed = & $load 'teams-federation'
    if ($null -eq $spo -and $null -eq $teamsFed) { return @{ available = $false; reason = 'No SharePoint or Teams evidence in the folder (the Entra collector reads Graph''s SharePoint settings; Invoke-PostureCollection -Collector Teams needs a Teams session).' } }

    # SharePoint tenant settings (CL-001 to CL-006, CL-008, CL-016)
    if ($null -eq $spo) { foreach ($id in 'CL-001', 'CL-002', 'CL-003', 'CL-004', 'CL-005', 'CL-006', 'CL-008', 'CL-016', 'CL-021', 'CL-022', 'CL-025', 'CL-026') { $notEvaluated[$id] = 'No SharePoint settings were collected: the Entra collector reads them through Graph (SharePointTenantSettings.Read.All); check errors.txt.' } }
    else {
        $cap = [string](& $v $spo 'SharingCapability')
        $facts.sharingCapability = $cap
        $facts.anyoneLinksAllowed = $cap -eq 'ExternalUserAndGuestSharing'
        $facts.tenantSharingLevelOk = $cap -in @('Disabled', 'ExternalUserSharingOnly', 'ExistingExternalUserSharingOnly')
        $facts.sharingDomainRestrictionMode = [string](& $v $spo 'SharingDomainRestrictionMode')
        $facts.sharingDomainRestricted = $facts.sharingDomainRestrictionMode -in @('AllowList', 'BlockList')
        $facts.legacyAuthProtocolsEnabled = (& $v $spo 'LegacyAuthProtocolsEnabled') -eq $true
        # CL-025: apps that sign in to SharePoint with a user name and password, which skip the second factor. Both
        # ways of reading carry it; a value that did not come back is no answer.
        if ($null -eq (& $v $spo 'LegacyAuthProtocolsEnabled')) { $notEvaluated['CL-025'] = 'The SharePoint settings that were read did not say whether legacy authentication is allowed.' }
        # CL-026: whether a guest may share on something they do not own.
        $reshare = & $v $spo 'PreventExternalUsersFromResharing'
        if ($null -eq $reshare) { $notEvaluated['CL-026'] = 'The SharePoint settings that were read did not say whether guests may share items they do not own.' }
        else { $facts.guestsCanReshare = [bool]($reshare -ne $true) }
        $facts.externalSharingToNewPeople = $cap -in @('ExternalUserSharingOnly', 'ExternalUserAndGuestSharing')
    }
    # CL-017 to CL-019: three settings Graph carries whichever way the rest was read. A departed user's OneDrive
    # (the admin read has that one too), sync limited to the organisation's own domain-joined computers, and
    # signing idle browser sessions out. A value Graph did not return is no answer.
    $graphSettings = & $load 'spo-tenant-settings-graph'
    $keepDays = $(if ($null -ne $graphSettings) { & $v $graphSettings 'deletedUserPersonalSiteRetentionPeriodInDays' })
    if ($null -eq $keepDays -and $null -ne $spo -and -not $graphOnly) { $keepDays = & $v $spo 'OrphanedPersonalSitesRetentionPeriod' }
    if ($null -eq $keepDays -or "$keepDays" -eq '') { $notEvaluated['CL-017'] = 'How long a deleted user''s OneDrive is kept was not in what was read (Graph''s SharePoint settings, or the SharePoint admin read).' }
    else { $facts.oneDriveRetentionDays = [int]$keepDays }
    if ($null -eq $graphSettings) { foreach ($id in 'CL-018', 'CL-019') { $notEvaluated[$id] = 'spo-tenant-settings-graph.json was not collected: the Entra collector reads it through Graph (SharePointTenantSettings.Read.All); check errors.txt.' } }
    else {
        $restricted = & $v $graphSettings 'isUnmanagedSyncAppForTenantRestricted'
        if ($null -eq $restricted) { $notEvaluated['CL-018'] = 'Graph did not return whether OneDrive sync is limited to the organisation''s computers.' }
        else {
            $syncDomains = @(& $v $graphSettings 'allowedDomainGuidsForSyncApp' | Where-Object { $_ })
            $facts.oneDriveSyncAllowedDomains = $syncDomains.Count
            # On, with at least one domain named: on with none named lets no domain-joined computer sync, or all, depending on the client (verify), so it is not counted as limited.
            $facts.oneDriveSyncRestricted = [bool]($restricted -eq $true -and $syncDomains.Count -gt 0)
        }
        $idle = & $v $graphSettings 'idleSessionSignOut'
        $idleOn = $(if ($null -ne $idle) { & $v $idle 'isEnabled' })
        if ($null -eq $idleOn) { $notEvaluated['CL-019'] = 'Graph did not return the idle session sign-out setting.' }
        else {
            $facts.idleSignOutEnabled = [bool]($idleOn -eq $true)
            $facts.idleSignOutMinutes = $(if ($facts.idleSignOutEnabled) { [int][Math]::Round([double](& $v $idle 'signOutAfterInSeconds') / 60) } else { $null })
            $facts.idleSignOutWithinLimit = [bool]($facts.idleSignOutEnabled -and $facts.idleSignOutMinutes -gt 0 -and $facts.idleSignOutMinutes -le [int]$t.maxIdleSignOutMinutes)
        }
    }

    # With Graph alone: OneDrive and Anyone links still answer when the tenant level rules Anyone out, since neither
    # can be more open than the tenant. The rest needs the admin read.
    if ($graphOnly) {
        if ($facts.anyoneLinksAllowed) { & $adminOnly 'CL-016' 'the OneDrive sharing level'; & $adminOnly 'CL-002' 'the Anyone link expiry' }
        else { $facts.oneDriveAnyoneLinks = $false; $facts.anonymousLinksControlled = $true }
        & $adminOnly 'CL-003' 'the default sharing link'
        & $adminOnly 'CL-005' 'the Everyone claims in the people picker'
        & $adminOnly 'CL-006' 'the guest access expiry'
        & $adminOnly 'CL-008' 'restricted access control'
        if ($facts.anyoneLinksAllowed) { & $adminOnly 'CL-021' 'what an Anyone link may do' }
        if ($facts.externalSharingToNewPeople) { & $adminOnly 'CL-022' 'verification code reauthentication' }
    }
    elseif ($null -ne $spo) {
        # CL-016: OneDrive holds personal working files; Anyone links there are rarely deliberate.
        $facts.oneDriveAnyoneLinks = [string](& $v $spo 'OneDriveSharingCapability') -eq 'ExternalUserAndGuestSharing'
        $days = & $v $spo 'RequireAnonymousLinksExpireInDays'
        $facts.anonymousLinkExpireDays = $(if ($null -ne $days) { [int]$days } else { -1 })
        $facts.anonymousLinksControlled = (-not $facts.anyoneLinksAllowed) -or ($facts.anonymousLinkExpireDays -ge 1 -and $facts.anonymousLinkExpireDays -le [int]$t.maxAnonymousLinkDays)
        $facts.defaultSharingLinkType = [string](& $v $spo 'DefaultSharingLinkType')
        $facts.defaultLinkPermission = [string](& $v $spo 'DefaultLinkPermission')
        $facts.defaultLinkSpecificPeopleView = $facts.defaultSharingLinkType -eq 'Direct' -and $facts.defaultLinkPermission -eq 'View'
        $facts.everyoneClaimsHidden = (& $v $spo 'ShowEveryoneClaim') -ne $true -and (& $v $spo 'ShowEveryoneExceptExternalUsersClaim') -ne $true -and (& $v $spo 'ShowAllUsersClaim') -ne $true
        $affected.everyoneClaimsShown = @(@(@('Everyone', (& $v $spo 'ShowEveryoneClaim')), @('Everyone except external users', (& $v $spo 'ShowEveryoneExceptExternalUsersClaim')), @('All Users', (& $v $spo 'ShowAllUsersClaim'))) | Where-Object { $_[1] -eq $true } | ForEach-Object { [ordered]@{ name = $_[0]; detail = 'shown in the people picker' } })
        $exp = & $v $spo 'ExternalUserExpireInDays'
        $facts.guestExpirationRequired = (& $v $spo 'ExternalUserExpirationRequired') -eq $true
        $facts.guestExpireDays = $(if ($null -ne $exp) { [int]$exp } else { -1 })
        $facts.guestExpirationOk = $facts.guestExpirationRequired -and $facts.guestExpireDays -ge 1 -and $facts.guestExpireDays -le [int]$t.maxGuestExpireDays
        $facts.restrictedAccessControlEnabled = (& $v $spo 'EnableRestrictedAccessControl') -eq $true
        # CL-021: an Anyone link that lets its holder edit. Only the links' types are read; no link is.
        $fileLink = [string](& $v $spo 'FileAnonymousLinkType'); $folderLink = [string](& $v $spo 'FolderAnonymousLinkType')
        if ($facts.anyoneLinksAllowed -and (-not $fileLink -or -not $folderLink)) { $notEvaluated['CL-021'] = 'The SharePoint settings that were read did not say what an Anyone link may do.' }
        else { $facts.anyoneLinksViewOnly = [bool]($fileLink -eq 'View' -and $folderLink -eq 'View'); $facts.anyoneLinkPermissions = "files $fileLink, folders $folderLink" }
        # CL-022: people who sign in with a one-time code are asked for a new one after so many days. A collection
        # from before 2026-11-23 did not save the two settings.
        $codeRequired = & $v $spo 'EmailAttestationRequired'; $codeDays = & $v $spo 'EmailAttestationReAuthDays'
        if ($null -eq $codeRequired) { if ($facts.externalSharingToNewPeople) { $notEvaluated['CL-022'] = 'spo-tenant-settings.json was collected before TenantKeep read the verification code settings. Collect SharePoint again (Resume-PostureRun -Collector SharePoint).' } }
        else {
            $facts.verificationCodeReauthRequired = [bool]($codeRequired -eq $true)
            $facts.verificationCodeReauthDays = $(if ($null -ne $codeDays) { [int]$codeDays } else { -1 })
            $facts.verificationCodeReauthOk = [bool]($facts.verificationCodeReauthRequired -and $facts.verificationCodeReauthDays -ge 1 -and $facts.verificationCodeReauthDays -le [int]$t.maxVerificationCodeReauthDays)
        }
    }

    # Ownerless sites and teams (CL-007)
    $sites = & $load 'spo-sites-summary'; $groups = & $load '07-groups-ownerless'; $groupSummary = & $load '07-groups-ownerless-summary'
    if ($null -eq $sites) { $notEvaluated['CL-007'] = 'The site list was not collected: it comes from the SharePoint admin read (the TenantKeep SharePoint app, or Get-SpoBaseline.ps1 from Export-PostureCollector -Kind SharePoint, brought in with Import-PostureEvidence), without -SkipSiteEnumeration.' }
    elseif ($null -eq $groups) { & $missing @('CL-007') '07-groups-ownerless' 'Entra' }
    else {
        # The ownerless sites, a row at a time from the site list.
        $ownerlessSites = [System.Collections.Generic.List[object]]::new()
        $null = Read-PostureEvidenceRow -Folder $Evidence -Name 'spo-sites' -OnRow { param($_row) if (Test-PostureTrue $_row.Ownerless) { $ownerlessSites.Add($_row) } }
        $facts.ownerlessSites = [int](& $v $sites 'Ownerless')
        $facts.ownerlessGroups = @(& $rows $groups).Count
        $facts.unifiedGroups = $(if ($null -ne $groupSummary) { [int](& $v $groupSummary 'UnifiedGroups') } else { $null })
        $affected.ownerless = @(@(@($ownerlessSites) | ForEach-Object { [ordered]@{ name = [string]$_.Url; detail = "site ($($_.Template)) with no owner" } }) +
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

    # Broad sharing (CL-015) from the SharePoint Advanced Management site permissions report the admin downloads;
    # Import-PostureSharingReport or the run summarises it. No file is "not provided", never zero.
    $dag = & $load 'spo-dag-site-permissions'
    if ($null -eq $dag) { $notEvaluated['CL-015'] = 'The SharePoint site permissions report was not provided. Run Site permissions across your organization under Reports, Data access governance in the SharePoint admin center, download the CSV and add it with Import-PostureSharingReport.' }
    else {
        $dt = & $v $dag 'totals'
        $facts.oversharedSites = [int](& $v $dag 'exposedSites')
        foreach ($k in 'sites', 'sitesWithAnyoneLinks', 'anyoneLinks', 'sitesWithOrgLinks', 'orgLinks', 'sitesWithEeeu', 'eeeuGrants', 'sitesWithEveryone', 'everyoneGrants') { $facts["sharing$($k.Substring(0,1).ToUpper())$($k.Substring(1))"] = [int](& $v $dt $k) }
        $facts.sharingReportDateUtc = [string](& $v $dag 'reportDateUtc')
        $affected.oversharedSites = @(@(& $rows (& $v $dag 'listed')) | ForEach-Object {
                $parts = @(@(@('Anyone links', $_.anyone), @('organization-wide links', $_.org), @('Everyone except external users grants', $_.eeeu), @('Everyone grants', $_.everyone)) | Where-Object { [int]$_[1] -gt 0 } | ForEach-Object { "$($_[1]) $($_[0])" })
                [ordered]@{ name = [string]$_.url; detail = ($parts -join ', ') + $(if ($_.label) { "; label $($_.label)" } else { '; no sensitivity label' }) }
            })
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
    if ($null -eq $client) { & $missing @('CL-012', 'CL-020') 'teams-client-config' 'Teams' }
    else {
        $facts.teamsGuestAccess = (& $v $client 'AllowGuestUser') -eq $true
        # CL-020: a channel's email address, which lets anyone who learns it post into the channel.
        $channelMail = & $v $client 'AllowEmailIntoChannel'
        if ($null -eq $channelMail) { $notEvaluated['CL-020'] = 'The Teams client configuration did not say whether channels accept email.' }
        else { $facts.teamsEmailIntoChannel = [bool]($channelMail -eq $true) }
        # Guests off needs nothing more. Guests on is governed by guest expiry, which only the SharePoint admin read
        # reports: without it the answer is unknown, not "ungoverned".
        $facts.teamsGuestAccessGoverned = $(if (-not $facts.teamsGuestAccess) { $true } elseif ($facts.Contains('guestExpirationOk')) { [bool]$facts.guestExpirationOk } else { $null })
    }
    $meeting = & $load 'teams-meeting-policy-global'
    if ($null -eq $meeting) { & $missing @('CL-013', 'CL-023', 'CL-024', 'CL-027') 'teams-meeting-policy-global' 'Teams' }
    else {
        $facts.anonymousMeetingJoin = (& $v $meeting 'AllowAnonymousUsersToJoinMeeting') -eq $true
        $facts.anonymousCanStartMeeting = (& $v $meeting 'AllowAnonymousUsersToStartMeeting') -eq $true
        $facts.autoAdmittedUsers = [string](& $v $meeting 'AutoAdmittedUsers')
        $facts.lobbyForExternal = $facts.autoAdmittedUsers -in @('EveryoneInCompany', 'EveryoneInCompanyExcludingGuests', 'OrganizerOnly', 'InvitedUsers')
        # CL-023 and CL-024: an outside participant taking control of a shared screen, and callers by phone walking
        # past the lobby. Each is one setting of the global meeting policy; one that did not come back is no answer.
        $control = & $v $meeting 'AllowExternalParticipantGiveRequestControl'
        if ($null -eq $control) { $notEvaluated['CL-023'] = 'The global meeting policy did not say whether outside participants may take control.' }
        else { $facts.teamsExternalControl = [bool]($control -eq $true) }
        $dialIn = & $v $meeting 'AllowPSTNUsersToBypassLobby'
        if ($null -eq $dialIn) { $notEvaluated['CL-024'] = 'The global meeting policy did not say whether callers by phone skip the lobby.' }
        else { $facts.teamsDialInBypassLobby = [bool]($dialIn -eq $true) }
        # CL-027: whether anyone may record a meeting under the policy everybody gets. A recording holds all that was
        # said and shown, and lands in the recorder's OneDrive or the channel's site.
        $recording = & $v $meeting 'AllowCloudRecording'
        if ($null -eq $recording) { $notEvaluated['CL-027'] = 'The global meeting policy did not say whether meetings may be recorded.' }
        else { $facts.teamsRecordingByDefault = [bool]($recording -eq $true) }
    }
    # CL-028: a live event recorded always, whatever its organiser wants. One setting of the global live events policy,
    # which a collection saves from version 0.4.0.
    $liveEvents = & $load 'teams-live-event-policy-global'
    if ($null -eq $liveEvents) { & $missing @('CL-028') 'teams-live-event-policy-global' 'Teams' }
    else {
        $recordingMode = [string](& $v $liveEvents 'BroadcastRecordingMode')
        if (-not $recordingMode) { $notEvaluated['CL-028'] = 'The global live events policy did not say when an event is recorded.' }
        else { $facts.teamsLiveEventRecordingMode = $recordingMode; $facts.teamsLiveEventsAlwaysRecorded = [bool]($recordingMode -eq 'AlwaysEnabled') }
    }
    # CL-014. Under app centric management the org-wide setting for third-party apps decides whether every third-party
    # app is available by default; GlobalApp is that setting, as GlobalCatalogApps named third-party apps in the old
    # permission policies (verify: Microsoft's cmdlet page lists DefaultApp, GlobalApp and PrivateApp without saying which
    # is which). A tenant not moved yet, or evidence from before this read, falls back to the global permission policy.
    $appSettings = & $load 'teams-app-settings'
    # The fallback is for a tenant not moved yet and for evidence from before this read. A run that tried the read and
    # could not make it is neither: the old permission policy is not what a moved tenant goes by, so judging on it
    # would answer for the wrong setting.
    $appSettingsFailed = $false
    if ($null -eq $appSettings) { $appSettingsFailed = @(Read-PostureRunFailure -Folder $Evidence | Where-Object { $_ -and [string]$_['step'] -eq 'Teams org-wide app settings' }).Count -gt 0 }
    $thirdParty = @($(if ($null -ne $appSettings) { & $rows $appSettings | Where-Object { [string](& $v $_ 'SettingName') -eq 'GlobalApp' } }) | Select-Object -First 1)
    $apps = & $load 'teams-app-permission-policies'
    if ($thirdParty.Count -and [string](& $v $thirdParty[0] 'SettingValue')) {
        $default = [string](& $v $thirdParty[0] 'SettingValue')
        $facts.thirdPartyAppsRestricted = $default -ne 'All'
        $facts.thirdPartyAppsSource = 'app centric management'
        # Every app's availability, all kinds together: the per-app list carries no publisher, so it is context, not the verdict.
        $catalog = & $load 'teams-app-availability'
        $tally = ''
        if ($null -ne $catalog) {
            $all = @(& $rows $catalog | Where-Object { $_ })
            $open = @($all | Where-Object { [string](& $v $_ 'IsBlocked') -ne 'Blocked' })
            $tally = "; of the $($all.Count) apps in the catalog, $(@($open | Where-Object { [string](& $v $_ 'AvailableTo') -eq 'Everyone' }).Count) are available to everyone, $(@($open | Where-Object { [string](& $v $_ 'AvailableTo') -eq 'UsersandGroups' }).Count) to named users or groups, and $(@($all | Where-Object { [string](& $v $_ 'IsBlocked') -eq 'Blocked' }).Count) are blocked"
        }
        $affected.thirdPartyAppsRestricted = @($(if (-not $facts.thirdPartyAppsRestricted) { [ordered]@{ name = 'Org-wide app settings'; detail = "every third-party app is available to everyone unless it is limited one by one$tally" } }))
    }
    elseif ($appSettingsFailed) { $notEvaluated['CL-014'] = 'The org-wide app settings could not be read in this run (Run Health says why), and the older app permission policy is not what a tenant on app centric management goes by.' }
    elseif ($null -ne $apps) {
        $global = @(& $rows $apps | Where-Object { [string]$_.Identity -match 'Global$' } | Select-Object -First 1)
        $facts.thirdPartyAppsRestricted = [bool]($global.Count -gt 0 -and [string](& $v $global[0] 'GlobalCatalogAppsType') -eq 'AllowedAppList')
        $facts.thirdPartyAppsSource = 'app permission policy'
        $affected.thirdPartyAppsRestricted = @($(if (-not $facts.thirdPartyAppsRestricted) { [ordered]@{ name = 'Global app permission policy'; detail = "third-party apps: $(if ($global.Count) { [string](& $v $global[0] 'GlobalCatalogAppsType') } else { 'no global policy' })" } }))
    }
    else { & $missing @('CL-014') 'teams-app-settings' 'Teams' }
    # CL-029: custom apps, the ones somebody in the organisation uploads. The same two sources as CL-014: the org-wide
    # setting PrivateApp under app centric management (verify: Microsoft's cmdlet page does not say which of DefaultApp,
    # GlobalApp and PrivateApp is which; PrivateCatalogApps named custom apps in the old permission policies), else the
    # global permission policy.
    $customApps = @($(if ($null -ne $appSettings) { & $rows $appSettings | Where-Object { [string](& $v $_ 'SettingName') -eq 'PrivateApp' } }) | Select-Object -First 1)
    if ($customApps.Count -and [string](& $v $customApps[0] 'SettingValue')) {
        $facts.customAppsRestricted = [string](& $v $customApps[0] 'SettingValue') -ne 'All'
        $affected.customAppsRestricted = @($(if (-not $facts.customAppsRestricted) { [ordered]@{ name = 'Org-wide app settings'; detail = 'every custom app is available to everyone unless it is limited one by one' } }))
    }
    elseif ($appSettingsFailed) { $notEvaluated['CL-029'] = 'The org-wide app settings could not be read in this run (Run Health says why), and the older app permission policy is not what a tenant on app centric management goes by.' }
    elseif ($null -ne $apps) {
        $globalApps = @(& $rows $apps | Where-Object { [string]$_.Identity -match 'Global$' } | Select-Object -First 1)
        $customType = $(if ($globalApps.Count) { [string](& $v $globalApps[0] 'PrivateCatalogAppsType') } else { '' })
        if (-not $customType) { $notEvaluated['CL-029'] = 'The global app permission policy did not say how custom apps are treated.' }
        else {
            $facts.customAppsRestricted = [bool]($customType -eq 'AllowedAppList')
            $affected.customAppsRestricted = @($(if (-not $facts.customAppsRestricted) { [ordered]@{ name = 'Global app permission policy'; detail = "custom apps: $customType" } }))
        }
    }
    else { & $missing @('CL-029') 'teams-app-settings' 'Teams' }

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('spo-tenant-settings.json', 'teams-federation.json', 'spo-dag-site-permissions.json') }
}
