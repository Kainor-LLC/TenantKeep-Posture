# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# The reads added with catalog 2026.11.1, which need no new permission: Secure Score over 90 days, subscriptions,
# Apple Automated Device Enrollment tokens and certificate connectors, applications that hold Graph permissions
# they have stopped using, Azure Policy compliance, Azure Lighthouse delegations, Direct Send, and three OneDrive
# and SharePoint settings. Each from evidence written here; every value is made up.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-reads-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $script:AsOf = [datetime]::new(2026, 11, 21, 0, 0, 0, [System.DateTimeKind]::Utc)
    $script:Folder = { param([string] $Name) $f = Join-Path $script:Root $Name; New-Item -ItemType Directory -Path $f -Force | Out-Null; InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache -Confirm:$false }; $f }
    $script:Write = { param([string] $Folder, [string] $Name, $Data) ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Folder "$Name.json") }
    $script:Day = { param([double] $Ago) $script:AsOf.AddDays(-$Ago).ToString('yyyy-MM-ddTHH:mm:ssZ') }
}

AfterAll {
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
}

Describe 'Secure Score over the last 90 days (OP-009)' {
    BeforeAll {
        $script:Ops = { param([string] $Folder) InModuleScope TenantKeep.Posture -Parameters @{ E = $Folder; AsOf = $script:AsOf } { param($E, $AsOf) Get-PostureOperationsFact -Evidence $E -OrgProfile @{} -Thresholds @{} -AsOf $AsOf } }
    }

    It 'measures the fall from the best day, as a share of the maximum' {
        $f = & $script:Folder 'score-fell'
        # 70% thirty days ago, 62% today, with the maximum raised on the way (Microsoft added controls).
        & $script:Write $f 'def-06-secure-score-history' @(0..59 | ForEach-Object { @{ Date = (& $script:Day $_); CurrentScore = $(if ($_ -ge 30) { 630 } else { 620 }); MaxScore = $(if ($_ -ge 30) { 900 } else { 1000 }) } })
        $r = & $script:Ops $f
        $r.facts.secureScoreHistoryDays | Should -Be 60
        $r.facts.secureScorePeakPct | Should -Be 70
        $r.facts.secureScoreDropPoints | Should -Be 8
        $r.notEvaluated.ContainsKey('OP-009') | Should -BeFalse
        @($r.facts.secureScoreHistory)[-1].value | Should -Be 62 -Because 'the history is oldest first, for the chart'
    }

    It 'is zero for a score that only rose' {
        $f = & $script:Folder 'score-rose'
        & $script:Write $f 'def-06-secure-score-history' @(0..20 | ForEach-Object { @{ Date = (& $script:Day $_); CurrentScore = 700 - $_; MaxScore = 1000 } })
        (& $script:Ops $f).facts.secureScoreDropPoints | Should -Be 0
    }

    It 'has no answer with under a week of history, or none collected' {
        $f = & $script:Folder 'score-short'
        & $script:Write $f 'def-06-secure-score-history' @(0..2 | ForEach-Object { @{ Date = (& $script:Day $_); CurrentScore = 500; MaxScore = 1000 } })
        (& $script:Ops $f).notEvaluated['OP-009'] | Should -Match '3 day\(s\) of history'
        (& $script:Ops (& $script:Folder 'score-none')).notEvaluated['OP-009'] | Should -Match 'def-06-secure-score-history\.json was not collected'
    }
}

Describe 'Subscriptions (OP-010) and the expiry calendar' {
    BeforeAll {
        $script:Subs = & $script:Folder 'subs'
        & $script:Write $script:Subs '01-subscriptions' @(
            @{ SkuPartNumber = 'SPE_E5'; Status = 'Enabled'; IsTrial = $false; TotalLicenses = 400; NextLifecycleDateTime = (& $script:Day -10) }
            @{ SkuPartNumber = 'TEAMS_PREMIUM'; Status = 'Enabled'; IsTrial = $true; TotalLicenses = 25; NextLifecycleDateTime = (& $script:Day -12) }
            @{ SkuPartNumber = 'VISIOCLIENT'; Status = 'Warning'; IsTrial = $false; TotalLicenses = 6; NextLifecycleDateTime = (& $script:Day -19) }
            @{ SkuPartNumber = 'PROJECT_P1'; Status = 'Suspended'; IsTrial = $false; TotalLicenses = 2; NextLifecycleDateTime = (& $script:Day -60) }
            @{ SkuPartNumber = 'OLD_PLAN'; Status = 'Deleted'; IsTrial = $false; TotalLicenses = 1; NextLifecycleDateTime = $null }
        )
        & $script:Write $script:Subs '09-apple-ade-tokens' @(@{ TokenName = 'Apple Business Manager'; TokenExpirationDateTime = (& $script:Day -20) })
        $script:SubFacts = InModuleScope TenantKeep.Posture -Parameters @{ E = $script:Subs; AsOf = $script:AsOf } { param($E, $AsOf) Get-PostureOperationsFact -Evidence $E -OrgProfile @{} -Thresholds @{} -AsOf $AsOf }
    }

    It 'lists the subscriptions in their grace period, suspended or locked out, and not a deleted one' {
        $script:SubFacts.facts.subscriptions | Should -Be 4
        $script:SubFacts.facts.subscriptionsPastTerm | Should -Be 2
        $script:SubFacts.facts.trialSubscriptions | Should -Be 1
        @($script:SubFacts.affected.subscriptionsPastTerm | ForEach-Object { "$($_.name): $($_.detail)" }) | Should -Be @('VISIOCLIENT: in its grace period, 6 licence(s); next change 2026-12-10', 'PROJECT_P1: suspended, 2 licence(s); next change 2027-01-20')
    }

    It 'puts the trial, the grace period and the Apple enrollment token on the calendar, and not a paid subscription''s renewal' {
        $kinds = @($script:SubFacts.facts.expiryCalendar | ForEach-Object { "$($_.kind): $($_.name) in $($_.days)" })
        $kinds | Should -Contain 'Trial subscription: TEAMS_PREMIUM in 12'
        $kinds | Should -Contain 'Subscription in its grace period: VISIOCLIENT in 19'
        $kinds | Should -Contain 'Apple ADE token: Apple Business Manager in 20'
        @($kinds | Where-Object { $_ -match 'SPE_E5|PROJECT_P1' }) | Should -BeNullOrEmpty -Because 'a paid subscription in good standing renews on its date, and a suspended one has already lapsed'
        $script:SubFacts.facts.expiringWithinWarning | Should -Be 3
    }

    It 'has no answer for the subscriptions when they were not collected' {
        $r = InModuleScope TenantKeep.Posture -Parameters @{ E = (& $script:Folder 'no-subs') } { param($E) Get-PostureOperationsFact -Evidence $E -OrgProfile @{} -Thresholds @{} }
        $r.notEvaluated['OP-010'] | Should -Match '01-subscriptions\.json was not collected'
    }
}

Describe 'Intune certificate connectors (DEV-024)' {
    BeforeAll {
        $script:Devices = { param([string] $Folder) InModuleScope TenantKeep.Posture -Parameters @{ E = $Folder } { param($E) Get-PostureDevicesFact -Evidence $E -OrgProfile @{} -Thresholds @{} } }
    }

    It 'lists a connector Intune calls inactive, one silent for days, and one never heard from' {
        $f = & $script:Folder 'connectors'
        & $script:Write $f '09-certificate-connectors' @(
            @{ DisplayName = 'Certificate Connector'; MachineName = 'PKI01'; State = 'active'; LastConnectionDateTime = (& $script:Day 0); DaysSinceLastConnection = 0 }
            @{ DisplayName = 'Certificate Connector'; MachineName = 'PKI02'; State = 'inactive'; LastConnectionDateTime = (& $script:Day 1); DaysSinceLastConnection = 1 }
            @{ DisplayName = 'Certificate Connector'; MachineName = 'PKI03'; State = 'active'; LastConnectionDateTime = (& $script:Day 9); DaysSinceLastConnection = 9 }
            @{ DisplayName = 'Certificate Connector'; MachineName = 'PKI04'; State = 'none'; LastConnectionDateTime = $null; DaysSinceLastConnection = $null }
        )
        $r = & $script:Devices $f
        $r.facts.certificateConnectors | Should -Be 4
        $r.facts.certificateConnectorsSilent | Should -Be 3
        @($r.affected.certificateConnectorsSilent | ForEach-Object { $_.name }) | Should -Be @('Certificate Connector on PKI02', 'Certificate Connector on PKI03', 'Certificate Connector on PKI04')
        @($r.affected.certificateConnectorsSilent)[2].detail | Should -Be 'never heard from'
    }

    It 'passes with no connector at all, and has no answer when the list was not collected' {
        $f = & $script:Folder 'no-connectors'
        & $script:Write $f '09-certificate-connectors' @()
        $r = & $script:Devices $f
        $r.facts.certificateConnectors | Should -Be 0
        $r.facts.certificateConnectorsSilent | Should -Be 0
        (& $script:Devices (& $script:Folder 'connectors-missing')).notEvaluated['DEV-024'] | Should -Match '09-certificate-connectors\.json was not collected'
    }

    It 'says the same when the report is built a week after the read' {
        # The silence is the collector's count at the time of the read, not today's date against the last contact.
        $f = & $script:Folder 'connectors-later'
        & $script:Write $f '09-certificate-connectors' @(@{ DisplayName = 'Certificate Connector'; MachineName = 'PKI01'; State = 'active'; LastConnectionDateTime = '2020-01-01T00:00:00Z'; DaysSinceLastConnection = 0 })
        (& $script:Devices $f).facts.certificateConnectorsSilent | Should -Be 0
    }
}

Describe 'Applications that hold Graph permissions and have stopped signing in (ID-024)' {
    BeforeAll {
        $script:Identity = { param([string] $Folder) InModuleScope TenantKeep.Posture -Parameters @{ E = $Folder; AsOf = $script:AsOf } { param($E, $AsOf) Get-PostureIdentityFact -Evidence $E -OrgProfile @{} -Thresholds @{} -AsOf $AsOf } }
        $script:Apps = {
            param([string] $Folder, [switch] $NoActivity, [switch] $DropServicePrincipal)
            & $script:Write $Folder '10-graph-app-permissions' @(
                @{ PrincipalDisplayName = 'Sync'; PrincipalId = 'sp-sync'; PrincipalType = 'ServicePrincipal'; Permission = 'Sites.ReadWrite.All' }
                @{ PrincipalDisplayName = 'Export'; PrincipalId = 'sp-export'; PrincipalType = 'ServicePrincipal'; Permission = 'User.Read.All' }
                @{ PrincipalDisplayName = 'Export'; PrincipalId = 'sp-export'; PrincipalType = 'ServicePrincipal'; Permission = 'Group.Read.All' }
                @{ PrincipalDisplayName = 'Archiver'; PrincipalId = 'sp-archiver'; PrincipalType = 'ServicePrincipal'; Permission = 'Mail.ReadWrite' }
                @{ PrincipalDisplayName = 'New Tool'; PrincipalId = 'sp-new'; PrincipalType = 'ServicePrincipal'; Permission = 'Mail.Send' }
            )
            $sps = @(
                @{ Id = 'sp-sync'; AppId = 'app-sync'; DisplayName = 'Sync'; CreatedDateTime = (& $script:Day 800) }
                @{ Id = 'sp-export'; AppId = 'app-export'; DisplayName = 'Export'; CreatedDateTime = (& $script:Day 800) }
                @{ Id = 'sp-archiver'; AppId = 'app-archiver'; DisplayName = 'Archiver'; CreatedDateTime = (& $script:Day 400) }
                @{ Id = 'sp-new'; AppId = 'app-new'; DisplayName = 'New Tool'; CreatedDateTime = (& $script:Day 20) }
                @{ Id = 'sp-other'; AppId = 'app-other'; DisplayName = 'No permissions'; CreatedDateTime = (& $script:Day 900) }
            )
            if ($DropServicePrincipal) { $sps = @($sps | Where-Object { $_.Id -ne 'sp-archiver' }) }
            & $script:Write $Folder '10-service-principals' $sps
            if (-not $NoActivity) { & $script:Write $Folder '10-app-signin-activity' @(@{ AppId = 'app-sync'; LastSignIn = (& $script:Day 1) }, @{ AppId = 'app-export'; LastSignIn = (& $script:Day 200) }) }
        }
    }

    It 'lists the one that stopped and the one with no sign-in on record, and not the one in use or the one made last month' {
        $f = & $script:Folder 'apps'; & $script:Apps $f
        $r = & $script:Identity $f
        $r.facts.appsWithGraphPermissions | Should -Be 4
        $r.facts.unusedAppsWithPermissions | Should -Be 2
        @($r.affected.unusedAppsWithPermissions | ForEach-Object { "$($_.name): $($_.detail)" }) | Should -Be @(
            'Archiver: 1 Graph permission(s): Mail.ReadWrite; no sign-in on record'
            'Export: 2 Graph permission(s): Group.Read.All, User.Read.All; last sign-in 2026-05-05'
        )
        $r.notEvaluated.ContainsKey('ID-024') | Should -BeFalse
    }

    It 'has no answer without the sign-in record: an application is never called unused because nothing was read' {
        $f = & $script:Folder 'apps-no-activity'; & $script:Apps $f -NoActivity
        $r = & $script:Identity $f
        $r.notEvaluated['ID-024'] | Should -Match '10-app-signin-activity\.json was not collected'
        $r.facts.Contains('unusedAppsWithPermissions') | Should -BeFalse
    }

    It 'says how many it judged when a holder is not in the service principal list, and has no answer when that leaves nothing found' {
        $f = & $script:Folder 'apps-partial'; & $script:Apps $f -DropServicePrincipal
        $r = & $script:Identity $f
        $r.facts.unusedAppsWithPermissions | Should -Be 1
        $r.notes['ID-024'] | Should -Be "Judged on 3 of the 4 applications that hold Graph permissions; the other 1 are not in this run's service principal list."
        # Only the application that is in use can be found: nothing is wrong among what was judged, which is not a pass.
        $g = & $script:Folder 'apps-unknown'; & $script:Apps $g
        & $script:Write $g '10-service-principals' @(@{ Id = 'sp-sync'; AppId = 'app-sync'; DisplayName = 'Sync'; CreatedDateTime = (& $script:Day 800) })
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache -Confirm:$false }
        (& $script:Identity $g).notEvaluated['ID-024'] | Should -Match "^3 of the 4 applications that hold Graph permissions are not in this run's service principal list"
    }
}

Describe 'Azure Policy compliance (AZ-029) and Azure Lighthouse (AZ-030)' {
    BeforeAll {
        $script:Azure = { param([string] $Folder) InModuleScope TenantKeep.Posture -Parameters @{ E = $Folder } { param($E) Get-PostureAzureFact -Evidence $E -OrgProfile @{} -Thresholds @{} } }
        # The file the provider needs before it reads anything else.
        $script:AzureBase = { param([string] $Folder) & $script:Write $Folder 'az-01-subscriptions' @(@{ SubscriptionId = 'sub-1'; Name = 'Prod'; State = 'Enabled'; AtTenantRoot = $false; DetailRead = $true; DetailError = $null }) }
    }

    It 'has no answer when Azure Policy evaluated nothing, or the read is not there' {
        $f = & $script:Folder 'policy-none'; & $script:AzureBase $f
        & $script:Write $f 'az-03-policy-compliance' @()
        (& $script:Azure $f).notEvaluated['AZ-029'] | Should -Match 'has evaluated no resources'
        $g = & $script:Folder 'policy-missing'; & $script:AzureBase $g
        (& $script:Azure $g).notEvaluated['AZ-029'] | Should -Match 'az-03-policy-compliance\.json was not collected'
        (& $script:Azure $g).notEvaluated['AZ-030'] | Should -Match 'az-17-lighthouse-delegations\.json was not collected'
    }

    It 'adds the subscriptions up, and passes a tenant with no delegation at all' {
        $f = & $script:Folder 'policy-ok'; & $script:AzureBase $f
        & $script:Write $f 'az-03-policy-compliance' @(@{ SubscriptionId = 'sub-1'; Resources = 90; NonCompliant = 5 }, @{ SubscriptionId = 'sub-2'; Resources = 10; NonCompliant = 0 })
        & $script:Write $f 'az-17-lighthouse-delegations' @()
        $r = & $script:Azure $f
        $r.facts.policyCompliancePct | Should -Be 95
        $r.facts.policyNonCompliantAssignments | Should -Be 0 -Because 'the list of assignments is optional: without it the percentage still stands'
        $r.facts.lighthouseDelegations | Should -Be 0
        $r.facts.lighthouseWriteDelegations | Should -Be 0
    }

    It 'lists a delegation with any role that is not read-only, eligible roles included' {
        $f = & $script:Folder 'lighthouse'; & $script:AzureBase $f
        & $script:Write $f 'az-17-lighthouse-delegations' @(
            @{ SubscriptionId = 'sub-1'; ResourceGroup = ''; DefinitionRead = $true; Offer = 'Read only'; ManagedByTenantName = 'Northwind'; Roles = 'acdd72a7-3385-48ef-bd42-f606fba81ae7;91c1777a-f3dc-4fae-b103-61d183457e46'; EligibleRoles = '' }
            @{ SubscriptionId = 'sub-1'; ResourceGroup = 'rg-app'; DefinitionRead = $true; Offer = 'Just in time'; ManagedByTenantId = '99999999-9999-9999-9999-999999999999'; ManagedByTenantName = ''; Roles = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'; EligibleRoles = 'b24988ac-6180-42a0-ab88-20f7382dd24c' }
            @{ SubscriptionId = 'sub-2'; ResourceGroup = ''; DefinitionRead = $true; Offer = 'Custom'; ManagedByTenantName = 'Fabrikam'; Roles = '11111111-2222-3333-4444-555555555555'; EligibleRoles = '' }
        )
        $r = & $script:Azure $f
        $r.facts.lighthouseDelegations | Should -Be 3
        $r.facts.lighthouseWriteDelegations | Should -Be 2
        @($r.affected.lighthouseWriteDelegations | ForEach-Object { "$($_.name) | $($_.detail)" }) | Should -Be @(
            'Just in time, managed by tenant 99999999-9999-9999-9999-999999999999 | resource group rg-app in sub-1: Contributor'
            'Custom, managed by Fabrikam | subscription sub-2: role 11111111-2222-3333-4444-555555555555'
        ) -Because 'a role this module does not know is not assumed to be read-only'
    }
}

Describe 'Direct Send (EM-028)' {
    BeforeAll {
        $script:Email = { param([string] $Folder) InModuleScope TenantKeep.Posture -Parameters @{ E = $Folder } { param($E) Get-PostureEmailFact -Evidence $E -OrgProfile @{} -Thresholds @{} } }
    }

    It 'reads <Value> as <Fact>' -ForEach @(
        @{ Value = $true; Fact = $true }, @{ Value = $false; Fact = $false }, @{ Value = 'True'; Fact = $true }
    ) {
        $f = & $script:Folder "direct-send-$Value-$($Value.GetType().Name)"
        & $script:Write $f 'exo-01-orgconfig' @{ Name = 'contoso.example'; RejectDirectSend = $Value; AuditDisabled = $false }
        $r = & $script:Email $f
        $r.facts.directSendRejected | Should -Be $Fact
        $r.notEvaluated.ContainsKey('EM-028') | Should -BeFalse
    }

    It 'has no answer when the organisation configuration does not carry the setting' {
        $f = & $script:Folder 'direct-send-absent'
        & $script:Write $f 'exo-01-orgconfig' @{ Name = 'contoso.example'; AuditDisabled = $false }
        $r = & $script:Email $f
        $r.notEvaluated['EM-028'] | Should -Match 'does not say whether Direct Send is rejected'
        $r.facts.Contains('directSendRejected') | Should -BeFalse -Because 'a setting that was not read is never "not rejected"'
        $g = & $script:Folder 'direct-send-null'
        & $script:Write $g 'exo-01-orgconfig' @{ Name = 'contoso.example'; RejectDirectSend = $null }
        (& $script:Email $g).notEvaluated.ContainsKey('EM-028') | Should -BeTrue
    }
}

Describe 'OneDrive retention, sync and idle sign-out (CL-017 to CL-019)' {
    BeforeAll {
        $script:Collab = { param([string] $Folder) InModuleScope TenantKeep.Posture -Parameters @{ E = $Folder } { param($E) Get-PostureCollaborationFact -Evidence $E -OrgProfile @{} -Thresholds @{} } }
    }

    It 'reads the three settings from Graph' {
        $f = & $script:Folder 'onedrive'
        & $script:Write $f 'spo-tenant-settings-graph' @{ sharingCapability = 'externalUserSharingOnly'; deletedUserPersonalSiteRetentionPeriodInDays = 365; isUnmanagedSyncAppForTenantRestricted = $true; allowedDomainGuidsForSyncApp = @('11111111-1111-1111-1111-111111111111'); idleSessionSignOut = @{ isEnabled = $true; signOutAfterInSeconds = 3600; warnAfterInSeconds = 3300 } }
        $r = & $script:Collab $f
        $r.facts.oneDriveRetentionDays | Should -Be 365
        $r.facts.oneDriveSyncRestricted | Should -BeTrue
        $r.facts.oneDriveSyncAllowedDomains | Should -Be 1
        $r.facts.idleSignOutEnabled | Should -BeTrue
        $r.facts.idleSignOutMinutes | Should -Be 60
        $r.facts.idleSignOutWithinLimit | Should -BeTrue
    }

    It 'does not call sync limited when the switch is on and no domain is named, or idle sign-out fine when it is off or longer than the limit' {
        $f = & $script:Folder 'onedrive-weak'
        & $script:Write $f 'spo-tenant-settings-graph' @{ sharingCapability = 'externalUserSharingOnly'; deletedUserPersonalSiteRetentionPeriodInDays = 7; isUnmanagedSyncAppForTenantRestricted = $true; allowedDomainGuidsForSyncApp = @(); idleSessionSignOut = @{ isEnabled = $true; signOutAfterInSeconds = 86400 } }
        $r = & $script:Collab $f
        $r.facts.oneDriveRetentionDays | Should -Be 7
        $r.facts.oneDriveSyncRestricted | Should -BeFalse
        $r.facts.idleSignOutMinutes | Should -Be 1440
        $r.facts.idleSignOutWithinLimit | Should -BeFalse
        $g = & $script:Folder 'onedrive-off'
        & $script:Write $g 'spo-tenant-settings-graph' @{ sharingCapability = 'externalUserSharingOnly'; isUnmanagedSyncAppForTenantRestricted = $false; idleSessionSignOut = @{ isEnabled = $false } }
        $off = & $script:Collab $g
        $off.facts.idleSignOutWithinLimit | Should -BeFalse
        $off.facts.oneDriveSyncRestricted | Should -BeFalse
    }

    It 'has no answer for a setting Graph did not return, and takes the retention from the admin read when that is what there is' {
        $f = & $script:Folder 'onedrive-thin'
        & $script:Write $f 'spo-tenant-settings-graph' @{ sharingCapability = 'externalUserSharingOnly' }
        $r = & $script:Collab $f
        foreach ($id in 'CL-017', 'CL-018', 'CL-019') { $r.notEvaluated.ContainsKey($id) | Should -BeTrue -Because "$id has nothing to judge" }
        foreach ($fact in 'oneDriveRetentionDays', 'oneDriveSyncRestricted', 'idleSignOutWithinLimit') { $r.facts.Contains($fact) | Should -BeFalse }
        $g = & $script:Folder 'onedrive-admin'
        & $script:Write $g 'spo-tenant-settings' @{ SharingCapability = 'ExternalUserSharingOnly'; OrphanedPersonalSitesRetentionPeriod = 90 }
        $admin = & $script:Collab $g
        $admin.facts.oneDriveRetentionDays | Should -Be 90
        $admin.notEvaluated['CL-018'] | Should -Match 'spo-tenant-settings-graph\.json was not collected'
    }
}

# ---- Catalog 2026.11.2: the reads that each need a new read permission on the consent ----

Describe 'Message Center (OP-011), service health and federation certificates on the calendar' {
    BeforeAll {
        $script:OpsNow = { param([string] $Folder) InModuleScope TenantKeep.Posture -Parameters @{ E = $Folder; AsOf = $script:AsOf } { param($E, $AsOf) Get-PostureOperationsFact -Evidence $E -OrgProfile @{} -Thresholds @{} -AsOf $AsOf } }
    }

    It 'lists the posts whose act-by date is inside the window, soonest first, and not one that has passed or is far off' {
        $f = & $script:Folder 'message-center'
        & $script:Write $f '12-message-center' @(
            @{ Id = 'MC3'; Title = 'Far off'; ActionRequiredByDateTime = (& $script:Day -90); Services = 'Microsoft Teams' }
            @{ Id = 'MC2'; Title = 'Next month'; ActionRequiredByDateTime = (& $script:Day -25); Services = 'Microsoft Entra;Microsoft Teams' }
            @{ Id = 'MC1'; Title = 'Next week'; ActionRequiredByDateTime = (& $script:Day -6); Services = '' }
            @{ Id = 'MC0'; Title = 'Last week'; ActionRequiredByDateTime = (& $script:Day 7); Services = 'Exchange Online' }
        )
        $r = & $script:OpsNow $f
        $r.facts.messageCenterActionsDue | Should -Be 2
        @($r.affected.messageCenterActionsDue | ForEach-Object { "$($_.name) | $($_.detail)" }) | Should -Be @('MC1: Next week | act by 2026-11-27, in 6 day(s)', 'MC2: Next month | act by 2026-12-16, in 25 day(s); Microsoft Entra, Microsoft Teams')
    }

    It 'has no answer without the read, and passes a tenant with no dated post' {
        (& $script:OpsNow (& $script:Folder 'message-center-none')).notEvaluated['OP-011'] | Should -Match '12-message-center\.json was not collected'
        $f = & $script:Folder 'message-center-empty'; & $script:Write $f '12-message-center' @()
        $r = & $script:OpsNow $f
        $r.facts.messageCenterActionsDue | Should -Be 0
        $r.notEvaluated.ContainsKey('OP-011') | Should -BeFalse
    }

    It 'counts what Microsoft has open as facts, and judges nothing by it' {
        $f = & $script:Folder 'service-health'
        & $script:Write $f '12-service-health' @(@{ Id = 'EX1'; Classification = 'advisory' }, @{ Id = 'TM2'; Classification = 'incident' }, @{ Id = 'SP3'; Classification = 'incident' })
        $r = & $script:OpsNow $f
        $r.facts.serviceIncidentsOpen | Should -Be 2
        $r.facts.serviceAdvisoriesOpen | Should -Be 1
        (& $script:OpsNow (& $script:Folder 'service-health-none')).facts.Contains('serviceIncidentsOpen') | Should -BeFalse -Because 'not read is not zero'
    }

    It 'puts each federated domain''s signing certificate on the expiry calendar' {
        $f = & $script:Folder 'federation'
        & $script:Write $f '01-federation-settings' @(@{ Domain = 'contoso.example'; SigningCertificateExpiry = (& $script:Day -12); SigningCertificateRead = $true }, @{ Domain = 'fabrikam.example'; SigningCertificateExpiry = (& $script:Day -200); SigningCertificateRead = $true })
        $r = & $script:OpsNow $f
        @($r.facts.expiryCalendar | ForEach-Object { "$($_.kind): $($_.name) in $($_.days)" }) | Should -Be @('Federation signing certificate: contoso.example in 12', 'Federation signing certificate: fabrikam.example in 200')
        $r.facts.expiringWithinWarning | Should -Be 1
        $r.partial.ContainsKey('OP-006') | Should -BeFalse
    }

    It 'has no answer for a calendar with nothing near its date when a signing certificate could not be read' {
        $f = & $script:Folder 'federation-unread'
        & $script:Write $f '01-federation-settings' @(@{ Domain = 'contoso.example'; SigningCertificateExpiry = (& $script:Day -200); SigningCertificateRead = $true }, @{ Domain = 'broken.example'; SigningCertificateExpiry = $null; SigningCertificateRead = $false })
        $r = & $script:OpsNow $f
        $r.facts.expiringWithinWarning | Should -Be 0
        $r.partial['OP-006'].noAnswer | Should -Be 'Nothing that was read is near its date, but the signing certificate of 1 federated domain(s) could not be read.'
        # Through the engine, with the two lists the calendar always needs: a pass on part of the data is no answer.
        & $script:Write $f '10-app-registrations' @(); & $script:Write $f '10-service-principals' @()
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache -Confirm:$false }
        $run = Invoke-PostureChecks -Evidence $f -Domain operations -PassThru
        $op6 = @($run.results | Where-Object { $_.id -eq 'OP-006' })[0]
        $op6.status | Should -Be 'notEvaluated'
        $op6.reason | Should -Match 'could not be read'
    }
}

Describe 'Defender for Identity health (HY-034)' {
    BeforeAll {
        $script:Hybrid = { param([string] $Folder) InModuleScope TenantKeep.Posture -Parameters @{ E = $Folder } { param($E) Get-PostureHybridFact -Evidence $E -OrgProfile @{} -Thresholds @{} } }
        $script:HybridBase = { param([string] $Folder) & $script:Write $Folder '01-onprem-sync-features' @(@{ id = 't'; features = @{ passwordSyncEnabled = $true } }) }
    }

    It 'lists every open issue, the most severe first, with the sensors it names' {
        $f = & $script:Folder 'mdi'; & $script:HybridBase $f
        & $script:Write $f '13-mdi-health-issues' @(
            @{ DisplayName = 'Low disk space on a sensor'; Severity = 'low'; Status = 'open'; CreatedDateTime = (& $script:Day 3); Sensors = 'DC03.contoso.example' }
            @{ DisplayName = 'Sensor stopped communicating'; Severity = 'high'; Status = 'open'; CreatedDateTime = (& $script:Day 40); Sensors = 'DC01.contoso.example;DC02.contoso.example;DC04.contoso.example;DC05.contoso.example' }
        )
        $r = & $script:Hybrid $f
        $r.facts.mdiOpenHealthIssues | Should -Be 2
        @($r.affected.mdiOpenHealthIssues | ForEach-Object { "$($_.name) | $($_.detail)" }) | Should -Be @(
            'Sensor stopped communicating | high severity, open since 2026-10-12; DC01.contoso.example, DC02.contoso.example, DC04.contoso.example and 1 more'
            'Low disk space on a sensor | low severity, open since 2026-11-18; DC03.contoso.example'
        )
    }

    It 'passes with none open, and has no answer when the read is not there' {
        $f = & $script:Folder 'mdi-clean'; & $script:HybridBase $f
        & $script:Write $f '13-mdi-health-issues' @()
        (& $script:Hybrid $f).facts.mdiOpenHealthIssues | Should -Be 0
        $g = & $script:Folder 'mdi-missing'; & $script:HybridBase $g
        $r = & $script:Hybrid $g
        $r.notEvaluated['HY-034'] | Should -Match '13-mdi-health-issues\.json was not collected'
        $r.facts.Contains('mdiOpenHealthIssues') | Should -BeFalse -Because 'no read is not no issues'
    }
}

Describe 'Intune multi-admin approval (DEV-025) and role scope (DEV-026)' {
    BeforeAll {
        $script:DevicesNow = { param([string] $Folder) InModuleScope TenantKeep.Posture -Parameters @{ E = $Folder } { param($E) Get-PostureDevicesFact -Evidence $E -OrgProfile @{} -Thresholds @{} } }
    }

    It 'counts the approval policies and says what they cover' {
        $f = & $script:Folder 'approval'
        & $script:Write $f '09-intune-approval-policies' @(@{ DisplayName = 'Wipe'; PolicyType = 'deviceWipe' }, @{ DisplayName = 'Scripts'; PolicyType = 'script' }, @{ DisplayName = 'More scripts'; PolicyType = 'script' })
        $r = & $script:DevicesNow $f
        $r.facts.multiAdminApprovalPolicies | Should -Be 3
        $r.facts.multiAdminApprovalCovers | Should -Be 'deviceWipe, script'
        $g = & $script:Folder 'approval-none'; & $script:Write $g '09-intune-approval-policies' @()
        (& $script:DevicesNow $g).facts.multiAdminApprovalPolicies | Should -Be 0
        (& $script:DevicesNow (& $script:Folder 'approval-missing')).notEvaluated['DEV-025'] | Should -Match '09-intune-approval-policies\.json was not collected'
    }

    It 'lists a writing role assigned over every device and user, and not a read-only or a scoped one' {
        $f = & $script:Folder 'intune-roles'
        & $script:Write $f '09-intune-role-assignments' @(
            @{ DisplayName = 'Help desk'; RoleName = 'Help Desk Operator'; ScopeType = 'allDevicesAndLicensedUsers'; MemberGroups = 2 }
            @{ DisplayName = 'Auditors'; RoleName = 'Read Only Operator'; ScopeType = 'allDevicesAndLicensedUsers'; MemberGroups = 1 }
            @{ DisplayName = 'Mac team'; RoleName = 'Policy and Profile manager'; ScopeType = 'resourceScope'; MemberGroups = 1 }
            @{ DisplayName = 'Kiosk owners'; RoleName = 'Kiosk admin'; ScopeType = 'allDevices'; MemberGroups = 1 }
        )
        & $script:Write $f '09-intune-scope-tags' @(@{ DisplayName = 'Default'; IsBuiltIn = $true }, @{ DisplayName = 'Mac'; IsBuiltIn = $false })
        $r = & $script:DevicesNow $f
        $r.facts.intuneRoleAssignments | Should -Be 4
        $r.facts.intuneRolesOrgWide | Should -Be 2
        $r.facts.intuneScopeTags | Should -Be 1
        @($r.affected.intuneRolesOrgWide | ForEach-Object { "$($_.name) | $($_.detail)" }) | Should -Be @('Help desk (Help Desk Operator) | over every device and every user; 2 member group(s)', 'Kiosk owners (Kiosk admin) | over every device; 1 member group(s)')
    }

    It 'passes a tenant that uses no Intune role assignments, and has no answer when they were not read' {
        $f = & $script:Folder 'intune-roles-none'; & $script:Write $f '09-intune-role-assignments' @()
        $r = & $script:DevicesNow $f
        $r.facts.intuneRolesOrgWide | Should -Be 0
        $r.facts.intuneScopeTags | Should -BeNullOrEmpty -Because 'the scope tags were not read, which is not zero tags'
        (& $script:DevicesNow (& $script:Folder 'intune-roles-missing')).notEvaluated['DEV-026'] | Should -Match '09-intune-role-assignments\.json was not collected'
    }
}

Describe 'Microsoft service health in Run Health' {
    It 'lists what Microsoft had open, incidents first, and says nothing when the read was not made' {
        . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
        $ev = Initialize-CollectionFixture -Root (Join-Path $script:Root 'health-report')
        & $script:Write $ev '12-service-health' @(@{ Id = 'EX1'; Title = 'Mail delays'; Service = 'Exchange Online'; Classification = 'advisory'; Status = 'serviceDegradation' }, @{ Id = 'TM2'; Title = 'Meetings cannot start'; Service = 'Microsoft Teams'; Classification = 'incident'; Status = 'investigating' })
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache -Confirm:$false }
        $r = New-PostureReport -Evidence $ev -PassThru 6>$null
        @($r.Report.runHealth.serviceHealth | ForEach-Object { "$($_.kind) $($_.id)" }) | Should -Be @('incident TM2', 'advisory EX1')
        $html = Get-Content -Raw (@($r.Files) -like '*.html')[0]
        $html | Should -Match 'Microsoft had 1 incident\(s\) and 1 advisory\(ies\) open for this tenant'
        $html | Should -Match '<code>TM2</code> Meetings cannot start'
        Get-Content -Raw (@($r.Files) -like '*.md')[0] | Should -Match '### Microsoft service health when this run was made'
        $bare = Initialize-CollectionFixture -Root (Join-Path $script:Root 'health-report-none')
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache -Confirm:$false }
        $none = New-PostureReport -Evidence $bare -PassThru 6>$null
        $none.Report.runHealth.serviceHealth | Should -BeNullOrEmpty
        Get-Content -Raw (@($none.Files) -like '*.html')[0] | Should -Not -Match 'Microsoft Service Health When This Run Was Made'
    }
}

