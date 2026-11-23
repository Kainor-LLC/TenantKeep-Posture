# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# The checks added in catalog 2026.11.3, most from settings the run already collects. Each is judged from a folder
# holding only the files it reads: good, bad, and the setting not there (no answer, never a pass).
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-hardening-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $script:Judge = {
        param([string] $Domain, [System.Collections.IDictionary] $Files, [string] $Baseline = 'standard')
        $dir = Join-Path $script:Root ([guid]::NewGuid().ToString('n'))
        New-Item -ItemType Directory -Path $dir | Out-Null
        foreach ($name in $Files.Keys) { ConvertTo-Json -InputObject $Files[$name] -Depth 8 | Set-Content (Join-Path $dir "$name.json") }
        '{ "version": 1, "licenses": ["E5", "MDO1", "MDO2", "P1", "P2"] }' | Set-Content (Join-Path $dir 'profile.json')
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
        $run = Invoke-PostureChecks -Evidence $dir -Domain $Domain -Baseline $Baseline -ProfilePath (Join-Path $dir 'profile.json') -PassThru
        $by = @{}; foreach ($r in $run.results) { $by[$r.id] = $r }
        $by
    }
    # Rows as a collection saves them: every property the provider reads is there.
    $script:ContentFilter = { param($Allowed) @(@{ Name = 'Default'; ZapEnabled = $true; SpamZapEnabled = $true; PhishZapEnabled = $true; HighConfidencePhishQuarantineTag = 'AdminOnlyAccessPolicy'; AllowedSenderDomains = @($Allowed) }) }
    $script:AntiPhish = { param([bool] $Tips, [bool] $FirstContact = $Tips) @(@{ Name = 'Office365 AntiPhish Default'; Enabled = $true; EnableSpoofIntelligence = $true; HonorDmarcPolicy = $true; EnableTargetedUserProtection = $true; TargetedUsersToProtect = @('x'); EnableOrganizationDomainsProtection = $true; EnableMailboxIntelligence = $true; EnableFirstContactSafetyTips = $FirstContact; EnableSimilarUsersSafetyTips = $Tips; EnableSimilarDomainsSafetyTips = $Tips; EnableUnusualCharactersSafetyTips = $Tips }) }
    $script:SafeLinks = { param([string] $Name, [bool] $Track, $ClickThrough = $false, [bool] $BuiltIn = $false) @{ Name = $Name; IsBuiltInProtection = $BuiltIn; EnableSafeLinksForEmail = $true; EnableSafeLinksForTeams = $true; EnableSafeLinksForOffice = $true; ScanUrls = $true; DeliverMessageAfterScan = $true; TrackClicks = $Track; AllowClickThrough = $ClickThrough } }
    $script:Spo = { param([hashtable] $Set) $row = @{ SharingCapability = 'ExternalUserAndGuestSharing'; FileAnonymousLinkType = 'View'; FolderAnonymousLinkType = 'View'; LegacyAuthProtocolsEnabled = $false; PreventExternalUsersFromResharing = $true; EmailAttestationRequired = $true; EmailAttestationReAuthDays = 30 }; foreach ($k in $Set.Keys) { if ($null -eq $Set[$k] -and $k -like 'Remove:*') { $row.Remove($k.Substring(7)) } else { $row[$k] = $Set[$k] } }; $row }
    $script:Teams = { param([hashtable] $Client, [hashtable] $Meeting) @{ 'teams-federation' = @{ AllowFederatedUsers = $false; AllowedDomains = ''; AllowTeamsConsumer = $false; AllowPublicUsers = $false }; 'teams-client-config' = (@{ AllowGuestUser = $false } + $Client); 'teams-meeting-policy-global' = (@{ AllowAnonymousUsersToJoinMeeting = $false; AllowAnonymousUsersToStartMeeting = $false; AutoAdmittedUsers = 'EveryoneInCompany' } + $Meeting) } }
}

AfterAll {
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
}

Describe 'Email settings (catalog 2026.11.3)' {
    It 'EM-029 fails on a sender domain an anti-spam policy allows, and names it' {
        (& $script:Judge 'email' @{ 'exo-04-eop-content-filter' = (& $script:ContentFilter @()) })['EM-029'].status | Should -Be 'pass'
        $r = (& $script:Judge 'email' @{ 'exo-04-eop-content-filter' = (& $script:ContentFilter @('partner.example', @{ Domain = 'other.example' })) })['EM-029']
        $r.status | Should -Be 'fail'
        @($r.affected.name) | Should -Be @('partner.example', 'other.example') -Because 'a domain is saved as text or as an object, depending on the module'
        (& $script:Judge 'email' @{ 'exo-06-sharing-policies' = @() })['EM-029'].status | Should -Be 'notEvaluated' -Because 'the anti-spam policies were not collected'
    }

    It 'EM-030 wants every Safe Links policy to check, record and refuse click-through, and looks past the built-in one' {
        $good = & $script:SafeLinks 'Standard' $true
        $builtIn = & $script:SafeLinks 'Built-In Protection Policy' $true $true $true
        (& $script:Judge 'email' @{ 'exo-05-mdo-safelinks' = @($good, $builtIn) })['EM-030'].status | Should -Be 'pass' -Because 'the built-in policy covers only people no other policy does'
        $r = (& $script:Judge 'email' @{ 'exo-05-mdo-safelinks' = @($good, (& $script:SafeLinks 'Sales' $false $true)) })['EM-030']
        $r.status | Should -Be 'fail'
        @($r.affected.name) | Should -Be @('Sales')
        $r.affected[0].detail | Should -Match 'records clicks False, click-through allowed True'
        (& $script:Judge 'email' @{ 'exo-05-mdo-safelinks' = @($builtIn) })['EM-030'].status | Should -Be 'fail' -Because 'when the built-in policy is the only one, its click-through is what people get'
    }

    It 'EM-031 fails while the connection filter safe list is on' {
        (& $script:Judge 'email' @{ 'exo-04-eop-connection-filter' = @(@{ Name = 'Default'; IPAllowList = @(); EnableSafeList = $false }) })['EM-031'].status | Should -Be 'pass'
        (& $script:Judge 'email' @{ 'exo-04-eop-connection-filter' = @(@{ Name = 'Default'; IPAllowList = @(); EnableSafeList = $true }) })['EM-031'].status | Should -Be 'fail'
    }

    It 'EM-032 fails when an anti-phishing policy has a safety tip off, and says which' {
        (& $script:Judge 'email' @{ 'exo-04-antiphish' = (& $script:AntiPhish $true) })['EM-032'].status | Should -Be 'pass'
        $r = (& $script:Judge 'email' @{ 'exo-04-antiphish' = (& $script:AntiPhish $true $false) })['EM-032']
        $r.status | Should -Be 'fail'
        $r.affected[0].detail | Should -Be 'off: first contact'
    }

    It 'EM-033 fails only when every outside domain gets contacts or calendar detail' {
        $policy = { param($Domains, $Enabled = $true) @(@{ Name = 'Default Sharing Policy'; Enabled = $Enabled; Domains = @($Domains) }) }
        (& $script:Judge 'email' @{ 'exo-06-sharing-policies' = (& $policy @('*:CalendarSharingFreeBusySimple', 'partner.example:CalendarSharingFreeBusyDetail, ContactsSharing')) })['EM-033'].status | Should -Be 'pass' -Because 'free and busy time for all, detail for a named partner'
        $r = (& $script:Judge 'email' @{ 'exo-06-sharing-policies' = (& $policy @('*:CalendarSharingFreeBusyDetail, ContactsSharing')) })['EM-033']
        $r.status | Should -Be 'fail'
        $r.affected[0].detail | Should -Be 'every outside domain gets CalendarSharingFreeBusyDetail, ContactsSharing'
        (& $script:Judge 'email' @{ 'exo-06-sharing-policies' = (& $policy @('*:ContactsSharing') $false) })['EM-033'].status | Should -Be 'pass' -Because 'a disabled policy shares nothing'
    }
}

Describe 'Teams and SharePoint settings (catalog 2026.11.3)' {
    It 'CL-020, CL-023 and CL-024 judge one Teams setting each' {
        $good = & $script:Judge 'collaboration' (& $script:Teams @{ AllowEmailIntoChannel = $false } @{ AllowExternalParticipantGiveRequestControl = $false; AllowPSTNUsersToBypassLobby = $false })
        foreach ($id in 'CL-020', 'CL-023', 'CL-024') { $good[$id].status | Should -Be 'pass' -Because $id }
        $bad = & $script:Judge 'collaboration' (& $script:Teams @{ AllowEmailIntoChannel = $true } @{ AllowExternalParticipantGiveRequestControl = $true; AllowPSTNUsersToBypassLobby = $true })
        foreach ($id in 'CL-020', 'CL-023', 'CL-024') { $bad[$id].status | Should -Be 'fail' -Because $id }
        $unknown = & $script:Judge 'collaboration' (& $script:Teams @{} @{})
        foreach ($id in 'CL-020', 'CL-023', 'CL-024') { $unknown[$id].status | Should -Be 'notEvaluated' -Because "${id}: a setting that was not read is not a pass" }
        $unknown['CL-023'].reason | Should -Match 'did not say whether outside participants may take control'
    }

    It 'CL-021 and CL-022 apply only where the sharing level makes them matter' {
        $ok = & $script:Judge 'collaboration' @{ 'spo-tenant-settings' = (& $script:Spo @{}) }
        foreach ($id in 'CL-021', 'CL-022', 'CL-025', 'CL-026') { $ok[$id].status | Should -Be 'pass' -Because $id }
        $bad = & $script:Judge 'collaboration' @{ 'spo-tenant-settings' = (& $script:Spo @{ FolderAnonymousLinkType = 'Edit'; EmailAttestationReAuthDays = 90; LegacyAuthProtocolsEnabled = $true; PreventExternalUsersFromResharing = $false }) }
        foreach ($id in 'CL-021', 'CL-022', 'CL-025', 'CL-026') { $bad[$id].status | Should -Be 'fail' -Because $id }
        (& $script:Judge 'collaboration' @{ 'spo-tenant-settings' = (& $script:Spo @{ EmailAttestationRequired = $false }) })['CL-022'].status | Should -Be 'fail' -Because 'the reauthentication is not required at all'
        $closed = & $script:Judge 'collaboration' @{ 'spo-tenant-settings' = (& $script:Spo @{ SharingCapability = 'ExistingExternalUserSharingOnly'; FolderAnonymousLinkType = 'Edit'; EmailAttestationRequired = $false }) }
        $closed['CL-021'].status | Should -Be 'pass' -Because 'no Anyone link can be made, so what one may do does not matter'
        $closed['CL-022'].status | Should -Be 'pass' -Because 'nobody new is invited, so nobody signs in with a code'
    }

    It 'CL-022 has no answer for a collection made before the two settings were saved' {
        $old = & $script:Judge 'collaboration' @{ 'spo-tenant-settings' = (& $script:Spo @{ 'Remove:EmailAttestationRequired' = $null; 'Remove:EmailAttestationReAuthDays' = $null }) }
        $old['CL-022'].status | Should -Be 'notEvaluated'
        $old['CL-022'].reason | Should -Match 'collected before TenantKeep read the verification code settings'
        $old['CL-021'].status | Should -Be 'pass' -Because 'the link types were saved all along'
    }

    It 'CL-025 and CL-026 answer from Graph alone, and have no answer when Graph left the value out' {
        $graph = & $script:Judge 'collaboration' @{ 'spo-tenant-settings-graph' = @{ sharingCapability = 'externalUserSharingOnly'; isLegacyAuthProtocolsEnabled = $false; isResharingByExternalUsersEnabled = $true } }
        $graph['CL-025'].status | Should -Be 'pass'
        $graph['CL-026'].status | Should -Be 'fail' -Because 'guests may share on'
        $graph['CL-022'].status | Should -Be 'notEvaluated' -Because 'Graph does not carry the verification code settings'
        $thin = & $script:Judge 'collaboration' @{ 'spo-tenant-settings-graph' = @{ sharingCapability = 'disabled' } }
        $thin['CL-025'].status | Should -Be 'notEvaluated'
        $thin['CL-026'].status | Should -Be 'notEvaluated'
    }
}

Describe 'ID-025: only administrators can register applications' {
    It 'reads the authorization policy, and has no answer when the policy does not say' {
        $policy = { param($Value) $p = @{ allowInvitesFrom = 'adminsAndGuestInviters'; guestUserRoleId = '2af84b1e-32c8-42b7-82bc-daa82404023b'; defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @() } }; if ($null -ne $Value) { $p.defaultUserRolePermissions['allowedToCreateApps'] = $Value }; $p }
        (& $script:Judge 'identity' @{ '02-authorization-policy' = (& $policy $false) })['ID-025'].status | Should -Be 'pass'
        (& $script:Judge 'identity' @{ '02-authorization-policy' = (& $policy $true) })['ID-025'].status | Should -Be 'fail'
        $r = (& $script:Judge 'identity' @{ '02-authorization-policy' = (& $policy $null) })['ID-025']
        $r.status | Should -Be 'notEvaluated'
        $r.reason | Should -Match 'did not say whether users may register applications'
    }
}

Describe 'DLP rules and alert policies (catalog 2026.11.3)' {
    BeforeAll {
        $script:Dlp = { param($Rules, [string] $Mode = 'Enable') @{ 'pv-02-dlp-policies' = @(@{ Name = 'Cards'; Enabled = $true; Mode = $Mode; Workload = 'Exchange'; ExchangeLocation = @('All'); SharePointLocation = @(); OneDriveLocation = @(); TeamsLocation = @(); EndpointDlpLocation = @() }); 'pv-02-dlp-rules' = @($Rules) } }
        $script:Rule = { param([bool] $Block, $Notify = @('LastModifier'), [string] $Name = 'Card numbers') @{ Name = $Name; ParentPolicyName = 'Cards'; Disabled = $false; BlockAccess = $Block; BlockAccessScope = $(if ($Block) { 'All' } else { $null }); NotifyUser = @($Notify) } }
        $script:AlertNames = 'Suspicious email sending patterns detected', 'Suspicious connector activity', 'Suspicious email forwarding activity', 'Messages have been delayed', 'Tenant restricted from sending unprovisioned email', 'Tenant restricted from sending email'
        $script:Alerts = { param([string[]] $Off = @(), [string[]] $Absent = @(), [string[]] $Quiet = @()) @{ 'pv-07-alert-policies' = @($script:AlertNames | Where-Object { $_ -notin $Absent } | ForEach-Object { @{ Name = $_; Disabled = ($_ -in $Off); NotifyUser = @($(if ($_ -notin $Quiet) { 'TenantAdmins' })); NotificationEnabled = $true } }) } }
    }

    It 'PV-010 wants an enforced policy with a rule that blocks, and names the policies that only report' {
        (& $script:Judge 'purview' (& $script:Dlp (& $script:Rule $true)))['PV-010'].status | Should -Be 'pass'
        $r = (& $script:Judge 'purview' (& $script:Dlp (& $script:Rule $false)))['PV-010']
        $r.status | Should -Be 'fail'
        @($r.affected.name) | Should -Be @('Cards')
        (& $script:Judge 'purview' (& $script:Dlp (& $script:Rule $true) 'TestWithNotifications'))['PV-010'].status | Should -Be 'fail' -Because 'a policy in simulation blocks nothing'
    }

    It 'PV-010 and PV-011 have no answer without the rules, or with rules saved before their actions were' {
        $policiesOnly = & $script:Dlp @(); $policiesOnly.Remove('pv-02-dlp-rules')
        $none = & $script:Judge 'purview' $policiesOnly
        foreach ($id in 'PV-010', 'PV-011') { $none[$id].status | Should -Be 'notEvaluated' -Because $id }
        $old = & $script:Judge 'purview' (& $script:Dlp @(@{ Name = 'Card numbers'; ParentPolicyName = 'Cards'; Disabled = $false }))
        foreach ($id in 'PV-010', 'PV-011') { $old[$id].reason | Should -Match 'collected before TenantKeep read what a rule does' -Because $id }
    }

    It 'PV-011 fails a policy that blocks without a word, and waits for PV-010 when nothing blocks' {
        (& $script:Judge 'purview' (& $script:Dlp (& $script:Rule $true)))['PV-011'].status | Should -Be 'pass'
        $r = (& $script:Judge 'purview' (& $script:Dlp @((& $script:Rule $true @() 'Silent block'), (& $script:Rule $false))))['PV-011']
        $r.status | Should -Be 'fail'
        $r.affected[0].detail | Should -Be 'blocks without telling the person: Silent block'
        $waits = (& $script:Judge 'purview' (& $script:Dlp (& $script:Rule $false)))['PV-011']
        $waits.status | Should -Be 'notEvaluated'
        $waits.reason | Should -Match 'no block to explain'
    }

    It 'PV-012 fails on an alert policy that is off or not there, and has no answer for an empty list' {
        (& $script:Judge 'purview' (& $script:Alerts))['PV-012'].status | Should -Be 'pass'
        $r = (& $script:Judge 'purview' (& $script:Alerts -Off 'Messages have been delayed' -Absent 'Suspicious connector activity'))['PV-012']
        $r.status | Should -Be 'fail'
        @($r.affected | ForEach-Object { "$($_.name): $($_.detail)" }) | Should -Be @('Suspicious connector activity: not found among the alert policies', 'Messages have been delayed: turned off')
        $empty = (& $script:Judge 'purview' @{ 'pv-07-alert-policies' = @(); 'pv-02-dlp-policies' = @() })['PV-012']
        $empty.status | Should -Be 'notEvaluated' -Because 'a tenant always has built-in alert policies, so none means not read'
    }

    It 'PV-013 fails on an alert that emails nobody, and has no answer when recipients were never saved' {
        (& $script:Judge 'purview' (& $script:Alerts))['PV-013'].status | Should -Be 'pass'
        $r = (& $script:Judge 'purview' (& $script:Alerts -Quiet 'Tenant restricted from sending email'))['PV-013']
        $r.status | Should -Be 'fail'
        @($r.affected.name) | Should -Be @('Tenant restricted from sending email')
        $old = (& $script:Judge 'purview' @{ 'pv-07-alert-policies' = @($script:AlertNames | ForEach-Object { @{ Name = $_; Disabled = $false } }) })
        $old['PV-012'].status | Should -Be 'pass' -Because 'whether a policy is on was saved all along'
        $old['PV-013'].reason | Should -Match 'collected before TenantKeep read who an alert is sent to'
    }
}

Describe 'Teams recording and custom apps (catalog 2026.11.3)' {
    It 'CL-027 judges recording in the policy everybody gets' {
        (& $script:Judge 'collaboration' (& $script:Teams @{} @{ AllowCloudRecording = $false }))['CL-027'].status | Should -Be 'pass'
        (& $script:Judge 'collaboration' (& $script:Teams @{} @{ AllowCloudRecording = $true }))['CL-027'].status | Should -Be 'fail'
        (& $script:Judge 'collaboration' (& $script:Teams @{} @{}))['CL-027'].status | Should -Be 'notEvaluated'
    }

    It 'CL-028 fails only when live events are always recorded, and needs the live events policy' {
        $with = { param($Policy) (& $script:Teams @{} @{}) + @{ 'teams-live-event-policy-global' = $Policy } }
        (& $script:Judge 'collaboration' (& $with @{ Identity = 'Global'; BroadcastRecordingMode = 'UserOverride' }))['CL-028'].status | Should -Be 'pass'
        (& $script:Judge 'collaboration' (& $with @{ Identity = 'Global'; BroadcastRecordingMode = 'AlwaysEnabled' }))['CL-028'].status | Should -Be 'fail'
        (& $script:Judge 'collaboration' (& $with @{ Identity = 'Global' }))['CL-028'].reason | Should -Match 'did not say when an event is recorded'
        $none = (& $script:Judge 'collaboration' (& $script:Teams @{} @{}))['CL-028']
        $none.status | Should -Be 'notEvaluated'
        $none.reason | Should -Match 'teams-live-event-policy-global'
    }

    It 'CL-029 reads the org-wide setting for custom apps, else the global permission policy' {
        $with = { param([hashtable] $Files) (& $script:Teams @{} @{}) + $Files }
        $setting = { param([string] $Value) @{ 'teams-app-settings' = @(@{ SettingName = 'GlobalApp'; SettingValue = 'None'; Users = ''; Groups = '' }, @{ SettingName = 'PrivateApp'; SettingValue = $Value; Users = ''; Groups = '' }) } }
        (& $script:Judge 'collaboration' (& $with (& $setting 'None')))['CL-029'].status | Should -Be 'pass'
        $r = (& $script:Judge 'collaboration' (& $with (& $setting 'All')))['CL-029']
        $r.status | Should -Be 'fail'
        $r.affected[0].name | Should -Be 'Org-wide app settings'
        $policy = { param([string] $Type) @{ 'teams-app-permission-policies' = @(@{ Identity = 'Global'; GlobalCatalogAppsType = 'AllowedAppList'; PrivateCatalogAppsType = $Type }) } }
        (& $script:Judge 'collaboration' (& $with (& $policy 'AllowedAppList')))['CL-029'].status | Should -Be 'pass'
        (& $script:Judge 'collaboration' (& $with (& $policy 'BlockedAppList')))['CL-029'].status | Should -Be 'fail'
        (& $script:Judge 'collaboration' (& $script:Teams @{} @{}))['CL-029'].status | Should -Be 'notEvaluated'
    }
}

Describe 'Role alerts and the app management policy (catalog 2026.11.3)' {
    BeforeAll {
        $script:Pim = { param([hashtable] $Alerts) @{ '04-pim-role-policies' = @(@{ Role = 'Global Administrator'; RoleDefinitionId = 'r-ga'; MaxActivationHours = 4; ActivationMfaRequired = $true; ActivationJustificationRequired = $true; ApprovalRequired = $true } + $Alerts) } }
        $script:AlertRules = { param($Admins, $Others) @{ EligibleAlertToAdmins = $Admins; EligibleAlertOtherRecipients = $Others; ActiveAlertToAdmins = $Admins; ActiveAlertOtherRecipients = $Others; ActivationAlertToAdmins = $Admins; ActivationAlertOtherRecipients = $Others } }
        $script:AppPolicy = { param([bool] $On, $SecretRules = @(), $CertificateRules = @()) @{ '02-app-management-policy' = @{ id = 'policy'; isEnabled = $On; applicationRestrictions = @{ passwordCredentials = @($SecretRules); keyCredentials = @($CertificateRules) } } } }
        $script:Restriction = { param([string] $Type, $Life = $null) @{ restrictionType = $Type; state = 'enabled'; maxLifetime = $Life; restrictForAppsCreatedAfterDateTime = '0001-01-01T00:00:00Z' } }
    }

    It 'ID-026 and ID-027 pass when the default recipients get the alerts, and fail when nobody does' {
        $default = & $script:Judge 'identity' (& $script:Pim (& $script:AlertRules $true 0))
        foreach ($id in 'ID-026', 'ID-027') { $default[$id].status | Should -Be 'pass' -Because $id }
        $nobody = & $script:Judge 'identity' (& $script:Pim (& $script:AlertRules $false 0))
        foreach ($id in 'ID-026', 'ID-027') { $nobody[$id].status | Should -Be 'fail' -Because $id }
        $nobody['ID-026'].affected[0].detail | Should -Be 'the alert that someone was made eligible goes to nobody; the alert that someone was made active goes to nobody'
        $nobody['ID-027'].affected[0].name | Should -Be 'Global Administrator'
    }

    It 'the CISA SCuBA baseline counts only an address beyond the default recipients' {
        $default = & $script:Judge 'identity' (& $script:Pim (& $script:AlertRules $true 0)) 'cisa-scuba'
        foreach ($id in 'ID-026', 'ID-027') { $default[$id].status | Should -Be 'fail' -Because $id }
        $default['ID-027'].affected[0].detail | Should -Be 'the alert that someone activated the role goes only to the administrators Microsoft sends it to by default'
        $named = & $script:Judge 'identity' (& $script:Pim (& $script:AlertRules $false 1)) 'cisa-scuba'
        foreach ($id in 'ID-026', 'ID-027') { $named[$id].status | Should -Be 'pass' -Because $id }
    }

    It 'ID-026 and ID-027 have no answer for role settings saved before the alert rules, or without them' {
        $old = & $script:Judge 'identity' (& $script:Pim @{})
        foreach ($id in 'ID-026', 'ID-027') { $old[$id].reason | Should -Match 'collected before TenantKeep read the alert rules' -Because $id }
        $blank = & $script:Judge 'identity' (& $script:Pim (& $script:AlertRules $null $null))
        $blank['ID-026'].reason | Should -Match 'without their assignment alert rules'
        $blank['ID-027'].reason | Should -Match 'without their activation alert rule'
    }

    It 'ID-028 wants the policy on and new secrets refused' {
        (& $script:Judge 'identity' (& $script:AppPolicy $true @((& $script:Restriction 'passwordAddition'))))['ID-028'].status | Should -Be 'pass'
        (& $script:Judge 'identity' (& $script:AppPolicy $false @((& $script:Restriction 'passwordAddition'))))['ID-028'].status | Should -Be 'fail' -Because 'a restriction in a policy that is off restricts nothing'
        (& $script:Judge 'identity' (& $script:AppPolicy $true))['ID-028'].status | Should -Be 'fail'
    }

    It 'ID-029 wants a lifetime on secrets and on certificates, within the limits' {
        $good = & $script:AppPolicy $true @((& $script:Restriction 'passwordLifetime' 'P181D')) @((& $script:Restriction 'asymmetricKeyLifetime' 'P365D'))
        (& $script:Judge 'identity' $good)['ID-029'].status | Should -Be 'pass'
        $r = (& $script:Judge 'identity' (& $script:AppPolicy $true @((& $script:Restriction 'passwordLifetime' 'P730D'))))['ID-029']
        $r.status | Should -Be 'fail'
        @($r.affected | ForEach-Object { "$($_.name): $($_.detail)" }) | Should -Be @('Client secrets: may live 730 days (limit 181)', 'Certificates: no maximum lifetime')
        $noSecrets = & $script:AppPolicy $true @((& $script:Restriction 'passwordAddition')) @((& $script:Restriction 'asymmetricKeyLifetime' 'P366D'))
        (& $script:Judge 'identity' $noSecrets)['ID-029'].status | Should -Be 'pass' -Because 'a tenant that refuses new secrets has no secret lifetime left to cap'
    }

    It 'ID-028 and ID-029 have no answer when the policy was not read or does not say whether it is on' {
        $blank = & $script:Judge 'identity' @{ '02-app-management-policy' = @{ id = 'policy' } }
        foreach ($id in 'ID-028', 'ID-029') { $blank[$id].reason | Should -Match 'did not say whether it is on' -Because $id }
        $none = & $script:Judge 'identity' @{ '02-authorization-policy' = @{ allowInvitesFrom = 'adminsAndGuestInviters'; guestUserRoleId = '2af84b1e-32c8-42b7-82bc-daa82404023b'; defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @() } } }
        foreach ($id in 'ID-028', 'ID-029') { $none[$id].reason | Should -Match '02-app-management-policy' -Because $id }
    }
}

Describe 'CA-017: registering a sign-in method is protected' {
    BeforeAll {
        # The sample snapshot holds one policy on the action: p-007, enabled, blocks registration away from trusted locations.
        $script:Snapshot = {
            param([scriptblock] $Change)
            $dir = Join-Path $script:Root ([guid]::NewGuid().ToString('n'))
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot') -Destination $dir -Recurse
            $path = Join-Path $dir 'policies.json'
            $policies = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json -AsHashtable -Depth 30
            if ($Change) { & $Change ($policies | Where-Object { $_.id -eq 'p-007' }) }
            ConvertTo-Json -InputObject @($policies) -Depth 30 | Set-Content -LiteralPath $path
            '{ "version": 1, "licenses": ["E5", "P1", "P2"] }' | Set-Content (Join-Path $dir 'profile.json')
            $dir
        }
        $script:Registration = {
            param([string] $Folder, [string] $Baseline = 'standard')
            InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
            $run = Invoke-PostureChecks -Evidence $Folder -Domain ca -Baseline $Baseline -ProfilePath (Join-Path $Folder 'profile.json') -PassThru
            @($run.results | Where-Object { $_.id -eq 'CA-017' })[0]
        }
    }

    It 'passes on any policy that protects the action, and fails when that policy is off' {
        (& $script:Registration (& $script:Snapshot $null)).status | Should -Be 'pass'
        (& $script:Registration (& $script:Snapshot { param($p) $p.state = 'disabled' })).status | Should -Be 'fail'
        (& $script:Registration (& $script:Snapshot { param($p) $p.state = 'enabledForReportingButNotEnforced' })).status | Should -Be 'fail' -Because 'report-only protects nothing'
    }

    It 'under the CISA SCuBA baseline counts only a policy that asks for a managed device' {
        (& $script:Registration (& $script:Snapshot $null) 'cisa-scuba').status | Should -Be 'fail' -Because 'the sample policy blocks by location'
        $managed = & $script:Snapshot { param($p) $p.grantControls.builtInControls = @('compliantDevice', 'domainJoinedDevice') }
        (& $script:Registration $managed 'cisa-scuba').status | Should -Be 'pass'
        (& $script:Registration $managed).status | Should -Be 'pass'
    }
}

Describe 'Directory and sign-in settings (catalog 2026.11.3)' {
    BeforeAll {
        # The authorization policy as Graph sends it; a key set to 'absent' is left out.
        $script:Authz = {
            param([hashtable] $Set = @{}, [hashtable] $Role = @{})
            $permissions = @{ permissionGrantPoliciesAssigned = @(); allowedToCreateApps = $false; allowedToCreateTenants = $false; allowedToCreateSecurityGroups = $false }
            foreach ($k in $Role.Keys) { if ($Role[$k] -is [string] -and $Role[$k] -eq 'absent') { $permissions.Remove($k) } else { $permissions[$k] = $Role[$k] } }
            $p = @{ allowInvitesFrom = 'adminsAndGuestInviters'; guestUserRoleId = '2af84b1e-32c8-42b7-82bc-daa82404023b'; allowedToSignUpEmailBasedSubscriptions = $false; allowEmailVerifiedUsersToJoinOrganization = $false; allowedToUseSSPR = $false; allowUserConsentForRiskyApps = $false; defaultUserRolePermissions = $permissions }
            foreach ($k in $Set.Keys) { if ($Set[$k] -is [string] -and $Set[$k] -eq 'absent') { $p.Remove($k) } else { $p[$k] = $Set[$k] } }
            $p
        }
        $script:Setting = { param([string] $Name, [string] $TemplateId, [hashtable] $Values) @{ DisplayName = $Name; TemplateId = $TemplateId; Values = $Values } }
        $script:Lockout = { param([hashtable] $Values) & $script:Setting 'Password Rule Settings' '5cf42378-d67d-4f36-ba46-e8b86229381d' $Values }
        $script:Unified = { param([hashtable] $Values) & $script:Setting 'Group.Unified' '62375ab9-6b52-47ed-826b-58e47e0e304b' $Values }
        $script:Consent = { param([hashtable] $Values) & $script:Setting 'Consent Policy Settings' 'dffd5d46-495d-40a9-8e21-954ff55e198a' $Values }
        $script:Identity = { param($Authz, $Settings = @()) @{ '02-authorization-policy' = $Authz; '02-directory-settings' = @($Settings) } }
    }

    It 'ID-030, ID-031 and ID-034 each read one switch of the authorization policy' {
        $good = & $script:Judge 'identity' (& $script:Identity (& $script:Authz))
        foreach ($id in 'ID-030', 'ID-031', 'ID-034') { $good[$id].status | Should -Be 'pass' -Because $id }
        $bad = & $script:Judge 'identity' (& $script:Identity (& $script:Authz @{ allowedToUseSSPR = $true } @{ allowedToCreateTenants = $true; allowedToCreateSecurityGroups = $true }))
        foreach ($id in 'ID-030', 'ID-031', 'ID-034') { $bad[$id].status | Should -Be 'fail' -Because $id }
        $silent = & $script:Judge 'identity' (& $script:Identity (& $script:Authz @{ allowedToUseSSPR = 'absent' } @{ allowedToCreateTenants = 'absent'; allowedToCreateSecurityGroups = 'absent' }))
        foreach ($id in 'ID-030', 'ID-031', 'ID-034') { $silent[$id].status | Should -Be 'notEvaluated' -Because "${id}: a switch the policy did not send is not a pass" }
        $silent['ID-030'].reason | Should -Match 'did not say whether users may create tenants'
    }

    It 'ID-033 fails on either way to an account with an email address alone, and names it' {
        (& $script:Judge 'identity' (& $script:Identity (& $script:Authz)))['ID-033'].status | Should -Be 'pass'
        $r = (& $script:Judge 'identity' (& $script:Identity (& $script:Authz @{ allowEmailVerifiedUsersToJoinOrganization = $true })))['ID-033']
        $r.status | Should -Be 'fail'
        @($r.affected.name) | Should -Be @('Join by email validation')
        (& $script:Judge 'identity' (& $script:Identity (& $script:Authz @{ allowedToSignUpEmailBasedSubscriptions = 'absent' })))['ID-033'].status | Should -Be 'notEvaluated'
    }

    It 'ID-035 fails when either place allows risky consent, and needs both files' {
        (& $script:Judge 'identity' (& $script:Identity (& $script:Authz)))['ID-035'].status | Should -Be 'pass'
        (& $script:Judge 'identity' (& $script:Identity (& $script:Authz @{ allowUserConsentForRiskyApps = 'absent' })))['ID-035'].status | Should -Be 'pass' -Because 'with neither place saying anything Microsoft''s default applies, which blocks'
        (& $script:Judge 'identity' (& $script:Identity (& $script:Authz @{ allowUserConsentForRiskyApps = $true })))['ID-035'].status | Should -Be 'fail'
        (& $script:Judge 'identity' (& $script:Identity (& $script:Authz) @((& $script:Consent @{ BlockUserConsentForRiskyApps = 'false'; EnableGroupSpecificConsent = 'false' }))))['ID-035'].status | Should -Be 'fail' -Because 'the consent settings object says it is not blocked'
        $half = (& $script:Judge 'identity' @{ '02-authorization-policy' = (& $script:Authz) })['ID-035']
        $half.status | Should -Be 'notEvaluated'
        $half.reason | Should -Match '02-directory-settings'
    }

    It 'ID-036 reads group owner consent, and has no answer for a tenant with no consent settings object' {
        $with = { param([string] $Value) & $script:Identity (& $script:Authz) @((& $script:Consent @{ EnableGroupSpecificConsent = $Value })) }
        (& $script:Judge 'identity' (& $with 'false'))['ID-036'].status | Should -Be 'pass'
        (& $script:Judge 'identity' (& $with 'True'))['ID-036'].status | Should -Be 'fail'
        $none = (& $script:Judge 'identity' (& $script:Identity (& $script:Authz)))['ID-036']
        $none.status | Should -Be 'notEvaluated'
        $none.reason | Should -Match 'no consent settings object'
    }

    It 'ID-032 and ID-039 read the Microsoft 365 group settings, with Microsoft''s defaults where there are none' {
        $default = & $script:Judge 'identity' (& $script:Identity (& $script:Authz))
        $default['ID-032'].status | Should -Be 'fail' -Because 'with no settings object everyone may create a group'
        $default['ID-039'].status | Should -Be 'pass' -Because 'with no settings object no guest may own one'
        $set = & $script:Judge 'identity' (& $script:Identity (& $script:Authz) @((& $script:Unified @{ EnableGroupCreation = 'false'; AllowGuestsToBeGroupOwner = 'true' })))
        $set['ID-032'].status | Should -Be 'pass'
        $set['ID-039'].status | Should -Be 'fail'
    }

    It 'ID-038 holds smart lockout to ten tries and a minute, and passes on Microsoft''s defaults' {
        (& $script:Judge 'identity' (& $script:Identity (& $script:Authz)))['ID-038'].status | Should -Be 'pass'
        (& $script:Judge 'identity' (& $script:Identity (& $script:Authz) @((& $script:Lockout @{ LockoutThreshold = '5'; LockoutDurationInSeconds = '120' }))))['ID-038'].status | Should -Be 'pass'
        (& $script:Judge 'identity' (& $script:Identity (& $script:Authz) @((& $script:Lockout @{ LockoutThreshold = '50'; LockoutDurationInSeconds = '60' }))))['ID-038'].status | Should -Be 'fail'
        (& $script:Judge 'identity' (& $script:Identity (& $script:Authz) @((& $script:Lockout @{ LockoutThreshold = '10'; LockoutDurationInSeconds = '30' }))))['ID-038'].status | Should -Be 'fail'
    }

    It 'ID-037 wants reviewers told and requests to expire, where the workflow is on' {
        $policy = { param([hashtable] $Set = @{}) $p = @{ isEnabled = $true; notifyReviewers = $true; remindersEnabled = $true; requestDurationInDays = 30; reviewers = @(@{ query = '/users/reviewer'; queryType = 'MicrosoftGraph' }) }; foreach ($k in $Set.Keys) { if ($Set[$k] -is [string] -and $Set[$k] -eq 'absent') { $p.Remove($k) } else { $p[$k] = $Set[$k] } }; @{ '02-admin-consent-request-policy' = $p } }
        (& $script:Judge 'identity' (& $policy))['ID-037'].status | Should -Be 'pass'
        $r = (& $script:Judge 'identity' (& $policy @{ notifyReviewers = $false; requestDurationInDays = 60 }))['ID-037']
        $r.status | Should -Be 'fail'
        @($r.affected | ForEach-Object { "$($_.name): $($_.detail)" }) | Should -Be @('New requests: reviewers are not emailed when someone asks', 'Expiry: a request stays open 60 days (limit 30)')
        (& $script:Judge 'identity' (& $policy @{ isEnabled = $false }))['ID-037'].reason | Should -Match 'ID-009 comes first'
        (& $script:Judge 'identity' (& $policy @{ notifyReviewers = 'absent' }))['ID-037'].status | Should -Be 'notEvaluated'
    }

    It 'AU-010 wants Report suspicious activity on for everyone, from either copy of the policy' {
        $beta = { param([string] $State, $Target = 'all_users') @{ '02-auth-system-preferred' = @{ State = 'enabled'; ReportSuspiciousActivityState = $State; ReportSuspiciousActivityTarget = $Target } } }
        (& $script:Judge 'auth' (& $beta 'enabled'))['AU-010'].status | Should -Be 'pass'
        (& $script:Judge 'auth' (& $beta 'default'))['AU-010'].status | Should -Be 'fail' -Because 'left to Microsoft it is off'
        (& $script:Judge 'auth' (& $beta 'enabled' '6f1c3a52-0000-4000-8000-000000000001'))['AU-010'].status | Should -Be 'fail' -Because 'a pilot group is not everyone'
        $v1 = @{ '02-authentication-methods-policy' = @{ policyMigrationState = 'migrationComplete'; authenticationMethodConfigurations = @(); reportSuspiciousActivitySettings = @{ state = 'enabled'; includeTarget = @{ id = 'all_users' } } } }
        (& $script:Judge 'auth' $v1)['AU-010'].status | Should -Be 'pass'
        $old = (& $script:Judge 'auth' @{ '02-auth-system-preferred' = @{ State = 'enabled' } })['AU-010']
        $old.status | Should -Be 'notEvaluated'
        $old.reason | Should -Match 'collected before TenantKeep read Report suspicious activity'
    }

    It 'AU-002 asks for the app name and the location, shown to everyone' {
        $policy = {
            param([string] $Location = 'enabled', [string] $Target = 'all_users')
            $shown = @{ displayAppInformationRequiredState = @{ state = 'enabled'; includeTarget = @{ id = 'all_users' } }; displayLocationInformationRequiredState = @{ state = $Location; includeTarget = @{ id = $Target } } }
            $authenticator = @{ id = 'MicrosoftAuthenticator'; state = 'enabled'; includeTargets = @(@{ id = 'all_users'; targetType = 'group' }); featureSettings = $shown }
            @{ '02-authentication-methods-policy' = @{ policyMigrationState = 'migrationComplete'; authenticationMethodConfigurations = @($authenticator) } }
        }
        (& $script:Judge 'auth' (& $policy))['AU-002'].status | Should -Be 'pass'
        (& $script:Judge 'auth' (& $policy 'default'))['AU-002'].status | Should -Be 'fail' -Because 'the app name alone is half of what the title says'
        (& $script:Judge 'auth' (& $policy 'enabled' '6f1c3a52-0000-4000-8000-000000000001'))['AU-002'].status | Should -Be 'fail' -Because 'the location is shown to a pilot group only'
    }
}

Describe 'Mail protection detail (catalog 2026.11.3)' {
    BeforeAll {
        # Policies as Exchange saves them whole. A key in $Set replaces the sound value.
        $script:Spam = {
            param([hashtable] $Set = @{})
            $p = @{ Name = 'Default'; IsDefault = $true; RecommendedPolicyType = 'Custom'; ZapEnabled = $true; SpamZapEnabled = $true; PhishZapEnabled = $true; HighConfidencePhishQuarantineTag = 'AdminOnlyAccessPolicy'; AllowedSenderDomains = @(); AllowedSenders = @(); BulkThreshold = 6; MarkAsSpamBulkMail = 'On'; SpamAction = 'MoveToJmf'; BulkSpamAction = 'MoveToJmf'; HighConfidenceSpamAction = 'Quarantine'; PhishSpamAction = 'Quarantine'; QuarantineRetentionPeriod = 30; InlineSafetyTipsEnabled = $true; MarkAsSpamNdrBackscatter = 'Off' }
            foreach ($k in $Set.Keys) { $p[$k] = $Set[$k] }
            $p
        }
        $script:Phish = {
            param([hashtable] $Set = @{})
            $p = @{ Name = 'Office365 AntiPhish Default'; RecommendedPolicyType = 'Custom'; Enabled = $true; EnableSpoofIntelligence = $true; HonorDmarcPolicy = $true; EnableTargetedUserProtection = $true; TargetedUsersToProtect = @('x'); EnableOrganizationDomainsProtection = $true; EnableTargetedDomainsProtection = $false; EnableMailboxIntelligence = $true; EnableFirstContactSafetyTips = $true; EnableSimilarUsersSafetyTips = $true; EnableSimilarDomainsSafetyTips = $true; EnableUnusualCharactersSafetyTips = $true; EnableUnauthenticatedSender = $true; AuthenticationFailAction = 'MoveToJmf'; PhishThresholdLevel = 3; EnableMailboxIntelligenceProtection = $true; MailboxIntelligenceProtectionAction = 'Quarantine'; TargetedUserProtectionAction = 'Quarantine'; TargetedDomainProtectionAction = 'Quarantine'; ExcludedSenders = @(); ExcludedDomains = @() }
            foreach ($k in $Set.Keys) { $p[$k] = $Set[$k] }
            $p
        }
        # The preset's rule: for everyone, or for one pilot group.
        $script:PresetRule = { param([bool] $Everyone) @(@{ Name = 'Standard Preset Security Policy'; State = 'Enabled'; Priority = 0; SentTo = @(); SentToMemberOf = @($(if (-not $Everyone) { 'pilot@contoso.example' })); RecipientDomainIs = @() }) }
        $script:SpamFiles = { param($Policies, [bool] $PresetForAll = $false) @{ 'exo-04-eop-content-filter' = @($Policies); 'exo-04-preset-rules-eop' = (& $script:PresetRule $PresetForAll) } }
        $script:PhishFiles = { param($Policies, [bool] $PresetForAll = $false) @{ 'exo-04-antiphish' = @($Policies); 'exo-04-preset-rules-eop' = (& $script:PresetRule $PresetForAll); 'exo-04-preset-rules-mdo' = (& $script:PresetRule $PresetForAll) } }
    }

    It 'EM-034 holds an anti-spam policy to the recommended values, and says which it misses' {
        (& $script:Judge 'email' (& $script:SpamFiles (& $script:Spam)))['EM-034'].status | Should -Be 'pass'
        $loose = & $script:Spam @{ BulkThreshold = 7; HighConfidenceSpamAction = 'MoveToJmf'; MarkAsSpamNdrBackscatter = 'On' }
        $r = (& $script:Judge 'email' (& $script:SpamFiles $loose))['EM-034']
        $r.status | Should -Be 'fail'
        $r.affected[0].detail | Should -Be 'bulk threshold 7 (limit 6); high-confidence spam: MoveToJmf; 1 advanced spam filter option(s) on'
    }

    It 'EM-034 judges only a policy that can apply' {
        $loose = & $script:Spam @{ BulkThreshold = 7 }
        (& $script:Judge 'email' (& $script:SpamFiles $loose $true))['EM-034'].status | Should -Be 'pass' -Because 'where the preset covers everyone the default policy reaches nobody'
        $preset = & $script:Spam @{ Name = 'Standard Preset Security Policy1700000000000'; RecommendedPolicyType = 'Standard'; IsDefault = $false; BulkThreshold = 9 }
        $r = (& $script:Judge 'email' (& $script:SpamFiles @($preset, $loose)))['EM-034']
        @($r.affected.name) | Should -Be @('Default') -Because 'a preset policy carries Microsoft''s values and is not second-guessed'
    }

    It 'EM-034 has no answer without the preset rules, or from a policy list with no actions in it' {
        $files = & $script:SpamFiles (& $script:Spam); $files.Remove('exo-04-preset-rules-eop')
        $r = (& $script:Judge 'email' $files)['EM-034']
        $r.status | Should -Be 'notEvaluated'
        $r.reason | Should -Match 'exo-04-preset-rules-eop'
        (& $script:Judge 'email' (& $script:SpamFiles @(@{ Name = 'Default'; ZapEnabled = $true; SpamZapEnabled = $true; PhishZapEnabled = $true; HighConfidencePhishQuarantineTag = 'AdminOnlyAccessPolicy' })))['EM-034'].status | Should -Be 'notEvaluated'
    }

    It 'EM-039 names each sender on an allowed list, however the module wrote it' {
        (& $script:Judge 'email' (& $script:SpamFiles (& $script:Spam)))['EM-039'].status | Should -Be 'pass'
        $r = (& $script:Judge 'email' (& $script:SpamFiles (& $script:Spam @{ AllowedSenders = @('billing@partner.example', @{ Sender = @{ Address = 'news@other.example' } }) })))['EM-039']
        $r.status | Should -Be 'fail'
        @($r.affected.name) | Should -Be @('billing@partner.example', 'news@other.example')
    }

    It 'EM-035 fails a policy that lets spoofed mail through unmarked' {
        (& $script:Judge 'email' (& $script:PhishFiles (& $script:Phish)))['EM-035'].status | Should -Be 'pass'
        $r = (& $script:Judge 'email' (& $script:PhishFiles (& $script:Phish @{ EnableUnauthenticatedSender = $false; AuthenticationFailAction = 'NoAction' })))['EM-035']
        $r.status | Should -Be 'fail'
        $r.affected[0].detail | Should -Be 'no question mark on senders that fail authentication; spoofed mail: NoAction'
    }

    It 'EM-036 wants impersonation quarantined, a threshold of three and nobody trusted past it' {
        (& $script:Judge 'email' (& $script:PhishFiles (& $script:Phish)))['EM-036'].status | Should -Be 'pass'
        $weak = & $script:Phish @{ PhishThresholdLevel = 1; TargetedUserProtectionAction = 'NoAction'; ExcludedDomains = @('partner.example') }
        $r = (& $script:Judge 'email' (& $script:PhishFiles $weak))['EM-036']
        $r.status | Should -Be 'fail'
        $r.affected[0].detail | Should -Be 'phishing threshold 1 (at least 3); impersonated people: NoAction; 1 trusted domain(s) skip impersonation protection'
        (& $script:Judge 'email' (& $script:PhishFiles $weak $true))['EM-036'].status | Should -Be 'pass' -Because 'the preset covers everyone'
        $files = & $script:PhishFiles $weak; $files.Remove('exo-04-preset-rules-mdo')
        $half = & $script:Judge 'email' $files
        $half['EM-036'].status | Should -Be 'notEvaluated'
        $half['EM-035'].status | Should -Be 'pass' -Because 'the spoof settings lean on the EOP preset rules only'
    }

    It 'EM-037 wants Safe Attachments to hold a file back, and Safe Documents to allow no click-through' {
        $files = { param([string] $Action = 'Block', [bool] $ClickThrough = $false, [bool] $BuiltIn = $false) @{ 'exo-05-mdo-safeattachments' = @(@{ Name = 'Attachments'; Enable = $true; Action = $Action; IsBuiltInProtection = $BuiltIn }); 'exo-05-mdo-global' = @{ EnableATPForSPOTeamsODB = $true; EnableSafeDocs = $true; AllowSafeDocsOpen = $ClickThrough } } }
        (& $script:Judge 'email' (& $files))['EM-037'].status | Should -Be 'pass'
        (& $script:Judge 'email' (& $files 'DynamicDelivery' $false $true))['EM-037'].status | Should -Be 'pass' -Because 'the built-in policy is what people get when it is the only one'
        $r = (& $script:Judge 'email' (& $files 'Allow' $true))['EM-037']
        $r.status | Should -Be 'fail'
        @($r.affected | ForEach-Object { "$($_.name): $($_.detail)" }) | Should -Be @('Attachments: an attachment it cannot clear: Allow', 'Safe Documents: people can leave Protected View for a file Safe Documents flagged')
        $none = (& $script:Judge 'email' @{ 'exo-05-mdo-safeattachments' = @(); 'exo-05-mdo-global' = @{ EnableSafeDocs = $false } })['EM-037']
        $none.status | Should -Be 'notEvaluated'
        $none.reason | Should -Match 'EM-005 comes first'
    }

    It 'EM-038 fails on an enabled rule that skips Safe Attachments or Safe Links' {
        $rule = { param([string] $State = 'Enabled', $Header = 'X-MS-Exchange-Organization-SkipSafeLinksProcessing') @{ 'exo-03-transport-rules' = @(@{ Name = 'Scanner'; State = $State; Priority = 0; SetSCL = $null; SetHeaderName = $Header; SetHeaderValue = '1'; SenderIpRanges = @(); HeaderContainsMessageHeader = $null; FromScope = 'NotInOrganization' }) } }
        $r = (& $script:Judge 'email' (& $rule))['EM-038']
        $r.status | Should -Be 'fail'
        $r.affected[0].detail | Should -Be 'sets X-MS-Exchange-Organization-SkipSafeLinksProcessing'
        (& $script:Judge 'email' (& $rule 'Disabled'))['EM-038'].status | Should -Be 'pass'
        (& $script:Judge 'email' (& $rule 'Enabled' 'X-Disclaimer'))['EM-038'].status | Should -Be 'pass'
        $old = (& $script:Judge 'email' @{ 'exo-03-transport-rules' = @(@{ Name = 'Scanner'; State = 'Enabled'; SetSCL = $null; SenderIpRanges = @() }) })['EM-038']
        $old.status | Should -Be 'notEvaluated'
        $old.reason | Should -Match 'collected before TenantKeep read the headers a rule sets'
    }

    It 'EM-030 also fails a Safe Links policy that leaves mail between colleagues unchecked' {
        $policy = (& $script:SafeLinks 'Standard' $true) + @{ EnableForInternalSenders = $false }
        $r = (& $script:Judge 'email' @{ 'exo-05-mdo-safelinks' = @($policy) })['EM-030']
        $r.status | Should -Be 'fail'
        $r.affected[0].detail | Should -Match 'mail between colleagues checked False'
    }
}

Describe 'Conditional Access detail (catalog 2026.11.3)' {
    BeforeAll {
        # The sample snapshot with its policies changed: the scriptblock gets them by id.
        $script:Policies = {
            param([scriptblock] $Change)
            $dir = Join-Path $script:Root ([guid]::NewGuid().ToString('n'))
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot') -Destination $dir -Recurse
            $path = Join-Path $dir 'policies.json'
            $policies = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json -AsHashtable -Depth 30
            $byId = @{}; foreach ($policy in $policies) { $byId[$policy.id] = $policy }
            if ($Change) { & $Change $byId }
            ConvertTo-Json -InputObject @($policies) -Depth 30 | Set-Content -LiteralPath $path
            '{ "version": 1, "licenses": ["E5", "P1", "P2"] }' | Set-Content (Join-Path $dir 'profile.json')
            InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
            $run = Invoke-PostureChecks -Evidence $dir -Domain ca -ProfilePath (Join-Path $dir 'profile.json') -PassThru
            $by = @{}; foreach ($r in $run.results) { $by[$r.id] = $r }
            $by
        }
    }

    It 'CA-018 wants authentication transfer blocked for everyone, and needs a snapshot that carries the flows' {
        (& $script:Policies $null)['CA-018'].status | Should -Be 'fail'
        $blocked = & $script:Policies { param($p) $p['p-003'].conditions.authenticationFlows = @{ transferMethods = 'deviceCodeFlow,authenticationTransfer' } }
        $blocked['CA-018'].status | Should -Be 'pass'
        $blocked['CA-016'].status | Should -Be 'pass'
        $bare = & $script:Policies { param($p) foreach ($policy in $p.Values) { $policy.conditions.Remove('authenticationFlows') } }
        $bare['CA-018'].status | Should -Be 'notEvaluated'
        $bare['CA-018'].reason | Should -Match 'carries no authentication flows'
    }

    It 'CA-019 and CA-020 name the policy with a retired grant, and the one that needs both risks at once' {
        $clean = & $script:Policies $null
        foreach ($id in 'CA-019', 'CA-020', 'CA-024') { $clean[$id].status | Should -Be 'pass' -Because $id }
        $r = & $script:Policies { param($p) $p['p-005'].grantControls.builtInControls = @('compliantDevice', 'approvedApplication'); $p['p-002'].conditions.signInRiskLevels = @('high'); $p['p-002'].conditions.userRiskLevels = @('high') }
        $r['CA-019'].status | Should -Be 'fail'
        @($r['CA-019'].affected.id) | Should -Be @('p-005')
        $r['CA-020'].status | Should -Be 'fail'
        @($r['CA-020'].affected.id) | Should -Be @('p-002')
    }

    It 'CA-021 passes on a block for every platform but the named ones' {
        (& $script:Policies $null)['CA-021'].status | Should -Be 'fail'
        (& $script:Policies { param($p) $p['p-003'].conditions.platforms = @{ includePlatforms = @('all'); excludePlatforms = @('windows', 'macOS', 'iOS', 'android') } })['CA-021'].status | Should -Be 'pass'
        (& $script:Policies { param($p) $p['p-003'].conditions.platforms = @{ includePlatforms = @('all'); excludePlatforms = @() } })['CA-021'].status | Should -Be 'fail' -Because 'a block with no platform excluded blocks everything and is not this control'
    }

    It 'CA-022 wants both session controls on a policy for unmanaged devices' {
        $unmanaged = { param($p, [bool] $Frequency) $p['p-002'].conditions.devices = @{ deviceFilter = @{ mode = 'include'; rule = 'device.isCompliant -ne True' } }; $p['p-002'].sessionControls = @{ persistentBrowser = @{ isEnabled = $true; mode = 'never' }; signInFrequency = @{ isEnabled = $Frequency; value = 8; type = 'hours' } } }
        (& $script:Policies { param($p) & $unmanaged $p $true })['CA-022'].status | Should -Be 'pass'
        (& $script:Policies { param($p) & $unmanaged $p $false })['CA-022'].status | Should -Be 'fail' -Because 'the session never persists but is never asked to sign in again either'
        (& $script:Policies $null)['CA-022'].status | Should -Be 'fail' -Because 'the sample''s only device filter is about ownership'
    }

    It 'CA-023 looks for app enforced restrictions on Office 365 for everyone' {
        (& $script:Policies $null)['CA-023'].status | Should -Be 'fail'
        (& $script:Policies { param($p) $p['p-002'].sessionControls = @{ applicationEnforcedRestrictions = @{ isEnabled = $true } } })['CA-023'].status | Should -Be 'pass'
    }

    It 'CA-024 names an enabled policy that targets nothing' {
        $r = (& $script:Policies { param($p) $p['p-003'].conditions.applications.includeApplications = @() })['CA-024']
        $r.status | Should -Be 'fail'
        @($r.affected.id) | Should -Be @('p-003')
    }
}

Describe 'MSOnline, BitLocker keys and passkey attestation (catalog 2026.11.3)' {
    It 'ID-040 and ID-041 each read one switch of the authorization policy' {
        $good = & $script:Judge 'identity' (& $script:Identity (& $script:Authz @{ blockMsolPowerShell = $true } @{ allowedToReadBitlockerKeysForOwnedDevice = $false }))
        foreach ($id in 'ID-040', 'ID-041') { $good[$id].status | Should -Be 'pass' -Because $id }
        $bad = & $script:Judge 'identity' (& $script:Identity (& $script:Authz @{ blockMsolPowerShell = $false } @{ allowedToReadBitlockerKeysForOwnedDevice = $true }))
        foreach ($id in 'ID-040', 'ID-041') { $bad[$id].status | Should -Be 'fail' -Because $id }
        $silent = & $script:Judge 'identity' (& $script:Identity (& $script:Authz))
        foreach ($id in 'ID-040', 'ID-041') { $silent[$id].status | Should -Be 'notEvaluated' -Because "${id}: a switch the policy did not send is not a pass" }
    }

    It 'AU-011 judges attestation only where passkeys are on' {
        $policy = { param([hashtable] $Fido) @{ '02-authentication-methods-policy' = @{ policyMigrationState = 'migrationComplete'; authenticationMethodConfigurations = @((@{ id = 'Fido2'; includeTargets = @(@{ id = 'all_users' }); keyRestrictions = @{ isEnforced = $false } } + $Fido)) } } }
        (& $script:Judge 'auth' (& $policy @{ state = 'enabled'; isAttestationEnforced = $true }))['AU-011'].status | Should -Be 'pass'
        (& $script:Judge 'auth' (& $policy @{ state = 'enabled'; isAttestationEnforced = $false }))['AU-011'].status | Should -Be 'fail'
        (& $script:Judge 'auth' (& $policy @{ state = 'disabled'; isAttestationEnforced = $false }))['AU-011'].reason | Should -Match 'AU-003 comes first'
        (& $script:Judge 'auth' (& $policy @{ state = 'enabled' }))['AU-011'].status | Should -Be 'notEvaluated'
    }
}
