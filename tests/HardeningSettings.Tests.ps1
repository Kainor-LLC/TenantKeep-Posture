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
