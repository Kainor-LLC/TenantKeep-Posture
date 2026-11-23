# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# The checks added in catalog 2026.11.3 from settings the run already collects. Each is judged from a folder holding
# only the file it reads: good, bad, and the setting not there (no answer, never a pass).
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-hardening-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $script:Judge = {
        param([string] $Domain, [System.Collections.IDictionary] $Files)
        $dir = Join-Path $script:Root ([guid]::NewGuid().ToString('n'))
        New-Item -ItemType Directory -Path $dir | Out-Null
        foreach ($name in $Files.Keys) { ConvertTo-Json -InputObject $Files[$name] -Depth 8 | Set-Content (Join-Path $dir "$name.json") }
        '{ "version": 1, "licenses": ["E5", "MDO1", "MDO2", "P1", "P2"] }' | Set-Content (Join-Path $dir 'profile.json')
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
        $run = Invoke-PostureChecks -Evidence $dir -Domain $Domain -ProfilePath (Join-Path $dir 'profile.json') -PassThru
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
