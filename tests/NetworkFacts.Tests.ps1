# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-network-$([guid]::NewGuid().ToString('n'))"
    $script:Write = { param([string] $Dir, [string] $Name, $Data) New-Item -ItemType Directory -Path $Dir -Force | Out-Null; ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }
    $script:Checks = {
        param([string] $Dir, [string] $ProfileJson)
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
        $pf = Join-Path $Dir 'profile.json'; $ProfileJson | Set-Content $pf
        $r = Invoke-PostureChecks -Evidence $Dir -Domain network -ProfilePath $pf -PassThru; $by = @{}; foreach ($x in $r.results) { $by[$x.id] = $x }; $by
    }
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Global Secure Access (network domain)' {
    It 'judges the profiles, web filtering and signaling for a licensed tenant' {
        $d = Join-Path $script:Root 'gsa'
        & $script:Write $d 'gsa-01-forwarding-profiles' @(@{ Name = 'Microsoft traffic'; TrafficForwardingType = 'm365'; State = 'enabled' }, @{ Name = 'Internet'; TrafficForwardingType = 'internet'; State = 'enabled' }, @{ Name = 'Private'; TrafficForwardingType = 'private'; State = 'disabled' })
        & $script:Write $d 'gsa-02-filtering-profiles' @(@{ Name = 'Baseline'; State = 'enabled'; Policies = 0 })
        & $script:Write $d 'gsa-03-settings' @{ RemoteNetworks = 0; SignalingStatus = 'enabled' }
        $by = & $script:Checks $d '{ "version": 1, "licenses": ["EntraSuite"] }'
        $by['NET-001'].status | Should -Be 'pass'
        $by['NET-002'].status | Should -Be 'fail' -Because 'the profile is on but no filtering policy is linked'
        $by['NET-003'].status | Should -Be 'fail'
        $by['NET-004'].status | Should -Be 'pass'
    }

    It 'reads as covered when another gateway does the job, and as needing the licence otherwise' {
        $d = Join-Path $script:Root 'vendor'
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        $by = & $script:Checks $d '{ "version": 1, "licenses": ["E3"], "thirdParty": { "swg": "Zscaler", "ztna": "none" } }'
        $by['NET-002'].status | Should -Be 'coveredBy'
        $by['NET-002'].reason | Should -Match 'Zscaler'
        $by['NET-003'].status | Should -Be 'notEvaluated'
        $by['NET-003'].reason | Should -Match 'Requires PrivateAccess or EntraSuite'
    }
}

Describe 'Global Secure Access configuration (catalog 2026.11.3)' {
    BeforeAll {
        # A tenant set up the way every check asks, as the collector saves it; a test changes what it is about.
        $script:Good = {
            $baselineLinks = @(@{ Kind = 'webFiltering'; State = 'enabled'; PolicyId = 'wf-1'; Policy = 'Block bad sites' }, @{ Kind = 'threatIntelligence'; State = 'enabled'; PolicyId = 'ti-1' }, @{ Kind = 'tlsInspection'; State = 'enabled'; PolicyId = 'tls-1' }, @{ Kind = 'cloudFirewall'; State = 'enabled'; PolicyId = 'fw-1' })
            [ordered]@{
                'gsa-01-forwarding-profiles' = @(
                    @{ Name = 'Microsoft traffic'; TrafficForwardingType = 'm365'; State = 'enabled'; AssignmentRequired = $true; Assigned = $true }
                    @{ Name = 'Internet'; TrafficForwardingType = 'internet'; State = 'enabled'; AssignmentRequired = $false; Assigned = $false }
                    @{ Name = 'Private'; TrafficForwardingType = 'private'; State = 'enabled'; AssignmentRequired = $true; Assigned = $true })
                'gsa-02-filtering-profiles'  = @(@{ Name = 'Baseline'; State = 'enabled'; Priority = 65000; Policies = 4 })
                'gsa-03-settings'            = @{ RemoteNetworks = 1; SignalingStatus = 'enabled'; TenantRestrictionsTagging = 'enabled'; PrivateNetworks = 1; DeploymentsRecent = 3; DeploymentsFailed = 0; DevicesSeen = 40; CompliantNetworkLocations = @('loc-compliant') }
                'gsa-04-security-profiles'   = @(
                    @{ Name = 'Baseline'; State = 'enabled'; Priority = 65000; Baseline = $true; ConditionalAccessPolicies = 0; Links = $baselineLinks }
                    @{ Name = 'Developers'; State = 'enabled'; Priority = 100; Baseline = $false; ConditionalAccessPolicies = 1; Links = @(@{ Kind = 'file'; State = 'enabled'; PolicyId = 'f-1' }, @{ Kind = 'prompt'; State = 'enabled'; PolicyId = 'p-1' }) })
                'gsa-05-filtering-policies'  = @(@{ Id = 'wf-1'; Name = 'Block bad sites'; Action = 'block'; RuleTypes = @('fqdn', 'webCategory'); WebCategories = @('CriminalActivity', 'Gambling', 'Hacking', 'IllegalSoftware'); HostRules = 2 })
                'gsa-06-tls-inspection'      = @{ Policies = @(@{ Id = 'tls-1'; Name = 'Inspect'; DefaultAction = 'inspect'; LastModifiedUtc = '2026-11-01T00:00:00Z'; Rules = 3; BypassRules = 2 }); CertificatesRead = $true; Certificates = @(@{ Name = 'ca-2026'; Status = 'active'; ExpiresUtc = '2027-11-01T00:00:00Z' }) }
                'gsa-07-private-apps'        = @(@{ Name = 'Quick Access'; AppId = 'app-qa'; QuickAccess = $true; Enabled = $true; AssignmentRequired = $true; Assigned = $true }, @{ Name = 'Payroll'; AppId = 'app-pay'; QuickAccess = $false; Enabled = $true; AssignmentRequired = $true; Assigned = $true })
                '02-cross-tenant-access-defaults' = @{ tenantRestrictions = @{ usersAndGroups = @{ accessType = 'blocked' }; applications = @{ accessType = 'blocked' } } }
                'policies'                   = @(
                    @{ displayName = 'MFA for everything'; state = 'enabled'; conditions = @{ applications = @{ includeApplications = @('All'); excludeApplications = @() }; locations = $null }; grantControls = @{ builtInControls = @('mfa') }; sessionControls = $null }
                    @{ displayName = 'Compliant network only'; state = 'enabled'; conditions = @{ applications = @{ includeApplications = @('Office365') }; locations = @{ includeLocations = @('All'); excludeLocations = @('loc-compliant') } }; grantControls = @{ builtInControls = @('block') } })
                'az-09-entra-diagnostic-settings' = @(@{ Name = 'to-law'; WorkspaceId = '/subscriptions/s/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/law'; Categories = @('AuditLogs', 'SignInLogs', 'NetworkAccessTrafficLogs', 'NetworkAccessAlerts', 'RemoteNetworkHealthLogs', 'EnrichedOffice365AuditLogs') })
            }
        }
        $script:Judge = {
            param([System.Collections.IDictionary] $Files)
            $d = Join-Path $script:Root ([guid]::NewGuid().ToString('n'))
            foreach ($name in $Files.Keys) { & $script:Write $d $name $Files[$name] }
            & $script:Checks $d '{ "version": 1, "licenses": ["EntraSuite"] }'
        }
        $script:New = { 'NET-005', 'NET-006', 'NET-007', 'NET-008', 'NET-009', 'NET-010', 'NET-011', 'NET-012', 'NET-013', 'NET-014', 'NET-015', 'NET-016', 'NET-017', 'NET-018', 'NET-019', 'NET-020', 'NET-021', 'NET-022', 'NET-023', 'NET-024' }
    }

    It 'passes every check on a tenant that filters, inspects, restricts and logs' {
        $by = & $script:Judge (& $script:Good)
        foreach ($id in (& $script:New)) { $by[$id].status | Should -Be 'pass' -Because "$id $($by[$id].reason)" }
        $by['NET-004'].status | Should -Be 'pass'
    }

    It 'says which file is missing for evidence collected before these reads, and still judges the first four checks' {
        $files = & $script:Good
        foreach ($name in 'gsa-04-security-profiles', 'gsa-05-filtering-policies', 'gsa-06-tls-inspection', 'gsa-07-private-apps') { $files.Remove($name) }
        $files['gsa-03-settings'] = @{ RemoteNetworks = 0; SignalingStatus = 'enabled' }
        $by = & $script:Judge $files
        $by['NET-001'].status | Should -Be 'pass'
        foreach ($id in 'NET-005', 'NET-009', 'NET-012') { $by[$id].status | Should -Be 'notEvaluated'; $by[$id].reason | Should -Match 'gsa-04-security-profiles\.json' -Because $id }
        $by['NET-010'].reason | Should -Match 'gsa-06-tls-inspection\.json'
        $by['NET-020'].reason | Should -Match 'gsa-07-private-apps\.json'
        foreach ($id in 'NET-017', 'NET-018', 'NET-022', 'NET-023') { $by[$id].status | Should -Be 'notEvaluated' -Because "${id}: a setting that was not read is not off" }
        $by['NET-017'].reason | Should -Match 'could not be read'
    }

    It 'counts a policy only when its link is on, on a profile that is on and reaches someone' {
        $files = & $script:Good
        # The baseline profile is turned off, and the other profile has no Conditional Access policy.
        $files['gsa-04-security-profiles'][0].State = 'disabled'
        $files['gsa-04-security-profiles'][1].ConditionalAccessPolicies = 0
        $by = & $script:Judge $files
        foreach ($id in 'NET-005', 'NET-006', 'NET-007', 'NET-009', 'NET-012', 'NET-013', 'NET-014', 'NET-015') { $by[$id].status | Should -Be 'fail' -Because $id }
        @($by['NET-005'].affected).name | Should -Be @('Developers') -Because 'it is on, holds policies and reaches nobody'
        $by['NET-008'].status | Should -Be 'fail' -Because 'a policy that applies to nobody blocks nothing'
        $by['NET-010'].status | Should -Be 'notEvaluated' -Because 'the certificate matters once inspection is in use'
        # A link that is off does not count, on a profile that applies.
        $files = & $script:Good
        @($files['gsa-04-security-profiles'][0].Links | Where-Object { $_.Kind -eq 'threatIntelligence' })[0].State = 'disabled'
        (& $script:Judge $files)['NET-012'].status | Should -Be 'fail'
    }

    It 'NET-008 names each high-risk category no applied policy blocks' {
        $files = & $script:Good
        $files['gsa-05-filtering-policies'][0].WebCategories = @('Gambling', 'Hacking')
        $by = & $script:Judge $files
        $by['NET-008'].status | Should -Be 'fail'
        @($by['NET-008'].affected).name | Should -Be @('Criminal activity', 'Illegal software')
        $files['gsa-05-filtering-policies'][0].Action = 'allow'
        @((& $script:Judge $files)['NET-008'].affected).Count | Should -Be 3 -Because 'a policy that allows a category does not block it'
    }

    It 'NET-010 and NET-011 go by dates: a certificate close to its end and bypass rules nobody has touched' {
        $files = & $script:Good
        $soon = [datetime]::UtcNow.AddDays(30).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $files['gsa-06-tls-inspection'].Certificates = @(@{ Name = 'ca-old'; Status = 'active'; ExpiresUtc = $soon }, @{ Name = 'ca-new'; Status = 'active'; ExpiresUtc = '2029-01-01T00:00:00Z' }, @{ Name = 'ca-request'; Status = 'csrGenerated'; ExpiresUtc = '' })
        $files['gsa-06-tls-inspection'].Policies[0].LastModifiedUtc = '2025-01-01T00:00:00Z'
        $by = & $script:Judge $files
        $by['NET-010'].status | Should -Be 'fail'
        @($by['NET-010'].affected).name | Should -Be @('ca-old')
        @($by['NET-010'].affected)[0].detail | Should -Match '^expires in (29|30) days$'
        $by['NET-011'].status | Should -Be 'fail'
        @($by['NET-011'].affected)[0].detail | Should -Match '^2 bypass rule\(s\), last changed \d+ days ago$'
        $files['gsa-06-tls-inspection'].Policies[0].BypassRules = 0
        (& $script:Judge $files)['NET-011'].status | Should -Be 'notEvaluated' -Because 'there is nothing to review'
        $files['gsa-06-tls-inspection'].CertificatesRead = $false
        (& $script:Judge $files)['NET-010'].status | Should -Be 'notEvaluated'
    }

    It 'judges who the profiles and the private applications reach, and has no answer where that was not read' {
        $files = & $script:Good
        $files['gsa-01-forwarding-profiles'][2].Assigned = $false
        $files['gsa-07-private-apps'][1].Assigned = $false
        $by = & $script:Judge $files
        $by['NET-016'].status | Should -Be 'fail'
        @($by['NET-016'].affected).name | Should -Be @('Private')
        $by['NET-020'].status | Should -Be 'fail'
        @($by['NET-020'].affected).name | Should -Be @('Payroll')
        $files = & $script:Good
        $files['gsa-01-forwarding-profiles'][0].Assigned = $null
        $files['gsa-07-private-apps'][0].Assigned = $null
        $by = & $script:Judge $files
        $by['NET-016'].status | Should -Be 'notEvaluated'
        $by['NET-020'].status | Should -Be 'notEvaluated'
        $files['gsa-07-private-apps'] = @()
        $by = & $script:Judge $files
        foreach ($id in 'NET-020', 'NET-021') { $by[$id].reason | Should -Match '^No Private Access application is published' -Because $id }
    }

    It 'NET-021 wants multifactor authentication asked of each private application, by name or through All' {
        $files = & $script:Good
        $files['policies'][0].conditions.applications.excludeApplications = @('app-pay')
        $by = & $script:Judge $files
        $by['NET-021'].status | Should -Be 'fail'
        @($by['NET-021'].affected).name | Should -Be @('Payroll')
        $files['policies'] += @{ displayName = 'Strength for payroll'; state = 'enabled'; conditions = @{ applications = @{ includeApplications = @('app-pay') } }; grantControls = @{ authenticationStrength = @{ id = 'strength-1' } } }
        (& $script:Judge $files)['NET-021'].status | Should -Be 'pass'
        $files['policies'][2].state = 'enabledForReportingButNotEnforced'
        (& $script:Judge $files)['NET-021'].status | Should -Be 'fail' -Because 'a policy in report-only asks nobody for anything'
    }

    It 'NET-012 wants threat intelligence on the baseline profile, which reaches everyone' {
        $files = & $script:Good
        # Moved off the baseline, onto the profile Conditional Access hands to developers.
        $files['gsa-04-security-profiles'][0].Links = @($files['gsa-04-security-profiles'][0].Links | Where-Object { $_.Kind -ne 'threatIntelligence' })
        $files['gsa-04-security-profiles'][1].Links += @{ Kind = 'threatIntelligence'; State = 'enabled'; PolicyId = 'ti-1' }
        (& $script:Judge $files)['NET-012'].status | Should -Be 'fail' -Because 'everyone who is not a developer browses without it'
    }

    It 'NET-025 wants a managed device asked of each private application' {
        $files = & $script:Good
        $by = & $script:Judge $files
        $by['NET-025'].status | Should -Be 'fail' -Because 'the policies ask for multifactor authentication and the network, not for the device'
        @($by['NET-025'].affected).name | Should -Be @('Quick Access', 'Payroll')
        $files['policies'] += @{ displayName = 'Managed devices for private apps'; state = 'enabled'; conditions = @{ applications = @{ includeApplications = @('app-qa', 'app-pay') } }; grantControls = @{ builtInControls = @('compliantDevice', 'domainJoinedDevice'); operator = 'OR' } }
        (& $script:Judge $files)['NET-025'].status | Should -Be 'pass'
        $files['policies'][2].conditions.applications.includeApplications = @('app-qa')
        @((& $script:Judge $files)['NET-025'].affected).name | Should -Be @('Payroll')
        $files['gsa-07-private-apps'] = @()
        (& $script:Judge $files)['NET-025'].reason | Should -Match '^No Private Access application is published'
    }

    It 'judges what Conditional Access is told about the network' {
        $files = & $script:Good
        $files['policies'][1].conditions.locations.excludeLocations = @('some-other-location')
        (& $script:Judge $files)['NET-018'].status | Should -Be 'fail' -Because 'no enabled policy names the compliant network'
        $files = & $script:Good
        $files['gsa-03-settings'].CompliantNetworkLocations = @()
        (& $script:Judge $files)['NET-018'].status | Should -Be 'fail' -Because 'the location does not exist until signaling is turned on'
        $files = & $script:Good
        $files['policies'] += @{ displayName = 'Legacy app sessions'; state = 'enabled'; conditions = @{ applications = @{ includeApplications = @('legacy') } }; sessionControls = @{ continuousAccessEvaluation = @{ mode = 'disabled' } } }
        $by = & $script:Judge $files
        $by['NET-019'].status | Should -Be 'fail'
        @($by['NET-019'].affected).name | Should -Be @('Legacy app sessions')
        $files = & $script:Good
        $files['02-cross-tenant-access-defaults'].tenantRestrictions.applications.accessType = 'allowed'
        (& $script:Judge $files)['NET-017'].status | Should -Be 'fail' -Because 'tagging with a default that allows everything restricts nothing'
        $files = & $script:Good
        $files['gsa-03-settings'].TenantRestrictionsTagging = 'disabled'
        (& $script:Judge $files)['NET-017'].status | Should -Be 'fail'
    }

    It 'judges branch offices, deployments and logs, each with its own no-answer case' {
        $files = & $script:Good
        $files['gsa-03-settings'].RemoteNetworks = 0
        (& $script:Judge $files)['NET-015'].reason | Should -Match '^No remote network'
        $files = & $script:Good
        $files['gsa-03-settings'].DeploymentsFailed = 1
        $files['gsa-03-settings'].PrivateNetworks = 0
        $by = & $script:Judge $files
        $by['NET-023'].status | Should -Be 'fail'
        $by['NET-022'].status | Should -Be 'fail'
        $files['gsa-03-settings'].DeploymentsRecent = 0; $files['gsa-03-settings'].DeploymentsFailed = 0
        (& $script:Judge $files)['NET-023'].status | Should -Be 'notEvaluated' -Because 'nothing was deployed, so nothing can be said to have worked'
        $files = & $script:Good
        $files['az-09-entra-diagnostic-settings'][0].Categories = @('AuditLogs', 'SignInLogs', 'NetworkAccessTrafficLogs')
        $by = & $script:Judge $files
        $by['NET-024'].status | Should -Be 'fail'
        @($by['NET-024'].affected).name | Should -Be @('NetworkAccessAlerts', 'RemoteNetworkHealthLogs', 'EnrichedOffice365AuditLogs')
        $files.Remove('az-09-entra-diagnostic-settings')
        $by = & $script:Judge $files
        $by['NET-024'].status | Should -Be 'notEvaluated'
        $by['NET-024'].reason | Should -Match 'az-09-entra-diagnostic-settings\.json'
    }
}
