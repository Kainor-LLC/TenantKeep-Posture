# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# The Global Secure Access part of the Entra collection, against a stand-in for Microsoft Graph: what is asked for,
# what is saved, and what is left out.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-gsa-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $script:Read = { param([string] $Name) Get-Content -Raw -LiteralPath (Join-Path $script:Root "$Name.json") | ConvertFrom-Json -Depth 10 }
    InModuleScope TenantKeep.Posture -Parameters @{ Folder = $script:Root } {
        param($Folder)
        $script:Asked = [System.Collections.Generic.List[hashtable]]::new()
        $script:Folder = $Folder
        $script:Now = [datetime]::new(2026, 11, 23, 12, 0, 0, [System.DateTimeKind]::Utc)
        Mock Invoke-PostureGraphRequest {
            $script:Asked.Add(@{ Uri = $Uri; ApiVersion = $ApiVersion; Single = [bool]$Single })
            $link = { param([string] $Type, [string] $State, [string] $Id) @{ '@odata.type' = "#microsoft.graph.networkaccess.$Type"; state = $State; priority = 100; policy = @{ id = $Id; name = "policy $Id"; action = 'block' } } }
            switch -Regex ($Uri) {
                '^networkAccess/forwardingProfiles\?\$expand=servicePrincipal' { return @(@{ name = 'Microsoft traffic'; trafficForwardingType = 'm365'; state = 'enabled'; servicePrincipal = @{ id = 'sp-m365'; appId = 'app-m365' } }, @{ name = 'Internet'; trafficForwardingType = 'internet'; state = 'disabled' }) }
                '^servicePrincipals/sp-m365\?' { return @{ id = 'sp-m365'; appRoleAssignmentRequired = $true } }
                '^servicePrincipals/sp-m365/appRoleAssignedTo' { return @{ value = @(@{ id = 'assignment-1'; principalId = 'user-77' }) } }
                '^networkAccess/filteringProfiles\?\$expand=policies$' { return @(@{ name = 'Baseline'; state = 'enabled'; priority = 65000; policies = @(@{}, @{}, @{}) }) }
                '^networkAccess/filteringProfiles\?\$expand=policies\(' {
                    return @(
                        @{ name = 'Baseline'; state = 'enabled'; priority = 65000; conditionalAccessPolicies = @(); policies = @((& $link 'filteringPolicyLink' 'enabled' 'wf-1'), (& $link 'threatIntelligencePolicyLink' 'enabled' 'ti-1'), (& $link 'tlsInspectionPolicyLink' 'disabled' 'tls-1')) }
                        @{ name = 'Developers'; state = 'enabled'; priority = 100; conditionalAccessPolicies = @(@{ id = 'ca-1' }); policies = @((& $link 'filePolicyLink' 'enabled' 'f-1'), (& $link 'somethingNewPolicyLink' 'enabled' 'x-1')) })
                }
                '^networkAccess/filteringPolicies\?' { return @(@{ id = 'wf-1'; name = 'Block bad sites'; action = 'block'; policyRules = @(@{ ruleType = 'webCategory'; destinations = @(@{ name = 'Hacking' }, @{ name = 'CriminalActivity' }) }, @{ ruleType = 'fqdn'; destinations = @(@{ value = 'internal-secret-host.contoso.example' }) }) }) }
                '^networkAccess/tlsInspectionPolicies\?' { return @(@{ id = 'tls-1'; name = 'Inspect'; lastModifiedDateTime = '2026-06-01T08:00:00Z'; settings = @{ defaultAction = 'inspect' }; policyRules = @(@{ action = 'bypass'; priority = 100 }, @{ action = 'bypass'; priority = 65000 }, @{ action = 'inspect'; priority = 200 }) }) }
                '^networkAccess/tls/externalCertificateAuthorityCertificates' { return @(@{ name = 'ca-2026'; status = 'active'; validity = @{ endDateTime = '2027-03-01T00:00:00Z' }; certificate = 'MIIB-not-to-be-saved' }) }
                '^servicePrincipals\?\$filter=tags/any' { return @(@{ id = 'pa-1'; appId = 'app-qa'; displayName = 'Quick Access'; accountEnabled = $true; appRoleAssignmentRequired = $true; tags = @('IsAccessibleViaZTNAClient', 'NetworkAccessQuickAccessApplication') }, @{ id = 'pa-2'; appId = 'app-pay'; displayName = 'Payroll'; accountEnabled = $true; appRoleAssignmentRequired = $true; tags = @('IsAccessibleViaZTNAClient') }) }
                '^servicePrincipals/pa-1/appRoleAssignedTo' { return @{ value = @() } }
                '^servicePrincipals/pa-2/appRoleAssignedTo' { throw 'Graph answered 403 Forbidden' }
                '^networkAccess/connectivity/remoteNetworks' { return @(@{ name = 'Branch 1' }) }
                '^networkAccess/settings/conditionalAccess' { return @{ signalingStatus = 'enabled' } }
                '^networkAccess/settings/crossTenantAccess' { return @{ networkPacketTaggingStatus = 'enabled' } }
                '^networkAccess/privateNetworks' { throw 'Graph answered 404 Not Found' }
                '^networkAccess/deployments' { return @(@{ deploymentEndDateTime = '2026-11-20T10:00:00Z'; status = @{ deploymentStage = 'succeeded' } }, @{ lastModifiedDateTime = '2026-11-21T10:00:00Z'; status = @{ deploymentStage = 'failed' } }, @{ deploymentEndDateTime = '2026-08-01T10:00:00Z'; status = @{ deploymentStage = 'failed' } }) }
                '^networkAccess/reports/getDeviceUsageSummary\(' { return @{ totalDeviceCount = 12; activeDeviceCount = 9 } }
                '^identity/conditionalAccess/namedLocations\?\$filter=isof' { return @(@{ id = 'loc-compliant'; displayName = 'All Compliant Network locations' }) }
                default { throw "The stand-in has no answer for $Uri" }
            }
        }
        $script:Result = Invoke-PostureNetworkAccessCollection -Folder $Folder -Licensed 'internetAccess', 'privateAccess' -AsOf $script:Now
    }
}

AfterAll { Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'The Global Secure Access collection' {
    It 'asks Graph beta for settings only, at addresses it names, and writes the seven files' {
        InModuleScope TenantKeep.Posture {
            @($script:Asked | Where-Object { $_.ApiVersion -ne 'beta' }).Count | Should -Be 0 -Because 'the API version is pinned on every call'
            $known = '^(networkAccess/(forwardingProfiles|filteringProfiles|filteringPolicies|tlsInspectionPolicies|tls/externalCertificateAuthorityCertificates|connectivity/remoteNetworks|settings/conditionalAccess|settings/crossTenantAccess|privateNetworks|deployments|reports/getDeviceUsageSummary\()|servicePrincipals(\?|/[a-z0-9-]+(\?|/appRoleAssignedTo\?))|identity/conditionalAccess/namedLocations\?)'
            foreach ($call in $script:Asked) { $call.Uri | Should -Match $known }
            @($script:Asked | Where-Object { $_.Uri -match 'onPremisesPublishingProfiles' }).Count | Should -Be 0 -Because 'connectors are listed only with a write permission, which this sign-in does not hold'
            @($script:Asked | Where-Object { $_.Uri -match 'appRoleAssignedTo' -and $_.Uri -notmatch '\$top=1' }).Count | Should -Be 0 -Because 'whether anyone is assigned takes one row, and the list of people is never read'
            @($script:Result['files'] | ForEach-Object { Split-Path $_ -Leaf } | Sort-Object) | Should -Be @('gsa-01-forwarding-profiles.json', 'gsa-02-filtering-profiles.json', 'gsa-03-settings.json', 'gsa-04-security-profiles.json', 'gsa-05-filtering-policies.json', 'gsa-06-tls-inspection.json', 'gsa-07-private-apps.json')
            Join-Path $script:Folder 'gsa-07-private-apps.csv' | Should -Exist -Because 'the application list is also written as a table'
        }
    }

    It 'saves who a forwarding profile reaches as two answers, and leaves them empty where there is no service principal' {
        $fp = @(& $script:Read 'gsa-01-forwarding-profiles')
        $fp[0].Name | Should -Be 'Microsoft traffic'
        $fp[0].AssignmentRequired | Should -BeTrue
        $fp[0].Assigned | Should -BeTrue
        $fp[1].AssignmentRequired | Should -BeNullOrEmpty
        $fp[1].Assigned | Should -BeNullOrEmpty
    }

    It 'saves each security profile with its links by kind, and which profile is the baseline' {
        $profiles = @(& $script:Read 'gsa-04-security-profiles')
        $profiles[0].Baseline | Should -BeTrue
        $profiles[1].Baseline | Should -BeFalse
        $profiles[1].ConditionalAccessPolicies | Should -Be 1
        @($profiles[0].Links | ForEach-Object { "$($_.Kind)=$($_.State)" }) | Should -Be @('webFiltering=enabled', 'threatIntelligence=enabled', 'tlsInspection=disabled')
        @($profiles[1].Links.Kind) | Should -Be @('file', 'other') -Because 'a kind of link this version does not know is kept as other, not guessed'
        $profiles[0].Links[0].PolicyId | Should -Be 'wf-1'
    }

    It 'saves the categories a filtering policy names and counts its host rules without saving a host name' {
        $policy = @(& $script:Read 'gsa-05-filtering-policies')[0]
        $policy.Action | Should -Be 'block'
        @($policy.WebCategories) | Should -Be @('CriminalActivity', 'Hacking')
        @($policy.RuleTypes) | Should -Be @('fqdn', 'webCategory')
        $policy.HostRules | Should -Be 1
        $everything = (Get-ChildItem -LiteralPath $script:Root -File | ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName }) -join "`n"
        $everything | Should -Not -Match 'internal-secret-host' -Because 'the host names in a rule are the organisation''s own business'
        $everything | Should -Not -Match 'user-77|assignment-1' -Because 'who is assigned is not saved'
        $everything | Should -Not -Match 'MIIB-not-to-be-saved' -Because 'a certificate is never saved, only its name, status and expiry'
    }

    It 'saves TLS inspection as policies with their own bypass rules counted, and certificates by name, status and expiry' {
        $tls = & $script:Read 'gsa-06-tls-inspection'
        $tls.Policies[0].DefaultAction | Should -Be 'inspect'
        $tls.Policies[0].Rules | Should -Be 3
        $tls.Policies[0].BypassRules | Should -Be 1 -Because 'the system bypass rule at priority 65000 is Microsoft''s, not a choice of the organisation'
        # Read as text: ConvertFrom-Json turns a date string into a date, and the file's own wording is what matters.
        $text = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'gsa-06-tls-inspection.json')
        $text | Should -Match '"LastModifiedUtc": "2026-06-01T08:00:00Z"' -Because 'dates in evidence are ISO 8601 in UTC'
        $text | Should -Match '"ExpiresUtc": "2027-03-01T00:00:00Z"'
        $tls.CertificatesRead | Should -BeTrue
        $tls.Certificates[0].Name | Should -Be 'ca-2026'
    }

    It 'says whether anyone is assigned to each private application, and leaves it empty where that was refused' {
        $apps = @(& $script:Read 'gsa-07-private-apps')
        $apps[0].QuickAccess | Should -BeTrue
        $apps[0].Assigned | Should -BeFalse -Because 'the read worked and found nobody'
        $apps[1].Name | Should -Be 'Payroll'
        $apps[1].Assigned | Should -BeNullOrEmpty -Because 'a read that was refused is not an answer'
    }

    It 'saves the settings one by one: a setting that could not be read is empty, and the others are there' {
        $settings = & $script:Read 'gsa-03-settings'
        $settings.SignalingStatus | Should -Be 'enabled'
        $settings.RemoteNetworks | Should -Be 1
        $settings.TenantRestrictionsTagging | Should -Be 'enabled'
        $settings.PrivateNetworks | Should -BeNullOrEmpty -Because 'Graph answered 404 for it'
        $settings.DeploymentsRecent | Should -Be 2 -Because 'one deployment is older than 30 days'
        $settings.DeploymentsFailed | Should -Be 1
        $settings.DevicesSeen | Should -Be 12
        @($settings.CompliantNetworkLocations) | Should -Be @('loc-compliant')
        @($settings.Licensed) | Should -Be @('internetAccess', 'privateAccess')
    }
}
