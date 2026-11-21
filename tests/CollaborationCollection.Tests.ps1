# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    . (Join-Path $PSScriptRoot 'Fixtures' 'CollaborationFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-collab-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $env:TKP_COLLAB_FIXTURE = (Join-Path $PSScriptRoot 'Fixtures' 'CollaborationFixture.ps1')

    Mock -ModuleName TenantKeep.Posture Get-MgContext { [pscustomobject]@{ TenantId = 'tenant-guid'; Account = 'reader@contoso.example'; AuthType = 'Delegated'; Scopes = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All') } }
    Mock -ModuleName TenantKeep.Posture Start-Transcript { }
    Mock -ModuleName TenantKeep.Posture Stop-Transcript { }
    Mock -ModuleName TenantKeep.Posture Test-PosturePnpSession { $env:TKP_COLLAB_CONNECTED -eq '1' }
    Mock -ModuleName TenantKeep.Posture Test-PostureTeamsSession { $env:TKP_COLLAB_CONNECTED -eq '1' }
    Mock -ModuleName TenantKeep.Posture Invoke-PosturePnpCommand { . $env:TKP_COLLAB_FIXTURE; $items = @(Get-CollaborationFixtureObject -Name $Name); if ($Name -eq 'Get-PnPTenantSite' -and -not ($Parameters -and $Parameters['IncludeOneDriveSites'])) { $items = @($items | Where-Object { [string]$_.Template -notlike 'SPSPERS*' }) }; if ($PesterBoundParameters.ContainsKey('OnItem')) { foreach ($i in $items) { & $PesterBoundParameters['OnItem'] $i }; return }; $items }
    Mock -ModuleName TenantKeep.Posture Invoke-PostureTeamsCommand { . $env:TKP_COLLAB_FIXTURE; @(Get-CollaborationFixtureObject -Name $Name) }
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
    Remove-Item Env:TKP_COLLAB_FIXTURE, Env:TKP_COLLAB_CONNECTED -ErrorAction SilentlyContinue
}

Describe 'Invoke-PostureCollection -Collector SharePoint, Teams' {
    Context 'with -IncludeOneDriveSites' {
        It 'lists the OneDrives as well and counts them apart' {
            $env:TKP_COLLAB_CONNECTED = '1'
            $folder = Join-Path $script:Root 'run-onedrive'
            $null = Invoke-PostureCollection -Collector SharePoint -IncludeOneDriveSites -SkipCaSnapshot -OutputFolder $folder -PassThru -WarningAction SilentlyContinue
            $s = Get-Content -Raw (Join-Path $folder 'spo-sites-summary.json') | ConvertFrom-Json -AsHashtable
            $s.Total | Should -Be 4
            $s.OneDrivesIncluded | Should -BeTrue
            $s.OneDrives | Should -Be 1
            $s.Sites | Should -Be 3
            @(Import-Csv -LiteralPath (Join-Path $folder 'spo-sites.csv') | Where-Object { $_.IsOneDrive -eq 'True' }).Count | Should -Be 1
        }
    }

    Context 'connected' {
        BeforeAll {
            $env:TKP_COLLAB_CONNECTED = '1'
            $script:Folder = Join-Path $script:Root 'run1'
            $script:Result = Invoke-PostureCollection -Collector SharePoint, Teams -SkipCaSnapshot -OutputFolder $script:Folder -PassThru -WarningAction SilentlyContinue
            $script:Read = { param([string] $n) Get-Content -Raw (Join-Path $script:Folder "$n.json") | ConvertFrom-Json -AsHashtable }
        }

        It 'writes the A.3 files with the audit plan names' {
            foreach ($n in 'spo-tenant-settings', 'spo-sites', 'spo-sites-summary', 'teams-federation', 'teams-client-config', 'teams-meeting-policy-global', 'teams-external-access', 'teams-app-permission-policies', 'teams-guest-messaging', 'teams-app-settings', 'teams-app-availability') {
                Join-Path $script:Folder "$n.json" | Should -Exist
            }
            Join-Path $script:Folder 'spo-sites.csv' | Should -Exist
            $script:Result.Collectors | Should -Be @('SharePoint', 'Teams')
            $script:Result.Errors.Count | Should -Be 0
        }

        It 'keeps the tenant settings as one object with the audit plan properties only' {
            $t = & $script:Read 'spo-tenant-settings'
            $t.SharingCapability | Should -Be 'ExternalUserAndGuestSharing'
            $t.ContainsKey('Identity') | Should -BeFalse
        }

        It 'lists the sites and not the OneDrives, with ownerless and anonymous sharing counted' {
            @(& $script:Read 'spo-sites' | Where-Object { $_.Ownerless }).Url | Should -Be 'https://contoso.sharepoint.example/sites/OldProject'
            @(& $script:Read 'spo-sites' | Where-Object { $_.IsOneDrive }).Count | Should -Be 0 -Because 'a OneDrive per user is not what any check reads'
            $s = & $script:Read 'spo-sites-summary'
            $s.Total | Should -Be 3
            $s.OneDrivesIncluded | Should -BeFalse
            $s.OneDrives | Should -BeNullOrEmpty -Because 'not listed is unknown, not zero'
            $s.Sites | Should -Be 3
            $s.Ownerless | Should -Be 1 -Because 'the group-connected site is judged through its group and the search centre is a system site'
            $s.AnonymousSharingAllowed | Should -Be 1
            $s.RestrictedAccessControl | Should -Be 1
        }

        It 'flattens the Teams policies' {
            (& $script:Read 'teams-federation').AllowedDomains | Should -Be 'AllowAllKnownDomains'
            @(& $script:Read 'teams-app-permission-policies')[0].GlobalCatalogAppsType | Should -Be 'BlockedAppList'
        }

        It 'flattens each app''s availability and the org-wide app settings' {
            $apps = @(& $script:Read 'teams-app-availability')
            $apps.Count | Should -Be 4
            ($apps | Where-Object Id -eq 'app-crm').AvailableTo | Should -Be 'UsersandGroups'
            ($apps | Where-Object Id -eq 'app-games').IsBlocked | Should -Be 'Blocked'
            ($apps | Where-Object Id -eq 'app-planner').AvailableToChangedUtc | Should -Not -BeNullOrEmpty
            (@(& $script:Read 'teams-app-settings') | Where-Object SettingName -eq 'GlobalApp').SettingValue | Should -Be 'All'
        }

        It 'feeds the collaboration checks, with the Entra files for groups' {
            '[]' | Set-Content -LiteralPath (Join-Path $script:Folder '07-groups-ownerless.json')
            '{ "Present": true, "GroupLifetimeInDays": 365, "ManagedGroupTypes": "All" }' | Set-Content -LiteralPath (Join-Path $script:Folder '02-group-lifecycle-policy.json')
            $profilePath = Join-Path $script:Root 'profile.json'
            '{ "version": 1, "externalCollaboration": "governed", "licenses": ["BusinessPremium", "P1"] }' | Set-Content -LiteralPath $profilePath
            $run = Invoke-PostureChecks -Evidence $script:Folder -Domain collaboration -ProfilePath $profilePath -PassThru
            $by = @{}; foreach ($r in $run.results) { $by[$r.id] = $r }
            $by['CL-001'].status | Should -Be 'fail'
            $by['CL-002'].status | Should -Be 'fail' -Because 'anyone links allowed with no expiry'
            $by['CL-003'].status | Should -Be 'fail'
            $by['CL-004'].status | Should -Be 'fail' -Because 'governed collaboration with no domain list'
            $by['CL-005'].status | Should -Be 'fail'
            $by['CL-005'].affected[0].name | Should -Be 'Everyone except external users'
            $by['CL-006'].status | Should -Be 'pass'
            $by['CL-007'].status | Should -Be 'fail'
            $by['CL-007'].affectedCount | Should -Be 1
            $by['CL-008'].status | Should -Be 'notEvaluated' -Because 'SAM is not licensed in the profile'
            $by['CL-009'].status | Should -Be 'pass'
            $by['CL-010'].status | Should -Be 'fail' -Because 'federation is open to all domains'
            $by['CL-011'].status | Should -Be 'fail'
            $by['CL-012'].status | Should -Be 'pass' -Because 'guests are on but expire'
            $by['CL-013'].status | Should -Be 'pass'
            $by['CL-014'].status | Should -Be 'fail'
            $by['CL-014'].affected[0].name | Should -Be 'Org-wide app settings' -Because 'app centric management decides when its settings were read'
            $by['CL-014'].affected[0].detail | Should -Match 'of the 4 apps in the catalog, 2 are available to everyone, 1 to named users or groups, and 1 are blocked'
        }

        It 'passes CL-014 when third-party apps are off by default, and falls back to the permission policy without the new read' {
            $profilePath = Join-Path $script:Root 'profile.json'
            $copy = Join-Path $script:Root "acm-$([guid]::NewGuid().ToString('n'))"
            Copy-Item -LiteralPath $script:Folder -Destination $copy -Recurse
            ConvertTo-Json -InputObject @(@{ SettingName = 'GlobalApp'; SettingValue = 'None' }) | Set-Content -LiteralPath (Join-Path $copy 'teams-app-settings.json')
            InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
            @((Invoke-PostureChecks -Evidence $copy -Domain collaboration -ProfilePath $profilePath -PassThru).results | Where-Object id -eq 'CL-014')[0].status | Should -Be 'pass'

            Remove-Item -LiteralPath (Join-Path $copy 'teams-app-settings.json')
            ConvertTo-Json -InputObject @(@{ Identity = 'Global'; GlobalCatalogAppsType = 'AllowedAppList' }) | Set-Content -LiteralPath (Join-Path $copy 'teams-app-permission-policies.json')
            InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
            @((Invoke-PostureChecks -Evidence $copy -Domain collaboration -ProfilePath $profilePath -PassThru).results | Where-Object id -eq 'CL-014')[0].status | Should -Be 'pass' -Because 'an allow list in the global permission policy'
        }
    }

    Context 'not connected' {
        BeforeAll { $env:TKP_COLLAB_CONNECTED = '0' }

        It 'refuses when SharePoint was asked for by name, naming the connect command' {
            { Invoke-PostureCollection -Collector SharePoint -SkipCaSnapshot -OutputFolder (Join-Path $script:Root 'run2') } | Should -Throw '*Connect-PnPOnline*'
        }

        It 'never connects on its own' {
            Should -Invoke -ModuleName TenantKeep.Posture Invoke-PosturePnpCommand -Times 0 -Scope It
            Should -Invoke -ModuleName TenantKeep.Posture Invoke-PostureTeamsCommand -Times 0 -Scope It
        }
    }
}

Describe 'PnP and Teams entry points' {
    It 'accept read cmdlet names only' {
        InModuleScope TenantKeep.Posture {
            { Invoke-PosturePnpCommand -Name 'Set-PnPTenant' } | Should -Throw
            { Invoke-PostureTeamsCommand -Name 'Set-CsTenantFederationConfiguration' } | Should -Throw
            { Invoke-PostureTeamsCommand -Name 'Remove-Team' } | Should -Throw
            { Invoke-PostureTeamsCommand -Name 'Update-M365TeamsApp' } | Should -Throw
            { Invoke-PostureTeamsCommand -Name 'Update-M365UnifiedTenantSettings' } | Should -Throw
            { Invoke-PostureTeamsCommand -Name 'Get-AllM365TeamsAppsAndMore' } | Should -Throw
        }
    }
}
