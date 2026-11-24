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
            foreach ($n in 'spo-tenant-settings', 'spo-sites', 'spo-sites-summary', 'teams-federation', 'teams-client-config', 'teams-meeting-policy-global', 'teams-live-event-policy-global', 'teams-external-access', 'teams-app-permission-policies', 'teams-guest-messaging', 'teams-app-settings', 'teams-app-availability') {
                Join-Path $script:Folder "$n.json" | Should -Exist
            }
            Join-Path $script:Folder 'spo-sites.csv' | Should -Exist
            $script:Result.Collectors | Should -Be @('SharePoint', 'Teams')
            $script:Result.Errors.Count | Should -Be 0
            (& $script:Read 'teams-live-event-policy-global').BroadcastRecordingMode | Should -Be 'AlwaysEnabled' -Because 'CL-028 reads the live events policy'
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

    Context 'the Teams app reads under a sign-in with access tokens' {
        # Seen on a live run: the Teams module wants a token for substrate.office.com, a session opened with access
        # tokens has none, and the module says so with a missing dictionary key.
        BeforeAll {
            $env:TKP_COLLAB_CONNECTED = '1'
            Mock -ModuleName TenantKeep.Posture Invoke-PostureTeamsCommand -ParameterFilter { $Name -in 'Get-M365UnifiedTenantSettings', 'Get-AllM365TeamsApps' } { throw "The given key 'https://substrate.office.com' was not present in the dictionary." }
            $script:NoApps = Join-Path $script:Root 'teams-no-app-reads'
            $script:NoAppsResult = Invoke-PostureCollection -Collector Teams -SkipCaSnapshot -OutputFolder $script:NoApps -PassThru -WarningAction SilentlyContinue
        }

        It 'says in words what could not be read, and how a run does read it' {
            $lines = @($script:NoAppsResult.Errors | Where-Object { $_ -match '^Teams (org-wide app settings|app availability) :: ' })
            $lines.Count | Should -Be 2
            $lines | ForEach-Object { $_ | Should -Match ' :: Not readable with this sign-in: the Teams module reads Get-(M365UnifiedTenantSettings|AllM365TeamsApps) with a Microsoft 365 token' }
            Join-Path $script:NoApps 'teams-app-settings.json' | Should -Not -Exist
            Join-Path $script:NoApps 'teams-app-permission-policies.json' | Should -Exist -Because 'the other Teams reads are not touched'
            InModuleScope TenantKeep.Posture -Parameters @{ folder = $script:NoApps } {
                param($folder)
                $failure = @(Read-PostureRunFailure -Folder $folder | Where-Object { [string]$_['step'] -eq 'Teams org-wide app settings' })[0]
                $failure['cause'] | Should -Be 'notReadable'
                $advice = Get-PostureFailureAdvice -Failure $failure
                $advice | Should -Match 'collect Teams again with: Resume-PostureRun -Collector Teams -TeamsAppSignIn\.'
                $advice | Should -Not -Match 'Nothing to grant' -Because 'the run was not asked for this read, and asking for it is something to do'
            }
        }

        It 'gives CL-014 no answer instead of judging a moved tenant on the old permission policy' {
            $profilePath = Join-Path $script:Root 'profile.json'
            '{ "version": 1, "externalCollaboration": "governed", "licenses": ["BusinessPremium", "P1"] }' | Set-Content -LiteralPath $profilePath
            InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
            $r = @((Invoke-PostureChecks -Evidence $script:NoApps -Domain collaboration -ProfilePath $profilePath -PassThru).results | Where-Object id -eq 'CL-014')[0]
            $r.status | Should -Be 'notEvaluated'
            $r.reason | Should -Match 'could not be read in this run'
        }
    }

    Context 'the Teams app reads with the Teams module''s own sign-in' {
        # Start-PostureRun -TeamsAppSignIn: the first read that meets the missing token signs the Teams module in by
        # itself, once, and both reads are made with that session.
        BeforeAll { $env:TKP_COLLAB_CONNECTED = '1' }
        AfterEach { InModuleScope TenantKeep.Posture { $script:PostureTeamsAppSignIn = $false; $script:PostureTeamsOwnSession = $false; $script:PostureTeamsOwnSessionRefused = $null } }

        It 'signs in once and reads both' {
            InModuleScope TenantKeep.Posture {
                $script:PostureTeamsAppSignIn = $true; $script:PostureTeamsOwnSession = $false
                Mock Connect-PostureTeamsOwnSession { $script:PostureTeamsOwnSession = $true }
                Mock Invoke-PostureTeamsCommand -ParameterFilter { $Name -in 'Get-M365UnifiedTenantSettings', 'Get-AllM365TeamsApps' } {
                    if (-not $script:PostureTeamsOwnSession) { throw "The given key 'https://substrate.office.com' was not present in the dictionary." }
                    . $env:TKP_COLLAB_FIXTURE; @(Get-CollaborationFixtureObject -Name $Name)
                }
            }
            $folder = Join-Path $script:Root 'teams-own-sign-in'
            $r = Invoke-PostureCollection -Collector Teams -SkipCaSnapshot -OutputFolder $folder -PassThru -WarningAction SilentlyContinue 6>$null
            @($r.Errors | Where-Object { $_ -match '^Teams (org-wide app settings|app availability) :: ' }) | Should -BeNullOrEmpty
            Join-Path $folder 'teams-app-settings.json' | Should -Exist
            Join-Path $folder 'teams-app-availability.json' | Should -Exist
            Should -Invoke -ModuleName TenantKeep.Posture Connect-PostureTeamsOwnSession -Times 1 -Exactly -Scope It
        }

        It 'passes on what the sign-in said: not completed, which a second attempt can fix' {
            InModuleScope TenantKeep.Posture {
                $script:PostureTeamsAppSignIn = $true; $script:PostureTeamsOwnSession = $false
                Mock Connect-PostureTeamsOwnSession { throw 'The Teams sign-in for the app settings was not completed: The code expired before anyone entered it. If the code ran out, run again with -TeamsAppSignIn and enter it.' }
                Mock Invoke-PostureTeamsCommand -ParameterFilter { $Name -in 'Get-M365UnifiedTenantSettings', 'Get-AllM365TeamsApps' } { throw "The given key 'https://substrate.office.com' was not present in the dictionary." }
            }
            $folder = Join-Path $script:Root 'teams-own-sign-in-failed'
            $r = Invoke-PostureCollection -Collector Teams -SkipCaSnapshot -OutputFolder $folder -PassThru -WarningAction SilentlyContinue 6>$null
            $lines = @($r.Errors | Where-Object { $_ -match '^Teams org-wide app settings :: ' })
            $lines.Count | Should -Be 1
            $lines[0] | Should -Match ':: The Teams sign-in for the app settings was not completed: The code expired before anyone entered it\. If the code ran out, run again with -TeamsAppSignIn'
            InModuleScope TenantKeep.Posture -Parameters @{ text = ($lines[0] -replace '^[^:]+ :: ', '') } { param($text) Get-PostureFailureCause -Message $text } | Should -Not -Be 'notReadable' -Because 'entering the code next time fixes it'
        }

        It 'says a Conditional Access refusal as a read this sign-in cannot make, on both steps, with nothing to collect again' {
            InModuleScope TenantKeep.Posture {
                $script:PostureTeamsAppSignIn = $true; $script:PostureTeamsOwnSession = $false
                Mock Connect-PostureTeamsOwnSession { throw "Not readable with this sign-in: Conditional Access in this tenant refused the Teams module's own sign-in, which outside Windows can only be made with a device code. That is the tenant's policy working, and nothing in the run changes it." }
                Mock Invoke-PostureTeamsCommand -ParameterFilter { $Name -in 'Get-M365UnifiedTenantSettings', 'Get-AllM365TeamsApps' } { throw "The given key 'https://substrate.office.com' was not present in the dictionary." }
            }
            $folder = Join-Path $script:Root 'teams-own-sign-in-refused'
            $r = Invoke-PostureCollection -Collector Teams -SkipCaSnapshot -OutputFolder $folder -PassThru -WarningAction SilentlyContinue 6>$null
            $lines = @($r.Errors | Where-Object { $_ -match '^Teams (org-wide app settings|app availability) :: ' })
            $lines.Count | Should -Be 2
            foreach ($line in $lines) {
                $line | Should -Match ':: Not readable with this sign-in: Conditional Access in this tenant refused'
                $line | Should -Not -Match 'Run again|enter the code'
                InModuleScope TenantKeep.Posture -Parameters @{ text = ($line -replace '^[^:]+ :: ', '') } { param($text) Get-PostureFailureCause -Message $text } | Should -Be 'notReadable'
            }
        }

        It 'asks once when Conditional Access refuses the device code, remembers the answer, and puts the run''s session back' {
            InModuleScope TenantKeep.Posture {
                $script:PostureSession = @{ tenantId = '11111111-1111-1111-1111-111111111111'; account = 'admin@contoso.example'; tokens = @{} }
                $script:Asked = 0; $script:Closed = 0
                Mock Test-PostureTeamsBrowserSignIn { $false }
                Mock Connect-PostureService { }
                Set-Item -Path Function:\Disconnect-MicrosoftTeams -Value { $script:Closed++ }
                # The message the Teams module passes on from the sign-in service (seen live 2026-11-22 as error 53003).
                Set-Item -Path Function:\Connect-MicrosoftTeams -Value { param($TenantId, $AccountId, [switch] $UseDeviceAuthentication) $script:Asked++; throw "AADSTS53003: Access has been blocked by Conditional Access policies. The access policy does not allow token issuance.`r`nTrace ID: 00000000-0000-0000-0000-000000000000" }
                try {
                    $first = $null; try { Connect-PostureTeamsOwnSession 6>$null } catch { $first = [string]$_.Exception.Message }
                    $first | Should -Match '^Not readable with this sign-in: Conditional Access in this tenant refused the Teams module''s own sign-in, which outside Windows can only be made with a device code\.'
                    $first | Should -Match 'On Windows the Teams module signs in through the browser instead'
                    $first | Should -Not -Match 'Trace ID|Run again'
                    Get-PostureFailureCause -Message $first | Should -Be 'notReadable'
                    $second = $null; try { Connect-PostureTeamsOwnSession 6>$null } catch { $second = [string]$_.Exception.Message }
                    $second | Should -Be $first
                    $script:Asked | Should -Be 1 -Because 'the second read must not prompt again'
                    Should -Invoke Connect-PostureService -Times 1 -Exactly -ParameterFilter { $Name -eq 'teams' }
                    $script:PostureTeamsOwnSession | Should -BeFalse
                }
                finally { $script:PostureSession = $null; $script:PostureTeamsOwnSessionRefused = $null; Remove-Item Function:\Connect-MicrosoftTeams, Function:\Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue }
            }
        }

        It 'says what else it could be when the code simply was not entered' {
            InModuleScope TenantKeep.Posture {
                $script:PostureSession = @{ tenantId = '11111111-1111-1111-1111-111111111111'; account = 'admin@contoso.example'; tokens = @{} }
                Mock Test-PostureTeamsBrowserSignIn { $false }
                Mock Connect-PostureService { }
                Set-Item -Path Function:\Disconnect-MicrosoftTeams -Value { }
                Set-Item -Path Function:\Connect-MicrosoftTeams -Value { param($TenantId, $AccountId, [switch] $UseDeviceAuthentication) throw 'Verification code expired before contacting the server.' }
                try {
                    $said = $null; try { Connect-PostureTeamsOwnSession 6>$null } catch { $said = [string]$_.Exception.Message }
                    $said | Should -Match '^The Teams sign-in for the app settings was not completed: Verification code expired before contacting the server\. If the code ran out, run again with -TeamsAppSignIn and enter it\.'
                    $said | Should -Match 'Conditional Access blocks device code sign-in in this tenant and running again will say the same'
                    Get-PostureFailureCause -Message $said | Should -Not -Be 'notReadable'
                }
                finally { $script:PostureSession = $null; $script:PostureTeamsOwnSessionRefused = $null; Remove-Item Function:\Connect-MicrosoftTeams, Function:\Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue }
            }
        }

        It 'signs in through the browser, as the run''s account, where the Teams module can (Windows), and by device code elsewhere' {
            InModuleScope TenantKeep.Posture {
                $script:PostureSession = @{ tenantId = '11111111-1111-1111-1111-111111111111'; account = 'admin@contoso.example'; tokens = @{} }
                $script:Seen = [System.Collections.Generic.List[hashtable]]::new()
                Set-Item -Path Function:\Disconnect-MicrosoftTeams -Value { }
                Set-Item -Path Function:\Connect-MicrosoftTeams -Value { param($TenantId, $AccountId, [switch] $UseDeviceAuthentication) $script:Seen.Add(@{ tenant = $TenantId; account = $AccountId; device = [bool]$UseDeviceAuthentication }); [pscustomobject]@{ TenantId = $TenantId; Account = 'admin@contoso.example' } }
                try {
                    Mock Test-PostureTeamsBrowserSignIn { $true }
                    Connect-PostureTeamsOwnSession 6>$null
                    $script:PostureTeamsOwnSession = $false
                    Mock Test-PostureTeamsBrowserSignIn { $false }
                    Connect-PostureTeamsOwnSession 6>$null
                    $script:Seen[0]['device'] | Should -BeFalse
                    $script:Seen[0]['account'] | Should -Be 'admin@contoso.example'
                    $script:Seen[0]['tenant'] | Should -Be '11111111-1111-1111-1111-111111111111'
                    $script:Seen[1]['device'] | Should -BeTrue
                    $script:Seen[1]['account'] | Should -BeNullOrEmpty
                }
                finally { $script:PostureSession = $null; $script:PostureTeamsOwnSession = $false; $script:PostureTeamsOwnSessionRefused = $null; Remove-Item Function:\Connect-MicrosoftTeams, Function:\Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue }
            }
        }

        It 'refuses a Teams session of another tenant or another account, and closes it' {
            InModuleScope TenantKeep.Posture {
                $script:PostureSession = @{ tenantId = '11111111-1111-1111-1111-111111111111'; account = 'admin@contoso.example'; tokens = @{} }
                $script:Closed = 0
                Mock Test-PostureTeamsBrowserSignIn { $false }
                Mock Connect-PostureService { }
                # Stand-ins for the Teams module's two cmdlets, set by name (the module is not installed where the tests run).
                Set-Item -Path Function:\Disconnect-MicrosoftTeams -Value { $script:Closed++ }
                Set-Item -Path Function:\Connect-MicrosoftTeams -Value { param($TenantId, [switch] $UseDeviceAuthentication) [pscustomobject]@{ TenantId = $TenantId; Account = 'someone.else@contoso.example' } }
                try {
                    { Connect-PostureTeamsOwnSession 6>$null } | Should -Throw '*was someone.else@contoso.example, not the run''s*'
                    $script:Closed | Should -Be 2 -Because 'the session before it and the mismatched one'
                    $script:PostureTeamsOwnSession | Should -BeFalse
                    Should -Invoke Connect-PostureService -Times 1 -Exactly -ParameterFilter { $Name -eq 'teams' }
                    Set-Item -Path Function:\Connect-MicrosoftTeams -Value { param($TenantId, [switch] $UseDeviceAuthentication) [pscustomobject]@{ TenantId = $TenantId; Account = 'admin@contoso.example' } }
                    Connect-PostureTeamsOwnSession 6>$null
                    $script:PostureTeamsOwnSession | Should -BeTrue
                }
                finally { $script:PostureSession = $null; $script:PostureTeamsOwnSession = $false; $script:PostureTeamsOwnSessionRefused = $null; Remove-Item Function:\Connect-MicrosoftTeams, Function:\Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue }
            }
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
