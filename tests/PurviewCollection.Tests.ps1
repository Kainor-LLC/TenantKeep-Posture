# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
    InModuleScope Tenantkeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-purview-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $env:TKP_PV_FIXTURE = (Join-Path $PSScriptRoot 'Fixtures' 'PurviewFixture.ps1')

    Mock -ModuleName Tenantkeep.Posture Get-MgContext { [pscustomobject]@{ TenantId = 'tenant-guid'; Account = 'reader@contoso.example'; AuthType = 'Delegated'; Scopes = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All') } }
    Mock -ModuleName Tenantkeep.Posture Start-Transcript { }
    Mock -ModuleName Tenantkeep.Posture Stop-Transcript { }
    Mock -ModuleName Tenantkeep.Posture Test-PosturePurviewSession { $env:TKP_PV_CONNECTED -eq '1' }
    Mock -ModuleName Tenantkeep.Posture Invoke-PostureExoCommand { . $env:TKP_PV_FIXTURE; @(Get-PurviewFixtureObject -Name $Name) }
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
    Remove-Item Env:TKP_PV_FIXTURE, Env:TKP_PV_CONNECTED -ErrorAction SilentlyContinue
}

Describe 'Invoke-PostureCollection -Collector Purview' {
    Context 'connected' {
        BeforeAll {
            $env:TKP_PV_CONNECTED = '1'
            $script:Folder = Join-Path $script:Root 'run1'
            $script:Result = Invoke-PostureCollection -Collector Purview -SkipCaSnapshot -OutputFolder $script:Folder -PassThru -WarningAction SilentlyContinue
            $script:Read = { param([string] $n) Get-Content -Raw (Join-Path $script:Folder "$n.json") | ConvertFrom-Json -AsHashtable }
            '{ "UnifiedAuditLogIngestionEnabled": true }' | Set-Content -LiteralPath (Join-Path $script:Folder 'exo-01-audit-config.json')
            '{ "Total": 10, "Labeled": 0 }' | Set-Content -LiteralPath (Join-Path $script:Folder 'spo-sites-summary.json')
        }

        It 'writes the A.2 pv-* files' {
            foreach ($n in 'pv-01-sensitivity-labels', 'pv-01-label-policies', 'pv-01-autolabel-policies', 'pv-02-dlp-policies', 'pv-02-dlp-rules', 'pv-03-retention-policies', 'pv-03-retention-rules', 'pv-03-retention-labels', 'pv-04-insider-risk-policies', 'pv-05-audit-retention-policies', 'pv-06-ediscovery-cases', 'pv-07-alert-policies', 'pv-08-role-groups') {
                Join-Path $script:Folder "$n.json" | Should -Exist
            }
            Join-Path $script:Folder 'pv-02-dlp-policies.csv' | Should -Exist
            $script:Result.Collectors | Should -Be @('Purview')
            $script:Result.Errors.Count | Should -Be 0
            @(& $script:Read 'pv-01-label-policies')[0].ExchangeLocation | Should -Be @('All')
        }

        It 'feeds the purview checks' {
            $profilePath = Join-Path $script:Root 'profile.json'
            '{ "version": 1, "licenses": ["E5"] }' | Set-Content -LiteralPath $profilePath
            $run = Invoke-PostureChecks -Evidence $script:Folder -Domain purview -ProfilePath $profilePath -PassThru
            $by = @{}; foreach ($r in $run.results) { $by[$r.id] = $r }
            $by['PV-001'].status | Should -Be 'pass' -Because $by['PV-001'].reason
            $by['PV-002'].status | Should -Be 'pass'
            $by['PV-003'].status | Should -Be 'fail' -Because 'the auto-labeling policy is in simulation'
            $by['PV-004'].status | Should -Be 'fail' -Because 'container labels exist but no site is labeled'
            $by['PV-005'].status | Should -Be 'fail'
            @($by['PV-005'].affected | ForEach-Object { $_.name }) | Should -Be @('Teams', 'EndpointDevices') -Because 'the Teams policy is in test mode and E5 expects Endpoint DLP'
            $by['PV-006'].status | Should -Be 'fail' -Because 'retention covers Exchange only'
            $by['PV-007'].status | Should -Be 'fail'
            $by['PV-008'].status | Should -Be 'fail' -Because 'six distinct members across the two admin groups'
            $by['PV-008'].affectedCount | Should -Be 6
        }
    }

    Context 'not connected' {
        It 'refuses when Purview was asked for by name' {
            $env:TKP_PV_CONNECTED = '0'
            { Invoke-PostureCollection -Collector Purview -SkipCaSnapshot -OutputFolder (Join-Path $script:Root 'run2') } | Should -Throw '*Connect-IPPSSession*'
        }
    }
}
