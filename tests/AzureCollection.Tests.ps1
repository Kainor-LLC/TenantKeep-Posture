# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
    . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-azure-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $env:TKP_AZ_FIXTURE = (Join-Path $PSScriptRoot 'Fixtures' 'AzureFixture.ps1')

    Mock -ModuleName Tenantkeep.Posture Get-MgContext { [pscustomobject]@{ TenantId = 'tenant-guid'; Account = 'reader@contoso.example'; AuthType = 'Delegated'; Scopes = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All') } }
    Mock -ModuleName Tenantkeep.Posture Start-Transcript { }
    Mock -ModuleName Tenantkeep.Posture Stop-Transcript { }
    Mock -ModuleName Tenantkeep.Posture Test-PostureAzureSession { $env:TKP_AZ_CONNECTED -eq '1' }
    Mock -ModuleName Tenantkeep.Posture Invoke-PostureAzureQuery { . $env:TKP_AZ_FIXTURE; @(Get-AzureFixtureQuery -Query $Query) }
    Mock -ModuleName Tenantkeep.Posture Invoke-PostureAzureRequest { . $env:TKP_AZ_FIXTURE; @(Get-AzureFixtureRequest -Path $Path) }
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
    Remove-Item Env:TKP_AZ_FIXTURE, Env:TKP_AZ_CONNECTED -ErrorAction SilentlyContinue
}

Describe 'Invoke-PostureCollection -Collector Azure' {
    Context 'connected' {
        BeforeAll {
            $env:TKP_AZ_CONNECTED = '1'
            $script:Folder = Join-Path $script:Root 'run1'
            $script:Result = Invoke-PostureCollection -Collector Azure -SkipCaSnapshot -OutputFolder $script:Folder -PassThru -WarningAction SilentlyContinue
            $script:Read = { param([string] $n) Get-Content -Raw (Join-Path $script:Folder "$n.json") | ConvertFrom-Json -AsHashtable }
            # Identity evidence for the joins and the CA snapshot for the management plane policy.
            $fx = Initialize-CollectionFixture -Root (Join-Path $script:Root 'a1')
            foreach ($f in '06-users', '07-groups', '10-service-principals') { if (Test-Path (Join-Path $fx "$f.json")) { Copy-Item (Join-Path $fx "$f.json") $script:Folder } }
            Copy-Item (Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot' 'policies.json') $script:Folder
        }

        It 'writes the az-* files and records the subscriptions' {
            foreach ($n in 'az-01-subscriptions', 'az-01-management-groups', 'az-02-defender-pricings', 'az-02-security-contacts', 'az-02-secure-scores', 'az-02-assessments-summary', 'az-02-assessments-top', 'az-03-policy-assignments', 'az-04-activity-log-exports', 'az-05-role-definitions-custom', 'az-05-role-assignments', 'az-05-classic-administrators', 'az-06-resources-by-type', 'az-06-resources-summary', 'az-06-locks', 'az-06-vaults', 'az-07-keyvaults', 'az-07-storage', 'az-07-sql-servers', 'az-08-entra-connect-health', 'az-09-entra-diagnostic-settings') {
                Join-Path $script:Folder "$n.json" | Should -Exist
            }
            $script:Result.Collectors | Should -Be @('Azure')
            $script:Result.Errors.Count | Should -Be 0
            @(& $script:Read 'az-01-subscriptions' | Where-Object { $_.AtTenantRoot }).Name | Should -Be 'Sandbox'
            @(& $script:Read 'az-03-policy-assignments' | Where-Object { $_.IsMcsb }).Count | Should -Be 1
        }

        It 'resolves role names, scope levels and subscription ids on the assignments' {
            $ra = @(& $script:Read 'az-05-role-assignments')
            @($ra | Where-Object { $_.Id -eq 'ra2' })[0].ScopeLevel | Should -Be 'root'
            @($ra | Where-Object { $_.Id -eq 'ra4' })[0].RoleName | Should -Be 'Contributor'
            @($ra | Where-Object { $_.Id -eq 'ra6' })[0].ScopeLevel | Should -Be 'resource'
            @($ra | Where-Object { $_.Id -eq 'ra6' })[0].SubscriptionId | Should -Be 'sub-1'
            @(& $script:Read 'az-05-role-definitions-custom')[0].Wildcard | Should -BeTrue
        }

        It 'summarises hygiene and parses the Entra diagnostic categories' {
            $s = & $script:Read 'az-06-resources-summary'
            $s.UnattachedDisks | Should -Be 2
            $s.EmptyResourceGroups | Should -Be 0
            @(& $script:Read 'az-09-entra-diagnostic-settings')[0].Categories | Should -Be @('AuditLogs', 'SignInLogs')
        }

        It 'feeds the azure checks and the identity and operations checks that wait on Azure' {
            $profilePath = Join-Path $script:Root 'profile.json'
            '{ "version": 1, "azure": "workloads", "identityModel": "hybrid-connect", "licenses": ["E5", "P1", "P2"] }' | Set-Content -LiteralPath $profilePath
            $run = Invoke-PostureChecks -Evidence $script:Folder -Domain azure, identity, operations -ProfilePath $profilePath -PassThru
            $by = @{}; foreach ($r in $run.results) { $by[$r.id] = $r }
            $by['AZ-001'].status | Should -Be 'fail'
            $by['AZ-002'].status | Should -Be 'fail' -Because 'Sandbox sits outside the landing zones group'
            $by['AZ-003'].status | Should -Be 'fail'
            @($by['AZ-003'].affected | ForEach-Object { $_.name }) | Should -Be @('Prod (sub-1): StorageAccounts', 'Sandbox (sub-2): Arm')
            $by['AZ-004'].status | Should -Be 'notEvaluated'
            $by['AZ-005'].status | Should -Be 'fail'
            $by['AZ-006'].status | Should -Be 'fail'
            $by['AZ-007'].status | Should -Be 'fail' -Because 'the Recovery Services vault has no lock'
            $by['AZ-009'].status | Should -Be 'fail' -Because '75% tagged'
            $by['AZ-010'].affectedCount | Should -Be 2
            $by['AZ-012'].status | Should -Be 'fail' -Because 'an Owner sits at the root'
            $by['AZ-014'].status | Should -Be 'fail'
            $by['AZ-015'].status | Should -Be 'fail'
            $by['AZ-016'].status | Should -Be 'fail'
            $by['AZ-017'].status | Should -Be 'fail'
            $by['AZ-018'].status | Should -Be 'pass'
            $by['AZ-019'].affectedCount | Should -Be 1
            $by['AZ-020'].affectedCount | Should -Be 1
            $by['AZ-021'].status | Should -Be 'notEvaluated'
            $by['AZ-022'].status | Should -Be 'pass' -Because ('the sample has an all-apps MFA policy: ' + $by['AZ-022'].reason)
            $by['ID-014'].status | Should -Be 'pass' -Because 'sign-in and audit logs go to a workspace'
            $by['OP-007'].status | Should -Be 'pass'
        }
    }

    Context 'not connected' {
        It 'refuses when Azure was asked for by name' {
            $env:TKP_AZ_CONNECTED = '0'
            { Invoke-PostureCollection -Collector Azure -SkipCaSnapshot -OutputFolder (Join-Path $script:Root 'run2') } | Should -Throw '*Connect-AzAccount*'
        }
    }
}
