# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    . (Join-Path $PSScriptRoot 'Fixtures' 'CheckEngineFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-catalog-$([guid]::NewGuid().ToString('n'))"
    $script:Fx = Initialize-CheckEngineFixture -Root $script:Root
    $script:Evidence = Join-Path $script:Root 'evidence'
    New-Item -ItemType Directory -Path $script:Evidence | Out-Null
    # Point the catalog loader at the fixture and give the engine the fixture provider.
    Mock -ModuleName TenantKeep.Posture Get-PostureDataFolder { param($Name) if ($Name -eq 'checks') { $env:TKP_TEST_CHECKS } elseif ($Name -eq 'baselines') { $env:TKP_TEST_BASELINES } }
    $env:TKP_TEST_CHECKS = $script:Fx.Checks
    $env:TKP_TEST_BASELINES = $script:Fx.Baselines
    # The engine looks up Get-Posture<Domain>Fact; define the fixture provider as that function inside the module.
    InModuleScope TenantKeep.Posture -Parameters @{ P = $script:Fx.Provider } { Set-Item -Path 'function:script:Get-PostureTestFact' -Value $P }
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
    Remove-Item Env:TKP_TEST_CHECKS, Env:TKP_TEST_BASELINES -ErrorAction SilentlyContinue
}

Describe 'Get-PostureCheckCatalog' {
    It 'lists checks with id, domain, severity and license, filtered by domain or id' {
        $all = @(Get-PostureCheckCatalog)
        $all.Count | Should -Be 7
        $all[0].CatalogVersion | Should -Be 'test.1'
        @(Get-PostureCheckCatalog -Domain test).Count | Should -Be 6
        $one = Get-PostureCheckCatalog -Id TS-002 -Full
        $one.License | Should -Be @('P2')
        $one.Pass | Should -Be 'facts.enabled'
        $one.Narrative | Should -Be 'n'
        (Get-PostureCheckCatalog -Id TS-002).PSObject.Properties.Name | Should -Not -Contain 'Pass'
    }
}
