# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    . (Join-Path $PSScriptRoot 'Fixtures' 'CheckEngineFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-checks-$([guid]::NewGuid().ToString('n'))"
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

Describe 'Invoke-PostureChecks' {
    It 'writes checks.json into the evidence folder and returns its path' {
        $path = Invoke-PostureChecks -Evidence $script:Evidence
        $path | Should -Be (Join-Path $script:Evidence 'checks.json')
        $j = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $j.catalogVersion | Should -Be 'test.1'
        $j.baseline | Should -Be 'standard'
        $j.results.Count | Should -Be 7
        ($j.results | Where-Object id -eq 'TS-001').status | Should -Be 'fail'
        $j.moduleVersion | Should -Not -BeNullOrEmpty
    }

    It 'takes profile, exceptions, a baseline path and a domain filter' {
        $r = Invoke-PostureChecks -Evidence $script:Evidence -Baseline (Join-Path $script:Fx.Baselines 'strict.json') -Profile $script:Fx.Profile -Exceptions $script:Fx.Exceptions -Domain test -OutputPath (Join-Path $script:Root 'out') -PassThru
        @($r.results | ForEach-Object { $_.id }) | Should -Be @('TS-001', 'TS-006')
        ($r.results | Where-Object id -eq 'TS-006').status | Should -Be 'acceptedRisk'
        $r.profile | Should -Be $script:Fx.Profile
        Join-Path $script:Root 'out' 'checks.json' | Should -Exist
    }

    It 'rejects a missing evidence folder and an unknown baseline' {
        { Invoke-PostureChecks -Evidence (Join-Path $script:Root 'nope') } | Should -Throw '*Evidence folder not found*'
        { Invoke-PostureChecks -Evidence $script:Evidence -Baseline 'does-not-exist' } | Should -Throw '*Baseline not found*'
    }
}
