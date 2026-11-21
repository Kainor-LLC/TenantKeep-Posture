# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-tier-$([guid]::NewGuid().ToString('n'))"
    $script:Ev = Initialize-CollectionFixture -Root (Join-Path $script:Root 'evidence')
    Copy-Item -Path (Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot' '*.json') -Destination $script:Ev
}

AfterAll {
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
}

Describe 'What a report shows without the full tier' {
    It 'shows the Conditional Access domain only: no charts, no administrators, no headline figures, no licensing, inventory limited to CA' {
        InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
        $free = New-PostureReport -Evidence $script:Ev -OutputPath (Join-Path $script:Root 'free') -PassThru 6>$null 3>$null
        $m = $free.Report
        @($m.charts.Keys).Count | Should -Be 0
        @($m.admins).Count | Should -Be 0
        $m.licenseAdvice | Should -BeNullOrEmpty
        $m.copilot | Should -BeNullOrEmpty
        @($m.headline.Values | Where-Object { $null -ne $_ }).Count | Should -Be 0
        @($m.inventory | Where-Object { $_.domain -ne 'ca' }).Count | Should -Be 0
        @($m.results | Where-Object { $_.domain -ne 'ca' -and $_.status -notin 'notEvaluated', 'notApplicable' }).Count | Should -Be 0

        InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
        $full = New-PostureReport -Evidence $script:Ev -OutputPath (Join-Path $script:Root 'full') -PassThru 6>$null
        @($full.Report.charts.Keys).Count | Should -BeGreaterThan 0 -Because 'the same evidence draws charts with the full tier'
        @($full.Report.admins).Count | Should -BeGreaterThan 0
    }
}
