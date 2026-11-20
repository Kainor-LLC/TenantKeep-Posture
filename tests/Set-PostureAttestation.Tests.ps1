# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    . (Join-Path $PSScriptRoot 'Fixtures' 'ClientRunFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-attest-$([guid]::NewGuid().ToString('n'))"
    $script:F = Initialize-ClientRunFixture -Root $script:Root
    $script:ProfilePath = Join-Path $script:F.Client 'profile.json'
    Mock Write-Host {} -ModuleName TenantKeep.Posture
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Set-PostureAttestation' {
    It 'records today under attestations and keeps the rest of the profile' {
        $r = Set-PostureAttestation -Client $script:F.Client -OutRoot $script:F.OutRoot -Key dspmReviewedUtc -NoReport
        $r.Date | Should -Be ([datetime]::UtcNow.ToString('yyyy-MM-dd'))
        $p = Get-Content -Raw $script:ProfilePath | ConvertFrom-Json -AsHashtable
        Get-Content -Raw $script:ProfilePath | Should -Match "`"dspmReviewedUtc`": `"$([datetime]::UtcNow.ToString('yyyy-MM-dd'))T00:00:00Z`""
        $p.tenantId | Should -Be $script:F.TenantId
        $p.clientName | Should -Be 'Contoso'
    }

    It 'records a given past date and rebuilds the newest report' {
        $null = Set-PostureAttestation -Client $script:F.Client -OutRoot $script:F.OutRoot -Key copilotSettingsReviewedUtc -Date '2026-11-02'
        Get-Content -Raw $script:ProfilePath | Should -Match '"copilotSettingsReviewedUtc": "2026-11-02T00:00:00Z"'
        Join-Path $script:F.Run 'report.html' | Should -Exist
    }

    It 'refuses a key no check asks for and a future date' {
        { Set-PostureAttestation -Client $script:F.Client -Key notAKey -NoReport } | Should -Throw '*not an attestation*'
        { Set-PostureAttestation -Client $script:F.Client -Key dspmReviewedUtc -Date ([datetime]::UtcNow.AddDays(3)) -NoReport } | Should -Throw '*in the future*'
    }
}
