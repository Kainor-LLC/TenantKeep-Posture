# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    . (Join-Path $PSScriptRoot 'Fixtures' 'ClientRunFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-rmex-$([guid]::NewGuid().ToString('n'))"
    $script:F = Initialize-ClientRunFixture -Root $script:Root
    $script:ExPath = Join-Path $script:F.Client 'exceptions.json'
    Mock Write-Host {} -ModuleName TenantKeep.Posture
    $script:Remaining = { @((Get-Content -Raw $script:ExPath | ConvertFrom-Json -AsHashtable).exceptions) }
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Remove-PostureException' {
    BeforeEach {
        $list = @(
            @{ check = 'ID-004'; object = 'a@contoso.example'; justification = 'j'; owner = 'o'; approver = 'a'; expires = '2099-01-01' }
            @{ check = 'ID-004'; object = 'b@contoso.example'; justification = 'j'; owner = 'o'; approver = 'a'; expires = '2099-01-01' }
            @{ check = 'ID-010'; object = $null; justification = 'j'; owner = 'o'; approver = 'a'; expires = '2020-01-01' }
        )
        @{ exceptions = $list } | ConvertTo-Json -Depth 5 | Set-Content $script:ExPath
    }

    It 'removes one object''s exception and keeps the rest' {
        $gone = @(Remove-PostureException -Client $script:F.Client -OutRoot $script:F.OutRoot -Check 'ID-004' -Object 'a@contoso.example' -NoReport -Confirm:$false)
        $gone.Count | Should -Be 1
        $left = & $script:Remaining
        $left.Count | Should -Be 2
        @($left | Where-Object { $_.object -eq 'b@contoso.example' }).Count | Should -Be 1
    }

    It 'removes every exception for a check when no object is given' {
        $null = Remove-PostureException -Client $script:F.Client -OutRoot $script:F.OutRoot -Check 'ID-004' -NoReport -Confirm:$false
        @(& $script:Remaining).check | Should -Be @('ID-010')
    }

    It 'removes only the expired ones with -Expired, and rebuilds the newest report' {
        $null = Remove-PostureException -Client $script:F.Client -OutRoot $script:F.OutRoot -Expired -Confirm:$false
        @(& $script:Remaining | Where-Object { $_.check -eq 'ID-010' }).Count | Should -Be 0
        @(& $script:Remaining).Count | Should -Be 2
        Join-Path $script:F.Run 'report.html' | Should -Exist
    }

    It 'leaves the file alone when nothing matches' {
        $before = Get-Content -Raw $script:ExPath
        $null = Remove-PostureException -Client $script:F.Client -OutRoot $script:F.OutRoot -Check 'EM-001' -NoReport -Confirm:$false
        Get-Content -Raw $script:ExPath | Should -Be $before
    }
}
