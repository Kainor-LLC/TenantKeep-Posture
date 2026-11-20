# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-getex-$([guid]::NewGuid().ToString('n'))"
    $script:Client = Join-Path $script:Root 'contoso'
    New-Item -ItemType Directory -Path $script:Client -Force | Out-Null
    $list = @(
        @{ check = 'EM-016'; object = 'payroll@contoso.example'; justification = 'Payroll provider'; owner = 'IT'; approver = 'CFO'; expires = '2099-06-30' }
        @{ check = 'CA-006'; object = $null; justification = 'Pilot'; owner = 'IT'; approver = 'CISO'; expires = '2020-01-01' }
    )
    @{ exceptions = $list } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $script:Client 'exceptions.json')
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Get-PostureException' {
    It 'lists every exception with the catalog title and the expiry state' {
        $all = @(Get-PostureException -Client $script:Client)
        $all.Count | Should -Be 2
        $em = $all | Where-Object Check -eq 'EM-016'
        $em.Title | Should -Not -BeNullOrEmpty
        $em.Expired | Should -BeFalse
        ($all | Where-Object Check -eq 'CA-006').Expired | Should -BeTrue
    }

    It 'filters by check and by expired' {
        @(Get-PostureException -Client $script:Client -Check 'EM-016').Count | Should -Be 1
        @(Get-PostureException -Client $script:Client -Expired).Check | Should -Be @('CA-006')
    }

    It 'returns nothing for a client folder without exceptions.json' {
        $empty = Join-Path $script:Root 'empty'; New-Item -ItemType Directory -Path $empty | Out-Null
        @(Get-PostureException -Client $empty).Count | Should -Be 0
    }
}
