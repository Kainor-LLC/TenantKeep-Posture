# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Sessions the admin opened (Invoke-PostureCollection) must be in the Graph session's tenant. Az saves its context
# between sessions and Exchange keeps several connections, so on a machine that works in two tenants the open session
# can belong to the other one.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    # Stand-ins so the session checks find the commands where Az and ExchangeOnlineManagement are not installed.
    function global:Get-AzContext { }
    function global:Invoke-AzRestMethod { }
    function global:Get-ConnectionInformation { }
}

AfterAll {
    Remove-Item Function:\global:Get-AzContext, Function:\global:Invoke-AzRestMethod, Function:\global:Get-ConnectionInformation -ErrorAction SilentlyContinue
}

Describe 'Session tenant checks' {
    It 'accepts an Azure context in the run tenant and refuses one saved from another tenant' {
        Mock -ModuleName TenantKeep.Posture Get-AzContext { [pscustomobject]@{ Account = 'reader@contoso.example'; Tenant = [pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' } } }
        Mock -ModuleName TenantKeep.Posture Invoke-AzRestMethod { [pscustomobject]@{ StatusCode = 200 } }
        InModuleScope TenantKeep.Posture {
            Test-PostureAzureSession -TenantId '11111111-1111-1111-1111-111111111111' | Should -BeTrue
            Test-PostureAzureSession -TenantId '22222222-2222-2222-2222-222222222222' | Should -BeFalse
            Test-PostureAzureSession | Should -BeTrue -Because 'without a tenant to match, any working context counts'
        }
    }

    It 'refuses Exchange and Purview when any connected session is in another tenant' {
        Mock -ModuleName TenantKeep.Posture Get-ConnectionInformation {
            [pscustomobject]@{ State = 'Connected'; ConnectionUri = 'https://outlook.office365.com'; TenantID = '11111111-1111-1111-1111-111111111111' }
            [pscustomobject]@{ State = 'Connected'; ConnectionUri = 'https://ps.compliance.protection.outlook.com'; TenantID = '11111111-1111-1111-1111-111111111111' }
        }
        InModuleScope TenantKeep.Posture {
            Test-PostureExoSession -TenantId '11111111-1111-1111-1111-111111111111' | Should -BeTrue
            Test-PosturePurviewSession -TenantId '11111111-1111-1111-1111-111111111111' | Should -BeTrue
            Test-PostureExoSession -TenantId '22222222-2222-2222-2222-222222222222' | Should -BeFalse
            Test-PosturePurviewSession -TenantId '22222222-2222-2222-2222-222222222222' | Should -BeFalse
        }
        Mock -ModuleName TenantKeep.Posture Get-ConnectionInformation {
            [pscustomobject]@{ State = 'Connected'; ConnectionUri = 'https://outlook.office365.com'; TenantID = '11111111-1111-1111-1111-111111111111' }
            [pscustomobject]@{ State = 'Connected'; ConnectionUri = 'https://outlook.office365.com'; TenantID = '22222222-2222-2222-2222-222222222222' }
        }
        InModuleScope TenantKeep.Posture { Test-PostureExoSession -TenantId '11111111-1111-1111-1111-111111111111' | Should -BeFalse -Because 'a second session in another tenant could answer the commands' }
    }

    It 'pins the module''s own Azure sign-in to the process' {
        $src = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'Private' 'Connect-PostureService.ps1')
        $src | Should -Match 'Connect-AzAccount -AccessToken [^\r\n]*-Scope Process'
    }
}
