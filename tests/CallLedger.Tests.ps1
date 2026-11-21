# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:NewRun = { param([string] $Root) foreach ($p in 'evidence', 'errors', 'logs') { New-Item -ItemType Directory -Path (Join-Path $Root $p) -Force | Out-Null }; $Root }
}

Describe 'The call ledger' {
    BeforeEach { InModuleScope TenantKeep.Posture { $script:PostureCallLedger.Clear() } }

    It 'keeps tenant names out of the targets: no host, query, ids or accounts' {
        InModuleScope TenantKeep.Posture {
            ConvertTo-PostureCallTarget -Target 'https://graph.microsoft.com/v1.0/users/0b1c2d3e-0000-4000-8000-000000000001/memberOf?$select=id' | Should -Be 'v1.0/users/{id}/memberOf'
            ConvertTo-PostureCallTarget -Target 'https://graph.microsoft.com/beta/users/jane.doe@contoso.example/authentication/methods' | Should -Be 'beta/users/{user}/authentication/methods'
            ConvertTo-PostureCallTarget -Target '/subscriptions/0b1c2d3e-0000-4000-8000-000000000001/providers/Microsoft.Security/secureScores?api-version=2020-01-01' | Should -Be 'subscriptions/{id}/providers/Microsoft.Security/secureScores'
            ConvertTo-PostureCallTarget -Target 'Get-Mailbox' | Should -Be 'Get-Mailbox'
        }
    }

    It 'counts each Graph page once and each request inside a batch, and the command wrappers by name' {
        InModuleScope TenantKeep.Posture {
            Mock Invoke-MgGraphRequest { @{ value = @(@{ id = 1 }) } }
            $null = Invoke-PostureGraphRequest -Uri 'users?$select=id' -ApiVersion v1.0
            $null = Invoke-PostureGraphRequest -Uri '$batch' -Method 'POST' -Body @{ requests = @(@{ id = '1'; method = 'GET'; url = '/users/0b1c2d3e-0000-4000-8000-000000000001/authentication/methods' }) } -ApiVersion beta -Single   # posture:read-only-post
            Mock Get-Command { $true } -ParameterFilter { $Name -eq 'Get-AcceptedDomain' }
            function Get-AcceptedDomain { @() }
            $null = Invoke-PostureExoCommand -Name 'Get-AcceptedDomain'
            $keys = @($script:PostureCallLedger.Keys)
            $keys | Should -Contain "graph`tGET`tv1.0/users"
            $keys | Should -Contain "graph`tPOST`tbeta/`$batch"
            $keys | Should -Contain "graph`tGET`tbeta/users/{id}/authentication/methods"
            $keys | Should -Contain "exchange`tCMDLET`tGet-AcceptedDomain"
        }
    }

    It 'merges the counts of both processes into logs/calls.json and calls only reads reads' {
        $run = & $script:NewRun (Join-Path $TestDrive 'run1')
        InModuleScope TenantKeep.Posture -Parameters @{ Run = $run } {
            Add-PostureCallRecord -Service graph -Method GET -Target 'https://graph.microsoft.com/v1.0/users'
            Add-PostureCallRecord -Service graph -Method GET -Target 'https://graph.microsoft.com/v1.0/users?$skiptoken=abc'
            $null = Save-PostureCallLedger -Folder $Run -Confirm:$false
            $script:PostureCallLedger.Count | Should -Be 0 -Because 'a second save must not count anything twice'
            Add-PostureCallRecord -Service graph -Method GET -Target 'https://graph.microsoft.com/v1.0/users'
            Add-PostureCallRecord -Service azure -Method POST -Target '/subscriptions/0b1c2d3e-0000-4000-8000-000000000001/providers/Microsoft.CostManagement/query?api-version=2023-11-01'
            Add-PostureCallRecord -Service graph -Method POST -Target 'https://graph.microsoft.com/v1.0/security/runHuntingQuery'
            $null = Save-PostureCallLedger -Folder $Run -Confirm:$false
            $sum = Get-PostureCallSummary -Folder $Run
            $sum.total | Should -Be 5
            @($sum.unexpected).Count | Should -Be 0 -Because 'the Cost Management query and advanced hunting are reads with the question in the body'
            ($sum.services | Where-Object service -eq 'graph').requests | Should -Be 4
            Add-PostureCallRecord -Service graph -Method PATCH -Target 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
            Add-PostureCallRecord -Service exchange -Method cmdlet -Target 'Set-Mailbox'
            $null = Save-PostureCallLedger -Folder $Run -Confirm:$false
            $bad = (Get-PostureCallSummary -Folder $Run).unexpected
            @($bad.target) | Should -Be @('Set-Mailbox', 'v1.0/policies/authorizationPolicy')
        }
    }

    It 'shows in Run Health what the run did, and says so plainly when anything was not a read' {
        $run = & $script:NewRun (Join-Path $TestDrive 'run2')
        Copy-Item -Path (Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot' '*.json') -Destination (Join-Path $run 'evidence')
        InModuleScope TenantKeep.Posture -Parameters @{ Run = $run } {
            Add-PostureCallRecord -Service graph -Method GET -Target 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
            $null = Save-PostureCallLedger -Folder $Run -Confirm:$false
        }
        $r = New-PostureReport -Evidence (Join-Path $run 'evidence') -OutputPath (Join-Path $TestDrive 'out2') -PassThru 6>$null
        $html = Get-Content -Raw ($r.Files | Where-Object { $_ -like '*report.html' })
        $html | Should -Match 'What This Run Did'
        $html | Should -Match 'Every one of the 1 requests was a read'
        InModuleScope TenantKeep.Posture -Parameters @{ Run = $run } {
            Add-PostureCallRecord -Service graph -Method DELETE -Target 'https://graph.microsoft.com/v1.0/users/x'
            $null = Save-PostureCallLedger -Folder $Run -Confirm:$false
        }
        $r = New-PostureReport -Evidence (Join-Path $run 'evidence') -OutputPath (Join-Path $TestDrive 'out3') -PassThru 6>$null
        Get-Content -Raw ($r.Files | Where-Object { $_ -like '*report.html' }) | Should -Match '1 call\(s\) were not reads'
    }
}
