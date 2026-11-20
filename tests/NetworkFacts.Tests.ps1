# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-network-$([guid]::NewGuid().ToString('n'))"
    $script:Write = { param([string] $Dir, [string] $Name, $Data) New-Item -ItemType Directory -Path $Dir -Force | Out-Null; ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }
    $script:Checks = {
        param([string] $Dir, [string] $ProfileJson)
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
        $pf = Join-Path $Dir 'profile.json'; $ProfileJson | Set-Content $pf
        $r = Invoke-PostureChecks -Evidence $Dir -Domain network -ProfilePath $pf -PassThru; $by = @{}; foreach ($x in $r.results) { $by[$x.id] = $x }; $by
    }
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Global Secure Access (network domain)' {
    It 'judges the profiles, web filtering and signaling for a licensed tenant' {
        $d = Join-Path $script:Root 'gsa'
        & $script:Write $d 'gsa-01-forwarding-profiles' @(@{ Name = 'Microsoft traffic'; TrafficForwardingType = 'm365'; State = 'enabled' }, @{ Name = 'Internet'; TrafficForwardingType = 'internet'; State = 'enabled' }, @{ Name = 'Private'; TrafficForwardingType = 'private'; State = 'disabled' })
        & $script:Write $d 'gsa-02-filtering-profiles' @(@{ Name = 'Baseline'; State = 'enabled'; Policies = 0 })
        & $script:Write $d 'gsa-03-settings' @{ RemoteNetworks = 0; SignalingStatus = 'enabled' }
        $by = & $script:Checks $d '{ "version": 1, "licenses": ["EntraSuite"] }'
        $by['NET-001'].status | Should -Be 'pass'
        $by['NET-002'].status | Should -Be 'fail' -Because 'the profile is on but no filtering policy is linked'
        $by['NET-003'].status | Should -Be 'fail'
        $by['NET-004'].status | Should -Be 'pass'
    }

    It 'reads as covered when another gateway does the job, and as needing the licence otherwise' {
        $d = Join-Path $script:Root 'vendor'
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        $by = & $script:Checks $d '{ "version": 1, "licenses": ["E3"], "thirdParty": { "swg": "Zscaler", "ztna": "none" } }'
        $by['NET-002'].status | Should -Be 'coveredBy'
        $by['NET-002'].reason | Should -Match 'Zscaler'
        $by['NET-003'].status | Should -Be 'notEvaluated'
        $by['NET-003'].reason | Should -Match 'Requires PrivateAccess or EntraSuite'
    }
}
