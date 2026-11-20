# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
}

Describe 'Get-PostureLicenseAdvice' {
    It 'advises a Business Premium tenant on the core goals: Entra ID P2 as the add-on, E5 as the bundle' {
        InModuleScope TenantKeep.Posture {
            $owned = @(Get-PostureOwnedFeature -Sku @(@{ SkuPartNumber = 'SPB' }))
            $a = Get-PostureLicenseAdvice -Owned $owned -Seats 40
            $a.advice.goalSource | Should -Be 'core'
            $a.advice.met | Should -BeFalse
            @($a.advice.addOns.sku) | Should -Be @('AAD_PREMIUM_P2') -Because 'the smallest purchase that covers risk-based access and just-in-time admin'
            $a.advice.upgrade.sku | Should -Be 'SPE_E5'
            ($a.goals | Where-Object id -EQ 'device-risk').met | Should -BeTrue -Because 'Defender for Business reports device risk'
            ($a.features | Where-Object id -EQ 'entraP2').status | Should -Be 'missing'
            $a.advice.note | Should -Match 'not licensing advice'
        }
    }

    It 'pairs add-ons when one does not cover, keeps capped bundles out above their cap, and names prerequisites' {
        InModuleScope TenantKeep.Posture {
            $a = Get-PostureLicenseAdvice -Owned @('mdo1') -Goal 'lifecycle', 'edr' -Seats 500
            @($a.advice.addOns.sku) | Should -Not -Contain 'MDE_SMB' -Because 'Defender for Business stops at 300 users'
            @($a.advice.addOns).Count | Should -BeLessOrEqual 2
            $a.advice.prerequisite | Should -Contain 'Microsoft Entra ID Governance needs Microsoft Entra ID P1.'
            $a.advice.goalSource | Should -Be 'profile'
        }
    }

    It 'says met when the goals are covered, and shows a feature switched on for only some users as partial' {
        InModuleScope TenantKeep.Posture {
            $owned = @(Get-PostureOwnedFeature -Sku @(@{ SkuPartNumber = 'SPE_E5' }))
            $a = Get-PostureLicenseAdvice -Owned $owned -LicensedUsers 100 -UsersByPlan @{ AAD_PREMIUM_P2 = 30; AAD_PREMIUM = 100 }
            $a.advice.met | Should -BeTrue
            @($a.advice.addOns).Count | Should -Be 0
            ($a.features | Where-Object id -EQ 'entraP2').status | Should -Be 'partial'
            ($a.features | Where-Object id -EQ 'entraP2').users | Should -Be 30
            ($a.features | Where-Object id -EQ 'entraP1').status | Should -Be 'owned'
        }
    }
}
