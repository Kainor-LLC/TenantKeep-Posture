# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
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
            $b = Get-PostureLicenseAdvice -Owned $owned -Seats 40 -Goal 'risk-based-access', 'ad-threats', 'phishing-training'
            @($b.advice.addOns.sku) | Should -Be @('DEFENDER_SUITE_FOR_BUSINESS_PREMIUM_NEW') -Because 'same features as E5 Security, and made for a business this size'
            $c = Get-PostureLicenseAdvice -Owned $owned -Seats 400 -Goal 'risk-based-access', 'ad-threats', 'phishing-training'
            @($c.advice.addOns.sku) | Should -Be @('IDENTITY_THREAT_PROTECTION') -Because 'above 300 users the business suite is not offered'
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

    It 'puts the advisor, seats, features and goals in the report, and the summary in report.md and findings.json' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-licview-$([guid]::NewGuid().ToString('n'))"
        try {
            $ev = Join-Path $root 'evidence'
            $null = Initialize-CollectionFixture -Root $ev
            '[ { "skuPartNumber": "SPB", "skuId": "s1", "capabilityStatus": "Enabled", "consumedUnits": 38, "prepaidUnits": { "enabled": 40 }, "servicePlans": [ { "servicePlanName": "AAD_PREMIUM" }, { "servicePlanName": "INTUNE_A" }, { "servicePlanName": "MDE_SMB" }, { "servicePlanName": "ATP_ENTERPRISE" } ] } ]' | Set-Content (Join-Path $ev '01-subscribed-skus.json')
            '{ "LicensedEnabledUsers": 38, "UsersByServicePlan": { "AAD_PREMIUM": 38, "INTUNE_A": 20, "MDE_SMB": 38, "ATP_ENTERPRISE": 38 } }' | Set-Content (Join-Path $ev '06-users-license-plans.json')
            $null = New-PostureReport -Evidence $ev 6>$null 3>$null
            $html = Get-Content -Raw (Get-ChildItem $root -Recurse -Filter 'report.html' | Select-Object -First 1).FullName
            $html | Should -Match '<h3>What To Add</h3>'
            $html | Should -Match 'Microsoft Entra ID P2' -Because 'the core goals need it and Business Premium lacks it'
            $html | Should -Match 'Partly assigned</span> <span class="muted">20 of 38 users' -Because 'Intune is switched on for 20 of 38 licensed users'
            $html | Should -Match '2 paid seats are not assigned to anyone\.'
            $html | Should -Match 'id="goals-unmet-only"'
            (Get-Content -Raw (Get-ChildItem $root -Recurse -Filter 'report.md' | Select-Object -First 1).FullName) | Should -Match '## Licensing'
            $doc = Get-Content -Raw (Get-ChildItem $root -Recurse -Filter 'findings.json' | Select-Object -First 1).FullName | ConvertFrom-Json
            $doc.licensing.advice.addOns.sku | Should -Contain 'AAD_PREMIUM_P2'
            $doc.licensing.featuresPartlyAssigned | Should -Contain 'Microsoft Intune Plan 1'
        }
        finally { if (Test-Path $root) { Remove-Item -LiteralPath $root -Recurse -Force } }
    }
}
