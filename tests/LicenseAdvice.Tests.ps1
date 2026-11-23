# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
}

Describe 'Get-PostureLicenseAdvice' {
    It 'recommends one combination for a Business Premium tenant on the core goals, with the reason each licence is in it' {
        InModuleScope TenantKeep.Posture {
            $owned = @(Get-PostureOwnedFeature -Sku @(@{ SkuPartNumber = 'SPB' }))
            $a = Get-PostureLicenseAdvice -Owned $owned -Seats 40 -OwnedSku 'SPB'
            $a.advice.goalSource | Should -Be 'core'
            $a.advice.met | Should -BeFalse
            $r = $a.advice.recommended
            $r.kind | Should -Be 'addons'
            $r.title | Should -Be 'Add Microsoft Entra ID P2 to Microsoft 365 Business Premium'
            @($r.licences.sku) | Should -Be @('AAD_PREMIUM_P2') -Because 'the smallest purchase that covers risk-based access and just-in-time admin'
            $r.licences[0].role | Should -Be 'add'
            @($r.licences[0].covers).Count | Should -Be 2 -Because 'both goals it is there for are named'
            $r.licences[0].brings | Should -Contain 'Microsoft Entra ID P2'
            @($r.replaces).Count | Should -Be 0
            $a.advice.Contains('options') | Should -BeFalse -Because 'the report states one combination, not a list to rank'
            ($a.goals | Where-Object id -EQ 'device-risk').met | Should -BeTrue -Because 'Defender for Business reports device risk'
            ($a.features | Where-Object id -EQ 'entraP2').status | Should -Be 'missing'
            $a.advice.note | Should -Match 'not licensing advice'
            $b = Get-PostureLicenseAdvice -Owned $owned -Seats 40 -OwnedSku 'SPB' -Goal 'risk-based-access', 'ad-threats', 'phishing-training'
            @($b.advice.recommended.licences.sku) | Should -Be @('DEFENDER_SUITE_FOR_BUSINESS_PREMIUM_NEW') -Because 'same features as E5 Security, and made for a business this size'
            $c = Get-PostureLicenseAdvice -Owned $owned -Seats 400 -OwnedSku 'SPB' -Goal 'risk-based-access', 'ad-threats', 'phishing-training'
            @($c.advice.recommended.licences.sku) | Should -Be @('IDENTITY_THREAT_PROTECTION') -Because 'above 300 users the business suite is not considered'
        }
    }

    It 'keeps the suite when add-ons do it in as few licences, and names what overlaps with another product' {
        InModuleScope TenantKeep.Posture {
            $owned = @(Get-PostureOwnedFeature -Sku @(@{ SkuPartNumber = 'SPE_E3' }))
            $a = Get-PostureLicenseAdvice -Owned $owned -Seats 2000 -Goal 'risk-based-access', 'lifecycle', 'auto-labels', 'dlp-devices', 'insider-risk', 'audit-year', 'edr', 'vpn-replacement' -ThirdParty @{ edr = 'CrowdStrike'; swg = 'Zscaler'; ztna = 'Zscaler' } -OwnedSku 'SPE_E3'
            ($a.goals | Where-Object id -EQ 'edr').met | Should -BeTrue -Because 'CrowdStrike covers it'
            ($a.features | Where-Object id -EQ 'mde2').status | Should -Be 'covered'
            $r = $a.advice.recommended
            @($r.licences.sku) | Should -Be @('INFORMATION_PROTECTION_COMPLIANCE', 'Microsoft_Entra_Suite') -Because 'two licences either way, and adding keeps the suite the tenant holds'
            $r.title | Should -Be 'Add Microsoft Purview Suite (was Microsoft 365 E5 Compliance) and Microsoft Entra Suite to Microsoft 365 E3'
            @($r.redundant.name) | Should -Contain 'Microsoft Entra Private Access'
            ($r.redundant | Where-Object name -EQ 'Microsoft Entra Private Access').vendor | Should -Be 'Zscaler'
            ($r.licences | Where-Object sku -EQ 'Microsoft_Entra_Suite').covers | Should -Contain 'Joiners, movers and leavers automated'
            @($r.licences.sku) | Should -Not -Contain 'PURVIEW_SUITE_FOR_BUSINESS' -Because 'the business suites are sold on Business Premium only'
            $small = Get-PostureLicenseAdvice -Owned $owned -Seats 120 -Goal 'auto-labels' -OwnedSku 'SPE_E3'
            @($small.advice.recommended.licences.sku) | Should -Be @('INFORMATION_PROTECTION_COMPLIANCE') -Because 'under 300 users an E3 tenant still buys the enterprise Purview Suite'
        }
    }

    It 'recommends the suite when it does in one licence what would take several, and says what it takes the place of' {
        InModuleScope TenantKeep.Posture {
            $owned = @(Get-PostureOwnedFeature -Sku @(@{ SkuPartNumber = 'SPE_E3' }))
            $r = (Get-PostureLicenseAdvice -Owned $owned -Seats 500 -Goal 'risk-based-access', 'auto-labels', 'dlp-devices', 'insider-risk', 'audit-year', 'edr', 'ad-threats' -OwnedSku 'SPE_E3').advice.recommended
            $r.kind | Should -Be 'suite'
            $r.title | Should -Be 'Move to Microsoft 365 E5'
            $r.licences[0].role | Should -Be 'moveTo'
            @($r.licences[0].covers).Count | Should -Be 7
            @($r.replaces.name) | Should -Be @('Microsoft 365 E3')
            $r.replaces[0].by | Should -Be 'Microsoft 365 E5'
            $r.alsoIncludes | Should -Contain 'Teams Phone'
        }
    }

    It 'brings what a licence needs first, and says which licence needs it' {
        InModuleScope TenantKeep.Posture {
            $a = Get-PostureLicenseAdvice -Owned @('mdo1') -Goal 'lifecycle', 'edr' -Seats 500
            $r = $a.advice.recommended
            @($r.licences.sku) | Should -Not -Contain 'MDE_SMB' -Because 'Defender for Business stops at 300 users'
            @($r.licences).Count | Should -BeLessOrEqual 2
            @($a.advice.prerequisite) | Should -BeNullOrEmpty -Because 'the combination brings Entra ID P1, which ID Governance needs'
            $a.advice.goalSource | Should -Be 'profile'
            # Governance alone needs Entra ID P1: with only that goal the licence that supplies P1 says why it is there.
            $g = (Get-PostureLicenseAdvice -Owned @() -Goal 'lifecycle' -Seats 500).advice.recommended
            $brought = @($g.licences | ForEach-Object { $_.brings })
            $brought | Should -Contain 'Microsoft Entra ID P1'
        }
    }

    It 'says met when the goals are covered, shows a feature switched on for only some users as partial, and names licences held twice over' {
        InModuleScope TenantKeep.Posture {
            $owned = @(Get-PostureOwnedFeature -Sku @(@{ SkuPartNumber = 'SPE_E5' }, @{ SkuPartNumber = 'AAD_PREMIUM_P2' }))
            $a = Get-PostureLicenseAdvice -Owned $owned -LicensedUsers 100 -UsersByPlan @{ AAD_PREMIUM_P2 = 30; AAD_PREMIUM = 100 } -OwnedSku 'SPE_E5', 'AAD_PREMIUM_P2'
            $a.advice.met | Should -BeTrue
            $a.advice.recommended | Should -BeNullOrEmpty
            ($a.features | Where-Object id -EQ 'entraP2').status | Should -Be 'partial'
            ($a.features | Where-Object id -EQ 'entraP2').users | Should -Be 30
            ($a.features | Where-Object id -EQ 'entraP1').status | Should -Be 'owned'
            @($a.advice.heldOverlap).Count | Should -Be 1
            $a.advice.heldOverlap[0].licence | Should -Be 'Microsoft Entra ID P2'
            $a.advice.heldOverlap[0].includedIn | Should -Be 'Microsoft 365 E5'
        }
    }

    It 'knows Microsoft 365 E7, Agent 365 and what E5 gained in July 2026, and does not answer two gaps with everything' {
        InModuleScope TenantKeep.Posture {
            $data = Get-PostureLicensingData
            @($data.goals.id) | Should -Contain 'copilot'
            @($data.goals.id) | Should -Contain 'agent-governance'
            $e7 = @($data.bundles | Where-Object sku -EQ 'MICROSOFT_365_E7')[0]
            foreach ($f in 'copilot', 'agent365', 'governance', 'privateAccess', 'internetAccess', 'intuneSuite', 'mde2', 'purviewIp') { @($e7.features) | Should -Contain $f -Because 'E7 is E5 with Copilot, Entra Suite and Agent 365' }
            Get-PostureLicenseToken -Sku @(@{ SkuPartNumber = 'MICROSOFT_365_E7' }) | Should -Contain 'E5' -Because 'a check that asks for E5 is met by E7'

            $e5 = @(Get-PostureOwnedFeature -Sku @(@{ SkuPartNumber = 'SPE_E5' }))
            $e5 | Should -Contain 'intuneSuite' -Because 'Endpoint Privilege Management came with Microsoft 365 E5 on 1 July 2026'
            $elevation = Get-PostureLicenseAdvice -Owned $e5 -Seats 400 -Goal 'admin-elevation' -OwnedSku 'SPE_E5'
            ($elevation.goals | Where-Object id -EQ 'admin-elevation').met | Should -BeTrue
            $elevation.advice.recommended | Should -BeNullOrEmpty -Because 'an E5 tenant was told to add the Intune Suite it already has'

            $e3 = @(Get-PostureOwnedFeature -Sku @(@{ SkuPartNumber = 'SPE_E3' }))
            $e3 | Should -Contain 'intunePlan2' -Because 'E3 gained Remote Help, Advanced Analytics and Plan 2'
            $e3 | Should -Not -Contain 'intuneSuite' -Because 'Endpoint Privilege Management is in E5, not E3'
            @((Get-PostureLicenseAdvice -Owned $e3 -Seats 400 -Goal 'admin-elevation' -OwnedSku 'SPE_E3').advice.recommended.licences.sku) | Should -Be @('Microsoft_Intune_Suite')

            # E7 when every product it adds is wanted; add-ons when it would bring one nobody asked for.
            $all3 = (Get-PostureLicenseAdvice -Owned $e5 -Seats 400 -Goal 'copilot', 'agent-governance', 'vpn-replacement' -OwnedSku 'SPE_E5').advice.recommended
            $all3.title | Should -Be 'Move to Microsoft 365 E7'
            $two = (Get-PostureLicenseAdvice -Owned $e5 -Seats 400 -Goal 'agent-governance', 'vpn-replacement' -OwnedSku 'SPE_E5').advice.recommended
            @($two.licences.sku) | Should -Be @('Microsoft_Entra_Suite_Step_Up_for_Microsoft_Entra_ID_P2', 'AGENT_365') -Because 'E7 would bring Copilot, which no chosen goal needs'
            @((Get-PostureLicenseAdvice -Owned $e5 -Seats 400 -Goal 'agent-governance' -OwnedSku 'SPE_E5').advice.recommended.licences.sku) | Should -Be @('AGENT_365')
            $held = @(Get-PostureOwnedFeature -Sku @(@{ SkuPartNumber = 'SPE_E5' }, @{ SkuPartNumber = 'Microsoft_365_Copilot' }))
            (Get-PostureLicenseAdvice -Owned $held -Seats 400 -Goal 'agent-governance', 'vpn-replacement' -OwnedSku 'SPE_E5', 'Microsoft_365_Copilot').advice.recommended.title | Should -Be 'Move to Microsoft 365 E7' -Because 'Copilot is already held, so E7 brings nothing unasked'

            # An E3 tenant with two gaps is not sent to E7, and is not offered the add-on made for tenants with P2.
            $gaps = (Get-PostureLicenseAdvice -Owned $e3 -Seats 400 -Goal 'auto-labels', 'vpn-replacement' -OwnedSku 'SPE_E3').advice.recommended
            @($gaps.licences.sku) | Should -Be @('INFORMATION_PROTECTION_COMPLIANCE', 'Microsoft_Entra_Suite')
            (Get-PostureLicenseAdvice -Owned $e3 -Seats 400 -Goal 'risk-based-access', 'edr', 'auto-labels', 'insider-risk' -OwnedSku 'SPE_E3').advice.recommended.title | Should -Be 'Move to Microsoft 365 E5' -Because 'both products E5 adds are wanted, and E7 would add three that are not'
        }
    }

    It 'gives the same answer in the page (templates/licensing.js under node) as in PowerShell without prices' {
        $node = Get-Command node -ErrorAction SilentlyContinue
        if (-not $node) { Set-ItResult -Skipped -Because 'node is not installed'; return }
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-licjs-$([guid]::NewGuid().ToString('n')).json"
        $js = Join-Path $PSScriptRoot '..' 'templates' 'licensing.js'
        $cases = @(
            @{ sku = @('SPB'); goals = @(); tp = @{}; seats = 40 }
            @{ sku = @('SPB'); goals = @('risk-based-access', 'ad-threats', 'phishing-training'); tp = @{}; seats = 400 }
            @{ sku = @('SPE_E3'); goals = @('risk-based-access', 'lifecycle', 'auto-labels', 'dlp-devices', 'insider-risk', 'audit-year', 'edr', 'vpn-replacement'); tp = @{ edr = 'CrowdStrike'; swg = 'Zscaler'; ztna = 'Zscaler' }; seats = 2000 }
            @{ sku = @('SPE_E3'); goals = @('risk-based-access', 'auto-labels', 'dlp-devices', 'insider-risk', 'audit-year', 'edr', 'ad-threats'); tp = @{}; seats = 500 }
            @{ sku = @('SPE_E5', 'AAD_PREMIUM_P2'); goals = @(); tp = @{}; seats = 100 }
            @{ sku = @('ENTERPRISEPACK', 'EMS'); goals = @('device-gating', 'copilot-data', 'email-protection'); tp = @{ email = 'Mimecast' }; seats = 250 }
            @{ sku = @(); goals = @('lifecycle', 'edr'); tp = @{}; seats = 500 }
            @{ sku = @('SPE_E5'); goals = @('copilot', 'agent-governance', 'vpn-replacement'); tp = @{}; seats = 400 }
            @{ sku = @('SPE_E5'); goals = @('agent-governance', 'vpn-replacement'); tp = @{}; seats = 400 }
            @{ sku = @('SPE_E5', 'Microsoft_365_Copilot'); goals = @('agent-governance', 'vpn-replacement', 'lifecycle', 'web-filtering', 'admin-elevation'); tp = @{}; seats = 400 }
            @{ sku = @('SPE_E3'); goals = @('auto-labels', 'vpn-replacement'); tp = @{}; seats = 400 }
            @{ sku = @('SPE_E3'); goals = @('admin-elevation', 'agent-governance'); tp = @{ ztna = 'Zscaler' }; seats = 900 }
        )
        $shape = {
            param($a)
            $r = $a['recommended']
            [ordered]@{
                met = [bool]$a['met']; missing = @($a['missing'] | ForEach-Object { @($_) -join '|' }); title = $(if ($r) { $r['title'] }); kind = $(if ($r) { $r['kind'] })
                licences = @($(if ($r) { $r['licences'] | ForEach-Object { "$($_['sku'])/$($_['role'])/$(@($_['covers']) -join ';')/$(@($_['brings']) -join ';')/$(@($_['neededBy']) -join ';')" } }))
                replaces = @($(if ($r) { $r['replaces'] | ForEach-Object { "$($_['name'])>$($_['by'])" } })); keeps = @($(if ($r) { $r['keeps'] })); noLonger = @($(if ($r) { $r['noLonger'] }))
                redundant = @($(if ($r) { $r['redundant'] | ForEach-Object { "$($_['name'])($($_['vendor']))" } })); also = @($(if ($r) { $r['alsoIncludes'] }))
                heldOverlap = @($a['heldOverlap'] | ForEach-Object { "$($_['licence'])<$($_['includedIn'])" }); prerequisite = @($a['prerequisite'] | Sort-Object)
            } | ConvertTo-Json -Depth 6 -Compress
        }
        try {
            foreach ($c in $cases) {
                $both = InModuleScope TenantKeep.Posture -Parameters @{ C = $c } {
                    param($C)
                    $owned = @(Get-PostureOwnedFeature -Sku @($C.sku | ForEach-Object { @{ SkuPartNumber = $_ } }))
                    @{ ps = (Get-PostureLicenseAdvice -Owned $owned -Goal $C.goals -Seats $C.seats -ThirdParty $C.tp -OwnedSku $C.sku).advice; page = (Get-PostureLicensePageData -Owned $owned -ThirdParty $C.tp -Seats $C.seats -Goal $C.goals -OwnedSku $C.sku) }
                }
                @{ data = $both.page; state = @{ goals = @($c.goals); thirdParty = $c.tp; seats = $c.seats } } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $tmp
                $out = & $node.Source -e "const f=require(process.argv[1]); const d=JSON.parse(require('fs').readFileSync(process.argv[2],'utf8')); console.log(JSON.stringify(f(d.data,d.state)))" $js $tmp | ConvertFrom-Json -AsHashtable
                (& $shape $out) | Should -Be (& $shape $both.ps) -Because "$($c.sku -join '+') with $(@($c.goals).Count) goal(s)"
            }
        }
        finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
    }
}

Describe 'Choosing with a price file' {
    # Every number here is made up and chosen to be easy to search for; none is a real price of anything.
    BeforeAll {
        $script:AllPrices = {
            param([decimal] $Suite, [decimal] $Addon, [hashtable] $Override = @{})
            InModuleScope TenantKeep.Posture -Parameters @{ S = $Suite; A = $Addon; O = $Override } {
                param($S, $A, $O)
                $p = @{}
                foreach ($b in (Get-PostureLicensingData).bundles) { $p[[string]$b.sku] = $(if ($O.ContainsKey([string]$b.sku)) { [decimal]$O[[string]$b.sku] } elseif ($b.kind -eq 'suite') { $S } else { $A }) }
                $p
            }
        }
    }

    It 'changes the choice between combinations that all work, and returns nothing that tells a price' {
        $cheapAddons = & $script:AllPrices 7919.31 6.07 @{ SPE_E3 = 4409.59; SPE_E5 = 9001.13 }
        $out = InModuleScope TenantKeep.Posture -Parameters @{ P = $cheapAddons } {
            param($P)
            $owned = @(Get-PostureOwnedFeature -Sku @(@{ SkuPartNumber = 'SPE_E3' }))
            $goals = 'risk-based-access', 'auto-labels', 'dlp-devices', 'insider-risk', 'audit-year', 'edr', 'ad-threats'
            $record = @{}
            $plain = Get-PostureLicenseAdvice -Owned $owned -Seats 500 -Goal $goals -OwnedSku 'SPE_E3'
            $priced = Get-PostureLicenseAdvice -Owned $owned -Seats 500 -Goal $goals -OwnedSku 'SPE_E3' -Price $P -Record $record
            @{ plain = $plain; priced = $priced; record = $record; page = (Get-PostureLicensePageData -Owned $owned -Seats 500 -Goal $goals -OwnedSku 'SPE_E3') }
        }
        $out.plain.advice.recommended.title | Should -Be 'Move to Microsoft 365 E5' -Because 'on function alone one licence beats several'
        $out.priced.advice.recommended.kind | Should -Be 'addons' -Because 'with these made-up prices the add-ons total far less than the move'
        $out.record['mode'] | Should -Be 'priced'
        @($out.record['withoutPrice']).Count | Should -Be 0
        # Nothing about price in what goes on to the report or the page.
        $text = (@($out.priced, $out.page) | ConvertTo-Json -Depth 20)
        $text | Should -Not -Match '7919|6\.07|4409|9001' -Because 'no price may leave the advisor'
        $text | Should -Not -Match '(?i)"(price|cost|total|rank|compare|erp|listPrice)[A-Za-z]*"\s*:'
        @($out.priced.advice.get_Keys()) | Should -Be @($out.plain.advice.get_Keys()) -Because 'the answer has the same shape whether or not prices were used'
    }

    It 'can favour the suite as well: the lower total wins, whichever kind it is' {
        $dearAddons = & $script:AllPrices 3301.07 5501.13 @{ SPB = 1001.01; SPE_E5 = 1051.02 }
        $r = InModuleScope TenantKeep.Posture -Parameters @{ P = $dearAddons } {
            param($P)
            $owned = @(Get-PostureOwnedFeature -Sku @(@{ SkuPartNumber = 'SPB' }))
            (Get-PostureLicenseAdvice -Owned $owned -Seats 40 -OwnedSku 'SPB' -Price $P).advice.recommended
        }
        $r.title | Should -Be 'Move to Microsoft 365 E5' -Because 'the move adds less than any add-on at these made-up prices; without prices the answer is Entra ID P2'
        @($r.replaces.name) | Should -Be @('Microsoft 365 Business Premium')
    }

    It 'goes back to function alone when one licence in the comparison has no price, and records which' {
        $prices = & $script:AllPrices 7919.31 6.07 @{ SPE_E3 = 4409.59 }
        $prices.Remove('SPE_E5')
        $out = InModuleScope TenantKeep.Posture -Parameters @{ P = $prices } {
            param($P)
            $owned = @(Get-PostureOwnedFeature -Sku @(@{ SkuPartNumber = 'SPE_E3' }))
            $record = @{}
            $a = Get-PostureLicenseAdvice -Owned $owned -Seats 500 -Goal 'risk-based-access', 'auto-labels', 'dlp-devices', 'insider-risk', 'audit-year', 'edr', 'ad-threats' -OwnedSku 'SPE_E3' -Price $P -Record $record
            @{ a = $a; record = $record }
        }
        $out.a.advice.recommended.title | Should -Be 'Move to Microsoft 365 E5' -Because 'half a comparison is not used'
        $out.record['mode'] | Should -Be 'function'
        $out.record['withoutPrice'] | Should -Contain 'Microsoft 365 E5'
        $out.record['why'] | Should -Match 'have no price'
    }

    It 'does not ask for the price of a licence that cannot be part of any combination' {
        # The business add-ons are sold on Business Premium only: an E3 tenant's comparison never touches them.
        $prices = & $script:AllPrices 7919.31 6.07 @{ SPE_E3 = 4409.59; SPE_E5 = 9001.13 }
        foreach ($k in 'DEFENDER_SUITE_FOR_BUSINESS_PREMIUM_NEW', 'PURVIEW_SUITE_FOR_BUSINESS') { if ($prices.ContainsKey($k)) { $prices.Remove($k) } }
        $record = InModuleScope TenantKeep.Posture -Parameters @{ P = $prices } {
            param($P)
            $owned = @(Get-PostureOwnedFeature -Sku @(@{ SkuPartNumber = 'SPE_E3' }))
            $rec = @{}
            $null = Get-PostureLicenseAdvice -Owned $owned -Seats 2000 -Goal 'risk-based-access', 'auto-labels' -OwnedSku 'SPE_E3' -Price $P -Record $rec
            $rec
        }
        $record['mode'] | Should -Be 'priced'
    }

    It 'records that there was nothing to choose when the goals are covered' {
        $record = InModuleScope TenantKeep.Posture -Parameters @{ P = (& $script:AllPrices 10 1) } {
            param($P)
            $rec = @{}
            $null = Get-PostureLicenseAdvice -Owned @(Get-PostureOwnedFeature -Sku @(@{ SkuPartNumber = 'SPE_E5' })) -OwnedSku 'SPE_E5' -Price $P -Record $rec
            $rec
        }
        $record['mode'] | Should -Be 'none'
    }
}

Describe 'Read-PosturePriceFile' {
    # Made-up rows. The names are the advisor's own licence names; the numbers are invented.
    BeforeAll {
        $script:PriceDir = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-price-$([guid]::NewGuid().ToString('n'))"
        $null = New-Item -ItemType Directory -Path $script:PriceDir
        $script:WritePrice = {
            param([string] $Name, [string[]] $Row, [string] $Header = 'SkuId,ProductName,Term,BillingCycle,Currency,Market,Erp,ListPrice,EffectiveDate,PartNumber', [hashtable] $Meta)
            $path = Join-Path $script:PriceDir "$Name.csv"
            Set-Content -LiteralPath $path -Value (@($Header) + @($Row))
            if ($Meta) { Set-Content -LiteralPath (Join-Path $script:PriceDir "$Name.meta.json") -Value ($Meta | ConvertTo-Json -Depth 5) }
            $path
        }
    }
    AfterAll { if (Test-Path $script:PriceDir) { Remove-Item -LiteralPath $script:PriceDir -Recurse -Force } }

    It 'takes the customer-side price of the assumed term and billing cycle, by part number or by name, and never the partner''s own' {
        $path = & $script:WritePrice 'basic' @(
            'X1:0001,Microsoft 365 E5,P1Y,Monthly,USD,US,7919.31,6007.77,2026-11-01,'
            'X1:0001,Microsoft 365 E5,P1Y,Annual,USD,US,88888.88,6007.77,2026-11-01,'
            'X1:0001,Microsoft 365 E5,P1M,Monthly,USD,US,99999.99,6007.77,2026-11-01,'
            'X2:0001,Some name the sheet uses,P1Y,Monthly,USD,US,5501.13,4409.59,2026-11-01,SPE_E3'
            'X3:0001,Microsoft Defender Suite,P1Y,Monthly,USD,US,3301.07,2203.91,2026-11-01,'
            'X4:0001,Microsoft 365 E5 Compliance,P1Y,Monthly,USD,US,2203.91,1101.01,2026-11-01,'
            'X5:0001,A product the advisor does not know,P1Y,Monthly,USD,US,1.23,1.00,2026-11-01,'
        ) -Meta @{ checkedUtc = '2026-11-20T09:17:00Z'; market = 'US'; currency = 'USD'; assume = @{ term = 'P1Y'; billingCycle = 'Monthly' } }
        $r = InModuleScope TenantKeep.Posture -Parameters @{ Path = $path } { param($Path) Read-PosturePriceFile -Path $Path -Now ([datetime]::new(2026, 11, 22, 0, 0, 0, [System.DateTimeKind]::Utc)) }
        $r.price['SPE_E5'] | Should -Be 7919.31d -Because 'the one-year term billed monthly, the customer-side column'
        $r.price['SPE_E3'] | Should -Be 5501.13d -Because 'the part number wins when the name in the sheet differs'
        $r.price['IDENTITY_THREAT_PROTECTION'] | Should -Be 3301.07d -Because 'the catalogue name without its "(was ...)" note'
        $r.price['INFORMATION_PROTECTION_COMPLIANCE'] | Should -Be 2203.91d -Because 'the old name inside the note'
        $r.price.get_Count() | Should -Be 4
        $r.basis['rowsRead'] | Should -Be 7
        $r.basis['ageDays'] | Should -Be 1
        $r.basis['stale'] | Should -BeFalse
        $r.basis['term'] | Should -Be 'P1Y'
        ($r.basis | ConvertTo-Json -Depth 5) | Should -Not -Match '7919|6007|5501|4409|3301|2203' -Because 'what the file says about itself holds no price'
    }

    It 'uses the latest row that has taken effect, skips one dated ahead, and gives no price when two rows disagree on one date' {
        $path = & $script:WritePrice 'dates' @(
            'X1:0001,Microsoft 365 E5,P1Y,Monthly,USD,US,7000.01,1,2026-01-01,'
            'X1:0001,Microsoft 365 E5,P1Y,Monthly,USD,US,7919.31,1,2026-11-01,'
            'X1:0001,Microsoft 365 E5,P1Y,Monthly,USD,US,8111.03,1,2026-12-01,'
            'X2:0001,Microsoft 365 E3,P1Y,Monthly,USD,US,5501.13,1,2026-11-01,'
            'X2:0002,Microsoft 365 E3,P1Y,Monthly,USD,US,5502.14,1,2026-11-01,'
            'X3:0001,Microsoft Entra ID P2,P1Y,Monthly,USD,US,not a number,1,2026-11-01,'
            'X4:0001,Microsoft Entra ID P1,P1Y,Monthly,EUR,DE,4409.59,1,2026-11-01,'
        ) -Meta @{ checkedUtc = '2026-11-20T09:17:00Z'; market = 'US'; currency = 'USD' }
        $r = InModuleScope TenantKeep.Posture -Parameters @{ Path = $path } { param($Path) Read-PosturePriceFile -Path $Path -Now ([datetime]::new(2026, 11, 22, 0, 0, 0, [System.DateTimeKind]::Utc)) }
        $r.price['SPE_E5'] | Should -Be 7919.31d
        $r.price.ContainsKey('SPE_E3') | Should -BeFalse
        $r.basis['ambiguous'] | Should -Contain 'Microsoft 365 E3'
        $r.price.ContainsKey('AAD_PREMIUM_P2') | Should -BeFalse -Because 'a price that is not a number is no price'
        $r.price.ContainsKey('AAD_PREMIUM') | Should -BeFalse -Because 'another market and currency than the file records'
    }

    It 'says when the prices are old, and when nothing says how old they are' {
        $old = & $script:WritePrice 'old' @('X1:0001,Microsoft 365 E5,P1Y,Monthly,USD,US,7919.31,1,2026-01-01,') -Meta @{ checkedUtc = '2026-10-01T00:00:00Z' }
        $none = & $script:WritePrice 'nometa' @('X1:0001,Microsoft 365 E5,P1Y,Monthly,USD,US,7919.31,1,2026-01-01,')
        $r = InModuleScope TenantKeep.Posture -Parameters @{ Old = $old; None = $none } { param($Old, $None) $now = [datetime]::new(2026, 11, 22, 0, 0, 0, [System.DateTimeKind]::Utc); @{ old = (Read-PosturePriceFile -Path $Old -Now $now); none = (Read-PosturePriceFile -Path $None -Now $now) } }
        $r.old.basis['ageDays'] | Should -Be 52
        $r.old.basis['stale'] | Should -BeTrue
        $r.none.basis['ageDays'] | Should -BeNullOrEmpty
        $r.none.basis['stale'] | Should -BeTrue
        $r.none.price['SPE_E5'] | Should -Be 7919.31d -Because 'the prices are still read; the warning is the caller''s to give'
    }

    It 'names a missing column and the columns it found, without quoting a row' {
        $path = & $script:WritePrice 'short' @('Microsoft 365 E5,P1Y,7919.31') -Header 'ProductName,Term,Erp'
        $said = $null
        try { InModuleScope TenantKeep.Posture -Parameters @{ Path = $path } { param($Path) Read-PosturePriceFile -Path $Path } } catch { $said = [string]$_.Exception.Message }
        $said | Should -Match 'has no column named BillingCycle, EffectiveDate'
        $said | Should -Match 'It has: ProductName, Term, Erp'
        $said | Should -Not -Match '7919'
    }
}

Describe 'The licensing section of a report' {
    BeforeAll {
        $script:LicRoot = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-licview-$([guid]::NewGuid().ToString('n'))"
        $script:LicEvidence = Join-Path $script:LicRoot 'evidence'
        $null = Initialize-CollectionFixture -Root $script:LicEvidence
        '[ { "skuPartNumber": "SPB", "skuId": "s1", "capabilityStatus": "Enabled", "consumedUnits": 38, "prepaidUnits": { "enabled": 40 }, "servicePlans": [ { "servicePlanName": "AAD_PREMIUM" }, { "servicePlanName": "INTUNE_A" }, { "servicePlanName": "MDE_SMB" }, { "servicePlanName": "ATP_ENTERPRISE" } ] } ]' | Set-Content (Join-Path $script:LicEvidence '01-subscribed-skus.json')
        '{ "LicensedEnabledUsers": 38, "UsersByServicePlan": { "AAD_PREMIUM": 38, "INTUNE_A": 20, "MDE_SMB": 38, "ATP_ENTERPRISE": 38 } }' | Set-Content (Join-Path $script:LicEvidence '06-users-license-plans.json')
        # A made-up price file: every licence the advisor knows, add-ons dear and one suite close to the one held, so
        # the choice with prices (a move) differs from the choice without (an add-on).
        $rows = InModuleScope TenantKeep.Posture {
            foreach ($b in (Get-PostureLicensingData).bundles) {
                $erp = $(switch ([string]$b.sku) { 'SPB' { '1001.01' } 'SPE_E5' { '1051.02' } default { if ($b.kind -eq 'suite') { '3301.07' } else { '5501.13' } } })
                "Z:1,`"$($b.name)`",P1Y,Monthly,USD,US,$erp,6007.77,2026-11-01,$($b.sku)"
            }
        }
        $script:LicPrices = Join-Path $script:LicRoot 'prices' 'licenses.csv'
        $null = New-Item -ItemType Directory -Path (Split-Path $script:LicPrices)
        Set-Content -LiteralPath $script:LicPrices -Value (@('SkuId,ProductName,Term,BillingCycle,Currency,Market,Erp,ListPrice,EffectiveDate,PartNumber') + @($rows))
        Set-Content -LiteralPath (Join-Path (Split-Path $script:LicPrices) 'licenses.meta.json') -Value (@{ checkedUtc = [datetime]::UtcNow.AddDays(-3).ToString('yyyy-MM-ddTHH:mm:ssZ'); market = 'US'; currency = 'USD'; assume = @{ term = 'P1Y'; billingCycle = 'Monthly' } } | ConvertTo-Json)
        # Words about money. Not 'saved' (the page says nothing a reader changes is saved) and not 'premium', which
        # is in Microsoft's own product names.
        $script:CostWords = '(?i)\b(price|prices|priced|pricing|cost|costs|costly|cheap|cheaper|cheapest|expensive|inexpensive|saves?|savings?|budget|discount|discounts|margin|afford|affordable|dollar|dollars|spend|fee|fees)\b|[$\u20AC\u00A3]\s?\d'
        $script:Sentinel = '1001\.01|1051\.02|3301\.07|5501\.13|6007\.77'
        $script:Section = { param([string] $Html) $i = $Html.IndexOf('<section class="view" id="licensing">'); if ($i -lt 0) { return '' }; $j = $Html.IndexOf('Seats Assigned', $i); if ($j -lt 0) { $j = [math]::Min($Html.Length, $i + 20000) }; ($Html.Substring($i, $j - $i) -replace '<[^>]+>', ' ') }
        $env:TENANTKEEP_PRICE_FILE = $null
    }
    AfterAll { if (Test-Path $script:LicRoot) { Remove-Item -LiteralPath $script:LicRoot -Recurse -Force } }

    It 'states one recommendation with its reasons, in the report, report.md and findings.json' {
        $null = New-PostureReport -Evidence $script:LicEvidence 6>$null 3>$null
        $html = Get-Content -Raw (Get-ChildItem $script:LicRoot -Recurse -Filter 'report.html' | Select-Object -First 1).FullName
        $html | Should -Match '<h3>What To Add</h3>'
        $html | Should -Match '<span class="chip">Recommended</span> Add Microsoft Entra ID P2 to Microsoft 365 Business Premium'
        $html | Should -Match 'Covers: [^<]*Administrator roles just in time'
        # The rendered card, not the page script's template for one: the script's copy is followed by a quote, not a title.
        @([regex]::Matches($html, 'class="advice-card advice-rec"><h4><span class="chip">Recommended</span> [A-Z]')).Count | Should -Be 1 -Because 'one combination, not a list to compare'
        $html | Should -Match 'Partly assigned</span> <span class="muted">20 of 38 users' -Because 'Intune is switched on for 20 of 38 licensed users'
        $html | Should -Match '2 paid seats are not assigned to anyone\.'
        $html | Should -Match 'id="goals-unmet-only"'
        (& $script:Section $html) | Should -Not -Match $script:CostWords
        $md = Get-Content -Raw (Get-ChildItem $script:LicRoot -Recurse -Filter 'report.md' | Select-Object -First 1).FullName
        $md | Should -Match '## Licensing'
        $md | Should -Match 'Recommended: Add Microsoft Entra ID P2 to Microsoft 365 Business Premium\.'
        $doc = Get-Content -Raw (Get-ChildItem $script:LicRoot -Recurse -Filter 'findings.json' | Select-Object -First 1).FullName | ConvertFrom-Json
        $doc.licensing.advice.recommended.licences[0].sku | Should -Be 'AAD_PREMIUM_P2'
        $doc.licensing.featuresPartlyAssigned | Should -Contain 'Microsoft Intune Plan 1'
        Get-ChildItem $script:LicRoot -Recurse -Filter 'licensing-basis.json' | Should -BeNullOrEmpty -Because 'no price file was named'
    }

    It 'leaves a licence Microsoft gives away out of the paid seats nobody uses: one it knows by name, and any with a million seats' {
        $skuFile = Join-Path $script:LicEvidence '01-subscribed-skus.json'
        $before = Get-Content -Raw -LiteralPath $skuFile
        try {
            $skus = @($before | ConvertFrom-Json -AsHashtable)
            $skus += @{ skuPartNumber = 'FLOW_FREE'; skuId = 's2'; capabilityStatus = 'Enabled'; consumedUnits = 3; prepaidUnits = @{ enabled = 10000 }; servicePlans = @() }
            $skus += @{ skuPartNumber = 'SOMETHING_NEW_VIRAL'; skuId = 's3'; capabilityStatus = 'Enabled'; consumedUnits = 0; prepaidUnits = @{ enabled = 1000000 }; servicePlans = @() }
            ConvertTo-Json -InputObject $skus -Depth 6 | Set-Content -LiteralPath $skuFile
            $out = Join-Path $script:LicRoot 'given-away'
            $null = New-PostureReport -Evidence $script:LicEvidence -OutputPath $out -Format Html 6>$null 3>$null
            $html = Get-Content -Raw (Get-ChildItem $out -Recurse -Filter 'report.html' | Select-Object -First 1).FullName
            $html | Should -Match '<p class="takeaway">2 paid seats are not assigned to anyone\. 2 licences Microsoft gives away are left out of the count\.</p>' -Because 'ten thousand free Power Automate seats and a million of anything are not seats someone bought'
            $html | Should -Match '<span class="seat-name">Microsoft 365 Business Premium <code>SPB</code></span>'
            $html | Should -Match '<td>Microsoft Power Automate Free \(FLOW_FREE\)</td><td>10000</td><td>3</td><td>9997</td><td>given away</td>'
            $html | Should -Match '<td>SOMETHING_NEW_VIRAL</td><td>1000000</td><td>0</td><td>1000000</td><td>given away</td>' -Because 'a licence the list has never heard of is recognised by its million seats'
            $html | Should -Not -Match '<span class="seat-frac">\d+ of 10000</span>|<span class="seat-frac">\d+ of 1000000</span>'
        }
        finally { Set-Content -LiteralPath $skuFile -Value $before -NoNewline }
    }

    It 'chooses with a price file and lets no price, total or cost word into anything it writes for the customer' {
        $said = New-PostureReport -Evidence $script:LicEvidence -PriceFile $script:LicPrices -Redact 6>&1 3>&1 | ForEach-Object { [string]$_ }
        $files = @(Get-ChildItem $script:LicRoot -Recurse -File | Where-Object { $_.FullName -notlike (Join-Path $script:LicRoot 'prices' '*') })
        $html = Get-Content -Raw ($files | Where-Object { $_.Name -eq 'report.html' -and $_.FullName -notmatch '[\\/]share[\\/]' } | Select-Object -First 1).FullName
        $html | Should -Match '<span class="chip">Recommended</span> Move to Microsoft 365 E5' -Because 'at these made-up prices the move adds less than the add-on'
        @([regex]::Matches($html, 'class="advice-card advice-rec"><h4><span class="chip">Recommended</span> [A-Z]')).Count | Should -Be 1
        (& $script:Section $html) | Should -Not -Match $script:CostWords
        # Every file of the run, the redacted copies and the logs included: none holds a number from the price file.
        foreach ($f in $files) { (Get-Content -Raw -LiteralPath $f.FullName) | Should -Not -Match $script:Sentinel -Because "$($f.Name) must hold no price" }
        # The page's own data: nothing to choose by price with.
        $page = [regex]::Match($html, '(?s)<script[^>]*id="data-licensing"[^>]*>(.*?)</script>').Groups[1].Value
        $page | Should -Not -BeNullOrEmpty
        $page | Should -Not -Match '(?i)"(price|cost|erp|listPrice)[A-Za-z]*"'
        # What the person running the report is told, and what the logs keep.
        ($said -join "`n") | Should -Match 'Licence prices: licenses\.csv, checked \d{4}-\d\d-\d\d \(3 day\(s\) ago\), US USD, one-year term billed monthly; \d+ licence\(s\) priced\.'
        ($said -join "`n") | Should -Match 'The licence recommendation was chosen with these prices\.'
        ($said -join "`n") | Should -Not -Match $script:Sentinel
        $basis = Get-Content -Raw ($files | Where-Object Name -EQ 'licensing-basis.json' | Select-Object -First 1).FullName | ConvertFrom-Json
        $basis.choice.mode | Should -Be 'priced'
        $basis.priceFile.term | Should -Be 'P1Y'
        $basis.priceFile.market | Should -Be 'US'
        ($files | Where-Object Name -EQ 'licensing-basis.json').FullName | Should -Not -Match '[\\/]share[\\/]'
        @($files | Where-Object { $_.FullName -match '[\\/]share[\\/]' -and $_.Name -eq 'licensing-basis.json' }) | Should -BeNullOrEmpty
    }

    It 'warns when the prices were last checked more than 35 days ago' {
        Set-Content -LiteralPath (Join-Path (Split-Path $script:LicPrices) 'licenses.meta.json') -Value (@{ checkedUtc = [datetime]::UtcNow.AddDays(-40).ToString('yyyy-MM-ddTHH:mm:ssZ'); market = 'US'; currency = 'USD' } | ConvertTo-Json)
        $warned = @()
        $null = New-PostureReport -Evidence $script:LicEvidence -PriceFile $script:LicPrices -WarningVariable warned -WarningAction SilentlyContinue 6>$null
        ($warned -join ' ') | Should -Match 'last checked 40 days ago, more than 35'
    }

    It 'reads the file named in TENANTKEEP_PRICE_FILE when no parameter is given, and keeps the record out of a folder that may be handed on' {
        $out = Join-Path $script:LicRoot 'handover'
        $env:TENANTKEEP_PRICE_FILE = $script:LicPrices
        try { $said = New-PostureReport -Evidence $script:LicEvidence -OutputPath $out 6>&1 3>&1 | ForEach-Object { [string]$_ } }
        finally { $env:TENANTKEEP_PRICE_FILE = $null }
        ($said -join "`n") | Should -Match 'Licence prices: licenses\.csv'
        Join-Path $out 'report.html' | Should -Exist
        Join-Path $out 'licensing-basis.json' | Should -Not -Exist
        foreach ($f in Get-ChildItem $out -Recurse -File) { (Get-Content -Raw -LiteralPath $f.FullName) | Should -Not -Match $script:Sentinel }
    }
}
