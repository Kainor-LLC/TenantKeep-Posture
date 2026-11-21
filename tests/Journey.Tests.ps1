# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Write = { param([string] $Dir, [string] $Name, $Data) New-Item -ItemType Directory -Path $Dir -Force | Out-Null; ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }
}

Describe 'Journeys' {
    It 'ships journeys that name only catalog checks, in plain words' {
        InModuleScope TenantKeep.Posture {
            $c = Import-PostureCheckCatalog
            $j = @(Get-PostureJourneyResult -Catalog $c -Result @())
            $j.Count | Should -BeGreaterThan 2
            foreach ($x in $j) { @($x.steps).Count | Should -BeGreaterThan 2; $x.known | Should -Be 0 -Because 'nothing was evaluated' }
            Get-Content -Raw (Join-Path $c.path 'journeys.json') | Should -Not -Match ([char]0x2014)
        }
    }

    It 'turns each step on, off or unknown from its check, and refuses a check the catalog lacks' {
        InModuleScope TenantKeep.Posture {
            $c = Import-PostureCheckCatalog
            $res = @([ordered]@{ id = 'UX-013'; status = 'pass' }, [ordered]@{ id = 'UX-011'; status = 'fail' }, [ordered]@{ id = 'UX-012'; status = 'coveredBy' })
            $sign = @(Get-PostureJourneyResult -Catalog $c -Result $res | Where-Object id -eq 'JR-002')[0]
            @($sign.steps[0..2] | ForEach-Object { $_.state }) | Should -Be @('on', 'off', 'on')
            $sign.steps[3].state | Should -Be 'unknown'
            $sign.on | Should -Be 2
            $sign.known | Should -Be 3
            $bad = Join-Path $TestDrive 'journeys.json'
            '{ "journeys": [ { "id": "JR-009", "name": "x", "domain": "experience", "steps": [ { "check": "XX-999", "label": "y" } ] } ] }' | Set-Content $bad
            { Get-PostureJourneyResult -Catalog $c -Path $bad } | Should -Throw "*XX-999*not in the catalog*"
        }
    }

    It 'draws journeys, Global Secure Access and the hybrid picture in the Domains view' {
        $d = Join-Path $TestDrive 'areas'
        & $script:Write $d '09-intune-config-profiles-settings-catalog' @()
        & $script:Write $d '09-intune-policy-settings' @()
        & $script:Write $d 'ad-03-privileged-groups' @(@{ Group = 'Domain Admins'; SamAccountName = 'a' }, @{ Group = 'Domain Admins'; SamAccountName = 'b' }, @{ Group = 'Schema Admins'; SamAccountName = 'a' })
        InModuleScope TenantKeep.Posture -Parameters @{ D = $d } {
            $facts = @{
                network = @{ microsoftProfileEnabled = $true; internetProfileEnabled = $false; privateProfileEnabled = $true; webFilteringPolicies = 2; signalingEnabled = $false }
                hybrid  = @{ krbtgtPasswordAgeDays = 400; seamlessSsoKeyAgeDays = 10; kerberoastableAccounts = 1; asrepRoastableAccounts = 0; unconstrainedDelegationNonDc = 0; gposWithCpassword = 0; staleEnabledUsers = 4; operatorGroupMembers = 0 }
            }
            $c = Get-PostureChartData -Evidence $D -DomainFacts $facts
            $c.networkProfiles.takeaway | Should -Be '2 of 3 traffic profiles are forwarding through Global Secure Access.'
            @($c.privilegedGroups.item | ForEach-Object { "$($_.label)=$($_.value)" }) | Should -Be @('Domain Admins=2', 'Schema Admins=1')
            @($c.keyAges.item | ForEach-Object { $_.tone }) | Should -Be @('err', 'ok')
            @($c.adExposure.rows | Where-Object { $_.value -gt 0 } | ForEach-Object { $_.label }) | Should -Be @('Kerberoastable accounts', 'Stale enabled users')
        }
        $rep = New-PostureReport -Evidence $d -OutputPath (Join-Path $TestDrive 'out') -PassThru 6>$null
        $html = Get-Content -Raw ($rep.Files | Where-Object { $_ -like '*report.html' })
        $html | Should -Match 'A new Windows laptop'
        $html | Should -Match '<ol class="journey">'
        $html | Should -Match 'Not read yet: the next collection fills these steps in'
        $html | Should -Match 'Privileged Group Members'
    }
}
