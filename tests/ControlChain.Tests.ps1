# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-chain-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'DEV-015, the chain''s middle link' {
    It 'is not evaluated, not failed, on compliance policies collected before the device risk setting was read' {
        $ev = Join-Path $script:Root 'old-intune'
        New-Item -ItemType Directory -Path $ev -Force | Out-Null
        '[ { "Id": "cp1", "DisplayName": "Windows", "Type": "windows10CompliancePolicy", "Assignments": 1 } ]' | Set-Content (Join-Path $ev '09-intune-compliance-policies.json')
        InModuleScope TenantKeep.Posture -Parameters @{ Ev = $ev } {
            param($Ev)
            Clear-PostureEvidenceCache
            $f = Get-PostureDevicesFact -Evidence $Ev
            $f.notEvaluated['DEV-015'] | Should -Match 'collected before'
            $f.facts.Contains('compliancePlatformsWithoutDeviceRisk') | Should -BeFalse
        }
    }
}

Describe 'Control chains' {
    It 'ships chains whose every link is a check in the catalog' {
        InModuleScope TenantKeep.Posture {
            $chains = @(Import-PostureControlChain -Catalog (Import-PostureCheckCatalog))
            $chains.Count | Should -BeGreaterOrEqual 3
            $chains[0].links.check | Should -Be @('DEV-012', 'DEV-015', 'CA-005')
        }
        Get-Content -Raw (Join-Path $PSScriptRoot '..' 'checks' 'chains.json') | Should -Not -Match ([char]0x2014)
    }

    It 'refuses a link to a check that is not in the catalog, and a chain of one' {
        InModuleScope TenantKeep.Posture -Parameters @{ Root = $script:Root } {
            param($Root)
            $catalog = [ordered]@{ path = $Root; checks = @(@{ id = 'XX-001' }, @{ id = 'XX-002' }) }
            $p = Join-Path $Root 'chains.json'
            '{ "chains": [ { "id": "CH-001", "name": "n", "why": "w", "links": [ { "check": "XX-001", "role": "r" }, { "check": "XX-009", "role": "r" } ] } ] }' | Set-Content $p
            { Import-PostureControlChain -Catalog $catalog } | Should -Throw "*'XX-009', which is not in the catalog*"
            '{ "chains": [ { "id": "CH-001", "name": "n", "why": "w", "links": [ { "check": "XX-001", "role": "r" } ] } ] }' | Set-Content $p
            { Import-PostureControlChain -Catalog $catalog } | Should -Throw '*at least two links*'
            Import-PostureControlChain -Catalog ([ordered]@{ checks = @() }) | Should -BeNullOrEmpty -Because 'a catalog with no folder has no chains'
        }
    }

    It 'holds when every link holds, breaks at the first failure, is incomplete while a link is unknown, and skips chains outside the run' {
        InModuleScope TenantKeep.Posture {
            $chain = @(
                [ordered]@{ id = 'CH-001'; name = 'n'; why = 'w'; links = @([ordered]@{ check = 'A-001'; role = 'r' }, [ordered]@{ check = 'A-002'; role = 'r' }, [ordered]@{ check = 'A-003'; role = 'r' }) }
            )
            # The comma keeps a one-chain answer an array: an ordered dictionary indexed with [0] returns its first value.
            $judge = { param([string[]] $s) , @(Get-PostureControlChainResult -Chain $chain -Result @(0..2 | Where-Object { $s[$_] } | ForEach-Object { @{ id = "A-00$($_ + 1)"; title = "t$_"; status = $s[$_]; severity = 'High' } })) }
            (& $judge 'pass', 'acceptedRisk', 'coveredBy')[0].status | Should -Be 'pass'
            $b = (& $judge 'pass', 'fail', 'fail')[0]
            $b.status | Should -Be 'broken'
            $b.brokenAt | Should -Be 'A-002' -Because 'the first failing link is the one to fix first'
            $b.held | Should -Be 1
            (& $judge 'pass', 'notEvaluated', 'pass')[0].status | Should -Be 'notEvaluated'
            (& $judge 'pass', $null, 'pass')[0].status | Should -Be 'notEvaluated' -Because 'a link outside the run is unknown'
            & $judge 'notApplicable', 'notApplicable', $null | Should -BeNullOrEmpty
        }
    }
}
