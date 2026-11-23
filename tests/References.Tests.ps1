# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
}

Describe 'Public references the catalog is measured against' {
    It 'accounts for every item of every reference: a check names it, or it has a reason' {
        InModuleScope TenantKeep.Posture {
            $coverage = Get-PostureReferenceCoverage -Catalog (Import-PostureCheckCatalog)
            @($coverage).Count | Should -BeGreaterThan 0
            foreach ($reference in $coverage) {
                $reference.problems | Should -BeNullOrEmpty -Because "$($reference.name) $($reference.version): an item needs a check or a reason, and a check may only name an id the reference has"
                $reference.counts.covered + $reference.counts.planned + $reference.counts.noReadApi + $reference.counts.outOfScope + $reference.counts.passThrough | Should -Be $reference.counts.total
            }
        }
    }

    It 'covers CISA SCuBA v2.0.0 as far as the changelog says' {
        InModuleScope TenantKeep.Posture {
            $scuba = @(Get-PostureReferenceCoverage -Catalog (Import-PostureCheckCatalog) | Where-Object { $_.name -eq 'cisa-scuba' })[0]
            $scuba.version | Should -Be 'v2.0.0'
            $scuba.counts.total | Should -Be 109
            $scuba.counts.covered | Should -BeGreaterOrEqual 55 -Because 'coverage only goes up; lower this number and the changelog says why'
            @($scuba.items | Where-Object { $_.id -eq 'MS.AAD.1.1v1' })[0].checks | Should -Be @('CA-001', 'ID-016')
            @($scuba.items | Where-Object { $_.id -eq 'MS.EXO.4.3v1' })[0].reason | Should -Be 'outOfScope'
        }
    }

    It 'accounts for every Maester test in the families compared so far' {
        InModuleScope TenantKeep.Posture {
            $catalog = Import-PostureCheckCatalog
            $maester = @(Get-PostureReferenceCoverage -Catalog $catalog | Where-Object { $_.name -eq 'maester' })[0]
            $maester.version | Should -Be '2.3.0'
            @($catalog.references['maester']['families']) | Should -Contain 'eidsca'
            @($catalog.references['maester']['families']) | Should -Contain 'orca'
            $maester.counts.total | Should -BeGreaterOrEqual 111 -Because 'a family is added once its tests have been compared with the catalog'
            $maester.counts.covered | Should -BeGreaterOrEqual 41
            @($maester.items | Where-Object { $_.id -eq 'EIDSCA.AT01' })[0].checks | Should -Be @('AU-005')
            @($maester.items | Where-Object { $_.id -eq 'ORCA.120.1' })[0].checks | Should -Be @('EM-006')
            @($maester.items | Where-Object { $_.id -like 'CIS.*' }).Count | Should -Be 0 -Because 'CIS benchmark content is licensed and is not reproduced'
        }
    }

    It 'knows every Secure Score action a check names, and counts the rest as shown from Microsoft''s own evaluation' {
        InModuleScope TenantKeep.Posture {
            $score = @(Get-PostureReferenceCoverage -Catalog (Import-PostureCheckCatalog) | Where-Object { $_.name -eq 'secure-score' })[0]
            $score.counts.total | Should -BeGreaterOrEqual 461 -Because 'the list only grows: a tenant adds the actions for its products'
            $score.counts.covered | Should -BeGreaterOrEqual 103
            $score.counts.covered + $score.counts.passThrough | Should -Be $score.counts.total -Because 'an action with no check still reaches the report, so it needs no reason'
            @($score.items | Where-Object { $_.id -eq 'BlockLegacyAuthentication' })[0].checks | Should -Be @('CA-001')
            $catalog = @{
                checks     = @([ordered]@{ id = 'AA-001'; frameworks = @{}; references = @{ secureScore = @('RealAction', 'DLPEnabled') } })
                references = [ordered]@{ 'secure-score' = @{ name = 'secure-score'; title = 't'; version = '1'; source = ''; passThrough = $true; checkKeys = @{ reference = 'secureScore' }; items = [ordered]@{ RealAction = 'one'; OtherAction = 'two' }; notCovered = @{} } }
            }
            $r = @(Get-PostureReferenceCoverage -Catalog $catalog)[0]
            $r.counts.covered | Should -Be 1
            $r.counts.passThrough | Should -Be 1
            @($r.problems) | Should -Be @('AA-001 names DLPEnabled, which secure-score 1 does not have') -Because 'an id written from memory that Microsoft does not have is the mistake this catches'
        }
    }

    It 'reports each kind of problem by name' {
        InModuleScope TenantKeep.Posture {
            $catalog = @{
                checks     = @(
                    [ordered]@{ id = 'AA-001'; frameworks = @{ 'made-up' = 'R.1' } }
                    [ordered]@{ id = 'AA-002'; frameworks = @{ 'made-up' = '' }; references = @{ madeUp = @('R.2', 'R.9') } }
                    [ordered]@{ id = 'AA-003'; frameworks = @{}; references = @{ madeUp = @('R.3') } }
                    [ordered]@{ id = 'ZZ-900'; custom = $true; frameworks = @{ 'made-up' = 'R.5' } }
                )
                references = [ordered]@{
                    'made-up' = @{
                        name = 'made-up'; title = 'A made-up reference'; version = '1'; source = ''; checkKeys = @{ framework = 'made-up'; reference = 'madeUp' }
                        items = [ordered]@{ 'R.1' = 'one'; 'R.2' = 'two'; 'R.3' = 'three'; 'R.4' = 'four'; 'R.5' = 'five'; 'R.6' = 'six'; 'R.7' = 'seven'; 'R.8' = 'eight' }
                        notCovered = [ordered]@{
                            'R.3' = @{ reason = 'planned'; note = 'Also named by a check.' }
                            'R.4' = @{ reason = 'noReadApi'; note = 'Portal only.' }
                            'R.6' = @{ reason = 'someday'; note = 'x' }
                            'R.7' = @{ reason = 'planned'; note = ' ' }
                            'R.8' = @{ reason = 'outOfScope'; note = 'Not for these tenants.' }
                            'R.0' = @{ reason = 'planned'; note = 'Not in the reference.' }
                        }
                    }
                }
            }
            $r = @(Get-PostureReferenceCoverage -Catalog $catalog)[0]
            $r.counts.total | Should -Be 8
            $r.counts.covered | Should -Be 2 -Because 'R.1 and R.2; R.3 is in dispute and a custom check does not count'
            $r.counts.noReadApi | Should -Be 1
            $r.counts.outOfScope | Should -Be 1
            $r.counts.planned | Should -Be 0
            $text = $r.problems -join "`n"
            $text | Should -Match 'AA-002 names R\.9, which made-up 1 does not have'
            $text | Should -Match 'R\.3 is named by AA-003 and also listed as not covered'
            $text | Should -Match 'R\.5 has no check and no reason'
            $text | Should -Match "R\.6 has the reason 'someday'"
            $text | Should -Match 'R\.7 is not covered and its note is empty'
            $text | Should -Match 'notCovered lists R\.0'
            @($r.problems).Count | Should -Be 6
            @(Get-PostureReferenceCoverage -Catalog @{ checks = @() }).Count | Should -Be 0
        }
    }

    It 'refuses a reference file without its name, items or check keys' {
        InModuleScope TenantKeep.Posture {
            $dir = Join-Path $TestDrive 'bad-reference'
            New-Item -ItemType Directory -Path (Join-Path $dir 'references') -Force | Out-Null
            '{ "domain": "identity", "checks": [] }' | Set-Content (Join-Path $dir 'identity.json')
            '{ "name": "x", "items": [] }' | Set-Content (Join-Path $dir 'references' 'x.json')
            { Import-PostureCheckCatalog -Path $dir } | Should -Throw '*needs name, items and checkKeys*'
        }
    }
}
