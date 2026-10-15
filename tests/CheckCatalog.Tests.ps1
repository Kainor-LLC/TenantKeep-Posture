# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeDiscovery {
    $script:CheckFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot '..' 'checks') -Filter '*.json' | Where-Object Name -ne 'catalog.json' | ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
    $script:BaselineFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot '..' 'baselines') -Filter '*.json' | ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
}

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
}

Describe 'Shipped check catalog' {
    It 'loads and validates as a whole' {
        InModuleScope Tenantkeep.Posture {
            $c = Import-PostureCheckCatalog
            $c.version | Should -Match '^\d{4}\.\d{1,2}\.\d+$'
            $c.checks | ForEach-Object { $_.custom | Should -BeFalse }
        }
    }

    Context 'file <Name>' -ForEach $script:CheckFiles -AllowNullOrEmptyForEach {
        BeforeAll { $script:Doc = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -AsHashtable -Depth 20 }

        It 'names its domain and the checks carry it' {
            $script:Doc.domain | Should -Match '^[a-z]+$'
            foreach ($c in $script:Doc.checks) { $c.domain | Should -Be $script:Doc.domain }
        }

        It 'every check has non-empty narrative, remediation and a Learn link, and only reference numbers for frameworks' {
            foreach ($c in $script:Doc.checks) {
                $c.narrative.Length | Should -BeGreaterThan 60 -Because "$($c.id) needs a real narrative"
                $c.remediation.Length | Should -BeGreaterThan 30 -Because "$($c.id) needs real remediation"
                $c.learn | Should -Match '^https://learn\.microsoft\.com/'
                foreach ($k in $c.frameworks.Keys) { ([string]$c.frameworks[$k]).Length | Should -BeLessThan 40 -Because 'framework fields hold identifiers, never benchmark text' }
            }
        }

        It 'every pass expression parses against its own thresholds' {
            InModuleScope Tenantkeep.Posture -Parameters @{ Doc = $script:Doc } {
                foreach ($c in $Doc.checks) {
                    $ids = [regex]::Matches($c.pass, 'facts\.[A-Za-z0-9_.]+') | ForEach-Object { $_.Value.Substring(6) } | Select-Object -Unique
                    $facts = @{}; foreach ($i in $ids) { $facts[$i.Split('.')[0]] = 0 }
                    { Invoke-PostureExpression -Expression $c.pass -Context @{ facts = $facts; thresholds = $c.thresholds } } | Should -Not -Throw -Because "$($c.id) pass expression must parse"
                }
            }
        }

        It 'has no em dash in user-facing text' {
            Get-Content -Raw -LiteralPath $Path | Should -Not -Match ([char]0x2014)
        }
    }

    Context 'baseline <Name>' -ForEach $script:BaselineFiles {
        It 'loads and references only known check ids' {
            InModuleScope Tenantkeep.Posture -Parameters @{ P = $Path } {
                $b = Import-PostureBaseline -Baseline $P
                $known = @((Import-PostureCheckCatalog).checks | ForEach-Object { $_.id })
                foreach ($id in @($b.checks | Where-Object { $_ -ne '*' -and $_ -notlike 'domain:*' -and $_ -notlike 'framework:*' }) + @($b.exclude) + @($b.thresholds.Keys) + @($b.severity.Keys)) { $known | Should -Contain $id }
                $domains = @((Import-PostureCheckCatalog).checks | ForEach-Object { $_.domain } | Sort-Object -Unique)
                foreach ($sel in @($b.checks | Where-Object { $_ -like 'domain:*' })) { $domains | Should -Contain $sel.Substring(7) }
                foreach ($sel in @($b.checks | Where-Object { $_ -like 'framework:*' })) { @('nist-csf-2', 'iso27001', 'cmmc', 'cisa-scuba', 'cis-m365') | Should -Contain $sel.Substring(10) }
            }
        }

        It 'selects at least one check and its crosswalk references resolve to mapped checks' {
            InModuleScope Tenantkeep.Posture -Parameters @{ P = $Path } {
                $b = Import-PostureBaseline -Baseline $P
                $catalog = Import-PostureCheckCatalog
                $run = Invoke-PostureCheckEvaluation -Catalog $catalog -Baseline $b -OrgProfile (Import-PostureProfile) -Exception @() -Evidence (Join-Path ([System.IO.Path]::GetTempPath()) 'tkp-no-evidence')
                @($run.results).Count | Should -BeGreaterThan 0
                if ($b.crosswalk -and $b.crosswalk.Contains('controls')) {
                    $key = [string]$b.crosswalk.framework
                    $refs = @($catalog.checks | ForEach-Object { [string]$_.frameworks[$key] } | Where-Object { $_ })
                    foreach ($control in @($b.crosswalk.controls.Keys)) { foreach ($ref in @($b.crosswalk.controls[$control])) { $refs | Should -Contain $ref -Because "$control references $ref" } }
                }
            }
        }
    }
}
