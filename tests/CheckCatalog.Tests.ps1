# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeDiscovery {
    $script:CheckFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot '..' 'checks') -Filter '*.json' | Where-Object Name -NotIn 'attack.json', 'catalog.json', 'chains.json', 'facts.json', 'journeys.json', 'layers.json', 'outcomes.json' | ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
    $script:BaselineFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot '..' 'baselines') -Filter '*.json' | ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
}

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
}

Describe 'Shipped check catalog' {
    It 'loads and validates as a whole' {
        InModuleScope TenantKeep.Posture {
            $c = Import-PostureCheckCatalog
            $c.version | Should -Match '^\d{4}\.\d{1,2}\.\d+$'
            $c.checks | ForEach-Object { $_.custom | Should -BeFalse }
        }
    }

    It 'says what changed in each catalog version, in plain words, for checks that exist' {
        InModuleScope TenantKeep.Posture {
            $c = Import-PostureCheckCatalog
            $ids = @($c.checks | ForEach-Object { [string]$_['id'] })
            @($c.changes).Count | Should -BeGreaterThan 0
            foreach ($entry in $c.changes) {
                [string]$entry['version'] | Should -Match '^\d{4}\.\d{1,2}\.\d+$'
                [version]$entry['version'] | Should -BeLessOrEqual ([version]$c.version) -Because 'a change is recorded under the version that carries it'
                [string]$entry['date'] | Should -Match '^\d{4}-\d{2}-\d{2}$'
                [string]$entry['summary'] | Should -Not -Match "\u2014|not just" -Because 'user-facing text: plain English'
                foreach ($k in $entry['checks'].get_Keys()) {
                    $k | Should -BeIn $ids
                    [string]$entry['checks'][$k] | Should -Match '\.$' -Because 'a sentence the trend prints as it is'
                }
            }
        }
    }

    It 'refuses a change that names a check the catalog does not have' {
        InModuleScope TenantKeep.Posture {
            $dir = Join-Path $TestDrive 'bad-changes'
            Copy-Item -Recurse -LiteralPath (Get-PostureDataFolder -Name 'checks') -Destination $dir
            $file = Join-Path $dir 'catalog.json'
            $doc = Get-Content -Raw -LiteralPath $file | ConvertFrom-Json -AsHashtable -Depth 10
            $doc['changes'][0]['checks']['ZZ-999'] = 'No such check.'
            ConvertTo-Json -InputObject $doc -Depth 10 | Set-Content -LiteralPath $file
            { Import-PostureCheckCatalog -Path $dir } | Should -Throw "*names 'ZZ-999', which is not a check*"
        }
    }

    It 'labels every fact a pass expression reads and every threshold, in plain words (checks/facts.json)' {
        InModuleScope TenantKeep.Posture {
            $c = Import-PostureCheckCatalog
            foreach ($check in $c.checks) {
                foreach ($m in [regex]::Matches([string]$check.pass, 'facts\.([A-Za-z0-9_]+)')) { $c.labels.facts.Keys | Should -Contain $m.Groups[1].Value -Because "$($check.id) shows that value on its card" }
                foreach ($t in @($check.thresholds.Keys)) { $c.labels.thresholds.Keys | Should -Contain $t -Because "$($check.id) shows that threshold on its card" }
            }
            Get-Content -Raw (Join-Path $c.path 'facts.json') | Should -Not -Match ([char]0x2014)
        }
    }

    It 'names only ATT&CK techniques in checks/attack.json, which is the pinned release and lists exactly the techniques used' {
        InModuleScope TenantKeep.Posture {
            $c = Import-PostureCheckCatalog
            $pin = (Get-Content -Raw (Join-Path $c.path 'catalog.json') | ConvertFrom-Json).attack.version
            $c.attack.version | Should -Be $pin -Because 'run build.ps1 -Task AttackData with the pinned release after moving the pin'
            $used = @($c.checks | Where-Object { $_.Contains('attack') } | ForEach-Object { @($_.attack) } | Sort-Object -Unique)
            @($c.attack.techniques.Keys | Sort-Object) | Should -Be $used -Because 'run build.ps1 -Task AttackData after changing a check''s attack ids'
            $tactics = @($c.attack.tactics | ForEach-Object { $_.key })
            foreach ($t in $c.attack.techniques.Values) {
                $t.name | Should -Not -BeNullOrEmpty
                $t.url | Should -Match '^https://attack\.mitre\.org/techniques/T\d{4}(/\d{3})?/$'
                @($t.tactics).Count | Should -BeGreaterThan 0
                foreach ($k in @($t.tactics)) { $tactics | Should -Contain $k }
            }
            $c.attack.notice | Should -Match 'The MITRE Corporation' -Because 'MITRE''s terms of use ask for the copyright designation in every copy'
            @($c.checks | Where-Object { $_.domain -eq 'experience' -and $_.Contains('attack') }).Count | Should -Be 0 -Because 'user experience improvements are not defences'
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
                (@($c.remediation) -join ' ').Length | Should -BeGreaterThan 30 -Because "$($c.id) needs real remediation"
                if ($c.remediation -is [array]) { foreach ($s in $c.remediation) { ([string]$s).Length | Should -BeGreaterThan 10 -Because "$($c.id) steps are whole actions" } }
                $c.userImpact.level | Should -BeIn @('none', 'low', 'medium', 'high') -Because "$($c.id) says what users notice when it is fixed"
                ([string]$c.userImpact.text).Length | Should -BeGreaterThan 20 -Because "$($c.id) user impact is a sentence"
                $c.learn | Should -Match '^https://learn\.microsoft\.com/'
                foreach ($k in $c.frameworks.Keys) { ([string]$c.frameworks[$k]).Length | Should -BeLessThan 40 -Because 'framework fields hold identifiers, never benchmark text' }
                $c.deepLink | Should -Match '^https://' -Because 'every check links to the portal page where the setting lives'
            }
        }

        It 'every pass expression parses against its own thresholds' {
            InModuleScope TenantKeep.Posture -Parameters @{ Doc = $script:Doc } {
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
            InModuleScope TenantKeep.Posture -Parameters @{ P = $Path } {
                $b = Import-PostureBaseline -Baseline $P
                $known = @((Import-PostureCheckCatalog).checks | ForEach-Object { $_.id })
                foreach ($id in @($b.checks | Where-Object { $_ -ne '*' -and $_ -notlike 'domain:*' -and $_ -notlike 'framework:*' }) + @($b.exclude) + @($b.thresholds.Keys) + @($b.severity.Keys)) { $known | Should -Contain $id }
                $domains = @((Import-PostureCheckCatalog).checks | ForEach-Object { $_.domain } | Sort-Object -Unique)
                foreach ($sel in @($b.checks | Where-Object { $_ -like 'domain:*' })) { $domains | Should -Contain $sel.Substring(7) }
                foreach ($sel in @($b.checks | Where-Object { $_ -like 'framework:*' })) { @('nist-csf-2', 'iso27001', 'cmmc', 'cisa-scuba') | Should -Contain $sel.Substring(10) }
            }
        }

        It 'selects at least one check and its crosswalk references resolve to mapped checks' {
            InModuleScope TenantKeep.Posture -Parameters @{ P = $Path } {
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
