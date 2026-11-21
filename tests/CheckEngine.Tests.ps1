# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    . (Join-Path $PSScriptRoot 'Fixtures' 'CheckEngineFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-engine-$([guid]::NewGuid().ToString('n'))"
    $script:Fx = Initialize-CheckEngineFixture -Root $script:Root
    $script:Evidence = Join-Path $script:Root 'evidence'
    New-Item -ItemType Directory -Path $script:Evidence | Out-Null
    # TS-001 names e.json as its evidence: the engine judges it only when the file is in the folder.
    Set-Content -LiteralPath (Join-Path $script:Evidence 'e.json') -Value '[]'
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
}

Describe 'Import-PostureCheckCatalog' {
    It 'loads the fixture catalog with its version' {
        InModuleScope TenantKeep.Posture -Parameters @{ P = $script:Fx.Checks } {
            $c = Import-PostureCheckCatalog -Path $P
            $c.version | Should -Be 'test.1'
            $c.checks.Count | Should -Be 7
            $c.checks[0].id | Should -Be 'OT-001'
        }
    }

    It 'rejects a check with a missing field, a bad severity or a duplicate id' {
        $bad = Join-Path $script:Root 'bad'
        New-Item -ItemType Directory -Path $bad -Force | Out-Null
        '{ "domain": "x", "checks": [ { "id": "XX-001", "title": "t" } ] }' | Set-Content (Join-Path $bad 'x.json')
        InModuleScope TenantKeep.Posture -Parameters @{ P = $bad } { { Import-PostureCheckCatalog -Path $P } | Should -Throw "*XX-001*missing: domain, severityDefault*" }
        '{ "domain": "x", "checks": [ { "id": "XX-001", "domain": "x", "title": "t", "severityDefault": "Urgent", "license": [], "applicableWhen": {}, "coveredBy": [], "thresholds": {}, "evidence": [], "pass": "true", "remediation": "", "learn": "", "deepLink": null, "narrative": "", "frameworks": {} } ] }' | Set-Content (Join-Path $bad 'x.json')
        InModuleScope TenantKeep.Posture -Parameters @{ P = $bad } { { Import-PostureCheckCatalog -Path $P } | Should -Throw "*severityDefault 'Urgent'*" }
        Copy-Item (Join-Path $script:Fx.Checks 'test.json') (Join-Path $bad 'x.json') -Force
        Copy-Item (Join-Path $script:Fx.Checks 'test.json') (Join-Path $bad 'y.json') -Force
        InModuleScope TenantKeep.Posture -Parameters @{ P = $bad } { { Import-PostureCheckCatalog -Path $P } | Should -Throw '*Duplicate check id*' }
    }

    It 'takes remediation as a string or as steps, and checks effort and category' {
        $dir = Join-Path $script:Root 'shapes'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $base = '"domain": "x", "title": "t", "severityDefault": "High", "license": [], "applicableWhen": {}, "coveredBy": [], "thresholds": {}, "evidence": [], "pass": "true", "learn": "", "deepLink": null, "narrative": "", "frameworks": {}'
        "{ ""domain"": ""x"", ""checks"": [ { ""id"": ""XX-001"", $base, ""remediation"": ""Turn it on."" }, { ""id"": ""XX-002"", $base, ""remediation"": [""Open the policy."", "" Set it to On. ""], ""effort"": ""S"", ""category"": ""improve"", ""userImpact"": { ""level"": ""low"", ""text"": ""t"" } } ] }" | Set-Content (Join-Path $dir 'x.json')
        '{ "name": "not a domain file" }' | Set-Content (Join-Path $dir 'chains.json')
        InModuleScope TenantKeep.Posture -Parameters @{ P = $dir } {
            $c = @((Import-PostureCheckCatalog -Path $P).checks)
            $c.Count | Should -Be 2 -Because 'chains.json is not a domain file'
            $c[0].steps | Should -Be @('Turn it on.')
            $c[0].category | Should -Be 'fix'
            $c[1].steps | Should -Be @('Open the policy.', 'Set it to On.')
            $c[1].remediation | Should -Be 'Open the policy. Set it to On.' -Because 'text readers get one string'
            $c[1].effort | Should -Be 'S'
            $c[1].category | Should -Be 'improve'
        }
        foreach ($case in @(@('"remediation": [], ', '*no remediation*'), @('"remediation": "r", "effort": "XL", ', "*effort 'XL'*"), @('"remediation": "r", "category": "nice", ', "*category 'nice'*"), @('"remediation": "r", "impact": "i", ', '*became userImpact*'), @('"remediation": "r", "userImpact": { "level": "some" }, ', '*userImpact needs a level*'))) {
            "{ ""domain"": ""x"", ""checks"": [ { ""id"": ""XX-001"", $($case[0])$base } ] }" | Set-Content (Join-Path $dir 'x.json')
            InModuleScope TenantKeep.Posture -Parameters @{ P = $dir; E = $case[1] } { { Import-PostureCheckCatalog -Path $P } | Should -Throw $E }
        }
    }
}

Describe 'Invoke-PostureCheckEvaluation' {
    BeforeAll {
        InModuleScope TenantKeep.Posture -Parameters @{ Fx = $script:Fx; Ev = $script:Evidence } {
            $script:Catalog = Import-PostureCheckCatalog -Path $Fx.Checks
            $script:Std = Import-PostureBaseline -Baseline (Join-Path $Fx.Baselines 'standard.json')
            $script:Strict = Import-PostureBaseline -Baseline (Join-Path $Fx.Baselines 'strict.json')
            $script:NoProfile = Import-PostureProfile
            $script:Profile = Import-PostureProfile -Path $Fx.Profile
            $script:Exceptions = @(Import-PostureException -Path $Fx.Exceptions)
            $script:Provider = @{ test = $Fx.Provider }
            $script:Run = Invoke-PostureCheckEvaluation -Catalog $script:Catalog -Baseline $script:Std -OrgProfile $script:NoProfile -Evidence $Ev -FactProvider $script:Provider
            $script:ById = @{}; foreach ($r in $script:Run.results) { $script:ById[$r.id] = $r }
        }
    }

    It 'evaluates pass and fail from facts and thresholds' {
        InModuleScope TenantKeep.Posture {
            $script:ById['TS-001'].status | Should -Be 'fail'   # count 3 > max 2
            $script:ById['TS-001'].affectedCount | Should -Be 3
            $script:ById['TS-001'].evidence | Should -Contain 'provider.json'
            $script:ById['TS-001'].observed['count'] | Should -Be 3 -Because 'the report says what was found, not only that it failed'
            $script:ById['TS-002'].status | Should -Be 'pass'   # no profile, no license gate
            $script:ById['TS-006'].status | Should -Be 'fail'
            $script:ById['TS-006'].severity | Should -Be 'Critical'
        }
    }

    It 'marks a missing fact and a missing provider as not evaluated with the reason' {
        InModuleScope TenantKeep.Posture {
            $script:ById['TS-005'].status | Should -Be 'notEvaluated'
            $script:ById['TS-005'].reason | Should -Match "Data missing: Unknown reference 'facts.nope'"
            $script:ById['OT-001'].status | Should -Be 'notEvaluated'
            $script:ById['OT-001'].reason | Should -Match "No fact provider for domain 'other'"
        }
    }

    It 'applies the profile: license gate, applicability, third-party coverage, global thresholds' {
        InModuleScope TenantKeep.Posture -Parameters @{ Ev = $script:Evidence } {
            $run = Invoke-PostureCheckEvaluation -Catalog $script:Catalog -Baseline $script:Std -OrgProfile $script:Profile -Evidence $Ev -FactProvider $script:Provider
            $by = @{}; foreach ($r in $run.results) { $by[$r.id] = $r }
            $by['TS-002'].status | Should -Be 'notEvaluated'
            $by['TS-002'].reason | Should -Be 'Requires P2.'
            $by['TS-003'].status | Should -Be 'notApplicable'
            $by['TS-003'].reason | Should -Match 'platforms is windows'
            $by['TS-004'].status | Should -Be 'coveredBy'
            $by['TS-004'].coveredBy | Should -Be 'mfa:duo'
            $by['TS-001'].status | Should -Be 'pass' -Because 'the profile raises max to 3'
            $by['TS-001'].thresholds.max | Should -Be 3
        }
    }

    It 'treats a third-party category set to none as not covered' {
        InModuleScope TenantKeep.Posture -Parameters @{ Ev = $script:Evidence } {
            $p = Import-PostureProfile
            $p.present = $true; $p.thirdParty = @{ mfa = 'none' }
            $run = Invoke-PostureCheckEvaluation -Catalog $script:Catalog -Baseline $script:Std -OrgProfile $p -Evidence $Ev -FactProvider $script:Provider
            ($run.results | Where-Object id -eq 'TS-004').status | Should -Be 'pass'
        }
    }

    It 'applies the baseline: selection, per-check thresholds, severity override' {
        InModuleScope TenantKeep.Posture -Parameters @{ Ev = $script:Evidence } {
            $run = Invoke-PostureCheckEvaluation -Catalog $script:Catalog -Baseline $script:Strict -OrgProfile $script:NoProfile -Evidence $Ev -FactProvider $script:Provider
            @($run.results | ForEach-Object { $_.id }) | Should -Be @('TS-001', 'TS-006')
            ($run.results | Where-Object id -eq 'TS-001').status | Should -Be 'pass'
            ($run.results | Where-Object id -eq 'TS-001').thresholds.max | Should -Be 5
            ($run.results | Where-Object id -eq 'TS-006').severity | Should -Be 'Low'
            $run.baseline | Should -Be 'strict'
        }
    }

    It 'passes merged domain thresholds to the provider' {
        InModuleScope TenantKeep.Posture -Parameters @{ Ev = $script:Evidence } {
            $spy = @{ test = { param($Evidence, $OrgProfile, $Thresholds) $script:SeenThresholds = $Thresholds; @{ facts = @{ count = 0; enabled = $true } } } }
            $null = Invoke-PostureCheckEvaluation -Catalog $script:Catalog -Baseline $script:Strict -OrgProfile $script:NoProfile -Evidence $Ev -FactProvider $spy
            $script:SeenThresholds.max | Should -Be 5
        }
    }

    It 'turns a failing check into accepted risk through a check-level exception' {
        InModuleScope TenantKeep.Posture -Parameters @{ Ev = $script:Evidence } {
            $run = Invoke-PostureCheckEvaluation -Catalog $script:Catalog -Baseline $script:Std -OrgProfile $script:NoProfile -Exception $script:Exceptions -Evidence $Ev -FactProvider $script:Provider
            $r = $run.results | Where-Object id -eq 'TS-006'
            $r.status | Should -Be 'acceptedRisk'
            $r.reason | Should -Match 'Accepted risk: Known, scheduled \(owner J\. Smith, approver CISO, until 2099-01-01\)'
        }
    }

    It 'removes excepted objects from the affected list and ignores expired exceptions' {
        InModuleScope TenantKeep.Posture -Parameters @{ Ev = $script:Evidence } {
            $run = Invoke-PostureCheckEvaluation -Catalog $script:Catalog -Baseline $script:Std -OrgProfile $script:NoProfile -Exception $script:Exceptions -Evidence $Ev -FactProvider $script:Provider
            $r = $run.results | Where-Object id -eq 'TS-001'
            $r.status | Should -Be 'fail'
            @($r.affected | ForEach-Object { $_.name }) | Should -Be @('alpha', 'gamma') -Because 'beta is excepted and the gamma exception expired'
            $r.reason | Should -Match '1 object\(s\) accepted by exception; 2 remain\. 1 expired exception\(s\) ignored\.'
        }
    }

    It 'becomes accepted risk when every affected object is excepted' {
        InModuleScope TenantKeep.Posture -Parameters @{ Ev = $script:Evidence } {
            $all = @('alpha', 'beta', 'gamma' | ForEach-Object { [ordered]@{ check = 'TS-001'; object = $_; justification = 'ok'; owner = 'o'; approver = 'a'; expires = [datetime]'2099-01-01'; expired = $false } })
            $run = Invoke-PostureCheckEvaluation -Catalog $script:Catalog -Baseline $script:Std -OrgProfile $script:NoProfile -Exception $all -Evidence $Ev -FactProvider $script:Provider
            ($run.results | Where-Object id -eq 'TS-001').status | Should -Be 'acceptedRisk'
        }
    }

    It 'counts statuses and records the catalog version' {
        InModuleScope TenantKeep.Posture {
            $script:Run.catalogVersion | Should -Be 'test.1'
            $script:Run.counts.fail | Should -Be 2
            $script:Run.counts.pass | Should -Be 3
            $script:Run.counts.notEvaluated | Should -Be 2
            $script:Run.profile | Should -Match 'none'
        }
    }
}

Describe 'The evidence contract' {
    BeforeAll {
        # Five checks over the same facts, differing only in what they say they need. The provider answers the same
        # whatever is in the folder, as a provider that defaults a missing file to "nothing found" would.
        $script:Contract = Join-Path $script:Root 'contract'
        $checks = Join-Path $script:Contract 'checks'
        New-Item -ItemType Directory -Path $checks -Force | Out-Null
        $base = @{ domain = 'test'; severityDefault = 'High'; license = @(); applicableWhen = @{}; coveredBy = @(); thresholds = @{}; remediation = 'r'; learn = 'https://learn.microsoft.com/'; deepLink = $null; narrative = 'n'; frameworks = @{} }
        $make = { param([hashtable] $Own) $c = @{}; foreach ($k in $base.Keys) { $c[$k] = $base[$k] }; foreach ($k in $Own.Keys) { $c[$k] = $Own[$k] }; $c }
        @{ domain = 'test'; checks = @(
                (& $make @{ id = 'EC-001'; title = 'Needs both files'; evidence = @('list.json', 'settings.json'); pass = 'facts.count == 0' })
                (& $make @{ id = 'EC-002'; title = 'Can do without the detail'; evidence = @('list.json', 'detail.json'); evidenceOptional = @('detail.json'); pass = 'facts.count == 0' })
                (& $make @{ id = 'EC-003'; title = 'Either source'; evidence = @('list.json', 'from-admin.json', 'from-graph.json'); evidenceAnyOf = @(, @('from-admin.json', 'from-graph.json')); pass = 'facts.count == 0' })
                (& $make @{ id = 'EC-004'; title = 'Left side decides'; evidence = @('list.json', 'rule.json'); evidenceOptional = @('rule.json'); pass = 'facts.count == 0 || facts.ruleOn' })
                (& $make @{ id = 'EC-005'; title = 'Needs the unknown fact'; evidence = @('list.json', 'rule.json'); evidenceOptional = @('rule.json'); pass = 'facts.count == 0 && facts.ruleOn' })
            )
        } | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $checks 'test.json')
        $script:ContractProvider = { param($Evidence, $OrgProfile, $Thresholds) @{ facts = @{ count = 0; ruleOn = $null } } }
        $script:Evaluate = {
            param([string[]] $Files, [string[]] $Unfinished = @())
            $ev = Join-Path $script:Contract "ev-$([guid]::NewGuid().ToString('n'))"
            New-Item -ItemType Directory -Path $ev | Out-Null
            foreach ($f in $Files) { Set-Content -LiteralPath (Join-Path $ev $f) -Value '[]' }
            foreach ($f in $Unfinished) { Set-Content -LiteralPath (Join-Path $ev "$f.part") -Value '[' }
            InModuleScope TenantKeep.Posture -Parameters @{ P = (Join-Path $script:Contract 'checks'); B = (Join-Path $script:Fx.Baselines 'standard.json'); Ev = $ev; Provider = $script:ContractProvider } {
                $run = Invoke-PostureCheckEvaluation -Catalog (Import-PostureCheckCatalog -Path $P) -Baseline (Import-PostureBaseline -Baseline $B) -OrgProfile (Import-PostureProfile) -Evidence $Ev -FactProvider @{ test = $Provider }
                $by = @{}; foreach ($r in $run.results) { $by[[string]$r.id] = $r }; $by
            }
        }
    }

    It 'does not judge a check whose evidence file is not in the folder, and names the file' {
        $by = & $script:Evaluate @('list.json')
        $by['EC-001'].status | Should -Be 'notEvaluated' -Because 'the provider says nothing was found, but settings.json was never read'
        $by['EC-001'].reason | Should -Match 'settings\.json was not collected'
        $by['EC-001'].reason | Should -Not -Match 'list\.json'
        (& $script:Evaluate @('list.json', 'settings.csv'))['EC-001'].status | Should -Be 'pass' -Because 'a list is there as its CSV or its JSON'
    }

    It 'judges a check without a file it lists as optional' {
        (& $script:Evaluate @('list.json'))['EC-002'].status | Should -Be 'pass'
    }

    It 'takes one file of an any-of group as enough, and names the group when none is there' {
        (& $script:Evaluate @('list.json', 'from-graph.json'))['EC-003'].status | Should -Be 'pass'
        (& $script:Evaluate @('list.json', 'from-admin.json'))['EC-003'].status | Should -Be 'pass'
        $none = (& $script:Evaluate @('list.json'))['EC-003']
        $none.status | Should -Be 'notEvaluated'
        $none.reason | Should -Match 'none of from-admin\.json, from-graph\.json was collected'
    }

    It 'says when the file was still being written when the run stopped' {
        $r = (& $script:Evaluate @('list.json') @('settings.json'))['EC-001']
        $r.status | Should -Be 'notEvaluated'
        $r.reason | Should -Match 'settings was still being written when the run stopped'
    }

    It 'passes on the side that decides, and is not evaluated when the answer needs a fact with no value' {
        $by = & $script:Evaluate @('list.json')
        $by['EC-004'].status | Should -Be 'pass' -Because 'count is 0, so the rule does not matter'
        $by['EC-005'].status | Should -Be 'notEvaluated' -Because 'count is 0 and the rule is unknown'
        $by['EC-005'].reason | Should -Match 'Data missing: facts\.ruleOn has no value in the evidence\. Not collected: rule\.json\.'
    }

    It 'refuses a catalog whose optional or any-of names are not in the evidence list' {
        $bad = Join-Path $script:Contract 'bad'
        New-Item -ItemType Directory -Path $bad -Force | Out-Null
        foreach ($case in @(@('"evidence": ["a.json"], "evidenceOptional": ["b.json"]', "*'b.json' in evidenceOptional but not in evidence*"), @('"evidence": ["a.json", "b.json"], "evidenceAnyOf": [["a.json", "c.json"]]', "*'c.json' in evidenceAnyOf but not in evidence*"), @('"evidence": ["a.json"], "evidenceAnyOf": [["a.json"]]', '*fewer than two files*'))) {
            "{ ""domain"": ""x"", ""checks"": [ { ""id"": ""XX-001"", ""domain"": ""x"", ""title"": ""t"", ""severityDefault"": ""High"", ""license"": [], ""applicableWhen"": {}, ""coveredBy"": [], ""thresholds"": {}, $($case[0]), ""pass"": ""true"", ""remediation"": ""r"", ""learn"": , deepLink: null, narrative: , ""frameworks"": {} } ] }" | Set-Content (Join-Path $bad 'x.json')
            InModuleScope TenantKeep.Posture -Parameters @{ P = $bad; E = $case[1] } { { Import-PostureCheckCatalog -Path $P } | Should -Throw $E }
        }
    }
}

