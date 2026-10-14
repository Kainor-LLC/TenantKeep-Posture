# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
    . (Join-Path $PSScriptRoot 'Fixtures' 'CheckEngineFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-engine-$([guid]::NewGuid().ToString('n'))"
    $script:Fx = Initialize-CheckEngineFixture -Root $script:Root
    $script:Evidence = Join-Path $script:Root 'evidence'
    New-Item -ItemType Directory -Path $script:Evidence | Out-Null
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
}

Describe 'Import-PostureCheckCatalog' {
    It 'loads the fixture catalog with its version' {
        InModuleScope Tenantkeep.Posture -Parameters @{ P = $script:Fx.Checks } {
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
        InModuleScope Tenantkeep.Posture -Parameters @{ P = $bad } { { Import-PostureCheckCatalog -Path $P } | Should -Throw "*XX-001*missing: domain, severityDefault*" }
        '{ "domain": "x", "checks": [ { "id": "XX-001", "domain": "x", "title": "t", "severityDefault": "Urgent", "license": [], "applicableWhen": {}, "coveredBy": [], "thresholds": {}, "evidence": [], "pass": "true", "remediation": "", "learn": "", "deepLink": null, "narrative": "", "frameworks": {} } ] }' | Set-Content (Join-Path $bad 'x.json')
        InModuleScope Tenantkeep.Posture -Parameters @{ P = $bad } { { Import-PostureCheckCatalog -Path $P } | Should -Throw "*severityDefault 'Urgent'*" }
        Copy-Item (Join-Path $script:Fx.Checks 'test.json') (Join-Path $bad 'x.json') -Force
        Copy-Item (Join-Path $script:Fx.Checks 'test.json') (Join-Path $bad 'y.json') -Force
        InModuleScope Tenantkeep.Posture -Parameters @{ P = $bad } { { Import-PostureCheckCatalog -Path $P } | Should -Throw '*Duplicate check id*' }
    }
}

Describe 'Invoke-PostureCheckEvaluation' {
    BeforeAll {
        InModuleScope Tenantkeep.Posture -Parameters @{ Fx = $script:Fx; Ev = $script:Evidence } {
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
        InModuleScope Tenantkeep.Posture {
            $script:ById['TS-001'].status | Should -Be 'fail'   # count 3 > max 2
            $script:ById['TS-001'].affectedCount | Should -Be 3
            $script:ById['TS-001'].evidence | Should -Contain 'provider.json'
            $script:ById['TS-002'].status | Should -Be 'pass'   # no profile, no license gate
            $script:ById['TS-006'].status | Should -Be 'fail'
            $script:ById['TS-006'].severity | Should -Be 'Critical'
        }
    }

    It 'marks a missing fact and a missing provider as not evaluated with the reason' {
        InModuleScope Tenantkeep.Posture {
            $script:ById['TS-005'].status | Should -Be 'notEvaluated'
            $script:ById['TS-005'].reason | Should -Match "Data missing: Unknown reference 'facts.nope'"
            $script:ById['OT-001'].status | Should -Be 'notEvaluated'
            $script:ById['OT-001'].reason | Should -Match "No fact provider for domain 'other'"
        }
    }

    It 'applies the profile: license gate, applicability, third-party coverage, global thresholds' {
        InModuleScope Tenantkeep.Posture -Parameters @{ Ev = $script:Evidence } {
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
        InModuleScope Tenantkeep.Posture -Parameters @{ Ev = $script:Evidence } {
            $p = Import-PostureProfile
            $p.present = $true; $p.thirdParty = @{ mfa = 'none' }
            $run = Invoke-PostureCheckEvaluation -Catalog $script:Catalog -Baseline $script:Std -OrgProfile $p -Evidence $Ev -FactProvider $script:Provider
            ($run.results | Where-Object id -eq 'TS-004').status | Should -Be 'pass'
        }
    }

    It 'applies the baseline: selection, per-check thresholds, severity override' {
        InModuleScope Tenantkeep.Posture -Parameters @{ Ev = $script:Evidence } {
            $run = Invoke-PostureCheckEvaluation -Catalog $script:Catalog -Baseline $script:Strict -OrgProfile $script:NoProfile -Evidence $Ev -FactProvider $script:Provider
            @($run.results | ForEach-Object { $_.id }) | Should -Be @('TS-001', 'TS-006')
            ($run.results | Where-Object id -eq 'TS-001').status | Should -Be 'pass'
            ($run.results | Where-Object id -eq 'TS-001').thresholds.max | Should -Be 5
            ($run.results | Where-Object id -eq 'TS-006').severity | Should -Be 'Low'
            $run.baseline | Should -Be 'strict'
        }
    }

    It 'passes merged domain thresholds to the provider' {
        InModuleScope Tenantkeep.Posture -Parameters @{ Ev = $script:Evidence } {
            $spy = @{ test = { param($Evidence, $OrgProfile, $Thresholds) $script:SeenThresholds = $Thresholds; @{ facts = @{ count = 0; enabled = $true } } } }
            $null = Invoke-PostureCheckEvaluation -Catalog $script:Catalog -Baseline $script:Strict -OrgProfile $script:NoProfile -Evidence $Ev -FactProvider $spy
            $script:SeenThresholds.max | Should -Be 5
        }
    }

    It 'turns a failing check into accepted risk through a check-level exception' {
        InModuleScope Tenantkeep.Posture -Parameters @{ Ev = $script:Evidence } {
            $run = Invoke-PostureCheckEvaluation -Catalog $script:Catalog -Baseline $script:Std -OrgProfile $script:NoProfile -Exception $script:Exceptions -Evidence $Ev -FactProvider $script:Provider
            $r = $run.results | Where-Object id -eq 'TS-006'
            $r.status | Should -Be 'acceptedRisk'
            $r.reason | Should -Match 'Accepted risk: Known, scheduled \(owner J\. Smith, approver CISO, until 2099-01-01\)'
        }
    }

    It 'removes excepted objects from the affected list and ignores expired exceptions' {
        InModuleScope Tenantkeep.Posture -Parameters @{ Ev = $script:Evidence } {
            $run = Invoke-PostureCheckEvaluation -Catalog $script:Catalog -Baseline $script:Std -OrgProfile $script:NoProfile -Exception $script:Exceptions -Evidence $Ev -FactProvider $script:Provider
            $r = $run.results | Where-Object id -eq 'TS-001'
            $r.status | Should -Be 'fail'
            @($r.affected | ForEach-Object { $_.name }) | Should -Be @('alpha', 'gamma') -Because 'beta is excepted and the gamma exception expired'
            $r.reason | Should -Match '1 object\(s\) accepted by exception; 2 remain\. 1 expired exception\(s\) ignored\.'
        }
    }

    It 'becomes accepted risk when every affected object is excepted' {
        InModuleScope Tenantkeep.Posture -Parameters @{ Ev = $script:Evidence } {
            $all = @('alpha', 'beta', 'gamma' | ForEach-Object { [ordered]@{ check = 'TS-001'; object = $_; justification = 'ok'; owner = 'o'; approver = 'a'; expires = [datetime]'2099-01-01'; expired = $false } })
            $run = Invoke-PostureCheckEvaluation -Catalog $script:Catalog -Baseline $script:Std -OrgProfile $script:NoProfile -Exception $all -Evidence $Ev -FactProvider $script:Provider
            ($run.results | Where-Object id -eq 'TS-001').status | Should -Be 'acceptedRisk'
        }
    }

    It 'counts statuses and records the catalog version' {
        InModuleScope Tenantkeep.Posture {
            $script:Run.catalogVersion | Should -Be 'test.1'
            $script:Run.counts.fail | Should -Be 2
            $script:Run.counts.pass | Should -Be 3
            $script:Run.counts.notEvaluated | Should -Be 2
            $script:Run.profile | Should -Match 'none'
        }
    }
}
