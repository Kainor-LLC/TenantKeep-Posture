# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
}

Describe 'MITRE ATT&CK mapping' {
    BeforeAll {
        # Two tactics, three techniques; T1078.004 sits under both tactics as it does in MITRE's matrix.
        $script:Cat = [ordered]@{
            attack = [ordered]@{
                version = '20.1'; notice = 'notice'
                tactics = @([ordered]@{ id = 'TA0001'; key = 'initial-access'; name = 'Initial Access' }, [ordered]@{ id = 'TA0006'; key = 'credential-access'; name = 'Credential Access' })
                techniques = [ordered]@{
                    'T1078.004' = [ordered]@{ id = 'T1078.004'; name = 'Valid Accounts: Cloud Accounts'; tactics = @('initial-access', 'credential-access'); url = 'https://attack.mitre.org/techniques/T1078/004/' }
                    'T1110.003' = [ordered]@{ id = 'T1110.003'; name = 'Brute Force: Password Spraying'; tactics = @('credential-access'); url = 'https://attack.mitre.org/techniques/T1110/003/' }
                    'T1566.002' = [ordered]@{ id = 'T1566.002'; name = 'Phishing: Spearphishing Link'; tactics = @('initial-access'); url = 'https://attack.mitre.org/techniques/T1566/002/' }
                }
            }
            checks = @(
                [ordered]@{ id = 'CA-001'; attack = @('T1110.003') }
                [ordered]@{ id = 'CA-002'; attack = @('T1078.004', 'T1110.003') }
                [ordered]@{ id = 'EM-001'; attack = @('T1566.002') }
                [ordered]@{ id = 'EM-002'; attack = @('T1566.002', 'T9999') }
                [ordered]@{ id = 'GV-001' }
            )
        }
    }

    It 'resolves a check''s technique ids to names, tactic names and links, and keeps an unknown id' {
        InModuleScope TenantKeep.Posture -Parameters @{ Cat = $script:Cat } {
            $t = @(Get-PostureAttackTechnique -Catalog $Cat -Check $Cat.checks[1])
            $t.Count | Should -Be 2
            $t[0].name | Should -Be 'Valid Accounts: Cloud Accounts'
            $t[0].tactics | Should -Be @('Initial Access', 'Credential Access')
            $u = @(Get-PostureAttackTechnique -Catalog $Cat -Check $Cat.checks[3])[1]
            $u.name | Should -Be 'T9999'
            $u.url | Should -Be 'https://attack.mitre.org/techniques/T9999/'
            @(Get-PostureAttackTechnique -Catalog $Cat -Check $Cat.checks[4]).Count | Should -Be 0
        }
    }

    It 'stands each technique by its worst check: gap, accepted, covered, unchecked' {
        InModuleScope TenantKeep.Posture -Parameters @{ Cat = $script:Cat } {
            $res = @(
                [ordered]@{ id = 'CA-001'; title = 'Legacy'; status = 'pass'; severity = 'High' }
                [ordered]@{ id = 'CA-002'; title = 'MFA'; status = 'fail'; severity = 'Critical' }
                [ordered]@{ id = 'EM-001'; title = 'EOP'; status = 'acceptedRisk'; severity = 'High' }
                [ordered]@{ id = 'EM-002'; title = 'MDO'; status = 'coveredBy'; severity = 'High' }
                [ordered]@{ id = 'GV-001'; title = 'Inactive'; status = 'fail'; severity = 'Medium' }
            )
            $a = Get-PostureAttackCoverage -Catalog $Cat -Result $res
            $a.techniques | Should -Be 3 -Because 'T9999 is not in attack.json and has no tactic to sit under'
            $a.totals.gap | Should -Be 2
            $a.totals.accepted | Should -Be 1
            @($a.tactics.key) | Should -Be @('initial-access', 'credential-access') -Because 'tactics keep MITRE''s order'
            $ia = $a.tactics[0]
            @($ia.techniques.id) | Should -Be @('T1078.004', 'T1566.002') -Because 'gaps come first'
            $ia.counts.gap | Should -Be 1
            $ca = $a.tactics[1]
            @($ca.techniques.id) | Should -Be @('T1078.004', 'T1110.003') -Because 'T1078.004 sits under both tactics'
            $spray = $ca.techniques[1]
            $spray.status | Should -Be 'gap'
            $spray.pass | Should -Be 1
            @($spray.checks.id) | Should -Be @('CA-001', 'CA-002')

            $res[1].status = 'notEvaluated'; $res[2].status = 'pass'
            $b = Get-PostureAttackCoverage -Catalog $Cat -Result $res
            ($b.tactics[0].techniques | Where-Object id -eq 'T1078.004').status | Should -Be 'unchecked'
            ($b.tactics[0].techniques | Where-Object id -eq 'T1566.002').status | Should -Be 'covered'

            $res[1].status = 'notApplicable'
            $n = Get-PostureAttackCoverage -Catalog $Cat -Result $res
            @($n.tactics[0].techniques.id) | Should -Be @('T1566.002') -Because 'a check the profile rules out says nothing about the tenant'
            @($n.tactics[1].techniques.id) | Should -Be @('T1110.003')
        }
    }

    It 'returns nothing without attack.json or when no evaluated check names a technique' {
        InModuleScope TenantKeep.Posture -Parameters @{ Cat = $script:Cat } {
            Get-PostureAttackCoverage -Catalog ([ordered]@{ attack = $null; checks = $Cat.checks }) -Result @([ordered]@{ id = 'CA-001'; title = 'x'; status = 'pass'; severity = 'High' }) | Should -BeNullOrEmpty
            Get-PostureAttackCoverage -Catalog $Cat -Result @([ordered]@{ id = 'GV-001'; title = 'x'; status = 'fail'; severity = 'High' }) | Should -BeNullOrEmpty
        }
    }

    It 'refuses a check whose attack field is not a list of technique ids' {
        InModuleScope TenantKeep.Posture {
            $dir = Join-Path $TestDrive 'bad-attack'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $check = [ordered]@{ id = 'XX-001'; domain = 'identity'; title = 't'; severityDefault = 'Low'; license = @(); applicableWhen = @{}; coveredBy = @(); thresholds = @{}; evidence = @(); pass = 'true'; remediation = 'Do the thing properly.'; learn = 'https://learn.microsoft.com/x'; deepLink = 'https://entra.microsoft.com'; narrative = 'n'; frameworks = @{}; attack = 'T1078' }
            @{ domain = 'identity'; checks = @($check) } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $dir 'identity.json')
            { Import-PostureCheckCatalog -Path $dir } | Should -Throw '*attack must be a list*'
            $check.attack = @('Valid Accounts')
            @{ domain = 'identity'; checks = @($check) } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $dir 'identity.json')
            { Import-PostureCheckCatalog -Path $dir } | Should -Throw '*attack must be a list*'
        }
    }

    It 'regenerates attack.json from a STIX bundle and refuses revoked ids and another release' {
        # A bundle built from the shipped attack.json: the task must write the same file back.
        $root = Join-Path $TestDrive 'build'
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        Copy-Item (Join-Path $PSScriptRoot '..' 'build.ps1') $root
        Copy-Item (Join-Path $PSScriptRoot '..' 'checks') $root -Recurse
        $shipped = Get-Content -Raw (Join-Path $root 'checks' 'attack.json') | ConvertFrom-Json -AsHashtable
        $ref = { param([string] $Id) @{ source_name = 'mitre-attack'; external_id = $Id } }
        $objects = [System.Collections.Generic.List[object]]::new()
        $objects.Add(@{ type = 'x-mitre-collection'; id = 'x-mitre-collection--1'; x_mitre_version = $shipped.version; modified = '2026-11-05T00:00:00Z' })
        $objects.Add(@{ type = 'x-mitre-matrix'; id = 'x-mitre-matrix--1'; tactic_refs = @($shipped.tactics | ForEach-Object { "x-mitre-tactic--$($_.key)" }) })
        foreach ($t in $shipped.tactics) { $objects.Add(@{ type = 'x-mitre-tactic'; id = "x-mitre-tactic--$($t.key)"; name = $t.name; x_mitre_shortname = $t.key; external_references = @(& $ref $t.id) }) }
        foreach ($t in $shipped.techniques) {
            $parent = $t.id.Split('.')[0]
            $short = $(if ($t.id.Contains('.')) { $t.name.Substring($t.name.IndexOf(': ') + 2) } else { $t.name })
            $objects.Add(@{ type = 'attack-pattern'; id = "attack-pattern--$($t.id)"; name = $short; external_references = @(& $ref $t.id); kill_chain_phases = @($t.tactics | ForEach-Object { @{ kill_chain_name = 'mitre-attack'; phase_name = $_ } }) })
            if ($t.id.Contains('.') -and -not @($shipped.techniques | Where-Object id -eq $parent).Count -and -not @($objects | Where-Object { $_.Contains('external_references') -and $_.external_references[0].external_id -eq $parent }).Count) {
                $objects.Add(@{ type = 'attack-pattern'; id = "attack-pattern--$parent"; name = $t.name.Substring(0, $t.name.IndexOf(': ')); external_references = @(& $ref $parent); kill_chain_phases = @() })
            }
        }
        $objects.Add(@{ type = 'attack-pattern'; id = 'attack-pattern--old'; name = 'Old'; revoked = $true; external_references = @(& $ref 'T1562.008'); kill_chain_phases = @() })
        $objects.Add(@{ type = 'relationship'; id = 'relationship--1'; relationship_type = 'revoked-by'; source_ref = 'attack-pattern--old'; target_ref = 'attack-pattern--T1685.002' })
        $stix = Join-Path $TestDrive 'enterprise-attack.json'
        @{ type = 'bundle'; objects = @($objects) } | ConvertTo-Json -Depth 10 | Set-Content $stix

        $before = Get-Content -Raw (Join-Path $root 'checks' 'attack.json')
        & pwsh -NoProfile -File (Join-Path $root 'build.ps1') -Task AttackData -AttackStix $stix *> $null
        $LASTEXITCODE | Should -Be 0
        Get-Content -Raw (Join-Path $root 'checks' 'attack.json') | Should -Be $before -Because 'the shipped file is what the task writes'

        $file = Join-Path $root 'checks' 'identity.json'
        $doc = Get-Content -Raw $file | ConvertFrom-Json -AsHashtable -Depth 20
        $doc.checks[0].attack = @('T1562.008')
        $doc | ConvertTo-Json -Depth 20 | Set-Content $file
        $out = & pwsh -NoProfile -File (Join-Path $root 'build.ps1') -Task AttackData -AttackStix $stix 2>&1 | Out-String
        $LASTEXITCODE | Should -Not -Be 0
        $out | Should -Match 'ID-001 names T1562\.008, revoked in ATT&CK'
        $out | Should -Match 'T1685\.002 \(Disable or Modify Cloud Log\)' -Because 'the error names the replacement'

        $cat = Join-Path $root 'checks' 'catalog.json'
        (Get-Content -Raw $cat) -replace '"version": "20\.1"', '"version": "19.0"' | Set-Content $cat
        $out = & pwsh -NoProfile -File (Join-Path $root 'build.ps1') -Task AttackData -AttackStix $stix 2>&1 | Out-String
        $out | Should -Match 'pins 19\.0'
    }
}
