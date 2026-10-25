# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Sample = Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot'
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-cafacts-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    InModuleScope TenantKeep.Posture -Parameters @{ S = $script:Sample } {
        $script:F = Get-PostureCaFact -Evidence $S -OrgProfile (Import-PostureProfile) -Thresholds @{}
    }
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
}

Describe 'Get-PostureCaFact on the sample snapshot' {
    It 'is available and names its evidence' {
        InModuleScope TenantKeep.Posture {
            $script:F.available | Should -BeTrue
            $script:F.evidence | Should -Contain 'policies.json'
            $script:F.facts.policyCount | Should -Be 8
            $script:F.facts.enabledPolicyCount | Should -Be 5
        }
    }

    It 'computes <Fact> = <Expected>' -ForEach @(
        @{ Fact = 'legacyAuthBlockPolicies'; Expected = 1 }
        @{ Fact = 'mfaAllUsersPolicies'; Expected = 0 }
        @{ Fact = 'adminRolesTotal'; Expected = 14 }
        @{ Fact = 'adminRolesPhishingResistant'; Expected = 3 }
        @{ Fact = 'signInRiskPolicies'; Expected = 0 }
        @{ Fact = 'userRiskPolicies'; Expected = 0 }
        @{ Fact = 'devicePlatformsRequired'; Expected = 2 }
        @{ Fact = 'devicePlatformsWithCompliance'; Expected = 2 }
        @{ Fact = 'reportOnlyOverThreshold'; Expected = 2 }
        @{ Fact = 'exclusionGroupsOverThreshold'; Expected = 1 }
        @{ Fact = 'trustedLocationMfaBypass'; Expected = 1 }
        @{ Fact = 'adminSessionControlPolicies'; Expected = 1 }   # p-001: admin roles, sign-in frequency 4h, non-persistent browser
        @{ Fact = 'tokenProtectionPolicies'; Expected = 0 }
        @{ Fact = 'microsoftManagedPolicies'; Expected = 0 }
        @{ Fact = 'microsoftManagedDisabled'; Expected = 0 }
        @{ Fact = 'breakGlassIdentified'; Expected = $true }
        @{ Fact = 'blockPoliciesMissingBreakGlass'; Expected = 2 }
        @{ Fact = 'policiesWithDeletedReferences'; Expected = 2 }
        @{ Fact = 'disabledOverThreshold'; Expected = 1 }
        @{ Fact = 'namingPatternConfigured'; Expected = $false }
    ) {
        InModuleScope TenantKeep.Posture -Parameters @{ Fact = $Fact; Expected = $Expected } {
            $script:F.facts[$Fact] | Should -Be $Expected
        }
    }

    It 'lists the affected objects behind the facts' {
        InModuleScope TenantKeep.Posture {
            $script:F.affected.exclusionGroupsOverThreshold.name | Should -Be @('CA-Exclude-MFA-Legacy')
            $script:F.affected.exclusionGroupsOverThreshold[0].detail | Should -Match '341 members, excluded from: CA-002.*CA-005'
            $script:F.affected.mfaAllUsersWithExtraExclusions.name | Should -Be @('CA-002-Users-Require MFA for all cloud apps')
            $script:F.affected.mfaAllUsersWithExtraExclusions[0].detail | Should -Match 'CA-Exclude-ServiceAccounts'
            $script:F.affected.adminRolesWithoutPhishingResistant.name | Should -Contain 'Conditional Access Administrator'
            $script:F.affected.adminRolesWithoutPhishingResistant.name | Should -Not -Contain 'Global Administrator'
            @($script:F.affected.blockPoliciesMissingBreakGlass.name | Sort-Object) | Should -Be @('Block legacy authentication', 'CA-007-Users-Register security info from trusted locations')
            $script:F.affected.trustedLocationMfaBypass[0].detail | Should -Match 'All trusted locations'
            $script:F.notEvaluated.ContainsKey('CA-015') | Should -BeFalse -Because 'without a pattern the names themselves are judged'
            $script:F.facts.namingConventionDetected | Should -BeFalse -Because 'six of eight sample names are structured, below eight in ten'
            $script:F.facts.namingNonConforming | Should -Be 2
        }
    }

    It 'honours thresholds, the profile break-glass list, platforms and a name pattern' {
        InModuleScope TenantKeep.Posture -Parameters @{ S = $script:Sample } {
            $p = Import-PostureProfile
            $p.breakGlass = @('breakglass01@contoso.example', 'breakglass02@contoso.example')
            $p.platforms = @('windows')
            $f = Get-PostureCaFact -Evidence $S -OrgProfile $p -Thresholds @{ maxExclusionGroupMembers = 500; reportOnlyMaxDays = 3650; namePattern = '^CA-\d{3}-' }
            $f.facts.exclusionGroupsOverThreshold | Should -Be 0
            $f.facts.reportOnlyOverThreshold | Should -Be 0
            $f.facts.devicePlatformsRequired | Should -Be 1
            $f.facts.namingPatternConfigured | Should -BeTrue
            $f.facts.namingNonConforming | Should -Be 2
            $f.notEvaluated.Count | Should -Be 0
            $f.facts.breakGlassIdentified | Should -BeTrue
        }
    }

    It 'reports unavailable for a folder without a snapshot' {
        InModuleScope TenantKeep.Posture -Parameters @{ R = $script:Root } {
            $f = Get-PostureCaFact -Evidence $R
            $f.available | Should -BeFalse
            $f.reason | Should -Match 'No Conditional Access snapshot'
        }
    }
}

Describe 'Invoke-PostureChecks on the sample snapshot (shipped catalog)' {
    BeforeAll {
        $script:Run = Invoke-PostureChecks -Evidence $script:Sample -Domain ca -OutputPath $script:Root -PassThru
        $script:By = @{}; foreach ($r in $script:Run.results) { $script:By[$r.id] = $r }
    }

    It 'evaluates all 15 CA checks against the shipped catalog version' {
        $script:Run.results.Count | Should -Be 15
        $script:Run.catalogVersion | Should -Match '^\d{4}\.'
        Join-Path $script:Root 'checks.json' | Should -Exist
    }

    It 'gives <Id> status <Status>' -ForEach @(
        @{ Id = 'CA-001'; Status = 'pass' }
        @{ Id = 'CA-002'; Status = 'fail' }
        @{ Id = 'CA-003'; Status = 'fail' }
        @{ Id = 'CA-004'; Status = 'fail' }
        @{ Id = 'CA-005'; Status = 'pass' }
        @{ Id = 'CA-006'; Status = 'fail' }
        @{ Id = 'CA-007'; Status = 'fail' }
        @{ Id = 'CA-008'; Status = 'fail' }
        @{ Id = 'CA-009'; Status = 'pass' }
        @{ Id = 'CA-010'; Status = 'fail' }
        @{ Id = 'CA-011'; Status = 'pass' }
        @{ Id = 'CA-012'; Status = 'fail' }
        @{ Id = 'CA-013'; Status = 'fail' }
        @{ Id = 'CA-014'; Status = 'fail' }
        @{ Id = 'CA-015'; Status = 'fail' }
    ) {
        $script:By[$Id].status | Should -Be $Status
    }

    It 'carries affected objects and the evidence list' {
        $script:By['CA-007'].affectedCount | Should -Be 1
        $script:By['CA-007'].affected[0].name | Should -Be 'CA-Exclude-MFA-Legacy'
        $script:By['CA-003'].affectedCount | Should -Be 11
        $script:By['CA-015'].affectedCount | Should -Be 2
        $script:By['CA-001'].evidence | Should -Contain 'group-scope.json'
    }

    It 'accepts the oversized group through an object-level exception' {
        $ex = Join-Path $script:Root 'exceptions.json'
        @(@{ check = 'CA-007'; object = 'CA-Exclude-MFA-Legacy'; justification = 'Legacy app, decommission 2027'; owner = 'J. Smith'; approver = 'CISO'; expires = '2027-03-31' }) | ConvertTo-Json | Set-Content $ex
        $r = Invoke-PostureChecks -Evidence $script:Sample -Domain ca -Exceptions $ex -OutputPath (Join-Path $script:Root 'ex') -PassThru
        ($r.results | Where-Object id -eq 'CA-007').status | Should -Be 'acceptedRisk'
    }
}
