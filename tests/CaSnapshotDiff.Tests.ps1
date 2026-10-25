# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Sample = Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot'
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-diff-$([guid]::NewGuid().ToString('n'))"
    $script:BeforeDir = Join-Path $script:Root 'before'
    $script:AfterDir = Join-Path $script:Root 'after'
    . (Join-Path $PSScriptRoot 'Fixtures' 'CaDiffFixture.ps1')
    $null = Initialize-CaDiffFixture -Root $script:Root -Sample $script:Sample

    InModuleScope TenantKeep.Posture -Parameters @{ B = $script:BeforeDir; A = $script:AfterDir } {
        $script:Diff = Compare-PostureCaModel -Before (Import-PostureCaSnapshot -Path $B) -After (Import-PostureCaSnapshot -Path $A)
    }
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
}

Describe 'ConvertTo-PostureCaFlatMap' {
    It 'flattens references to sorted names, scalars to strings, nulls to empty' {
        InModuleScope TenantKeep.Posture {
            $m = ConvertTo-PostureCaFlatMap ([ordered]@{
                    a = @([ordered]@{ id = '2'; name = 'Zed'; type = 'user' }, [ordered]@{ id = '1'; name = 'Amy'; type = 'user' })
                    b = @('y', 'x'); c = $null; d = [ordered]@{ e = $true; raw = 'skip' }; f = @()
                })
            $m['a'] | Should -Be 'Amy; Zed'
            $m['b'] | Should -Be 'x; y'
            $m['c'] | Should -Be ''
            $m['d.e'] | Should -Be 'True'
            $m.Contains('d.raw') | Should -BeFalse
            $m['f'] | Should -Be ''
        }
    }

    It 'reports only changed paths, including one-sided ones' {
        InModuleScope TenantKeep.Posture {
            $c = Compare-PostureCaFlatMap -Before ([ordered]@{ x = '1'; y = '2'; gone = 'g' }) -After ([ordered]@{ x = '1'; y = '3'; new = 'n' })
            @($c | ForEach-Object { $_.path } | Sort-Object) | Should -Be @('gone', 'new', 'y')
            ($c | Where-Object path -eq 'y').before | Should -Be '2'
            ($c | Where-Object path -eq 'y').after | Should -Be '3'
        }
    }
}

Describe 'Compare-PostureCaModel' {
    It 'classifies added, removed and changed policies' {
        InModuleScope TenantKeep.Posture {
            $script:Diff.policies.added.id | Should -Be @('p-009')
            $script:Diff.policies.removed.id | Should -Be @('p-008')
            @($script:Diff.policies.changed | ForEach-Object { $_.id }) | Should -Be @('p-001', 'p-002', 'p-003', 'p-005')
        }
    }

    It 'flags rename and state change separately from field changes' {
        InModuleScope TenantKeep.Posture {
            $c = $script:Diff.policies.changed | Where-Object id -eq 'p-003'
            $c.renamed | Should -BeTrue
            $c.nameBefore | Should -Be 'Block legacy authentication'
            $c.modified | Should -BeFalse
            $s = $script:Diff.policies.changed | Where-Object id -eq 'p-002'
            $s.stateChanged | Should -BeTrue
            $s.stateBefore | Should -Be 'enabled'
            $s.stateAfter | Should -Be 'disabled'
        }
    }

    It 'gives field-level before and after with names, not ids' {
        InModuleScope TenantKeep.Posture {
            $c = $script:Diff.policies.changed | Where-Object id -eq 'p-001'
            $f = $c.fields | Where-Object path -eq 'assignments.excludeUsers'
            $f.before | Should -Be 'BreakGlass-01; BreakGlass-02'
            $f.after | Should -Be 'BreakGlass-01'
            ($c.fields | Where-Object path -eq 'grant.authenticationStrength').after | Should -Be 'Multifactor authentication'
            $e = ($script:Diff.policies.changed | Where-Object id -eq 'p-002').fields | Where-Object path -eq 'assignments.excludeGroups'
            $e.after | Should -Match 'CA-Exclude-LegacyAuth-Printers'
            $e.after | Should -Not -Match '2222'
        }
    }

    It 'diffs named locations and strengths' {
        InModuleScope TenantKeep.Posture {
            $script:Diff.locations.added.name | Should -Be @('Branch VPN')
            ($script:Diff.locations.changed | Where-Object name -eq 'HQ egress').fields.path | Should -Contain 'ipRanges'
            ($script:Diff.strengths.changed | Where-Object name -eq 'Phishing-resistant MFA').fields.path | Should -Be @('allowedCombinations')
            $script:Diff.contexts.added.Count + $script:Diff.contexts.removed.Count + $script:Diff.contexts.changed.Count | Should -Be 0
        }
    }

    It 'reports scope drift with member detail when both sides have members' {
        InModuleScope TenantKeep.Posture {
            $big = $script:Diff.scope | Where-Object name -eq 'CA-Exclude-MFA-Legacy'
            $big.countBefore | Should -Be 341
            $big.countAfter | Should -Be 350
            $big.delta | Should -Be 9
            $big.memberDetail | Should -BeFalse
            $small = $script:Diff.scope | Where-Object name -eq 'CA-Exclude-ServiceAccounts'
            $small.memberDetail | Should -BeTrue
            $small.membersAdded.displayName | Should -Be @('Member Three')
            $small.membersRemoved.displayName | Should -Be @('Member One')
            @($script:Diff.scope).Count | Should -Be 2
        }
    }
}

Describe 'Get-PostureCaRiskChange' {
    It 'raises exactly the expected risk-relevant changes' {
        InModuleScope TenantKeep.Posture {
            $rules = @($script:Diff.risk | ForEach-Object { "$($_.rule):$($_.subject)" } | Sort-Object)
            $rules | Should -Be @(
                'authStrengthWeakened:CA-001-Admins-Require phishing-resistant MFA'
                'authStrengthWeakened:Phishing-resistant MFA'
                'breakGlassExclusionRemoved:CA-001-Admins-Require phishing-resistant MFA'
                'deletedReference:CA-009-Users-Require MFA for admin portals'
                'deviceComplianceRemoved:CA-005-Users-Require compliant device for Windows and macOS'
                'exclusionAdded:CA-002-Users-Require MFA for all cloud apps'
                'stateWeakened:CA-002-Users-Require MFA for all cloud apps'
                'trustedLocationAdded:Branch VPN'
                'trustedLocationAdded:HQ egress'
            )
        }
    }

    It 'does not count a removed report-only policy or an unchanged deleted reference' {
        InModuleScope TenantKeep.Posture {
            @($script:Diff.risk | Where-Object rule -eq 'enabledPolicyRemoved').Count | Should -Be 0
            @($script:Diff.risk | Where-Object { $_.rule -eq 'deletedReference' -and $_.subject -like 'CA-007*' }).Count | Should -Be 0
        }
    }

    It 'uses an explicit break-glass list when given' {
        InModuleScope TenantKeep.Posture {
            $none = Get-PostureCaRiskChange -Diff $script:Diff -BreakGlass @('someone-else@contoso.example')
            @($none | Where-Object rule -eq 'breakGlassExclusionRemoved').Count | Should -Be 0
            $hit = Get-PostureCaRiskChange -Diff $script:Diff -BreakGlass @('breakglass02@contoso.example')
            @($hit | Where-Object rule -eq 'breakGlassExclusionRemoved').Count | Should -Be 1
        }
    }

    It 'ranks authentication strength levels' {
        InModuleScope TenantKeep.Posture {
            $mk = { param($combos, $controls) [ordered]@{ grant = [ordered]@{ builtInControls = $controls; authenticationStrength = $(if ($null -ne $combos) { [ordered]@{ id = 's'; name = 's'; deleted = $false; allowedCombinations = $combos } } else { $null }) } } }
            Get-PostureCaStrengthLevel -Policy (& $mk @('fido2', 'windowsHelloForBusiness') @()) | Should -Be 3
            Get-PostureCaStrengthLevel -Policy (& $mk @('fido2', 'microsoftAuthenticatorPush') @()) | Should -Be 2
            Get-PostureCaStrengthLevel -Policy (& $mk @('password,sms', 'fido2') @()) | Should -Be 1
            Get-PostureCaStrengthLevel -Policy (& $mk $null @('mfa')) | Should -Be 1
            Get-PostureCaStrengthLevel -Policy (& $mk $null @('block')) | Should -Be 0
        }
    }

    It 'returns nothing when both snapshots are the same' {
        InModuleScope TenantKeep.Posture -Parameters @{ B = $script:BeforeDir } {
            $same = Compare-PostureCaModel -Before (Import-PostureCaSnapshot -Path $B) -After (Import-PostureCaSnapshot -Path $B)
            @($same.risk).Count | Should -Be 0
            $same.policies.added.Count + $same.policies.removed.Count + $same.policies.changed.Count | Should -Be 0
            @($same.scope).Count | Should -Be 0
        }
    }
}
