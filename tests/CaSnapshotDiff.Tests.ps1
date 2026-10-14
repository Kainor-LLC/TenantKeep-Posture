# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
    $script:Sample = Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot'
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-diff-$([guid]::NewGuid().ToString('n'))"
    $script:BeforeDir = Join-Path $script:Root 'before'
    $script:AfterDir = Join-Path $script:Root 'after'
    Copy-Item -Path $script:Sample -Destination $script:BeforeDir -Recurse
    Copy-Item -Path $script:Sample -Destination $script:AfterDir -Recurse

    $load = { param($dir, $name) Get-Content -Raw -LiteralPath (Join-Path $dir "$name.json") | ConvertFrom-Json -AsHashtable -Depth 30 }
    $save = { param($dir, $name, $obj) ConvertTo-Json -InputObject $obj -Depth 30 | Set-Content -LiteralPath (Join-Path $dir "$name.json") }

    # Before: give group 201 a member list so member-level diff is exercised.
    $g = & $load $script:BeforeDir 'group-scope'
    ($g | Where-Object groupId -eq '22222222-2222-2222-2222-222222222201').members = @(
        @{ id = 'm1'; type = 'user'; displayName = 'Member One'; userPrincipalName = 'one@contoso.example' }
        @{ id = 'm2'; type = 'user'; displayName = 'Member Two'; userPrincipalName = 'two@contoso.example' }
    )
    & $save $script:BeforeDir 'group-scope' $g

    # After: the changes the diff and the risk rules must see.
    $policies = & $load $script:AfterDir 'policies'
    $byId = @{}; foreach ($p in $policies) { $byId[$p.id] = $p }
    $byId['p-001'].conditions.users.excludeUsers = @('11111111-1111-1111-1111-111111111111')               # break-glass 02 removed
    $byId['p-001'].grantControls.authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000002'; displayName = 'Multifactor authentication' }  # weakened
    $byId['p-002'].state = 'disabled'                                                                        # enabled -> disabled
    $byId['p-002'].conditions.users.excludeGroups += '22222222-2222-2222-2222-222222222203'                 # exclusion added to MFA policy
    $byId['p-003'].displayName = 'CA-008-Users-Block legacy authentication'                                 # rename only
    $byId['p-005'].grantControls.builtInControls = @('mfa')                                                 # compliance removed
    $byId['p-005'].modifiedDateTime = '2026-10-12T10:00:00Z'
    $new = @{
        id = 'p-009'; displayName = 'CA-009-Users-Require MFA for admin portals'; state = 'enabled'
        createdDateTime = '2026-10-12T09:00:00Z'; modifiedDateTime = '2026-10-12T09:00:00Z'
        conditions = @{ users = @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @('22222222-2222-2222-2222-222222222299'); excludeGroups = @(); includeRoles = @(); excludeRoles = @() }; applications = @{ includeApplications = @('MicrosoftAdminPortals'); excludeApplications = @(); includeUserActions = @() }; clientAppTypes = @('all') }
        grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }
    }
    $policies = @($policies | Where-Object { $_.id -ne 'p-008' }) + @($new)                                 # p-008 removed, p-009 added
    & $save $script:AfterDir 'policies' $policies

    $names = & $load $script:AfterDir 'resolved-names'
    $names['00000000-0000-0000-0000-000000000002'] = @{ displayName = 'Multifactor authentication'; type = 'authenticationStrength'; deleted = $false }
    $names['MicrosoftAdminPortals'] = @{ displayName = 'Microsoft Admin Portals (built-in app group)'; type = 'builtIn'; deleted = $false }
    & $save $script:AfterDir 'resolved-names' $names

    $locs = & $load $script:AfterDir 'named-locations'
    ($locs | Where-Object id -eq '55555555-5555-5555-5555-555555555501').ipRanges += @{ '@odata.type' = '#microsoft.graph.iPv4CidrRange'; cidrAddress = '198.51.100.0/24' }
    $locs += @{ '@odata.type' = '#microsoft.graph.ipNamedLocation'; id = '55555555-5555-5555-5555-555555555503'; displayName = 'Branch VPN'; isTrusted = $true; ipRanges = @(@{ '@odata.type' = '#microsoft.graph.iPv4CidrRange'; cidrAddress = '192.0.2.0/24' }) }
    & $save $script:AfterDir 'named-locations' $locs

    $str = & $load $script:AfterDir 'auth-strengths'
    ($str | Where-Object id -eq '00000000-0000-0000-0000-000000000004').allowedCombinations += 'password,sms'
    & $save $script:AfterDir 'auth-strengths' $str

    $g = & $load $script:AfterDir 'group-scope'
    ($g | Where-Object groupId -eq '22222222-2222-2222-2222-222222222201').members = @(
        @{ id = 'm2'; type = 'user'; displayName = 'Member Two'; userPrincipalName = 'two@contoso.example' }
        @{ id = 'm3'; type = 'user'; displayName = 'Member Three'; userPrincipalName = 'three@contoso.example' }
    )
    ($g | Where-Object groupId -eq '22222222-2222-2222-2222-222222222201').memberHash = 'changed'
    $big = $g | Where-Object groupId -eq '22222222-2222-2222-2222-222222222202'
    $big.memberCount = 350; $big.memberHash = 'changed-too'
    & $save $script:AfterDir 'group-scope' $g

    $meta = & $load $script:AfterDir 'metadata'
    $meta.timestampUtc = '2026-10-14T09:05:00.0000000Z'
    & $save $script:AfterDir 'metadata' $meta

    InModuleScope Tenantkeep.Posture -Parameters @{ B = $script:BeforeDir; A = $script:AfterDir } {
        $script:Diff = Compare-PostureCaModel -Before (Import-PostureCaSnapshot -Path $B) -After (Import-PostureCaSnapshot -Path $A)
    }
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
}

Describe 'ConvertTo-PostureCaFlatMap' {
    It 'flattens references to sorted names, scalars to strings, nulls to empty' {
        InModuleScope Tenantkeep.Posture {
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
        InModuleScope Tenantkeep.Posture {
            $c = Compare-PostureCaFlatMap -Before ([ordered]@{ x = '1'; y = '2'; gone = 'g' }) -After ([ordered]@{ x = '1'; y = '3'; new = 'n' })
            @($c | ForEach-Object { $_.path } | Sort-Object) | Should -Be @('gone', 'new', 'y')
            ($c | Where-Object path -eq 'y').before | Should -Be '2'
            ($c | Where-Object path -eq 'y').after | Should -Be '3'
        }
    }
}

Describe 'Compare-PostureCaModel' {
    It 'classifies added, removed and changed policies' {
        InModuleScope Tenantkeep.Posture {
            $script:Diff.policies.added.id | Should -Be @('p-009')
            $script:Diff.policies.removed.id | Should -Be @('p-008')
            @($script:Diff.policies.changed | ForEach-Object { $_.id }) | Should -Be @('p-001', 'p-002', 'p-003', 'p-005')
        }
    }

    It 'flags rename and state change separately from field changes' {
        InModuleScope Tenantkeep.Posture {
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
        InModuleScope Tenantkeep.Posture {
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
        InModuleScope Tenantkeep.Posture {
            $script:Diff.locations.added.name | Should -Be @('Branch VPN')
            ($script:Diff.locations.changed | Where-Object name -eq 'HQ egress').fields.path | Should -Contain 'ipRanges'
            ($script:Diff.strengths.changed | Where-Object name -eq 'Phishing-resistant MFA').fields.path | Should -Be @('allowedCombinations')
            $script:Diff.contexts.added.Count + $script:Diff.contexts.removed.Count + $script:Diff.contexts.changed.Count | Should -Be 0
        }
    }

    It 'reports scope drift with member detail when both sides have members' {
        InModuleScope Tenantkeep.Posture {
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
        InModuleScope Tenantkeep.Posture {
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
        InModuleScope Tenantkeep.Posture {
            @($script:Diff.risk | Where-Object rule -eq 'enabledPolicyRemoved').Count | Should -Be 0
            @($script:Diff.risk | Where-Object { $_.rule -eq 'deletedReference' -and $_.subject -like 'CA-007*' }).Count | Should -Be 0
        }
    }

    It 'uses an explicit break-glass list when given' {
        InModuleScope Tenantkeep.Posture {
            $none = Get-PostureCaRiskChange -Diff $script:Diff -BreakGlass @('someone-else@contoso.example')
            @($none | Where-Object rule -eq 'breakGlassExclusionRemoved').Count | Should -Be 0
            $hit = Get-PostureCaRiskChange -Diff $script:Diff -BreakGlass @('breakglass02@contoso.example')
            @($hit | Where-Object rule -eq 'breakGlassExclusionRemoved').Count | Should -Be 1
        }
    }

    It 'ranks authentication strength levels' {
        InModuleScope Tenantkeep.Posture {
            $mk = { param($combos, $controls) [ordered]@{ grant = [ordered]@{ builtInControls = $controls; authenticationStrength = $(if ($null -ne $combos) { [ordered]@{ id = 's'; name = 's'; deleted = $false; allowedCombinations = $combos } } else { $null }) } } }
            Get-PostureCaStrengthLevel -Policy (& $mk @('fido2', 'windowsHelloForBusiness') @()) | Should -Be 3
            Get-PostureCaStrengthLevel -Policy (& $mk @('fido2', 'microsoftAuthenticatorPush') @()) | Should -Be 2
            Get-PostureCaStrengthLevel -Policy (& $mk @('password,sms', 'fido2') @()) | Should -Be 1
            Get-PostureCaStrengthLevel -Policy (& $mk $null @('mfa')) | Should -Be 1
            Get-PostureCaStrengthLevel -Policy (& $mk $null @('block')) | Should -Be 0
        }
    }

    It 'returns nothing when both snapshots are the same' {
        InModuleScope Tenantkeep.Posture -Parameters @{ B = $script:BeforeDir } {
            $same = Compare-PostureCaModel -Before (Import-PostureCaSnapshot -Path $B) -After (Import-PostureCaSnapshot -Path $B)
            @($same.risk).Count | Should -Be 0
            $same.policies.added.Count + $same.policies.removed.Count + $same.policies.changed.Count | Should -Be 0
            @($same.scope).Count | Should -Be 0
        }
    }
}
