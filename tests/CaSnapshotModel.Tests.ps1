# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
    $script:Sample = Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot'
    $script:Pattern = '^CA-\d{3}-(Admins|Users|Guests|WorkloadIDs)-.+$'
    InModuleScope Tenantkeep.Posture -Parameters @{ Sample = $script:Sample; Pattern = $script:Pattern } {
        $script:Snap = Import-PostureCaSnapshot -Path $Sample
        $script:Models = ConvertTo-PostureCaPolicyModel -Snapshot $script:Snap -NamePattern $Pattern
        $script:ById = @{}
        foreach ($m in $script:Models) { $script:ById[$m.id] = $m }
    }
}

Describe 'Import-PostureCaSnapshot' {
    It 'loads the sample snapshot with every collection' {
        InModuleScope Tenantkeep.Posture {
            $script:Snap.Policies.Count | Should -Be 8
            $script:Snap.NamedLocations.Count | Should -Be 2
            $script:Snap.AuthStrengths.Count | Should -Be 3
            $script:Snap.AuthContexts.Count | Should -Be 1
            $script:Snap.ResolvedNames.Count | Should -BeGreaterThan 10
            $script:Snap.GroupScope.Keys.Count | Should -Be 4
            $script:Snap.Errors | Should -BeNullOrEmpty
            $script:Snap.Metadata.snapshotType | Should -Be 'conditional-access'
        }
    }

    It 'refuses a folder that is missing snapshot files' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-bad-$([guid]::NewGuid().ToString('n'))"
        New-Item -ItemType Directory -Path $tmp | Out-Null
        try {
            InModuleScope Tenantkeep.Posture -Parameters @{ Tmp = $tmp } { { Import-PostureCaSnapshot -Path $Tmp } | Should -Throw '*Not a CA snapshot folder*' }
        }
        finally { Remove-Item -LiteralPath $tmp -Recurse -Force }
    }

    It 'refuses a missing folder' {
        InModuleScope Tenantkeep.Posture { { Import-PostureCaSnapshot -Path '/definitely/not/here' } | Should -Throw '*not found*' }
    }
}

Describe 'ConvertTo-PostureCaPolicyModel' {
    It 'returns one model per policy sorted by name' {
        InModuleScope Tenantkeep.Posture {
            $script:Models.Count | Should -Be 8
            $names = @($script:Models | ForEach-Object { $_.name })
            $names | Should -Be @($names | Sort-Object)
        }
    }

    It 'maps state to enabled, reportOnly, disabled' {
        InModuleScope Tenantkeep.Posture {
            $script:ById['p-001'].state | Should -Be 'enabled'
            $script:ById['p-004'].state | Should -Be 'reportOnly'
            $script:ById['p-004'].stateLabel | Should -Be 'Report-only'
            $script:ById['p-006'].state | Should -Be 'disabled'
        }
    }

    It 'resolves ids to names with member counts and deleted markers' {
        InModuleScope Tenantkeep.Posture {
            $m = $script:ById['p-005']
            $m.assignments.excludeUsers[0].name | Should -Be 'BreakGlass-01'
            $m.assignments.excludeUsers[0].userPrincipalName | Should -Be 'breakglass01@contoso.example'
            ($m.assignments.excludeGroups | Where-Object name -eq 'CA-Exclude-MFA-Legacy').memberCount | Should -Be 341
            $gone = $m.assignments.excludeGroups | Where-Object deleted
            $gone.name | Should -Match '^<deleted group '
            $script:ById['p-001'].assignments.includeRoles.name | Should -Contain 'Global Administrator'
            $script:ById['p-001'].grant.authenticationStrength.name | Should -Be 'Phishing-resistant MFA'
            $script:ById['p-001'].grant.authenticationStrength.allowedCombinations | Should -Contain 'fido2'
        }
    }

    It 'parses dates as UTC' {
        InModuleScope Tenantkeep.Posture {
            $script:ById['p-001'].modified.Kind | Should -Be 'Utc'
            $script:ById['p-001'].modified.ToString('yyyy-MM-dd') | Should -Be '2026-01-15'
        }
    }

    It 'keeps the raw policy' {
        InModuleScope Tenantkeep.Posture { $script:ById['p-003'].raw.displayName | Should -Be 'Block legacy authentication' }
    }
}

Describe 'Get-PostureCaPolicySummary' {
    It 'writes the spec 5.2 sentence for <Id>' -ForEach @(
        @{ Id = 'p-001'; Expected = 'Require Phishing-resistant MFA for users in Global Administrator and 2 other roles, all cloud apps, any platform. Excludes BreakGlass-01, BreakGlass-02.' }
        @{ Id = 'p-002'; Expected = 'Require MFA for all users, all cloud apps, any platform, from any location except trusted locations, for browsers and modern clients. Excludes BreakGlass-01, BreakGlass-02, CA-Exclude-ServiceAccounts (12 members), CA-Exclude-MFA-Legacy (341 members).' }
        @{ Id = 'p-003'; Expected = 'Block access for all users, all cloud apps, any platform, for legacy authentication clients. Excludes CA-Exclude-LegacyAuth-Printers (0 members).' }
        @{ Id = 'p-004'; Expected = 'Report-only: Require MFA for guests and external users, Office 365, any platform.' }
        @{ Id = 'p-005'; Expected = 'Require a compliant device for all users, Office 365, on windows, macOS, with a device filter (exclude). Excludes BreakGlass-01, BreakGlass-02, CA-Exclude-MFA-Legacy (341 members), <deleted group 22222222-2222-2222-2222-222222222299>.' }
        @{ Id = 'p-006'; Expected = 'Disabled: Block access for all workload identities in the tenant, all cloud apps, any platform, from any location except HQ egress. Excludes Backup Runner.' }
        @{ Id = 'p-007'; Expected = "Block access for all users, the action 'register security information', any platform, from any location except trusted locations, <deleted namedLocation 55555555-5555-5555-5555-555555555599>." }
        @{ Id = 'p-008'; Expected = 'Report-only: Require MFA for all users, all cloud apps, any platform, when sign-in risk is high or medium.' }
    ) {
        InModuleScope Tenantkeep.Posture -Parameters @{ Id = $Id; Expected = $Expected } {
            $script:ById[$Id].summary | Should -Be $Expected
        }
    }
}

Describe 'Get-PostureCaHealthFlag' {
    It 'flags <Id> with <Codes>' -ForEach @(
        @{ Id = 'p-001'; Codes = @() }
        @{ Id = 'p-002'; Codes = @('exclusionGroupSize') }
        @{ Id = 'p-003'; Codes = @('emptyExcludedGroup', 'namingMismatch') }
        @{ Id = 'p-004'; Codes = @('reportOnlyAge') }
        @{ Id = 'p-005'; Codes = @('deletedReference', 'exclusionGroupSize') }
        @{ Id = 'p-006'; Codes = @('disabledAge') }
        @{ Id = 'p-007'; Codes = @('deletedReference') }
        @{ Id = 'p-008'; Codes = @('reportOnlyAge', 'namingMismatch') }
    ) {
        InModuleScope Tenantkeep.Posture -Parameters @{ Id = $Id; Codes = $Codes } {
            $actual = @($script:ById[$Id].healthFlags | ForEach-Object { $_.code } | Sort-Object)
            $actual | Should -Be @($Codes | Sort-Object)
        }
    }

    It 'measures ages from the snapshot timestamp, not from now' {
        InModuleScope Tenantkeep.Posture {
            # p-004 modified 2026-05-20, snapshot 2026-10-13: 146 days
            $f = $script:ById['p-004'].healthFlags | Where-Object code -eq 'reportOnlyAge'
            $f.message | Should -Match 'for 146 days'
        }
    }

    It 'honours thresholds and AsOf' {
        InModuleScope Tenantkeep.Posture {
            $models = ConvertTo-PostureCaPolicyModel -Snapshot $script:Snap -ExclusionGroupThreshold 500 -ReportOnlyDays 365 -AsOf ([datetime]'2026-06-01T00:00:00Z')
            $m = @{}; foreach ($x in $models) { $m[$x.id] = $x }
            @($m['p-002'].healthFlags).Count | Should -Be 0
            @($m['p-004'].healthFlags).Count | Should -Be 0
            @($m['p-008'].healthFlags | Where-Object code -eq 'reportOnlyAge').Count | Should -Be 0 -Because '243 days is under a 365-day threshold'
            @($m['p-003'].healthFlags | Where-Object code -eq 'namingMismatch').Count | Should -Be 0 -Because 'no pattern was given'
        }
    }

    It 'flags an empty assignment' {
        InModuleScope Tenantkeep.Posture {
            $p = [ordered]@{
                id = 'x'; name = 'x'; state = 'enabled'; modified = [datetime]::UtcNow
                assignments = [ordered]@{ includeUsers = @(); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @(); includeGuestsOrExternal = $null; excludeGuestsOrExternal = $null; includeServicePrincipals = @(); excludeServicePrincipals = @() }
                targets = [ordered]@{ includeApplications = @(); excludeApplications = @(); userActions = @(); authenticationContexts = @() }
                conditions = [ordered]@{ includeLocations = @(); excludeLocations = @() }
                grant = [ordered]@{ authenticationStrength = $null }
            }
            (Get-PostureCaHealthFlag -Policy $p -AsOf ([datetime]::UtcNow)).code | Should -Contain 'emptyAssignment'
        }
    }
}
