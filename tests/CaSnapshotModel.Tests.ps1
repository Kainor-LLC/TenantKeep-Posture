# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Sample = Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot'
    $script:Pattern = '^CA-\d{3}-(Admins|Users|Guests|WorkloadIDs)-.+$'
    InModuleScope TenantKeep.Posture -Parameters @{ Sample = $script:Sample; Pattern = $script:Pattern } {
        $script:Snap = Import-PostureCaSnapshot -Path $Sample
        $script:Models = ConvertTo-PostureCaPolicyModel -Snapshot $script:Snap -NamePattern $Pattern
        $script:ById = @{}
        foreach ($m in $script:Models) { $script:ById[$m.id] = $m }
    }
}

Describe 'Import-PostureCaSnapshot' {
    It 'loads the sample snapshot with every collection' {
        InModuleScope TenantKeep.Posture {
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
            InModuleScope TenantKeep.Posture -Parameters @{ Tmp = $tmp } { { Import-PostureCaSnapshot -Path $Tmp } | Should -Throw '*Not a CA snapshot folder*' }
        }
        finally { Remove-Item -LiteralPath $tmp -Recurse -Force }
    }

    It 'refuses a missing folder' {
        InModuleScope TenantKeep.Posture { { Import-PostureCaSnapshot -Path '/definitely/not/here' } | Should -Throw '*not found*' }
    }
}

Describe 'ConvertTo-PostureCaPolicyModel on policies the sample lacks' {
    BeforeAll {
        # A copy of the sample with one more policy: guest types object, an authentication context, the admin portals value. Shapes seen on a real tenant 2026-10-15.
        $script:Extra = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-ca-extra-$([guid]::NewGuid().ToString('n'))"
        Copy-Item -Path $script:Sample -Destination $script:Extra -Recurse
        $policiesPath = Join-Path $script:Extra 'policies.json'
        $policies = @(Get-Content -Raw $policiesPath | ConvertFrom-Json -AsHashtable -Depth 20)
        $policies += [ordered]@{
            id = 'p-extra'; displayName = 'CA-009-Guests-Require auth context for sensitive sites'; state = 'enabled'; createdDateTime = '2026-01-01T00:00:00Z'; modifiedDateTime = '2026-01-02T00:00:00Z'
            conditions = [ordered]@{
                users = [ordered]@{ includeUsers = @(); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @(); includeGuestsOrExternalUsers = [ordered]@{ guestOrExternalUserTypes = 'b2bCollaborationGuest,b2bCollaborationMember'; externalTenants = [ordered]@{ membershipKind = 'all' } } }
                applications = [ordered]@{ includeApplications = @('MicrosoftAdminPortals'); excludeApplications = @(); includeUserActions = @(); includeAuthenticationContextClassReferences = @('c1') }
                clientAppTypes = @('all'); locations = $null; platforms = $null
            }
            grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('mfa'); authenticationStrength = $null }
            sessionControls = $null
        }
        ConvertTo-Json -InputObject $policies -Depth 20 | Set-Content -LiteralPath $policiesPath
        InModuleScope TenantKeep.Posture -Parameters @{ Extra = $script:Extra } {
            $script:ExtraSnap = Import-PostureCaSnapshot -Path $Extra
            $script:ExtraModels = @(ConvertTo-PostureCaPolicyModel -Snapshot $script:ExtraSnap)
        }
    }
    AfterAll { Remove-Item -LiteralPath $script:Extra -Recurse -Force -ErrorAction SilentlyContinue }

    It 'models the guest type object, the authentication context and the admin portals value without an error' {
        InModuleScope TenantKeep.Posture {
            $script:ExtraModels.Count | Should -Be 9
            $m = $script:ExtraModels | Where-Object { $_.id -eq 'p-extra' }
            $m.assignments.includeGuestsOrExternal.guestOrExternalUserTypes | Should -Match 'b2bCollaborationGuest'
            @($m.targets.authenticationContexts).Count | Should -Be 1
            @($m.targets.includeApplications)[0].id | Should -Be 'MicrosoftAdminPortals'
            @($m.healthFlags | Where-Object { $_.code -eq 'deletedReference' }).Count | Should -Be 0
        }
    }

    It 'renders the document and evaluates the facts over it' {
        $out = Join-Path $script:Extra 'out'
        { New-PostureCaDocument -Snapshot $script:Extra -Format Html -OutputPath $out } | Should -Not -Throw
        InModuleScope TenantKeep.Posture -Parameters @{ Extra = $script:Extra } { (Get-PostureCaFact -Evidence $Extra).facts.policyCount | Should -Be 9 }
    }
}

Describe 'ConvertTo-PostureCaPolicyModel' {
    It 'returns one model per policy sorted by name' {
        InModuleScope TenantKeep.Posture {
            $script:Models.Count | Should -Be 8
            $names = @($script:Models | ForEach-Object { $_.name })
            $names | Should -Be @($names | Sort-Object)
        }
    }

    It 'maps state to enabled, reportOnly, disabled' {
        InModuleScope TenantKeep.Posture {
            $script:ById['p-001'].state | Should -Be 'enabled'
            $script:ById['p-004'].state | Should -Be 'reportOnly'
            $script:ById['p-004'].stateLabel | Should -Be 'Report-only'
            $script:ById['p-006'].state | Should -Be 'disabled'
        }
    }

    It 'resolves ids to names with member counts and deleted markers' {
        InModuleScope TenantKeep.Posture {
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

    It 'parses dates as UTC regardless of the machine time zone' {
        InModuleScope TenantKeep.Posture {
            $script:ById['p-001'].modified.Kind | Should -Be 'Utc'
            $script:ById['p-001'].modified.ToString('yyyy-MM-dd HH:mm') | Should -Be '2026-01-15 09:30'
            $script:ById['p-003'].created.ToString('yyyy-MM-dd HH:mm') | Should -Be '2025-03-04 10:10'
        }
    }

    It 'normalises strings, local DateTimes and DateTimeOffsets to UTC' {
        InModuleScope TenantKeep.Posture {
            (ConvertTo-PostureUtcDateTime '2025-03-04T10:10:00Z').ToString('HH:mm') | Should -Be '10:10'
            (ConvertTo-PostureUtcDateTime '2025-03-04T10:10:00+02:00').ToString('HH:mm') | Should -Be '08:10'
            $local = [datetime]::new(2025, 3, 4, 10, 10, 0, [System.DateTimeKind]::Utc).ToLocalTime()
            (ConvertTo-PostureUtcDateTime $local).ToString('HH:mm') | Should -Be '10:10'
            (ConvertTo-PostureUtcDateTime ([System.DateTimeOffset]::Parse('2025-03-04T10:10:00-05:00'))).ToString('HH:mm') | Should -Be '15:10'
            ConvertTo-PostureUtcDateTime $null | Should -BeNullOrEmpty
        }
    }

    It 'keeps the raw policy' {
        InModuleScope TenantKeep.Posture { $script:ById['p-003'].raw.displayName | Should -Be 'Block legacy authentication' }
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
        InModuleScope TenantKeep.Posture -Parameters @{ Id = $Id; Expected = $Expected } {
            $script:ById[$Id].summary | Should -Be $Expected
        }
    }
}

Describe 'Get-PostureCaSessionSummary' {
    It 'describes session-only policies instead of calling them uncontrolled' {
        InModuleScope TenantKeep.Posture {
            $base = [ordered]@{
                state = 'enabled'
                assignments = [ordered]@{ includeUsers = @([ordered]@{ id = 'All'; name = 'All (built-in)'; type = 'builtIn'; deleted = $false }); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @(); includeGuestsOrExternal = $null; excludeGuestsOrExternal = $null; includeServicePrincipals = @(); excludeServicePrincipals = @() }
                targets = [ordered]@{ includeApplications = @([ordered]@{ id = 'All'; name = 'All (built-in)'; type = 'builtIn'; deleted = $false }); excludeApplications = @(); userActions = @(); authenticationContexts = @() }
                conditions = [ordered]@{ clientAppTypes = @(); includePlatforms = @(); excludePlatforms = @(); includeLocations = @(); excludeLocations = @(); signInRiskLevels = @(); userRiskLevels = @(); insiderRiskLevels = $null; deviceFilter = $null }
                grant = [ordered]@{ operator = $null; builtInControls = @(); authenticationStrength = $null; termsOfUse = @(); customFactors = @() }
                session = [ordered]@{ signInFrequency = @{ isEnabled = $true; value = 4; type = 'hours'; frequencyInterval = 'timeBased' }; persistentBrowser = @{ isEnabled = $true; mode = 'never' }; applicationEnforcedRestrictions = $null; cloudAppSecurity = $null; continuousAccessEvaluation = $null; secureSignInSession = $null; disableResilienceDefaults = $null }
            }
            Get-PostureCaPolicySummary -Policy $base | Should -Be 'Apply session controls (sign-in frequency 4 hours, non-persistent browser) for all users, all cloud apps, any platform.'
            $base.session = [ordered]@{ signInFrequency = $null; persistentBrowser = $null; applicationEnforcedRestrictions = $null; cloudAppSecurity = $null; continuousAccessEvaluation = $null; secureSignInSession = @{ isEnabled = $true }; disableResilienceDefaults = $null }
            Get-PostureCaPolicySummary -Policy $base | Should -Be 'Apply session controls (token protection) for all users, all cloud apps, any platform.'
            $base.session = [ordered]@{ signInFrequency = $null; persistentBrowser = $null; applicationEnforcedRestrictions = $null; cloudAppSecurity = $null; continuousAccessEvaluation = $null; secureSignInSession = $null; disableResilienceDefaults = $null }
            Get-PostureCaPolicySummary -Policy $base | Should -Be 'Grant access with no controls for all users, all cloud apps, any platform.'
            $base.conditions.includePlatforms = @('all'); $base.conditions.excludePlatforms = @('windows', 'macOS')
            Get-PostureCaPolicySummary -Policy $base | Should -Match 'on all platforms except windows, macOS\.$'
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
        InModuleScope TenantKeep.Posture -Parameters @{ Id = $Id; Codes = $Codes } {
            $actual = @($script:ById[$Id].healthFlags | ForEach-Object { $_.code } | Sort-Object)
            $actual | Should -Be @($Codes | Sort-Object)
        }
    }

    It 'measures ages from the snapshot timestamp, not from now' {
        InModuleScope TenantKeep.Posture {
            # p-004 modified 2026-05-20, snapshot 2026-10-13: 146 days
            $f = $script:ById['p-004'].healthFlags | Where-Object code -eq 'reportOnlyAge'
            $f.message | Should -Match 'for 146 days'
        }
    }

    It 'honours thresholds and AsOf' {
        InModuleScope TenantKeep.Posture {
            $models = ConvertTo-PostureCaPolicyModel -Snapshot $script:Snap -ExclusionGroupThreshold 500 -ReportOnlyDays 365 -AsOf ([datetime]'2026-06-01T00:00:00Z')
            $m = @{}; foreach ($x in $models) { $m[$x.id] = $x }
            @($m['p-002'].healthFlags).Count | Should -Be 0
            @($m['p-004'].healthFlags).Count | Should -Be 0
            @($m['p-008'].healthFlags | Where-Object code -eq 'reportOnlyAge').Count | Should -Be 0 -Because '243 days is under a 365-day threshold'
            @($m['p-003'].healthFlags | Where-Object code -eq 'namingMismatch').Count | Should -Be 0 -Because 'no pattern was given'
        }
    }

    It 'flags an empty assignment' {
        InModuleScope TenantKeep.Posture {
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
