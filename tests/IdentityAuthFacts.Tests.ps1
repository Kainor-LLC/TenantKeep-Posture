# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-idauth-$([guid]::NewGuid().ToString('n'))"
    $script:Ev = Initialize-CollectionFixture -Root (Join-Path $script:Root 'evidence')
    $script:AsOf = [datetime]::new(2026, 10, 14, 0, 0, 0, [System.DateTimeKind]::Utc)
    InModuleScope TenantKeep.Posture -Parameters @{ E = $script:Ev; AsOf = $script:AsOf } {
        $script:Id = Get-PostureIdentityFact -Evidence $E -OrgProfile (Import-PostureProfile) -Thresholds @{} -AsOf $AsOf
        $script:Au = Get-PostureAuthFact -Evidence $E -OrgProfile (Import-PostureProfile) -Thresholds @{}
    }
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
}

Describe 'Get-PostureIdentityFact' {
    It 'computes <Fact> = <Expected>' -ForEach @(
        @{ Fact = 'globalAdmins'; Expected = 4 }
        @{ Fact = 'permanentPrivilegedOutsideBreakGlass'; Expected = 2 }
        @{ Fact = 'eligiblePrivileged'; Expected = 1 }
        @{ Fact = 'adminsSyncedFromOnPrem'; Expected = 1 }
        @{ Fact = 'adminsWithLicenses'; Expected = 1 }
        @{ Fact = 'servicePrincipalsWithRoles'; Expected = 1 }
        @{ Fact = 'servicePrincipalsWithGlobalAdmin'; Expected = 1 }
        @{ Fact = 'breakGlassAccounts'; Expected = 1 }
        @{ Fact = 'breakGlassSynced'; Expected = 0 }
        @{ Fact = 'userConsentMode'; Expected = 'all' }
        @{ Fact = 'adminConsentWorkflowEnabled'; Expected = $false }
        @{ Fact = 'appCredentialsExpired'; Expected = 1 }
        @{ Fact = 'appCredentialsExpiringSoon'; Expected = 1 }
        @{ Fact = 'highPrivilegeAppPermissions'; Expected = 1 }
        @{ Fact = 'inactiveGuests'; Expected = 2 }
        @{ Fact = 'crossTenantInboundDefaultOpen'; Expected = $true }
        @{ Fact = 'highRiskUsersUnaddressed'; Expected = 1 }
        @{ Fact = 'pimPolicyRolesChecked'; Expected = 4 }
        @{ Fact = 'pimPolicyCompliantRoles'; Expected = 2 }
    ) {
        InModuleScope TenantKeep.Posture -Parameters @{ Fact = $Fact; Expected = $Expected } { $script:Id.facts[$Fact] | Should -Be $Expected }
    }

    It 'names the affected objects and the checks it cannot evaluate' {
        InModuleScope TenantKeep.Posture {
            $script:Id.affected.permanentPrivilegedOutsideBreakGlass.name | Should -Be @('Admin One: Global Administrator', 'Admin Two: Global Administrator')
            $script:Id.affected.adminsWithLicenses.name | Should -Be @('admin1@contoso.example')
            $script:Id.affected.inactiveGuests.name | Should -Be @('old_guest#EXT#@contoso.example', 'never_guest#EXT#@contoso.example')
            $script:Id.affected.appCredentialProblems.name | Should -Be @('Old App', 'Soon App')
            $script:Id.affected.highRiskUsersUnaddressed.name | Should -Be @('admin1@contoso.example')
            $script:Id.affected.pimPolicyProblems.name | Should -Be @('Global Administrator', 'Security Administrator')
            ($script:Id.affected.pimPolicyProblems | Where-Object name -eq 'Global Administrator').detail | Should -Be 'no approval'
            ($script:Id.affected.pimPolicyProblems | Where-Object name -eq 'Security Administrator').detail | Should -Match 'no MFA on activation, activation up to 24h'
            $script:Id.notEvaluated.Keys | Should -Not -Contain 'ID-006'
            $script:Id.notEvaluated.Keys | Should -Contain 'ID-014'
            $script:Id.notEvaluated.Keys | Should -Not -Contain 'ID-015'
        }
    }

    It 'uses the profile break-glass list and marks missing files' {
        InModuleScope TenantKeep.Posture -Parameters @{ E = $script:Ev; AsOf = $script:AsOf; Root = $script:Root } {
            $p = Import-PostureProfile; $p.breakGlass = @('admin1@contoso.example')
            $f = Get-PostureIdentityFact -Evidence $E -OrgProfile $p -Thresholds @{ maxGlobalAdmins = 2 } -AsOf $AsOf
            $f.facts.permanentPrivilegedOutsideBreakGlass | Should -Be 2 -Because 'BreakGlass-01 is no longer break-glass by the profile list, Admin One is'
            $f.facts.breakGlassAccounts | Should -Be 1
            $empty = Join-Path $Root 'empty'; New-Item -ItemType Directory -Path $empty -Force | Out-Null
            $g = Get-PostureIdentityFact -Evidence $empty -AsOf $AsOf
            $g.notEvaluated['ID-001'] | Should -Match '04-role-assignments-active.json was not collected'
            $g.notEvaluated['ID-015'] | Should -Match 'P2'
            '[]' | Set-Content (Join-Path $empty '11-risky-users.json')
            $h = Get-PostureIdentityFact -Evidence $empty -AsOf $AsOf
            $h.notEvaluated.Keys | Should -Not -Contain 'ID-015' -Because 'an empty list is a collected, clean result'
            $h.facts.highRiskUsersUnaddressed | Should -Be 0
        }
    }
}

Describe 'Get-PostureAuthFact' {
    It 'computes <Fact> = <Expected>' -ForEach @(
        @{ Fact = 'smsEnabledForAllUsers'; Expected = $true }
        @{ Fact = 'voiceEnabledForAllUsers'; Expected = $false }
        @{ Fact = 'authenticatorEnabled'; Expected = $true }
        @{ Fact = 'authenticatorAppInformation'; Expected = $false }
        @{ Fact = 'authenticatorLocationInformation'; Expected = $true }
        @{ Fact = 'fido2Enabled'; Expected = $true }
        @{ Fact = 'policyMigrationState'; Expected = 'migrationInProgress' }
        @{ Fact = 'tapEnabled'; Expected = $true }
        @{ Fact = 'tapOneTimeDefault'; Expected = $false }
        @{ Fact = 'mfaRegisteredPct'; Expected = 75 }
        @{ Fact = 'passwordlessCapablePct'; Expected = 50 }
        @{ Fact = 'admins'; Expected = 5 }
        @{ Fact = 'adminsWithoutPhishingResistant'; Expected = 3 }   # admin1 (push, sms), admin3 (push), auditor (Global Reader, nothing registered)
        @{ Fact = 'perUserMfaEnforced'; Expected = 1 }
        @{ Fact = 'perUserMfaEnabled'; Expected = 0 }
    ) {
        InModuleScope TenantKeep.Posture -Parameters @{ Fact = $Fact; Expected = $Expected } { $script:Au.facts[$Fact] | Should -Be $Expected }
    }

    It 'marks AU-009 not evaluated when every per-user MFA read failed' {
        InModuleScope TenantKeep.Posture -Parameters @{ Root = $script:Root } {
            $dir = Join-Path $Root 'mfa-errors'; New-Item -ItemType Directory -Path $dir -Force | Out-Null
            @{ Users = 5; Enforced = 0; Enabled = 0; Disabled = 0; Errors = 5; FirstError = "400 Resource not found for the segment 'requirements'." } | ConvertTo-Json | Set-Content (Join-Path $dir '05-per-user-mfa-summary.json')
            $f = Get-PostureAuthFact -Evidence $dir
            $f.notEvaluated['AU-009'] | Should -Match "Every per-user MFA read failed \(400 Resource not found"
        }
    }

    It 'lists admins without a phishing-resistant method, joining roles and the report' {
        InModuleScope TenantKeep.Posture {
            $script:Au.affected.adminsWithoutPhishingResistant.name | Should -Be @('admin1@contoso.example', 'admin3@contoso.example', 'auditor@contoso.example')
            $script:Au.notEvaluated.Keys | Should -BeNullOrEmpty
            $script:Au.affected.perUserMfaEnforced.name | Should -Be @('admin2@contoso.example')
        }
    }
}

Describe 'Invoke-PostureChecks for identity and auth on the fixture' {
    BeforeAll {
        $script:Run = Invoke-PostureChecks -Evidence $script:Ev -Domain identity, auth -OutputPath $script:Root -PassThru
        $script:By = @{}; foreach ($r in $script:Run.results) { $script:By[$r.id] = $r }
    }

    It 'evaluates 24 checks' { $script:Run.results.Count | Should -Be 24 }

    It 'gives <Id> status <Status>' -ForEach @(
        @{ Id = 'ID-001'; Status = 'pass' }
        @{ Id = 'ID-002'; Status = 'fail' }
        @{ Id = 'ID-003'; Status = 'fail' }
        @{ Id = 'ID-004'; Status = 'fail' }
        @{ Id = 'ID-005'; Status = 'pass' }
        @{ Id = 'ID-006'; Status = 'fail' }
        @{ Id = 'ID-007'; Status = 'fail' }
        @{ Id = 'ID-008'; Status = 'fail' }
        @{ Id = 'ID-009'; Status = 'fail' }
        @{ Id = 'ID-010'; Status = 'fail' }
        @{ Id = 'ID-011'; Status = 'fail' }
        @{ Id = 'ID-012'; Status = 'fail' }
        @{ Id = 'ID-013'; Status = 'fail' }
        @{ Id = 'ID-014'; Status = 'notEvaluated' }
        @{ Id = 'ID-015'; Status = 'fail' }
        @{ Id = 'AU-001'; Status = 'fail' }
        @{ Id = 'AU-002'; Status = 'fail' }
        @{ Id = 'AU-003'; Status = 'pass' }
        @{ Id = 'AU-004'; Status = 'fail' }
        @{ Id = 'AU-005'; Status = 'fail' }
        @{ Id = 'AU-006'; Status = 'fail' }
        @{ Id = 'AU-007'; Status = 'pass' }
        @{ Id = 'AU-008'; Status = 'fail' }
        @{ Id = 'AU-009'; Status = 'fail' }
    ) {
        $script:By[$Id].status | Should -Be $Status
    }

    It 'covers the MFA checks when the profile names a third-party MFA vendor' {
        $p = Join-Path $script:Root 'profile.json'
        $null = New-PostureProfile -Path $p -NonInteractive -ThirdParty @{ mfa = 'duo' } -Licenses P1
        $r = Invoke-PostureChecks -Evidence $script:Ev -Domain auth, identity -Profile $p -OutputPath (Join-Path $script:Root 'p') -PassThru
        ($r.results | Where-Object id -eq 'AU-001').status | Should -Be 'coveredBy'
        ($r.results | Where-Object id -eq 'ID-002').status | Should -Be 'notEvaluated'
        ($r.results | Where-Object id -eq 'ID-002').reason | Should -Be 'Requires P2.'
    }
}
