# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-experience-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $script:Write = { param([string] $Dir, [string] $Name, $Data) New-Item -ItemType Directory -Path $Dir -Force | Out-Null; ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }
    $script:Facts = { param([string] $Dir) InModuleScope TenantKeep.Posture -Parameters @{ D = $Dir } { param($D) Clear-PostureEvidenceCache; Get-PostureExperienceFact -Evidence $D } }
    $script:Checks = { param([string] $Dir) $r = Invoke-PostureChecks -Evidence $Dir -Domain experience -PassThru; $by = @{}; foreach ($x in $r.results) { $by[$x.id] = $x }; $by }
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Get-PostureExperienceFact' {
    It 'is unavailable without Entra or Intune evidence, even with a CA snapshot' {
        $d = Join-Path $script:Root 'ca-only'
        & $script:Write $d 'policies' @(@{ displayName = 'p'; state = 'enabled' })
        (& $script:Facts $d).available | Should -BeFalse
    }

    It 'reads OneDrive, Edge, the Enrollment Status Page, restore, Autopilot naming and branding' {
        $d = Join-Path $script:Root 'devices'
        & $script:Write $d '09-intune-config-profiles-settings-catalog' @(@{ Id = 'od'; Assignments = 1 }, @{ Id = 'edge'; Assignments = 1 }, @{ Id = 'draft'; Assignments = 0 })
        & $script:Write $d '09-intune-policy-settings' @(
            @{ PolicyId = 'od'; PolicyName = 'OneDrive'; SettingDefinitionId = 'device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_silentaccountconfig'; Value = 'device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_silentaccountconfig_1' }
            @{ PolicyId = 'draft'; PolicyName = 'Draft'; SettingDefinitionId = 'device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmsilentoptin'; Value = 'device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmsilentoptin_1' }
            @{ PolicyId = 'edge'; PolicyName = 'Edge lockdown'; SettingDefinitionId = 'device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge_browsersignin'; Value = 'device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge_browsersignin_0' }
        )
        & $script:Write $d '09-intune-enrollment-restrictions' @(@{ Type = 'windows10EnrollmentCompletionPageConfiguration'; Assignments = 1; ShowInstallationProgress = $true }, @{ Type = 'windowsRestoreDeviceEnrollmentConfiguration'; Assignments = 1; State = 'notConfigured' })
        & $script:Write $d '09-autopilot-profiles' @(@{ DisplayName = 'Standard'; DeviceNameTemplate = 'CTS-%SERIAL%'; Assignments = 1 }, @{ DisplayName = 'Kiosk'; DeviceNameTemplate = $null; Assignments = 1 })
        & $script:Write $d '01-company-branding' @{ Present = $true; HasBannerLogo = $true; HasSignInText = $true }
        $by = & $script:Checks $d
        $by['UX-001'].status | Should -Be 'fail' -Because 'the folder move sits in an unassigned policy'
        $by['UX-001'].observed['onedriveSilentSignIn'] | Should -BeTrue
        $by['UX-002'].status | Should -Be 'fail'
        $by['UX-002'].affected[0].name | Should -Be 'Edge lockdown'
        $by['UX-003'].status | Should -Be 'pass'
        $by['UX-004'].status | Should -Be 'fail'
        $by['UX-005'].affected.name | Should -Be @('Kiosk')
        $by['UX-006'].status | Should -Be 'pass'
    }

    It 'flags short sign-in frequency for everyone but not for admin roles or risk, and judges self-service reset' {
        $d = Join-Path $script:Root 'access'
        & $script:Write $d 'policies' @(
            @{ displayName = 'Everyone 4h'; state = 'enabled'; conditions = @{ users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('All') } }; sessionControls = @{ signInFrequency = @{ isEnabled = $true; type = 'hours'; value = 4; frequencyInterval = 'timeBased' } } }
            @{ displayName = 'Admins 4h'; state = 'enabled'; conditions = @{ users = @{ includeUsers = @('All'); includeRoles = @('62e90394-69f5-4237-9190-012177145e10') }; applications = @{ includeApplications = @('All') } }; sessionControls = @{ signInFrequency = @{ isEnabled = $true; type = 'hours'; value = 4; frequencyInterval = 'timeBased' } } }
            @{ displayName = 'Risky every time'; state = 'enabled'; conditions = @{ signInRiskLevels = @('high'); users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('All') } }; sessionControls = @{ signInFrequency = @{ isEnabled = $true; frequencyInterval = 'everyTime' } } }
            @{ displayName = 'Everyone 7d'; state = 'enabled'; conditions = @{ users = @{ includeUsers = @('All') } }; sessionControls = @{ signInFrequency = @{ isEnabled = $true; type = 'days'; value = 7; frequencyInterval = 'timeBased' } } }
        )
        & $script:Write $d '05-auth-registration' @(@{ UserType = 'member'; IsSsprEnabled = $true }, @{ UserType = 'member'; IsSsprEnabled = $false }, @{ UserType = 'guest'; IsSsprEnabled = $false })
        $by = & $script:Checks $d
        $by['UX-007'].affected.name | Should -Be @('Everyone 4h')
        $by['UX-008'].status | Should -Be 'fail'
        $by['UX-008'].observed['ssprEnabledPct'] | Should -Be 50 -Because 'guests are not counted'
    }

    It 'compares sign-in names with email and finds Last, First display names, and asks for a fresh collection on old evidence' {
        $d = Join-Path $script:Root 'users'
        & $script:Write $d '06-users' @(
            @{ UserPrincipalName = 'jane@contoso.example'; Mail = 'jane@contoso.example'; DisplayName = 'Jane Doe'; GivenName = 'Jane'; Surname = 'Doe'; UserType = 'Member'; AccountEnabled = $true }
            @{ UserPrincipalName = 'jsmith@contoso.onmicrosoft.com'; Mail = 'john.smith@contoso.example'; DisplayName = 'Smith, John'; GivenName = 'John'; Surname = 'Smith'; UserType = 'Member'; AccountEnabled = $true }
            @{ UserPrincipalName = 'ext#EXT#@contoso.example'; Mail = 'x@partner.example'; DisplayName = 'Partner, X'; UserType = 'Guest'; AccountEnabled = $true }
        )
        $by = & $script:Checks $d
        $by['UX-009'].affected.name | Should -Be @('jsmith@contoso.onmicrosoft.com')
        $by['UX-010'].affected.name | Should -Be @('Smith, John') -Because 'guests are someone else''s directory'
        $old = Join-Path $script:Root 'users-old'
        & $script:Write $old '06-users' @(@{ UserPrincipalName = 'jane@contoso.example'; DisplayName = 'Jane Doe'; UserType = 'Member'; AccountEnabled = $true })
        $f = & $script:Facts $old
        $f.notEvaluated['UX-009'] | Should -Match 'collected before'
    }
}
