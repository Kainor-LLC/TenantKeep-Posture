# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-gaps-$([guid]::NewGuid().ToString('n'))"
    $script:Write = { param([string] $Dir, [string] $Name, $Data) New-Item -ItemType Directory -Path $Dir -Force | Out-Null; ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }
    $script:Checks = {
        param([string] $Dir, [string[]] $Domain, [string] $ProfileJson)
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
        $p = @{}; if ($ProfileJson) { $pf = Join-Path $Dir 'profile.json'; $ProfileJson | Set-Content $pf; $p.ProfilePath = $pf }
        $r = Invoke-PostureChecks -Evidence $Dir -Domain $Domain -PassThru @p; $by = @{}; foreach ($x in $r.results) { $by[$x.id] = $x }; $by
    }
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Gap checks from existing evidence' {
    It 'judges outbound spam action, the attachment filter and partner connectors' {
        $d = Join-Path $script:Root 'mail'
        & $script:Write $d 'exo-04-outbound-spam' @(@{ Name = 'Default'; AutoForwardingMode = 'Off'; ActionWhenThresholdReached = 'Alert' }, @{ Name = 'Strict'; AutoForwardingMode = 'Off'; ActionWhenThresholdReached = 'BlockUser' })
        & $script:Write $d 'exo-04-eop-malware' @(@{ Name = 'Default'; ZapEnabled = $true; EnableFileFilter = $true }, @{ Name = 'Legacy'; ZapEnabled = $true; EnableFileFilter = $false })
        & $script:Write $d 'exo-03-inbound-connectors' @(@{ Name = 'Partner A'; Enabled = $true; ConnectorType = 'Partner'; RestrictDomainsToCertificate = $true }, @{ Name = 'Partner B'; Enabled = $true; ConnectorType = 'Partner' }, @{ Name = 'OnPrem'; Enabled = $true; ConnectorType = 'OnPremises' })
        $by = & $script:Checks $d 'email'
        $by['EM-022'].affected.name | Should -Be @('Default')
        $by['EM-023'].affected.name | Should -Be @('Legacy')
        $by['EM-024'].affected.name | Should -Be @('Partner B') -Because 'only partner connectors are judged, and Partner A requires a certificate'
    }

    It 'fails OneDrive Anyone links even when the tenant allows them for sites' {
        $d = Join-Path $script:Root 'spo'
        & $script:Write $d 'spo-tenant-settings' @{ SharingCapability = 'ExternalUserAndGuestSharing'; OneDriveSharingCapability = 'ExternalUserAndGuestSharing' }
        (& $script:Checks $d 'collaboration')['CL-016'].status | Should -Be 'fail'
    }

    It 'reads personal enrollment against the BYOD stance, and the no-policy compliance default' {
        $d = Join-Path $script:Root 'dev'
        & $script:Write $d '09-intune-enrollment-restrictions' @(@{ Type = 'deviceEnrollmentPlatformRestrictionsConfiguration'; Assignments = 1; windowsPersonalBlocked = $true; iosPersonalBlocked = $true; androidPersonalBlocked = $false; macOSPersonalBlocked = $false })
        & $script:Write $d '09-intune-settings' @{ SecureByDefault = $true }
        $mam = & $script:Checks $d 'devices' '{ "version": 1, "byod": "mam", "platforms": ["windows", "iOS", "android"] }'
        $mam['DEV-016'].affected.name | Should -Be @('android') -Because 'macOS is not in the profile''s platforms'
        $mam['DEV-017'].status | Should -Be 'pass'
        $mdm = & $script:Checks $d 'devices' '{ "version": 1, "byod": "mdm", "platforms": ["windows", "iOS", "android"] }'
        $mdm['DEV-016'].status | Should -Be 'pass' -Because 'a full-management stance means personal enrollment is intended'
    }

    It 'passes DEV-018 for a hybrid tenant once GPOs are analysed, and lists them in the inventory lowest support first' {
        $d = Join-Path $script:Root 'gpo'
        & $script:Write $d '09-intune-gpo-analytics' @(@{ DisplayName = 'Browser'; MigrationReadiness = 'complete'; TotalSettings = 10; SupportedSettings = 10; SupportedPercent = 100; TargetedInActiveDirectory = $true }, @{ DisplayName = 'Legacy drive maps'; MigrationReadiness = 'none'; TotalSettings = 8; SupportedSettings = 0; SupportedPercent = 0; TargetedInActiveDirectory = $true })
        $by = & $script:Checks $d 'devices' '{ "version": 1, "identityModel": "hybrid-connect" }'
        $by['DEV-018'].status | Should -Be 'pass'
        $inv = InModuleScope TenantKeep.Posture -Parameters @{ D = $d } { param($D) Clear-PostureEvidenceCache; @(Get-PostureInventory -Evidence $D) | Where-Object key -EQ 'gpo-analytics' }
        $inv.rows[0].GPO | Should -Be 'Legacy drive maps'
        $inv.rows[0].Readiness | Should -Be 'None'
    }
}

