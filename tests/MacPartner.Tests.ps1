# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Write = { param([string] $Dir, [string] $Name, $Data) New-Item -ItemType Directory -Path $Dir -Force | Out-Null; ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }
    $script:Checks = {
        param([string] $Dir, [string] $MacMdm = 'none', [string[]] $Domain = @('devices'))
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
        $pf = Join-Path $Dir 'profile.json'
        @{ version = 1; identityModel = 'cloud-only'; platforms = @('windows', 'macOS'); licenses = @('Intune', 'P1'); thirdParty = @{ mdm = 'none'; macMdm = $MacMdm; edr = 'none' } } | ConvertTo-Json -Depth 5 | Set-Content $pf
        $r = Invoke-PostureChecks -Evidence $Dir -Domain $Domain -ProfilePath $pf -PassThru; $by = @{}; foreach ($x in $r.results) { $by[$x.id] = $x }; $by
    }
    $script:Recent = [datetime]::UtcNow.AddDays(-1).ToString('o')
    $script:Old = [datetime]::UtcNow.AddDays(-30).ToString('o')
    $script:Base = {
        param([string] $Dir)
        & $script:Write $Dir '08-entra-devices' @(
            @{ DeviceId = 'm1'; DisplayName = 'MAC-1'; OperatingSystem = 'MacMDM'; JoinType = 'Registered'; AccountEnabled = $true; ApproximateLastSignInDateTime = $script:Recent; IsManaged = $true; IsCompliant = $true; Stale = $false }
            @{ DeviceId = 'm2'; DisplayName = 'MAC-2'; OperatingSystem = 'MacMDM'; JoinType = 'Registered'; AccountEnabled = $true; ApproximateLastSignInDateTime = $script:Recent; IsManaged = $true; IsCompliant = $true; Stale = $false }
            @{ DeviceId = 'm3'; DisplayName = 'MAC-3'; OperatingSystem = 'MacMDM'; JoinType = 'Registered'; AccountEnabled = $true; ApproximateLastSignInDateTime = $script:Recent; IsManaged = $true; IsCompliant = $false; Stale = $false }
        )
        & $script:Write $Dir '09-intune-managed-devices' @(@{ DeviceName = 'MAC-1'; OperatingSystem = 'macOS'; OSVersion = '15.1'; UserPrincipalName = 'u@contoso.example'; ManagementAgent = 'jamf'; AzureAdDeviceId = 'm1'; ComplianceState = 'compliant'; AutopilotEnrolled = $false; IsEncrypted = $true; IntuneWorkloads = '' })
    }
}

Describe 'Macs on a partner MDM' {
    It 'says nothing when no Mac MDM is in play' {
        $d = Join-Path $TestDrive 'none'
        & $script:Write $d '08-entra-devices' @()
        & $script:Write $d '09-intune-managed-devices' @()
        & $script:Write $d '09-intune-compliance-partners' @()
        & $script:Write $d '09-intune-device-management-partners' @()
        $by = & $script:Checks $d
        $by['DEV-022'].status | Should -Be 'pass'
        $by['DEV-023'].status | Should -Be 'pass'
    }

    It 'fails the link when the profile names Jamf but Intune has no partner, and when the partner stopped reporting' {
        $d = Join-Path $TestDrive 'missing'
        & $script:Base $d
        & $script:Write $d '09-intune-compliance-partners' @()
        & $script:Write $d '09-intune-device-management-partners' @()
        $by = & $script:Checks $d 'Jamf'
        $by['DEV-022'].status | Should -Be 'fail'
        @($by['DEV-022'].affected)[0].detail | Should -Be 'no partner connected in Intune for macOS'
        $stale = Join-Path $TestDrive 'stale'
        & $script:Base $stale
        & $script:Write $stale '09-intune-compliance-partners' @(@{ DisplayName = 'Jamf'; PartnerState = 'enabled'; LastHeartbeatDateTime = $script:Old; MacOsOnboarded = $true })
        & $script:Write $stale '09-intune-device-management-partners' @()
        $by2 = & $script:Checks $stale
        $by2['DEV-022'].status | Should -Be 'fail' -Because 'Intune lists Macs from Jamf, so a partner is expected even with the profile at none'
        @($by2['DEV-022'].affected)[0].detail | Should -Match 'last heartbeat 30 days ago'
    }

    It 'passes a live link and judges the Macs Entra shows compliant' {
        $d = Join-Path $TestDrive 'live'
        & $script:Base $d
        & $script:Write $d '09-intune-compliance-partners' @(@{ DisplayName = 'Jamf'; PartnerState = 'enabled'; LastHeartbeatDateTime = $script:Recent; MacOsOnboarded = $true })
        & $script:Write $d '09-intune-device-management-partners' @()
        $by = & $script:Checks $d 'Jamf'
        $by['DEV-022'].status | Should -Be 'pass'
        $by['DEV-023'].status | Should -Be 'fail'
        $by['DEV-023'].observed['macEntraCompliantPct'] | Should -Be 66.7
        @($by['DEV-023'].affected.name) | Should -Be @('MAC-3')
        $rep = New-PostureReport -Evidence $d -OutputPath (Join-Path $TestDrive 'out-live') -PassThru 6>$null
        $html = Get-Content -Raw ($rep.Files | Where-Object { $_ -like '*report.html' })
        $html | Should -Match 'Macs on a Partner MDM'
        $html | Should -Match '2 of 3 Macs in use are compliant in Entra, as reported by Jamf'
        $html | Should -Match 'id="inv-mdm-partners"'
    }

    It 'lists in the inventory only the partners the tenant has set up, not every partner Microsoft offers' {
        # Intune answers with its whole catalogue: a partner nobody set up has the state unknown and a heartbeat in the year 1.
        $offered = @('Relution', 'NinjaOne', 'Addigy') | ForEach-Object { @{ DisplayName = $_; PartnerState = 'unknown'; LastHeartbeatDateTime = '0001-01-01T00:00:00Z'; MacOsOnboarded = $false; IosOnboarded = $false; AndroidOnboarded = $false; LinuxOnboarded = $false } }
        $section = {
            param([string] $Dir)
            InModuleScope TenantKeep.Posture -Parameters @{ Dir = $Dir } { param($Dir) Clear-PostureEvidenceCache; @(Get-PostureInventory -Evidence $Dir | Where-Object { $_.key -eq 'mdm-partners' })[0] }
        }
        $none = Join-Path $TestDrive 'offered-only'
        & $script:Write $none '09-intune-compliance-partners' @($offered)
        & $script:Write $none '09-intune-device-management-partners' @(@{ DisplayName = 'Legacy MDM'; PartnerState = 'unknown'; IsConfigured = $false; LastHeartbeatDateTime = '0001-01-01T00:00:00Z' })
        $empty = & $section $none
        $empty.total | Should -Be 0
        $empty.note | Should -Be 'No device management partner is connected to Intune. Microsoft lists 4 that Intune can connect to, and none is set up in this tenant.'

        $some = Join-Path $TestDrive 'offered-and-used'
        & $script:Write $some '09-intune-compliance-partners' (@($offered) + @(
                @{ DisplayName = 'Jamf'; PartnerState = 'enabled'; LastHeartbeatDateTime = '2026-11-20T08:15:00Z'; MacOsOnboarded = $true }
                @{ DisplayName = 'Broken Partner'; PartnerState = 'terminated'; LastHeartbeatDateTime = '0001-01-01T00:00:00Z'; MacOsOnboarded = $false }
            ))
        & $script:Write $some '09-intune-device-management-partners' @()
        $used = & $section $some
        @($used.rows | ForEach-Object { $_.Partner }) | Should -Be @('Jamf', 'Broken Partner')
        $used.rows[0].'Last Heartbeat' | Should -Be '2026-11-20'
        $used.rows[1].'Last Heartbeat' | Should -Be 'never' -Because 'the year 1 is how Microsoft writes no heartbeat'
        $used.note | Should -BeNullOrEmpty
    }

    It 'lets a Mac-only MDM cover the macOS checks and nothing else' {
        $d = Join-Path $TestDrive 'covered'
        & $script:Base $d
        & $script:Write $d '09-intune-compliance-partners' @(@{ DisplayName = 'Jamf'; PartnerState = 'enabled'; LastHeartbeatDateTime = $script:Recent; MacOsOnboarded = $true })
        $by = & $script:Checks $d 'Jamf' @('devices', 'endpoint')
        foreach ($id in 'DEV-006', 'EP-015', 'EP-016', 'EP-017') { $by[$id].status | Should -Be 'coveredBy' -Because "$id is a macOS check" }
        $by['EP-001'].status | Should -Not -Be 'coveredBy' -Because 'a Mac MDM does not manage Windows'
        $by['DEV-022'].status | Should -Not -Be 'coveredBy' -Because 'the link itself is what a Mac MDM must have'
    }

    It 'says when the evidence predates the partner read' {
        $d = Join-Path $TestDrive 'old'
        & $script:Base $d
        $by = & $script:Checks $d 'Jamf'
        $by['DEV-022'].status | Should -Be 'notEvaluated'
        $by['DEV-022'].reason | Should -Match 'Resume-PostureRun -Collector Intune'
    }

    It 'discovers the Mac MDM from a connected partner, without overriding a vendor the profile already names' {
        $d = Join-Path $TestDrive 'discover'
        & $script:Base $d
        & $script:Write $d '09-intune-compliance-partners' @(@{ DisplayName = 'Jamf'; PartnerState = 'enabled'; LastHeartbeatDateTime = $script:Recent; MacOsOnboarded = $true })
        $p1 = Join-Path $TestDrive 'p1.json'
        $null = New-PostureProfile -Path $p1 -Evidence $d -NonInteractive 6>$null
        (Get-Content -Raw $p1 | ConvertFrom-Json).thirdParty.macMdm | Should -Be 'Jamf'
        $p2 = Join-Path $TestDrive 'p2.json'
        $null = New-PostureProfile -Path $p2 -Evidence $d -NonInteractive -ThirdParty @{ macMdm = 'Kandji' } 6>$null
        (Get-Content -Raw $p2 | ConvertFrom-Json).thirdParty.macMdm | Should -Be 'Kandji'
    }
}
