# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Write = { param([string] $Dir, [string] $Name, $Data) New-Item -ItemType Directory -Path $Dir -Force | Out-Null; ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }
    $script:Checks = {
        param([string] $Dir)
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
        $pf = Join-Path $Dir 'profile.json'
        '{ "version": 1, "identityModel": "hybrid-connect", "platforms": ["windows"], "licenses": ["Intune", "P1"] }' | Set-Content $pf
        $r = Invoke-PostureChecks -Evidence $Dir -Domain devices -ProfilePath $pf -PassThru; $by = @{}; foreach ($x in $r.results) { $by[$x.id] = $x }; @{ by = $by; run = $r }
    }
    # Hybrid-joined Windows devices in Entra: two nothing in the cloud manages, one Intune manages, one Configuration
    # Manager reports through tenant attach (Entra says not managed), and one that has not signed in for months.
    $script:Entra = @(
        @{ DeviceId = 'e1'; DisplayName = 'GP-ONLY-1'; OperatingSystem = 'Windows'; JoinType = 'HybridJoined'; AccountEnabled = $true; ApproximateLastSignInDateTime = '2026-11-01T00:00:00Z'; IsManaged = $false; Stale = $false }
        @{ DeviceId = 'e2'; DisplayName = 'GP-ONLY-2'; OperatingSystem = 'Windows'; JoinType = 'HybridJoined'; AccountEnabled = $true; ApproximateLastSignInDateTime = '2026-11-01T00:00:00Z'; IsManaged = $false; Stale = $false }
        @{ DeviceId = 'e3'; DisplayName = 'INTUNE-1'; OperatingSystem = 'Windows'; JoinType = 'HybridJoined'; AccountEnabled = $true; ApproximateLastSignInDateTime = '2026-11-01T00:00:00Z'; IsManaged = $true; Stale = $false }
        @{ DeviceId = 'e4'; DisplayName = 'SCCM-ONLY-1'; OperatingSystem = 'Windows'; JoinType = 'HybridJoined'; AccountEnabled = $true; ApproximateLastSignInDateTime = '2026-11-01T00:00:00Z'; IsManaged = $false; Stale = $false }
        @{ DeviceId = 'e5'; DisplayName = 'OLD-1'; OperatingSystem = 'Windows'; JoinType = 'HybridJoined'; AccountEnabled = $true; ApproximateLastSignInDateTime = '2026-11-01T00:00:00Z'; IsManaged = $false; Stale = $true }
    )
    $script:Managed = @(
        @{ DeviceName = 'INTUNE-1'; OperatingSystem = 'Windows'; OSVersion = '10.0.26100.1'; UserPrincipalName = 'user@contoso.example'; AutopilotEnrolled = $false; IsEncrypted = $true; ManagementAgent = 'mdm'; AzureAdDeviceId = 'e3'; ComplianceState = 'compliant'; IntuneWorkloads = '' }
        @{ DeviceName = 'SCCM-ONLY-1'; OperatingSystem = 'Windows'; OSVersion = '10.0.26100.1'; UserPrincipalName = 'user@contoso.example'; AutopilotEnrolled = $false; IsEncrypted = $true; ManagementAgent = 'configurationManagerClient'; AzureAdDeviceId = 'e4'; ComplianceState = 'unknown'; IntuneWorkloads = '' }
        @{ DeviceName = 'COMGMT-1'; OperatingSystem = 'Windows'; OSVersion = '10.0.26100.1'; UserPrincipalName = 'user@contoso.example'; AutopilotEnrolled = $false; IsEncrypted = $true; ManagementAgent = 'configurationManagerClientMdm'; AzureAdDeviceId = 'e6'; ComplianceState = 'compliant'; IntuneWorkloads = 'compliancePolicy;deviceConfiguration' }
        @{ DeviceName = 'COMGMT-2'; OperatingSystem = 'Windows'; OSVersion = '10.0.26100.1'; UserPrincipalName = 'user@contoso.example'; AutopilotEnrolled = $false; IsEncrypted = $true; ManagementAgent = 'configurationManagerClientMdm'; AzureAdDeviceId = 'e7'; ComplianceState = 'compliant'; IntuneWorkloads = 'compliancePolicy;deviceConfiguration;windowsUpdateForBusiness;endpointProtection' }
    )
}

Describe 'Who manages the Windows fleet' {
    It 'finds devices on Configuration Manager alone, hybrid devices with no cloud management, and co-management left half done' {
        $d = Join-Path $TestDrive 'mixed'
        & $script:Write $d '08-entra-devices' $script:Entra
        & $script:Write $d '09-intune-managed-devices' $script:Managed
        & $script:Write $d '09-intune-comanagement' @{ CoManagedDevices = 2; Workloads = @(@{ Name = 'compliancePolicy'; OnIntune = 2 }, @{ Name = 'windowsUpdateForBusiness'; OnIntune = 1 }) }
        $r = & $script:Checks $d
        $r.by['DEV-019'].status | Should -Be 'fail'
        @($r.by['DEV-019'].affected.name) | Should -Be @('SCCM-ONLY-1')
        $r.by['DEV-020'].status | Should -Be 'fail'
        @($r.by['DEV-020'].affected.name | Sort-Object) | Should -Be @('GP-ONLY-1', 'GP-ONLY-2') -Because 'the tenant-attached device is counted under Configuration Manager, and the stale one is not in use'
        $r.by['DEV-020'].observed['adOnlyWindowsPct'] | Should -Be 50
        $r.by['DEV-021'].status | Should -Be 'fail'
        @($r.by['DEV-021'].affected)[0].detail | Should -Be 'on Configuration Manager: Windows Update policies, endpoint protection'
    }

    It 'adds the workstations in AD that Entra does not know at all, leaving out servers, domain controllers and old ones' {
        $d = Join-Path $TestDrive 'with-ad'
        & $script:Write $d '08-entra-devices' $script:Entra
        & $script:Write $d '09-intune-managed-devices' $script:Managed
        & $script:Write $d 'ad-06-computers' @(
            @{ Name = 'GP-ONLY-1'; OperatingSystem = 'Windows 11 Enterprise'; IsServer = $false; IsDomainController = $false; Stale = $false }
            @{ Name = 'DESK-NOENTRA'; OperatingSystem = 'Windows 11 Enterprise'; IsServer = $false; IsDomainController = $false; Stale = $false }
            @{ Name = 'SRV-1'; OperatingSystem = 'Windows Server 2022 Standard'; IsServer = $true; IsDomainController = $false; Stale = $false }
            @{ Name = 'DC01'; OperatingSystem = 'Windows Server 2022 Standard'; IsServer = $true; IsDomainController = $true; Stale = $false }
            @{ Name = 'DESK-OLD'; OperatingSystem = 'Windows 10 Pro'; IsServer = $false; IsDomainController = $false; Stale = $true }
        )
        $r = & $script:Checks $d
        $o = $r.by['DEV-020'].observed
        $r.run.domains['devices'].facts['adWorkstationsNotInEntra'] | Should -Be 1
        $o['adOnlyWindowsPct'] | Should -Be 60 -Because 'three of five workstations in use: two hybrid and unmanaged, one Entra never heard of'
        @($r.by['DEV-020'].affected.name) | Should -Contain 'DESK-NOENTRA'
    }

    It 'passes when Intune manages everything, and says plainly when the evidence predates the workload read' {
        $d = Join-Path $TestDrive 'clean'
        & $script:Write $d '08-entra-devices' @($script:Entra[2])
        & $script:Write $d '09-intune-managed-devices' @($script:Managed[0])
        $r = & $script:Checks $d
        foreach ($id in 'DEV-019', 'DEV-020', 'DEV-021') { $r.by[$id].status | Should -Be 'pass' -Because "$id has nothing to flag" }
        $old = Join-Path $TestDrive 'old'
        & $script:Write $old '08-entra-devices' @($script:Entra[2])
        & $script:Write $old '09-intune-managed-devices' @(@{ DeviceName = 'COMGMT-OLD'; OperatingSystem = 'Windows'; OSVersion = '10.0.26100.1'; UserPrincipalName = 'user@contoso.example'; AutopilotEnrolled = $false; IsEncrypted = $true; ManagementAgent = 'configurationManagerClientMdm'; AzureAdDeviceId = 'e3'; ComplianceState = 'compliant' })
        $r2 = & $script:Checks $old
        $r2.by['DEV-021'].status | Should -Be 'notEvaluated'
        $r2.by['DEV-021'].reason | Should -Match 'collected before'
    }

    It 'draws the fleet by who manages it and the workloads moved' {
        $d = Join-Path $TestDrive 'chart'
        & $script:Write $d '08-entra-devices' $script:Entra
        & $script:Write $d '09-intune-managed-devices' $script:Managed
        & $script:Write $d '09-intune-comanagement' @{ CoManagedDevices = 2; Workloads = @(@{ Name = 'compliancePolicy'; OnIntune = 2 }, @{ Name = 'windowsUpdateForBusiness'; OnIntune = 1 }) }
        $facts = (& $script:Checks $d).run.domains['devices'].facts
        InModuleScope TenantKeep.Posture -Parameters @{ D = $d; F = $facts } {
            $c = Get-PostureChartData -Evidence $D -DomainFacts @{ devices = $F }
            @($c.deviceManagement.segment | ForEach-Object { $_.value }) | Should -Be @(1, 2, 1, 2, 0)
            $c.deviceManagement.takeaway | Should -Match '^50% of 6 Windows devices'
            @($c.coManagement.rows.label) | Should -Be @('Compliance policies', 'Windows Update policies')
            ($c.coManagement.rows | Where-Object label -eq 'Windows Update policies').onConfigMgr | Should -Be 1
        }
        $rep = New-PostureReport -Evidence $d -OutputPath (Join-Path $TestDrive 'out') -PassThru 6>$null
        $html = Get-Content -Raw ($rep.Files | Where-Object { $_ -like '*report.html' })
        $html | Should -Match 'Windows Devices by Who Manages Them'
        $html | Should -Match 'Co-management Workloads'
    }
}
