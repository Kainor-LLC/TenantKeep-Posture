# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureDevicesFact {
    <#
    .SYNOPSIS
        Fact provider for the devices domain (spec 4.4): Entra devices, Intune managed devices, Autopilot, Apple
        certificates, enrollment restrictions, endpoint security policies, the MDE connector, the cleanup rule and
        BitLocker key presence.
    .DESCRIPTION
        Thresholds read: minCompliancePct, maxHybridJoinedPct, minAutopilotPct, minBitLockerEscrowedPct,
        minMacEncryptedPct, minAppleCertDays, minLinuxDevices. Profile read: platforms, byod.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [Parameter()] [System.Collections.IDictionary] $OrgProfile = @{},
        [Parameter()] [System.Collections.IDictionary] $Thresholds = @{},
        [datetime] $AsOf = [datetime]::UtcNow
    )

    $ErrorActionPreference = 'Stop'
    $t = @{ minCompliancePct = 0; maxHybridJoinedPct = 100; minAutopilotPct = 0; minBitLockerEscrowedPct = 100; minMacEncryptedPct = 100; minAppleCertDays = 60; minLinuxDevices = 0 }
    foreach ($k in @($Thresholds.Keys)) { $t[$k] = $Thresholds[$k] }
    $load = {
        param([string] $Name)
        $f = Join-Path $Evidence "$Name.json"
        if (-not (Test-Path -LiteralPath $f)) { return $null }
        $text = Get-Content -Raw -LiteralPath $f
        if ([string]::IsNullOrWhiteSpace($text)) { return , @() }
        $parsed = ConvertFrom-Json -InputObject $text -AsHashtable -Depth 20
        if ($null -eq $parsed) { return , @() }
        return $parsed
    }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $pct = { param([double] $n, [double] $d) if ($d -le 0) { $null } else { [Math]::Round(100.0 * $n / $d, 1) } }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    $missing = { param([string[]] $Ids, [string] $File) foreach ($id in $Ids) { $notEvaluated[$id] = "$File.json was not collected (Invoke-PostureCollection -Collector Intune; check errors.txt and the scopes)." } }

    # Entra devices (08)
    $entra = & $load '08-entra-devices'
    if ($null -eq $entra) { & $missing @('DEV-002', 'DEV-003', 'DEV-005') '08-entra-devices' }
    else {
        $enabled = @($entra | Where-Object { $_ -and $_.AccountEnabled -ne $false })
        $facts.entraDevices = $enabled.Count
        $facts.entraJoined = @($enabled | Where-Object { $_.JoinType -eq 'EntraJoined' }).Count
        $facts.hybridJoined = @($enabled | Where-Object { $_.JoinType -eq 'HybridJoined' }).Count
        $facts.registered = @($enabled | Where-Object { $_.JoinType -eq 'Registered' }).Count
        $facts.hybridJoinedPct = $(if ($enabled.Count -gt 0) { & $pct $facts.hybridJoined $enabled.Count } else { 0 })
        $stale = @($enabled | Where-Object { $_.Stale -eq $true })
        $facts.staleEntraDevices = $stale.Count
        $affected.staleEntraDevices = @($stale | ForEach-Object { [ordered]@{ name = $_.DisplayName; detail = "$($_.JoinType), $($_.OperatingSystem), last sign-in $(if ($_.ApproximateLastSignInDateTime) { (ConvertTo-PostureUtcDateTime $_.ApproximateLastSignInDateTime).ToString('yyyy-MM-dd') } else { 'never' })" } })

        $keys = & $load '08-bitlocker-keys-by-device'
        $windows = @($enabled | Where-Object { $_.OperatingSystem -eq 'Windows' -and $_.JoinType -in @('EntraJoined', 'HybridJoined') })
        if ($null -eq $keys) { & $missing @('DEV-005') '08-bitlocker-keys-by-device' }
        else {
            $withKey = @{}; foreach ($k in @($keys | Where-Object { $_ })) { $withKey[[string]$k.DeviceId] = [int]$k.Keys }
            $escrowed = @($windows | Where-Object { $withKey.ContainsKey([string]$_.DeviceId) })
            $facts.windowsEntraDevices = $windows.Count
            $facts.bitlockerEscrowedPct = $(if ($windows.Count -gt 0) { & $pct $escrowed.Count $windows.Count } else { 100 })
            $affected.windowsDevicesWithoutBitLockerKey = @($windows | Where-Object { -not $withKey.ContainsKey([string]$_.DeviceId) } | ForEach-Object { [ordered]@{ name = $_.DisplayName; detail = 'no BitLocker recovery key in Entra' } })
        }
    }

    # Intune managed devices (09)
    $managed = & $load '09-intune-managed-devices'
    if ($null -eq $managed) { & $missing @('DEV-001', 'DEV-004', 'DEV-006', 'DEV-007', 'DEV-014') '09-intune-managed-devices' }
    else {
        $m = @($managed | Where-Object { $_ })
        $facts.managedDevices = $m.Count
        $known = @($m | Where-Object { $_.ComplianceState -in @('compliant', 'noncompliant', 'inGracePeriod', 'conflict', 'error') })
        $compliant = @($known | Where-Object { $_.ComplianceState -eq 'compliant' })
        $facts.intuneCompliancePct = $(if ($known.Count -gt 0) { & $pct $compliant.Count $known.Count } else { $null })
        $byPlat = [ordered]@{}
        foreach ($os in @($m | ForEach-Object { $_.OperatingSystem } | Sort-Object -Unique)) {
            $k = @($known | Where-Object { $_.OperatingSystem -eq $os }); $c = @($k | Where-Object { $_.ComplianceState -eq 'compliant' })
            $byPlat[[string]$os] = $(if ($k.Count -gt 0) { & $pct $c.Count $k.Count } else { $null })
        }
        $facts.compliancePctByPlatform = $byPlat
        $affected.noncompliantDevices = @($known | Where-Object { $_.ComplianceState -ne 'compliant' } | ForEach-Object { [ordered]@{ name = $_.DeviceName; detail = "$($_.OperatingSystem) $($_.OSVersion), $($_.ComplianceState), user $($_.UserPrincipalName)" } })
        if ($null -eq $facts.intuneCompliancePct) { $notEvaluated['DEV-001'] = 'No Intune managed devices with a compliance state.' }

        $win = @($m | Where-Object { $_.OperatingSystem -eq 'Windows' })
        $facts.windowsManagedDevices = $win.Count
        $auto = & $load '09-autopilot-devices'
        if ($null -eq $auto) { & $missing @('DEV-004') '09-autopilot-devices' }
        else {
            $autoCount = @($win | Where-Object { $_.AutopilotEnrolled -eq $true }).Count
            $facts.autopilotRegistered = @($auto | Where-Object { $_ }).Count
            $facts.autopilotPct = $(if ($win.Count -gt 0) { & $pct $autoCount $win.Count } else { $null })
            if ($null -eq $facts.autopilotPct) { $notEvaluated['DEV-004'] = 'No Windows devices managed by Intune.' }
        }

        $macs = @($m | Where-Object { $_.OperatingSystem -eq 'macOS' })
        $facts.macManagedDevices = $macs.Count
        $facts.macEncryptedPct = $(if ($macs.Count -gt 0) { & $pct @($macs | Where-Object { $_.IsEncrypted -eq $true }).Count $macs.Count } else { $null })
        $affected.macsNotEncrypted = @($macs | Where-Object { $_.IsEncrypted -ne $true } | ForEach-Object { [ordered]@{ name = $_.DeviceName; detail = 'FileVault not reported as enabled' } })
        if ($null -eq $facts.macEncryptedPct) { $notEvaluated['DEV-006'] = 'No macOS devices managed by Intune.' }

        $win10 = @($win | Where-Object { [string]$_.OSVersion -match '^10\.0\.1\d{4}' })
        $facts.windows10Devices = $win10.Count
        $affected.windows10Devices = @($win10 | ForEach-Object { [ordered]@{ name = $_.DeviceName; detail = "Windows build $($_.OSVersion)" } })

        $facts.linuxManagedDevices = @($m | Where-Object { $_.OperatingSystem -match '(?i)linux|ubuntu' }).Count
    }

    # Apple certificates
    $apns = & $load '09-apple-push-cert'
    $vpp = & $load '09-apple-vpp-tokens'
    if ($null -eq $apns) { & $missing @('DEV-008') '09-apple-push-cert' }
    else {
        $facts.applePushCertPresent = [bool](& $v $apns 'Present')
        $exp = ConvertTo-PostureUtcDateTime (& $v $apns 'ExpirationDateTime')
        $facts.applePushCertDays = $(if ($exp) { [Math]::Floor(($exp - $AsOf).TotalDays) } else { 0 })
        $soon = @(@($vpp | Where-Object { $_ }) | Where-Object { $e = ConvertTo-PostureUtcDateTime $_.ExpirationDateTime; $e -and [Math]::Floor(($e - $AsOf).TotalDays) -lt [int]$t.minAppleCertDays })
        $facts.vppTokens = @($vpp | Where-Object { $_ }).Count
        $facts.vppTokensExpiringSoon = $soon.Count
        $affected.appleExpiry = @(@($(if ($facts.applePushCertPresent -and $facts.applePushCertDays -lt [int]$t.minAppleCertDays) { [ordered]@{ name = 'Apple push certificate'; detail = "expires in $($facts.applePushCertDays) day(s)" } })) + @($soon | ForEach-Object { [ordered]@{ name = "VPP token $($_.OrganizationName)"; detail = "expires $((ConvertTo-PostureUtcDateTime $_.ExpirationDateTime).ToString('yyyy-MM-dd'))" } }))
    }

    # Enrollment restrictions
    $restrict = & $load '09-intune-enrollment-restrictions'
    if ($null -eq $restrict) { & $missing @('DEV-009') '09-intune-enrollment-restrictions' }
    else {
        $facts.windowsPersonalEnrollmentBlocked = [bool](@($restrict | Where-Object { $_ -and ($_.Contains('windowsPersonalBlocked') -and $_.windowsPersonalBlocked -eq $true) }).Count -gt 0)
    }

    # Endpoint security policies by template family, and LAPS
    $catalog = & $load '09-intune-config-profiles-settings-catalog'
    if ($null -eq $catalog) { & $missing @('DEV-010', 'DEV-011') '09-intune-config-profiles-settings-catalog' }
    else {
        $assigned = @($catalog | Where-Object { $_ -and [int]$_.Assignments -gt 0 })
        $families = [ordered]@{ antivirus = 'endpointSecurityAntivirus'; diskEncryption = 'endpointSecurityDiskEncryption'; firewall = 'endpointSecurityFirewall'; attackSurfaceReduction = 'endpointSecurityAttackSurfaceReductionRules'; endpointDetectionAndResponse = 'endpointSecurityEndpointDetectionAndResponse' }
        $present = @($families.Keys | Where-Object { $fam = $families[$_]; @($assigned | Where-Object { [string]$_.TemplateFamily -eq $fam }).Count -gt 0 })
        $facts.endpointSecurityFamiliesRequired = $families.Count
        $facts.endpointSecurityFamiliesAssigned = $present.Count
        $affected.endpointSecurityFamiliesMissing = @($families.Keys | Where-Object { $_ -notin $present } | ForEach-Object { [ordered]@{ name = $_; detail = 'no assigned endpoint security policy of this type' } })
        $facts.lapsPoliciesAssigned = @($assigned | Where-Object { [string]$_.TemplateFamily -eq 'endpointSecurityAccountProtection' -and ([string]$_.TemplateDisplayName -match '(?i)LAPS|local admin' -or [string]$_.Name -match '(?i)LAPS') }).Count
    }

    $mde = & $load '09-intune-mde-connector'
    if ($null -eq $mde) { & $missing @('DEV-012') '09-intune-mde-connector' }
    else { $facts.mdeConnectorEnabled = [bool](@($mde | Where-Object { $_ -and $_.PartnerState -eq 'available' -and ($_.WindowsEnabled -eq $true -or $_.MacEnabled -eq $true -or $_.MicrosoftDefenderForEndpointAttachEnabled -eq $true) }).Count -gt 0) }

    $cleanup = & $load '09-intune-device-cleanup'
    if ($null -eq $cleanup) { & $missing @('DEV-013') '09-intune-device-cleanup'; if (-not $facts.Contains('deviceCleanupRuleEnabled')) { $facts.deviceCleanupRuleEnabled = $false } }
    else { $facts.deviceCleanupRuleEnabled = [bool](& $v $cleanup 'Enabled'); $facts.deviceCleanupDays = & $v $cleanup 'DeviceInactivityBeforeRetirementInDays' }

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('08-entra-devices.json', '09-intune-managed-devices.json', '09-intune-config-profiles-settings-catalog.json') }
}
