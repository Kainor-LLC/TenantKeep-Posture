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
    # Parsed once per evaluation and shared with the other domains (Read-PostureEvidenceFile); a missing file is
    # $null, an empty one an empty array.
    $load = {
        param([string] $Name)
        $parsed = Read-PostureEvidenceFile -Folder $Evidence -Name $Name
        if ($null -eq $parsed) { return $null }
        if ($parsed -is [array] -and $parsed.Count -eq 0) { return , @() }
        return $parsed
    }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $pct = { param([double] $n, [double] $d) if ($d -le 0) { $null } else { [Math]::Round(100.0 * $n / $d, 1) } }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    $missing = { param([string[]] $Ids, [string] $File) foreach ($id in $Ids) { $notEvaluated[$id] = "$File.json was not collected (Invoke-PostureCollection -Collector Intune; check errors.txt and the scopes)." } }

    # Entra devices (08): one pass, a row at a time, every count and affected list built on the way.
    $keys = & $load '08-bitlocker-keys-by-device'
    $withKey = @{}; foreach ($k in @($keys | Where-Object { $_ })) { $withKey[[string]$k.DeviceId] = [int]$k.Keys }
    $e = @{ enabled = 0; entraJoined = 0; hybridJoined = 0; registered = 0; windows = 0; escrowed = 0 }
    $staleList = [System.Collections.Generic.List[object]]::new(); $noKey = [System.Collections.Generic.List[object]]::new()
    $haveEntra = Read-PostureEvidenceRow -Folder $Evidence -Name '08-entra-devices' -OnRow {
        param($_row)
        $row = $_row
        if ([string]$row.AccountEnabled -eq 'False') { return }
        $e.enabled++
        switch ([string]$row.JoinType) { 'EntraJoined' { $e.entraJoined++ } 'HybridJoined' { $e.hybridJoined++ } 'Registered' { $e.registered++ } }
        if (Test-PostureTrue $row.Stale) { $staleList.Add([ordered]@{ name = $row.DisplayName; detail = "$($row.JoinType), $($row.OperatingSystem), last sign-in $(if ($row.ApproximateLastSignInDateTime) { (ConvertTo-PostureUtcDateTime $row.ApproximateLastSignInDateTime).ToString('yyyy-MM-dd') } else { 'never' })" }) }
        if ([string]$row.OperatingSystem -eq 'Windows' -and [string]$row.JoinType -in @('EntraJoined', 'HybridJoined')) {
            $e.windows++
            if ($withKey.ContainsKey([string]$row.DeviceId)) { $e.escrowed++ } else { $noKey.Add([ordered]@{ name = $row.DisplayName; detail = 'no BitLocker recovery key in Entra' }) }
        }
    }
    if (-not $haveEntra) { & $missing @('DEV-002', 'DEV-003', 'DEV-005') '08-entra-devices' }
    else {
        $facts.entraDevices = $e.enabled
        $facts.entraJoined = $e.entraJoined; $facts.hybridJoined = $e.hybridJoined; $facts.registered = $e.registered
        $facts.hybridJoinedPct = $(if ($e.enabled -gt 0) { & $pct $e.hybridJoined $e.enabled } else { 0 })
        $facts.staleEntraDevices = $staleList.Count
        $affected.staleEntraDevices = @($staleList)
        if ($null -eq $keys) { & $missing @('DEV-005') '08-bitlocker-keys-by-device' }
        else {
            $facts.windowsEntraDevices = $e.windows
            $facts.bitlockerEscrowedPct = $(if ($e.windows -gt 0) { & $pct $e.escrowed $e.windows } else { 100 })
            $affected.windowsDevicesWithoutBitLockerKey = @($noKey)
        }
    }

    # Intune managed devices (09): one pass as well.
    $i = @{ total = 0; known = 0; compliant = 0; windows = 0; autopilot = 0; macs = 0; macsEncrypted = 0; linux = 0 }
    $plat = @{}
    $noncompliant = [System.Collections.Generic.List[object]]::new(); $macsOpen = [System.Collections.Generic.List[object]]::new(); $win10 = [System.Collections.Generic.List[object]]::new()
    $states = @('compliant', 'noncompliant', 'inGracePeriod', 'conflict', 'error')
    $haveManaged = Read-PostureEvidenceRow -Folder $Evidence -Name '09-intune-managed-devices' -OnRow {
        param($_row)
        $row = $_row
        $i.total++
        $os = [string]$row.OperatingSystem
        if (-not $plat.ContainsKey($os)) { $plat[$os] = @{ known = 0; compliant = 0 } }
        $state = [string]$row.ComplianceState
        if ($state -in $states) {
            $i.known++; $plat[$os].known++
            if ($state -eq 'compliant') { $i.compliant++; $plat[$os].compliant++ }
            else { $noncompliant.Add([ordered]@{ name = $row.DeviceName; detail = "$($row.OperatingSystem) $($row.OSVersion), $($row.ComplianceState), user $($row.UserPrincipalName)" }) }
        }
        if ($os -eq 'Windows') {
            $i.windows++
            if (Test-PostureTrue $row.AutopilotEnrolled) { $i.autopilot++ }
            if ([string]$row.OSVersion -match '^10\.0\.1\d{4}') { $win10.Add([ordered]@{ name = $row.DeviceName; detail = "Windows build $($row.OSVersion)" }) }
        }
        if ($os -eq 'macOS') { $i.macs++; if (Test-PostureTrue $row.IsEncrypted) { $i.macsEncrypted++ } else { $macsOpen.Add([ordered]@{ name = $row.DeviceName; detail = 'FileVault not reported as enabled' }) } }
        if ($os -match '(?i)linux|ubuntu') { $i.linux++ }
    }
    if (-not $haveManaged) { & $missing @('DEV-001', 'DEV-004', 'DEV-006', 'DEV-007', 'DEV-014') '09-intune-managed-devices' }
    else {
        $facts.managedDevices = $i.total
        $facts.intuneCompliancePct = $(if ($i.known -gt 0) { & $pct $i.compliant $i.known } else { $null })
        $byPlat = [ordered]@{}
        foreach ($os in @($plat.Keys | Sort-Object)) { $byPlat[$os] = $(if ($plat[$os].known -gt 0) { & $pct $plat[$os].compliant $plat[$os].known } else { $null }) }
        $facts.compliancePctByPlatform = $byPlat
        $affected.noncompliantDevices = @($noncompliant)
        if ($null -eq $facts.intuneCompliancePct) { $notEvaluated['DEV-001'] = 'No Intune managed devices with a compliance state.' }

        $facts.windowsManagedDevices = $i.windows
        $auto = & $load '09-autopilot-devices'
        if ($null -eq $auto) { & $missing @('DEV-004') '09-autopilot-devices' }
        else {
            $facts.autopilotRegistered = @($auto | Where-Object { $_ }).Count
            $facts.autopilotPct = $(if ($i.windows -gt 0) { & $pct $i.autopilot $i.windows } else { $null })
            if ($null -eq $facts.autopilotPct) { $notEvaluated['DEV-004'] = 'No Windows devices managed by Intune.' }
        }

        $facts.macManagedDevices = $i.macs
        $facts.macEncryptedPct = $(if ($i.macs -gt 0) { & $pct $i.macsEncrypted $i.macs } else { $null })
        $affected.macsNotEncrypted = @($macsOpen)
        if ($null -eq $facts.macEncryptedPct) { $notEvaluated['DEV-006'] = 'No macOS devices managed by Intune.' }

        $facts.windows10Devices = $win10.Count
        $affected.windows10Devices = @($win10)
        $facts.linuxManagedDevices = $i.linux
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
    if ($null -eq $restrict) { & $missing @('DEV-009', 'DEV-016') '09-intune-enrollment-restrictions' }
    else {
        $facts.windowsPersonalEnrollmentBlocked = [bool](@($restrict | Where-Object { $_ -and ($_.Contains('windowsPersonalBlocked') -and $_.windowsPersonalBlocked -eq $true) }).Count -gt 0)
        # DEV-016: personal phones and Macs enrol only when the profile's BYOD stance is full management.
        $byod = $(if ($OrgProfile.Contains('byod')) { [string]$OrgProfile['byod'] } else { 'mam' })
        $inScope = @($(if ($OrgProfile.Contains('platforms')) { $OrgProfile['platforms'] } else { @('iOS', 'android', 'macOS') }))
        $open = @()
        if ($byod -ne 'mdm') {
            $default = @($restrict | Where-Object { $_ -and [string]$_.Type -eq 'deviceEnrollmentPlatformRestrictionsConfiguration' })
            foreach ($pair in @(@('iOS', 'ios'), @('android', 'android'), @('macOS', 'macOS'))) {
                if ($pair[0] -notin $inScope) { continue }
                $key = "$($pair[1])PersonalBlocked"
                if (@($default | Where-Object { $_.Contains($key) -and $_[$key] -eq $true }).Count -eq 0) { $open += [ordered]@{ name = $pair[0]; detail = "personal devices can enrol; the profile's BYOD stance is $byod" } }
            }
        }
        $facts.personalPlatformsOpen = $open.Count
        $affected.personalPlatformsOpen = $open
    }
    # DEV-018: Group Policy analysed for the move to Intune (hybrid tenants).
    $gpa = & $load '09-intune-gpo-analytics'
    if ($null -eq $gpa) { & $missing @('DEV-018') '09-intune-gpo-analytics' }
    else {
        $g = @($gpa | Where-Object { $_ })
        $facts.gposAnalysed = $g.Count
        $tot = [double](@($g | ForEach-Object { [double](& $v $_ 'TotalSettings') }) + 0 | Measure-Object -Sum).Sum
        $sup = [double](@($g | ForEach-Object { [double](& $v $_ 'SupportedSettings') }) + 0 | Measure-Object -Sum).Sum
        $facts.gpoSettingsSupportedPct = $(if ($tot -gt 0) { [Math]::Round(100 * $sup / $tot, 1) } else { $null })
    }
    # DEV-017: a device with no compliance policy counts as noncompliant, so CA-005 cannot be passed by omission.
    $ims = & $load '09-intune-settings'
    if ($null -eq $ims) { & $missing @('DEV-017') '09-intune-settings' }
    else { $facts.noPolicyMeansNoncompliant = (& $v $ims 'SecureByDefault') -eq $true }

    # Endpoint security policies by template family, and LAPS
    $catalog = & $load '09-intune-config-profiles-settings-catalog'
    if ($null -eq $catalog) { & $missing @('DEV-010', 'DEV-011') '09-intune-config-profiles-settings-catalog' }
    else {
        $assigned = @($catalog | Where-Object { $_ -and [int]$_.Assignments -gt 0 })
        # Template family values as Graph returns them (confirmed 2026-10-14): attack surface reduction has no 'Rules' suffix.
        $families = [ordered]@{ antivirus = 'endpointSecurityAntivirus'; diskEncryption = 'endpointSecurityDiskEncryption'; firewall = 'endpointSecurityFirewall'; attackSurfaceReduction = 'endpointSecurityAttackSurfaceReduction'; endpointDetectionAndResponse = 'endpointSecurityEndpointDetectionAndResponse' }
        $present = @($families.Keys | Where-Object { $fam = $families[$_]; @($assigned | Where-Object { [string]$_.TemplateFamily -like "$fam*" }).Count -gt 0 })
        $facts.endpointSecurityFamiliesRequired = $families.Count
        $facts.endpointSecurityFamiliesAssigned = $present.Count
        $affected.endpointSecurityFamiliesMissing = @($families.Keys | Where-Object { $_ -notin $present } | ForEach-Object { [ordered]@{ name = $_; detail = 'no assigned endpoint security policy of this type' } })
        $facts.lapsPoliciesAssigned = @($assigned | Where-Object { [string]$_.TemplateFamily -eq 'endpointSecurityAccountProtection' -and ([string]$_.TemplateDisplayName -match '(?i)LAPS|local admin' -or [string]$_.Name -match '(?i)LAPS') }).Count
    }

    $mde = & $load '09-intune-mde-connector'
    if ($null -eq $mde) { & $missing @('DEV-012') '09-intune-mde-connector' }
    else { $facts.mdeConnectorEnabled = [bool](@($mde | Where-Object { $_ -and $_.PartnerState -in @('available', 'enabled') -and ($_.WindowsEnabled -eq $true -or $_.MacEnabled -eq $true -or $_.MicrosoftDefenderForEndpointAttachEnabled -eq $true) }).Count -gt 0) }

    # Compliance on device risk (DEV-015): on every platform with an assigned compliance policy, one of them asks
    # Defender for a risk level, so a device under attack stops counting as compliant. Files collected before the
    # setting was read (2026-11-20) do not carry it.
    $cp = & $load '09-intune-compliance-policies'
    $hasKey = { param($o, [string] $k) if ($o -is [System.Collections.IDictionary]) { $o.Contains($k) } else { $null -ne $o.PSObject.Properties[$k] } }
    if ($null -eq $cp) { & $missing @('DEV-015') '09-intune-compliance-policies' }
    elseif (@($cp | Where-Object { $_ -and (& $hasKey $_ 'DeviceThreatProtectionEnabled') }).Count -eq 0 -and @($cp | Where-Object { $_ }).Count -gt 0) {
        $notEvaluated['DEV-015'] = '09-intune-compliance-policies.json was collected before TenantKeep read the device risk setting. Collect Intune again (Resume-PostureRun -Collector Intune).'
    }
    else {
        $platformOf = { param([string] $type) switch -Regex ($type) { '^windows' { 'Windows' } '^macOS' { 'macOS' } '^ios' { 'iOS' } '^(android|aosp)' { 'Android' } default { $null } } }
        $byPlatform = [ordered]@{}
        foreach ($p in @($cp | Where-Object { $_ -and [int](& $v $_ 'Assignments') -gt 0 })) {
            $pl = & $platformOf ([string](& $v $p 'Type')); if (-not $pl) { continue }
            if (-not $byPlatform.Contains($pl)) { $byPlatform[$pl] = $false }
            if ((& $v $p 'DeviceThreatProtectionEnabled') -eq $true -and [string](& $v $p 'DeviceThreatProtectionRequiredSecurityLevel') -notin @('', 'unavailable', 'notSet')) { $byPlatform[$pl] = $true }
        }
        $facts.compliancePlatforms = $byPlatform.Count
        $affected.compliancePlatformsWithoutDeviceRisk = @($byPlatform.Keys | Where-Object { -not $byPlatform[$_] } | ForEach-Object { [ordered]@{ name = $_; detail = 'no assigned compliance policy requires a Defender device risk level' } })
        $facts.compliancePlatformsWithoutDeviceRisk = @($affected.compliancePlatformsWithoutDeviceRisk).Count
    }

    $cleanup = & $load '09-intune-device-cleanup'
    if ($null -eq $cleanup) { & $missing @('DEV-013') '09-intune-device-cleanup'; if (-not $facts.Contains('deviceCleanupRuleEnabled')) { $facts.deviceCleanupRuleEnabled = $false } }
    else { $facts.deviceCleanupRuleEnabled = [bool](& $v $cleanup 'Enabled'); $facts.deviceCleanupDays = & $v $cleanup 'DeviceInactivityBeforeRetirementInDays' }

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('08-entra-devices.json', '09-intune-managed-devices.json', '09-intune-config-profiles-settings-catalog.json') }
}
