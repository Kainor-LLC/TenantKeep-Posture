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
    $t = @{ minCompliancePct = 0; maxHybridJoinedPct = 100; minAutopilotPct = 0; minBitLockerEscrowedPct = 100; minMacEncryptedPct = 100; minAppleCertDays = 60; minLinuxDevices = 0; maxAdOnlyWindowsPct = 5; maxPartnerHeartbeatDays = 7; minPartnerMacCompliantPct = 90; maxConnectorSilentDays = 3 }
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
    # A list of affected objects holds 500 at most; affectedCounts carries how many there are when the list is cut.
    $affectedCounts = @{}
    $missing = { param([string[]] $Ids, [string] $File) foreach ($id in $Ids) { $notEvaluated[$id] = "$File.json was not collected (Invoke-PostureCollection -Collector Intune; check errors.txt and the scopes)." } }

    # Entra devices (08): one pass, a row at a time, every count and affected list built on the way.
    # Recovery keys by device, read a row at a time into a lookup by device id (the list has a row per Windows device).
    $withKey = @{}
    $haveKeys = Read-PostureEvidenceRow -Folder $Evidence -Name '08-bitlocker-keys-by-device' -OnRow { param($k) $withKey[[string](& $v $k 'DeviceId')] = [int](& $v $k 'Keys') }
    $e = @{ enabled = 0; entraJoined = 0; hybridJoined = 0; registered = 0; windows = 0; escrowed = 0 }
    $staleList = [System.Collections.Generic.List[object]]::new(); $noKey = [System.Collections.Generic.List[object]]::new()
    # Hybrid-joined Windows devices in use that nothing in the cloud manages (DEV-020); the Intune pass below takes out
    # the ones Configuration Manager reports through tenant attach.
    $hybridActive = @{ count = 0 }; $unmanagedHybrid = [System.Collections.Generic.List[object]]::new()
    # Every Windows device name Entra knows, so the AD collector's workstations can be matched by name (DEV-020).
    $entraWindowsNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    # Macs signed in to Entra recently, and how many a partner MDM reports compliant (DEV-023).
    $macs = @{ inUse = 0; compliant = 0 }; $macsNotCompliant = [System.Collections.Generic.List[object]]::new()
    $haveEntra = Read-PostureEvidenceRow -Folder $Evidence -Name '08-entra-devices' -OnRow {
        param($_row)
        $row = $_row
        if ([string]$row.AccountEnabled -eq 'False') { return }
        $e.enabled++
        switch ([string]$row.JoinType) { 'EntraJoined' { $e.entraJoined++ } 'HybridJoined' { $e.hybridJoined++ } 'Registered' { $e.registered++ } }
        if (Test-PostureTrue $row.Stale) { $staleList.Add([ordered]@{ name = $row.DisplayName; detail = "$($row.JoinType), $($row.OperatingSystem), last sign-in $(if ($row.ApproximateLastSignInDateTime) { (ConvertTo-PostureUtcDateTime $row.ApproximateLastSignInDateTime).ToString('yyyy-MM-dd') } else { 'never' })" }) }
        if ([string]$row.OperatingSystem -eq 'Windows') { $null = $entraWindowsNames.Add([string]$row.DisplayName) }
        if ([string]$row.OperatingSystem -match '(?i)^mac' -and -not (Test-PostureTrue $row.Stale)) {
            $macs.inUse++
            if (Test-PostureTrue (& $v $row 'IsCompliant')) { $macs.compliant++ } elseif ($macsNotCompliant.Count -lt 500) { $macsNotCompliant.Add([ordered]@{ name = [string]$row.DisplayName; detail = 'Mac not reported compliant in Entra' }) }
        }
        if ([string]$row.OperatingSystem -eq 'Windows' -and [string]$row.JoinType -eq 'HybridJoined' -and -not (Test-PostureTrue $row.Stale)) {
            $hybridActive.count++
            if (-not (Test-PostureTrue (& $v $row 'IsManaged'))) { $unmanagedHybrid.Add([ordered]@{ id = [string](& $v $row 'DeviceId'); name = [string]$row.DisplayName }) }
        }
        if ([string]$row.OperatingSystem -eq 'Windows' -and [string]$row.JoinType -in @('EntraJoined', 'HybridJoined')) {
            $e.windows++
            if ($withKey.ContainsKey([string]$row.DeviceId)) { $e.escrowed++ } else { $noKey.Add([ordered]@{ name = $row.DisplayName; detail = 'no BitLocker recovery key in Entra' }) }
        }
    }
    if (-not $haveEntra) { & $missing @('DEV-002', 'DEV-003', 'DEV-005') '08-entra-devices' }
    else {
        $facts.entraDevices = $e.enabled
        $facts.entraJoined = $e.entraJoined; $facts.hybridJoined = $e.hybridJoined; $facts.registered = $e.registered
        # No devices at all is nothing to judge, not a rate of zero.
        $facts.hybridJoinedPct = $(if ($e.enabled -gt 0) { & $pct $e.hybridJoined $e.enabled } else { $null })
        if ($e.enabled -eq 0) { $notEvaluated['DEV-003'] = 'No enabled devices in Entra, so there is no join type mix to judge.' }
        $facts.staleEntraDevices = $staleList.Count
        $affected.staleEntraDevices = @($staleList)
        if (-not $haveKeys) { & $missing @('DEV-005') '08-bitlocker-keys-by-device' }
        else {
            $facts.windowsEntraDevices = $e.windows
            $facts.bitlockerEscrowedPct = $(if ($e.windows -gt 0) { & $pct $e.escrowed $e.windows } else { $null })
            if ($e.windows -eq 0) { $notEvaluated['DEV-005'] = 'No Windows devices joined to Entra, so there are no recovery keys to expect.' }
            $affected.windowsDevicesWithoutBitLockerKey = @($noKey)
        }
    }

    # Intune managed devices (09): one pass as well.
    $i = @{ total = 0; known = 0; compliant = 0; windows = 0; autopilot = 0; macs = 0; macsEncrypted = 0; linux = 0; partnerMacs = 0 }
    $plat = @{}
    $noncompliant = [System.Collections.Generic.List[object]]::new(); $macsOpen = [System.Collections.Generic.List[object]]::new(); $win10 = [System.Collections.Generic.List[object]]::new()
    $states = @('compliant', 'noncompliant', 'inGracePeriod', 'conflict', 'error')
    # Who manages each Windows device, from its management agent: Intune alone, co-managed with Configuration Manager,
    # Configuration Manager alone (seen through tenant attach), or only Defender's security settings management.
    $agents = @{ intune = 0; coManaged = 0; configMgr = 0; securityOnly = 0; other = 0 }
    $configMgrOnly = [System.Collections.Generic.List[object]]::new(); $inIntune = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $keyWorkloads = @('compliancePolicy', 'deviceConfiguration', 'windowsUpdateForBusiness', 'endpointProtection')
    $workloadLabel = @{ compliancePolicy = 'compliance policies'; deviceConfiguration = 'device configuration'; windowsUpdateForBusiness = 'Windows Update policies'; endpointProtection = 'endpoint protection' }
    $co = @{ known = $false; behind = 0 }; $coBehind = [System.Collections.Generic.List[object]]::new()
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
            $agent = [string](& $v $row 'ManagementAgent')
            $group = switch -Regex ($agent) { '^configurationManagerClient$' { 'configMgr' } '^configurationManagerClientMdm' { 'coManaged' } '^msSense$' { 'securityOnly' } '^(mdm|easMdm|intuneClient|microsoft365ManagedMdm)$' { 'intune' } default { 'other' } }
            $agents[$group]++
            $aadId = [string](& $v $row 'AzureAdDeviceId'); if ($aadId) { $null = $inIntune.Add($aadId) }
            if ($group -eq 'configMgr') { $configMgrOnly.Add([ordered]@{ name = $row.DeviceName; detail = "Configuration Manager only, user $($row.UserPrincipalName)" }) }
            # Rows collected before the workloads were read have no IntuneWorkloads column at all.
            $hasWorkloads = $(if ($row -is [System.Collections.IDictionary]) { $row.Contains('IntuneWorkloads') } else { $null -ne $row.PSObject.Properties['IntuneWorkloads'] })
            if ($group -eq 'coManaged' -and $hasWorkloads) {
                $co.known = $true
                $onIntune = @(([string]$row.IntuneWorkloads) -split ';' | Where-Object { $_ })
                $left = @($keyWorkloads | Where-Object { $_ -notin $onIntune })
                if ($left.Count) { $co.behind++; if ($coBehind.Count -lt 500) { $coBehind.Add([ordered]@{ name = $row.DeviceName; detail = "on Configuration Manager: $(@($left | ForEach-Object { $workloadLabel[$_] }) -join ', ')" }) } }
            }
            $i.windows++
            if (Test-PostureTrue $row.AutopilotEnrolled) { $i.autopilot++ }
            if ([string]$row.OSVersion -match '^10\.0\.1\d{4}') { $win10.Add([ordered]@{ name = $row.DeviceName; detail = "Windows build $($row.OSVersion)" }) }
        }
        if ($os -eq 'macOS') { $i.macs++; if (Test-PostureTrue $row.IsEncrypted) { $i.macsEncrypted++ } else { $macsOpen.Add([ordered]@{ name = $row.DeviceName; detail = 'FileVault not reported as enabled' }) } }
        if ($os -match '(?i)linux|ubuntu') { $i.linux++ }
        if ($os -eq 'macOS' -and [string](& $v $row 'ManagementAgent') -eq 'jamf') { $i.partnerMacs++ }
    }
    if (-not $haveManaged) { & $missing @('DEV-001', 'DEV-004', 'DEV-006', 'DEV-007', 'DEV-014', 'DEV-019', 'DEV-021') '09-intune-managed-devices' }
    else {
        $facts.managedDevices = $i.total
        $facts.intuneCompliancePct = $(if ($i.known -gt 0) { & $pct $i.compliant $i.known } else { $null })
        $byPlat = [ordered]@{}
        foreach ($os in @($plat.Keys | Sort-Object)) { $byPlat[$os] = $(if ($plat[$os].known -gt 0) { & $pct $plat[$os].compliant $plat[$os].known } else { $null }) }
        $facts.compliancePctByPlatform = $byPlat
        $affected.noncompliantDevices = @($noncompliant)
        if ($null -eq $facts.intuneCompliancePct) { $notEvaluated['DEV-001'] = 'No Intune managed devices with a compliance state.' }

        $facts.windowsManagedDevices = $i.windows
        # Counted a row at a time: the list has a row per registered device.
        $autopilot = @{ n = 0 }
        $haveAutopilot = Read-PostureEvidenceRow -Folder $Evidence -Name '09-autopilot-devices' -OnRow { param($a) $autopilot.n++ }
        if (-not $haveAutopilot) { & $missing @('DEV-004') '09-autopilot-devices' }
        else {
            $facts.autopilotRegistered = $autopilot.n
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

        # DEV-019 and DEV-021: Configuration Manager alone, and co-managed devices with workloads still on it.
        $facts.windowsIntuneOnly = $agents.intune; $facts.windowsCoManaged = $agents.coManaged; $facts.windowsConfigMgrOnly = $agents.configMgr; $facts.windowsSecuritySettingsOnly = $agents.securityOnly
        $affected.windowsConfigMgrOnly = @($configMgrOnly | Select-Object -First 500); $affectedCounts.windowsConfigMgrOnly = $configMgrOnly.Count
        if ($agents.coManaged -eq 0) { $facts.coManagedWorkloadsOnConfigMgr = 0 }
        elseif (-not $co.known) { $notEvaluated['DEV-021'] = '09-intune-managed-devices was collected before TenantKeep read the co-management workloads. Collect Intune again (Resume-PostureRun -Collector Intune).' }
        else { $facts.coManagedWorkloadsOnConfigMgr = $co.behind; $affected.coManagedWorkloadsOnConfigMgr = @($coBehind); $affectedCounts.coManagedWorkloadsOnConfigMgr = $co.behind }
        $comgmt = & $load '09-intune-comanagement'
        if ($comgmt) { $facts.coManagementWorkloads = @(@(& $v $comgmt 'Workloads') | Where-Object { $_ } | ForEach-Object { [ordered]@{ name = [string](& $v $_ 'Name'); onIntune = [int](& $v $_ 'OnIntune') } }); $facts.coManagedDevices = [int](& $v $comgmt 'CoManagedDevices') }
    }

    # DEV-020: hybrid-joined Windows devices in use with no cloud management at all (Group Policy, or Configuration
    # Manager without tenant attach). Needs both device lists.
    if (-not $haveEntra -or -not $haveManaged) { $notEvaluated['DEV-020'] = 'It needs both device lists: 08-entra-devices (the Entra collector) and 09-intune-managed-devices (the Intune collector).' }
    else {
        $adOnly = @($unmanagedHybrid | Where-Object { -not ($_.id -and $inIntune.Contains($_.id)) })
        # With the AD collector's files: workstations in use in AD (not servers, not domain controllers) that Entra
        # does not know at all, matched by name. Invisible from the cloud, so Group Policy is all they get.
        $notInEntra = [System.Collections.Generic.List[object]]::new()
        $haveAd = Read-PostureEvidenceRow -Folder $Evidence -Name 'ad-06-computers' -OnRow {
            param($_row)
            if ((Test-PostureTrue (& $v $_row 'IsDomainController')) -or (Test-PostureTrue (& $v $_row 'IsServer')) -or (Test-PostureTrue (& $v $_row 'Stale'))) { return }
            if ([string](& $v $_row 'OperatingSystem') -notmatch 'Windows') { return }
            if (-not $entraWindowsNames.Contains([string](& $v $_row 'Name'))) { $notInEntra.Add([ordered]@{ name = [string](& $v $_row 'Name'); detail = 'in Active Directory, signed in recently, not registered in Entra' }) }
        }
        $facts.hybridWindowsInUse = $hybridActive.count
        $facts.hybridUnmanagedWindows = $adOnly.Count
        $facts.adWorkstationsNotInEntra = $(if ($haveAd) { $notInEntra.Count } else { $null })
        $facts.adOnlyWindowsDevices = $adOnly.Count + $notInEntra.Count
        $facts.adOnlyWindowsPct = $(if (($hybridActive.count + $notInEntra.Count) -gt 0) { & $pct ($adOnly.Count + $notInEntra.Count) ($hybridActive.count + $notInEntra.Count) } else { 0 })
        $affected.adOnlyWindowsDevices = @(@($adOnly | ForEach-Object { [ordered]@{ name = $_.name; detail = 'hybrid joined, signed in recently, not managed by Intune' } }) + @($notInEntra) | Select-Object -First 500)
        $affectedCounts.adOnlyWindowsDevices = $adOnly.Count + $notInEntra.Count
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
        # The token list not collected is unknown, not "no tokens".
        $facts.vppTokens = $(if ($null -eq $vpp) { $null } else { @($vpp | Where-Object { $_ }).Count })
        $facts.vppTokensExpiringSoon = $(if ($null -eq $vpp) { $null } else { $soon.Count })
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
    # DEV-027: every platform that has managed devices has a compliance policy that is assigned. Without one the
    # devices of that platform are judged on nothing (and DEV-017 decides whether that reads as compliant).
    if ($null -eq $cp) { & $missing @('DEV-027') '09-intune-compliance-policies' }
    elseif (-not $haveManaged) { $notEvaluated['DEV-027'] = '09-intune-managed-devices.json was not collected, so which platforms are in the fleet is not known.' }
    else {
        $family = { param([string] $name) switch -Regex ($name) { '^(?i)windows' { 'Windows'; break } '^(?i)mac' { 'macOS'; break } '^(?i)(ios|ipados)' { 'iOS'; break } '^(?i)(android|aosp)' { 'Android'; break } default { $null } } }
        $withPolicy = @($cp | Where-Object { $_ -and [int](& $v $_ 'Assignments') -gt 0 } | ForEach-Object { & $family ([string](& $v $_ 'Type')) } | Where-Object { $_ } | Sort-Object -Unique)
        $fleet = @($plat.get_Keys() | ForEach-Object { & $family ([string]$_) } | Where-Object { $_ } | Sort-Object -Unique)
        $bare = @($fleet | Where-Object { $_ -notin $withPolicy })
        $facts.fleetPlatforms = $fleet.Count
        $facts.platformsWithoutCompliancePolicy = $bare.Count
        $affected.platformsWithoutCompliancePolicy = @($bare | ForEach-Object { [ordered]@{ name = $_; detail = 'devices of this platform are managed, and no assigned compliance policy covers them' } })
        if ($fleet.Count -eq 0) { $notEvaluated['DEV-027'] = 'No managed Windows, macOS, iOS or Android device.' }
    }
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
    # Not collected: unknown. DEV-002 passes without it only when there are no stale devices to clean up.
    if ($null -eq $cleanup) { & $missing @('DEV-013') '09-intune-device-cleanup'; $facts.deviceCleanupRuleEnabled = $null }
    else { $facts.deviceCleanupRuleEnabled = [bool](& $v $cleanup 'Enabled'); $facts.deviceCleanupDays = & $v $cleanup 'DeviceInactivityBeforeRetirementInDays' }

    # DEV-022 and DEV-023: Macs on a partner MDM (Jamf, Kandji, Mosyle). One is expected when the profile names it,
    # when Intune shows a partner onboarded for Macs, or when Intune lists Macs that Jamf reports.
    $tp = $(if ($OrgProfile.Contains('thirdParty') -and $OrgProfile['thirdParty']) { $OrgProfile['thirdParty'] } else { @{} })
    $vendor = $(if ($tp.Contains('macMdm')) { [string]$tp['macMdm'] } else { '' })
    $cpRows = & $load '09-intune-compliance-partners'; $dpRows = & $load '09-intune-device-management-partners'
    if ($null -eq $cpRows -and $null -eq $dpRows) {
        $why = $(if ($haveManaged) { '09-intune-compliance-partners.json was not collected: the Intune collector reads the partner connections since 2026-11-20 (Resume-PostureRun -Collector Intune).' } else { '09-intune-compliance-partners.json was not collected (the Intune collector).' })
        foreach ($id in 'DEV-022', 'DEV-023') { $notEvaluated[$id] = $why }
    }
    else {
        $hb = { param($x) $d = ConvertTo-PostureUtcDateTime $x; if ($d) { [Math]::Floor(($AsOf - $d).TotalDays) } else { $null } }
        $partners = @(
            @(@($cpRows) | Where-Object { $_ -and (Test-PostureTrue (& $v $_ 'MacOsOnboarded')) } | ForEach-Object { [ordered]@{ name = [string](& $v $_ 'DisplayName'); kind = 'compliance partner'; state = [string](& $v $_ 'PartnerState'); days = (& $hb (& $v $_ 'LastHeartbeatDateTime')) } })
            @(@($dpRows) | Where-Object { $_ -and (Test-PostureTrue (& $v $_ 'IsConfigured')) } | ForEach-Object { [ordered]@{ name = [string](& $v $_ 'DisplayName'); kind = 'device management partner'; state = [string](& $v $_ 'PartnerState'); days = (& $hb (& $v $_ 'LastHeartbeatDateTime')) } })
        )
        $isOk = { param($x) $x.state -eq 'enabled' -and $null -ne $x.days -and $x.days -le [int]$t.maxPartnerHeartbeatDays }
        $facts.macPartnerExpected = ($vendor -and $vendor -ne 'none') -or $partners.Count -gt 0 -or $i.partnerMacs -gt 0
        $facts.macPartnerReporting = @($partners | Where-Object { & $isOk $_ }).Count -gt 0
        $facts.macPartners = @($partners | ForEach-Object { $_.name })
        $facts.partnerReportedMacs = $i.partnerMacs
        $problems = @($partners | Where-Object { -not (& $isOk $_) })
        $facts.macPartnerProblems = $problems.Count
        $affected.macPartnerProblems = @($problems | ForEach-Object { [ordered]@{ name = $_.name; detail = "$($_.kind), state $(if ($_.state) { $_.state } else { 'unknown' }), $(if ($null -ne $_.days) { "last heartbeat $($_.days) days ago" } else { 'no heartbeat recorded' })" } })
        if ($facts.macPartnerExpected -and $partners.Count -eq 0) { $facts.macPartnerProblems = 1; $affected.macPartnerProblems = @([ordered]@{ name = $(if ($vendor -and $vendor -ne 'none') { $vendor } else { 'Mac MDM' }); detail = 'no partner connected in Intune for macOS' }) }
        if ($haveEntra) {
            if ($facts.macPartnerExpected -and $macs.inUse -eq 0) { $notEvaluated['DEV-023'] = 'No Macs have signed in to Entra recently, so there is no compliance to read.' }
            else { $facts.macEntraCompliantPct = $(if ($macs.inUse -gt 0) { & $pct $macs.compliant $macs.inUse } else { 100 }); $facts.macsInEntra = $macs.inUse; $facts.macsCompliantInEntra = $macs.compliant; $affected.macsNotCompliantInEntra = @($macsNotCompliant); $affectedCounts.macsNotCompliantInEntra = $macs.inUse - $macs.compliant }
        }
        else { $notEvaluated['DEV-023'] = '08-entra-devices.json was not collected (the Entra collector).' }
    }

    # DEV-025: multi-admin approval. With it, a wipe, a script or a policy change one admin starts waits for a
    # second admin; without it one stolen admin session reaches every device at once.
    $approval = & $load '09-intune-approval-policies'
    if ($null -eq $approval) { & $missing @('DEV-025') '09-intune-approval-policies' }
    else {
        $approvalList = @($approval | Where-Object { $_ })
        $facts.multiAdminApprovalPolicies = $approvalList.Count
        $facts.multiAdminApprovalCovers = (@($approvalList | ForEach-Object { [string](Get-PostureValue $_ 'PolicyType') } | Where-Object { $_ } | Sort-Object -Unique) -join ', ')
    }
    # DEV-026: Intune's own role assignments. One that gives a role that can change things over every device and
    # every user is listed; a read-only role is not. No assignment at all (the Entra roles are used) passes.
    $intuneRoles = & $load '09-intune-role-assignments'
    if ($null -eq $intuneRoles) { & $missing @('DEV-026') '09-intune-role-assignments' }
    else {
        $roleList = @($intuneRoles | Where-Object { $_ })
        $orgWide = @($roleList | Where-Object { [string](Get-PostureValue $_ 'ScopeType') -in 'allDevices', 'allLicensedUsers', 'allDevicesAndLicensedUsers' -and [string](Get-PostureValue $_ 'RoleName') -notmatch '(?i)read.?only' })
        $facts.intuneRoleAssignments = $roleList.Count
        $facts.intuneRolesOrgWide = $orgWide.Count
        $tags = & $load '09-intune-scope-tags'
        $facts.intuneScopeTags = $(if ($null -ne $tags) { @($tags | Where-Object { $_ -and (Get-PostureValue $_ 'IsBuiltIn') -ne $true }).Count } else { $null })
        $scopeWords = @{ allDevices = 'every device'; allLicensedUsers = 'every user'; allDevicesAndLicensedUsers = 'every device and every user' }
        $affected.intuneRolesOrgWide = @($orgWide | ForEach-Object { [ordered]@{ name = "$([string](Get-PostureValue $_ 'DisplayName')) ($([string](Get-PostureValue $_ 'RoleName')))"; detail = "over $($scopeWords[[string](Get-PostureValue $_ 'ScopeType')]); $([int](Get-PostureValue $_ 'MemberGroups')) member group(s)" } })
    }

    # DEV-024: the on-premises certificate connectors (SCEP through NDES, PKCS). One Intune calls inactive, or one
    # that has not been heard from in days, issues no certificates. A tenant with none has nothing to lose here.
    $connectors = & $load '09-certificate-connectors'
    if ($null -eq $connectors) { & $missing @('DEV-024') '09-certificate-connectors' }
    else {
        $connectorList = @($connectors | Where-Object { $_ })
        # How long each had been silent when the list was read (the collector's own count), so a report built
        # later says the same thing.
        $silent = @($connectorList | Where-Object {
                $days = Get-PostureValue $_ 'DaysSinceLastConnection'
                [string](Get-PostureValue $_ 'State') -eq 'inactive' -or $null -eq $days -or "$days" -eq '' -or [int]$days -gt [int]$t.maxConnectorSilentDays
            })
        $facts.certificateConnectors = $connectorList.Count
        $facts.certificateConnectorsSilent = $silent.Count
        $affected.certificateConnectorsSilent = @($silent | ForEach-Object {
                $heard = ConvertTo-PostureUtcDateTime (Get-PostureValue $_ 'LastConnectionDateTime')
                [ordered]@{ name = "$([string](Get-PostureValue $_ 'DisplayName'))$(if (Get-PostureValue $_ 'MachineName') { " on $([string](Get-PostureValue $_ 'MachineName'))" })"; detail = $(if ($heard) { "last heard from $($heard.ToString('yyyy-MM-dd'))" } else { 'never heard from' }) + $(if ([string](Get-PostureValue $_ 'State') -eq 'inactive') { ', inactive' } else { '' }) }
            })
    }

    return @{ available = $true; facts = $facts; affected = $affected; affectedCounts = $affectedCounts; notEvaluated = $notEvaluated; evidence = @('08-entra-devices.json', '09-intune-managed-devices.json', '09-intune-config-profiles-settings-catalog.json') }
}
