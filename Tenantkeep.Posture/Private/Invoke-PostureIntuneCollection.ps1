# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureIntuneCollection {
    <#
    .SYNOPSIS
        The A.1 section 9 collector plus the spec 4.4 additions: Intune managed devices and summaries, Autopilot,
        compliance policies, configuration profiles, settings catalog, apps, Apple certificates, enrollment
        restrictions, endpoint security policies by template family, the MDE connector, the cleanup rule, and
        BitLocker recovery key presence.
    .DESCRIPTION
        One step per file; a denied endpoint is a line in errors.txt. Scopes: DeviceManagementManagedDevices.Read.All,
        DeviceManagementConfiguration.Read.All, DeviceManagementServiceConfig.Read.All, DeviceManagementApps.Read.All,
        BitLockerKey.ReadBasic.All. Several endpoints are beta; each call pins its version. Items marked (verify) in
        the code are endpoints confirmed only against documentation until the first real run.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [int] $StaleDays = 90,
        [datetime] $AsOf = [datetime]::UtcNow
    )

    $ErrorActionPreference = 'Stop'
    $files = [System.Collections.Generic.List[string]]::new()
    $save = { param($Data, [string] $Name, [bool] $Csv = $false) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data -AsArray -Csv:$Csv)) }
    $saveOne = { param($Data, [string] $Name) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data)) }
    $get = { param([string] $Uri, [string] $Api = 'v1.0') @(Invoke-PostureGraphRequest -Uri $Uri -ApiVersion $Api) }
    $one = { param([string] $Uri, [string] $Api = 'v1.0') Invoke-PostureGraphRequest -Uri $Uri -ApiVersion $Api -Single }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $group = { param($rows, [string[]] $keys) @(@($rows | ForEach-Object { [pscustomobject]$_ }) | Group-Object -Property $keys | ForEach-Object { [ordered]@{ Name = $_.Name; Count = $_.Count } } | Sort-Object { -$_.Count }) }
    $odataType = { param($o) ([string]$o['@odata.type']) -replace '^#microsoft\.graph\.', '' }

    # ---------- 9. Intune managed devices (beta for joinType and autopilotEnrolled) ----------
    # The step returns the flattened list so the summaries and the return value share it.
    $managed = @(Invoke-PostureStep -Label 'Intune managed devices' -Folder $Folder -Script {
            $rows = & $get 'deviceManagement/managedDevices?$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,skuFamily,complianceState,managementAgent,joinType,deviceEnrollmentType,managedDeviceOwnerType,autopilotEnrolled,isEncrypted,isSupervised,lastSyncDateTime,enrolledDateTime,manufacturer,model,serialNumber,azureADDeviceId&$top=999' 'beta'
            $flat = @($rows | ForEach-Object {
                    [ordered]@{
                        Id = $_.id; DeviceName = (& $v $_ 'deviceName'); UserPrincipalName = (& $v $_ 'userPrincipalName'); OperatingSystem = (& $v $_ 'operatingSystem'); OSVersion = (& $v $_ 'osVersion'); SkuFamily = (& $v $_ 'skuFamily')
                        ComplianceState = (& $v $_ 'complianceState'); ManagementAgent = (& $v $_ 'managementAgent'); JoinType = (& $v $_ 'joinType'); DeviceEnrollmentType = (& $v $_ 'deviceEnrollmentType'); ManagedDeviceOwnerType = (& $v $_ 'managedDeviceOwnerType')
                        AutopilotEnrolled = [bool](& $v $_ 'autopilotEnrolled'); IsEncrypted = [bool](& $v $_ 'isEncrypted'); IsSupervised = [bool](& $v $_ 'isSupervised'); LastSyncDateTime = (& $v $_ 'lastSyncDateTime'); EnrolledDateTime = (& $v $_ 'enrolledDateTime')
                        Manufacturer = (& $v $_ 'manufacturer'); Model = (& $v $_ 'model'); SerialNumber = (& $v $_ 'serialNumber'); AzureAdDeviceId = (& $v $_ 'azureADDeviceId')
                    }
                })
            & $save $flat '09-intune-managed-devices' $true
            & $save (& $group $flat @('OperatingSystem', 'ManagementAgent', 'JoinType')) '09-intune-summary-os-agent-join' $true
            & $save (& $group $flat @('OperatingSystem', 'ComplianceState')) '09-intune-summary-compliance' $true
            & $save (& $group @($flat | Where-Object { $_.OperatingSystem -eq 'Windows' }) @('OSVersion')) '09-intune-summary-windows-builds' $true
            $flat
        })

    Invoke-PostureStep -Label 'Autopilot devices' -Folder $Folder -Script {
        $rows = & $get 'deviceManagement/windowsAutopilotDeviceIdentities?$top=999'
        & $save @($rows | ForEach-Object { [ordered]@{ SerialNumber = (& $v $_ 'serialNumber'); Manufacturer = (& $v $_ 'manufacturer'); Model = (& $v $_ 'model'); GroupTag = (& $v $_ 'groupTag'); EnrollmentState = (& $v $_ 'enrollmentState'); LastContactedDateTime = (& $v $_ 'lastContactedDateTime'); DeploymentProfileAssignmentStatus = (& $v $_ 'deploymentProfileAssignmentStatus'); ManagedDeviceId = (& $v $_ 'managedDeviceId'); AzureActiveDirectoryDeviceId = (& $v $_ 'azureActiveDirectoryDeviceId') } }) '09-autopilot-devices' $true
    } | Out-Null

    Invoke-PostureStep -Label 'Intune compliance policies' -Folder $Folder -Script {
        $rows = & $get 'deviceManagement/deviceCompliancePolicies?$expand=assignments'
        & $save @($rows | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); Type = (& $odataType $_); CreatedDateTime = (& $v $_ 'createdDateTime'); LastModifiedDateTime = (& $v $_ 'lastModifiedDateTime'); Version = (& $v $_ 'version'); Assignments = @(& $v $_ 'assignments').Count } }) '09-intune-compliance-policies' $true
    } | Out-Null

    Invoke-PostureStep -Label 'Intune config profiles (templates)' -Folder $Folder -Script {
        $rows = & $get 'deviceManagement/deviceConfigurations?$expand=assignments'
        & $save @($rows | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); Type = (& $odataType $_); CreatedDateTime = (& $v $_ 'createdDateTime'); LastModifiedDateTime = (& $v $_ 'lastModifiedDateTime'); Assignments = @(& $v $_ 'assignments').Count } }) '09-intune-config-profiles-templates' $true
    } | Out-Null

    Invoke-PostureStep -Label 'Intune settings catalog and endpoint security policies' -Folder $Folder -Script {
        # Settings catalog policies carry templateReference.templateFamily: endpointSecurityAntivirus, endpointSecurityDiskEncryption,
        # endpointSecurityFirewall, endpointSecurityEndpointDetectionAndResponse, endpointSecurityAttackSurfaceReductionRules, endpointSecurityAccountProtection (LAPS), none. (beta)
        $rows = & $get 'deviceManagement/configurationPolicies?$expand=assignments&$top=999' 'beta'
        & $save @($rows | ForEach-Object { [ordered]@{ Id = $_.id; Name = (& $v $_ 'name'); Platforms = (& $v $_ 'platforms'); Technologies = (& $v $_ 'technologies'); TemplateFamily = (& $v $_ 'templateReference.templateFamily'); TemplateDisplayName = (& $v $_ 'templateReference.templateDisplayName'); SettingCount = (& $v $_ 'settingCount'); CreatedDateTime = (& $v $_ 'createdDateTime'); LastModifiedDateTime = (& $v $_ 'lastModifiedDateTime'); Assignments = @(& $v $_ 'assignments').Count } }) '09-intune-config-profiles-settings-catalog' $true
    } | Out-Null

    Invoke-PostureStep -Label 'Intune apps' -Folder $Folder -Script {
        $rows = & $get 'deviceAppManagement/mobileApps?$top=999'
        & $save @($rows | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); Publisher = (& $v $_ 'publisher'); Type = (& $odataType $_); IsFeatured = (& $v $_ 'isFeatured'); CreatedDateTime = (& $v $_ 'createdDateTime'); LastModifiedDateTime = (& $v $_ 'lastModifiedDateTime') } }) '09-intune-apps' $true
    } | Out-Null

    Invoke-PostureStep -Label 'Apple push certificate' -Folder $Folder -Script {
        # NotFound means no APNs certificate has been uploaded: a fact, not a failure.
        $c = $null
        try { $c = & $one 'deviceManagement/applePushNotificationCertificate' }
        catch { if ($_.Exception.Message -match 'NotFound|404') { $c = @{} } else { throw } }
        & $saveOne ([ordered]@{ AppleIdentifier = (& $v $c 'appleIdentifier'); ExpirationDateTime = (& $v $c 'expirationDateTime'); LastModifiedDateTime = (& $v $c 'lastModifiedDateTime'); TopicIdentifier = (& $v $c 'topicIdentifier'); Present = [bool](& $v $c 'expirationDateTime') }) '09-apple-push-cert'
    } | Out-Null
    Invoke-PostureStep -Label 'Apple VPP tokens' -Folder $Folder -Script {
        $rows = & $get 'deviceAppManagement/vppTokens'
        & $save @($rows | ForEach-Object { [ordered]@{ OrganizationName = (& $v $_ 'organizationName'); AppleId = (& $v $_ 'appleId'); VppTokenAccountType = (& $v $_ 'vppTokenAccountType'); State = (& $v $_ 'state'); ExpirationDateTime = (& $v $_ 'expirationDateTime'); LastSyncDateTime = (& $v $_ 'lastSyncDateTime'); LastSyncStatus = (& $v $_ 'lastSyncStatus'); AutomaticallyUpdateApps = (& $v $_ 'automaticallyUpdateApps') } }) '09-apple-vpp-tokens' $true
    } | Out-Null

    # ---------- 4.4 additions ----------
    Invoke-PostureStep -Label 'Enrollment restrictions' -Folder $Folder -Script {
        # deviceEnrollmentPlatformRestrictionsConfiguration carries per-platform personalDeviceEnrollmentBlocked. (verify) beta shape for the newer per-platform configurations
        $rows = & $get 'deviceManagement/deviceEnrollmentConfigurations?$expand=assignments' 'beta'
        $flat = @($rows | ForEach-Object {
                $type = & $odataType $_
                $entry = [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); Type = $type; Priority = (& $v $_ 'priority'); Assignments = @(& $v $_ 'assignments').Count }
                foreach ($plat in 'windows', 'macOS', 'ios', 'android', 'androidForWork') {
                    $r = & $v $_ "${plat}Restriction"
                    if ($null -eq $r -and $type -eq 'deviceEnrollmentPlatformRestrictionConfiguration') { $r = & $v $_ 'platformRestriction' }
                    if ($null -ne $r) { $entry["$plat`PlatformBlocked"] = [bool](& $v $r 'platformBlocked'); $entry["$plat`PersonalBlocked"] = [bool](& $v $r 'personalDeviceEnrollmentBlocked') }
                }
                if ($type -eq 'deviceEnrollmentPlatformRestrictionConfiguration') { $entry.PlatformType = (& $v $_ 'platformType') }
                $entry
            })
        & $save $flat '09-intune-enrollment-restrictions' $true
    } | Out-Null

    Invoke-PostureStep -Label 'MDE connector' -Folder $Folder -Script {
        # The Defender for Endpoint connector state lives on the mobileThreatDefenseConnectors collection as the Microsoft Defender partner. (verify) partner identification
        $rows = & $get 'deviceManagement/mobileThreatDefenseConnectors' 'beta'
        & $save @($rows | ForEach-Object { [ordered]@{ Id = $_.id; PartnerState = (& $v $_ 'partnerState'); LastHeartbeatDateTime = (& $v $_ 'lastHeartbeatDateTime'); WindowsDeviceBlockedOnMissingPartnerData = (& $v $_ 'windowsDeviceBlockedOnMissingPartnerData'); WindowsEnabled = (& $v $_ 'windowsEnabled'); MacEnabled = (& $v $_ 'macEnabled'); LinuxEnabled = (& $v $_ 'linuxEnabled'); IosEnabled = (& $v $_ 'iosEnabled'); AndroidEnabled = (& $v $_ 'androidEnabled'); MicrosoftDefenderForEndpointAttachEnabled = (& $v $_ 'microsoftDefenderForEndpointAttachEnabled') } }) '09-intune-mde-connector' $true
    } | Out-Null

    Invoke-PostureStep -Label 'Device cleanup rules' -Folder $Folder -Script {
        # managedDeviceCleanupRules (beta) is the per-platform list; managedDeviceCleanupSettings is forbidden for delegated reads (confirmed 2026-10-14).
        $rules = & $get 'deviceManagement/managedDeviceCleanupRules' 'beta'
        $flat = @($rules | ForEach-Object { [ordered]@{ Id = (& $v $_ 'id'); DisplayName = (& $v $_ 'displayName'); PlatformType = (& $v $_ 'deviceCleanupRulePlatformType'); DeviceInactivityBeforeRetirementInDays = (& $v $_ 'deviceInactivityBeforeRetirementInDays') } })
        $days = @($flat | ForEach-Object { $_.DeviceInactivityBeforeRetirementInDays } | Where-Object { $null -ne $_ } | Sort-Object)
        & $saveOne ([ordered]@{ Rules = $flat; Enabled = ($flat.Count -gt 0); DeviceInactivityBeforeRetirementInDays = $(if ($days.Count -gt 0) { $days[0] } else { $null }) }) '09-intune-device-cleanup'
    } | Out-Null

    Invoke-PostureStep -Label 'BitLocker recovery keys' -Folder $Folder -Script {
        # Key presence per device only; the key material is never read. (verify) scope: BitLockerKey.ReadBasic.All
        $keys = & $get 'informationProtection/bitlocker/recoveryKeys?$select=id,deviceId,createdDateTime,volumeType'
        $byDevice = @{}
        foreach ($k in $keys) { $d = [string](& $v $k 'deviceId'); if ($d) { if (-not $byDevice.ContainsKey($d)) { $byDevice[$d] = 0 }; $byDevice[$d]++ } }
        & $save @($byDevice.Keys | Sort-Object | ForEach-Object { [ordered]@{ DeviceId = $_; Keys = $byDevice[$_] } }) '08-bitlocker-keys-by-device' $true
        & $saveOne ([ordered]@{ Keys = $keys.Count; DevicesWithKeys = $byDevice.Count }) '08-bitlocker-keys-summary'
    } | Out-Null

    $errorsPath = Join-Path $Folder 'errors.txt'
    return @{ files = $files.ToArray(); errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath }); managedDevices = $managed.Count }
}
