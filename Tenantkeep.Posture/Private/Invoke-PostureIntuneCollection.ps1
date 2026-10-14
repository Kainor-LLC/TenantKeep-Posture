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

    $compliance = @(Invoke-PostureStep -Label 'Intune compliance policies' -Folder $Folder -Script {
            $rows = & $get 'deviceManagement/deviceCompliancePolicies?$expand=assignments'
            & $save @($rows | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); Type = (& $odataType $_); CreatedDateTime = (& $v $_ 'createdDateTime'); LastModifiedDateTime = (& $v $_ 'lastModifiedDateTime'); Version = (& $v $_ 'version'); Assignments = @(& $v $_ 'assignments').Count } }) '09-intune-compliance-policies' $true
            $rows
        })

    $templates = @(Invoke-PostureStep -Label 'Intune config profiles (templates)' -Folder $Folder -Script {
            $rows = & $get 'deviceManagement/deviceConfigurations?$expand=assignments'
            & $save @($rows | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); Type = (& $odataType $_); CreatedDateTime = (& $v $_ 'createdDateTime'); LastModifiedDateTime = (& $v $_ 'lastModifiedDateTime'); Assignments = @(& $v $_ 'assignments').Count } }) '09-intune-config-profiles-templates' $true
            $rows
        })

    $catalog = @(Invoke-PostureStep -Label 'Intune settings catalog and endpoint security policies' -Folder $Folder -Script {
            # Settings catalog policies carry templateReference.templateFamily: endpointSecurityAntivirus, endpointSecurityDiskEncryption,
            # endpointSecurityFirewall, endpointSecurityEndpointDetectionAndResponse, endpointSecurityAttackSurfaceReductionRules, endpointSecurityAccountProtection (LAPS), none. (beta)
            $rows = & $get 'deviceManagement/configurationPolicies?$expand=assignments&$top=999' 'beta'
            & $save @($rows | ForEach-Object { [ordered]@{ Id = $_.id; Name = (& $v $_ 'name'); Platforms = (& $v $_ 'platforms'); Technologies = (& $v $_ 'technologies'); TemplateFamily = (& $v $_ 'templateReference.templateFamily'); TemplateDisplayName = (& $v $_ 'templateReference.templateDisplayName'); SettingCount = (& $v $_ 'settingCount'); CreatedDateTime = (& $v $_ 'createdDateTime'); LastModifiedDateTime = (& $v $_ 'lastModifiedDateTime'); Assignments = @(& $v $_ 'assignments').Count } }) '09-intune-config-profiles-settings-catalog' $true
            $rows
        })

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
    $enrollment = @(Invoke-PostureStep -Label 'Enrollment restrictions' -Folder $Folder -Script {
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
            $rows
        })

    # ---------- 4.11 policy state ----------
    # Settings catalog values, one row per setting instance, recursed through choice children and group collections.
    # Definition ids are self-describing (device_vendor_msft_bitlocker_requiredeviceencryption, value ..._1), so the
    # endpoint facts match on them without the settings definition catalog.
    $flattenSetting = {
        param($Instance, [string] $Prefix, $Policy, $Out)
        $defId = [string](& $v $Instance 'settingDefinitionId')
        $add = { param($Value) $Out.Add([ordered]@{ PolicyId = $Policy.Id; PolicyName = $Policy.Name; TemplateFamily = $Policy.TemplateFamily; TemplateDisplayName = $Policy.TemplateDisplayName; Platforms = $Policy.Platforms; SettingDefinitionId = $defId; Value = $Value }) }
        $choice = & $v $Instance 'choiceSettingValue'
        if ($null -ne $choice) {
            & $add ([string](& $v $choice 'value'))
            foreach ($child in @(& $v $choice 'children')) { & $flattenSetting $child $defId $Policy $Out }
            return
        }
        $simple = & $v $Instance 'simpleSettingValue'
        if ($null -ne $simple) { & $add (& $v $simple 'value'); return }
        $simpleList = & $v $Instance 'simpleSettingCollectionValue'
        if ($null -ne $simpleList) { & $add (@(@($simpleList) | ForEach-Object { [string](& $v $_ 'value') }) -join '|'); return }
        $choiceList = & $v $Instance 'choiceSettingCollectionValue'
        if ($null -ne $choiceList) {
            & $add (@(@($choiceList) | ForEach-Object { [string](& $v $_ 'value') }) -join '|')
            foreach ($c in @($choiceList)) { foreach ($child in @(& $v $c 'children')) { & $flattenSetting $child $defId $Policy $Out } }
            return
        }
        $group = & $v $Instance 'groupSettingValue'
        if ($null -ne $group) { foreach ($child in @(& $v $group 'children')) { & $flattenSetting $child $defId $Policy $Out }; return }
        $groups = & $v $Instance 'groupSettingCollectionValue'
        if ($null -ne $groups) { foreach ($g in @($groups)) { foreach ($child in @(& $v $g 'children')) { & $flattenSetting $child $defId $Policy $Out } }; return }
        & $add $null
    }
    Invoke-PostureStep -Label 'Settings catalog policy settings' -Folder $Folder -Script {
        $out = [System.Collections.Generic.List[object]]::new()
        # $catalog holds the raw Graph rows; the projection the facts read is what the step wrote.
        foreach ($raw in @($catalog | Where-Object { $_ -and @(& $v $_ 'assignments').Count -gt 0 })) {
            $p = [ordered]@{ Id = $raw.id; Name = (& $v $raw 'name'); TemplateFamily = (& $v $raw 'templateReference.templateFamily'); TemplateDisplayName = (& $v $raw 'templateReference.templateDisplayName'); Platforms = (& $v $raw 'platforms') }
            $settings = & $get "deviceManagement/configurationPolicies/$($p.Id)/settings" 'beta'
            foreach ($s in $settings) { & $flattenSetting (& $v $s 'settingInstance') '' $p $out }
        }
        & $save $out.ToArray() '09-intune-policy-settings' $true
    } | Out-Null

    # Template profiles and compliance policies: every scalar property of an assigned policy, so the facts can read
    # deadlines, jailbreak detection, SmartScreen and the other classic settings without a per-type projection.
    $meta = @('id', 'displayName', 'description', 'createdDateTime', 'lastModifiedDateTime', 'version', 'assignments', '@odata.type', 'roleScopeTagIds', 'supportsScopeTags', 'deviceManagementApplicabilityRuleOsEdition', 'deviceManagementApplicabilityRuleOsVersion', 'deviceManagementApplicabilityRuleDeviceMode', 'scheduledActionsForRule')
    $scalarRows = {
        param($Policies)
        @(foreach ($p in @($Policies | Where-Object { $_ -and @(& $v $_ 'assignments').Count -gt 0 })) {
                foreach ($k in @($p.Keys | Where-Object { $_ -notin $meta } | Sort-Object)) {
                    $val = $p[$k]
                    if ($null -eq $val -or $val -is [string] -or $val -is [bool] -or $val -is [int] -or $val -is [long] -or $val -is [double]) { [ordered]@{ PolicyId = $p.id; PolicyName = (& $v $p 'displayName'); Type = (& $odataType $p); Setting = $k; Value = $val } }
                    elseif ($val -is [System.Collections.IList] -and @($val | Where-Object { $_ -is [System.Collections.IDictionary] }).Count -eq 0) { [ordered]@{ PolicyId = $p.id; PolicyName = (& $v $p 'displayName'); Type = (& $odataType $p); Setting = $k; Value = (@($val) -join '|') } }
                }
            })
    }
    Invoke-PostureStep -Label 'Config profile settings' -Folder $Folder -Script { & $save (& $scalarRows $templates) '09-intune-config-profile-settings' $true } | Out-Null
    Invoke-PostureStep -Label 'Compliance policy settings' -Folder $Folder -Script { & $save (& $scalarRows $compliance) '09-intune-compliance-policy-settings' $true } | Out-Null

    Invoke-PostureStep -Label 'Windows Hello for Business' -Folder $Folder -Script {
        $whfb = @($enrollment | Where-Object { $_ -and (& $odataType $_) -eq 'windowsHelloForBusinessConfiguration' } | Select-Object -First 1)
        & $saveOne $(if ($whfb.Count -gt 0) { [ordered]@{ Present = $true; State = (& $v $whfb[0] 'state'); PinMinimumLength = (& $v $whfb[0] 'pinMinimumLength'); SecurityDeviceRequired = (& $v $whfb[0] 'securityDeviceRequired'); UnlockWithBiometricsEnabled = (& $v $whfb[0] 'unlockWithBiometricsEnabled'); EnhancedBiometricsState = (& $v $whfb[0] 'enhancedBiometricsState'); SecurityKeyForSignIn = (& $v $whfb[0] 'securityKeyForSignIn') } } else { [ordered]@{ Present = $false } }) '09-intune-windows-hello'
    } | Out-Null

    Invoke-PostureStep -Label 'App protection policies' -Folder $Folder -Script {
        $rows = & $get 'deviceAppManagement/managedAppPolicies'
        & $save @($rows | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); Type = (& $odataType $_); IsAssigned = (& $v $_ 'isAssigned'); DeployedAppCount = (& $v $_ 'deployedAppCount'); LastModifiedDateTime = (& $v $_ 'lastModifiedDateTime') } }) '09-intune-app-protection-policies' $true
    } | Out-Null

    Invoke-PostureStep -Label 'Feature update profiles' -Folder $Folder -Script {
        $rows = & $get 'deviceManagement/windowsFeatureUpdateProfiles?$expand=assignments' 'beta'
        & $save @($rows | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); FeatureUpdateVersion = (& $v $_ 'featureUpdateVersion'); EndOfSupportDate = (& $v $_ 'endOfSupportDate'); Assignments = @(& $v $_ 'assignments').Count } }) '09-intune-feature-update-profiles' $true
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
