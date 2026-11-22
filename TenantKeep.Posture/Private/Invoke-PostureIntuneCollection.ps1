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
    # A list written a row at a time as its pages arrive, so none of it is held: -Row turns one Graph item ($_) into
    # the row to write. Returns how many rows were written.
    $streamed = {
        param([string] $Uri, [string] $Name, [scriptblock] $Row, [string] $Api = 'v1.0')
        $written = @{ n = 0 }
        $stream = Open-PostureEvidenceStream -Folder $Folder -Name $Name -Csv -Confirm:$false
        try {
            $null = Invoke-PostureGraphRequest -Uri $Uri -ApiVersion $Api -Label $Name -OnPage {
                param($page)
                foreach ($item in $page) { $r = ForEach-Object -InputObject $item -Process $Row; if ($r) { Add-PostureEvidenceRow -Stream $stream -Row $r; $written.n++ } }
            }
            $files.Add((Close-PostureEvidenceStream -Stream $stream))
        }
        catch { Stop-PostureEvidenceStream -Stream $stream -Confirm:$false; throw }
        $written.n
    }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $group = { param($rows, [string[]] $keys) @(@($rows | ForEach-Object { [pscustomobject]$_ }) | Group-Object -Property $keys | ForEach-Object { [ordered]@{ Name = $_.Name; Count = $_.Count } } | Sort-Object { -$_.Count }) }
    $odataType = { param($o) ([string]$o['@odata.type']) -replace '^#microsoft\.graph\.', '' }

    # ---------- 9. Intune managed devices (beta for joinType and autopilotEnrolled) ----------
    # The step returns the flattened list so the summaries and the return value share it.
    # Streamed: one pass writes the device rows and tallies the three summaries (the Group-Object shape: Name
    # "a, b, c" and Count, largest first), so a fleet of hundreds of thousands is never held in memory.
    $managed = @{ Count = 0 }
    # Carries on from a cursor when a read stopped part way, and is kept when it finished in this run and the run is
    # resumed; the device count the collector returns then comes from the record of what the step wrote.
    $keepFiles = { param($kept) foreach ($f in @($kept.files)) { $files.Add((Join-Path $Folder "$([string]$f.name).json")) } }
    Invoke-PostureStep -Label 'Intune managed devices' -Folder $Folder -KeepDone -WhenKept {
        param($kept)
        & $keepFiles $kept
        foreach ($f in @($kept.files)) { if ([string]$f.name -eq '09-intune-managed-devices') { $managed['Count'] = [int]$f.rows } }
    } -Script {
        $byOsAgentJoin = @{}; $byOsCompliance = @{}; $byWindowsBuild = @{}
        # Co-management: for each device Configuration Manager and Intune share, which workloads Intune has taken over.
        $workloadNames = @('compliancePolicy', 'deviceConfiguration', 'windowsUpdateForBusiness', 'endpointProtection', 'resourceAccess', 'modernApps', 'officeApps', 'inventory')
        $co = @{ devices = 0 }; foreach ($w in $workloadNames) { $co[$w] = 0 }
        $tally = { param([hashtable] $Map, [string] $Key) $Map[$Key] = 1 + $(if ($Map.ContainsKey($Key)) { $Map[$Key] } else { 0 }) }
        $read = Invoke-PostureListRead -Folder $Folder -ListName '09-intune-managed-devices' -ListUri 'deviceManagement/managedDevices?$select=id,deviceName,configurationManagerClientEnabledFeatures,userPrincipalName,operatingSystem,osVersion,skuFamily,complianceState,managementAgent,joinType,deviceEnrollmentType,managedDeviceOwnerType,autopilotEnrolled,isEncrypted,isSupervised,lastSyncDateTime,enrolledDateTime,manufacturer,model,serialNumber,azureADDeviceId&$top=999' -ListApi 'beta' -ListLabel 'Intune devices' -ListStream '09-intune-managed-devices' -ListState @{ byOsAgentJoin = $byOsAgentJoin; byOsCompliance = $byOsCompliance; byWindowsBuild = $byWindowsBuild; co = $co; managed = $managed } -ListOnPage {
            param($page, $info, $streams)
            $stream = $streams['09-intune-managed-devices']
            foreach ($d in $page) {
                $row = [ordered]@{
                    Id = $d['id']; DeviceName = $d['deviceName']; UserPrincipalName = $d['userPrincipalName']; OperatingSystem = $d['operatingSystem']; OSVersion = $d['osVersion']; SkuFamily = $d['skuFamily']
                    ComplianceState = $d['complianceState']; ManagementAgent = $d['managementAgent']; JoinType = $d['joinType']; DeviceEnrollmentType = $d['deviceEnrollmentType']; ManagedDeviceOwnerType = $d['managedDeviceOwnerType']
                    AutopilotEnrolled = [bool]$d['autopilotEnrolled']; IsEncrypted = [bool]$d['isEncrypted']; IsSupervised = [bool]$d['isSupervised']; LastSyncDateTime = $d['lastSyncDateTime']; EnrolledDateTime = $d['enrolledDateTime']
                    Manufacturer = $d['manufacturer']; Model = $d['model']; SerialNumber = $d['serialNumber']; AzureAdDeviceId = $d['azureADDeviceId']
                    IntuneWorkloads = ''
                }
                if ([string]$row.ManagementAgent -like 'configurationManagerClientMdm*') {
                    $features = $d['configurationManagerClientEnabledFeatures']
                    $on = @($workloadNames | Where-Object { $features -and $features[$_] -eq $true })
                    $row.IntuneWorkloads = $on -join ';'
                    $co.devices++; foreach ($w in $on) { $co[$w]++ }
                }
                Add-PostureEvidenceRow -Stream $stream -Row $row
                $managed.Count++
                & $tally $byOsAgentJoin "$($row.OperatingSystem), $($row.ManagementAgent), $($row.JoinType)"
                & $tally $byOsCompliance "$($row.OperatingSystem), $($row.ComplianceState)"
                if ($row.OperatingSystem -eq 'Windows') { & $tally $byWindowsBuild ([string]$row.OSVersion) }
            }
        }
        foreach ($f in $read.files) { $files.Add($f) }
        $rows = { param([hashtable] $Map) @($Map.Keys | ForEach-Object { [ordered]@{ Name = $_; Count = $Map[$_] } } | Sort-Object { - $_.Count }) }
        & $save (& $rows $byOsAgentJoin) '09-intune-summary-os-agent-join' $true
        & $save (& $rows $byOsCompliance) '09-intune-summary-compliance' $true
        & $save (& $rows $byWindowsBuild) '09-intune-summary-windows-builds' $true
        & $saveOne ([ordered]@{ CoManagedDevices = $co.devices; Workloads = @($workloadNames | ForEach-Object { [ordered]@{ Name = $_; OnIntune = $co[$_] } }) }) '09-intune-comanagement'
    } | Out-Null

    Invoke-PostureStep -Label 'Group Policy analytics' -Folder $Folder -Script {
        # GPOs an admin imported into Intune Group Policy analytics, with how many of their settings MDM supports:
        # the view of Group Policy from the Intune side, without reading Active Directory. Counts only.
        $rows = & $get 'deviceManagement/groupPolicyMigrationReports' 'beta'
        & $save @($rows | ForEach-Object { [ordered]@{ DisplayName = (& $v $_ 'displayName'); MigrationReadiness = (& $v $_ 'migrationReadiness'); TotalSettings = (& $v $_ 'totalSettingsCount'); SupportedSettings = (& $v $_ 'supportedSettingsCount'); SupportedPercent = (& $v $_ 'supportedSettingsPercent'); TargetedInActiveDirectory = (& $v $_ 'targetedInActiveDirectory'); LastModifiedDateTime = (& $v $_ 'lastModifiedDateTime') } }) '09-intune-gpo-analytics' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Intune tenant settings' -Folder $Folder -Script {
        # Compliance defaults: whether a device with no compliance policy counts as compliant (secureByDefault).
        $dm = Invoke-PostureGraphRequest -Uri 'deviceManagement?$select=settings' -ApiVersion 'v1.0' -Single
        & $saveOne ([ordered]@{ SecureByDefault = (& $v $dm 'settings.secureByDefault'); ComplianceCheckinThresholdDays = (& $v $dm 'settings.deviceComplianceCheckinThresholdDays'); IsScheduledActionEnabled = (& $v $dm 'settings.isScheduledActionEnabled') }) '09-intune-settings'
    } | Out-Null
    Invoke-PostureStep -Label 'Autopilot profiles' -Folder $Folder -Script {
        # How new devices are set up: the naming template and the join type, for the experience checks.
        $rows = & $get 'deviceManagement/windowsAutopilotDeploymentProfiles?$expand=assignments' 'beta'
        & $save @($rows | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); Type = (& $odataType $_); DeviceNameTemplate = (& $v $_ 'deviceNameTemplate'); Language = (& $v $_ 'language'); Assignments = @(& $v $_ 'assignments').Count } }) '09-autopilot-profiles' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Autopilot devices' -Folder $Folder -Script {
        $null = & $streamed 'deviceManagement/windowsAutopilotDeviceIdentities?$top=999' '09-autopilot-devices' { [ordered]@{ SerialNumber = (& $v $_ 'serialNumber'); Manufacturer = (& $v $_ 'manufacturer'); Model = (& $v $_ 'model'); GroupTag = (& $v $_ 'groupTag'); EnrollmentState = (& $v $_ 'enrollmentState'); LastContactedDateTime = (& $v $_ 'lastContactedDateTime'); DeploymentProfileAssignmentStatus = (& $v $_ 'deploymentProfileAssignmentStatus'); ManagedDeviceId = (& $v $_ 'managedDeviceId'); AzureActiveDirectoryDeviceId = (& $v $_ 'azureActiveDirectoryDeviceId') } }
    } | Out-Null

    $compliance = @(Invoke-PostureStep -Label 'Intune compliance policies' -Folder $Folder -Script {
            $rows = & $get 'deviceManagement/deviceCompliancePolicies?$expand=assignments'
            & $save @($rows | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); Type = (& $odataType $_); CreatedDateTime = (& $v $_ 'createdDateTime'); LastModifiedDateTime = (& $v $_ 'lastModifiedDateTime'); Version = (& $v $_ 'version'); Assignments = @(& $v $_ 'assignments').Count; DeviceThreatProtectionEnabled = (& $v $_ 'deviceThreatProtectionEnabled'); DeviceThreatProtectionRequiredSecurityLevel = (& $v $_ 'deviceThreatProtectionRequiredSecurityLevel') } }) '09-intune-compliance-policies' $true
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
        # Only the properties that are written: an app's full record carries its icon and its detection rules.
        $null = & $streamed 'deviceAppManagement/mobileApps?$select=id,displayName,publisher,isFeatured,createdDateTime,lastModifiedDateTime&$top=999' '09-intune-apps' { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); Publisher = (& $v $_ 'publisher'); Type = (& $odataType $_); IsFeatured = (& $v $_ 'isFeatured'); CreatedDateTime = (& $v $_ 'createdDateTime'); LastModifiedDateTime = (& $v $_ 'lastModifiedDateTime') } }
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
    Invoke-PostureStep -Label 'Apple ADE tokens' -Folder $Folder -Script {
        # Automated Device Enrollment (the old DEP) tokens: each lasts a year, and new Apple devices stop enrolling
        # the day one lapses. Beta only. A tenant with none answers an empty list.
        $rows = & $get 'deviceManagement/depOnboardingSettings' 'beta'
        & $save @($rows | ForEach-Object { [ordered]@{ TokenName = (& $v $_ 'tokenName'); AppleIdentifier = (& $v $_ 'appleIdentifier'); TokenType = (& $v $_ 'tokenType'); TokenExpirationDateTime = (& $v $_ 'tokenExpirationDateTime'); LastSuccessfulSyncDateTime = (& $v $_ 'lastSuccessfulSyncDateTime'); LastSyncErrorCode = (& $v $_ 'lastSyncErrorCode') } }) '09-apple-ade-tokens' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Certificate connectors' -Folder $Folder -Script {
        # The on-premises connectors that issue certificates to devices (SCEP through NDES, PKCS). One that has stopped
        # answering means no new Wi-Fi, VPN or email certificates. Beta only; state is none, active or inactive.
        # DaysSinceLastConnection is worked out now, against the time of this read: a report built from this
        # evidence a week later must not find every connector a week more silent.
        $rows = & $get 'deviceManagement/ndesConnectors' 'beta'
        & $save @($rows | ForEach-Object {
                $heard = ConvertTo-PostureUtcDateTime (& $v $_ 'lastConnectionDateTime')
                [ordered]@{ DisplayName = (& $v $_ 'displayName'); MachineName = (& $v $_ 'machineName'); State = (& $v $_ 'state'); LastConnectionDateTime = (& $v $_ 'lastConnectionDateTime'); DaysSinceLastConnection = $(if ($heard) { [int][Math]::Max(0, [Math]::Floor(($AsOf - $heard).TotalDays)) } else { $null }); EnrolledDateTime = (& $v $_ 'enrolledDateTime'); ConnectorVersion = (& $v $_ 'connectorVersion') }
            }) '09-certificate-connectors' $true
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
                    # The Enrollment Status Page and Windows settings restore, for the experience checks (restore state verify).
                    if ($type -eq 'windows10EnrollmentCompletionPageConfiguration') { $entry.ShowInstallationProgress = [bool](& $v $_ 'showInstallationProgress'); $entry.AllowDeviceUseOnInstallFailure = [bool](& $v $_ 'allowDeviceUseOnInstallFailure') }
                    if ($type -in 'windowsRestoreDeviceEnrollmentConfiguration', 'deviceEnrollmentWindowsHelloForBusinessConfiguration') { $entry.State = (& $v $_ 'state') }
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
        # One read per assigned policy, twenty to a request ($batch). A policy whose settings are refused fails the
        # step after the others are written down, so one policy never costs the rest.
        $assigned = @($catalog | Where-Object { $_ -and @(& $v $_ 'assignments').Count -gt 0 })
        $answers = @(Invoke-PostureGraphBatch -Url @($assigned | ForEach-Object { "deviceManagement/configurationPolicies/$($_.id)/settings" }) -ApiVersion 'beta' -Label 'Settings catalog policy settings')
        $refused = [System.Collections.Generic.List[string]]::new()
        for ($n = 0; $n -lt $assigned.Count; $n++) {
            $raw = $assigned[$n]; $answer = $answers[$n]
            if ($answer.status -ge 400 -or $answer.status -eq 0) { $refused.Add("$(& $v $raw 'name'): $($answer.status) $($answer.error)"); continue }
            $p = [ordered]@{ Id = $raw.id; Name = (& $v $raw 'name'); TemplateFamily = (& $v $raw 'templateReference.templateFamily'); TemplateDisplayName = (& $v $raw 'templateReference.templateDisplayName'); Platforms = (& $v $raw 'platforms') }
            foreach ($s in @(& $v $answer.body 'value' | Where-Object { $_ })) { & $flattenSetting (& $v $s 'settingInstance') '' $p $out }
        }
        & $save $out.ToArray() '09-intune-policy-settings' $true
        if ($refused.Count -gt 0) { throw "The settings of $($refused.Count) of $($assigned.Count) assigned settings catalog policies could not be read: $($refused[0])" }
    } | Out-Null

    # Template profiles and compliance policies: every scalar property of an assigned policy, so the facts can read
    # deadlines, jailbreak detection, SmartScreen and the other classic settings without a per-type projection.
    $meta = @('id', 'displayName', 'description', 'createdDateTime', 'lastModifiedDateTime', 'version', 'assignments', '@odata.type', 'roleScopeTagIds', 'supportsScopeTags', 'deviceManagementApplicabilityRuleOsEdition', 'deviceManagementApplicabilityRuleOsVersion', 'deviceManagementApplicabilityRuleDeviceMode', 'scheduledActionsForRule')
    $scalarRows = {
        param($Policies)
        @(foreach ($p in @($Policies | Where-Object { $_ -and @(& $v $_ 'assignments').Count -gt 0 })) {
                foreach ($k in @($p.get_Keys() | Where-Object { $_ -notin $meta } | Sort-Object)) {
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
        # The PIN and biometric settings on iOS and Android policies, for the user experience check (UX-018).
        & $save @($rows | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); Type = (& $odataType $_); IsAssigned = (& $v $_ 'isAssigned'); DeployedAppCount = (& $v $_ 'deployedAppCount'); LastModifiedDateTime = (& $v $_ 'lastModifiedDateTime'); PinRequired = (& $v $_ 'pinRequired'); FingerprintBlocked = (& $v $_ 'fingerprintBlocked'); FaceIdBlocked = (& $v $_ 'faceIdBlocked') } }) '09-intune-app-protection-policies' $true
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

    Invoke-PostureStep -Label 'Device management partners' -Folder $Folder -Script {
        # A Mac (or phone) MDM such as Jamf reports compliance to Intune as a compliance management partner (Partner
        # compliance management); the older integration shows as a device management partner. State and heartbeat say
        # whether the link still works.
        $compliance = & $get 'deviceManagement/complianceManagementPartners' 'beta'
        & $save @($compliance | ForEach-Object {
                [ordered]@{
                    Id = $_.id; DisplayName = (& $v $_ 'displayName'); PartnerState = (& $v $_ 'partnerState'); LastHeartbeatDateTime = (& $v $_ 'lastHeartbeatDateTime')
                    MacOsOnboarded = (& $v $_ 'macOsOnboarded'); IosOnboarded = (& $v $_ 'iosOnboarded'); AndroidOnboarded = (& $v $_ 'androidOnboarded'); LinuxOnboarded = (& $v $_ 'linuxOnboarded')
                    MacOsAssignments = @(& $v $_ 'macOsEnrollmentAssignments').Count
                }
            }) '09-intune-compliance-partners' $true
        $legacy = & $get 'deviceManagement/deviceManagementPartners' 'v1.0'
        & $save @($legacy | ForEach-Object {
                [ordered]@{
                    Id = $_.id; DisplayName = (& $v $_ 'displayName'); PartnerState = (& $v $_ 'partnerState'); IsConfigured = (& $v $_ 'isConfigured'); LastHeartbeatDateTime = (& $v $_ 'lastHeartbeatDateTime')
                    PartnerAppType = (& $v $_ 'partnerAppType'); GroupsRequiringPartnerEnrollment = @(& $v $_ 'groupsRequiringPartnerEnrollment').Count
                }
            }) '09-intune-device-management-partners' $true
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
        # Counted per device as the pages arrive: a device has two or three keys, and only how many is kept. (The
        # counter is not called $total: the page reader has a variable of that name, and a block it calls sees its.)
        $byDevice = @{}; $keysSeen = @{ n = 0 }
        $null = Invoke-PostureGraphRequest -Uri 'informationProtection/bitlocker/recoveryKeys?$select=id,deviceId,createdDateTime,volumeType' -ApiVersion 'v1.0' -Label 'BitLocker recovery keys' -OnPage {
            param($page)
            foreach ($k in $page) { $keysSeen.n++; $d = [string](& $v $k 'deviceId'); if ($d) { $byDevice[$d] = 1 + $(if ($byDevice.ContainsKey($d)) { $byDevice[$d] } else { 0 }) } }
        }
        $stream = Open-PostureEvidenceStream -Folder $Folder -Name '08-bitlocker-keys-by-device' -Csv -Confirm:$false
        try {
            foreach ($d in @($byDevice.get_Keys() | Sort-Object)) { Add-PostureEvidenceRow -Stream $stream -Row ([ordered]@{ DeviceId = $d; Keys = $byDevice[$d] }) }
            $files.Add((Close-PostureEvidenceStream -Stream $stream))
        }
        catch { Stop-PostureEvidenceStream -Stream $stream -Confirm:$false; throw }
        & $saveOne ([ordered]@{ Keys = $keysSeen.n; DevicesWithKeys = $byDevice.get_Count() }) '08-bitlocker-keys-summary'
    } | Out-Null

    $errorsPath = Join-Path (Get-PostureRunLayout -Folder $Folder).errors 'errors.txt'
    return @{ files = $files.ToArray(); errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath }); managedDevices = $managed.Count }
}
