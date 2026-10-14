# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-collect-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $env:TKP_TEST_PIM = 'ok'

    Mock -ModuleName Tenantkeep.Posture Get-MgContext {
        [pscustomobject]@{ TenantId = 'tenant-guid'; Account = 'reader@contoso.example'; AuthType = 'Delegated'; Scopes = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All', 'User.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All', 'RoleManagement.Read.Directory', 'IdentityRiskEvent.Read.All') }
    }
    Mock -ModuleName Tenantkeep.Posture Start-Transcript { }
    Mock -ModuleName Tenantkeep.Posture Stop-Transcript { }

    # Synthetic tenant, routed by path. Every value is made up.
    Mock -ModuleName Tenantkeep.Posture Invoke-MgGraphRequest {
        $path = [uri]::UnescapeDataString(([uri]$Uri).PathAndQuery) -replace '^/(v1\.0|beta)/', ''
        $u = { param($items) @{ value = $items } }
        switch -Regex ($path) {
            '^organization\?' { & $u @(@{ id = 'tenant-guid'; displayName = 'Contoso'; onPremisesSyncEnabled = $false; verifiedDomains = @(@{ name = 'contoso.example'; isDefault = $true }) }); break }
            '^subscribedSkus$' { & $u @(@{ skuPartNumber = 'SPB'; skuId = 's1'; consumedUnits = 10; prepaidUnits = @{ enabled = 12; suspended = 0; warning = 0 }; servicePlans = @(@{ servicePlanName = 'AAD_PREMIUM'; provisioningStatus = 'Success' }, @{ servicePlanName = 'INTUNE_A'; provisioningStatus = 'Success' }) }); break }
            '^directory/onPremisesSynchronization$' { & $u @(); break }
            '^policies/(authorizationPolicy|identitySecurityDefaultsEnforcementPolicy|authenticationMethodsPolicy|adminConsentRequestPolicy|crossTenantAccessPolicy/default)$' { @{ id = ($path -split '/')[-1]; isEnabled = $false }; break }
            '^policies/authenticationStrengthPolicies$' { & $u @(@{ id = 's-phish'; displayName = 'Phishing-resistant MFA'; allowedCombinations = @('fido2') }); break }
            '^policies/crossTenantAccessPolicy/partners$' { & $u @(); break }
            '^roleManagement/directory/roleDefinitions' { & $u @(@{ id = 'r-ga'; displayName = 'Global Administrator'; isBuiltIn = $true; isPrivileged = $true; templateId = 'r-ga' }, @{ id = 'r-sec'; displayName = 'Security Administrator'; isBuiltIn = $true; isPrivileged = $true; templateId = 'r-sec' }); break }
            '^roleManagement/directory/roleAssignmentScheduleInstances' {
                if ($env:TKP_TEST_PIM -ne 'ok') { throw 'Request_UnsupportedQuery: PIM is not licensed' }
                & $u @(
                    @{ roleDefinitionId = 'r-ga'; assignmentType = 'Assigned'; memberType = 'Direct'; directoryScopeId = '/'; principalId = 'u1'; principal = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Admin One'; userPrincipalName = 'admin1@contoso.example'; onPremisesSyncEnabled = $false } }
                    @{ roleDefinitionId = 'r-ga'; assignmentType = 'Assigned'; memberType = 'Direct'; directoryScopeId = '/'; principalId = 'u2'; principal = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Admin Two'; userPrincipalName = 'admin2@contoso.example'; onPremisesSyncEnabled = $true } }
                    @{ roleDefinitionId = 'r-ga'; assignmentType = 'Activated'; memberType = 'Direct'; directoryScopeId = '/'; principalId = 'u3'; principal = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Admin Three'; userPrincipalName = 'admin3@contoso.example' } }
                )
                break
            }
            '^roleManagement/directory/roleEligibilityScheduleInstances' { & $u @(@{ roleDefinitionId = 'r-sec'; memberType = 'Direct'; directoryScopeId = '/'; principalId = 'u3'; principal = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Admin Three'; userPrincipalName = 'admin3@contoso.example' } }); break }
            '^roleManagement/directory/roleAssignments' { & $u @(@{ roleDefinitionId = 'r-ga'; directoryScopeId = '/'; principalId = 'u1'; principal = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Admin One'; userPrincipalName = 'admin1@contoso.example' } }); break }
            '^policies/roleManagementPolicyAssignments' {
                $gaRules = @(
                    @{ id = 'Expiration_EndUser_Assignment'; isExpirationRequired = $true; maximumDuration = 'PT8H' },
                    @{ id = 'Enablement_EndUser_Assignment'; enabledRules = @('MultiFactorAuthentication', 'Justification') },
                    @{ id = 'Approval_EndUser_Assignment'; setting = @{ isApprovalRequired = $false } }
                )
                $secRules = @(
                    @{ id = 'Expiration_EndUser_Assignment'; isExpirationRequired = $true; maximumDuration = 'P1D' },
                    @{ id = 'Enablement_EndUser_Assignment'; enabledRules = @('Justification') },
                    @{ id = 'Approval_EndUser_Assignment'; setting = @{ isApprovalRequired = $false } }
                )
                & $u @(
                    @{ roleDefinitionId = 'r-ga'; policyId = 'pol-ga'; policy = @{ rules = $gaRules } },
                    @{ roleDefinitionId = 'r-sec'; policyId = 'pol-sec'; policy = @{ rules = $secRules } }
                )
                break
            }
            '^\$batch$' {
                $reqs = ($Body | ConvertFrom-Json -AsHashtable).requests
                @{ responses = @($reqs | ForEach-Object { @{ id = $_.id; status = 200; body = @{ perUserMfaState = $(if ($_.url -like '*/u2/*') { 'enforced' } else { 'disabled' }) } } }) }; break
            }
            '^devices\?' {
                & $u @(
                    @{ id = 'd1'; deviceId = 'dev-1'; displayName = 'LAPTOP-1'; operatingSystem = 'Windows'; operatingSystemVersion = '10.0.26100.1'; trustType = 'AzureAd'; approximateLastSignInDateTime = '2026-10-10T00:00:00Z'; isCompliant = $true; isManaged = $true; accountEnabled = $true }
                    @{ id = 'd2'; deviceId = 'dev-2'; displayName = 'OLD-PC'; operatingSystem = 'Windows'; operatingSystemVersion = '10.0.19045.1'; trustType = 'ServerAd'; approximateLastSignInDateTime = '2025-01-01T00:00:00Z'; isCompliant = $false; isManaged = $false; accountEnabled = $true }
                    @{ id = 'd3'; deviceId = 'dev-3'; displayName = 'MAC-1'; operatingSystem = 'MacMDM'; trustType = 'Workplace'; isCompliant = $null; isManaged = $false; accountEnabled = $true }
                ); break
            }
            '^reports/authenticationMethods/userRegistrationDetails' {
                & $u @(
                    @{ userPrincipalName = 'admin1@contoso.example'; userDisplayName = 'Admin One'; userType = 'member'; isAdmin = $true; isMfaRegistered = $true; isMfaCapable = $true; isPasswordlessCapable = $true; isSsprRegistered = $true; methodsRegistered = @('passKeyDeviceBound', 'microsoftAuthenticatorPush') }
                    @{ userPrincipalName = 'admin2@contoso.example'; userDisplayName = 'Admin Two'; userType = 'member'; isAdmin = $true; isMfaRegistered = $false; isMfaCapable = $false; isPasswordlessCapable = $false; isSsprRegistered = $false; methodsRegistered = @() }
                    @{ userPrincipalName = 'user1@contoso.example'; userDisplayName = 'User One'; userType = 'member'; isAdmin = $false; isMfaRegistered = $true; isMfaCapable = $true; isPasswordlessCapable = $false; isSsprRegistered = $true; methodsRegistered = @('mobilePhone') }
                    @{ userPrincipalName = 'guest_x#EXT#@contoso.example'; userDisplayName = 'Guest'; userType = 'guest'; isAdmin = $false; isMfaRegistered = $false; isMfaCapable = $false; isPasswordlessCapable = $false; isSsprRegistered = $false; methodsRegistered = @() }
                )
                break
            }
            '^users\?.*signInActivity' { throw 'Authorization_RequestDenied: Insufficient privileges'; break }
            '^users\?' {
                & $u @(
                    @{ id = 'u1'; userPrincipalName = 'admin1@contoso.example'; displayName = 'Admin One'; accountEnabled = $true; userType = 'Member'; onPremisesSyncEnabled = $false; assignedLicenses = @(@{ skuId = 's1' }) }
                    @{ id = 'u2'; userPrincipalName = 'admin2@contoso.example'; displayName = 'Admin Two'; accountEnabled = $true; userType = 'Member'; onPremisesSyncEnabled = $true; assignedLicenses = @() }
                    @{ id = 'u4'; userPrincipalName = 'old@contoso.example'; displayName = 'Old'; accountEnabled = $false; userType = 'Member'; assignedLicenses = @(@{ skuId = 's1' }) }
                    @{ id = 'g1'; userPrincipalName = 'guest_x#EXT#@contoso.example'; displayName = 'Guest'; accountEnabled = $true; userType = 'Guest'; externalUserState = 'PendingAcceptance'; assignedLicenses = @() }
                )
                break
            }
            '^groups\?' { & $u @(@{ id = 'grp1'; displayName = 'All Staff'; groupTypes = @('Unified'); mailEnabled = $true; securityEnabled = $false }, @{ id = 'grp2'; displayName = 'Dyn'; groupTypes = @('DynamicMembership'); mailEnabled = $false; securityEnabled = $true; membershipRule = 'user.department -eq "x"' }, @{ id = 'grp3'; displayName = 'Sec'; groupTypes = @(); mailEnabled = $false; securityEnabled = $true; isAssignableToRole = $true }); break }
            '^groups/.*/transitiveMembers' { & $u @(); break }
            '^applications\?' { & $u @(@{ id = 'a1'; appId = 'app-1'; displayName = 'Old App'; signInAudience = 'AzureADMyOrg'; passwordCredentials = @(@{ endDateTime = '2024-01-01T00:00:00Z' }, @{ endDateTime = '2030-01-01T00:00:00Z' }); keyCredentials = @() }); break }
            "^servicePrincipals\?.*appId eq '00000003" { & $u @(@{ id = 'sp-graph'; appId = '00000003-0000-0000-c000-000000000000'; appRoles = @(@{ id = 'role-1'; value = 'Directory.Read.All' }) }); break }
            '^servicePrincipals\?.*appId in' { & $u @(); break }
            '^servicePrincipals\?' { & $u @(@{ id = 'sp1'; appId = 'app-1'; displayName = 'Old App'; accountEnabled = $true; servicePrincipalType = 'Application'; appOwnerOrganizationId = 'tenant-guid'; tags = @('WindowsAzureActiveDirectoryIntegratedApp'); keyCredentials = @(@{ usage = 'Verify'; endDateTime = '2027-05-05T00:00:00Z' }); passwordCredentials = @() }); break }
            '^servicePrincipals/sp-graph/appRoleAssignedTo' { & $u @(@{ principalDisplayName = 'Old App'; principalId = 'sp1'; principalType = 'ServicePrincipal'; appRoleId = 'role-1'; createdDateTime = '2025-01-01T00:00:00Z' }); break }
            '^oauth2PermissionGrants' { & $u @(@{ clientId = 'sp1'; consentType = 'AllPrincipals'; resourceId = 'sp-graph'; scope = 'User.Read openid' }); break }
            '^identityProtection/riskyUsers' { throw 'Authorization_RequestDenied: Insufficient privileges to complete the operation.'; break }
            '^identityProtection/riskDetections' { & $u @(@{ userPrincipalName = 'user1@contoso.example'; riskEventType = 'anonymizedIPAddress'; riskLevel = 'medium'; riskState = 'atRisk'; activityDateTime = '2026-10-10T00:00:00Z'; ipAddress = '203.0.113.9'; location = @{ countryOrRegion = 'US' } }); break }
            '^deviceManagement/managedDevices' {
                & $u @(
                    @{ id = 'm1'; deviceName = 'LAPTOP-1'; userPrincipalName = 'admin1@contoso.example'; operatingSystem = 'Windows'; osVersion = '10.0.26100.1'; complianceState = 'compliant'; managementAgent = 'mdm'; joinType = 'azureADJoined'; autopilotEnrolled = $true; isEncrypted = $true; azureADDeviceId = 'dev-1' },
                    @{ id = 'm2'; deviceName = 'OLD-PC'; userPrincipalName = 'user1@contoso.example'; operatingSystem = 'Windows'; osVersion = '10.0.19045.1'; complianceState = 'noncompliant'; managementAgent = 'mdm'; joinType = 'hybridAzureADJoined'; autopilotEnrolled = $false; isEncrypted = $false; azureADDeviceId = 'dev-2' },
                    @{ id = 'm3'; deviceName = 'MAC-1'; userPrincipalName = 'user1@contoso.example'; operatingSystem = 'macOS'; osVersion = '15.1'; complianceState = 'compliant'; managementAgent = 'mdm'; joinType = 'azureADRegistered'; autopilotEnrolled = $false; isEncrypted = $true; azureADDeviceId = 'dev-3' }
                ); break
            }
            '^deviceManagement/windowsAutopilotDeviceIdentities' { & $u @(@{ serialNumber = 'SN1'; manufacturer = 'Dell'; model = 'Latitude'; enrollmentState = 'enrolled'; managedDeviceId = 'm1' }); break }
            '^deviceManagement/deviceCompliancePolicies' { & $u @(@{ id = 'cp1'; displayName = 'Windows compliance'; '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; bitLockerEnabled = $true; assignments = @(@{ id = 'a1' }) }, @{ id = 'cp2'; displayName = 'iOS compliance'; '@odata.type' = '#microsoft.graph.iosCompliancePolicy'; securityBlockJailbrokenDevices = $true; passcodeRequired = $true; scheduledActionsForRule = @(@{ ruleName = 'x' }); assignments = @(@{ id = 'a1' }) }); break }
            '^deviceManagement/deviceConfigurations' { & $u @(@{ id = 'dc1'; displayName = 'Wi-Fi'; '@odata.type' = '#microsoft.graph.windowsWifiConfiguration'; assignments = @() }, @{ id = 'dc2'; displayName = 'Update ring'; '@odata.type' = '#microsoft.graph.windowsUpdateForBusinessConfiguration'; deadlineForQualityUpdatesInDays = 3; deadlineForFeatureUpdatesInDays = 7; deadlineGracePeriodInDays = 2; qualityUpdatesDeferralPeriodInDays = 0; assignments = @(@{ id = 'a1' }) }); break }
            '^deviceManagement/configurationPolicies/sc1/settings' {
                $ch = { param([string] $Def, [string] $Val, $Children = @()) @{ settingInstance = @{ settingDefinitionId = $Def; choiceSettingValue = @{ value = $Val; children = $Children } } } }
                & $u @(
                    (& $ch 'device_vendor_msft_policy_config_defender_allowrealtimemonitoring' 'device_vendor_msft_policy_config_defender_allowrealtimemonitoring_1'),
                    (& $ch 'device_vendor_msft_policy_config_defender_allowcloudprotection' 'device_vendor_msft_policy_config_defender_allowcloudprotection_1'),
                    (& $ch 'device_vendor_msft_policy_config_defender_puaprotection' 'device_vendor_msft_policy_config_defender_puaprotection_1'),
                    (& $ch 'device_vendor_msft_policy_config_defender_submitsamplesconsent' 'device_vendor_msft_policy_config_defender_submitsamplesconsent_1'),
                    (& $ch 'device_vendor_msft_policy_config_defender_schedulescanday' 'device_vendor_msft_policy_config_defender_schedulescanday_8'),
                    (& $ch 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablecontentfromemailclientandwebmail' 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablecontentfromemailclientandwebmail_block'),
                    (& $ch 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwin32apicallsfromofficemacros' 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwin32apicallsfromofficemacros_audit'),
                    @{ settingInstance = @{ settingDefinitionId = 'device_vendor_msft_policy_config_defender_attacksurfacereductiononlyexclusions'; simpleSettingCollectionValue = @(@{ value = 'C:\Tools\legacy.exe' }, @{ value = 'C:\Build' }) } }
                ); break
            }
            '^deviceManagement/configurationPolicies/sc2/settings' {
                & $u @(
                    @{ settingInstance = @{ settingDefinitionId = 'device_vendor_msft_bitlocker_requiredeviceencryption'; choiceSettingValue = @{ value = 'device_vendor_msft_bitlocker_requiredeviceencryption_1'; children = @() } } },
                    @{ settingInstance = @{ settingDefinitionId = 'device_vendor_msft_bitlocker_encryptionmethodbydrivetype'; choiceSettingValue = @{ value = 'device_vendor_msft_bitlocker_encryptionmethodbydrivetype_1'; children = @(@{ settingDefinitionId = 'device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsosdropdown_name'; choiceSettingValue = @{ value = 'device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsosdropdown_name_7'; children = @() } }) } } },
                    @{ settingInstance = @{ settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions'; groupSettingCollectionValue = @(@{ children = @(@{ settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osrequireactivedirectorybackup_name'; choiceSettingValue = @{ value = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osrequireactivedirectorybackup_name_1'; children = @() } }) }) } },
                    @{ settingInstance = @{ settingDefinitionId = 'device_vendor_msft_laps_policies_passwordagedays'; simpleSettingValue = @{ value = 30 } } }
                ); break
            }
            '^deviceManagement/configurationPolicies/sc3/settings' {
                & $u @(
                    @{ settingInstance = @{ settingDefinitionId = 'device_vendor_msft_laps_policies_backupdirectory'; choiceSettingValue = @{ value = 'device_vendor_msft_laps_policies_backupdirectory_1'; children = @() } } },
                    @{ settingInstance = @{ settingDefinitionId = 'device_vendor_msft_laps_policies_postauthenticationactions'; choiceSettingValue = @{ value = 'device_vendor_msft_laps_policies_postauthenticationactions_3'; children = @() } } }
                ); break
            }
            '^deviceManagement/configurationPolicies' {
                & $u @(
                    @{ id = 'sc1'; name = 'AV baseline'; platforms = 'windows10'; technologies = 'mdm'; templateReference = @{ templateFamily = 'endpointSecurityAntivirus'; templateDisplayName = 'Microsoft Defender Antivirus' }; settingCount = 12; assignments = @(@{ id = 'a' }) },
                    @{ id = 'sc2'; name = 'BitLocker'; platforms = 'windows10'; technologies = 'mdm'; templateReference = @{ templateFamily = 'endpointSecurityDiskEncryption'; templateDisplayName = 'BitLocker' }; settingCount = 8; assignments = @(@{ id = 'a' }) },
                    @{ id = 'sc3'; name = 'LAPS'; platforms = 'windows10'; technologies = 'mdm'; templateReference = @{ templateFamily = 'endpointSecurityAccountProtection'; templateDisplayName = 'Local admin password solution (Windows LAPS)' }; settingCount = 4; assignments = @(@{ id = 'a' }) },
                    @{ id = 'sc4'; name = 'Firewall draft'; platforms = 'windows10'; technologies = 'mdm'; templateReference = @{ templateFamily = 'endpointSecurityFirewall'; templateDisplayName = 'Firewall' }; settingCount = 3; assignments = @() }
                ); break
            }
            '^deviceAppManagement/managedAppPolicies' { & $u @(@{ id = 'mam1'; displayName = 'iOS MAM'; '@odata.type' = '#microsoft.graph.iosManagedAppProtection'; isAssigned = $true; deployedAppCount = 12 }, @{ id = 'mam2'; displayName = 'Android MAM draft'; '@odata.type' = '#microsoft.graph.androidManagedAppProtection'; isAssigned = $false; deployedAppCount = 0 }); break }
            '^deviceManagement/windowsFeatureUpdateProfiles' { & $u @(@{ id = 'fu1'; displayName = 'Windows 11 24H2'; featureUpdateVersion = 'Windows 11, version 24H2'; assignments = @(@{ id = 'a' }) }); break }
            '^deviceAppManagement/mobileApps' { & $u @(@{ id = 'app1'; displayName = 'Company Portal'; publisher = 'Microsoft'; '@odata.type' = '#microsoft.graph.winGetApp' }); break }
            '^deviceManagement/applePushNotificationCertificate$' { if ($env:TKP_TEST_APNS -eq 'missing') { throw 'Response status code does not indicate success: NotFound (Not Found).' }; @{ appleIdentifier = 'apple@contoso.example'; expirationDateTime = '2026-11-20T00:00:00Z'; topicIdentifier = 'com.apple.mgmt.x' }; break }
            '^deviceAppManagement/vppTokens' { & $u @(@{ organizationName = 'Contoso'; appleId = 'apple@contoso.example'; state = 'valid'; expirationDateTime = '2027-06-01T00:00:00Z' }); break }
            '^deviceManagement/deviceEnrollmentConfigurations' { & $u @(@{ id = 'er1'; displayName = 'All users and all devices'; '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'; priority = 0; windowsRestriction = @{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $true }; macOSRestriction = @{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $false }; assignments = @() }, @{ id = 'whfb'; displayName = 'All users and all devices'; '@odata.type' = '#microsoft.graph.windowsHelloForBusinessConfiguration'; priority = 0; state = 'enabled'; pinMinimumLength = 6; securityDeviceRequired = $true; unlockWithBiometricsEnabled = $true; assignments = @() }); break }
            '^deviceManagement/mobileThreatDefenseConnectors' { & $u @(@{ id = 'mde'; partnerState = 'available'; windowsEnabled = $true; macEnabled = $true; lastHeartbeatDateTime = '2026-10-13T00:00:00Z' }); break }
            '^deviceManagement/managedDeviceCleanupRules' { & $u @(@{ id = 'r1'; displayName = 'Windows 90d'; deviceCleanupRulePlatformType = 'windows'; deviceInactivityBeforeRetirementInDays = 90 }); break }
            '^informationProtection/bitlocker/recoveryKeys' { & $u @(@{ id = 'k1'; deviceId = 'dev-1'; volumeType = 'operatingSystemVolume' }, @{ id = 'k2'; deviceId = 'dev-1'; volumeType = 'fixedDataVolume' }); break }
            '^identity/conditionalAccess/policies$' { & $u @(); break }
            '^identity/conditionalAccess/namedLocations$' { & $u @(); break }
            '^identity/conditionalAccess/authenticationContextClassReferences$' { & $u @(); break }
            default { throw "Unexpected Graph call in test: $path" }
        }
    }
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
    Remove-Item Env:TKP_TEST_PIM -ErrorAction SilentlyContinue
}

Describe 'Invoke-PostureCollection' {
    Context 'full run' {
        BeforeAll {
            $script:R = Invoke-PostureCollection -OutRoot $script:Root -PassThru -WarningAction SilentlyContinue -WarningVariable script:W
            $script:Read = { param($n) Get-Content -Raw -LiteralPath (Join-Path $script:R.Folder "$n.json") | ConvertFrom-Json }
        }

        It 'creates a bare-stamp run folder and writes the A.1 files plus the CA snapshot' {
            Split-Path $script:R.Folder -Leaf | Should -Match '^\d{8}-\d{4}$'
            foreach ($f in '01-organization', '01-subscribed-skus', '02-authorization-policy', '02-authentication-strengths', '04-role-assignments-active', '04-role-assignments-pim-eligible', '04-pim-role-policies', '05-auth-registration', '05-auth-registration-summary', '05-per-user-mfa', '05-per-user-mfa-summary', '06-users', '06-users-summary', '07-groups', '08-entra-devices', '08-entra-devices-by-join-os', '08-entra-devices-stale', '10-app-registrations', '10-service-principals', '10-graph-app-permissions', '10-oauth2-delegated-grants', '11-risk-detections-30d', 'policies', 'resolved-names', 'metadata', 'collection') {
                Join-Path $script:R.Folder "$f.json" | Should -Exist
            }
            foreach ($f in '01-subscribed-skus', '04-role-assignments-active', '05-auth-registration', '06-users', '07-groups', '10-app-registrations', '10-service-principals') {
                Join-Path $script:R.Folder "$f.csv" | Should -Exist
            }
            $script:R.Collectors | Should -Be @('ConditionalAccess', 'Entra', 'Intune')
            foreach ($f in '09-intune-managed-devices', '09-intune-summary-compliance', '09-intune-summary-windows-builds', '09-autopilot-devices', '09-intune-compliance-policies', '09-intune-config-profiles-templates', '09-intune-config-profiles-settings-catalog', '09-intune-apps', '09-apple-push-cert', '09-apple-vpp-tokens', '09-intune-enrollment-restrictions', '09-intune-mde-connector', '09-intune-device-cleanup', '08-bitlocker-keys-by-device', '08-bitlocker-keys-summary') {
                Join-Path $script:R.Folder "$f.json" | Should -Exist
            }
        }

        It 'collects Intune devices, policies by template family, restrictions, the connector and BitLocker key presence' {
            $m = & $script:Read '09-intune-managed-devices'
            $m.Count | Should -Be 3
            ($m | Where-Object DeviceName -eq 'LAPTOP-1').AutopilotEnrolled | Should -BeTrue
            (& $script:Read '09-intune-summary-compliance' | Where-Object Name -eq 'Windows, noncompliant').Count | Should -Be 1
            $sc = & $script:Read '09-intune-config-profiles-settings-catalog'
            ($sc | Where-Object Name -eq 'LAPS').TemplateFamily | Should -Be 'endpointSecurityAccountProtection'
            ($sc | Where-Object Name -eq 'Firewall draft').Assignments | Should -Be 0
            (& $script:Read '09-intune-enrollment-restrictions')[0].windowsPersonalBlocked | Should -BeTrue
            (& $script:Read '09-intune-mde-connector')[0].PartnerState | Should -Be 'available'
            (& $script:Read '09-intune-device-cleanup').Enabled | Should -BeTrue
            (& $script:Read '09-intune-device-cleanup').DeviceInactivityBeforeRetirementInDays | Should -Be 90
            (& $script:Read '08-bitlocker-keys-summary').DevicesWithKeys | Should -Be 1
            (& $script:Read '08-bitlocker-keys-by-device')[0].Keys | Should -Be 2
        }

        It 'flattens settings catalog values through choice children and group collections, and the policy scalars' {
            $settings = @(& $script:Read '09-intune-policy-settings')
            @($settings | Where-Object { $_.PolicyId -eq 'sc4' }).Count | Should -Be 0 -Because 'unassigned policies are not read'
            $xts = @($settings | Where-Object { $_.SettingDefinitionId -like '*encryptionmethodwithxtsosdropdown_name' })
            $xts.Count | Should -Be 1
            $xts[0].Value | Should -Match '_7$'
            @($settings | Where-Object { $_.SettingDefinitionId -like '*osrequireactivedirectorybackup_name' }).Count | Should -Be 1 -Because 'group collections are recursed'
            @($settings | Where-Object { $_.SettingDefinitionId -like '*passwordagedays' })[0].Value | Should -Be 30
            @($settings | Where-Object { $_.SettingDefinitionId -like '*attacksurfacereductiononlyexclusions' })[0].Value | Should -Be 'C:\Tools\legacy.exe|C:\Build'
            $cfg = @(& $script:Read '09-intune-config-profile-settings')
            @($cfg | Where-Object { $_.Setting -eq 'deadlineForQualityUpdatesInDays' })[0].Value | Should -Be 3
            @($cfg | Where-Object { $_.PolicyId -eq 'dc1' }).Count | Should -Be 0
            $comp = @(& $script:Read '09-intune-compliance-policy-settings')
            @($comp | Where-Object { $_.Setting -eq 'securityBlockJailbrokenDevices' })[0].Type | Should -Be 'iosCompliancePolicy'
            @($comp | Where-Object { $_.Setting -eq 'scheduledActionsForRule' }).Count | Should -Be 0
            (& $script:Read '09-intune-windows-hello').State | Should -Be 'enabled'
            @(& $script:Read '09-intune-app-protection-policies' | Where-Object { $_.IsAssigned }).Count | Should -Be 1
            @(& $script:Read '09-intune-feature-update-profiles')[0].Assignments | Should -Be 1
        }

        It 'feeds the endpoint checks from the same folder' {
            $profilePath = Join-Path $script:Root 'endpoint-profile.json'
            '{ "version": 1, "identityModel": "cloud-only", "platforms": ["windows", "macOS", "iOS"], "byod": "mam", "licenses": ["BusinessPremium", "Intune", "MDEBusiness"] }' | Set-Content -LiteralPath $profilePath
            $run = Invoke-PostureChecks -Evidence $script:R.Folder -Domain endpoint -ProfilePath $profilePath -OutputPath (Join-Path $script:Root 'endpoint-checks') -PassThru
            $by = @{}; foreach ($r in $run.results) { $by[$r.id] = $r }
            $by['EP-002'].status | Should -Be 'fail' -Because $by['EP-002'].reason
            @($by['EP-002'].affected | ForEach-Object { $_.name }) | Should -Be @('silent enablement', 'TPM required at startup')
            $by['EP-004'].status | Should -Be 'pass'
            $by['EP-005'].status | Should -Be 'fail' -Because 'scheduled scan day 8 is never'
            $by['EP-008'].status | Should -Be 'fail'
            $by['EP-008'].affectedCount | Should -Be 18 -Because 'one rule blocks, one audits, seventeen are not configured'
            $by['EP-009'].affectedCount | Should -Be 2
            $by['EP-012'].status | Should -Be 'pass'
            $by['EP-013'].status | Should -Be 'notApplicable' -Because 'the fixture profile is cloud-only'
            $by['EP-014'].status | Should -Be 'pass'
            $by['EP-015'].status | Should -Be 'fail' -Because 'macOS is in scope and no FileVault policy exists'
            $by['EP-018'].status | Should -Be 'pass' -Because 'iOS has an assigned app protection policy and jailbreak detection; Android is out of scope'
        }

        It 'flattens roles with names and counts permanent Global Administrators' {
            $a = & $script:Read '04-role-assignments-active'
            $a.Count | Should -Be 3
            ($a | Where-Object PrincipalUpn -eq 'admin2@contoso.example').Role | Should -Be 'Global Administrator'
            ($a | Where-Object PrincipalUpn -eq 'admin2@contoso.example').PrincipalSynced | Should -BeTrue
            $e = & $script:Read '04-role-assignments-pim-eligible'
            $e[0].AssignmentType | Should -Be 'Eligible'
            $s = & $script:Read '04-role-assignments-summary'
            $s.source | Should -Be 'pim'
            $s.permanentGlobalAdmins | Should -Be 2
        }

        It 'flattens PIM role policies with hours, MFA, justification and approval' {
            $pim = & $script:Read '04-pim-role-policies'
            $pim.Count | Should -Be 2
            $ga = $pim | Where-Object Role -eq 'Global Administrator'
            $ga.MaxActivationHours | Should -Be 8
            $ga.ActivationMfaRequired | Should -BeTrue
            $ga.ApprovalRequired | Should -BeFalse
            $sec = $pim | Where-Object Role -eq 'Security Administrator'
            $sec.MaxActivationHours | Should -Be 24
            $sec.ActivationMfaRequired | Should -BeFalse
        }

        It 'reads per-user MFA state through batched requests and summarises it' {
            $s = & $script:Read '05-per-user-mfa-summary'
            $s.Users | Should -Be 3
            $s.Enforced | Should -Be 1
            $s.Disabled | Should -Be 2
            (& $script:Read '05-per-user-mfa' | Where-Object UserPrincipalName -eq 'admin2@contoso.example').PerUserMfaState | Should -Be 'enforced'
            Should -Invoke -ModuleName Tenantkeep.Posture Invoke-MgGraphRequest -Times 1 -Exactly -Scope Context -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/beta/$batch' -and $Method -eq 'POST' } -Because 'authentication/requirements exists only in beta'
        }

        It 'collects Entra devices with join type and staleness' {
            $d = & $script:Read '08-entra-devices'
            $d.Count | Should -Be 3
            ($d | Where-Object DisplayName -eq 'LAPTOP-1').JoinType | Should -Be 'EntraJoined'
            ($d | Where-Object DisplayName -eq 'OLD-PC').JoinType | Should -Be 'HybridJoined'
            ($d | Where-Object DisplayName -eq 'OLD-PC').Stale | Should -BeTrue
            ($d | Where-Object DisplayName -eq 'MAC-1').Stale | Should -BeTrue -Because 'never signed in'
            (& $script:Read '08-entra-devices-stale').Count | Should -BeGreaterOrEqual 2
        }

        It 'computes the registration summary' {
            $s = & $script:Read '05-auth-registration-summary'
            $s.TotalMembers | Should -Be 3
            $s.MfaRegisteredPct | Should -Be 66.7
            $s.Admins | Should -Be 2
            $s.AdminsNoMfa | Should -Be 1
            $s.AdminsNotPasswordless | Should -Be 1
            $s.UsersWithSms | Should -Be 1
            $s.UsersWithPasskeyOrFido | Should -Be 1
        }

        It 'falls back to users without sign-in activity and says so in the summary' {
            $s = & $script:Read '06-users-summary'
            $s.Total | Should -Be 4
            $s.Members | Should -Be 3
            $s.Guests | Should -Be 1
            $s.Synced | Should -Be 1
            $s.DisabledWithLicenses | Should -Be 1
            $s.PendingGuestInvites | Should -Be 1
            $s.SignInActivityAvailable | Should -BeFalse
            $s.EnabledNeverSignedIn | Should -Be 2 -Because 'without sign-in data every enabled member looks never signed in'
        }

        It 'classifies groups and flags expired app credentials' {
            $g = & $script:Read '07-groups'
            @($g | ForEach-Object { $_.Kind }) | Should -Be @('M365', 'DynamicSecurity', 'Security')
            ($g | Where-Object DisplayName -eq 'Dyn').Dynamic | Should -BeTrue
            $apps = & $script:Read '10-app-registrations'
            $apps[0].Secrets | Should -Be 2
            $apps[0].ExpiredCredentials | Should -Be 1
            ([datetime]$apps[0].EarliestExpiry).ToUniversalTime().ToString('yyyy-MM-dd') | Should -Be '2024-01-01'
            $sps = & $script:Read '10-service-principals'
            $sps[0].HomeTenantApp | Should -BeTrue
            ([datetime]$sps[0].SamlCertExpiry).ToUniversalTime().ToString('yyyy-MM-dd') | Should -Be '2027-05-05'
            (& $script:Read '10-graph-app-permissions')[0].Permission | Should -Be 'Directory.Read.All'
        }

        It 'logs a denied step to errors.txt and keeps going' {
            $script:R.Errors | Should -HaveCount 1
            $script:R.Errors[0] | Should -Match '^Risky users :: '
            Join-Path $script:R.Folder '11-risky-users.json' | Should -Not -Exist
            (& $script:Read '11-risk-detections-30d')[0].Country | Should -Be 'US'
        }

        It 'writes collection.json with tenant, scopes, api versions and the file list, and keeps the CA metadata separate' {
            $m = & $script:Read 'collection'
            $m.tenantId | Should -Be 'tenant-guid'
            $m.collectors | Should -Be @('ConditionalAccess', 'Entra', 'Intune')
            $m.graphApiVersions | Should -Be @('beta', 'v1.0') -Because 'the per-user MFA batch is the one beta call'
            $m.files | Should -Contain '06-users.csv'
            $m.errorCount | Should -Be 1
            (& $script:Read 'metadata').snapshotType | Should -Be 'conditional-access'
        }

        It 'warns about optional scopes that are missing' {
            @($script:W | Where-Object { $_ -like '*IdentityRiskyUser.Read.All*' }).Count | Should -Be 1
        }

        It 'feeds the CA and devices checks from the same folder' {
            $r = Invoke-PostureChecks -Evidence $script:R.Folder -Domain ca, devices -PassThru
            $r.results.Count | Should -Be 29
            $d = @{}; foreach ($x in $r.results) { $d[$x.id] = $x }
            $d['DEV-005'].status | Should -Be 'fail' -Because 'OLD-PC has no BitLocker key'
            $d['DEV-007'].status | Should -Be 'fail' -Because 'OLD-PC is Windows 10'
            $d['DEV-009'].status | Should -Be 'pass'
            $d['DEV-010'].status | Should -Be 'fail' -Because 'firewall is unassigned and ASR and EDR are missing'
            $d['DEV-010'].affected.name | Should -Be @('firewall', 'attackSurfaceReduction', 'endpointDetectionAndResponse')
            $d['DEV-011'].status | Should -Be 'pass'
            $d['DEV-012'].status | Should -Be 'pass'
            $d['DEV-013'].status | Should -Be 'pass'
            $d['DEV-002'].status | Should -Be 'pass' -Because 'stale devices exist but the cleanup rule is on'
            $d['DEV-008'].status | Should -Be 'fail' -Because 'the push certificate expires within 60 days of the run'
            $rep = New-PostureReport -Evidence $script:R.Folder -OutputPath (Join-Path $script:Root 'rep') -Format Markdown -PassThru
            $rep.Report.headline.intuneCompliancePct | Should -Be 66.7 -Because 'two of three devices with a known state are compliant'
        }
    }

    Context 'without PIM' {
        It 'falls back to plain role assignments' {
            $env:TKP_TEST_PIM = 'no'
            try {
                $r = Invoke-PostureCollection -OutputFolder (Join-Path $script:Root 'nopim') -Collector Entra -SkipCaSnapshot -SkipPerUserMfa -PassThru -WarningAction SilentlyContinue
                Join-Path $r.Folder '05-per-user-mfa-summary.json' | Should -Not -Exist
                $s = Get-Content -Raw (Join-Path $r.Folder '04-role-assignments-summary.json') | ConvertFrom-Json
                $s.source | Should -Be 'roleAssignments'
                $s.active | Should -Be 1
                $s.eligible | Should -Be 0
                $r.Collectors | Should -Be @('Entra')
                Join-Path $r.Folder 'policies.json' | Should -Not -Exist
            }
            finally { $env:TKP_TEST_PIM = 'ok' }
        }
    }

    Context 'Apple certificate absent' {
        It 'records Present = false instead of failing the step' {
            $env:TKP_TEST_APNS = 'missing'
            try {
                $r = Invoke-PostureCollection -OutputFolder (Join-Path $script:Root 'noapns') -Collector Intune -SkipCaSnapshot -PassThru -WarningAction SilentlyContinue
                (Get-Content -Raw (Join-Path $r.Folder '09-apple-push-cert.json') | ConvertFrom-Json).Present | Should -BeFalse
                @($r.Errors | Where-Object { $_ -like 'Apple push*' }).Count | Should -Be 0
            }
            finally { Remove-Item Env:TKP_TEST_APNS -ErrorAction SilentlyContinue }
        }
    }

    Context 'scope check' {
        It 'refuses without the core scopes' {
            Mock -ModuleName Tenantkeep.Posture Get-MgContext { [pscustomobject]@{ TenantId = 't'; Account = 'a'; AuthType = 'Delegated'; Scopes = @('User.Read') } }
            { Invoke-PostureCollection -OutRoot $script:Root } | Should -Throw '*missing scope(s)*'
        }
    }
}
