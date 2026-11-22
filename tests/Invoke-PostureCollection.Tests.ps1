# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-collect-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $env:TKP_TEST_PIM = 'ok'

    Mock -ModuleName TenantKeep.Posture Get-MgContext {
        [pscustomobject]@{ TenantId = 'tenant-guid'; Account = 'reader@contoso.example'; AuthType = 'Delegated'; Scopes = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All', 'User.Read.All', 'AuditLog.Read.All', 'SharePointTenantSettings.Read.All', 'UserAuthenticationMethod.Read.All', 'RoleManagement.Read.Directory', 'IdentityRiskEvent.Read.All', 'ThreatHunting.Read.All', 'SecurityIncident.Read.All', 'SecurityEvents.Read.All') }
    }
    Mock -ModuleName TenantKeep.Posture Start-Transcript { }
    Mock -ModuleName TenantKeep.Posture Stop-Transcript { }
    Mock -ModuleName TenantKeep.Posture Test-PostureAzureSession { $false }

    # Synthetic tenant, routed by path. Every value is made up. The route is a script block of its own so a request
    # inside a $batch is answered exactly as the same request sent alone.
    $script:GraphRoute = {
        param([string] $Uri, $Body)
        $path = [uri]::UnescapeDataString(([uri]$Uri).PathAndQuery) -replace '^/(v1\.0|beta)/', ''
        $u = { param($items) @{ value = $items } }
        switch -Regex ($path) {
            '^admin/sharepoint/settings$' { @{ sharingCapability = 'externalUserSharingOnly'; isResharingByExternalUsersEnabled = $false }; break }
            '^auditLogs/signIns' { & $u @(@{ id = 's1'; createdDateTime = '2026-10-14T09:00:00Z'; userPrincipalName = 'user1@contoso.example'; clientAppUsed = 'IMAP4'; isInteractive = $true; conditionalAccessStatus = 'notApplied'; status = @{ errorCode = 0 }; location = @{ countryOrRegion = 'US' } }); break }
            '^organization\?' { & $u @(@{ id = 'tenant-guid'; displayName = 'Contoso'; onPremisesSyncEnabled = $false; verifiedDomains = @(@{ name = 'contoso.example'; isDefault = $true }) }); break }
            '^deviceManagement/groupPolicyMigrationReports' { & $u @(@{ displayName = 'Workstation baseline'; migrationReadiness = 'partial'; totalSettingsCount = 40; supportedSettingsCount = 30; supportedSettingsPercent = 75; targetedInActiveDirectory = $true }); break }
            '^deviceManagement\?' { @{ settings = @{ secureByDefault = $false; deviceComplianceCheckinThresholdDays = 30; isScheduledActionEnabled = $true } }; break }
            '^groupSettings' { & $u @(@{ displayName = 'Password Rule Settings'; templateId = '5cf42378-d67d-4f36-ba46-e8b86229381d'; values = @(@{ name = 'EnableBannedPasswordCheck'; value = 'True' }, @{ name = 'BannedPasswordList'; value = "contoso`tcontosoltd`tseattle" }, @{ name = 'BannedPasswordCheckOnPremisesMode'; value = 'Audit' }) }); break }
            '^organization/[^/?]+/branding' { @{ backgroundImageRelativeUrl = 'bg.png'; bannerLogoRelativeUrl = 'logo.png'; signInPageText = 'Contoso staff only' }; break }
            '^deviceManagement/windowsAutopilotDeploymentProfiles' { & $u @(@{ id = 'ap1'; displayName = 'Standard'; '@odata.type' = '#microsoft.graph.azureADWindowsAutopilotDeploymentProfile'; deviceNameTemplate = 'CTS-%SERIAL%'; assignments = @(@{ id = 'a1' }) }); break }
            '^domains\?' { & $u @(@{ id = 'contoso.example'; isDefault = $true; isInitial = $false; isVerified = $true; authenticationType = 'Managed' }); break }
            '^subscribedSkus$' { & $u @(@{ skuPartNumber = 'SPB'; skuId = 's1'; consumedUnits = 10; prepaidUnits = @{ enabled = 12; suspended = 0; warning = 0 }; servicePlans = @(@{ servicePlanName = 'AAD_PREMIUM'; servicePlanId = 'p-aad'; provisioningStatus = 'Success' }, @{ servicePlanName = 'INTUNE_A'; servicePlanId = 'p-intune'; provisioningStatus = 'Success' }) }); break }
            '^directory/onPremisesSynchronization$' { & $u @(); break }
            { $_ -eq 'policies/authenticationMethodsPolicy' -and $Uri -match '/beta/' } { @{ id = 'authenticationMethodsPolicy'; systemCredentialPreferences = @{ state = 'enabled' } }; break }
            '^policies/(authorizationPolicy|identitySecurityDefaultsEnforcementPolicy|authenticationMethodsPolicy|adminConsentRequestPolicy|crossTenantAccessPolicy/default)$' { @{ id = ($path -split '/')[-1]; isEnabled = $false }; break }
            '^policies/authenticationStrengthPolicies$' { & $u @(@{ id = 's-phish'; displayName = 'Phishing-resistant MFA'; allowedCombinations = @('fido2') }); break }
            '^policies/crossTenantAccessPolicy/partners$' { & $u @(); break }
            '^roleManagement/directory/roleDefinitions' { & $u @(@{ id = 'r-ga'; displayName = 'Global Administrator'; isBuiltIn = $true; isPrivileged = $true; templateId = 'r-ga' }, @{ id = 'r-sec'; displayName = 'Security Administrator'; isBuiltIn = $true; isPrivileged = $true; templateId = 'r-sec' }); break }
            '^roleManagement/directory/roleAssignmentScheduleInstances' {
                if ($env:TKP_TEST_PIM -eq 'broken') { throw 'Request_BadRequest: Could not find a property named principal on type microsoft.graph.unifiedRoleAssignmentScheduleInstance.' }
                if ($env:TKP_TEST_PIM -ne 'ok') { throw 'Request_UnsupportedQuery: PIM is not licensed' }
                & $u @(
                    @{ roleDefinitionId = 'r-ga'; assignmentType = 'Assigned'; memberType = 'Direct'; directoryScopeId = '/'; principalId = 'u1'; principal = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Admin One'; userPrincipalName = 'admin1@contoso.example'; onPremisesSyncEnabled = $false } }
                    @{ roleDefinitionId = 'r-ga'; assignmentType = 'Assigned'; memberType = 'Direct'; directoryScopeId = '/'; principalId = 'u2'; principal = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Admin Two'; userPrincipalName = 'admin2@contoso.example'; onPremisesSyncEnabled = $true } }
                    @{ roleDefinitionId = 'r-ga'; assignmentType = 'Activated'; memberType = 'Direct'; directoryScopeId = '/'; principalId = 'u3'; principal = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Admin Three'; userPrincipalName = 'admin3@contoso.example' } }
                    # A role assigned to a group: User One holds it as a member, Admin One can join through PIM for Groups.
                    @{ roleDefinitionId = 'r-sec'; assignmentType = 'Assigned'; memberType = 'Direct'; directoryScopeId = '/'; principalId = 'grp-admins'; principal = @{ '@odata.type' = '#microsoft.graph.group'; displayName = 'Tier 0 Admins' } }
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
                @{ responses = @($reqs | ForEach-Object {
                            $request = $_
                            if ($request.url -like '*/authentication/requirements') { @{ id = $request.id; status = 200; body = @{ perUserMfaState = $(if ($request.url -like '*/u2/*') { 'enforced' } else { 'disabled' }) } } }
                            else {
                                # Any other request in a batch gets the answer the same request gets alone; a refusal becomes its status.
                                try { @{ id = $request.id; status = 200; body = (& $script:GraphRoute "https://graph.microsoft.com/v1.0$($request.url)" $null) } }
                                catch { @{ id = $request.id; status = 403; body = @{ error = @{ message = $_.Exception.Message } } } }
                            }
                        })
                }; break
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
                    @{ id = 'u1'; userPrincipalName = 'admin1@contoso.example'; displayName = 'Admin One'; accountEnabled = $true; userType = 'Member'; onPremisesSyncEnabled = $false; assignedLicenses = @(@{ skuId = 's1'; disabledPlans = @('p-intune') }) }
                    @{ id = 'u2'; userPrincipalName = 'admin2@contoso.example'; displayName = 'Admin Two'; accountEnabled = $true; userType = 'Member'; onPremisesSyncEnabled = $true; assignedLicenses = @() }
                    @{ id = 'u4'; userPrincipalName = 'old@contoso.example'; displayName = 'Old'; accountEnabled = $false; userType = 'Member'; assignedLicenses = @(@{ skuId = 's1' }) }
                    @{ id = 'g1'; userPrincipalName = 'guest_x#EXT#@contoso.example'; displayName = 'Guest'; accountEnabled = $true; userType = 'Guest'; externalUserState = 'PendingAcceptance'; assignedLicenses = @() }
                )
                break
            }
            '^identityGovernance/accessReviews/definitions' {
                & $u @(
                    @{ id = 'ar1'; displayName = 'Quarterly admin review'; status = 'InProgress'; scope = @{ '@odata.type' = '#microsoft.graph.accessReviewQueryScope'; query = '/roleManagement/directory/roleAssignmentScheduleInstances?$filter=roleDefinitionId eq ''r-ga'''; queryType = 'MicrosoftGraph' }; settings = @{ recurrence = @{ pattern = @{ type = 'absoluteMonthly'; interval = 3 } } } },
                    @{ id = 'ar2'; displayName = 'Guest review'; status = 'InProgress'; scope = @{ '@odata.type' = '#microsoft.graph.principalResourceMembershipsScope'; principalScopes = @(@{ query = '/users?$filter=(userType eq ''Guest'')' }); resourceScopes = @(@{ query = '/groups/g1' }) }; settings = @{ recurrence = @{ pattern = @{ type = 'weekly'; interval = 1 } } } },
                    @{ id = 'ar3'; displayName = 'One-off'; status = 'Completed'; scope = @{ query = '/groups/g2/members' }; settings = @{ recurrence = @{ pattern = $null } } }
                )
                break
            }
            '^identityGovernance/entitlementManagement/accessPackages' { & $u @(@{ id = 'pk1'; displayName = 'Vendor access'; isHidden = $false }); break }
            '^identityGovernance/entitlementManagement/catalogs' { & $u @(@{ id = 'cat1'; displayName = 'General'; state = 'published' }); break }
            '^identityGovernance/entitlementManagement/connectedOrganizations' { & $u @(); break }
            '^identityGovernance/lifecycleWorkflows/workflows' { & $u @(@{ id = 'wf1'; displayName = 'Leaver'; category = 'leaver'; isEnabled = $true; isSchedulingEnabled = $true }, @{ id = 'wf2'; displayName = 'Joiner draft'; category = 'joiner'; isEnabled = $false; isSchedulingEnabled = $false }); break }
            '^identityGovernance/privilegedAccess/group/eligibilitySchedules' { & $u @(@{ id = 'es1'; groupId = 'grp-admins'; accessId = 'member'; principalId = 'u1'; status = 'Provisioned'; memberType = 'Direct' }); break }
            '^directory/administrativeUnits' { & $u @(); break }
            '^security/runHuntingQuery$' {
                $q = [string](ConvertFrom-Json $Body).Query
                $hex = $(if ($q -match "startswith '([0-9a-f])'") { $Matches[1] } else { '' })
                # Each table is first asked how many rows every shard has: two devices in shard a, none elsewhere.
                if ($q -match 'summarize Count = count\(\) by Shard') { @{ results = @(@{ Shard = 'a'; Count = $(if ($env:TKP_DEF_SHORT) { 9 } elseif ($env:TKP_DEF_SPLIT) { 5 } else { 2 }) }) }; break }
                # A shard at the row cap, read again by the second character of the id: five devices under a1 and a2.
                if ($env:TKP_DEF_SPLIT -and $q -match "startswith '(a[0-9a-f])'") {
                    $two = $Matches[1]; $n = $(if ($two -eq 'a1') { 3 } elseif ($two -eq 'a2') { 2 } else { 0 })
                    @{ results = @(for ($k = 1; $k -le $n; $k++) { @{ DeviceId = "$two$k"; DeviceName = "PC-$two$k"; OSPlatform = 'Windows11'; OnboardingStatus = 'Onboarded'; SensorHealthState = 'Active'; ExposureLevel = 'Low'; AadDeviceId = "dev-$two$k"; AvMode = '0'; AvIsSignatureUpToDate = 'true' } }) }; break
                }
                switch -Regex ($q) {
                    '^DeviceInfo' { if ($hex -eq 'a') { @{ results = @(@{ DeviceId = 'a1'; DeviceName = 'PC-1'; OSPlatform = 'Windows11'; OnboardingStatus = 'Onboarded'; SensorHealthState = 'Active'; ExposureLevel = 'Medium'; AadDeviceId = 'dev-1'; Timestamp = '2026-10-13T00:00:00Z' }, @{ DeviceId = 'a2'; DeviceName = 'OLD-PC'; OSPlatform = 'Windows10'; OnboardingStatus = 'Onboarded'; SensorHealthState = 'Inactive'; ExposureLevel = 'High'; AadDeviceId = 'dev-2'; Timestamp = '2026-10-01T00:00:00Z' }) } } else { @{ results = @() } }; break }
                    '^DeviceTvmInfoGathering' { if ($hex -eq 'a') { @{ results = @(@{ DeviceId = 'a1'; DeviceName = 'PC-1'; OSPlatform = 'Windows11'; AvMode = '0'; AvIsSignatureUpToDate = 'true' }, @{ DeviceId = 'a2'; DeviceName = 'OLD-PC'; OSPlatform = 'Windows10'; AvMode = '1'; AvIsSignatureUpToDate = 'false' }) } } else { @{ results = @() } }; break }
                    '^DeviceTvmSecureConfigurationAssessment' { @{ results = @(@{ ConfigurationId = 'scid-1'; ConfigurationName = 'Block executable content from email client and webmail'; ConfigurationCategory = 'Security controls'; ConfigurationSubcategory = 'Attack Surface Reduction'; ConfigurationImpact = 8; Devices = 2; Compliant = 1 }, @{ ConfigurationId = 'scid-2'; ConfigurationName = 'Turn on Tamper Protection'; ConfigurationCategory = 'Security controls'; ConfigurationSubcategory = 'Antivirus'; ConfigurationImpact = 9; Devices = 2; Compliant = 2 }) }; break }
                    '^DeviceTvmSoftwareVulnerabilities.*summarize Devices = dcount\(DeviceId\), Cves' { @{ results = @(@{ Devices = 1; Cves = 2; CvesOver30d = 1; DevicesOver30d = 1 }) }; break }
                    '^DeviceTvmSoftwareVulnerabilities' { @{ results = @(@{ CveId = 'CVE-2026-0001'; SoftwareName = 'Reader'; SoftwareVendor = 'Vendor'; CvssScore = 9.8; PublishedDate = '2026-08-01T00:00:00Z'; Devices = 1 }) }; break }
                    default { throw "No hunting answer for $q" }
                }
                break
            }
            '^security/incidents' { & $u @(@{ id = 'i1'; displayName = 'Suspicious sign-in'; severity = 'medium'; status = 'active'; assignedTo = $null; createdDateTime = [datetime]::UtcNow.AddDays(-20).ToString('yyyy-MM-ddTHH:mm:ssZ') }, @{ id = 'i2'; displayName = 'Malware'; severity = 'high'; status = 'active'; assignedTo = 'soc@contoso.example'; createdDateTime = [datetime]::UtcNow.AddDays(-40).ToString('yyyy-MM-ddTHH:mm:ssZ') }); break }
            '^security/secureScores' { & $u @(@{ id = 's1'; createdDateTime = '2026-10-13T00:00:00Z'; currentScore = 412.5; maxScore = 900; licensedUserCount = 12; activeUserCount = 10; averageComparativeScores = @(@{ basis = 'AllTenants'; averageScore = 390 }); controlScores = @(@{ controlCategory = 'Identity'; score = 200 }, @{ controlCategory = 'Device'; score = 100 }, @{ controlCategory = 'Identity'; score = 12.5 }) }); break }
            '^security/secureScoreControlProfiles' { & $u @(@{ id = 'MFARegistrationV2'; title = 'Ensure all users can complete MFA'; controlCategory = 'Identity'; maxScore = 9; implementationCost = 'Low'; userImpact = 'Low'; actionType = 'Config'; tier = 'Core'; rank = 1; deprecated = $false; controlStateUpdates = @(@{ state = 'Default' }, @{ state = 'ThirdParty' }); remediation = 'Register everyone.' }, @{ id = 'Old'; title = 'Retired'; deprecated = $true; controlStateUpdates = @() }); break }
            '^groupLifecyclePolicies' { & $u @(@{ id = 'lc1'; groupLifetimeInDays = 180; managedGroupTypes = 'All'; alternateNotificationEmails = 'it@contoso.example' }); break }
            '^groups\?\$filter=groupTypes' { & $u @(@{ id = 'grp1'; displayName = 'All Staff'; createdDateTime = '2024-01-01T00:00:00Z'; visibility = 'Private'; owners = @(@{ id = 'u1' }) }, @{ id = 'grp9'; displayName = 'Orphaned Project'; createdDateTime = '2023-05-01T00:00:00Z'; visibility = 'Private'; owners = @() }); break }
            '^groups\?' { & $u @(@{ id = 'grp1'; displayName = 'All Staff'; groupTypes = @('Unified'); mailEnabled = $true; securityEnabled = $false }, @{ id = 'grp2'; displayName = 'Dyn'; groupTypes = @('DynamicMembership'); mailEnabled = $false; securityEnabled = $true; membershipRule = 'user.department -eq "x"' }, @{ id = 'grp3'; displayName = 'Sec'; groupTypes = @(); mailEnabled = $false; securityEnabled = $true; isAssignableToRole = $true }, @{ id = 'grp4'; displayName = 'Synced Staff'; groupTypes = @(); mailEnabled = $false; securityEnabled = $true; onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = 'S-1-5-21-1-2-3-1101'; assignedLicenses = @(@{ skuId = 'x' }) }, @{ id = 'grp5'; displayName = 'Moved From AD'; groupTypes = @(); mailEnabled = $false; securityEnabled = $true; onPremisesSecurityIdentifier = 'S-1-5-21-1-2-3-1102' }); break }
            '^groups/grp-admins/transitiveMembers/microsoft\.graph\.user' {
                if ($env:TKP_TEST_ROLEGROUP -eq 'denied') { throw 'Authorization_RequestDenied: Insufficient privileges to complete the operation.' }
                & $u @(@{ id = 'u5'; userPrincipalName = 'user1@contoso.example'; displayName = 'User One'; accountEnabled = $true; onPremisesSyncEnabled = $false }); break
            }
            '^directoryObjects/u1$' { @{ '@odata.type' = '#microsoft.graph.user'; id = 'u1'; displayName = 'Admin One'; userPrincipalName = 'admin1@contoso.example'; onPremisesSyncEnabled = $false }; break }
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
                    @{ id = 'm2'; deviceName = 'OLD-PC'; userPrincipalName = 'user1@contoso.example'; operatingSystem = 'Windows'; osVersion = '10.0.19045.1'; complianceState = 'noncompliant'; managementAgent = 'configurationManagerClientMdm'; configurationManagerClientEnabledFeatures = @{ compliancePolicy = $true; deviceConfiguration = $true; windowsUpdateForBusiness = $false; endpointProtection = $false; inventory = $false; modernApps = $false; officeApps = $false; resourceAccess = $true }; joinType = 'hybridAzureADJoined'; autopilotEnrolled = $false; isEncrypted = $false; azureADDeviceId = 'dev-2' },
                    @{ id = 'm3'; deviceName = 'MAC-1'; userPrincipalName = 'user1@contoso.example'; operatingSystem = 'macOS'; osVersion = '15.1'; complianceState = 'compliant'; managementAgent = 'mdm'; joinType = 'azureADRegistered'; autopilotEnrolled = $false; isEncrypted = $true; azureADDeviceId = 'dev-3' }
                ); break
            }
            '^deviceManagement/windowsAutopilotDeviceIdentities' { & $u @(@{ serialNumber = 'SN1'; manufacturer = 'Dell'; model = 'Latitude'; enrollmentState = 'enrolled'; managedDeviceId = 'm1' }); break }
            '^deviceManagement/deviceCompliancePolicies' { & $u @(@{ id = 'cp1'; displayName = 'Windows compliance'; '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; bitLockerEnabled = $true; deviceThreatProtectionEnabled = $true; deviceThreatProtectionRequiredSecurityLevel = 'low'; assignments = @(@{ id = 'a1' }) }, @{ id = 'cp2'; displayName = 'iOS compliance'; '@odata.type' = '#microsoft.graph.iosCompliancePolicy'; securityBlockJailbrokenDevices = $true; passcodeRequired = $true; scheduledActionsForRule = @(@{ ruleName = 'x' }); assignments = @(@{ id = 'a1' }) }); break }
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
            '^deviceManagement/depOnboardingSettings' { & $u @(@{ id = 'dep1'; tokenName = 'Apple Business Manager'; appleIdentifier = 'apple@contoso.example'; tokenType = 'dep'; tokenExpirationDateTime = '2027-03-01T00:00:00Z'; lastSuccessfulSyncDateTime = '2026-10-13T00:00:00Z'; lastSyncErrorCode = 0 }); break }
            '^deviceManagement/ndesConnectors' { & $u @(@{ id = 'c1'; displayName = 'Certificate Connector'; machineName = 'PKI01'; state = 'active'; lastConnectionDateTime = [datetime]::UtcNow.AddHours(-2).ToString('o'); connectorVersion = '6.2406.0.1001' }, @{ id = 'c2'; displayName = 'Certificate Connector'; machineName = 'PKI02'; state = 'inactive'; lastConnectionDateTime = [datetime]::UtcNow.AddDays(-12.5).ToString('o') }, @{ id = 'c3'; displayName = 'Certificate Connector'; machineName = 'PKI03'; state = 'none' }); break }
            '^directory/subscriptions' { & $u @(@{ id = 'sub1'; skuPartNumber = 'SPB'; skuId = 's1'; status = 'Enabled'; isTrial = $false; totalLicenses = 12; createdDateTime = '2024-01-01T00:00:00Z'; nextLifecycleDateTime = '2027-01-01T00:00:00Z' }, @{ id = 'sub2'; skuPartNumber = 'TEAMS_PREMIUM'; skuId = 's2'; status = 'Warning'; isTrial = $true; totalLicenses = 25; nextLifecycleDateTime = '2026-11-01T00:00:00Z' }); break }
            '^reports/servicePrincipalSignInActivities' {
                & $u @(
                    @{ id = 'a1'; appId = 'app-1'; lastSignInActivity = @{ lastSignInDateTime = '2026-10-01T00:00:00Z' }; applicationAuthenticationClientSignInActivity = @{ lastSignInDateTime = '2026-10-12T08:00:00Z' }; delegatedClientSignInActivity = @{ lastSignInDateTime = $null } }
                    @{ id = 'a2'; appId = 'app-2'; lastSignInActivity = @{} }
                ); break
            }
            '^deviceAppManagement/vppTokens' { & $u @(@{ organizationName = 'Contoso'; appleId = 'apple@contoso.example'; state = 'valid'; expirationDateTime = '2027-06-01T00:00:00Z' }); break }
            '^deviceManagement/deviceEnrollmentConfigurations' { & $u @(@{ id = 'er1'; displayName = 'All users and all devices'; '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'; priority = 0; windowsRestriction = @{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $true }; macOSRestriction = @{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $false }; assignments = @() }, @{ id = 'whfb'; displayName = 'All users and all devices'; '@odata.type' = '#microsoft.graph.windowsHelloForBusinessConfiguration'; priority = 0; state = 'enabled'; pinMinimumLength = 6; securityDeviceRequired = $true; unlockWithBiometricsEnabled = $true; assignments = @() }); break }
            '^deviceManagement/complianceManagementPartners' { & $u @(@{ id = 'jamf'; displayName = 'Jamf'; partnerState = 'enabled'; lastHeartbeatDateTime = '2026-10-13T00:00:00Z'; macOsOnboarded = $true; iosOnboarded = $false; macOsEnrollmentAssignments = @(@{ target = @{ groupId = 'g1' } }) }); break }
            '^deviceManagement/deviceManagementPartners' { & $u @(); break }
            '^deviceManagement/mobileThreatDefenseConnectors' { & $u @(@{ id = 'mde'; partnerState = 'available'; windowsEnabled = $true; macEnabled = $true; lastHeartbeatDateTime = '2026-10-13T00:00:00Z' }); break }
            '^deviceManagement/managedDeviceCleanupRules' { & $u @(@{ id = 'r1'; displayName = 'Windows 90d'; deviceCleanupRulePlatformType = 'windows'; deviceInactivityBeforeRetirementInDays = 90 }); break }
            '^informationProtection/bitlocker/recoveryKeys' { & $u @(@{ id = 'k1'; deviceId = 'dev-1'; volumeType = 'operatingSystemVolume' }, @{ id = 'k2'; deviceId = 'dev-1'; volumeType = 'fixedDataVolume' }); break }
            '^identity/conditionalAccess/policies$' { & $u @(); break }
            '^identity/conditionalAccess/namedLocations$' { & $u @(); break }
            '^identity/conditionalAccess/authenticationContextClassReferences$' { & $u @(); break }
            default { throw "Unexpected Graph call in test: $path" }
        }
    }
    # The body by its bound parameter: a GET binds none, and under strict mode (another test file may leave it on)
    # reading $Body itself would throw.
    # Every request is noted, so a test can say what a collection asked for and what it did not.
    $script:GraphAsked = [System.Collections.Generic.List[string]]::new()
    Mock -ModuleName TenantKeep.Posture Invoke-MgGraphRequest { $script:GraphAsked.Add([string]$Uri); & $script:GraphRoute $Uri $PesterBoundParameters['Body'] }
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
            $script:R.Collectors | Should -Be @('ConditionalAccess', 'Entra', 'SignIns', 'Intune', 'Defender')
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
            ($m | Where-Object DeviceName -eq 'OLD-PC').IntuneWorkloads | Should -Be 'compliancePolicy;deviceConfiguration;resourceAccess' -Because 'a co-managed device records which workloads Intune holds'
            ($m | Where-Object DeviceName -eq 'LAPTOP-1').IntuneWorkloads | Should -BeNullOrEmpty
            $co = & $script:Read '09-intune-comanagement'
            $co.CoManagedDevices | Should -Be 1
            ($co.Workloads | Where-Object Name -eq 'compliancePolicy').OnIntune | Should -Be 1
            ($co.Workloads | Where-Object Name -eq 'endpointProtection').OnIntune | Should -Be 0
            $partner = @(& $script:Read '09-intune-compliance-partners')[0]
            $partner.DisplayName | Should -Be 'Jamf'
            $partner.MacOsOnboarded | Should -BeTrue
            $partner.MacOsAssignments | Should -Be 1
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
            '{ "version": 1, "identityModel": "cloud-only", "platforms": ["windows", "macOS", "iOS"], "byod": "mam", "licenses": ["BusinessPremium", "Intune", "MDEBusiness", "MDE2", "E5"] }' | Set-Content -LiteralPath $profilePath
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
            $by['EP-019'].status | Should -Be 'fail' -Because 'MAC-1 has no onboarded Defender record'
            $by['EP-020'].status | Should -Be 'fail' -Because 'OLD-PC sensor is inactive'
            $by['EP-021'].status | Should -Be 'fail' -Because 'OLD-PC is in passive mode'
            $by['EP-022'].status | Should -Be 'fail' -Because 'the ASR rule is at 50%'
            $by['EP-023'].status | Should -Be 'pass'
            $by['EP-024'].status | Should -Be 'fail'
            $by['EP-025'].status | Should -Be 'fail'
            $by['EP-018'].status | Should -Be 'pass' -Because 'iOS has an assigned app protection policy and jailbreak detection; Android is out of scope'
        }

        It 'writes everyone who holds a role: directly, as eligible, as a member of a group that does, and as someone who can join it' {
            $h = @(& $script:Read '04-role-holders')
            $how = @($h | ForEach-Object { "$($_.UserPrincipalName)|$($_.Role)|$($_.Held)|$($_.Membership)|$($_.GroupName)" })
            $how | Should -Be @(
                'admin1@contoso.example|Global Administrator|Direct||'
                'admin2@contoso.example|Global Administrator|Direct||'
                'admin3@contoso.example|Global Administrator|Direct||'
                'user1@contoso.example|Security Administrator|Group|Member|Tier 0 Admins'
                'admin1@contoso.example|Security Administrator|EligibleGroup|EligibleMember|Tier 0 Admins'
                'admin3@contoso.example|Security Administrator|Eligible||'
            )
            ($h | Where-Object { $_.Held -eq 'Direct' -and $_.UserPrincipalName -eq 'admin3@contoso.example' }).AssignmentType | Should -Be 'Activated'
            $s = & $script:Read '04-role-holders-summary'
            $s.Holders | Should -Be 4
            $s.Direct | Should -Be 3
            $s.ThroughGroup | Should -Be 1
            $s.EligibleOnly | Should -Be 0
            $s.GroupsHoldingRoles | Should -Be 1
            $s.GroupsRead | Should -Be 1
            @($s.GroupsNotRead).Count | Should -Be 0
        }

        It 'counts the person who holds a role through a group among the administrators' {
            @(& $script:Read '05-auth-registration-admins' | ForEach-Object { $_.UserPrincipalName }) | Should -Be @('admin1@contoso.example', 'admin2@contoso.example', 'user1@contoso.example') -Because 'User One is in the group that holds Security Administrator'
        }

        It 'asks Identity Protection for the users at risk now, not for everyone who ever was' {
            @($script:R.Errors | Where-Object { $_ -like "Risky users ::*riskyUsers*riskState eq 'atRisk'*" }).Count | Should -Be 1 -Because 'the synthetic tenant refuses the read, and the refusal names the request'
        }

        It 'reads PIM for Groups for every role-assignable group in one batch' {
            Should -Invoke -ModuleName TenantKeep.Posture Invoke-MgGraphRequest -Times 1 -Exactly -Scope Context -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/$batch' -and $Method -eq 'POST' -and ([string]$Body -match 'eligibilitySchedules') }
            (& $script:Read 'gov-04-pim-groups-summary').GroupsRead | Should -Be (& $script:Read 'gov-04-pim-groups-summary').RoleAssignableGroups
        }

        It 'collects the governance reads: reviews with their scope queries, packages, workflows, PIM groups, administrative units' {
            $ar = @(& $script:Read 'gov-01-access-reviews')
            $ar.Count | Should -Be 3
            @($ar | Where-Object { $_.Id -eq 'ar2' })[0].ScopeQuery | Should -Match "userType eq 'Guest'"
            @($ar | Where-Object { $_.Id -eq 'ar2' })[0].ScopeQuery | Should -Match '/groups/g1'
            @($ar | Where-Object { $_.Id -eq 'ar3' })[0].Recurring | Should -BeFalse
            (& $script:Read 'gov-02-access-packages-summary').Packages | Should -Be 1
            @(& $script:Read 'gov-03-lifecycle-workflows' | Where-Object { $_.IsEnabled }).Category | Should -Be 'leaver'
            (& $script:Read 'gov-04-pim-groups-summary').Groups | Should -Be 1
            @(& $script:Read 'gov-05-administrative-units').Count | Should -Be 0
            @(& $script:Read '10-service-principals')[0].PSObject.Properties['OwnerCount'] | Should -Not -BeNullOrEmpty
        }

        It 'feeds the governance checks from the same folder' {
            $run = Invoke-PostureChecks -Evidence $script:R.Folder -Domain governance -PassThru
            $by = @{}; foreach ($r in $run.results) { $by[$r.id] = $r }
            $by['GV-002'].status | Should -Be 'pass' -Because 'a recurring review targets role assignments'
            $by['GV-003'].status | Should -Be 'pass'
            $by['GV-004'].status | Should -Be 'pass'
            $by['GV-005'].status | Should -Be 'fail' -Because 'the joiner workflow is disabled'
            $by['GV-009'].status | Should -Be 'pass' -Because 'under the scale threshold'
            $by['GV-010'].status | Should -Be 'fail' -Because 'the listed enterprise app has no owners'
            $by['GV-010'].affectedCount | Should -Be 1
        }

        It 'reads the subscriptions with their state, and when each application last signed in' {
            $subs = @(& $script:Read '01-subscriptions')
            @($subs | ForEach-Object { "$($_.SkuPartNumber) $($_.Status) trial=$($_.IsTrial)" }) | Should -Be @('SPB Enabled trial=False', 'TEAMS_PREMIUM Warning trial=True')
            $subs[1].TotalLicenses | Should -Be 25
            $activity = @(Import-Csv (Join-Path $script:R.Folder '10-app-signin-activity.csv'))
            $activity.Count | Should -Be 2
            ($activity | Where-Object AppId -eq 'app-1').LastSignIn | Should -Match '^2026-10-12T08:00:00' -Because 'the latest of the kinds of sign-in is the last sign-in'
            ($activity | Where-Object AppId -eq 'app-2').LastSignIn | Should -BeNullOrEmpty
            @($script:GraphAsked | Where-Object { $_ -match '/beta/reports/servicePrincipalSignInActivities' }).Count | Should -BeGreaterOrEqual 1 -Because 'the report is beta only'
            @($script:GraphAsked | Where-Object { $_ -match '/v1\.0/directory/subscriptions' }).Count | Should -BeGreaterOrEqual 1
        }

        It 'reads the Apple enrollment tokens and the certificate connectors, with how long each had been silent at the read' {
            $ade = @(& $script:Read '09-apple-ade-tokens')
            $ade[0].TokenName | Should -Be 'Apple Business Manager'
            ([datetime]$ade[0].TokenExpirationDateTime).ToUniversalTime().ToString('yyyy-MM-dd') | Should -Be '2027-03-01'
            $connectors = @(& $script:Read '09-certificate-connectors')
            @($connectors | ForEach-Object { "$($_.MachineName) $($_.State) $($_.DaysSinceLastConnection)" }) | Should -Be @('PKI01 active 0', 'PKI02 inactive 12', 'PKI03 none ')
            @($script:GraphAsked | Where-Object { $_ -match '/beta/deviceManagement/(depOnboardingSettings|ndesConnectors)' }).Count | Should -BeGreaterOrEqual 2
        }

        It 'keeps a day-by-day history of Secure Score beside the latest score' {
            $history = @(& $script:Read 'def-06-secure-score-history')
            $history.Count | Should -Be 1 -Because 'the synthetic tenant has one day'
            $history[0].CurrentScore | Should -Be 412.5
            $history[0].MaxScore | Should -Be 900
            @($script:GraphAsked | Where-Object { $_ -match 'security/secureScores\?\$top=90' }).Count | Should -BeGreaterOrEqual 1
        }

        It 'collects Defender effective state: sharded hunting answers, incidents and Secure Score' {
            $script:Result = $script:R
            $d = @(& $script:Read 'def-01-devices')
            $d.Count | Should -Be 2
            (& $script:Read 'def-01-devices-summary').Onboarded | Should -Be 2
            (& $script:Read 'def-01-devices-summary').RowsExpected | Should -Be 2
            (& $script:Read 'def-01-devices-summary').Truncated | Should -BeFalse -Because 'every shard returned as many rows as it said it has'
            (& $script:Read 'def-02-av-state-summary').Truncated | Should -BeFalse
            (& $script:Read 'def-02-av-state-summary').SignatureOutOfDate | Should -Be 1
            @(& $script:Read 'def-03-secure-config' | Where-Object { $_.ConfigurationId -eq 'scid-1' })[0].CompliantPct | Should -Be 50
            (& $script:Read 'def-04-vulnerabilities-summary').CriticalCvesOver30d | Should -Be 1
            (& $script:Read 'def-05-incidents-summary').OpenOver7DaysUnassigned | Should -Be 1
            $wk = & $script:Read 'def-05-incidents-weekly'
            $wk.Incidents | Should -Be 2
            [int](@($wk.Weeks | ForEach-Object { $_.Medium }) | Measure-Object -Sum).Sum | Should -Be 1
            [int](@($wk.Weeks | ForEach-Object { $_.High }) | Measure-Object -Sum).Sum | Should -Be 1
            @($wk.Weeks | Where-Object { ([datetime]$_.WeekStart).DayOfWeek -ne 'Monday' }).Count | Should -Be 0 -Because 'weeks start on Monday'
            $ss = & $script:Read 'def-06-secure-score'
            $ss.CurrentScore | Should -Be 412.5
            $ss.ByCategory.Identity | Should -Be 212.5
            @(& $script:Read 'def-06-secure-score-controls').Count | Should -Be 1 -Because 'deprecated profiles are left out'
            @(& $script:Read 'def-06-secure-score-controls')[0].State | Should -Be 'ThirdParty' -Because 'the latest state update wins'
            Should -Invoke -ModuleName TenantKeep.Posture Invoke-MgGraphRequest -Times 34 -Exactly -Scope Context -ParameterFilter { $Uri -like '*runHuntingQuery' -and $Method -eq 'POST' -and ([string]$Body -match 'DeviceInfo|DeviceTvmInfoGathering') } -Because 'two device tables, each one count by shard and then sixteen shards'
        }

        It 'records the verified domains with their authentication type' {
            @(& $script:Read '01-domains')[0].AuthenticationType | Should -Be 'Managed'
        }

        It 'records the group expiration policy and the ownerless Microsoft 365 groups' {
            (& $script:Read '02-group-lifecycle-policy').ManagedGroupTypes | Should -Be 'All'
            $o = @(& $script:Read '07-groups-ownerless')
            $o.Count | Should -Be 1
            $o[0].DisplayName | Should -Be 'Orphaned Project'
            (& $script:Read '07-groups-ownerless-summary').UnifiedGroups | Should -Be 2
        }

        It 'flattens roles with names and counts permanent Global Administrators' {
            $a = & $script:Read '04-role-assignments-active'
            $a.Count | Should -Be 4
            ($a | Where-Object PrincipalType -eq 'group').PrincipalName | Should -Be 'Tier 0 Admins'
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
            Should -Invoke -ModuleName TenantKeep.Posture Invoke-MgGraphRequest -Times 1 -Exactly -Scope Context -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/beta/$batch' -and $Method -eq 'POST' -and ([string]$Body -match 'authentication/requirements') } -Because 'authentication/requirements exists only in beta'
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
            $ds = @(& $script:Read '02-directory-settings')[0]
            $ds.Values.BannedPasswordCount | Should -Be 3
            (& $script:Read '02-auth-system-preferred').State | Should -Be 'enabled' -Because 'the beta policy is read whole, without the $select Graph refused'
            ($ds | ConvertTo-Json -Depth 5) | Should -Not -Match 'seattle' -Because 'the banned words are the organisation''s own names; only the count is kept'
            $lp = & $script:Read '06-users-license-plans'
            $lp.LicensedEnabledUsers | Should -Be 1 -Because 'the disabled user does not count'
            $lp.UsersByServicePlan.AAD_PREMIUM | Should -Be 1
            $lp.UsersByServicePlan.PSObject.Properties.Name | Should -Not -Contain 'INTUNE_A' -Because 'Intune is switched off on that licence'
            $s.EnabledNeverSignedIn | Should -Be 2 -Because 'without sign-in data every enabled member looks never signed in'
        }

        It 'classifies groups and flags expired app credentials' {
            $g = & $script:Read '07-groups'
            @($g | ForEach-Object { $_.Kind }) | Should -Be @('M365', 'DynamicSecurity', 'Security', 'Security', 'Security')
            ($g | Where-Object DisplayName -eq 'Dyn').Dynamic | Should -BeTrue
            @($g | ForEach-Object { $_.Source }) | Should -Be @('Cloud', 'Cloud', 'Cloud', 'ActiveDirectory', 'EntraFromAD') -Because 'sync on is AD; sync empty with an AD identifier is a group whose source of authority moved to Entra'
            ($g | Where-Object DisplayName -eq 'Synced Staff').Licensed | Should -BeTrue
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
            $m.collectors | Should -Be @('ConditionalAccess', 'Entra', 'SignIns', 'Intune', 'Defender')
            $m.graphApiVersions | Should -Be @('beta', 'v1.0') -Because 'the per-user MFA batch is the one beta call'
            $m.files | Should -Contain '06-users.csv'
            $m.errorCount | Should -Be 1
            $m.powerShell | Should -Be $PSVersionTable.PSVersion.ToString()
            $m.os | Should -Not -BeNullOrEmpty
            @($m.modules.PSObject.Properties.Name) | Should -Contain 'Microsoft.Graph.Authentication' -Because 'the run records every service module version, null when not installed'
            @($m.modules.PSObject.Properties.Name) | Should -Contain 'ExchangeOnlineManagement'
            $meta = & $script:Read 'metadata'
            $meta.snapshotType | Should -Be 'conditional-access'
            @($meta.modules.PSObject.Properties.Name) | Should -Contain 'Microsoft.Graph.Authentication'
        }

        It 'warns about optional scopes that are missing' {
            @($script:W | Where-Object { $_ -like '*IdentityRiskyUser.Read.All*' }).Count | Should -Be 1
        }

        It 'feeds the CA and devices checks from the same folder' {
            $r = Invoke-PostureChecks -Evidence $script:R.Folder -Domain ca, devices -PassThru
            $r.results.Count | Should -Be 40
            $d = @{}; foreach ($x in $r.results) { $d[$x.id] = $x }
            $d['DEV-005'].status | Should -Be 'fail' -Because 'OLD-PC has no BitLocker key'
            $d['DEV-007'].status | Should -Be 'fail' -Because 'OLD-PC is Windows 10'
            $d['DEV-009'].status | Should -Be 'pass'
            $d['DEV-010'].status | Should -Be 'fail' -Because 'firewall is unassigned and ASR and EDR are missing'
            $d['DEV-010'].affected.name | Should -Be @('firewall', 'attackSurfaceReduction', 'endpointDetectionAndResponse')
            $d['DEV-011'].status | Should -Be 'pass'
            $d['DEV-012'].status | Should -Be 'pass'
            $d['DEV-013'].status | Should -Be 'pass'
            $d['DEV-015'].status | Should -Be 'fail' -Because 'the iOS policy does not ask Defender for a risk level'
            $d['DEV-015'].affected.name | Should -Be @('iOS')
            $d['DEV-017'].status | Should -Be 'fail' -Because 'secureByDefault is off: a device with no policy reports compliant'
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

    Context 'the role read fails for a reason that is not a refusal or a licence' {
        It 'fails the step with its cause, and does not fall back to a list without the eligible assignments' {
            # An error is not "this tenant has no PIM": falling back would write the roles without the eligible ones
            # and every check on them would read a tenant with none.
            $env:TKP_TEST_PIM = 'broken'
            try {
                $r = Invoke-PostureCollection -OutputFolder (Join-Path $script:Root 'pimbroken') -Collector Entra -SkipCaSnapshot -SkipPerUserMfa -PassThru -WarningAction SilentlyContinue
                @($r.Errors | Where-Object { $_ -like 'Role assignments :: Request_BadRequest*' }).Count | Should -Be 1
                Join-Path $r.Folder '04-role-assignments-active.json' | Should -Not -Exist
                Join-Path $r.Folder '04-role-assignments-summary.json' | Should -Not -Exist
                Join-Path $r.Folder '04-role-holders.json' | Should -Not -Exist -Because 'there are no assignments to open'
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

    Context 'Defender returns fewer rows than it has' {
        It 'records the short read in the summaries, and the checks on those lists have no answer' {
            # The count by shard says nine devices; the shards return two.
            $env:TKP_DEF_SHORT = '1'
            try { $r = Invoke-PostureCollection -OutputFolder (Join-Path $script:Root 'defshort') -Collector Intune, Defender -SkipCaSnapshot -PassThru -WarningAction SilentlyContinue }
            finally { Remove-Item Env:TKP_DEF_SHORT -ErrorAction SilentlyContinue }
            $summary = Get-Content -Raw (Join-Path $r.Folder 'def-01-devices-summary.json') | ConvertFrom-Json
            $summary.Truncated | Should -BeTrue
            $summary.RowsExpected | Should -Be 9
            $summary.RowsRead | Should -Be 2
            (Get-Content -Raw (Join-Path $r.Folder 'def-02-av-state-summary.json') | ConvertFrom-Json).Truncated | Should -BeTrue

            $profilePath = Join-Path $script:Root 'defshort-profile.json'
            '{ "version": 1, "identityModel": "cloud-only", "platforms": ["windows", "macOS", "iOS"], "byod": "mam", "licenses": ["BusinessPremium", "Intune", "MDEBusiness", "MDE2", "E5"] }' | Set-Content -LiteralPath $profilePath
            $run = Invoke-PostureChecks -Evidence $r.Folder -Domain endpoint -ProfilePath $profilePath -OutputPath (Join-Path $script:Root 'defshort-checks') -PassThru
            $by = @{}; foreach ($x in $run.results) { $by[$x.id] = $x }
            foreach ($id in 'EP-019', 'EP-020', 'EP-021') {
                $by[$id].status | Should -Be 'notEvaluated' -Because "$id would count devices over a list that is cut short"
                $by[$id].reason | Should -Match 'Defender returned 2 of 9 device rows'
            }
        }
    }

    Context 'a group that holds a role cannot be opened' {
        It 'keeps everyone it could read, names the group in the summary, and logs the step as failed' {
            $env:TKP_TEST_ROLEGROUP = 'denied'
            try { $r = Invoke-PostureCollection -OutputFolder (Join-Path $script:Root 'rolegroup') -Collector Entra -SkipCaSnapshot -SkipPerUserMfa -PassThru -WarningAction SilentlyContinue }
            finally { Remove-Item Env:TKP_TEST_ROLEGROUP -ErrorAction SilentlyContinue }
            $s = Get-Content -Raw (Join-Path $r.Folder '04-role-holders-summary.json') | ConvertFrom-Json
            @($s.GroupsNotRead) | Should -Be @('Tier 0 Admins')
            $s.GroupsRead | Should -Be 0
            @(Get-Content -Raw (Join-Path $r.Folder '04-role-holders.json') | ConvertFrom-Json).Count | Should -Be 4 -Because 'the people the assignments name are still written'
            @($r.Errors | Where-Object { $_ -like 'Role holders ::*members of 1 group(s) that hold a role could not be read*' }).Count | Should -Be 1

            # The checks that count administrators say what they could not see.
            $run = Invoke-PostureChecks -Evidence $r.Folder -Domain auth, identity -PassThru
            $by = @{}; foreach ($x in $run.results) { $by[$x.id] = $x }
            $by['AU-008'].status | Should -Be 'fail' -Because 'Admin Two has nothing registered, whatever the group holds'
            $by['AU-008'].reason | Should -Match 'the members of 1 group\(s\) that hold a role were not read \(Tier 0 Admins\)'
            $by['ID-003'].status | Should -Be 'fail' -Because 'Admin Two is synced'
            $by['ID-003'].reason | Should -Match 'Judged on the role holders that were read'
            $by['ID-001'].status | Should -Be 'pass' -Because 'the group holds Security Administrator, not Global Administrator: the count is whole'
            # The synthetic tenant answers the methods policy without its methods: that is no answer, not "every method off".
            $by['AU-001'].status | Should -Be 'notEvaluated'
            $by['AU-001'].reason | Should -Match 'lists no authentication methods'
        }
    }

    Context 'a Defender shard at the row cap' {
        It 'reads the shard again in sixteen parts and has the whole list' {
            # The count says five devices under a; one query for a returns two (the cap); a1 and a2 return three and two.
            $env:TKP_DEF_SPLIT = '1'
            try { $r = Invoke-PostureCollection -OutputFolder (Join-Path $script:Root 'defsplit') -Collector Defender -SkipCaSnapshot -PassThru -WarningAction SilentlyContinue }
            finally { Remove-Item Env:TKP_DEF_SPLIT -ErrorAction SilentlyContinue }
            $summary = Get-Content -Raw (Join-Path $r.Folder 'def-01-devices-summary.json') | ConvertFrom-Json
            $summary.Truncated | Should -BeFalse -Because 'the sixteen parts returned every row the shard has'
            $summary.RowsExpected | Should -Be 5
            $summary.RowsRead | Should -Be 5
            $summary.Devices | Should -Be 5
            @(Import-Csv -LiteralPath (Join-Path $r.Folder 'def-01-devices.csv') | ForEach-Object { $_.DeviceId }) | Should -Be @('a11', 'a12', 'a13', 'a21', 'a22')
            (Get-Content -Raw (Join-Path $r.Folder 'def-02-av-state-summary.json') | ConvertFrom-Json).Truncated | Should -BeFalse
        }
    }

    Context 'collected again into the same folder' {
        BeforeAll {
            $env:TKP_TEST_PIM = 'ok'
            $script:Again = Join-Path $script:Root 'again'
            $script:Collect = { $script:GraphAsked.Clear(); Invoke-PostureCollection -Collector Entra, Intune -SkipCaSnapshot -OutputFolder $script:Again -PassThru -WarningAction SilentlyContinue 6>$null }
            $script:Long = '/users\?\$select|userRegistrationDetails|/groups\?\$select|/devices\?\$select|deviceManagement/managedDevices\?'
            $script:First = & $script:Collect
            $script:FirstAsked = @($script:GraphAsked)
            $script:Hashes = @{}; foreach ($n in '06-users', '05-auth-registration', '07-groups', '08-entra-devices', '09-intune-managed-devices', '05-per-user-mfa') { $script:Hashes[$n] = (Get-FileHash (Join-Path $script:Again "$n.json")).Hash }
            $script:Second = & $script:Collect
            $script:SecondAsked = @($script:GraphAsked)
        }

        It 'reads the long lists once: the second collection keeps them and asks only for the rest' {
            @($script:FirstAsked | Where-Object { $_ -match $script:Long }).Count | Should -BeGreaterOrEqual 5
            @($script:SecondAsked | Where-Object { $_ -match $script:Long }) | Should -BeNullOrEmpty -Because 'users, registration, groups and both device lists finished in this run'
            @($script:SecondAsked | Where-Object { $_ -match '/organization\?' }).Count | Should -Be 1 -Because 'the short steps run again'
            foreach ($n in $script:Hashes.get_Keys()) { (Get-FileHash (Join-Path $script:Again "$n.json")).Hash | Should -Be $script:Hashes[$n] -Because "$n is the file the first collection wrote" }
            @($script:Second.Files | Where-Object { $_ -match '06-users\.json$' }).Count | Should -Be 1 -Because 'a kept list is still one of the files the collection reports'
        }

        It 'says in the journal which steps were kept, and still counts them as done' {
            $kept = @(Get-Content (Join-Path $script:Again 'journal.jsonl') | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.kind -eq 'step' -and $_.state -eq 'kept' } | ForEach-Object { $_.step })
            foreach ($step in 'Auth method registration', 'Users', 'Per-user MFA state', 'Groups', 'Entra devices', 'Intune managed devices') { $kept | Should -Contain $step }
            InModuleScope TenantKeep.Posture -Parameters @{ F = $script:Again } {
                param($F)
                $state = Get-PostureJournalState -Folder $F
                $state.steps['Entra|Users'].state | Should -Be 'done'
                @(Get-PostureStaleEvidence -Folder $F) | Should -BeNullOrEmpty -Because 'a kept file is this run''s evidence'
            }
        }

        It 'returns the device count of a kept Intune list, and reads PIM for Groups from the kept group list' {
            InModuleScope TenantKeep.Posture -Parameters @{ F = $script:Again } {
                param($F)
                $script:PostureJournalFolder = $F; $script:PostureCurrentCollector = 'Intune'
                try { $r = Invoke-PostureIntuneCollection -Folder $F 6>$null 3>$null } finally { $script:PostureJournalFolder = $null; $script:PostureCurrentCollector = $null }
                $r.managedDevices | Should -Be @(Get-Content -Raw (Join-Path $F '09-intune-managed-devices.json') | ConvertFrom-Json).Count
                $r.managedDevices | Should -BeGreaterThan 0
            }
            (Get-Content -Raw (Join-Path $script:Again 'gov-04-pim-groups-summary.json') | ConvertFrom-Json).RoleAssignableGroups | Should -Be (Get-Content -Raw (Join-Path $script:Again '07-groups-summary.json') | ConvertFrom-Json).RoleAssignable
        }

        It 'reads the users and the registration again when the people who hold a role are not the same' {
            # Without PIM the role read falls back to plain assignments: fewer holders, so another key.
            $env:TKP_TEST_PIM = 'none'
            try { $null = & $script:Collect } finally { $env:TKP_TEST_PIM = 'ok' }
            $asked = @($script:GraphAsked)
            @($asked | Where-Object { $_ -match '/users\?\$select' }).Count | Should -BeGreaterOrEqual 1 -Because 'the admin files written with the user list depend on who holds a role'
            @($asked | Where-Object { $_ -match 'userRegistrationDetails' }).Count | Should -Be 1
            @($asked | Where-Object { $_ -match '/groups\?\$select|/devices\?\$select|deviceManagement/managedDevices\?' }) | Should -BeNullOrEmpty -Because 'the group and device lists do not depend on it'
        }
    }

    Context 'the user list stops part way' {
        BeforeAll {
            $env:TKP_TEST_PIM = 'ok'
            $script:Part = Join-Path $script:Root 'part'
            # Fifteen users, one to a page; signInActivity is refused, as in the rest of this file, so the read is the
            # one without it. The page in failAt answers that the sign-in has ended.
            $script:UsersPaged = @{ failAt = 0; asked = [System.Collections.Generic.List[string]]::new() }
            Mock -ModuleName TenantKeep.Posture Invoke-MgGraphRequest -ParameterFilter { $Uri -match '/v1\.0/users\?' } {
                $script:UsersPaged.asked.Add([string]$Uri)
                if ($Uri -match 'signInActivity') { throw 'Authorization_RequestDenied: Insufficient privileges' }
                $n = $(if ($Uri -match 'skiptoken=u(\d+)') { [int]$Matches[1] } else { 1 })
                if ($script:UsersPaged.failAt -eq $n) { throw 'InvalidAuthenticationToken: Lifetime validation failed, the token is expired.' }
                $page = @{ value = @(@{ id = "u$n"; userPrincipalName = $(if ($n -eq 1) { 'admin1@contoso.example' } else { "user$n@contoso.example" }); displayName = "User $n"; accountEnabled = $true; userType = $(if ($n % 4 -eq 0) { 'Guest' } else { 'Member' }); assignedLicenses = @(@{ skuId = 's1'; disabledPlans = @('p-intune') }); createdDateTime = '2025-01-01T00:00:00Z' }) }
                if ($n -lt 15) { $page['@odata.nextLink'] = "https://graph.microsoft.com/v1.0/users?`$top=999&`$skiptoken=u$($n + 1)" }
                $page
            }
            $script:CollectPart = { param([int] $FailAt) $script:UsersPaged.failAt = $FailAt; $script:UsersPaged.asked.Clear(); $script:GraphAsked.Clear(); Invoke-PostureCollection -Collector Entra -SkipCaSnapshot -SkipPerUserMfa -OutputFolder $script:Part -PassThru -WarningAction SilentlyContinue 6>$null }
            $script:Stopped = & $script:CollectPart 12
            $script:StoppedFiles = @(Get-ChildItem $script:Part -Name)
            $script:Carried = & $script:CollectPart 0
            $script:CarriedAsked = @($script:UsersPaged.asked)
        }

        It 'fails the step with its cause and keeps what it read, with a cursor, where no reader takes it for the list' {
            @($script:Stopped.Errors) -join ' ' | Should -Match 'Users :: .*token is expired'
            $script:StoppedFiles | Should -Contain '06-users.json.part'
            $script:StoppedFiles | Should -Contain '06-users.csv.part'
            $script:StoppedFiles | Should -Contain 'cursor-06-users.json'
            $script:StoppedFiles | Should -Not -Contain '06-users.json'
            $script:StoppedFiles | Should -Not -Contain '06-users-summary.json' -Because 'a summary of the part that was read would be read as the tenant'
        }

        It 'carries on from the page after the cursor, with the request it was making, and has every user once' {
            $script:CarriedAsked[0] | Should -Match 'skiptoken=u11$' -Because 'ten pages were read and saved before it stopped'
            @($script:CarriedAsked | Where-Object { $_ -match 'signInActivity' }) | Should -BeNullOrEmpty -Because 'the request that was refused the first time is not tried again part way through'
            $script:CarriedAsked.Count | Should -Be 5
            $users = @(Get-Content -Raw (Join-Path $script:Part '06-users.json') | ConvertFrom-Json)
            @($users.Id) | Should -Be @(1..15 | ForEach-Object { "u$_" })
            @(Import-Csv (Join-Path $script:Part '06-users.csv')).Count | Should -Be 15
            @(Get-Content -Raw (Join-Path $script:Part '06-users-guests.json') | ConvertFrom-Json).Count | Should -Be 3
            Get-ChildItem $script:Part -Name | Should -Not -Contain 'cursor-06-users.json'
            @(Get-ChildItem $script:Part -Filter '*.part').Count | Should -Be 0
        }

        It 'counts the whole list in the summaries, not only the pages read after it carried on' {
            $s = Get-Content -Raw (Join-Path $script:Part '06-users-summary.json') | ConvertFrom-Json
            $s.Total | Should -Be 15
            $s.Guests | Should -Be 3
            $s.Members | Should -Be 12
            $lp = Get-Content -Raw (Join-Path $script:Part '06-users-license-plans.json') | ConvertFrom-Json
            $lp.LicensedEnabledUsers | Should -Be 15
            $lp.UsersByServicePlan.AAD_PREMIUM | Should -Be 15
            # The administrator was on the first page, read before the cursor: the row came back from it.
            $admins = @(Get-Content -Raw (Join-Path $script:Part '06-users-admins.json') | ConvertFrom-Json)
            @($admins.UserPrincipalName) | Should -Be @('admin1@contoso.example')
            $admins[0].CreatedDateTime | Should -Not -BeNullOrEmpty
        }

        It 'keeps the lists that finished the first time, and clears the failure' {
            @($script:GraphAsked | Where-Object { $_ -match 'userRegistrationDetails|/groups\?\$select|/devices\?\$select' }) | Should -BeNullOrEmpty
            $steps = @(Get-Content (Join-Path $script:Part 'journal.jsonl') | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.kind -eq 'list' })
            @($steps | Where-Object { $_.state -eq 'resumed' -and $_.list -eq '06-users' }).Count | Should -Be 1
            InModuleScope TenantKeep.Posture -Parameters @{ F = $script:Part } { param($F) (Get-PostureJournalState -Folder $F).steps['Entra|Users'].state | Should -Be 'done' }
        }
    }

    Context 'the long lists a later step reads from the folder' {
        It 'fails the step, and writes no summary of zero, when the list was never collected' {
            InModuleScope TenantKeep.Posture -Parameters @{ Root = $script:Root } {
                param($Root)
                $f = Join-Path $Root 'no-lists'; New-Item -ItemType Directory -Path $f | Out-Null
                Mock Invoke-MgGraphRequest -ParameterFilter { $Uri -match '/v1\.0/(users|groups)\?\$select' } { throw 'Authorization_RequestDenied: Insufficient privileges' }
                $null = Invoke-PostureEntraCollection -Folder $f 6>$null 3>$null
                $errors = Get-Content (Join-Path $f 'errors.txt')
                $errors -join "`n" | Should -Match 'Per-user MFA state :: The user list \(06-users\) was not collected'
                $errors -join "`n" | Should -Match 'PIM for Groups :: The group list \(07-groups\) was not collected'
                Join-Path $f '05-per-user-mfa-summary.json' | Should -Not -Exist -Because 'no members read is not the same as no members with per-user MFA'
                Join-Path $f 'gov-04-pim-groups-summary.json' | Should -Not -Exist -Because 'no groups read is not the same as no role-assignable groups'
            }
        }
    }

    Context 'tenant guard' {
        It 'refuses a profile that belongs to another tenant before reading anything' {
            $p = Join-Path $script:Root 'other-tenant-profile.json'
            '{ "version": 1, "tenantId": "99999999-9999-9999-9999-999999999999" }' | Set-Content -LiteralPath $p
            { Invoke-PostureCollection -Collector Entra -SkipCaSnapshot -ProfilePath $p -OutputFolder (Join-Path $script:Root 'guard') } | Should -Throw '*belongs to tenant 99999999-9999-9999-9999-999999999999*'
            Join-Path $script:Root 'guard' 'collection.json' | Should -Not -Exist
        }

        It 'accepts the matching tenant' {
            $p = Join-Path $script:Root 'same-tenant-profile.json'
            '{ "version": 1, "tenantId": "tenant-guid" }' | Set-Content -LiteralPath $p
            { Invoke-PostureCollection -Collector Entra -SkipCaSnapshot -ProfilePath $p -OutputFolder (Join-Path $script:Root 'guard-ok') -WarningAction SilentlyContinue -ErrorAction SilentlyContinue } | Should -Not -Throw
        }
    }

    Context 'scope check' {
        It 'refuses without the core scopes' {
            Mock -ModuleName TenantKeep.Posture Get-MgContext { [pscustomobject]@{ TenantId = 't'; Account = 'a'; AuthType = 'Delegated'; Scopes = @('User.Read') } }
            { Invoke-PostureCollection -OutRoot $script:Root } | Should -Throw '*missing scope(s)*'
        }
    }
}

Describe 'Azure optional' {
    It 'skips the Azure collector when the profile says azure: none and no collector list was given' {
        $src = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'Public' 'Invoke-PostureCollection.ps1')
        $src | Should -Match ([regex]::Escape("eq 'none' -and 'Azure' -in `$Collector"))
        $src | Should -Match ([regex]::Escape("ContainsKey('Collector')")) -Because 'a named collector list always wins'
        $rb = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'deploy' 'schedules' 'posture-runbook.ps1')
        $rb | Should -Match "azure: none" -Because 'the runbook honours the same profile value'
    }
}
