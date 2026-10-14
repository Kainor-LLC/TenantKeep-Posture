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
            foreach ($f in '01-organization', '01-subscribed-skus', '02-authorization-policy', '02-authentication-strengths', '04-role-assignments-active', '04-role-assignments-pim-eligible', '05-auth-registration', '05-auth-registration-summary', '06-users', '06-users-summary', '07-groups', '10-app-registrations', '10-service-principals', '10-graph-app-permissions', '10-oauth2-delegated-grants', '11-risk-detections-30d', 'policies', 'resolved-names', 'metadata', 'collection') {
                Join-Path $script:R.Folder "$f.json" | Should -Exist
            }
            foreach ($f in '01-subscribed-skus', '04-role-assignments-active', '05-auth-registration', '06-users', '07-groups', '10-app-registrations', '10-service-principals') {
                Join-Path $script:R.Folder "$f.csv" | Should -Exist
            }
            $script:R.Collectors | Should -Be @('ConditionalAccess', 'Entra')
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
            $m.collectors | Should -Be @('ConditionalAccess', 'Entra')
            $m.graphApiVersions | Should -Be @('v1.0')
            $m.files | Should -Contain '06-users.csv'
            $m.errorCount | Should -Be 1
            (& $script:Read 'metadata').snapshotType | Should -Be 'conditional-access'
        }

        It 'warns about optional scopes that are missing' {
            @($script:W | Where-Object { $_ -like '*IdentityRiskyUser.Read.All*' }).Count | Should -Be 1
        }

        It 'feeds the CA checks from the same folder' {
            $r = Invoke-PostureChecks -Evidence $script:R.Folder -Domain ca -PassThru
            $r.results.Count | Should -Be 15
        }
    }

    Context 'without PIM' {
        It 'falls back to plain role assignments' {
            $env:TKP_TEST_PIM = 'no'
            try {
                $r = Invoke-PostureCollection -OutputFolder (Join-Path $script:Root 'nopim') -SkipCaSnapshot -PassThru -WarningAction SilentlyContinue
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

    Context 'scope check' {
        It 'refuses without the core scopes' {
            Mock -ModuleName Tenantkeep.Posture Get-MgContext { [pscustomobject]@{ TenantId = 't'; Account = 'a'; AuthType = 'Delegated'; Scopes = @('User.Read') } }
            { Invoke-PostureCollection -OutRoot $script:Root } | Should -Throw '*missing scope(s)*'
        }
    }
}
