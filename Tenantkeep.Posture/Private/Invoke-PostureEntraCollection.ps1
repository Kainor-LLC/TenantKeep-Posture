# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureEntraCollection {
    <#
    .SYNOPSIS
        The A.1 identity collector: organization, licensing, tenant policies, roles, authentication registration, users,
        groups, applications and Identity Protection, written with the audit plan's file names.
    .DESCRIPTION
        One step per file through Invoke-PostureStep: a permission failure lands in errors.txt and the run goes on.
        JSON holds what Graph returned (selected properties, untouched casing); CSV holds the flat projection the
        audit plan defines. Two fallbacks: users without signInActivity when AuditLog.Read.All is missing, and plain
        role assignments when PIM schedule instances are unavailable (no P2).
        Returns the list of files written and the step failures.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [int] $StaleDays = 90,
        [int] $RiskDetectionDays = 30,
        [datetime] $AsOf = [datetime]::UtcNow
    )

    $ErrorActionPreference = 'Stop'
    $files = [System.Collections.Generic.List[string]]::new()
    $save = { param($Data, [string] $Name, [bool] $Csv = $false) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data -AsArray -Csv:$Csv)) }
    $saveOne = { param($Data, [string] $Name) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data)) }
    $get = { param([string] $Uri, [string] $Api = 'v1.0') @(Invoke-PostureGraphRequest -Uri $Uri -ApiVersion $Api) }
    $one = { param([string] $Uri, [string] $Api = 'v1.0') Invoke-PostureGraphRequest -Uri $Uri -ApiVersion $Api -Single }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $cutoff = $AsOf.AddDays(-$StaleDays)
    $date = { param($s) ConvertTo-PostureUtcDateTime $s }

    # ---------- 1. Tenant and licensing ----------
    Invoke-PostureStep -Label 'Organization' -Folder $Folder -Script {
        $org = & $get 'organization?$select=id,displayName,tenantType,countryLetterCode,onPremisesSyncEnabled,onPremisesLastSyncDateTime,verifiedDomains,createdDateTime'
        & $save $org '01-organization'
    } | Out-Null
    Invoke-PostureStep -Label 'Subscribed SKUs' -Folder $Folder -Script {
        $skus = & $get 'subscribedSkus'
        $flat = @($skus | ForEach-Object {
                [ordered]@{
                    SkuPartNumber = $_.skuPartNumber; SkuId = $_.skuId; CapabilityStatus = (& $v $_ 'capabilityStatus'); ConsumedUnits = (& $v $_ 'consumedUnits')
                    Enabled = (& $v $_ 'prepaidUnits.enabled'); Suspended = (& $v $_ 'prepaidUnits.suspended'); Warning = (& $v $_ 'prepaidUnits.warning')
                    ServicePlans = (@(& $v $_ 'servicePlans' | Where-Object { (& $v $_ 'provisioningStatus') -eq 'Success' } | ForEach-Object { $_.servicePlanName }) -join ';')
                }
            })
        $files.Add((Write-PostureEvidence -Folder $Folder -Name '01-subscribed-skus' -InputObject $skus -AsArray))
        @($flat | ForEach-Object { [pscustomobject]$_ }) | Export-Csv -Path (Join-Path $Folder '01-subscribed-skus.csv') -NoTypeInformation
    } | Out-Null
    Invoke-PostureStep -Label 'Hybrid sync features' -Folder $Folder -Script {
        & $save (& $get 'directory/onPremisesSynchronization') '01-onprem-sync-features'
    } | Out-Null

    # ---------- 2. Tenant-wide policies ----------
    # Comma-separated on purpose: newline-separated nested arrays inside @( ) are flattened by PowerShell.
    $policySteps = @(
        ('Authorization policy', 'policies/authorizationPolicy', '02-authorization-policy', $true),
        ('Security defaults', 'policies/identitySecurityDefaultsEnforcementPolicy', '02-security-defaults', $true),
        ('Authentication methods policy', 'policies/authenticationMethodsPolicy', '02-authentication-methods-policy', $true),
        ('Authentication strengths', 'policies/authenticationStrengthPolicies', '02-authentication-strengths', $false),
        ('Admin consent request policy', 'policies/adminConsentRequestPolicy', '02-admin-consent-request-policy', $true),
        ('Cross-tenant access defaults', 'policies/crossTenantAccessPolicy/default', '02-cross-tenant-access-defaults', $true),
        ('Cross-tenant access partners', 'policies/crossTenantAccessPolicy/partners', '02-cross-tenant-access-partners', $false)
    )
    foreach ($pol in $policySteps) {
        $label, $uri, $name, $single = $pol
        Invoke-PostureStep -Label $label -Folder $Folder -Script {
            if ($single) { & $saveOne (& $one $uri) $name } else { & $save (& $get $uri) $name }
        } | Out-Null
    }

    # ---------- 4. Privileged roles ----------
    Invoke-PostureStep -Label 'Role assignments' -Folder $Folder -Script {
        $defs = & $get 'roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn,isPrivileged,templateId'
        $roleName = @{}; foreach ($d in $defs) { $roleName[[string]$d.id] = [string]$d.displayName }
        $files.Add((Write-PostureEvidence -Folder $Folder -Name '04-role-definitions' -InputObject $defs -AsArray))
        $flatten = {
            param($rows, [bool] $eligible)
            @($rows | ForEach-Object {
                    $p = & $v $_ 'principal'
                    [ordered]@{
                        Role = $roleName[[string](& $v $_ 'roleDefinitionId')]; RoleDefinitionId = (& $v $_ 'roleDefinitionId')
                        AssignmentType = $(if ($eligible) { 'Eligible' } else { [string](& $v $_ 'assignmentType') }); MemberType = (& $v $_ 'memberType')
                        DirectoryScopeId = (& $v $_ 'directoryScopeId'); StartDateTime = (& $v $_ 'startDateTime'); EndDateTime = (& $v $_ 'endDateTime')
                        PrincipalType = $(if ($p) { [string]$p['@odata.type'] -replace '^#microsoft\.graph\.', '' } else { '' }); PrincipalName = (& $v $p 'displayName')
                        PrincipalUpn = (& $v $p 'userPrincipalName'); PrincipalSynced = (& $v $p 'onPremisesSyncEnabled'); PrincipalId = (& $v $_ 'principalId')
                    }
                })
        }
        $active = $null; $eligibleRows = $null; $source = 'pim'
        try {
            $active = & $get 'roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal'
            $eligibleRows = & $get 'roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal'
        }
        catch {
            Write-Warning "PIM schedule instances unavailable ($($_.Exception.Message)); falling back to roleAssignments (no eligibility data)."
            $active = & $get 'roleManagement/directory/roleAssignments?$expand=principal'
            $eligibleRows = @(); $source = 'roleAssignments'
        }
        $a = @(& $flatten $active $false); $e = @(& $flatten $eligibleRows $true)
        & $save $a '04-role-assignments-active' $true
        & $save $e '04-role-assignments-pim-eligible' $true
        & $saveOne ([ordered]@{ source = $source; active = $a.Count; eligible = $e.Count; permanentGlobalAdmins = @($a | Where-Object { $_.Role -eq 'Global Administrator' -and $_.AssignmentType -ne 'Activated' }).Count; privilegedRoleDefinitions = @($defs | Where-Object { & $v $_ 'isPrivileged' }).Count }) '04-role-assignments-summary'
    } | Out-Null

    # ---------- 5. Authentication method registration ----------
    Invoke-PostureStep -Label 'Auth method registration' -Folder $Folder -Script {
        $reg = & $get 'reports/authenticationMethods/userRegistrationDetails?$top=999'
        $flat = @($reg | ForEach-Object {
                [ordered]@{
                    UserPrincipalName = $_.userPrincipalName; UserDisplayName = (& $v $_ 'userDisplayName'); UserType = (& $v $_ 'userType'); IsAdmin = (& $v $_ 'isAdmin')
                    IsMfaRegistered = (& $v $_ 'isMfaRegistered'); IsMfaCapable = (& $v $_ 'isMfaCapable'); IsPasswordlessCapable = (& $v $_ 'isPasswordlessCapable')
                    IsSsprRegistered = (& $v $_ 'isSsprRegistered'); IsSsprEnabled = (& $v $_ 'isSsprEnabled'); IsSsprCapable = (& $v $_ 'isSsprCapable')
                    IsSystemPreferredAuthenticationMethodEnabled = (& $v $_ 'isSystemPreferredAuthenticationMethodEnabled')
                    SystemPreferredAuthenticationMethods = (@(& $v $_ 'systemPreferredAuthenticationMethods') -join ';')
                    UserPreferredMethodForSecondaryAuthentication = (& $v $_ 'userPreferredMethodForSecondaryAuthentication'); LastUpdatedDateTime = (& $v $_ 'lastUpdatedDateTime')
                    MethodsRegistered = (@(& $v $_ 'methodsRegistered') -join ';')
                }
            })
        & $save $flat '05-auth-registration' $true
        $members = @($flat | Where-Object { $_.UserType -eq 'member' })
        $n = [Math]::Max(1, $members.Count)
        & $saveOne ([ordered]@{
                TotalMembers = $members.Count
                MfaRegisteredPct = [Math]::Round(100 * @($members | Where-Object { $_.IsMfaRegistered }).Count / $n, 1)
                PasswordlessCapablePct = [Math]::Round(100 * @($members | Where-Object { $_.IsPasswordlessCapable }).Count / $n, 1)
                SsprRegisteredPct = [Math]::Round(100 * @($members | Where-Object { $_.IsSsprRegistered }).Count / $n, 1)
                Admins = @($members | Where-Object { $_.IsAdmin }).Count
                AdminsNotPasswordless = @($members | Where-Object { $_.IsAdmin -and -not $_.IsPasswordlessCapable }).Count
                AdminsNoMfa = @($members | Where-Object { $_.IsAdmin -and -not $_.IsMfaRegistered }).Count
                UsersWithSms = @($members | Where-Object { ($_.MethodsRegistered -split ';') -contains 'mobilePhone' }).Count
                UsersWithPasskeyOrFido = @($members | Where-Object { $_.MethodsRegistered -match 'fido2|passKey' }).Count
                UsersWithWhfb = @($members | Where-Object { ($_.MethodsRegistered -split ';') -contains 'windowsHelloForBusiness' }).Count
            }) '05-auth-registration-summary'
    } | Out-Null

    # ---------- 6. Users ----------
    Invoke-PostureStep -Label 'Users' -Folder $Folder -Script {
        $base = 'id,userPrincipalName,displayName,accountEnabled,userType,onPremisesSyncEnabled,createdDateTime,assignedLicenses,department,jobTitle,companyName,usageLocation,creationType,externalUserState'
        $users = $null
        try { $users = & $get "users?`$select=$base,signInActivity&`$top=999" }
        catch {
            Write-Warning "Users with signInActivity failed ($($_.Exception.Message)); retrying without it (needs AuditLog.Read.All)."
            $users = & $get "users?`$select=$base&`$top=999"
        }
        $flat = @($users | ForEach-Object {
                [ordered]@{
                    Id = $_.id; UserPrincipalName = $_.userPrincipalName; DisplayName = (& $v $_ 'displayName'); AccountEnabled = (& $v $_ 'accountEnabled'); UserType = (& $v $_ 'userType')
                    OnPremisesSyncEnabled = [bool](& $v $_ 'onPremisesSyncEnabled'); CreatedDateTime = (& $v $_ 'createdDateTime'); Department = (& $v $_ 'department'); JobTitle = (& $v $_ 'jobTitle')
                    CompanyName = (& $v $_ 'companyName'); UsageLocation = (& $v $_ 'usageLocation'); CreationType = (& $v $_ 'creationType'); ExternalUserState = (& $v $_ 'externalUserState')
                    LicenseCount = @(& $v $_ 'assignedLicenses').Count
                    LastInteractiveSignIn = (& $v $_ 'signInActivity.lastSignInDateTime'); LastNonInteractiveSignIn = (& $v $_ 'signInActivity.lastNonInteractiveSignInDateTime')
                }
            })
        & $save $flat '06-users' $true
        $last = { param($r) & $date $r.LastInteractiveSignIn }
        & $saveOne ([ordered]@{
                Total = $flat.Count
                Members = @($flat | Where-Object { $_.UserType -eq 'Member' }).Count
                Guests = @($flat | Where-Object { $_.UserType -eq 'Guest' }).Count
                Synced = @($flat | Where-Object { $_.OnPremisesSyncEnabled }).Count
                CloudOnlyMembers = @($flat | Where-Object { $_.UserType -eq 'Member' -and -not $_.OnPremisesSyncEnabled }).Count
                Disabled = @($flat | Where-Object { -not $_.AccountEnabled }).Count
                DisabledWithLicenses = @($flat | Where-Object { -not $_.AccountEnabled -and $_.LicenseCount -gt 0 }).Count
                EnabledInactiveMembers = @($flat | Where-Object { $_.AccountEnabled -and $_.UserType -eq 'Member' -and $_.LastInteractiveSignIn -and (& $last $_) -lt $cutoff }).Count
                EnabledNeverSignedIn = @($flat | Where-Object { $_.AccountEnabled -and $_.UserType -eq 'Member' -and -not $_.LastInteractiveSignIn }).Count
                InactiveGuests = @($flat | Where-Object { $_.UserType -eq 'Guest' -and (-not $_.LastInteractiveSignIn -or (& $last $_) -lt $cutoff) }).Count
                PendingGuestInvites = @($flat | Where-Object { $_.ExternalUserState -eq 'PendingAcceptance' }).Count
                SignInActivityAvailable = [bool](@($flat | Where-Object { $_.LastInteractiveSignIn }).Count -gt 0)
                StaleDays = $StaleDays
            }) '06-users-summary'
    } | Out-Null

    # ---------- 7. Groups ----------
    Invoke-PostureStep -Label 'Groups' -Folder $Folder -Script {
        $groups = & $get 'groups?$select=id,displayName,groupTypes,mailEnabled,securityEnabled,onPremisesSyncEnabled,membershipRule,membershipRuleProcessingState,createdDateTime,visibility,isAssignableToRole,expirationDateTime&$top=999'
        $flat = @($groups | ForEach-Object {
                $types = @(& $v $_ 'groupTypes')
                $kind = if ($types -contains 'Unified') { 'M365' } elseif ($types -contains 'DynamicMembership') { 'DynamicSecurity' } elseif ((& $v $_ 'mailEnabled') -and (& $v $_ 'securityEnabled')) { 'MailEnabledSecurity' } elseif (& $v $_ 'mailEnabled') { 'Distribution' } else { 'Security' }
                [ordered]@{
                    Id = $_.id; DisplayName = (& $v $_ 'displayName'); OnPremisesSyncEnabled = [bool](& $v $_ 'onPremisesSyncEnabled'); CreatedDateTime = (& $v $_ 'createdDateTime')
                    Visibility = (& $v $_ 'visibility'); IsAssignableToRole = [bool](& $v $_ 'isAssignableToRole'); ExpirationDateTime = (& $v $_ 'expirationDateTime'); MembershipRule = (& $v $_ 'membershipRule')
                    Kind = $kind; Dynamic = ($types -contains 'DynamicMembership')
                }
            })
        & $save $flat '07-groups' $true
    } | Out-Null

    # ---------- 10. Applications and service principals ----------
    Invoke-PostureStep -Label 'App registrations' -Folder $Folder -Script {
        $apps = & $get 'applications?$select=id,appId,displayName,signInAudience,createdDateTime,passwordCredentials,keyCredentials,publisherDomain&$top=999'
        $flat = @($apps | ForEach-Object {
                $ends = @(@(& $v $_ 'passwordCredentials') + @(& $v $_ 'keyCredentials') | ForEach-Object { & $date (& $v $_ 'endDateTime') } | Where-Object { $_ })
                [ordered]@{
                    Id = $_.id; AppId = $_.appId; DisplayName = (& $v $_ 'displayName'); SignInAudience = (& $v $_ 'signInAudience'); PublisherDomain = (& $v $_ 'publisherDomain'); CreatedDateTime = (& $v $_ 'createdDateTime')
                    Secrets = @(& $v $_ 'passwordCredentials').Count; Certs = @(& $v $_ 'keyCredentials').Count
                    EarliestExpiry = $(if ($ends.Count -gt 0) { ($ends | Sort-Object | Select-Object -First 1).ToString('o') } else { $null })
                    ExpiredCredentials = @($ends | Where-Object { $_ -lt $AsOf }).Count
                }
            })
        & $save $flat '10-app-registrations' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Service principals' -Folder $Folder -Script {
        $tenantId = [string](Get-MgContext).TenantId
        $sps = & $get 'servicePrincipals?$select=id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId,preferredSingleSignOnMode,signInAudience,tags,keyCredentials,passwordCredentials,createdDateTime,appRoleAssignmentRequired&$top=999'
        $flat = @($sps | ForEach-Object {
                $ends = @(@(& $v $_ 'passwordCredentials') + @(& $v $_ 'keyCredentials') | ForEach-Object { & $date (& $v $_ 'endDateTime') } | Where-Object { $_ })
                $saml = @(@(& $v $_ 'keyCredentials') | Where-Object { (& $v $_ 'usage') -eq 'Verify' } | ForEach-Object { & $date (& $v $_ 'endDateTime') } | Where-Object { $_ } | Sort-Object | Select-Object -First 1)
                [ordered]@{
                    Id = $_.id; AppId = $_.appId; DisplayName = (& $v $_ 'displayName'); AccountEnabled = (& $v $_ 'accountEnabled'); ServicePrincipalType = (& $v $_ 'servicePrincipalType')
                    AppOwnerOrganizationId = (& $v $_ 'appOwnerOrganizationId'); PreferredSingleSignOnMode = (& $v $_ 'preferredSingleSignOnMode'); SignInAudience = (& $v $_ 'signInAudience')
                    AppRoleAssignmentRequired = (& $v $_ 'appRoleAssignmentRequired'); CreatedDateTime = (& $v $_ 'createdDateTime')
                    HomeTenantApp = ([string](& $v $_ 'appOwnerOrganizationId') -eq $tenantId); IsEnterpriseAppListed = (@(& $v $_ 'tags') -contains 'WindowsAzureActiveDirectoryIntegratedApp')
                    SamlCertExpiry = $(if ($saml.Count -gt 0) { $saml[0].ToString('o') } else { $null }); HasExpiredCreds = (@($ends | Where-Object { $_ -lt $AsOf }).Count -gt 0)
                }
            })
        & $save $flat '10-service-principals' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Graph application permissions' -Folder $Folder -Script {
        $graphSp = @(& $get "servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles")[0]
        $roleMap = @{}; foreach ($r in @(& $v $graphSp 'appRoles')) { $roleMap[[string]$r.id] = [string]$r.value }
        $grants = & $get "servicePrincipals/$($graphSp.id)/appRoleAssignedTo?`$top=999"
        $flat = @($grants | ForEach-Object { [ordered]@{ PrincipalDisplayName = (& $v $_ 'principalDisplayName'); PrincipalId = (& $v $_ 'principalId'); PrincipalType = (& $v $_ 'principalType'); Permission = $roleMap[[string](& $v $_ 'appRoleId')]; CreatedDateTime = (& $v $_ 'createdDateTime') } } | Sort-Object { $_.Permission })
        & $save $flat '10-graph-app-permissions' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Delegated OAuth2 grants' -Folder $Folder -Script {
        $grants = & $get 'oauth2PermissionGrants?$top=999'
        $flat = @($grants | ForEach-Object { [ordered]@{ ClientId = (& $v $_ 'clientId'); ConsentType = (& $v $_ 'consentType'); PrincipalId = (& $v $_ 'principalId'); ResourceId = (& $v $_ 'resourceId'); Scope = (& $v $_ 'scope') } })
        & $save $flat '10-oauth2-delegated-grants' $true
    } | Out-Null

    # ---------- 11. Identity Protection (P2; fails gracefully) ----------
    Invoke-PostureStep -Label 'Risky users' -Folder $Folder -Script {
        $rows = & $get 'identityProtection/riskyUsers?$top=500'
        $flat = @($rows | ForEach-Object { [ordered]@{ UserPrincipalName = (& $v $_ 'userPrincipalName'); RiskLevel = (& $v $_ 'riskLevel'); RiskState = (& $v $_ 'riskState'); RiskDetail = (& $v $_ 'riskDetail'); RiskLastUpdatedDateTime = (& $v $_ 'riskLastUpdatedDateTime'); IsDeleted = (& $v $_ 'isDeleted'); IsProcessing = (& $v $_ 'isProcessing') } })
        & $save $flat '11-risky-users' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Risk detections' -Folder $Folder -Script {
        $since = $AsOf.AddDays(-$RiskDetectionDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $rows = & $get "identityProtection/riskDetections?`$filter=activityDateTime ge $since&`$top=500"
        $flat = @($rows | ForEach-Object { [ordered]@{ UserPrincipalName = (& $v $_ 'userPrincipalName'); RiskEventType = (& $v $_ 'riskEventType'); RiskLevel = (& $v $_ 'riskLevel'); RiskState = (& $v $_ 'riskState'); RiskDetail = (& $v $_ 'riskDetail'); DetectionTimingType = (& $v $_ 'detectionTimingType'); ActivityDateTime = (& $v $_ 'activityDateTime'); IPAddress = (& $v $_ 'ipAddress'); Country = (& $v $_ 'location.countryOrRegion') } })
        & $save $flat "11-risk-detections-$($RiskDetectionDays)d" $true
    } | Out-Null

    $errorsPath = Join-Path $Folder 'errors.txt'
    return @{
        files  = $files.ToArray()
        errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath })
    }
}
