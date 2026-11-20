# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureEntraCollection {
    <#
    .SYNOPSIS
        The A.1 identity collector: organization, licensing, tenant policies, roles, authentication registration, users,
        groups, applications and Identity Protection, written with the audit plan's file names.
    .DESCRIPTION
        One step per file through Invoke-PostureStep: a permission failure lands in errors.txt and the run goes on.
        Added beyond the audit plan's A.1: 04-pim-role-policies (activation rules per role), 05-per-user-mfa (legacy
        per-user MFA state, batched reads: every member up to 5,000 or with -FullPerUserMfa, else every admin and a random 1,000, and everyone only when one has it; -SkipPerUserMfa leaves it out), 08-entra-devices.
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
        [switch] $SkipPerUserMfa,
        [switch] $FullPerUserMfa,
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
    $load = { param([string] $Name) $f = Join-Path $Folder "$Name.json"; if (Test-Path -LiteralPath $f) { ConvertFrom-Json -InputObject (Get-Content -Raw -LiteralPath $f) -AsHashtable -Depth 20 } }

    # ---------- 1. Tenant and licensing ----------
    Invoke-PostureStep -Label 'Organization' -Folder $Folder -Script {
        $org = & $get 'organization?$select=id,displayName,tenantType,countryLetterCode,onPremisesSyncEnabled,onPremisesLastSyncDateTime,verifiedDomains,createdDateTime'
        & $save $org '01-organization'
    } | Out-Null
    Invoke-PostureStep -Label 'Domains' -Folder $Folder -Script {
        # Federated domains say ADFS or another federation is in play; the profile discovery reads this for the identity model.
        $domains = & $get 'domains?$select=id,isDefault,isInitial,isVerified,authenticationType'
        & $save @($domains | ForEach-Object { [ordered]@{ Id = $_.id; IsDefault = (& $v $_ 'isDefault'); IsInitial = (& $v $_ 'isInitial'); IsVerified = (& $v $_ 'isVerified'); AuthenticationType = (& $v $_ 'authenticationType') } }) '01-domains' $true
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
        # isPrivileged is beta-only on unifiedRoleDefinition; v1.0 rejects it in $select.
        $defs = & $get 'roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn,templateId'
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
        & $saveOne ([ordered]@{ source = $source; active = $a.Count; eligible = $e.Count; permanentGlobalAdmins = @($a | Where-Object { $_.Role -eq 'Global Administrator' -and $_.AssignmentType -ne 'Activated' }).Count; roleDefinitions = $defs.Count }) '04-role-assignments-summary'
    } | Out-Null

    # ---------- 4b. PIM role management policies (ID-006) ----------
    Invoke-PostureStep -Label 'PIM role policies' -Folder $Folder -Script {
        # Policy assignments map a role to its policy; the rules carry activation MFA, justification, duration and approval. (verify) scope: RoleManagement.Read.Directory
        $assignments = & $get "policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&`$expand=policy(`$expand=rules)"
        $defs = @(& $load '04-role-definitions')
        $roleName = @{}; foreach ($d in $defs) { $roleName[[string]$d.id] = [string]$d.displayName }
        $flat = @($assignments | ForEach-Object {
                $rules = @(& $v $_ 'policy.rules')
                $rule = { param([string] $Id) @($rules | Where-Object { [string]$_.id -eq $Id }) | Select-Object -First 1 }
                $exp = & $rule 'Expiration_EndUser_Assignment'; $en = & $rule 'Enablement_EndUser_Assignment'; $ap = & $rule 'Approval_EndUser_Assignment'
                $duration = [string](& $v $exp 'maximumDuration')
                $hours = $null
                if ($duration) { try { $hours = [System.Xml.XmlConvert]::ToTimeSpan($duration).TotalHours } catch { $hours = $null } }
                $enabled = @(& $v $en 'enabledRules')
                [ordered]@{
                    RoleDefinitionId = (& $v $_ 'roleDefinitionId'); Role = $roleName[[string](& $v $_ 'roleDefinitionId')]; PolicyId = (& $v $_ 'policyId')
                    MaxActivationHours = $hours; ActivationExpirationRequired = [bool](& $v $exp 'isExpirationRequired')
                    ActivationMfaRequired = ($enabled -contains 'MultiFactorAuthentication'); ActivationJustificationRequired = ($enabled -contains 'Justification'); ActivationTicketRequired = ($enabled -contains 'Ticketing')
                    ApprovalRequired = [bool](& $v $ap 'setting.isApprovalRequired')
                }
            })
        & $save $flat '04-pim-role-policies' $true
    } | Out-Null

    # Admins (active and eligible role holders), from the role step's files: the registration and users passes
    # write admin-only files from them, so the report and the facts never reload the full lists to find admins.
    $adminUpns = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in '04-role-assignments-active', '04-role-assignments-pim-eligible') {
        foreach ($a in @(& $load $name)) { if ($a -and $a['PrincipalUpn']) { $null = $adminUpns.Add([string]$a['PrincipalUpn']) } }
    }

    # ---------- 5. Authentication method registration ----------
    # One streaming pass: rows written as they come, the summary and the strongest-method counts tallied, admin rows kept.
    Invoke-PostureStep -Label 'Auth method registration' -Folder $Folder -Script {
        $c = @{ members = 0; mfa = 0; passwordless = 0; sspr = 0; admins = 0; adminsNotPasswordless = 0; adminsNoMfa = 0; sms = 0; fido = 0; whfb = 0 }
        $strength = [ordered]@{ PhishingResistant = 0; Passwordless = 0; Authenticator = 0; PhoneOnly = 0; None = 0 }
        $adminRows = [System.Collections.Generic.List[object]]::new()
        $stream = Open-PostureEvidenceStream -Folder $Folder -Name '05-auth-registration' -Csv -Confirm:$false
        try {
            $null = Invoke-PostureGraphRequest -Uri 'reports/authenticationMethods/userRegistrationDetails?$top=999' -ApiVersion 'v1.0' -Label 'Registration' -OnPage {
                param($page)
                foreach ($r in $page) {
                    $methods = @($r['methodsRegistered'] | Where-Object { $_ })
                    $row = [ordered]@{
                        UserPrincipalName = $r['userPrincipalName']; UserDisplayName = $r['userDisplayName']; UserType = $r['userType']; IsAdmin = $r['isAdmin']
                        IsMfaRegistered = $r['isMfaRegistered']; IsMfaCapable = $r['isMfaCapable']; IsPasswordlessCapable = $r['isPasswordlessCapable']
                        IsSsprRegistered = $r['isSsprRegistered']; IsSsprEnabled = $r['isSsprEnabled']; IsSsprCapable = $r['isSsprCapable']
                        IsSystemPreferredAuthenticationMethodEnabled = $r['isSystemPreferredAuthenticationMethodEnabled']
                        SystemPreferredAuthenticationMethods = (@($r['systemPreferredAuthenticationMethods']) -join ';')
                        UserPreferredMethodForSecondaryAuthentication = $r['userPreferredMethodForSecondaryAuthentication']; LastUpdatedDateTime = $r['lastUpdatedDateTime']
                        MethodsRegistered = ($methods -join ';')
                    }
                    Add-PostureEvidenceRow -Stream $stream -Row $row
                    $isAdmin = [bool]$row.IsAdmin -or $adminUpns.Contains([string]$row.UserPrincipalName)
                    if ($isAdmin) { $adminRows.Add($row) }
                    if ($row.UserType -ne 'member') { continue }
                    $c.members++
                    if ($row.IsMfaRegistered) { $c.mfa++ }
                    if ($row.IsPasswordlessCapable) { $c.passwordless++ }
                    if ($row.IsSsprRegistered) { $c.sspr++ }
                    if ($row.IsAdmin) { $c.admins++; if (-not $row.IsPasswordlessCapable) { $c.adminsNotPasswordless++ }; if (-not $row.IsMfaRegistered) { $c.adminsNoMfa++ } }
                    if ($methods -contains 'mobilePhone') { $c.sms++ }
                    $joined = $row.MethodsRegistered
                    if ($joined -match 'fido2|passKey') { $c.fido++ }
                    if ($methods -contains 'windowsHelloForBusiness') { $c.whfb++ }
                    # Strongest method registered, the categories the report charts.
                    if ($joined -match 'fido2|passKey|x509Certificate|windowsHelloForBusiness') { $strength.PhishingResistant++ }
                    elseif ($joined -match 'microsoftAuthenticatorPasswordless|macOsSecureEnclaveKey') { $strength.Passwordless++ }
                    elseif ($joined -match 'microsoftAuthenticator|softwareOneTimePasscode|hardwareOneTimePasscode') { $strength.Authenticator++ }
                    elseif ($joined -match 'mobilePhone|alternateMobilePhone|officePhone|email') { $strength.PhoneOnly++ }
                    else { $strength.None++ }
                }
            }
            $files.Add((Close-PostureEvidenceStream -Stream $stream))
        }
        catch { Stop-PostureEvidenceStream -Stream $stream -Confirm:$false; throw }
        & $save @($adminRows) '05-auth-registration-admins'
        $n = [Math]::Max(1, $c.members)
        & $saveOne ([ordered]@{
                TotalMembers = $c.members
                MfaRegisteredPct = [Math]::Round(100 * $c.mfa / $n, 1)
                PasswordlessCapablePct = [Math]::Round(100 * $c.passwordless / $n, 1)
                SsprRegisteredPct = [Math]::Round(100 * $c.sspr / $n, 1)
                Admins = $c.admins
                AdminsNotPasswordless = $c.adminsNotPasswordless
                AdminsNoMfa = $c.adminsNoMfa
                UsersWithSms = $c.sms
                UsersWithPasskeyOrFido = $c.fido
                UsersWithWhfb = $c.whfb
                StrongestMethod = $strength
            }) '05-auth-registration-summary'
    } | Out-Null

    # ---------- 6. Users ----------
    # One streaming pass, at any size: each page is flattened, written and counted, and only the members' ids are
    # kept, for the per-user MFA step. Nothing holds the whole user list.
    $memberIds = [System.Collections.Generic.List[object]]::new()
    $adminUsers = [System.Collections.Generic.List[object]]::new()
    Invoke-PostureStep -Label 'Users' -Folder $Folder -Script {
        $base = 'id,userPrincipalName,displayName,accountEnabled,userType,onPremisesSyncEnabled,createdDateTime,assignedLicenses,department,jobTitle,companyName,usageLocation,creationType,externalUserState'
        $c = [ordered]@{ Total = 0; Members = 0; Guests = 0; Synced = 0; CloudOnlyMembers = 0; Disabled = 0; DisabledWithLicenses = 0; EnabledInactiveMembers = 0; EnabledNeverSignedIn = 0; InactiveGuests = 0; PendingGuestInvites = 0; WithSignIn = 0 }
        $read = {
            param([string] $Select)
            $stream = Open-PostureEvidenceStream -Folder $Folder -Name '06-users' -Csv -Confirm:$false
            try {
                $null = Invoke-PostureGraphRequest -Uri "users?`$select=$Select&`$top=999" -ApiVersion 'v1.0' -Label 'Users' -OnPage {
                    param($page)
                    foreach ($u in $page) {
                        $sia = $(if ($u.ContainsKey('signInActivity')) { $u['signInActivity'] } else { $null })
                        $last = $(if ($sia) { $sia['lastSignInDateTime'] } else { $null })
                        $licences = $(if ($u.ContainsKey('assignedLicenses')) { @($u['assignedLicenses']).Count } else { 0 })
                        $row = [ordered]@{
                            Id = $u['id']; UserPrincipalName = $u['userPrincipalName']; DisplayName = $u['displayName']; AccountEnabled = $u['accountEnabled']; UserType = $u['userType']
                            OnPremisesSyncEnabled = [bool]$u['onPremisesSyncEnabled']; CreatedDateTime = $u['createdDateTime']; Department = $u['department']; JobTitle = $u['jobTitle']
                            CompanyName = $u['companyName']; UsageLocation = $u['usageLocation']; CreationType = $u['creationType']; ExternalUserState = $u['externalUserState']
                            LicenseCount = $licences; LastInteractiveSignIn = $last; LastNonInteractiveSignIn = $(if ($sia) { $sia['lastNonInteractiveSignInDateTime'] } else { $null })
                        }
                        Add-PostureEvidenceRow -Stream $stream -Row $row
                        if ($adminUpns.Contains([string]$row.UserPrincipalName)) { $adminUsers.Add($row) }
                        $member = $row.UserType -eq 'Member'; $guest = $row.UserType -eq 'Guest'; $enabled = [bool]$row.AccountEnabled
                        $old = $(if ($last) { (& $date $last) -lt $cutoff } else { $false })
                        $c.Total++
                        if ($member) { $c.Members++; $memberIds.Add(@{ Id = $row.Id; UserPrincipalName = $row.UserPrincipalName }) }
                        if ($guest) { $c.Guests++ }
                        if ($row.OnPremisesSyncEnabled) { $c.Synced++ } elseif ($member) { $c.CloudOnlyMembers++ }
                        if (-not $enabled) { $c.Disabled++; if ($licences -gt 0) { $c.DisabledWithLicenses++ } }
                        if ($enabled -and $member) { if (-not $last) { $c.EnabledNeverSignedIn++ } elseif ($old) { $c.EnabledInactiveMembers++ } }
                        if ($guest -and (-not $last -or $old)) { $c.InactiveGuests++ }
                        if ($row.ExternalUserState -eq 'PendingAcceptance') { $c.PendingGuestInvites++ }
                        if ($last) { $c.WithSignIn++ }
                    }
                }
                $files.Add((Close-PostureEvidenceStream -Stream $stream))
            }
            catch { Stop-PostureEvidenceStream -Stream $stream -Confirm:$false; throw }
        }
        try { & $read "$base,signInActivity" }
        catch {
            Write-Warning "Users with signInActivity failed ($($_.Exception.Message)); reading them again without it (needs AuditLog.Read.All and Entra ID P1)."
            foreach ($k in @($c.Keys)) { $c[$k] = 0 }
            $memberIds.Clear(); $adminUsers.Clear()
            & $read $base
        }
        & $save @($adminUsers) '06-users-admins'
        $summary = [ordered]@{}
        foreach ($k in 'Total', 'Members', 'Guests', 'Synced', 'CloudOnlyMembers', 'Disabled', 'DisabledWithLicenses', 'EnabledInactiveMembers', 'EnabledNeverSignedIn', 'InactiveGuests', 'PendingGuestInvites') { $summary[$k] = $c[$k] }
        $summary.SignInActivityAvailable = $c.WithSignIn -gt 0
        $summary.StaleDays = $StaleDays
        & $saveOne $summary '06-users-summary'
    } | Out-Null

    # ---------- 6b. Legacy per-user MFA state (AU-009) ----------
    if (-not $SkipPerUserMfa) {
        Invoke-PostureStep -Label 'Per-user MFA state' -Folder $Folder -Script {
            # One read per user, batched 20 at a time through $batch. authentication/requirements is beta-only (confirmed 2026-10-14).
            # (verify) scope: UserAuthenticationMethod.Read.All
            $members = $(if ($memberIds.Count -gt 0) { $memberIds } else { @(& $load '06-users' | Where-Object { $_ -and $_.UserType -eq 'Member' }) })
            $states = [System.Collections.Generic.List[object]]::new()
            # Graph throttles inside a batch per sub-request: a 429 or 503 there is sent again, after its Retry-After.
            $scan = {
                param($members)
                for ($i = 0; $i -lt $members.Count; $i += 20) {
                    $chunk = @($members[$i..([Math]::Min($i + 20, $members.Count) - 1)])
                    $pending = @(0..($chunk.Count - 1))
                    for ($try = 1; $pending.Count -gt 0; $try++) {
                        $requests = @(foreach ($n in $pending) { @{ id = [string]$n; method = 'GET'; url = "/users/$($chunk[$n].Id)/authentication/requirements" } })
                        $batch = Invoke-PostureGraphRequest -Uri '$batch' -Method 'POST' -Body @{ requests = $requests } -ApiVersion 'beta' -Single   # posture:read-only-post
                        $again = [System.Collections.Generic.List[int]]::new(); $wait = 0
                        foreach ($resp in @(& $v $batch 'responses')) {
                            $idx = [int](& $v $resp 'id'); $m = $chunk[$idx]; $status = [int](& $v $resp 'status')
                            if ($status -in 429, 503 -and $try -lt $script:PostureGraphRetry.maxAttempts) {
                                $again.Add($idx)
                                $ra = 0; if ([int]::TryParse([string](& $v $resp 'headers.Retry-After'), [ref]$ra)) { $wait = [Math]::Max($wait, $ra) }
                                continue
                            }
                            $states.Add([ordered]@{ UserPrincipalName = $m.UserPrincipalName; Status = $status; PerUserMfaState = (& $v $resp 'body.perUserMfaState'); Error = (& $v $resp 'body.error.message') })
                        }
                        $pending = @($again)
                        if ($pending.Count -gt 0) {
                            $delay = [Math]::Min($script:PostureGraphRetry.maxWaitSeconds, [Math]::Max($wait, $script:PostureGraphRetry.baseSeconds * [Math]::Pow(2, $try - 1)))
                            if ($delay -gt 0) { Start-Sleep -Seconds $delay }
                        }
                    }
                    if ($script:PostureProgress -and ($i / 20) % 25 -eq 0) { $script:PostureProgress.label = "Per-user MFA state: $('{0:N0}' -f $states.Count) of $('{0:N0}' -f $members.Count) members"; Write-PostureProgress }
                }
            }
            # Per-user MFA is legacy and Microsoft is retiring it, so most tenants have none. Up to 5,000 members, or with
            # -FullPerUserMfa, every member is read. Above that, every admin and 1,000 members at random are read first;
            # only when one of them has it is everyone else read too. None in 1,000 puts the rate under 0.3% (95%).
            $mode = 'full'; $sampleSize = $members.Count
            if ($FullPerUserMfa -or $members.Count -le 5000) { & $scan $members }
            else {
                $admins = @($members | Where-Object { $adminUpns.Contains([string]$_.UserPrincipalName) })
                $rest = @($members | Where-Object { -not $adminUpns.Contains([string]$_.UserPrincipalName) })
                $sample = @($admins) + @($rest | Get-Random -Count ([Math]::Min(1000, $rest.Count)))
                & $scan $sample
                $found = @($states | Where-Object { $_.PerUserMfaState -in 'enforced', 'enabled' }).Count
                if ($found -gt 0) {
                    $seen = [System.Collections.Generic.HashSet[string]]::new([string[]]@($sample | ForEach-Object { [string]$_.UserPrincipalName }), [System.StringComparer]::OrdinalIgnoreCase)
                    & $scan @($members | Where-Object { -not $seen.Contains([string]$_.UserPrincipalName) })
                }
                else { $mode = 'sample'; $sampleSize = $sample.Count }
            }
            $rows = @($states.ToArray())
            & $save $rows '05-per-user-mfa' $true
            $failed = @($rows | Where-Object { [int]$_.Status -ge 400 })
            & $saveOne ([ordered]@{ Users = $rows.Count; Members = $members.Count; Mode = $mode; SampleSize = $sampleSize; Enforced = @($rows | Where-Object { $_.PerUserMfaState -eq 'enforced' }).Count; Enabled = @($rows | Where-Object { $_.PerUserMfaState -eq 'enabled' }).Count; Disabled = @($rows | Where-Object { $_.PerUserMfaState -eq 'disabled' }).Count; Errors = $failed.Count; FirstError = $(if ($failed.Count -gt 0) { "$($failed[0].Status) $($failed[0].Error)" } else { $null }) }) '05-per-user-mfa-summary'
        } | Out-Null
    }

    # ---------- 7. Groups ----------
    Invoke-PostureStep -Label 'Group lifecycle policy' -Folder $Folder -Script {
        # Spec 4.6: the Microsoft 365 group expiration policy. One policy per tenant, or none.
        $p = @(& $get 'groupLifecyclePolicies')
        & $saveOne $(if ($p.Count -gt 0) { [ordered]@{ Present = $true; GroupLifetimeInDays = (& $v $p[0] 'groupLifetimeInDays'); ManagedGroupTypes = (& $v $p[0] 'managedGroupTypes'); AlternateNotificationEmails = (& $v $p[0] 'alternateNotificationEmails') } } else { [ordered]@{ Present = $false } }) '02-group-lifecycle-policy'
    } | Out-Null

    Invoke-PostureStep -Label 'Ownerless Microsoft 365 groups' -Folder $Folder -Script {
        # Owners expanded with ids only; a group with none is a team or site nobody can administer.
        $unified = & $get 'groups?$filter=groupTypes/any(c:c eq ''Unified'')&$select=id,displayName,createdDateTime,visibility&$expand=owners($select=id)'
        $rows = @($unified | Where-Object { @(& $v $_ 'owners').Count -eq 0 } | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); CreatedDateTime = (& $v $_ 'createdDateTime'); Visibility = (& $v $_ 'visibility') } })
        & $save $rows '07-groups-ownerless' $true
        & $saveOne ([ordered]@{ UnifiedGroups = @($unified).Count; Ownerless = $rows.Count }) '07-groups-ownerless-summary'
    } | Out-Null

    # Streamed; only the role-assignable groups are kept, for the PIM for Groups step.
    $groupRows = [System.Collections.Generic.List[object]]::new()
    Invoke-PostureStep -Label 'Groups' -Folder $Folder -Script {
        $stream = Open-PostureEvidenceStream -Folder $Folder -Name '07-groups' -Csv -Confirm:$false
        try {
            $null = Invoke-PostureGraphRequest -Uri 'groups?$select=id,displayName,groupTypes,mailEnabled,securityEnabled,onPremisesSyncEnabled,membershipRule,membershipRuleProcessingState,createdDateTime,visibility,isAssignableToRole,expirationDateTime&$top=999' -ApiVersion 'v1.0' -Label 'Groups' -OnPage {
                param($page)
                foreach ($g in $page) {
                    $types = @($g['groupTypes'])
                    $kind = if ($types -contains 'Unified') { 'M365' } elseif ($types -contains 'DynamicMembership') { 'DynamicSecurity' } elseif ($g['mailEnabled'] -and $g['securityEnabled']) { 'MailEnabledSecurity' } elseif ($g['mailEnabled']) { 'Distribution' } else { 'Security' }
                    $row = [ordered]@{
                        Id = $g['id']; DisplayName = $g['displayName']; OnPremisesSyncEnabled = [bool]$g['onPremisesSyncEnabled']; CreatedDateTime = $g['createdDateTime']
                        Visibility = $g['visibility']; IsAssignableToRole = [bool]$g['isAssignableToRole']; ExpirationDateTime = $g['expirationDateTime']; MembershipRule = $g['membershipRule']
                        Kind = $kind; Dynamic = ($types -contains 'DynamicMembership')
                    }
                    Add-PostureEvidenceRow -Stream $stream -Row $row
                    if ($row.IsAssignableToRole) { $groupRows.Add($row) }
                }
            }
            $files.Add((Close-PostureEvidenceStream -Stream $stream))
        }
        catch { Stop-PostureEvidenceStream -Stream $stream -Confirm:$false; throw }
    } | Out-Null

    # ---------- 8. Entra devices ----------
    # Streamed, with the join type and staleness counts tallied in the same pass.
    Invoke-PostureStep -Label 'Entra devices' -Folder $Folder -Script {
        $byJoinOs = @{}; $byJoinStale = @{}
        $stream = Open-PostureEvidenceStream -Folder $Folder -Name '08-entra-devices' -Csv -Confirm:$false
        try {
            $null = Invoke-PostureGraphRequest -Uri 'devices?$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,approximateLastSignInDateTime,isCompliant,isManaged,accountEnabled,registrationDateTime,profileType,managementType,enrollmentType&$top=999' -ApiVersion 'v1.0' -Label 'Entra devices' -OnPage {
                param($page)
                foreach ($d in $page) {
                    $last = & $date $d['approximateLastSignInDateTime']
                    $join = switch ([string]$d['trustType']) { 'AzureAd' { 'EntraJoined' } 'ServerAd' { 'HybridJoined' } 'Workplace' { 'Registered' } default { [string]$d['trustType'] } }
                    $stale = (-not $last -or $last -lt $cutoff)
                    $row = [ordered]@{
                        Id = $d['id']; DeviceId = $d['deviceId']; DisplayName = $d['displayName']; OperatingSystem = $d['operatingSystem']; OperatingSystemVersion = $d['operatingSystemVersion']
                        AccountEnabled = $d['accountEnabled']; IsCompliant = $d['isCompliant']; IsManaged = $d['isManaged']; ApproximateLastSignInDateTime = $d['approximateLastSignInDateTime']
                        RegistrationDateTime = $d['registrationDateTime']; ProfileType = $d['profileType']; ManagementType = $d['managementType']; EnrollmentType = $d['enrollmentType']; TrustType = $d['trustType']
                        JoinType = $join; Stale = $stale
                    }
                    Add-PostureEvidenceRow -Stream $stream -Row $row
                    $k1 = "$join, $($row.OperatingSystem)"; $byJoinOs[$k1] = 1 + $(if ($byJoinOs.ContainsKey($k1)) { $byJoinOs[$k1] } else { 0 })
                    $k2 = "$join, $stale"; $byJoinStale[$k2] = 1 + $(if ($byJoinStale.ContainsKey($k2)) { $byJoinStale[$k2] } else { 0 })
                }
            }
            $files.Add((Close-PostureEvidenceStream -Stream $stream))
        }
        catch { Stop-PostureEvidenceStream -Stream $stream -Confirm:$false; throw }
        # Same shape Group-Object gave: Name "JoinType, OperatingSystem" and Count, largest first.
        $rows = { param([hashtable] $Map) @($Map.Keys | ForEach-Object { [ordered]@{ Name = $_; Count = $Map[$_] } } | Sort-Object { - $_.Count }) }
        & $save (& $rows $byJoinOs) '08-entra-devices-by-join-os' $true
        & $save (& $rows $byJoinStale) '08-entra-devices-stale' $true
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
        $sps = & $get 'servicePrincipals?$select=id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId,preferredSingleSignOnMode,signInAudience,tags,keyCredentials,passwordCredentials,createdDateTime,appRoleAssignmentRequired&$expand=owners($select=id)&$top=999'
        $flat = @($sps | ForEach-Object {
                $ends = @(@(& $v $_ 'passwordCredentials') + @(& $v $_ 'keyCredentials') | ForEach-Object { & $date (& $v $_ 'endDateTime') } | Where-Object { $_ })
                $saml = @(@(& $v $_ 'keyCredentials') | Where-Object { (& $v $_ 'usage') -eq 'Verify' } | ForEach-Object { & $date (& $v $_ 'endDateTime') } | Where-Object { $_ } | Sort-Object | Select-Object -First 1)
                [ordered]@{
                    Id = $_.id; AppId = $_.appId; DisplayName = (& $v $_ 'displayName'); AccountEnabled = (& $v $_ 'accountEnabled'); ServicePrincipalType = (& $v $_ 'servicePrincipalType')
                    AppOwnerOrganizationId = (& $v $_ 'appOwnerOrganizationId'); PreferredSingleSignOnMode = (& $v $_ 'preferredSingleSignOnMode'); SignInAudience = (& $v $_ 'signInAudience')
                    AppRoleAssignmentRequired = (& $v $_ 'appRoleAssignmentRequired'); CreatedDateTime = (& $v $_ 'createdDateTime')
                    HomeTenantApp = ([string](& $v $_ 'appOwnerOrganizationId') -eq $tenantId); IsEnterpriseAppListed = (@(& $v $_ 'tags') -contains 'WindowsAzureActiveDirectoryIntegratedApp')
                    SamlCertExpiry = $(if ($saml.Count -gt 0) { $saml[0].ToString('o') } else { $null }); HasExpiredCreds = (@($ends | Where-Object { $_ -lt $AsOf }).Count -gt 0)
                    OwnerCount = @(@(& $v $_ 'owners') | Where-Object { $_ }).Count   # owners expanded with ids only (Graph caps it at 20); an absent property is zero, not a one-element array of null
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
    # ---------- Governance (spec 4.8): identity governance reads, each behind its own optional scope ----------
    Invoke-PostureStep -Label 'Access review definitions' -Folder $Folder -Script {
        # AccessReview.Read.All. The scope query says what is reviewed: a role assignment path, a guest filter, a group.
        $defs = & $get 'identityGovernance/accessReviews/definitions?$select=id,displayName,status,scope,settings,createdDateTime,lastModifiedDateTime'
        & $save @($defs | ForEach-Object {
                $scope = & $v $_ 'scope'
                $queries = @(@(& $v $scope 'query') + @(@(& $v $scope 'principalScopes') | ForEach-Object { & $v $_ 'query' }) + @(@(& $v $scope 'resourceScopes') | ForEach-Object { & $v $_ 'query' }) | Where-Object { $_ })
                [ordered]@{
                    Id = $_.id; DisplayName = (& $v $_ 'displayName'); Status = (& $v $_ 'status'); ScopeType = ([string]$(if ($scope -is [System.Collections.IDictionary]) { $scope['@odata.type'] })) -replace '^#microsoft\.graph\.', ''
                    ScopeQuery = ($queries -join ' | '); Recurring = [bool](& $v $_ 'settings.recurrence.pattern.type'); RecurrencePattern = (& $v $_ 'settings.recurrence.pattern.type')
                    RecurrenceInterval = (& $v $_ 'settings.recurrence.pattern.interval'); CreatedDateTime = (& $v $_ 'createdDateTime'); LastModifiedDateTime = (& $v $_ 'lastModifiedDateTime')
                }
            }) 'gov-01-access-reviews' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Access packages' -Folder $Folder -Script {
        # EntitlementManagement.Read.All
        $packages = & $get 'identityGovernance/entitlementManagement/accessPackages?$select=id,displayName,isHidden,createdDateTime'
        $catalogs = & $get 'identityGovernance/entitlementManagement/catalogs?$select=id,displayName,state,isExternallyVisible'
        $orgs = & $get 'identityGovernance/entitlementManagement/connectedOrganizations?$select=id,displayName,state'
        & $save @($packages | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); IsHidden = (& $v $_ 'isHidden'); CreatedDateTime = (& $v $_ 'createdDateTime') } }) 'gov-02-access-packages' $true
        & $saveOne ([ordered]@{ Packages = @($packages).Count; Catalogs = @($catalogs).Count; ConnectedOrganizations = @($orgs).Count }) 'gov-02-access-packages-summary'
    } | Out-Null
    Invoke-PostureStep -Label 'Lifecycle workflows' -Folder $Folder -Script {
        # LifecycleWorkflows.Read.All (Entra ID Governance). A tenant without that licence answers Forbidden (Kainor, 2026-10-23);
        # GV-005 is gated on the licence, so the line in errors.txt says which of the two it is likely to be.
        try { $wf = & $get 'identityGovernance/lifecycleWorkflows/workflows?$select=id,displayName,category,isEnabled,isSchedulingEnabled,lastModifiedDateTime' }
        catch {
            if ($_.Exception.Message -match 'Forbidden') { throw "Forbidden: Entra ID Governance (Entra Suite) is not licensed in this tenant, or LifecycleWorkflows.Read.All was not consented. GV-005 needs that licence." }
            throw
        }
        & $save @($wf | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); Category = (& $v $_ 'category'); IsEnabled = (& $v $_ 'isEnabled'); IsSchedulingEnabled = (& $v $_ 'isSchedulingEnabled'); LastModifiedDateTime = (& $v $_ 'lastModifiedDateTime') } }) 'gov-03-lifecycle-workflows' $true
    } | Out-Null
    Invoke-PostureStep -Label 'PIM for Groups' -Folder $Folder -Script {
        # PrivilegedEligibilitySchedule.Read.AzureADGroup. The endpoint needs a groupId or principalId filter (confirmed 2026-10-15: unfiltered is BadRequest),
        # so it is read once per role-assignable group; those are the groups that carry admin roles. Capped at 100 groups.
        $candidates = @($groupRows | Where-Object { $_ -and $_.IsAssignableToRole -eq $true } | Select-Object -First 100)
        $sched = @(foreach ($g in $candidates) { & $get "identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$($g.Id)'&`$select=id,groupId,accessId,principalId,status,memberType" })
        $rows = @($sched | ForEach-Object { [ordered]@{ Id = $_.id; GroupId = (& $v $_ 'groupId'); AccessId = (& $v $_ 'accessId'); PrincipalId = (& $v $_ 'principalId'); Status = (& $v $_ 'status'); MemberType = (& $v $_ 'memberType') } })
        & $save $rows 'gov-04-pim-groups' $true
        & $saveOne ([ordered]@{ EligibleAssignments = $rows.Count; Groups = @($rows | ForEach-Object { $_.GroupId } | Where-Object { $_ } | Sort-Object -Unique).Count }) 'gov-04-pim-groups-summary'
    } | Out-Null
    Invoke-PostureStep -Label 'Administrative units' -Folder $Folder -Script {
        # AdministrativeUnit.Read.All
        $aus = & $get 'directory/administrativeUnits?$select=id,displayName,membershipType,isMemberManagementRestricted'
        & $save @($aus | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); MembershipType = (& $v $_ 'membershipType'); IsMemberManagementRestricted = (& $v $_ 'isMemberManagementRestricted') } }) 'gov-05-administrative-units' $true
    } | Out-Null

    return @{
        files  = $files.ToArray()
        errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath })
    }
}
