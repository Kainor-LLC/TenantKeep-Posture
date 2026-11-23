# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureEntraCollection {
    <#
    .SYNOPSIS
        The A.1 identity collector: organization, licensing, tenant policies, roles, authentication registration, users,
        groups, applications and Identity Protection, written with the audit plan's file names.
    .DESCRIPTION
        One step per file through Invoke-PostureStep: a permission failure lands in errors.txt and the run goes on.
        Added beyond the audit plan's A.1: 04-pim-role-policies (activation rules per role), 05-per-user-mfa (legacy
        per-user MFA state, batched reads: every member up to 5,000 or with -FullPerUserMfa, else a sample of every admin and a random 1,000 members, which the summary and the check say; -SkipPerUserMfa leaves it out), 08-entra-devices.
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
    # A list written a row at a time as its pages arrive, so none of it is held: -Row turns one Graph item ($_) into
    # the row to write, or into nothing to leave the item out. Returns how many rows were written.
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
    # A refusal or a licence the tenant does not have: the two reasons a read falls back to a lesser one. Anything
    # else (a timeout, throttling that outlasted the retries, a server error) is the step's failure, with its cause.
    $refusal = { param($e) (Get-PostureHttpStatus -ErrorRecord $e) -eq 403 -or [string]$e.Exception.Message -match '(?i)Authorization_RequestDenied|Forbidden|AccessDenied|insufficient privileges|PermissionScopeNotGranted|licen[cs]e|not licensed|premium|RequestFromNonPremiumTenant' }
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
        $domains = & $get 'domains?$select=id,isDefault,isInitial,isVerified,authenticationType,passwordValidityPeriodInDays,passwordNotificationWindowInDays'
        & $save @($domains | ForEach-Object { [ordered]@{ Id = $_.id; IsDefault = (& $v $_ 'isDefault'); IsInitial = (& $v $_ 'isInitial'); IsVerified = (& $v $_ 'isVerified'); AuthenticationType = (& $v $_ 'authenticationType'); PasswordValidityPeriodInDays = (& $v $_ 'passwordValidityPeriodInDays'); PasswordNotificationWindowInDays = (& $v $_ 'passwordNotificationWindowInDays') } }) '01-domains' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Federation settings' -Folder $Folder -Script {
        # For each federated domain: when the token-signing certificate Entra trusts runs out, whether a next one is
        # staged, and how the last automatic renewal went. The day it lapses, everyone in the domain stops signing
        # in. Only the dates and the thumbprint are kept, never the certificate. A tenant with no federated domain
        # sends nothing and writes an empty list. Domain-InternalFederation.Read.All.
        $federated = @(& $load '01-domains' | Where-Object { $_ -and [string]$_.AuthenticationType -eq 'Federated' })
        $certificate = {
            param([string] $Base64)
            if (-not $Base64) { return $null }
            try { $x = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.Convert]::FromBase64String($Base64)); try { @{ notAfter = $x.NotAfter.ToUniversalTime().ToString('o'); thumbprint = $x.Thumbprint } } finally { $x.Dispose() } }
            catch { $null }
        }
        $rows = foreach ($domain in $federated) {
            foreach ($f in @(& $get "domains/$([uri]::EscapeDataString([string]$domain.Id))/federationConfiguration")) {
                $current = & $certificate ([string](& $v $f 'signingCertificate')); $next = & $certificate ([string](& $v $f 'nextSigningCertificate'))
                [ordered]@{
                    Domain = [string]$domain.Id; DisplayName = (& $v $f 'displayName'); IssuerUri = (& $v $f 'issuerUri')
                    SigningCertificateExpiry = $(if ($current) { $current.notAfter }); SigningCertificateThumbprint = $(if ($current) { $current.thumbprint }); SigningCertificateRead = ($null -ne $current)
                    NextSigningCertificateExpiry = $(if ($next) { $next.notAfter })
                    LastCertificateUpdateResult = (& $v $f 'signingCertificateUpdateStatus.certificateUpdateResult'); LastCertificateUpdateRun = (& $v $f 'signingCertificateUpdateStatus.lastRunDateTime')
                    FederatedIdpMfaBehavior = (& $v $f 'federatedIdpMfaBehavior'); IsSignedAuthenticationRequestRequired = (& $v $f 'isSignedAuthenticationRequestRequired'); PreferredAuthenticationProtocol = (& $v $f 'preferredAuthenticationProtocol')
                }
            }
        }
        & $save @($rows) '01-federation-settings' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Company branding' -Folder $Folder -Script {
        # What the sign-in page shows, as presence only: a page with the organisation's logo and words is one users
        # learn to recognise. A tenant without branding answers 404, which means none.
        $orgId = [string](@(& $load '01-organization')[0].id)
        $b = $null
        try { $b = & $one "organization/$orgId/branding" }
        catch { if ([string]$_.Exception.Message -notmatch '404|NotFound|ResourceNotFound') { throw } }
        & $saveOne ([ordered]@{ Present = ($null -ne $b); HasBackground = [bool](& $v $b 'backgroundImageRelativeUrl'); HasBannerLogo = [bool](& $v $b 'bannerLogoRelativeUrl'); HasSquareLogo = [bool](& $v $b 'squareLogoRelativeUrl'); HasFavicon = [bool](& $v $b 'faviconRelativeUrl'); HasSignInText = [bool](& $v $b 'signInPageText'); HasUsernameHint = [bool](& $v $b 'usernameHintText') }) '01-company-branding'
    } | Out-Null
    Invoke-PostureStep -Label 'Company branding logos' -Folder $Folder -Script {
        # The organisation's own logo and icon, as its sign-in page shows them, for the top of the report and the
        # browser tab (in a redacted copy they are left out). Read only when the branding says there is one. What
        # comes back is the tenant's to choose, so it is kept only when its first bytes are those of a PNG, a JPEG,
        # a GIF or an icon, and never above half a megabyte. No check reads this.
        $branding = @(& $load '01-company-branding' | Where-Object { $_ })
        $orgId = [string](@(& $load '01-organization')[0].id)
        $kindOf = {
            param([byte[]] $Bytes)
            if ($null -eq $Bytes -or $Bytes.Length -lt 8) { return $null }
            $head = [System.BitConverter]::ToString($Bytes, 0, 8)
            if ($head.StartsWith('89-50-4E-47')) { return 'image/png' }
            if ($head.StartsWith('FF-D8-FF')) { return 'image/jpeg' }
            if ($head.StartsWith('47-49-46-38')) { return 'image/gif' }
            if ($head.StartsWith('00-00-01-00')) { return 'image/x-icon' }
            return $null
        }
        $doc = [ordered]@{}
        $wanted = [ordered]@{ BannerLogo = 'bannerLogo'; SquareLogo = 'squareLogo'; Favicon = 'favicon' }
        $has = @{ BannerLogo = 'HasBannerLogo'; SquareLogo = 'HasSquareLogo'; Favicon = 'HasFavicon' }
        if ($branding.Count -gt 0 -and $orgId) {
            foreach ($name in $wanted.get_Keys()) {
                if ((& $v $branding[0] $has[$name]) -ne $true) { continue }
                $bytes = Invoke-PostureGraphStream -Uri "organization/$orgId/branding/localizations/default/$($wanted[$name])" -ApiVersion 'v1.0'
                $type = & $kindOf $bytes
                if ($type) { $doc[$name] = [ordered]@{ ContentType = $type; Bytes = $bytes.Length; Base64 = [System.Convert]::ToBase64String($bytes) } }
            }
        }
        & $saveOne $doc '01-company-branding-logos'
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
        $skuCsv = Join-Path $Folder '01-subscribed-skus.csv'
        @($flat | ForEach-Object { [pscustomobject]$_ }) | Export-Csv -Path "$skuCsv.part"
        [System.IO.File]::Move("$skuCsv.part", $skuCsv, $true)
    } | Out-Null
    Invoke-PostureStep -Label 'Subscriptions' -Folder $Folder -Script {
        # What the tenant has bought, with what the SKU list does not say: whether it is a trial, its state
        # (Enabled, Warning for the grace period, Suspended, LockedOut, Deleted) and the date it moves to the next
        # state if nothing is done. For a paid subscription that renews by itself that date is the next renewal.
        $subs = & $get 'directory/subscriptions'
        & $save @($subs | ForEach-Object { [ordered]@{ SkuPartNumber = (& $v $_ 'skuPartNumber'); SkuId = (& $v $_ 'skuId'); Status = (& $v $_ 'status'); IsTrial = (& $v $_ 'isTrial'); TotalLicenses = (& $v $_ 'totalLicenses'); CreatedDateTime = (& $v $_ 'createdDateTime'); NextLifecycleDateTime = (& $v $_ 'nextLifecycleDateTime') } }) '01-subscriptions' $true
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

    Invoke-PostureStep -Label 'System-preferred MFA' -Folder $Folder -Script {
        # Only the beta endpoint returns systemCredentialPreferences (Microsoft offering each person their strongest
        # registered method first). The whole policy, not $select: Graph answered 400 to the $select on Kainor, 2026-11-21.
        $p = & $one 'policies/authenticationMethodsPolicy' 'beta'
        & $saveOne ([ordered]@{ State = (& $v $p 'systemCredentialPreferences.state') }) '02-auth-system-preferred'
    } | Out-Null

    Invoke-PostureStep -Label 'Directory settings' -Folder $Folder -Script {
        # Tenant-wide directory settings, among them Entra Password Protection (Password Rule Settings). The custom
        # banned password list is kept as a count: its words are often the organisation's own names.
        $settings = & $get 'groupSettings'
        & $save @($settings | ForEach-Object {
                $vals = [ordered]@{}
                foreach ($x in @(& $v $_ 'values')) { $n = [string](& $v $x 'name'); $val = [string](& $v $x 'value'); if ($n -eq 'BannedPasswordList') { $vals.BannedPasswordCount = @($val -split "[`t,;`r`n]+" | Where-Object { $_.Trim() }).Count } else { $vals[$n] = $val } }
                [ordered]@{ DisplayName = (& $v $_ 'displayName'); TemplateId = (& $v $_ 'templateId'); Values = $vals }
            }) '02-directory-settings'
    } | Out-Null

    # ---------- 3. Global Secure Access, only where licensed ----------
    # A tenant without Internet Access or Private Access answers these APIs with errors that would land in Run Health
    # on every run, so they are read only when the subscriptions carry one of them.
    $gsaOwned = @(Get-PostureOwnedFeature -Sku @(& $load '01-subscribed-skus' | Where-Object { $_ }) | Where-Object { $_ -in 'internetAccess', 'privateAccess' })
    if ($gsaOwned.Count) {
        Invoke-PostureStep -Label 'Global Secure Access forwarding profiles' -Folder $Folder -Script {
            $fp = & $get 'networkAccess/forwardingProfiles' 'beta'
            & $save @($fp | ForEach-Object { [ordered]@{ Name = (& $v $_ 'name'); TrafficForwardingType = (& $v $_ 'trafficForwardingType'); State = (& $v $_ 'state') } }) 'gsa-01-forwarding-profiles'
        } | Out-Null
        Invoke-PostureStep -Label 'Global Secure Access filtering' -Folder $Folder -Script {
            $prof = & $get 'networkAccess/filteringProfiles?$expand=policies' 'beta'
            & $save @($prof | ForEach-Object { [ordered]@{ Name = (& $v $_ 'name'); State = (& $v $_ 'state'); Priority = (& $v $_ 'priority'); Policies = @(& $v $_ 'policies').Count } }) 'gsa-02-filtering-profiles'
        } | Out-Null
        Invoke-PostureStep -Label 'Global Secure Access remote networks and signaling' -Folder $Folder -Script {
            $rn = @(& $get 'networkAccess/connectivity/remoteNetworks' 'beta')
            $sig = $(try { & $one 'networkAccess/settings/conditionalAccess' 'beta' } catch { $null })
            & $saveOne ([ordered]@{ RemoteNetworks = $rn.Count; SignalingStatus = (& $v $sig 'signalingStatus'); Licensed = $gsaOwned }) 'gsa-03-settings'
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
            if (-not (& $refusal $_)) { throw }
            Write-Warning "PIM schedule instances unavailable ($($_.Exception.Message)); falling back to roleAssignments (no eligibility data)."
            $active = & $get 'roleManagement/directory/roleAssignments?$expand=principal'
            $eligibleRows = @(); $source = 'roleAssignments'
        }
        $a = @(& $flatten $active $false); $e = @(& $flatten $eligibleRows $true)
        & $save $a '04-role-assignments-active' $true
        & $save $e '04-role-assignments-pim-eligible' $true
        & $saveOne ([ordered]@{ source = $source; active = $a.Count; eligible = $e.Count; permanentGlobalAdmins = @($a | Where-Object { $_.Role -eq 'Global Administrator' -and $_.AssignmentType -ne 'Activated' }).Count; roleDefinitions = $defs.Count }) '04-role-assignments-summary'
    } | Out-Null

    # ---------- 4a. Everyone who holds a role ----------
    # A role is held directly, as eligible, or through a group that holds it: as a member, or as someone PIM for
    # Groups lets become a member or an owner. The assignments above name the group, never its people. This step
    # reads who is in each group that holds a role and writes one row per person and role, so every admin set
    # (registration, users, sign-in tallies, the checks, the admins table) counts people.
    Invoke-PostureStep -Label 'Role holders' -Folder $Folder -Script {
        # Nothing to open when the role step did not write its file; its own error is already logged.
        if (-not (Test-Path -LiteralPath (Join-Path $Folder '04-role-assignments-active.json'))) { return }
        $assignments = @(@(& $load '04-role-assignments-active') + @(& $load '04-role-assignments-pim-eligible') | Where-Object { $_ })
        $pim = [string](& $v (& $load '04-role-assignments-summary') 'source') -eq 'pim'
        $userSelect = '$select=id,userPrincipalName,displayName,accountEnabled,onPremisesSyncEnabled&$top=999'
        $groups = @{}; $firstError = $null
        $notRead = [System.Collections.Generic.List[string]]::new(); $eligibleNotRead = [System.Collections.Generic.List[string]]::new()
        $oneLine = { param($e) (([string]$e.Exception.Message) -replace '\s*[\r\n]+\s*', ' ').Trim() }
        foreach ($a in @($assignments | Where-Object { [string]$_['PrincipalType'] -eq 'group' })) {
            $gid = [string]$a['PrincipalId']
            if (-not $gid -or $groups.ContainsKey($gid)) { continue }
            $g = @{ id = $gid; name = [string]$a['PrincipalName']; people = [System.Collections.Generic.List[object]]::new() }
            $groups[$gid] = $g
            # Members, nested groups included (Group.Read.All or Directory.Read.All). When this fails the people in
            # the group are unknown: the summary says so, the other groups are still read, and the step fails at the end.
            try { foreach ($u in (& $get "groups/$gid/transitiveMembers/microsoft.graph.user?$userSelect")) { $g.people.Add(@{ user = $u; membership = 'Member' }) } }
            catch { $g.people = $null; $notRead.Add($g.name); if (-not $firstError) { $firstError = & $oneLine $_ }; continue }
            # PIM for Groups, where the tenant has PIM: whoever can make themselves a member, or an owner who can
            # add members (PrivilegedEligibilitySchedule.Read.AzureADGroup). The principal is a person or a group.
            # (verify) live: directoryObjects/{id} answers with the derived type and its default properties.
            if (-not $pim) { continue }
            try {
                foreach ($s in (& $get "identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$gid'&`$select=id,groupId,accessId,principalId,status,memberType")) {
                    $membership = $(if ([string](& $v $s 'accessId') -eq 'owner') { 'EligibleOwner' } else { 'EligibleMember' })
                    $principalId = [string](& $v $s 'principalId')
                    if (-not $principalId) { continue }
                    $p = @(& $get "directoryObjects/$principalId")[0]
                    # Read by its key: the name has a dot in it, which Get-PostureValue would take for a path.
                    $type = [string]$(if ($p -is [System.Collections.IDictionary]) { $p['@odata.type'] })
                    if ($type -match 'group$') { foreach ($u in (& $get "groups/$principalId/transitiveMembers/microsoft.graph.user?$userSelect")) { $g.people.Add(@{ user = $u; membership = $membership }) } }
                    elseif ($type -match 'user$') { $g.people.Add(@{ user = $p; membership = $membership }) }
                }
            }
            catch { $eligibleNotRead.Add($g.name); if (-not $firstError) { $firstError = & $oneLine $_ } }
        }
        $rows = [System.Collections.Generic.List[object]]::new()
        $holder = {
            param($User, $Assignment, [string] $Held, [string] $Membership, $Group)
            if (-not (& $v $User 'userPrincipalName')) { return }
            $rows.Add([ordered]@{
                    UserId = [string](& $v $User 'id'); UserPrincipalName = (& $v $User 'userPrincipalName'); DisplayName = (& $v $User 'displayName')
                    AccountEnabled = (& $v $User 'accountEnabled'); Synced = (& $v $User 'onPremisesSyncEnabled')
                    Role = $Assignment['Role']; RoleDefinitionId = $Assignment['RoleDefinitionId']; DirectoryScopeId = $Assignment['DirectoryScopeId']; AssignmentType = $Assignment['AssignmentType']
                    Held = $Held; GroupId = $(if ($Group) { [string]$Group.id }); GroupName = $(if ($Group) { [string]$Group.name }); Membership = $Membership
                })
        }
        foreach ($a in $assignments) {
            $eligible = [string]$a['AssignmentType'] -eq 'Eligible'
            switch ([string]$a['PrincipalType']) {
                'user' { & $holder @{ id = $a['PrincipalId']; userPrincipalName = $a['PrincipalUpn']; displayName = $a['PrincipalName']; onPremisesSyncEnabled = $a['PrincipalSynced'] } $a $(if ($eligible) { 'Eligible' } else { 'Direct' }) '' $null }
                'group' {
                    $g = $groups[[string]$a['PrincipalId']]
                    if ($g -and $null -ne $g.people) { foreach ($m in $g.people) { & $holder $m.user $a $(if ($eligible -or $m.membership -ne 'Member') { 'EligibleGroup' } else { 'Group' }) $m.membership $g } }
                }
            }
        }
        $all = $rows.ToArray()
        $people = { param([string[]] $Held) @($all | Where-Object { $_.Held -in $Held } | ForEach-Object { [string]$_.UserPrincipalName } | Sort-Object -Unique) }
        $standing = @(& $people @('Direct', 'Group'))
        & $save $all '04-role-holders' $true
        & $saveOne ([ordered]@{
                Holders = @(& $people @('Direct', 'Group', 'Eligible', 'EligibleGroup')).Count
                Direct = @(& $people @('Direct')).Count; ThroughGroup = @(& $people @('Group')).Count
                EligibleOnly = @(& $people @('Eligible', 'EligibleGroup') | Where-Object { $_ -notin $standing }).Count
                GroupsHoldingRoles = $groups.get_Count(); GroupsRead = $groups.get_Count() - $notRead.Count; GroupsNotRead = @($notRead); EligibleMembersNotRead = @($eligibleNotRead)
            }) '04-role-holders-summary'
        # Both files are written; the step still counts as failed so Run Health shows what was not read.
        if ($notRead.Count -gt 0) { throw "The members of $($notRead.Count) group(s) that hold a role could not be read, so the people who hold it through them are unknown: $firstError" }
        if ($eligibleNotRead.Count -gt 0) { throw "Who can join $($eligibleNotRead.Count) group(s) that hold a role through PIM for Groups could not be read: $firstError" }
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

    # Admins: everyone who holds a role, directly, as eligible or through a group (04-role-holders). The
    # registration and users passes write admin-only files from the set, so the report and the facts never reload
    # the full lists to find admins.
    $adminUpns = (Get-PostureRoleHolder -Folder $Folder).upns
    # The long lists below are hours of reading in a large tenant. Each carries on from a cursor when a read stopped
    # part way (Invoke-PostureListRead), and each that finished in this run is kept when the run is resumed
    # (Invoke-PostureStep -KeepDone). What a list's files depend on besides the tenant goes in its key: a list
    # read under other inputs (other role holders, another -StaleDays) is read again.
    $adminKey = "admins $(Get-PostureSetKey -Value $adminUpns)"
    $keepFiles = { param($kept) foreach ($f in @($kept.files)) { $files.Add((Join-Path $Folder "$([string]$f.name).json")) } }

    # ---------- 5. Authentication method registration ----------
    # One streaming pass: rows written as they come, the summary and the strongest-method counts tallied, admin rows kept.
    Invoke-PostureStep -Label 'Auth method registration' -Folder $Folder -KeepDone -KeepKey $adminKey -WhenKept $keepFiles -Script {
        $c = @{ members = 0; mfa = 0; passwordless = 0; sspr = 0; admins = 0; adminsNotPasswordless = 0; adminsNoMfa = 0; sms = 0; fido = 0; whfb = 0 }
        $strength = [ordered]@{ PhishingResistant = 0; Passwordless = 0; Authenticator = 0; PhoneOnly = 0; None = 0 }
        # What the report reads from this list, counted here so the report never loads it (Add-PostureRegistrationTally).
        $tally = @{ Users = 0; SsprEnabled = 0; Phishable = 0; PhishableAdmins = 0 }
        $adminRows = [System.Collections.Generic.List[object]]::new()
        $read = Invoke-PostureListRead -Folder $Folder -ListName '05-auth-registration' -ListUri 'reports/authenticationMethods/userRegistrationDetails?$top=999' -ListApi 'v1.0' -ListLabel 'Registration' -ListStream '05-auth-registration' -ListKey $adminKey -ListState @{ c = $c; strength = $strength; tally = $tally; adminRows = $adminRows } -ListOnPage {
            param($page, $info, $streams)
            $stream = $streams['05-auth-registration']
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
                Add-PostureRegistrationTally -Tally $tally -Row $row -AdminUpns $adminUpns
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
        foreach ($f in $read.files) { $files.Add($f) }
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
                Tally = [ordered]@{ Users = $tally.Users; SsprEnabled = $tally.SsprEnabled; Phishable = $tally.Phishable; PhishableAdmins = $tally.PhishableAdmins }
            }) '05-auth-registration-summary'
    } | Out-Null

    # ---------- 6. Users ----------
    # One streaming pass, at any size: each page is flattened, written and counted. Nothing holds the user list, and
    # no later step takes anything from this one in memory: the per-user MFA step reads the members from the file.
    $usersKey = "$adminKey, stale $StaleDays"
    $adminUsers = [System.Collections.Generic.List[object]]::new()
    # Break-glass candidates for ID-005: every role holder (a break-glass account holds Global Administrator) and any
    # account named like one. Small, so the check never needs the full user list.
    $breakGlass = [System.Collections.Generic.List[object]]::new()
    Invoke-PostureStep -Label 'Users' -Folder $Folder -KeepDone -KeepKey $usersKey -WhenKept $keepFiles -Script {
        $base = 'id,userPrincipalName,displayName,givenName,surname,mail,accountEnabled,userType,onPremisesSyncEnabled,onPremisesSecurityIdentifier,createdDateTime,assignedLicenses,department,jobTitle,companyName,usageLocation,creationType,externalUserState'
        $c = [ordered]@{ Total = 0; Members = 0; Guests = 0; Synced = 0; CloudOnlyMembers = 0; EntraManagedFromAd = 0; Disabled = 0; DisabledWithLicenses = 0; EnabledInactiveMembers = 0; EnabledNeverSignedIn = 0; InactiveGuests = 0; PendingGuestInvites = 0; WithSignIn = 0 }
        # Which service plans each enabled user actually has: a licence's plans minus the ones switched off for that
        # user, so a feature bought but disabled for most people shows as partial. Counts only, from the SKU file.
        $skuPlans = @{}
        foreach ($s in @(& $load '01-subscribed-skus' | Where-Object { $_ })) {
            $skuPlans[[string](& $v $s 'skuId')] = @(& $v $s 'servicePlans' | Where-Object { $_ -and (& $v $_ 'provisioningStatus') -ne 'Disabled' } | ForEach-Object { @{ id = [string](& $v $_ 'servicePlanId'); name = [string](& $v $_ 'servicePlanName') } })
        }
        # A hashtable, like $c: the page handler runs in a child scope, where a plain counter would not stick.
        $planUse = @{}; $licensing = @{ enabled = 0 }
        $read = {
            param([string] $Select)
            # Two lists from one pass: every user, and the guests alone with the columns ID-012 reads, so the
            # inactive guest check reads that instead of every user.
            $got = Invoke-PostureListRead -Folder $Folder -ListName '06-users' -ListUri "users?`$select=$Select&`$top=999" -ListApi 'v1.0' -ListLabel 'Users' -ListStream '06-users', '06-users-guests' -ListKey $usersKey -ListState @{ c = $c; planUse = $planUse; licensing = $licensing; adminUsers = $adminUsers; breakGlass = $breakGlass } -ListOnPage {
                param($page, $info, $streams)
                $stream = $streams['06-users']; $guestStream = $streams['06-users-guests']
                foreach ($u in $page) {
                    $sia = $(if ($u.ContainsKey('signInActivity')) { $u['signInActivity'] } else { $null })
                    $last = $(if ($sia) { $sia['lastSignInDateTime'] } else { $null })
                    $licences = $(if ($u.ContainsKey('assignedLicenses')) { @($u['assignedLicenses']).Count } else { 0 })
                    $row = [ordered]@{
                        Id = $u['id']; UserPrincipalName = $u['userPrincipalName']; DisplayName = $u['displayName']; GivenName = $u['givenName']; Surname = $u['surname']; Mail = $u['mail']; AccountEnabled = $u['accountEnabled']; UserType = $u['userType']
                        OnPremisesSyncEnabled = [bool]$u['onPremisesSyncEnabled']; Source = (Get-PostureObjectSource -Object $u); CreatedDateTime = $u['createdDateTime']; Department = $u['department']; JobTitle = $u['jobTitle']
                        CompanyName = $u['companyName']; UsageLocation = $u['usageLocation']; CreationType = $u['creationType']; ExternalUserState = $u['externalUserState']
                        LicenseCount = $licences; LastInteractiveSignIn = $last; LastNonInteractiveSignIn = $(if ($sia) { $sia['lastNonInteractiveSignInDateTime'] } else { $null })
                    }
                    Add-PostureEvidenceRow -Stream $stream -Row $row
                    if ($licences -gt 0 -and $row.AccountEnabled) {
                        $licensing.enabled++
                        $userPlans = [System.Collections.Generic.HashSet[string]]::new()
                        foreach ($al in @($u['assignedLicenses'])) {
                            $off = @($al['disabledPlans'] | ForEach-Object { [string]$_ })
                            foreach ($sp in @($skuPlans[[string]$al['skuId']])) { if ($sp -and $sp.id -notin $off) { $null = $userPlans.Add($sp.name) } }
                        }
                        foreach ($n in $userPlans) { $planUse[$n] = 1 + $(if ($planUse.ContainsKey($n)) { $planUse[$n] } else { 0 }) }
                    }
                    $isAdmin = $adminUpns.Contains([string]$row.UserPrincipalName)
                    if ($isAdmin) { $adminUsers.Add($row) }
                    if ($isAdmin -or [string]$row.UserPrincipalName -match '(?i)break.?glass|emergency' -or [string]$row.DisplayName -match '(?i)break.?glass|emergency') { $breakGlass.Add($row) }
                    if ($row.UserType -eq 'Guest') { Add-PostureEvidenceRow -Stream $guestStream -Row ([ordered]@{ Id = $row.Id; UserPrincipalName = $row.UserPrincipalName; DisplayName = $row.DisplayName; AccountEnabled = $row.AccountEnabled; CreatedDateTime = $row.CreatedDateTime; ExternalUserState = $row.ExternalUserState; LastInteractiveSignIn = $row.LastInteractiveSignIn }) }
                    $member = $row.UserType -eq 'Member'; $guest = $row.UserType -eq 'Guest'; $enabled = [bool]$row.AccountEnabled
                    $old = $(if ($last) { (& $date $last) -lt $cutoff } else { $false })
                    $c.Total++
                    if ($member) { $c.Members++ }
                    if ($guest) { $c.Guests++ }
                    if ($row.OnPremisesSyncEnabled) { $c.Synced++ } elseif ($member) { $c.CloudOnlyMembers++ }
                    if ($member -and $row.Source -eq 'EntraFromAD') { $c.EntraManagedFromAd++ }
                    if (-not $enabled) { $c.Disabled++; if ($licences -gt 0) { $c.DisabledWithLicenses++ } }
                    if ($enabled -and $member) { if (-not $last) { $c.EnabledNeverSignedIn++ } elseif ($old) { $c.EnabledInactiveMembers++ } }
                    if ($guest -and (-not $last -or $old)) { $c.InactiveGuests++ }
                    if ($row.ExternalUserState -eq 'PendingAcceptance') { $c.PendingGuestInvites++ }
                    if ($last) { $c.WithSignIn++ }
                }
            }
            foreach ($f in $got.files) { $files.Add($f) }
        }
        # A read that stopped part way carries on with the request it was making: when that was the one without
        # signInActivity (the first had been refused), the first is not tried again.
        $usersCursor = Get-PostureListCursor -Folder $Folder -ListName '06-users'
        if ($usersCursor -and [string]$usersCursor['uri'] -eq "users?`$select=$base&`$top=999" -and [string]$usersCursor['key'] -eq $usersKey) { & $read $base }
        else {
            try { & $read "$base,signInActivity" }
            catch {
                if (-not (& $refusal $_)) { throw }
                Write-Warning "Users with signInActivity failed ($($_.Exception.Message)); reading them again without it (needs AuditLog.Read.All and Entra ID P1)."
                foreach ($k in @($c.get_Keys())) { $c[$k] = 0 }
                $planUse.Clear(); $licensing.enabled = 0
                $adminUsers.Clear(); $breakGlass.Clear()
                & $read $base
            }
        }
        & $save @($adminUsers) '06-users-admins'
        & $save @($breakGlass) '06-users-breakglass-candidates'
        $summary = [ordered]@{}
        foreach ($k in 'Total', 'Members', 'Guests', 'Synced', 'CloudOnlyMembers', 'Disabled', 'DisabledWithLicenses', 'EnabledInactiveMembers', 'EnabledNeverSignedIn', 'InactiveGuests', 'PendingGuestInvites') { $summary[$k] = $c[$k] }
        $summary.SignInActivityAvailable = $c.WithSignIn -gt 0
        $summary.StaleDays = $StaleDays
        & $saveOne $summary '06-users-summary'
        $planRows = [ordered]@{}; foreach ($k in @($planUse.Keys | Sort-Object)) { $planRows[$k] = $planUse[$k] }
        & $saveOne ([ordered]@{ LicensedEnabledUsers = $licensing.enabled; UsersByServicePlan = $planRows }) '06-users-license-plans'
    } | Out-Null

    # ---------- 6b. Legacy per-user MFA state (AU-009) ----------
    if (-not $SkipPerUserMfa) {
        Invoke-PostureStep -Label 'Per-user MFA state' -Folder $Folder -KeepDone -KeepKey "$usersKey, full $([bool]$FullPerUserMfa)" -WhenKept $keepFiles -Script {
            # One read per user, batched 20 at a time through $batch. authentication/requirements is beta-only (confirmed 2026-10-14).
            # (verify) scope: UserAuthenticationMethod.Read.All
            # The members, from the user list on disk a row at a time: an id and a name each is all that is held.
            # Without the list there is no one to ask about, and the step says so; it never writes a summary of zero.
            $members = [System.Collections.Generic.List[object]]::new()
            $haveUsers = Read-PostureEvidenceRow -Folder $Folder -Name '06-users' -OnRow { param($u) if ([string](& $v $u 'UserType') -eq 'Member') { $members.Add(@{ Id = [string](& $v $u 'Id'); UserPrincipalName = [string](& $v $u 'UserPrincipalName') }) } }
            if (-not $haveUsers) { throw 'The user list (06-users) was not collected, so there is no one to read the per-user MFA state of.' }
            # Rows are written and counted as each batch answers; nothing is held for the whole tenant.
            $tally = @{ rows = 0; enforced = 0; enabled = 0; disabled = 0; errors = 0; firstError = $null }
            $stream = Open-PostureEvidenceStream -Folder $Folder -Name '05-per-user-mfa' -Csv -Confirm:$false
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
                            $row = [ordered]@{ UserPrincipalName = $m.UserPrincipalName; Status = $status; PerUserMfaState = (& $v $resp 'body.perUserMfaState'); Error = (& $v $resp 'body.error.message') }
                            Add-PostureEvidenceRow -Stream $stream -Row $row
                            $tally.rows++
                            if ($status -ge 400) { $tally.errors++; if (-not $tally.firstError) { $tally.firstError = "$status $($row.Error)" } }
                            switch ([string]$row.PerUserMfaState) { 'enforced' { $tally.enforced++ } 'enabled' { $tally.enabled++ } 'disabled' { $tally.disabled++ } }
                        }
                        $pending = @($again)
                        if ($pending.Count -gt 0) {
                            $delay = [Math]::Min($script:PostureGraphRetry.maxWaitSeconds, [Math]::Max($wait, $script:PostureGraphRetry.baseSeconds * [Math]::Pow(2, $try - 1)))
                            if ($delay -gt 0) { Start-Sleep -Seconds $delay }
                        }
                    }
                    # After every batch: the display draws at most four times a second by itself. Every 500 accounts, as it
                    # was, left a sample of 1,000 standing at "20 of 1,004" for most of the step.
                    if ($script:PostureProgress) { $script:PostureProgress.label = "Per-user MFA state: $('{0:N0}' -f $tally.rows) of $('{0:N0}' -f $members.Count) accounts"; Write-PostureProgress }
                }
            }
            # Per-user MFA is legacy and Microsoft is retiring it, so most tenants have none. Up to 5,000 members, or with
            # -FullPerUserMfa, every member is read. Above that the read is a sample, and the summary says so: every
            # administrator and 1,000 other members at random. None among 1,000 puts the rate under 0.3% (95%); one
            # among them fails the check on the sample. Reading everyone takes a request per account, hours on a
            # tenant of hundreds of thousands, so it happens only when it is asked for.
            $mode = 'full'; $sampleSize = $members.Count; $sampledAdmins = $null; $sampledMembers = $null
            try {
                if ($FullPerUserMfa -or $members.Count -le 5000) { & $scan $members }
                else {
                    $admins = @($members | Where-Object { $adminUpns.Contains([string]$_.UserPrincipalName) })
                    $rest = @($members | Where-Object { -not $adminUpns.Contains([string]$_.UserPrincipalName) })
                    $sample = @($admins) + @($rest | Get-Random -Count ([Math]::Min(1000, $rest.Count)))
                    & $scan $sample
                    $mode = 'sample'; $sampleSize = $sample.Count; $sampledAdmins = $admins.Count; $sampledMembers = $sample.Count - $admins.Count
                }
                $files.Add((Close-PostureEvidenceStream -Stream $stream))
            }
            catch { Stop-PostureEvidenceStream -Stream $stream -Confirm:$false; throw }
            & $saveOne ([ordered]@{
                    Users = $tally.rows; Members = $members.Count; Mode = $mode; SampleSize = $sampleSize; SampledAdmins = $sampledAdmins; SampledMembers = $sampledMembers
                    Enforced = $tally.enforced; Enabled = $tally.enabled; Disabled = $tally.disabled; Errors = $tally.errors; FirstError = $tally.firstError
                }) '05-per-user-mfa-summary'
        } | Out-Null
    }

    # ---------- 6c. SharePoint tenant settings through Graph ----------
    # Beside the PnP read (which needs SharePoint Administrator): Graph's admin/sharepoint/settings may answer to Global
    # Reader. Written as Graph sends it, to compare on a live run before any check moves to it (verify).
    Invoke-PostureStep -Label 'SharePoint tenant settings (Graph)' -Folder $Folder -Script {
        $context = Get-MgContext
        if ($context -and 'SharePointTenantSettings.Read.All' -notin @($context.Scopes)) {
            if ([string]$context.AuthType -eq 'Delegated') { throw 'missing scope SharePointTenantSettings.Read.All: the tenant consented to the TenantKeep app before this permission was added; an admin consents again to add it.' }
            throw 'missing scope SharePointTenantSettings.Read.All: the identity that runs this was granted its roles before this one was added. Run deploy/automation/Grant-ManagedIdentityGraphRole.ps1 -IncludePosture again; a role reaches a running identity within a day.'
        }
        & $saveOne (Invoke-PostureGraphRequest -Uri 'admin/sharepoint/settings' -ApiVersion 'v1.0' -Single) 'spo-tenant-settings-graph'
    } | Out-Null

    # ---------- 7. Groups ----------
    Invoke-PostureStep -Label 'Group lifecycle policy' -Folder $Folder -Script {
        # Spec 4.6: the Microsoft 365 group expiration policy. One policy per tenant, or none.
        $p = @(& $get 'groupLifecyclePolicies')
        & $saveOne $(if ($p.Count -gt 0) { [ordered]@{ Present = $true; GroupLifetimeInDays = (& $v $p[0] 'groupLifetimeInDays'); ManagedGroupTypes = (& $v $p[0] 'managedGroupTypes'); AlternateNotificationEmails = (& $v $p[0] 'alternateNotificationEmails') } } else { [ordered]@{ Present = $false } }) '02-group-lifecycle-policy'
    } | Out-Null

    Invoke-PostureStep -Label 'Ownerless Microsoft 365 groups' -Folder $Folder -Script {
        # Owners expanded with ids only; a group with none is a team or site nobody can administer.
        # Paged; a group with owners is counted and let go.
        $seen = @{ unified = 0 }
        $ownerless = & $streamed 'groups?$filter=groupTypes/any(c:c eq ''Unified'')&$select=id,displayName,createdDateTime,visibility&$expand=owners($select=id)' '07-groups-ownerless' {
            $seen.unified++
            if (@(& $v $_ 'owners').Count -eq 0) { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); CreatedDateTime = (& $v $_ 'createdDateTime'); Visibility = (& $v $_ 'visibility') } }
        }
        & $saveOne ([ordered]@{ UnifiedGroups = $seen.unified; Ownerless = $ownerless }) '07-groups-ownerless-summary'
    } | Out-Null

    # Streamed. The PIM for Groups step reads the role-assignable groups from the file.
    Invoke-PostureStep -Label 'Groups' -Folder $Folder -KeepDone -WhenKept $keepFiles -Script {
        # Counted as the list is written, so the report reads a handful of numbers and never the list.
        $tally = @{ groups = 0; byKind = [ordered]@{}; roleAssignable = 0; synced = 0; licensed = 0; dynamic = 0 }
        $read = Invoke-PostureListRead -Folder $Folder -ListName '07-groups' -ListUri 'groups?$select=id,displayName,groupTypes,mailEnabled,securityEnabled,onPremisesSyncEnabled,onPremisesSecurityIdentifier,assignedLicenses,membershipRule,membershipRuleProcessingState,createdDateTime,visibility,isAssignableToRole,expirationDateTime&$top=999' -ListApi 'v1.0' -ListLabel 'Groups' -ListStream '07-groups' -ListState @{ tally = $tally } -ListOnPage {
            param($page, $info, $streams)
            $stream = $streams['07-groups']
            foreach ($g in $page) {
                $types = @($g['groupTypes'])
                $kind = if ($types -contains 'Unified') { 'M365' } elseif ($types -contains 'DynamicMembership') { 'DynamicSecurity' } elseif ($g['mailEnabled'] -and $g['securityEnabled']) { 'MailEnabledSecurity' } elseif ($g['mailEnabled']) { 'Distribution' } else { 'Security' }
                $row = [ordered]@{
                    Id = $g['id']; DisplayName = $g['displayName']; OnPremisesSyncEnabled = [bool]$g['onPremisesSyncEnabled']; Source = (Get-PostureObjectSource -Object $g); Licensed = (@($g['assignedLicenses'] | Where-Object { $_ }).Count -gt 0); CreatedDateTime = $g['createdDateTime']
                    Visibility = $g['visibility']; IsAssignableToRole = [bool]$g['isAssignableToRole']; ExpirationDateTime = $g['expirationDateTime']; MembershipRule = $g['membershipRule']
                    Kind = $kind; Dynamic = ($types -contains 'DynamicMembership')
                }
                Add-PostureEvidenceRow -Stream $stream -Row $row
                if ($row.IsAssignableToRole) { $tally.roleAssignable++ }
                $tally.groups++
                $tally.byKind[$kind] = 1 + $(if ($tally.byKind.Contains($kind)) { $tally.byKind[$kind] } else { 0 })
                if ($row.OnPremisesSyncEnabled) { $tally.synced++ }
                if ($row.Licensed) { $tally.licensed++ }
                if ($row.Dynamic) { $tally.dynamic++ }
            }
        }
        foreach ($f in $read.files) { $files.Add($f) }
        & $saveOne ([ordered]@{ Groups = $tally.groups; ByKind = $tally.byKind; RoleAssignable = $tally.roleAssignable; Synced = $tally.synced; Licensed = $tally.licensed; Dynamic = $tally.dynamic }) '07-groups-summary'
    } | Out-Null

    # ---------- 8. Entra devices ----------
    # Streamed, with the join type and staleness counts tallied in the same pass.
    Invoke-PostureStep -Label 'Entra devices' -Folder $Folder -KeepDone -KeepKey "stale $StaleDays" -WhenKept $keepFiles -Script {
        $byJoinOs = @{}; $byJoinStale = @{}
        $read = Invoke-PostureListRead -Folder $Folder -ListName '08-entra-devices' -ListUri 'devices?$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,approximateLastSignInDateTime,isCompliant,isManaged,accountEnabled,registrationDateTime,profileType,managementType,enrollmentType&$top=999' -ListApi 'v1.0' -ListLabel 'Entra devices' -ListStream '08-entra-devices' -ListKey "stale $StaleDays" -ListState @{ byJoinOs = $byJoinOs; byJoinStale = $byJoinStale } -ListOnPage {
            param($page, $info, $streams)
            $stream = $streams['08-entra-devices']
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
        foreach ($f in $read.files) { $files.Add($f) }
        # Same shape Group-Object gave: Name "JoinType, OperatingSystem" and Count, largest first.
        $rows = { param([hashtable] $Map) @($Map.Keys | ForEach-Object { [ordered]@{ Name = $_; Count = $Map[$_] } } | Sort-Object { - $_.Count }) }
        & $save (& $rows $byJoinOs) '08-entra-devices-by-join-os' $true
        & $save (& $rows $byJoinStale) '08-entra-devices-stale' $true
    } | Out-Null

    # ---------- 10. Applications and service principals ----------
    Invoke-PostureStep -Label 'App registrations' -Folder $Folder -Script {
        $null = & $streamed 'applications?$select=id,appId,displayName,signInAudience,createdDateTime,passwordCredentials,keyCredentials,publisherDomain&$top=999' '10-app-registrations' {
            $ends = @(@(& $v $_ 'passwordCredentials') + @(& $v $_ 'keyCredentials') | ForEach-Object { & $date (& $v $_ 'endDateTime') } | Where-Object { $_ })
            [ordered]@{
                Id = $_.id; AppId = $_.appId; DisplayName = (& $v $_ 'displayName'); SignInAudience = (& $v $_ 'signInAudience'); PublisherDomain = (& $v $_ 'publisherDomain'); CreatedDateTime = (& $v $_ 'createdDateTime')
                Secrets = @(& $v $_ 'passwordCredentials').Count; Certs = @(& $v $_ 'keyCredentials').Count
                EarliestExpiry = $(if ($ends.Count -gt 0) { ($ends | Sort-Object | Select-Object -First 1).ToString('o') } else { $null })
                ExpiredCredentials = @($ends | Where-Object { $_ -lt $AsOf }).Count
            }
        }
    } | Out-Null
    Invoke-PostureStep -Label 'Service principals' -Folder $Folder -Script {
        $tenantId = [string](Get-MgContext).TenantId
        $null = & $streamed 'servicePrincipals?$select=id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId,preferredSingleSignOnMode,signInAudience,tags,keyCredentials,passwordCredentials,createdDateTime,appRoleAssignmentRequired&$expand=owners($select=id)&$top=999' '10-service-principals' {
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
        }
    } | Out-Null
    Invoke-PostureStep -Label 'Graph application permissions' -Folder $Folder -Script {
        $graphSp = @(& $get "servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles")[0]
        $roleMap = @{}; foreach ($r in @(& $v $graphSp 'appRoles')) { $roleMap[[string]$r.id] = [string]$r.value }
        $grants = & $get "servicePrincipals/$($graphSp.id)/appRoleAssignedTo?`$top=999"
        $flat = @($grants | ForEach-Object { [ordered]@{ PrincipalDisplayName = (& $v $_ 'principalDisplayName'); PrincipalId = (& $v $_ 'principalId'); PrincipalType = (& $v $_ 'principalType'); Permission = $roleMap[[string](& $v $_ 'appRoleId')]; CreatedDateTime = (& $v $_ 'createdDateTime') } } | Sort-Object { $_.Permission })
        & $save $flat '10-graph-app-permissions' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Application sign-in activity' -Folder $Folder -Script {
        # When each application last signed in, as itself or for a user, as the client or as the resource: one row
        # for each application Entra has seen sign in. AuditLog.Read.All; beta only. An application that is not in
        # the list has no sign-in on record. (verify) how far back the record goes on a live tenant.
        $null = & $streamed 'reports/servicePrincipalSignInActivities' '10-app-signin-activity' {
            # The latest of the kinds of sign-in the report keeps apart.
            $last = $null
            foreach ($kind in 'lastSignInActivity', 'delegatedClientSignInActivity', 'delegatedResourceSignInActivity', 'applicationAuthenticationClientSignInActivity', 'applicationAuthenticationResourceSignInActivity') {
                $when = & $date (& $v $_ "$kind.lastSignInDateTime")
                if ($when -and (-not $last -or $when -gt $last)) { $last = $when }
            }
            [ordered]@{ AppId = (& $v $_ 'appId'); LastSignIn = $(if ($last) { $last.ToString('o') } else { $null }) }
        } 'beta'
    } | Out-Null
    Invoke-PostureStep -Label 'Delegated OAuth2 grants' -Folder $Folder -Script {
        # Every delegated grant, hundreds of thousands where user consent was ever open: written as the pages arrive.
        $null = & $streamed 'oauth2PermissionGrants?$top=999' '10-oauth2-delegated-grants' { [ordered]@{ ClientId = (& $v $_ 'clientId'); ConsentType = (& $v $_ 'consentType'); PrincipalId = (& $v $_ 'principalId'); ResourceId = (& $v $_ 'resourceId'); Scope = (& $v $_ 'scope') } }
    } | Out-Null

    # ---------- 11. Identity Protection (P2; fails gracefully) ----------
    Invoke-PostureStep -Label 'Risky users' -Folder $Folder -Script {
        # The users at risk now, not everyone who ever had a risk: the list is the open cases, which is what ID-015
        # and the chart read. Remediated and dismissed users stay out of it.
        $null = & $streamed "identityProtection/riskyUsers?`$filter=riskState eq 'atRisk' or riskState eq 'confirmedCompromised'&`$top=500" '11-risky-users' { [ordered]@{ UserPrincipalName = (& $v $_ 'userPrincipalName'); RiskLevel = (& $v $_ 'riskLevel'); RiskState = (& $v $_ 'riskState'); RiskDetail = (& $v $_ 'riskDetail'); RiskLastUpdatedDateTime = (& $v $_ 'riskLastUpdatedDateTime'); IsDeleted = (& $v $_ 'isDeleted'); IsProcessing = (& $v $_ 'isProcessing') } }
    } | Out-Null
    Invoke-PostureStep -Label 'Risk detections' -Folder $Folder -Script {
        $since = $AsOf.AddDays(-$RiskDetectionDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $null = & $streamed "identityProtection/riskDetections?`$filter=activityDateTime ge $since&`$top=500" "11-risk-detections-$($RiskDetectionDays)d" { [ordered]@{ UserPrincipalName = (& $v $_ 'userPrincipalName'); RiskEventType = (& $v $_ 'riskEventType'); RiskLevel = (& $v $_ 'riskLevel'); RiskState = (& $v $_ 'riskState'); RiskDetail = (& $v $_ 'riskDetail'); DetectionTimingType = (& $v $_ 'detectionTimingType'); ActivityDateTime = (& $v $_ 'activityDateTime'); IPAddress = (& $v $_ 'ipAddress'); Country = (& $v $_ 'location.countryOrRegion') } }
    } | Out-Null

    $errorsPath = Join-Path (Get-PostureRunLayout -Folder $Folder).errors 'errors.txt'
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
        # so it is read once per role-assignable group; those are the groups that carry admin roles (the service
        # limit is 500 per tenant (verify)). Every one is read; the summary says how many, so a short read is never
        # taken for all.
        # From the group list on disk. Without it the role-assignable groups are not known, and the step says so; it
        # never writes "none".
        $candidates = [System.Collections.Generic.List[object]]::new()
        $haveGroups = Read-PostureEvidenceRow -Folder $Folder -Name '07-groups' -OnRow { param($g) if ([string](& $v $g 'IsAssignableToRole') -eq 'True') { $candidates.Add(@{ Id = [string](& $v $g 'Id') }) } }
        if (-not $haveGroups) { throw 'The group list (07-groups) was not collected, so the role-assignable groups are not known.' }
        # Twenty groups to a request ($batch). A group whose read is refused counts as not read, and the step fails
        # after the others are written, so one group never costs the rest.
        $answers = @(Invoke-PostureGraphBatch -Url @($candidates | ForEach-Object { "identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$($_.Id)'&`$select=id,groupId,accessId,principalId,status,memberType" }) -ApiVersion 'v1.0' -Label 'PIM for Groups')
        $refused = @($answers | Where-Object { $_.status -ge 400 -or $_.status -eq 0 })
        $sched = @($answers | Where-Object { $_.status -gt 0 -and $_.status -lt 400 } | ForEach-Object { @(Get-PostureValue $_.body 'value') } | Where-Object { $_ })
        $rows = @($sched | ForEach-Object { [ordered]@{ Id = $_.id; GroupId = (& $v $_ 'groupId'); AccessId = (& $v $_ 'accessId'); PrincipalId = (& $v $_ 'principalId'); Status = (& $v $_ 'status'); MemberType = (& $v $_ 'memberType') } })
        & $save $rows 'gov-04-pim-groups' $true
        & $saveOne ([ordered]@{ EligibleAssignments = $rows.Count; Groups = @($rows | ForEach-Object { $_.GroupId } | Where-Object { $_ } | Sort-Object -Unique).Count; RoleAssignableGroups = $candidates.Count; GroupsRead = $candidates.Count - $refused.Count }) 'gov-04-pim-groups-summary'
        if ($refused.Count -gt 0) { throw "PIM for Groups could not be read for $($refused.Count) of $($candidates.Count) role-assignable groups: $($refused[0].status) $($refused[0].error)" }
    } | Out-Null
    Invoke-PostureStep -Label 'Administrative units' -Folder $Folder -Script {
        # AdministrativeUnit.Read.All
        $aus = & $get 'directory/administrativeUnits?$select=id,displayName,membershipType,isMemberManagementRestricted'
        & $save @($aus | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); MembershipType = (& $v $_ 'membershipType'); IsMemberManagementRestricted = (& $v $_ 'isMemberManagementRestricted') } }) 'gov-05-administrative-units' $true
    } | Out-Null

    # ---------- 12. Microsoft's own notices: service health and the Message Center ----------
    Invoke-PostureStep -Label 'Service health' -Folder $Folder -Script {
        # The incidents and advisories Microsoft has open for this tenant now. They are Microsoft's to fix, not a
        # finding; Run Health lists them, since an incident on the day of a run explains a read that failed.
        # ServiceHealth.Read.All.
        # Asked for the open ones; when Graph will not take the filter, every issue is read and the open ones kept.
        $issues = $(try { & $get 'admin/serviceAnnouncement/issues?$filter=isResolved eq false' } catch { if ((Get-PostureHttpStatus -ErrorRecord $_) -ne 400) { throw }; & $get 'admin/serviceAnnouncement/issues' })
        & $save @($issues | Where-Object { (& $v $_ 'isResolved') -ne $true } | ForEach-Object { [ordered]@{ Id = $_.id; Title = (& $v $_ 'title'); Service = (& $v $_ 'service'); Feature = (& $v $_ 'feature'); Classification = (& $v $_ 'classification'); Status = (& $v $_ 'status'); StartDateTime = (& $v $_ 'startDateTime'); LastModifiedDateTime = (& $v $_ 'lastModifiedDateTime') } }) '12-service-health' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Message Center' -Folder $Folder -Script {
        # The Message Center posts that carry a date to act by. Every post is read (a few hundred, a hundred to a
        # page) and counted; the ones with a date that is still ahead, or passed in the last 30 days, are kept.
        # ServiceMessage.Read.All.
        $seen = @{ posts = 0; major = 0 }
        $keepFrom = $AsOf.AddDays(-30)
        $due = [System.Collections.Generic.List[object]]::new()
        $null = Invoke-PostureGraphRequest -Uri 'admin/serviceAnnouncement/messages' -ApiVersion 'v1.0' -Label 'Message Center' -OnPage {
            param($page)
            foreach ($m in $page) {
                $seen.posts++
                if ((& $v $m 'isMajorChange') -eq $true) { $seen.major++ }
                $by = & $date (& $v $m 'actionRequiredByDateTime')
                if (-not $by -or $by -lt $keepFrom) { continue }
                $due.Add([ordered]@{ Id = $m['id']; Title = (& $v $m 'title'); Category = (& $v $m 'category'); Severity = (& $v $m 'severity'); IsMajorChange = (& $v $m 'isMajorChange'); ActionRequiredByDateTime = $by.ToString('o'); Services = (@(& $v $m 'services' | Where-Object { $_ }) -join ';'); LastModifiedDateTime = (& $v $m 'lastModifiedDateTime') })
            }
        }
        & $save @($due | Sort-Object { $_.ActionRequiredByDateTime }) '12-message-center' $true
        & $saveOne ([ordered]@{ Posts = $seen.posts; MajorChanges = $seen.major; WithActionDate = $due.Count }) '12-message-center-summary'
    } | Out-Null

    # ---------- 13. Defender for Identity (hybrid tenants) ----------
    # Its sensors sit on the domain controllers, so a tenant that does not sync from a domain is not asked: the
    # read would only say that there is no Defender for Identity here. SecurityIdentitiesHealth.Read.All.
    $syncs = $false
    foreach ($o in @(& $load '01-organization' | Where-Object { $_ })) { if ((& $v $o 'onPremisesSyncEnabled') -eq $true) { $syncs = $true } }
    if ($syncs) {
        Invoke-PostureStep -Label 'Defender for Identity health' -Folder $Folder -Script {
            $open = & $get "security/identities/healthIssues?`$filter=status eq 'open'"
            & $save @($open | Where-Object { [string](& $v $_ 'status') -eq 'open' } | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); HealthIssueType = (& $v $_ 'healthIssueType'); Severity = (& $v $_ 'severity'); Status = (& $v $_ 'status'); CreatedDateTime = (& $v $_ 'createdDateTime'); LastModifiedDateTime = (& $v $_ 'lastModifiedDateTime'); Domains = (@(& $v $_ 'domainNames' | Where-Object { $_ }) -join ';'); Sensors = (@(& $v $_ 'sensorDNSNames' | Where-Object { $_ }) -join ';') } }) '13-mdi-health-issues' $true
        } | Out-Null
    }

    return @{
        files  = $files.ToArray()
        errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath })
    }
}
