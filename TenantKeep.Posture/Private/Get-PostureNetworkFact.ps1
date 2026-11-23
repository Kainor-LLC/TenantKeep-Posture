# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureNetworkFact {
    <#
    .SYNOPSIS
        Fact provider for the network domain: Global Secure Access (Entra Internet Access and Private Access). Which
        traffic forwarding profiles are on and who gets them, what the security profiles do to internet traffic
        (web filtering, threat intelligence, TLS inspection, file and prompt policies), how Private Access
        applications are assigned and protected, and what Conditional Access is told about the network.
    .DESCRIPTION
        The Entra collector reads Global Secure Access only where the tenant holds Internet Access or Private Access,
        so a tenant without either has no evidence here; the checks then read as needing the licence, or as covered
        when the profile names another secure web gateway (swg) or ZTNA vendor.

        A security profile applies when it is on and is either the baseline profile, which covers all traffic, or
        handed out by at least one Conditional Access policy. A policy linked to a profile that applies to nobody
        protects nobody, so the checks on what is filtered look only at links that are on, on profiles that apply.

        A setting the collector could not read is empty in the evidence, and the check that needs it has no answer.
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
    $t = @{ tlsCertificateWarningDays = 90; tlsBypassReviewDays = 90 }
    foreach ($k in @($Thresholds.Keys)) { $t[$k] = $Thresholds[$k] }
    $load = { param([string] $Name) Read-PostureEvidenceFile -Folder $Evidence -Name $Name }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $fp = & $load 'gsa-01-forwarding-profiles'
    if ($null -eq $fp) { return @{ available = $false; reason = 'Global Secure Access was not read: the tenant holds no Internet Access or Private Access licence, or NetworkAccess.Read.All was not consented.' } }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    $again = 'Collect Entra again with this version (Resume-PostureRun -Collector Entra) and check errors.txt.'
    $missing = { param([string[]] $Ids, [string] $File) foreach ($id in $Ids) { $notEvaluated[$id] = "$File.json was not collected. $again" } }
    $unread = { param([string[]] $Ids, [string] $What) foreach ($id in $Ids) { $notEvaluated[$id] = "$What could not be read. $again" } }
    $enabled = { param($o) [string](& $v $o 'State') -eq 'enabled' }

    # ---- Forwarding profiles: which are on (NET-001 to NET-003), and whether one that asks for an assignment has anyone assigned (NET-016) ----
    $profilesOn = @($fp | Where-Object { $_ -and (& $enabled $_) })
    $on = { param([string] $type) @($profilesOn | Where-Object { [string](& $v $_ 'TrafficForwardingType') -eq $type }).Count -gt 0 }
    $facts.microsoftProfileEnabled = & $on 'm365'
    $facts.internetProfileEnabled = & $on 'internet'
    $facts.privateProfileEnabled = & $on 'private'
    if ($profilesOn.Count -eq 0) { $notEvaluated['NET-016'] = 'No traffic forwarding profile is on; NET-001 to NET-003 ask for them.' }
    else {
        $known = @($profilesOn | Where-Object { $null -ne (& $v $_ 'AssignmentRequired') -and $null -ne (& $v $_ 'Assigned') })
        # On, asking for an assignment, and nobody assigned: the profile reaches no one.
        $empty = @($known | Where-Object { (& $v $_ 'AssignmentRequired') -eq $true -and (& $v $_ 'Assigned') -ne $true })
        $facts.forwardingProfilesUnassigned = $(if ($empty.Count -gt 0) { $empty.Count } elseif ($known.Count -lt $profilesOn.Count) { $null } else { 0 })
        $affected.forwardingProfilesUnassigned = @($empty | ForEach-Object { [ordered]@{ name = [string](& $v $_ 'Name'); detail = 'on, with nobody assigned' } })
        if ($null -eq $facts.forwardingProfilesUnassigned) { $notEvaluated['NET-016'] = "Who the forwarding profiles are assigned to could not be read. $again" }
    }

    $fprof = & $load 'gsa-02-filtering-profiles'
    if ($null -eq $fprof) { $notEvaluated['NET-002'] = 'gsa-02-filtering-profiles.json was not collected (check errors.txt).' }
    else { $facts.webFilteringPolicies = [int](@($fprof | Where-Object { $_ -and [string](& $v $_ 'State') -eq 'enabled' } | ForEach-Object { [int](& $v $_ 'Policies') }) + 0 | Measure-Object -Sum).Sum }

    # ---- Tenant settings: signaling (NET-004), tenant restrictions (NET-017), private networks (NET-022), deployments (NET-023) ----
    $st = & $load 'gsa-03-settings'
    if ($null -eq $st -or $null -eq (& $v $st 'SignalingStatus')) { $notEvaluated['NET-004'] = 'The Global Secure Access signaling setting was not read (check errors.txt).' }
    else { $facts.signalingEnabled = [string](& $v $st 'SignalingStatus') -eq 'enabled' }
    $setting = { param([string] $Name) $(if ($null -eq $st) { $null } else { & $v $st $Name }) }
    $tagging = & $setting 'TenantRestrictionsTagging'
    $xtap = & $load '02-cross-tenant-access-defaults'
    if ($null -eq $tagging) { & $unread @('NET-017') 'The universal tenant restrictions setting' }
    elseif ($null -eq $xtap) { & $missing @('NET-017') '02-cross-tenant-access-defaults' }
    else {
        $facts.tenantRestrictionsTagging = [string]$tagging -eq 'enabled'
        # What the tenant restrictions policy says by default about other tenants: blocked for users and for applications.
        $facts.tenantRestrictionsBlockByDefault = [string](& $v $xtap 'tenantRestrictions.usersAndGroups.accessType') -eq 'blocked' -and [string](& $v $xtap 'tenantRestrictions.applications.accessType') -eq 'blocked'
    }
    if ($null -eq (& $setting 'PrivateNetworks')) { & $unread @('NET-022') 'The private networks' } else { $facts.privateNetworks = [int](& $setting 'PrivateNetworks') }
    if ($null -eq (& $setting 'DeploymentsRecent')) { & $unread @('NET-023') 'The deployment log' }
    else {
        $facts.deploymentsRecent = [int](& $setting 'DeploymentsRecent'); $facts.deploymentsFailed = [int](& $setting 'DeploymentsFailed')
        if ($facts.deploymentsRecent -eq 0) { $notEvaluated['NET-023'] = 'No change to Global Secure Access was deployed in the last 30 days.' }
    }

    # ---- Security profiles and what is linked to them (NET-005 to NET-009, NET-012 to NET-015) ----
    $linked = 'NET-005', 'NET-006', 'NET-007', 'NET-008', 'NET-009', 'NET-012', 'NET-013', 'NET-014', 'NET-015'
    $profiles = & $load 'gsa-04-security-profiles'
    $appliedTls = $false
    if ($null -eq $profiles) { & $missing $linked 'gsa-04-security-profiles' }
    else {
        $pr = @($profiles | Where-Object { $_ })
        $baseline = @($pr | Where-Object { (& $enabled $_) -and (& $v $_ 'Baseline') -eq $true })
        $byPolicy = @($pr | Where-Object { (& $enabled $_) -and (& $v $_ 'Baseline') -ne $true -and [int](& $v $_ 'ConditionalAccessPolicies') -gt 0 })
        $applied = @($baseline) + @($byPolicy)
        $links = { param($Set, [string] $Kind) @($Set | ForEach-Object { @(& $v $_ 'Links') } | Where-Object { $_ -and [string](& $v $_ 'Kind') -eq $Kind -and [string](& $v $_ 'State') -eq 'enabled' }) }
        $facts.securityProfiles = $pr.Count
        $facts.webFilteringApplied = @(& $links $applied 'webFiltering').Count -gt 0
        $facts.profilesByConditionalAccess = $byPolicy.Count
        $facts.baselineWebFiltering = @(& $links $baseline 'webFiltering').Count -gt 0
        $facts.tlsInspectionApplied = @(& $links $applied 'tlsInspection').Count -gt 0
        $facts.threatIntelligenceApplied = @(& $links $applied 'threatIntelligence').Count -gt 0
        $facts.filePolicyApplied = @(& $links $applied 'file').Count -gt 0
        $facts.promptPolicyApplied = @(& $links $applied 'prompt').Count -gt 0
        $facts.cloudFirewallOnBaseline = @(& $links $baseline 'cloudFirewall').Count -gt 0
        $appliedTls = $facts.tlsInspectionApplied
        # Profiles that are on, hold a link and apply to nobody: neither the baseline nor named by a policy.
        $affected.webFilteringApplied = @($pr | Where-Object { (& $enabled $_) -and $_ -notin $applied -and @(& $v $_ 'Links').Count -gt 0 } | ForEach-Object { [ordered]@{ name = [string](& $v $_ 'Name'); detail = 'on, with policies linked, and no Conditional Access policy hands it out' } })
        if ($null -eq (& $setting 'RemoteNetworks')) { & $unread @('NET-015') 'The remote networks' }
        elseif ([int](& $setting 'RemoteNetworks') -eq 0) { $notEvaluated['NET-015'] = 'No remote network (branch office) is connected to Global Secure Access.' }
        else { $facts.remoteNetworks = [int](& $setting 'RemoteNetworks') }

        # NET-008: the categories a web filtering policy that applies blocks. Which rule wins when another policy
        # allows the same category is not worked out: a category counts as blocked when an applied policy blocks it.
        $policies = & $load 'gsa-05-filtering-policies'
        if ($null -eq $policies) { & $missing @('NET-008') 'gsa-05-filtering-policies' }
        else {
            $appliedIds = @(& $links $applied 'webFiltering' | ForEach-Object { [string](& $v $_ 'PolicyId') } | Where-Object { $_ })
            $blocking = @($policies | Where-Object { $_ -and [string](& $v $_ 'Id') -in $appliedIds -and [string](& $v $_ 'Action') -eq 'block' })
            $blocked = @($blocking | ForEach-Object { @(& $v $_ 'WebCategories') } | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
            $highRisk = [ordered]@{ CriminalActivity = 'Criminal activity'; Hacking = 'Hacking'; IllegalSoftware = 'Illegal software' }
            $open = @($highRisk.get_Keys() | Where-Object { $_ -notin $blocked })
            $facts.webCategoriesBlocked = $blocked.Count
            $facts.highRiskCategoriesOpen = $open.Count
            $affected.highRiskCategoriesOpen = @($open | ForEach-Object { [ordered]@{ name = [string]$highRisk[$_]; detail = 'no web filtering policy that applies blocks this category' } })
        }
    }

    # ---- TLS inspection: the certificates it signs with (NET-010) and its own bypass rules (NET-011) ----
    $tls = & $load 'gsa-06-tls-inspection'
    if ($null -eq $tls) { & $missing @('NET-010', 'NET-011') 'gsa-06-tls-inspection' }
    else {
        $tlsPolicies = @(@(& $v $tls 'Policies') | Where-Object { $_ })
        if ($tlsPolicies.Count -eq 0) { foreach ($id in 'NET-010', 'NET-011') { $notEvaluated[$id] = 'There is no TLS inspection policy; NET-009 asks for one.' } }
        else {
            if ((& $v $tls 'CertificatesRead') -ne $true) { & $unread @('NET-010') 'The TLS inspection certificates' }
            else {
                $certs = @(@(& $v $tls 'Certificates') | Where-Object { $_ })
                $left = { param($c) $e = ConvertTo-PostureUtcDateTime (& $v $c 'ExpiresUtc'); if ($e) { [int][Math]::Floor(($e - $AsOf).TotalDays) } else { $null } }
                $inUse = @($certs | Where-Object { [string](& $v $_ 'Status') -in 'active', 'enabled', 'expiring', 'expired' })
                $soon = @($inUse | Where-Object { $d = & $left $_; [string](& $v $_ 'Status') -in 'expiring', 'expired' -or ($null -ne $d -and $d -le [int]$t.tlsCertificateWarningDays) })
                $facts.tlsCertificates = $inUse.Count
                $facts.tlsCertificatesExpiring = $soon.Count
                $affected.tlsCertificatesExpiring = @($soon | ForEach-Object { $d = & $left $_; [ordered]@{ name = [string](& $v $_ 'Name'); detail = $(if ($null -eq $d) { [string](& $v $_ 'Status') } elseif ($d -lt 0) { "expired $(-$d) days ago" } else { "expires in $d days" }) } })
                if ($inUse.Count -eq 0) { $notEvaluated['NET-010'] = 'No TLS inspection certificate is in use.' }
            }
            # A policy with bypass rules of its own that nobody has changed for a long time: the exceptions were not looked at.
            $withBypass = @($tlsPolicies | Where-Object { [int](& $v $_ 'BypassRules') -gt 0 })
            $age = { param($p) $m = ConvertTo-PostureUtcDateTime (& $v $p 'LastModifiedUtc'); if ($m) { [int][Math]::Floor(($AsOf - $m).TotalDays) } else { $null } }
            $stale = @($withBypass | Where-Object { $d = & $age $_; $null -ne $d -and $d -gt [int]$t.tlsBypassReviewDays })
            $undated = @($withBypass | Where-Object { $null -eq (& $age $_) })
            $facts.tlsBypassRules = [int](@($withBypass | ForEach-Object { [int](& $v $_ 'BypassRules') }) + 0 | Measure-Object -Sum).Sum
            $facts.tlsBypassPoliciesStale = $(if ($stale.Count -gt 0) { $stale.Count } elseif ($undated.Count -gt 0) { $null } else { 0 })
            $affected.tlsBypassPoliciesStale = @($stale | ForEach-Object { [ordered]@{ name = [string](& $v $_ 'Name'); detail = "$([int](& $v $_ 'BypassRules')) bypass rule(s), last changed $(& $age $_) days ago" } })
            if ($withBypass.Count -eq 0) { $notEvaluated['NET-011'] = 'No TLS inspection policy has a bypass rule of its own.' }
            elseif ($null -eq $facts.tlsBypassPoliciesStale) { $notEvaluated['NET-011'] = "When the TLS inspection policies were last changed could not be read. $again" }
        }
    }
    if (-not $appliedTls -and -not $notEvaluated.ContainsKey('NET-010') -and $null -ne $profiles) { $notEvaluated['NET-010'] = 'TLS inspection is not linked to a security profile that applies; NET-009 asks for that first.' }

    # ---- Conditional Access and the network: the compliant network (NET-018), continuous access evaluation (NET-019), Private Access applications (NET-021) ----
    $raw = & $load 'policies'
    $caPolicies = $(if ($null -eq $raw) { $null } else { @($(if ($raw -is [System.Collections.IDictionary] -and $raw.Contains('value')) { $raw['value'] } else { $raw }) | Where-Object { $_ -and [string](& $v $_ 'state') -eq 'enabled' }) })
    $list = { param($policy, [string] $path) @(& $v $policy $path | Where-Object { $_ } | ForEach-Object { [string]$_ }) }
    if ($null -eq $caPolicies) { & $missing @('NET-018', 'NET-019', 'NET-021') 'policies' }
    else {
        # Read straight from the object: an empty list (the location does not exist) is an answer, and passing it
        # through a script block would turn it into nothing, which here means "not read".
        $compliant = $null; $compliantRead = $false
        if ($st -is [System.Collections.IDictionary]) { if ($st.Contains('CompliantNetworkLocations')) { $compliant = $st['CompliantNetworkLocations'] } }
        elseif ($st -and $st.PSObject.Properties['CompliantNetworkLocations']) { $compliant = $st.CompliantNetworkLocations }
        if ($null -ne $compliant) { $compliantRead = $true }
        if (-not $compliantRead) { & $unread @('NET-018') 'The compliant network location' }
        else {
            $ids = @($compliant | Where-Object { $_ } | ForEach-Object { [string]$_ })
            $facts.compliantNetworkLocation = $ids.Count -gt 0
            # A policy that names the compliant network either way: required by blocking everywhere else, or as a condition.
            $using = @($caPolicies | Where-Object { $p = $_; @(@(& $list $p 'conditions.locations.includeLocations') + @(& $list $p 'conditions.locations.excludeLocations') | Where-Object { $_ -in $ids }).Count -gt 0 })
            $facts.compliantNetworkPolicies = $using.Count
        }
        $caeOff = @($caPolicies | Where-Object { [string](& $v $_ 'sessionControls.continuousAccessEvaluation.mode') -eq 'disabled' })
        $facts.policiesDisablingCae = $caeOff.Count
        $affected.policiesDisablingCae = @($caeOff | ForEach-Object { [ordered]@{ name = [string](& $v $_ 'displayName'); detail = 'turns continuous access evaluation off' } })
    }

    # ---- Private Access applications: assigned to someone (NET-020), and under Conditional Access with strong authentication (NET-021) ----
    $apps = & $load 'gsa-07-private-apps'
    if ($null -eq $apps) { & $missing @('NET-020', 'NET-021') 'gsa-07-private-apps' }
    else {
        $pa = @($apps | Where-Object { $_ -and (& $v $_ 'Enabled') -ne $false })
        $facts.privateApps = $pa.Count
        if ($pa.Count -eq 0) { foreach ($id in 'NET-020', 'NET-021') { $notEvaluated[$id] = 'No Private Access application is published; NET-003 asks whether private apps are reached this way.' } }
        else {
            $known = @($pa | Where-Object { $null -ne (& $v $_ 'Assigned') })
            $nobody = @($known | Where-Object { (& $v $_ 'Assigned') -ne $true })
            $facts.privateAppsUnassigned = $(if ($nobody.Count -gt 0) { $nobody.Count } elseif ($known.Count -lt $pa.Count) { $null } else { 0 })
            $affected.privateAppsUnassigned = @($nobody | ForEach-Object { [ordered]@{ name = [string](& $v $_ 'Name'); detail = $(if ((& $v $_ 'QuickAccess') -eq $true) { 'Quick Access, with nobody assigned' } else { 'nobody assigned' }) } })
            if ($null -eq $facts.privateAppsUnassigned) { $notEvaluated['NET-020'] = "Who the Private Access applications are assigned to could not be read. $again" }
            if ($null -ne $caPolicies) {
                # Strong authentication: multifactor authentication or an authentication strength, asked of this application or of all.
                $strong = @($caPolicies | Where-Object { @(& $list $_ 'grantControls.builtInControls') -contains 'mfa' -or (& $v $_ 'grantControls.authenticationStrength.id') })
                $bare = @($pa | Where-Object { $id = [string](& $v $_ 'AppId'); @($strong | Where-Object { $inc = @(& $list $_ 'conditions.applications.includeApplications'); ($inc -contains 'All' -or $inc -contains $id) -and @(& $list $_ 'conditions.applications.excludeApplications') -notcontains $id }).Count -eq 0 })
                $facts.privateAppsWithoutStrongAuth = $bare.Count
                $affected.privateAppsWithoutStrongAuth = @($bare | ForEach-Object { [ordered]@{ name = [string](& $v $_ 'Name'); detail = 'no enabled Conditional Access policy asks for multifactor authentication for it' } })
            }
        }
    }

    # ---- NET-024: the network access logs leave Entra for a workspace, from the Azure collector's read of the Entra diagnostic settings ----
    $diag = & $load 'az-09-entra-diagnostic-settings'
    if ($null -eq $diag) { $notEvaluated['NET-024'] = 'az-09-entra-diagnostic-settings.json was not collected (the Azure collector reads the Entra diagnostic settings; Resume-PostureRun -Collector Azure).' }
    else {
        $sent = @(@($diag | Where-Object { $_ -and ((& $v $_ 'WorkspaceId') -or (& $v $_ 'EventHub')) }) | ForEach-Object { @(& $v $_ 'Categories') } | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
        $wanted = @('NetworkAccessTrafficLogs', 'NetworkAccessAlerts', 'RemoteNetworkHealthLogs', 'EnrichedOffice365AuditLogs')
        $lost = @($wanted | Where-Object { $_ -notin $sent })
        $facts.networkLogCategoriesMissing = $lost.Count
        $affected.networkLogCategoriesMissing = @($lost | ForEach-Object { [ordered]@{ name = $_; detail = 'not sent to a workspace or an event hub' } })
    }

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('gsa-01-forwarding-profiles.json', 'gsa-02-filtering-profiles.json', 'gsa-03-settings.json', 'gsa-04-security-profiles.json', 'gsa-05-filtering-policies.json', 'gsa-06-tls-inspection.json', 'gsa-07-private-apps.json') }
}
