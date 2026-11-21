# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureAzureFact {
    <#
    .SYNOPSIS
        Fact provider for the azure domain (spec 4.13): tenant and subscription hygiene, Defender for Cloud plans
        and contacts, policy coverage, activity log export, resource locks, tags and orphans, and the IAM layer:
        owners, standing root rights, guests, service principals, orphaned assignments, custom roles, classic
        administrators, user assignments at resource scope, Key Vault, storage and SQL authentication, and the
        Conditional Access policy over Azure management.
    .DESCRIPTION
        Reads the az-* files and joins role assignments to 06-users, 07-groups and 10-service-principals when they
        are there. Thresholds read: maxOwnersPerSubscription, minTaggedPct, maxUserResourceScopeAssignments,
        maxServicePrincipalOwners. Microsoft's Azure Secure Score and assessments are facts for the report, not grades.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [Parameter()] [System.Collections.IDictionary] $OrgProfile = @{},
        [Parameter()] [System.Collections.IDictionary] $Thresholds = @{}
    )

    $ErrorActionPreference = 'Stop'
    $t = @{ maxOwnersPerSubscription = 3; minTaggedPct = 95; maxUserResourceScopeAssignments = 10; maxServicePrincipalOwners = 0 }
    foreach ($k in @($Thresholds.Keys)) { $t[$k] = $Thresholds[$k] }
    # Parsed once per evaluation and shared with the other domains (Read-PostureEvidenceFile); a missing file is
    # $null, an empty one an empty array.
    $load = {
        param([string] $Name)
        $parsed = Read-PostureEvidenceFile -Folder $Evidence -Name $Name
        if ($null -eq $parsed) { return $null }
        if ($parsed -is [array] -and $parsed.Count -eq 0) { return , @() }
        return $parsed
    }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $rows = { param($o) @($o | Where-Object { $_ }) }
    $pct = { param([double] $n, [double] $d) if ($d -le 0) { $null } else { [Math]::Round(100.0 * $n / $d, 1) } }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}; $notes = @{}
    $missing = { param([string[]] $Ids, [string] $File) foreach ($id in $Ids) { $notEvaluated[$id] = "$File.json was not collected (Invoke-PostureCollection -Collector Azure; check errors.txt and the Reader and Security Reader roles)." } }

    $subs = & $load 'az-01-subscriptions'
    if ($null -eq $subs) { return @{ available = $false; reason = 'No Azure evidence in the folder (Invoke-PostureCollection -Collector Azure needs a Connect-AzAccount session).' } }
    $s = @(& $rows $subs | Where-Object { [string]$_.State -eq 'Enabled' })
    $facts.subscriptions = $s.Count
    # Which subscriptions the per-subscription reads covered: the collector's DetailRead flag. Evidence from before
    # the flag read the first 200 enabled subscriptions, so up to 200 all were read; above that az-13-budgets, which
    # has one row for every subscription read, says which. The checks below that read per-subscription files judge
    # these and only these: a subscription that was never read has no contact, no export and no plan in the files,
    # and is not a finding.
    $has = { param($o, [string] $k) if ($o -is [System.Collections.IDictionary]) { $o.Contains($k) } else { $null -ne $o.PSObject.Properties[$k] } }
    $read = $s
    if (@($s | Where-Object { & $has $_ 'DetailRead' }).Count -gt 0) { $read = @($s | Where-Object { (& $v $_ 'DetailRead') -eq $true }) }
    elseif ($s.Count -gt 200) {
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($row in @(& $rows (& $load 'az-13-budgets'))) { $null = $seen.Add([string](& $v $row 'SubscriptionId')) }
        $read = @($s | Where-Object { $seen.Contains([string]$_.SubscriptionId) })
    }
    $facts.subscriptionsRead = $read.Count
    # A gap that was seen is a finding, with how much was looked at. With no gap among those read and others unread,
    # there is no answer for the tenant.
    $partial = {
        param([string] $Id, [int] $Gaps, [string] $What)
        if ($read.Count -ge $s.Count) { return }
        if ($read.Count -eq 0) { $notEvaluated[$Id] = "The evidence does not say which of the $($s.Count) subscriptions were read in detail. Collect Azure again (Resume-PostureRun -Collector Azure)."; return }
        if ($Gaps -gt 0) { $notes[$Id] = "Judged on $($read.Count) of $($s.Count) subscriptions; the other $($s.Count - $read.Count) were not read." }
        else { $notEvaluated[$Id] = "No $What among the $($read.Count) subscriptions that were read; the other $($s.Count - $read.Count) were not read (the per-subscription reads cover the first 200), so there is no answer for the tenant yet." }
    }
    $subName = @{}; foreach ($x in $s) { $subName[[string]$x.SubscriptionId] = [string]$x.Name }
    $label = { param([string] $id) $(if ($subName.ContainsKey($id)) { "$($subName[$id]) ($id)" } else { $id }) }

    # AZ-001 management group hierarchy
    $mgs = & $load 'az-01-management-groups'
    $facts.managementGroups = $(if ($null -ne $mgs) { @(& $rows $mgs).Count } else { 0 })
    $atRoot = @($s | Where-Object { $_.AtTenantRoot -eq $true })
    $facts.subscriptionsAtTenantRoot = $atRoot.Count
    $affected.subscriptionsAtTenantRoot = @($atRoot | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = 'sits directly under the tenant root group' } })

    # AZ-002 MCSB assigned, AZ-008 policy coverage
    $pol = & $load 'az-03-policy-assignments'
    if ($null -eq $pol) { & $missing @('AZ-002', 'AZ-008') 'az-03-policy-assignments' }
    else {
        $p = @(& $rows $pol)
        # An assignment covers a subscription at root scope, at the subscription itself, or at a management group in the subscription's ancestor chain.
        $covers = { param($assignment, $sub) $scope = [string]$assignment.Scope; if ($scope -eq '/') { return $true }; if ($scope -match "^/subscriptions/$([regex]::Escape([string]$sub.SubscriptionId))/?$") { return $true }; if ($scope -match '^/providers/Microsoft\.Management/managementGroups/([^/]+)/?$') { return (@($sub.ManagementGroupNames | ForEach-Object { [string]$_ }) -contains $Matches[1]) }; $false }
        $noMcsb = @($s | Where-Object { $sub = $_; @($p | Where-Object { $_.IsMcsb -eq $true -and (& $covers $_ $sub) }).Count -eq 0 })
        $facts.subscriptionsWithoutMcsb = $noMcsb.Count
        $affected.subscriptionsWithoutMcsb = @($noMcsb | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = 'no Microsoft cloud security benchmark assignment at subscription, management group or root scope' } })
        $noPolicy = @($s | Where-Object { $sub = $_; @($p | Where-Object { $_.IsMcsb -ne $true -and (& $covers $_ $sub) }).Count -eq 0 })
        $facts.subscriptionsWithoutOwnPolicy = $noPolicy.Count
        $affected.subscriptionsWithoutOwnPolicy = @($noPolicy | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = 'no policy assignment beyond the benchmark' } })
    }

    # AZ-003 Defender plans where the resource types exist, AZ-004 Defender CSPM
    $pricing = & $load 'az-02-defender-pricings'; $byType = & $load 'az-06-resources-by-type'
    if ($null -eq $pricing) { & $missing @('AZ-003', 'AZ-004') 'az-02-defender-pricings' }
    else {
        $pr = @(& $rows $pricing)
        # (verify) plan names as the pricings API spells them
        $planFor = [ordered]@{ VirtualMachines = 'microsoft.compute/virtualmachines'; StorageAccounts = 'microsoft.storage/storageaccounts'; KeyVaults = 'microsoft.keyvault/vaults'; SqlServers = 'microsoft.sql/servers'; Containers = 'microsoft.containerservice/managedclusters'; AppServices = 'microsoft.web/sites'; Api = 'microsoft.apimanagement/service' }
        # Resource types and plan tiers by subscription, built once: asked per subscription from the lists themselves
        # this took minutes on a tenant of 1,500 subscriptions.
        $typesBySub = @{}
        foreach ($row in @(& $rows $byType)) { $k = [string]$row.SubscriptionId; if (-not $typesBySub.ContainsKey($k)) { $typesBySub[$k] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) }; $null = $typesBySub[$k].Add([string]$row.Type) }
        $tiersBySubPlan = @{}
        foreach ($row in $pr) { $k = "$([string]$row.SubscriptionId)|$([string]$row.Plan)"; if (-not $tiersBySubPlan.ContainsKey($k)) { $tiersBySubPlan[$k] = [System.Collections.Generic.List[string]]::new() }; $tiersBySubPlan[$k].Add([string]$row.Tier) }
        $gaps = [System.Collections.Generic.List[object]]::new()
        foreach ($sub in $read) {
            $id = [string]$sub.SubscriptionId
            $types = $typesBySub[$id]
            foreach ($plan in $planFor.Keys) {
                if (-not $types -or -not $types.Contains($planFor[$plan])) { continue }
                $tier = @($(if ($tiersBySubPlan.ContainsKey("$id|$plan")) { $tiersBySubPlan["$id|$plan"] }))
                if ($tier -notcontains 'Standard') { $gaps.Add([ordered]@{ name = "$(& $label $id): $plan"; detail = "resources of that type exist and the plan is $(if ($tier.Count -gt 0) { $tier[0] } else { 'absent' })" }) }
            }
            $arm = @($(if ($tiersBySubPlan.ContainsKey("$id|Arm")) { $tiersBySubPlan["$id|Arm"] }))
            if ($arm -notcontains 'Standard') { $gaps.Add([ordered]@{ name = "$(& $label $id): Arm"; detail = 'Defender for Resource Manager off' }) }
        }
        $facts.defenderPlanGaps = $gaps.Count
        $affected.defenderPlanGaps = @($gaps)
        & $partial 'AZ-003' $gaps.Count 'Defender plan gap'
        $facts.defenderCspmSubscriptions = @($pr | Where-Object { [string]$_.Plan -eq 'CloudPosture' -and [string]$_.Tier -eq 'Standard' } | ForEach-Object { $_.SubscriptionId } | Sort-Object -Unique).Count
        if ($facts.defenderCspmSubscriptions -eq 0) { $notEvaluated['AZ-004'] = $(if ($read.Count -lt $s.Count) { "Defender CSPM is on none of the $($read.Count) subscriptions that were read; the other $($s.Count - $read.Count) were not read." } else { 'Requires Defender CSPM on at least one subscription; attack paths, permissions creep and unused permissions come with it.' }) }
    }

    # AZ-005 security contacts
    $contacts = & $load 'az-02-security-contacts'
    if ($null -eq $contacts) { & $missing @('AZ-005') 'az-02-security-contacts' }
    else {
        $c = @(& $rows $contacts)
        # The subscriptions that have a working contact, as a set: one pass over the contacts, one over the subscriptions.
        $withContact = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($row in $c) { if ($row.Emails -and [string]$row.AlertState -ne 'Off' -and $row.IsEnabled -ne $false) { $null = $withContact.Add([string]$row.SubscriptionId) } }
        $noContact = @($read | Where-Object { -not $withContact.Contains([string]$_.SubscriptionId) })
        $facts.subscriptionsWithoutSecurityContact = $noContact.Count
        $affected.subscriptionsWithoutSecurityContact = @($noContact | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = 'no security contact with alert notifications on' } })
        & $partial 'AZ-005' $noContact.Count 'subscription without a security contact'
    }

    # AZ-006 activity log export
    $exports = & $load 'az-04-activity-log-exports'
    if ($null -eq $exports) { & $missing @('AZ-006') 'az-04-activity-log-exports' }
    else {
        $e = @(& $rows $exports)
        $withExport = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($row in $e) { if (($row.WorkspaceId -or $row.EventHub) -and [int]$row.Categories -gt 0) { $null = $withExport.Add([string]$row.SubscriptionId) } }
        $noExport = @($read | Where-Object { -not $withExport.Contains([string]$_.SubscriptionId) })
        $facts.subscriptionsWithoutActivityLogExport = $noExport.Count
        $affected.subscriptionsWithoutActivityLogExport = @($noExport | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = 'no diagnostic setting sends the activity log to a workspace or event hub' } })
        & $partial 'AZ-006' $noExport.Count 'subscription without an activity log export'
    }

    # AZ-007 locks on vaults, AZ-009 tags, AZ-010 orphans
    $locks = & $load 'az-06-locks'; $vaults = & $load 'az-06-vaults'
    if ($null -eq $vaults) { & $missing @('AZ-007') 'az-06-vaults' }
    else {
        $lockScopes = @(& $rows $locks | Where-Object { [string]$_.Level -eq 'CanNotDelete' } | ForEach-Object { ([string]$_.LockedScope).ToLowerInvariant() })
        $unlocked = @(& $rows $vaults | Where-Object { $id = ([string]$_.Id).ToLowerInvariant(); @($lockScopes | Where-Object { $id.StartsWith($_) }).Count -eq 0 })
        $facts.vaults = @(& $rows $vaults).Count
        $facts.vaultsWithoutDeleteLock = $unlocked.Count
        $affected.vaultsWithoutDeleteLock = @($unlocked | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = "$($_.Type) with no CanNotDelete lock at any scope" } })
    }
    $summary = & $load 'az-06-resources-summary'
    if ($null -eq $summary) { & $missing @('AZ-009', 'AZ-010') 'az-06-resources-summary' }
    else {
        $facts.resources = [int](& $v $summary 'Resources')
        $facts.taggedPct = & $pct ([int](& $v $summary 'TaggedOwnerAndEnvironment')) $facts.resources
        if ($facts.resources -eq 0) { $notEvaluated['AZ-009'] = 'No resources in the subscriptions.'; $notEvaluated['AZ-010'] = 'No resources in the subscriptions.' }
        $orphans = @(@(@('Unattached disks', [int](& $v $summary 'UnattachedDisks')), @('Unused public IPs', [int](& $v $summary 'UnusedPublicIps')), @('NICs without a VM', [int](& $v $summary 'NicsWithoutVm')), @('Empty resource groups', [int](& $v $summary 'EmptyResourceGroups'))) | Where-Object { $_[1] -gt 0 } | ForEach-Object { [ordered]@{ name = $_[0]; detail = "$($_[1])" } })
        $facts.orphanedResources = @($orphans | ForEach-Object { [int]$_.detail } | Measure-Object -Sum).Sum
        $affected.orphanedResources = $orphans
    }

    # IAM: role assignments joined to the identity evidence
    $ra = & $load 'az-05-role-assignments'
    if ($null -eq $ra) { & $missing @('AZ-011', 'AZ-012', 'AZ-013', 'AZ-014', 'AZ-015', 'AZ-018') 'az-05-role-assignments' }
    else {
        $a = @(& $rows $ra)
        # Only the principals the assignments name, read a row at a time from each list, not every user, group and app.
        $principalIds = @($a | ForEach-Object { [string]$_.PrincipalId } | Sort-Object -Unique)
        $users = Find-PostureEvidenceRow -Folder $Evidence -Name '06-users' -Key 'Id' -Value $principalIds
        $groups = Find-PostureEvidenceRow -Folder $Evidence -Name '07-groups' -Key 'Id' -Value $principalIds
        $sps = Find-PostureEvidenceRow -Folder $Evidence -Name '10-service-principals' -Key 'Id' -Value $principalIds
        $userById = $(if ($null -ne $users) { $users } else { @{} })
        $groupIds = $(if ($null -ne $groups) { $groups } else { @{} })
        $spById = $(if ($null -ne $sps) { $sps } else { @{} })
        $who = { param($x) $id = [string]$x.PrincipalId; if ($userById.ContainsKey($id)) { [string]$userById[$id].UserPrincipalName } elseif ($spById.ContainsKey($id)) { [string]$spById[$id].DisplayName } elseif ($groupIds.ContainsKey($id)) { [string]$groupIds[$id].DisplayName } else { "$($x.PrincipalType) $id" } }

        # AZ-011 owners per subscription (direct plus inherited from management group and root)
        $owners = @($a | Where-Object { [string]$_.RoleName -eq 'Owner' })
        $overLimit = @(); $syncedOwners = @()
        # Owners by subscription, built once; the ones at the root or a management group apply to every subscription.
        $inheritedOwners = @($owners | Where-Object { [string]$_.ScopeLevel -in @('root', 'managementGroup') })
        $ownersBySub = @{}
        foreach ($o in $owners) { if ([string]$o.ScopeLevel -ne 'subscription') { continue }; $k = [string]$o.SubscriptionId; if (-not $ownersBySub.ContainsKey($k)) { $ownersBySub[$k] = [System.Collections.Generic.List[object]]::new() }; $ownersBySub[$k].Add($o) }
        foreach ($sub in $s) {
            $mine = @(@($(if ($ownersBySub.ContainsKey([string]$sub.SubscriptionId)) { $ownersBySub[[string]$sub.SubscriptionId] })) + @($inheritedOwners))
            $principals = @($mine | ForEach-Object { $_.PrincipalId } | Sort-Object -Unique)
            if ($principals.Count -gt [int]$t.maxOwnersPerSubscription) { $overLimit += , [ordered]@{ name = [string]$sub.Name; detail = "$($principals.Count) owners (limit $($t.maxOwnersPerSubscription)): $(@($mine | ForEach-Object { & $who $_ } | Sort-Object -Unique) -join ', ')" } }
            foreach ($o in $mine) { $u = $userById[[string]$o.PrincipalId]; if ($u -and $u.OnPremisesSyncEnabled -eq $true) { $syncedOwners += , [ordered]@{ name = [string]$u.UserPrincipalName; detail = "Owner on $($sub.Name), synced from on-premises AD" } } }
        }
        $facts.subscriptionsOverOwnerLimit = $overLimit.Count
        # Unknown without the user list: an owner cannot be told synced from cloud-only.
        $facts.syncedOwners = $(if ($null -eq $users) { $null } else { @($syncedOwners | ForEach-Object { $_.name } | Sort-Object -Unique).Count })
        $affected.ownerProblems = @($overLimit + $syncedOwners)

        # AZ-012 standing Owner or User Access Administrator at root or management group
        $standing = @($a | Where-Object { [string]$_.RoleName -in @('Owner', 'User Access Administrator') -and [string]$_.ScopeLevel -in @('root', 'managementGroup') })
        $facts.standingRootOrMgAdmins = $standing.Count
        $affected.standingRootOrMgAdmins = @($standing | ForEach-Object { [ordered]@{ name = (& $who $_); detail = "$($_.RoleName) at $($_.Scope)" } })

        # AZ-013 guests, AZ-014 service principals with Owner or Contributor, AZ-015 orphaned, AZ-018 users at resource scope
        if ($null -eq $users) { $notEvaluated['AZ-013'] = '06-users.json was not collected; guests cannot be told from members.' }
        else {
            $guest = @($a | Where-Object { $u = $userById[[string]$_.PrincipalId]; $u -and [string]$u.UserType -eq 'Guest' })
            $facts.guestRoleAssignments = $guest.Count
            $affected.guestRoleAssignments = @($guest | ForEach-Object { [ordered]@{ name = (& $who $_); detail = "$($_.RoleName) at $($_.Scope)" } })
        }
        $spPriv = @($a | Where-Object { [string]$_.PrincipalType -eq 'ServicePrincipal' -and [string]$_.RoleName -in @('Owner', 'Contributor') })
        $facts.servicePrincipalOwnersOrContributors = $spPriv.Count
        $affected.servicePrincipalOwnersOrContributors = @($spPriv | ForEach-Object { [ordered]@{ name = (& $who $_); detail = "$($_.RoleName) at $($_.Scope)" } })
        $known = ($null -ne $users -and $null -ne $groups -and $null -ne $sps)
        $orphan = @($a | Where-Object { [string]$_.PrincipalType -eq 'Unknown' -or ($known -and -not ($userById.ContainsKey([string]$_.PrincipalId) -or $groupIds.ContainsKey([string]$_.PrincipalId) -or $spById.ContainsKey([string]$_.PrincipalId))) })
        $facts.orphanedRoleAssignments = $orphan.Count
        $affected.orphanedRoleAssignments = @($orphan | ForEach-Object { [ordered]@{ name = "$($_.PrincipalType) $($_.PrincipalId)"; detail = "$($_.RoleName) at $($_.Scope); principal not found$(if (-not $known) { ' (type Unknown)' })" } })
        $facts.userAssignmentsAtResourceScope = @($a | Where-Object { [string]$_.PrincipalType -eq 'User' -and [string]$_.ScopeLevel -eq 'resource' }).Count
    }

    # AZ-016 custom roles with wildcards
    $custom = & $load 'az-05-role-definitions-custom'
    if ($null -eq $custom) { & $missing @('AZ-016') 'az-05-role-definitions-custom' }
    else {
        $wild = @(& $rows $custom | Where-Object { $_.Wildcard -eq $true })
        $facts.customRolesWithWildcard = $wild.Count
        $affected.customRolesWithWildcard = @($wild | ForEach-Object { [ordered]@{ name = [string]$_.RoleName; detail = 'custom role with * in Actions or DataActions' } })
    }

    # AZ-017 classic administrators
    $classic = & $load 'az-05-classic-administrators'
    if ($null -eq $classic) { & $missing @('AZ-017') 'az-05-classic-administrators' }
    else {
        $cl = @(& $rows $classic | Where-Object { [string]$_.Role -notmatch '(?i)^AccountAdministrator$' })
        $facts.classicAdministrators = $cl.Count
        $affected.classicAdministrators = @($cl | ForEach-Object { [ordered]@{ name = [string]$_.EmailAddress; detail = "$($_.Role) on $(& $label $_.SubscriptionId)" } })
        & $partial 'AZ-017' $cl.Count 'classic administrator'
    }

    # AZ-019 Key Vault, AZ-020 storage, AZ-021 SQL
    $kv = & $load 'az-07-keyvaults'
    if ($null -eq $kv) { & $missing @('AZ-019') 'az-07-keyvaults' }
    else {
        $bad = @(& $rows $kv | Where-Object { $_.RbacAuthorization -ne $true -or $_.PurgeProtection -ne $true -or $_.SoftDelete -ne $true -or ([string]$_.PublicNetworkAccess -notmatch '(?i)disabled' -and [string]$_.DefaultAction -notmatch '(?i)deny') })
        $facts.keyVaults = @(& $rows $kv).Count
        $facts.keyVaultsOffModel = $bad.Count
        $affected.keyVaultsOffModel = @($bad | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = (@($(if ($_.RbacAuthorization -ne $true) { 'access policies instead of RBAC' }), $(if ($_.PurgeProtection -ne $true) { 'no purge protection' }), $(if ($_.SoftDelete -ne $true) { 'soft delete off' }), $(if ([string]$_.PublicNetworkAccess -notmatch '(?i)disabled' -and [string]$_.DefaultAction -notmatch '(?i)deny') { 'public network access' })) | Where-Object { $_ }) -join ', ' } })
    }
    $st = & $load 'az-07-storage'
    if ($null -eq $st) { & $missing @('AZ-020') 'az-07-storage' }
    else {
        $bad = @(& $rows $st | Where-Object { $_.AllowSharedKeyAccess -ne $false -or $_.AllowBlobPublicAccess -eq $true -or $_.HttpsOnly -ne $true -or [string]$_.MinimumTlsVersion -ne 'TLS1_2' })
        $facts.storageAccounts = @(& $rows $st).Count
        $facts.storageAccountsOffModel = $bad.Count
        $affected.storageAccountsOffModel = @($bad | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = (@($(if ($_.AllowSharedKeyAccess -ne $false) { 'shared key access on' }), $(if ($_.AllowBlobPublicAccess -eq $true) { 'anonymous blob access allowed' }), $(if ($_.HttpsOnly -ne $true) { 'HTTP allowed' }), $(if ([string]$_.MinimumTlsVersion -ne 'TLS1_2') { "TLS $($_.MinimumTlsVersion)" })) | Where-Object { $_ }) -join ', ' } })
    }
    $sql = & $load 'az-07-sql-servers'
    if ($null -eq $sql) { & $missing @('AZ-021') 'az-07-sql-servers' }
    else {
        $bad = @(& $rows $sql | Where-Object { $_.EntraOnlyAuthentication -ne $true })
        $facts.sqlServers = @(& $rows $sql).Count
        $facts.sqlServersWithLocalAuth = $bad.Count
        $affected.sqlServersWithLocalAuth = @($bad | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = 'SQL authentication still enabled alongside Entra' } })
        if ($facts.sqlServers -eq 0) { $notEvaluated['AZ-021'] = 'No Azure SQL servers in the subscriptions.' }
    }

    # AZ-022 Conditional Access over the Azure management plane, from the CA snapshot in the same folder
    $policies = & $load 'policies'
    if ($null -eq $policies) { $notEvaluated['AZ-022'] = 'policies.json (the Conditional Access snapshot) is not in the folder.' }
    else {
        $azureApp = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
        $hit = @(& $rows $policies | Where-Object { [string](& $v $_ 'state') -eq 'enabled' } | Where-Object { $apps = @(& $v $_ 'conditions.applications.includeApplications') | ForEach-Object { [string]$_ }; $apps -contains $azureApp -or $apps -contains 'All' } | Where-Object { $g = & $v $_ 'grantControls'; $controls = @(& $v $g 'builtInControls') | ForEach-Object { [string]$_ }; ($controls -contains 'mfa') -or ($controls -contains 'compliantDevice') -or ($null -ne (& $v $g 'authenticationStrength')) })
        $facts.azureManagementCaPolicies = $hit.Count
    }

    # Microsoft's own numbers for the report, not grades.
    $scores = & $load 'az-02-secure-scores'
    if ($null -ne $scores) { $facts.azureSecureScores = @(& $rows $scores | ForEach-Object { [ordered]@{ subscription = (& $label $_.SubscriptionId); current = $_.Current; max = $_.Max; percentage = $_.Percentage } }) }

    # Microsoft 365 pay-as-you-go: every paying subscription has a budget (AZ-023).
    $payg = & $load 'az-10-m365-payg'
    if ($null -eq $payg) { $notEvaluated['AZ-023'] = 'az-10-m365-payg.json was not collected (the Azure collector; Cost Management Reader on the subscriptions).' }
    else {
        $paying = @($payg | Where-Object { $_ })
        $noBudget = @($paying | Where-Object { [int](& $v $_ 'Budgets') -eq 0 })
        $facts.m365PaygSubscriptions = $paying.Count
        $facts.m365PaygWithoutBudget = $noBudget.Count
        $affected.m365PaygWithoutBudget = @($noBudget | ForEach-Object { [ordered]@{ name = [string](& $v $_ 'SubscriptionId'); detail = (@(& $v $_ 'Services' | ForEach-Object { "$(& $v $_ 'Name') $(& $v $_ 'Cost') $(& $v $_ 'Currency')" }) -join '; ') } })
        & $partial 'AZ-023' $noBudget.Count 'pay-as-you-go spend without a budget'
    }
    # AZ-024: management ports (SSH, RDP, WinRM) open to the internet on a network security group in use.
    $ports = & $load 'az-12-open-management-ports'
    if ($null -eq $ports) { & $missing @('AZ-024') 'az-12-open-management-ports' }
    else { $open = @(& $rows $ports); $facts.managementPortsOpen = $open.Count; $affected.managementPortsOpen = @($open | ForEach-Object { [ordered]@{ name = "$($_.Nsg) / $($_.Rule)"; detail = "ports $($_.Ports) open to the internet, $(& $label $_.SubscriptionId)" } }) }

    # AZ-025: a budget with an alert on every subscription (a spike in spend is often the first sign of misuse).
    $budgets = & $load 'az-13-budgets'
    if ($null -eq $budgets) { & $missing @('AZ-025') 'az-13-budgets' }
    else { $none = @(& $rows $budgets | Where-Object { [int]$_.Budgets -eq 0 }); $facts.subscriptionsWithoutBudget = $none.Count; $affected.subscriptionsWithoutBudget = @($none | ForEach-Object { [ordered]@{ name = (& $label $_.SubscriptionId); detail = 'no budget' } }); & $partial 'AZ-025' $none.Count 'subscription without a budget' }

    # AZ-026: backup vaults keep deleted backups (soft delete) and refuse to shorten or remove them (immutability).
    $bv = & $load 'az-14-backup-vaults'
    if ($null -eq $bv) { & $missing @('AZ-026') 'az-14-backup-vaults' }
    else {
        $weak = @(& $rows $bv | Where-Object { [string]$_.SoftDelete -notin 'Enabled', 'AlwaysON', 'On' -or [string]$_.Immutability -notin 'Unlocked', 'Locked' })
        $facts.backupVaultsUnprotected = $weak.Count
        # Nothing to protect is not a pass: say so, as AZ-021 does for SQL.
        if (@(& $rows $bv).Count -eq 0) { $notEvaluated['AZ-026'] = 'No backup vaults in the subscriptions.' }
        $affected.backupVaultsUnprotected = @($weak | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = "soft delete $(if ($_.SoftDelete) { $_.SoftDelete } else { 'off' }), immutability $(if ($_.Immutability) { $_.Immutability } else { 'off' })" } })
    }

    # AZ-027: a Sentinel workspace receives Entra, Microsoft 365 and Defender XDR.
    $sentinel = & $load 'az-15-sentinel'
    if ($null -eq $sentinel) { & $missing @('AZ-027') 'az-15-sentinel' }
    else {
        $ws = @(& $rows $sentinel)
        $core = @('AzureActiveDirectory', 'Office365', 'MicrosoftThreatProtection')
        $complete = @($ws | Where-Object { $have = @(([string]$_.Connectors) -split ',\s*'); @($core | Where-Object { $_ -notin $have }).Count -eq 0 })
        $facts.sentinelWorkspaces = $ws.Count
        $facts.sentinelWithCoreConnectors = $complete.Count
        if ($ws.Count -eq 0) { $notEvaluated['AZ-027'] = 'No Microsoft Sentinel workspace in the subscriptions; OP-001 asks whether a SIEM receives these logs.' }
        $affected.sentinelWithCoreConnectors = @($ws | Where-Object { $_ -notin $complete } | ForEach-Object { $have = @(([string]$_.Connectors) -split ',\s*'); [ordered]@{ name = [string]$_.Workspace; detail = "missing $(@($core | Where-Object { $_ -notin $have }) -join ', ')" } })
    }

    # AZ-028: Entra Domain Services without NTLMv1, TLS 1.0, RC4 or NTLM password hashes it does not need.
    $ds = & $load 'az-16-entra-domain-services'
    if ($null -eq $ds) { & $missing @('AZ-028') 'az-16-entra-domain-services' }
    else {
        $weakDs = @(& $rows $ds | ForEach-Object {
                $x = $_; $why = @(@(@('NTLMv1', 'NtlmV1'), @('TLS 1.0', 'TlsV1'), @('Kerberos RC4', 'KerberosRc4Encryption'), @('NTLM password sync', 'SyncNtlmPasswords')) | Where-Object { [string](& $v $x $_[1]) -eq 'Enabled' } | ForEach-Object { $_[0] })
                if ($why.Count) { [ordered]@{ name = [string]$x.Name; detail = "$($why -join ', ') on" } }
            })
        $facts.entraDomainServicesWeak = $weakDs.Count
        if (@(& $rows $ds).Count -eq 0) { $notEvaluated['AZ-028'] = 'No Entra Domain Services in the subscriptions.' }
        $affected.entraDomainServicesWeak = @($weakDs)
    }

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; notes = $notes; evidence = @('az-01-subscriptions.json', 'az-05-role-assignments.json', 'az-12-open-management-ports.json', 'az-13-budgets.json', 'az-14-backup-vaults.json', 'az-15-sentinel.json', 'az-16-entra-domain-services.json') }
}
