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
    $load = {
        param([string] $Name)
        $f = Join-Path $Evidence "$Name.json"
        if (-not (Test-Path -LiteralPath $f)) { return $null }
        $text = Get-Content -Raw -LiteralPath $f
        if ([string]::IsNullOrWhiteSpace($text)) { return , @() }
        $parsed = ConvertFrom-Json -InputObject $text -AsHashtable -Depth 20
        if ($null -eq $parsed) { return , @() }
        return $parsed
    }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $rows = { param($o) @($o | Where-Object { $_ }) }
    $pct = { param([double] $n, [double] $d) if ($d -le 0) { $null } else { [Math]::Round(100.0 * $n / $d, 1) } }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    $missing = { param([string[]] $Ids, [string] $File) foreach ($id in $Ids) { $notEvaluated[$id] = "$File.json was not collected (Invoke-PostureCollection -Collector Azure; check errors.txt and the Reader and Security Reader roles)." } }

    $subs = & $load 'az-01-subscriptions'
    if ($null -eq $subs) { return @{ available = $false; reason = 'No Azure evidence in the folder (Invoke-PostureCollection -Collector Azure needs a Connect-AzAccount session).' } }
    $s = @(& $rows $subs | Where-Object { [string]$_.State -eq 'Enabled' })
    $facts.subscriptions = $s.Count
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
        $gaps = @()
        foreach ($sub in $s) {
            $types = @($(if ($null -ne $byType) { @(& $rows $byType | Where-Object { [string]$_.SubscriptionId -eq [string]$sub.SubscriptionId } | ForEach-Object { ([string]$_.Type).ToLowerInvariant() }) }))
            foreach ($plan in $planFor.Keys) {
                if ($types -notcontains $planFor[$plan]) { continue }
                $tier = @($pr | Where-Object { [string]$_.SubscriptionId -eq [string]$sub.SubscriptionId -and [string]$_.Plan -eq $plan } | ForEach-Object { [string]$_.Tier })
                if ($tier -notcontains 'Standard') { $gaps += , [ordered]@{ name = "$(& $label $sub.SubscriptionId): $plan"; detail = "resources of that type exist and the plan is $(if ($tier.Count -gt 0) { $tier[0] } else { 'absent' })" } }
            }
            $arm = @($pr | Where-Object { [string]$_.SubscriptionId -eq [string]$sub.SubscriptionId -and [string]$_.Plan -eq 'Arm' } | ForEach-Object { [string]$_.Tier })
            if ($arm -notcontains 'Standard') { $gaps += , [ordered]@{ name = "$(& $label $sub.SubscriptionId): Arm"; detail = 'Defender for Resource Manager off' } }
        }
        $facts.defenderPlanGaps = $gaps.Count
        $affected.defenderPlanGaps = @($gaps)
        $facts.defenderCspmSubscriptions = @($pr | Where-Object { [string]$_.Plan -eq 'CloudPosture' -and [string]$_.Tier -eq 'Standard' } | ForEach-Object { $_.SubscriptionId } | Sort-Object -Unique).Count
        if ($facts.defenderCspmSubscriptions -eq 0) { $notEvaluated['AZ-004'] = 'Requires Defender CSPM on at least one subscription; attack paths, permissions creep and unused permissions come with it.' }
    }

    # AZ-005 security contacts
    $contacts = & $load 'az-02-security-contacts'
    if ($null -eq $contacts) { & $missing @('AZ-005') 'az-02-security-contacts' }
    else {
        $c = @(& $rows $contacts)
        $noContact = @($s | Where-Object { $sub = $_; @($c | Where-Object { [string]$_.SubscriptionId -eq [string]$sub.SubscriptionId -and $_.Emails -and [string]$_.AlertState -ne 'Off' -and $_.IsEnabled -ne $false }).Count -eq 0 })
        $facts.subscriptionsWithoutSecurityContact = $noContact.Count
        $affected.subscriptionsWithoutSecurityContact = @($noContact | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = 'no security contact with alert notifications on' } })
    }

    # AZ-006 activity log export
    $exports = & $load 'az-04-activity-log-exports'
    if ($null -eq $exports) { & $missing @('AZ-006') 'az-04-activity-log-exports' }
    else {
        $e = @(& $rows $exports)
        $noExport = @($s | Where-Object { $sub = $_; @($e | Where-Object { [string]$_.SubscriptionId -eq [string]$sub.SubscriptionId -and ($_.WorkspaceId -or $_.EventHub) -and [int]$_.Categories -gt 0 }).Count -eq 0 })
        $facts.subscriptionsWithoutActivityLogExport = $noExport.Count
        $affected.subscriptionsWithoutActivityLogExport = @($noExport | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = 'no diagnostic setting sends the activity log to a workspace or event hub' } })
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
        $users = & $load '06-users'; $groups = & $load '07-groups'; $sps = & $load '10-service-principals'
        $userById = @{}; foreach ($u in @(& $rows $users)) { $userById[[string]$u.Id] = $u }
        $groupIds = @{}; foreach ($g in @(& $rows $groups)) { $groupIds[[string]$g.Id] = $g }
        $spById = @{}; foreach ($sp in @(& $rows $sps)) { $spById[[string]$sp.Id] = $sp }
        $who = { param($x) $id = [string]$x.PrincipalId; if ($userById.ContainsKey($id)) { [string]$userById[$id].UserPrincipalName } elseif ($spById.ContainsKey($id)) { [string]$spById[$id].DisplayName } elseif ($groupIds.ContainsKey($id)) { [string]$groupIds[$id].DisplayName } else { "$($x.PrincipalType) $id" } }

        # AZ-011 owners per subscription (direct plus inherited from management group and root)
        $owners = @($a | Where-Object { [string]$_.RoleName -eq 'Owner' })
        $overLimit = @(); $syncedOwners = @()
        foreach ($sub in $s) {
            $mine = @($owners | Where-Object { ([string]$_.SubscriptionId -eq [string]$sub.SubscriptionId -and [string]$_.ScopeLevel -eq 'subscription') -or [string]$_.ScopeLevel -in @('root', 'managementGroup') })
            $principals = @($mine | ForEach-Object { $_.PrincipalId } | Sort-Object -Unique)
            if ($principals.Count -gt [int]$t.maxOwnersPerSubscription) { $overLimit += , [ordered]@{ name = [string]$sub.Name; detail = "$($principals.Count) owners (limit $($t.maxOwnersPerSubscription)): $(@($mine | ForEach-Object { & $who $_ } | Sort-Object -Unique) -join ', ')" } }
            foreach ($o in $mine) { $u = $userById[[string]$o.PrincipalId]; if ($u -and $u.OnPremisesSyncEnabled -eq $true) { $syncedOwners += , [ordered]@{ name = [string]$u.UserPrincipalName; detail = "Owner on $($sub.Name), synced from on-premises AD" } } }
        }
        $facts.subscriptionsOverOwnerLimit = $overLimit.Count
        $facts.syncedOwners = @($syncedOwners | ForEach-Object { $_.name } | Sort-Object -Unique).Count
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

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('az-01-subscriptions.json', 'az-05-role-assignments.json') }
}
