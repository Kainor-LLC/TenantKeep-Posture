# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureAzureCollection {
    <#
    .SYNOPSIS
        The Azure collector (spec 4.13): subscriptions and management groups, Defender for Cloud plans, contacts,
        secure scores and assessments, policy assignments, activity log exports, role assignments and definitions,
        classic administrators, resource hygiene (tags, locks, orphans), Key Vault, storage and SQL posture, Entra
        Connect Health, and the Entra diagnostic settings that feed the log export check.
    .DESCRIPTION
        Needs a Connect-AzAccount session with Reader on the subscriptions (or the management group) and Security
        Reader; never connects. Resource Graph at tenant scope carries the fleet-wide reads; per-subscription REST reads
        are capped at 200 subscriptions. Every call goes through the two Get-only entry points. API versions are pinned
        per call; items marked (verify) are confirmed against documentation only until the first live run.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Folder)

    $ErrorActionPreference = 'Stop'
    $files = [System.Collections.Generic.List[string]]::new()
    $save = { param($Data, [string] $Name, [bool] $Csv = $false) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data -AsArray -Csv:$Csv)) }
    $saveOne = { param($Data, [string] $Name) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data)) }
    $q = { param([string] $Kql) @(Invoke-PostureAzureQuery -Query $Kql) }
    $rest = { param([string] $Path) @(Invoke-PostureAzureRequest -Path $Path) }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $str = { param($x) [string]$x }

    # ---------- 1. Subscriptions and management groups ----------
    $subs = @(Invoke-PostureStep -Label 'Azure subscriptions' -Folder $Folder -Script {
            $rows = & $q "resourcecontainers | where type == 'microsoft.resources/subscriptions' | project subscriptionId, name, state = tostring(properties.state), chain = properties.managementGroupAncestorsChain"
            $flat = @($rows | ForEach-Object {
                    $chainObjects = @(& $v $_ 'chain')
                    $chain = @($chainObjects | ForEach-Object { [string](& $v $_ 'displayName') } | Where-Object { $_ })
                    $chainNames = @($chainObjects | ForEach-Object { [string](& $v $_ 'name') } | Where-Object { $_ })
                    [ordered]@{ SubscriptionId = (& $str $_.subscriptionId); Name = (& $str $_.name); State = (& $str $_.state); ManagementGroupChain = ($chain -join ' / '); ManagementGroupNames = $chainNames; AtTenantRoot = ($chain.Count -le 1); DetailRead = $false }
                })
            # The per-subscription reads below (Defender plans, contacts, activity log export, classic administrators,
            # budgets, spend) go to every enabled subscription. DetailRead says which of them answered every one of
            # those reads, so the checks judge those and say how many were left out, and never count a subscription
            # that was not read as a gap. It is false here and set once the reads are done: a run that stops in
            # between leaves a list that claims nothing.
            & $save $flat 'az-01-subscriptions' $true
            $flat
        })
    $subIds = @($subs | Where-Object { $_ -and $_.State -eq 'Enabled' } | ForEach-Object { $_.SubscriptionId })
    # One read per subscription. A subscription that refuses costs its own rows, never the step's: the others are
    # read and written, the refusal is kept against the subscription, and the step is logged once with how many refused.
    $subErrors = @{}; $subFailures = @{}
    $eachSub = {
        param([string] $What, [scriptblock] $Read)
        $subFailures[$What] = @{ n = 0; first = $null }
        $done = 0
        foreach ($sub in $subIds) {
            try { & $Read $sub }
            catch {
                $message = (([string]$_.Exception.Message) -replace '\s*[\r\n]+\s*', ' ').Trim()
                $subFailures[$What].n++
                if (-not $subFailures[$What].first) { $subFailures[$What].first = "$($sub): $message" }
                if (-not $subErrors.ContainsKey($sub)) { $subErrors[$sub] = [System.Collections.Generic.List[string]]::new() }
                $subErrors[$sub].Add("$($What): $message")
            }
            $done++
            if ($script:PostureProgress -and $subIds.Count -gt 20 -and $done % 20 -eq 0) { $script:PostureProgress.label = "$($What): $done of $($subIds.Count) subscriptions"; Write-PostureProgress }
        }
    }
    $refusals = { param([string] $What) if ($subFailures[$What].n -gt 0) { throw "$What could not be read for $($subFailures[$What].n) of $($subIds.Count) subscriptions. The first: $($subFailures[$What].first)" } }
    Invoke-PostureStep -Label 'Azure management groups' -Folder $Folder -Script {
        $rows = & $q "resourcecontainers | where type == 'microsoft.management/managementgroups' | project name, displayName = tostring(properties.displayName), parent = tostring(properties.details.parent.name)"
        & $save @($rows | ForEach-Object { [ordered]@{ Name = (& $str $_.name); DisplayName = (& $str $_.displayName); Parent = (& $str $_.parent) } }) 'az-01-management-groups' $true
    } | Out-Null

    # ---------- 2. Defender for Cloud ----------
    Invoke-PostureStep -Label 'Defender for Cloud plans' -Folder $Folder -Script {
        $rows = & $eachSub 'Defender for Cloud plans' {
            param($s)
            foreach ($p in @(& $rest "/subscriptions/$s/providers/Microsoft.Security/pricings?api-version=2024-01-01")) { [ordered]@{ SubscriptionId = $s; Plan = (& $v $p 'name'); Tier = (& $v $p 'properties.pricingTier'); SubPlan = (& $v $p 'properties.subPlan') } }
        }
        & $save @($rows) 'az-02-defender-pricings' $true
        & $refusals 'Defender for Cloud plans'
    } | Out-Null
    Invoke-PostureStep -Label 'Defender for Cloud security contacts' -Folder $Folder -Script {
        # The 2023-12-01-preview shape carries notificationsSources (sourceType Alert with minimalSeverity) and isEnabled; older contacts carry alertNotifications. Both are read (live shape confirmed 2026-10-15).
        $rows = & $eachSub 'Defender for Cloud security contacts' {
            param($s)
            foreach ($c in @(& $rest "/subscriptions/$s/providers/Microsoft.Security/securityContacts?api-version=2023-12-01-preview")) {
                $alertSource = @(@(& $v $c 'properties.notificationsSources') | Where-Object { [string](& $v $_ 'sourceType') -eq 'Alert' } | Select-Object -First 1)
                $minimal = & $v $c 'properties.alertNotifications.minimalSeverity'
                if (-not $minimal -and $alertSource.Count -gt 0) { $minimal = & $v $alertSource[0] 'minimalSeverity' }
                $state = & $v $c 'properties.alertNotifications.state'
                if (-not $state) { $state = $(if ($alertSource.Count -gt 0) { 'On' } elseif ((& $v $c 'properties.notificationsSources')) { 'Off' } else { $null }) }
                [ordered]@{ SubscriptionId = $s; Name = (& $v $c 'name'); Emails = (& $v $c 'properties.emails'); AlertState = $state; MinimalSeverity = $minimal; NotifyRoles = @(@(& $v $c 'properties.notificationsByRole.roles') | ForEach-Object { [string]$_ }); IsEnabled = (& $v $c 'properties.isEnabled') }
            }
        }
        & $save @($rows) 'az-02-security-contacts' $true
        & $refusals 'Defender for Cloud security contacts'
    } | Out-Null
    Invoke-PostureStep -Label 'Azure Secure Score and assessments' -Folder $Folder -Script {
        $scores = & $q "securityresources | where type == 'microsoft.security/securescores' | project subscriptionId, name, current = todouble(properties.score.current), max = todouble(properties.score.max), percentage = todouble(properties.score.percentage)"
        & $save @($scores | ForEach-Object { [ordered]@{ SubscriptionId = (& $str $_.subscriptionId); Name = (& $str $_.name); Current = $_.current; Max = $_.max; Percentage = $_.percentage } }) 'az-02-secure-scores' $true
        $summary = & $q "securityresources | where type == 'microsoft.security/assessments' | extend status = tostring(properties.status.code), severity = tostring(properties.metadata.severity) | summarize Count = count() by subscriptionId, status, severity"
        & $save @($summary | ForEach-Object { [ordered]@{ SubscriptionId = (& $str $_.subscriptionId); Status = (& $str $_.status); Severity = (& $str $_.severity); Count = [int]$_.Count } }) 'az-02-assessments-summary' $true
        $top = & $q "securityresources | where type == 'microsoft.security/assessments' | where tostring(properties.status.code) == 'Unhealthy' | extend severity = tostring(properties.metadata.severity), displayName = tostring(properties.displayName) | summarize Affected = count() by displayName, severity | top 50 by Affected desc"
        & $save @($top | ForEach-Object { [ordered]@{ Recommendation = (& $str $_.displayName); Severity = (& $str $_.severity); Affected = [int]$_.Affected } }) 'az-02-assessments-top' $true
    } | Out-Null

    # ---------- 3. Policy ----------
    Invoke-PostureStep -Label 'Azure Policy assignments' -Folder $Folder -Script {
        $rows = & $q "policyresources | where type == 'microsoft.authorization/policyassignments' | project id, name, displayName = tostring(properties.displayName), scope = tostring(properties.scope), policyDefinitionId = tostring(properties.policyDefinitionId), enforcementMode = tostring(properties.enforcementMode)"
        & $save @($rows | ForEach-Object { [ordered]@{ Id = (& $str $_.id); Name = (& $str $_.name); DisplayName = (& $str $_.displayName); Scope = (& $str $_.scope); PolicyDefinitionId = (& $str $_.policyDefinitionId); EnforcementMode = (& $str $_.enforcementMode); IsMcsb = ([string]$_.policyDefinitionId -match '(?i)1f3afdf9-d0c9-4c3d-847f-89da613e70a8' -or [string]$_.displayName -match '(?i)cloud security benchmark') } }) 'az-03-policy-assignments' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Azure Policy compliance' -Folder $Folder -Script {
        # What Azure Policy found when it last evaluated: for each subscription how many resources it looked at and
        # how many break at least one policy, and the assignments that most resources break. Counts of distinct
        # resources, from the policy states Resource Graph keeps (the latest evaluation of each).
        $bySub = & $q "policyresources | where type == 'microsoft.policyinsights/policystates' | extend resourceId = tolower(tostring(properties.resourceId)), state = tostring(properties.complianceState) | summarize NonCompliant = dcountif(resourceId, state == 'NonCompliant'), Resources = dcount(resourceId) by subscriptionId"
        & $save @($bySub | ForEach-Object { [ordered]@{ SubscriptionId = (& $str $_.subscriptionId); Resources = [long]$_.Resources; NonCompliant = [long]$_.NonCompliant } }) 'az-03-policy-compliance' $true
        $top = & $q "policyresources | where type == 'microsoft.policyinsights/policystates' | where tostring(properties.complianceState) == 'NonCompliant' | summarize Resources = dcount(tolower(tostring(properties.resourceId))) by assignmentId = tolower(tostring(properties.policyAssignmentId)), assignment = tostring(properties.policyAssignmentName) | order by Resources desc | take 50"
        & $save @($top | ForEach-Object { [ordered]@{ AssignmentId = (& $str $_.assignmentId); Assignment = (& $str $_.assignment); Resources = [long]$_.Resources } }) 'az-03-policy-noncompliant-assignments' $true
    } | Out-Null

    # ---------- 4. Activity log export ----------
    Invoke-PostureStep -Label 'Activity log diagnostic settings' -Folder $Folder -Script {
        $rows = & $eachSub 'Activity log diagnostic settings' {
            param($s)
            $settings = @(& $rest "/subscriptions/$s/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview")
            if ($settings.Count -eq 0) { [ordered]@{ SubscriptionId = $s; Name = $null; WorkspaceId = $null; EventHub = $null; StorageAccountId = $null; Categories = 0 } }
            foreach ($d in $settings) { [ordered]@{ SubscriptionId = $s; Name = (& $v $d 'name'); WorkspaceId = (& $v $d 'properties.workspaceId'); EventHub = (& $v $d 'properties.eventHubAuthorizationRuleId'); StorageAccountId = (& $v $d 'properties.storageAccountId'); Categories = @(@(& $v $d 'properties.logs') | Where-Object { (& $v $_ 'enabled') -eq $true }).Count } }
        }
        & $save @($rows) 'az-04-activity-log-exports' $true
        & $refusals 'Activity log diagnostic settings'
    } | Out-Null

    # ---------- 5. IAM ----------
    Invoke-PostureStep -Label 'Azure role assignments' -Folder $Folder -Script {
        $defs = & $q "authorizationresources | where type == 'microsoft.authorization/roledefinitions' | project id, roleName = tostring(properties.roleName), roleType = tostring(properties.type), actions = properties.permissions[0].actions, dataActions = properties.permissions[0].dataActions"
        $nameById = @{}
        foreach ($d in $defs) { $nameById[([string]$d.id).ToLowerInvariant()] = [string]$d.roleName }
        $custom = @($defs | Where-Object { [string]$_.roleType -eq 'CustomRole' } | ForEach-Object {
                $acts = @(@($_.actions) | ForEach-Object { [string]$_ }); $data = @(@($_.dataActions) | ForEach-Object { [string]$_ })
                [ordered]@{ Id = (& $str $_.id); RoleName = (& $str $_.roleName); Actions = $acts.Count; Wildcard = (($acts -contains '*') -or ($data -contains '*')) }
            })
        & $save $custom 'az-05-role-definitions-custom' $true
        $rows = & $q "authorizationresources | where type == 'microsoft.authorization/roleassignments' | project id, principalId = tostring(properties.principalId), principalType = tostring(properties.principalType), roleDefinitionId = tostring(properties.roleDefinitionId), scope = tostring(properties.scope), createdOn = tostring(properties.createdOn)"
        $flat = @($rows | ForEach-Object {
                $scope = [string]$_.scope
                $level = $(if ($scope -eq '/') { 'root' } elseif ($scope -match '^/providers/Microsoft\.Management/managementGroups/') { 'managementGroup' } elseif ($scope -match '^/subscriptions/[^/]+/?$') { 'subscription' } elseif ($scope -match '^/subscriptions/[^/]+/resourceGroups/[^/]+/?$') { 'resourceGroup' } else { 'resource' })
                $subId = $(if ($scope -match '^/subscriptions/([^/]+)') { $Matches[1] } else { $null })
                $roleKey = ([string]$_.roleDefinitionId).ToLowerInvariant()
                [ordered]@{ Id = (& $str $_.id); PrincipalId = (& $str $_.principalId); PrincipalType = (& $str $_.principalType); RoleName = $(if ($nameById.ContainsKey($roleKey)) { $nameById[$roleKey] } else { ($roleKey -split '/')[-1] }); RoleDefinitionId = (& $str $_.roleDefinitionId); Scope = $scope; ScopeLevel = $level; SubscriptionId = $subId; CreatedOn = (& $str $_.createdOn) }
            })
        & $save $flat 'az-05-role-assignments' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Classic administrators' -Folder $Folder -Script {
        # The classic administrators resource type is gone on tenants that completed the 2024 retirement (confirmed 2026-10-15: 404 InvalidResourceType);
        # that answer means none are left, which is the pass. Any other error is logged.
        $rows = & $eachSub 'Classic administrators' {
            param($s)
            $answer = $(try { @(& $rest "/subscriptions/$s/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01") } catch { if ($_.Exception.Message -match 'InvalidResourceType|404') { @() } else { throw } })
            foreach ($a in $answer) { [ordered]@{ SubscriptionId = $s; EmailAddress = (& $v $a 'properties.emailAddress'); Role = (& $v $a 'properties.role') } }
        }
        & $save @($rows) 'az-05-classic-administrators' $true
        & $refusals 'Classic administrators'
    } | Out-Null
    Invoke-PostureStep -Label 'Azure Lighthouse delegations' -Folder $Folder -Script {
        # Subscriptions and resource groups another tenant manages through Azure Lighthouse: who, under which offer,
        # with which roles. The assignment says where, the definition says who and what; they are read apart and
        # joined here. A delegation whose definition cannot be read keeps its row, with its roles unknown.
        $assignments = & $q "managedserviceresources | where type == 'microsoft.managedservices/registrationassignments' | project id, subscriptionId, resourceGroup, definitionId = tolower(tostring(properties.registrationDefinitionId))"
        $definitions = & $q "managedserviceresources | where type == 'microsoft.managedservices/registrationdefinitions' | project definitionId = tolower(id), offer = tostring(properties.registrationDefinitionName), managedByTenantId = tostring(properties.managedByTenantId), managedByTenantName = tostring(properties.managedByTenantName), authorizations = properties.authorizations, eligible = properties.eligibleAuthorizations"
        $byDefinition = @{}; foreach ($d in $definitions) { $byDefinition[(& $str $d.definitionId)] = $d }
        $roleIds = { param($list) @(@($list) | Where-Object { $_ } | ForEach-Object { ((& $str (& $v $_ 'roleDefinitionId')) -split '/')[-1].ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique) }
        & $save @($assignments | ForEach-Object {
                $key = & $str $_.definitionId
                $d = $(if ($byDefinition.ContainsKey($key)) { $byDefinition[$key] } else { $null })
                [ordered]@{
                    Id = (& $str $_.id); SubscriptionId = (& $str $_.subscriptionId); ResourceGroup = (& $str $_.resourceGroup)
                    DefinitionRead = ($null -ne $d); Offer = $(if ($d) { & $str $d.offer }); ManagedByTenantId = $(if ($d) { & $str $d.managedByTenantId }); ManagedByTenantName = $(if ($d) { & $str $d.managedByTenantName })
                    Roles = $(if ($d) { (& $roleIds $d.authorizations) -join ';' }); EligibleRoles = $(if ($d) { (& $roleIds $d.eligible) -join ';' })
                    Principals = $(if ($d) { @(@($d.authorizations) + @($d.eligible) | Where-Object { $_ } | ForEach-Object { & $str (& $v $_ 'principalId') } | Where-Object { $_ } | Sort-Object -Unique).Count })
                }
            }) 'az-17-lighthouse-delegations' $true
    } | Out-Null

    # ---------- 6. Resource hygiene ----------
    Invoke-PostureStep -Label 'Azure resource hygiene' -Folder $Folder -Script {
        $byType = & $q "resources | summarize Count = count() by subscriptionId, type"
        & $save @($byType | ForEach-Object { [ordered]@{ SubscriptionId = (& $str $_.subscriptionId); Type = (& $str $_.type); Count = [int]$_.Count } }) 'az-06-resources-by-type' $true
        $tags = @(& $q "resources | extend hasOwner = isnotempty(tags['owner']) or isnotempty(tags['Owner']), hasEnv = isnotempty(tags['environment']) or isnotempty(tags['Environment']) | summarize Total = count(), Tagged = countif(hasOwner and hasEnv)")
        $disks = @(& $q "resources | where type == 'microsoft.compute/disks' and tostring(properties.diskState) == 'Unattached' | summarize Count = count()")
        $pips = @(& $q "resources | where type == 'microsoft.network/publicipaddresses' and isnull(properties.ipConfiguration) | summarize Count = count()")
        $nics = @(& $q "resources | where type == 'microsoft.network/networkinterfaces' and isnull(properties.virtualMachine) and isnull(properties.privateEndpoint) | summarize Count = count()")
        $emptyRg = @(& $q "resourcecontainers | where type == 'microsoft.resources/subscriptions/resourcegroups' | project subscriptionId, resourceGroup = tolower(name) | join kind=leftouter (resources | summarize c = count() by subscriptionId, resourceGroup = tolower(resourceGroup)) on subscriptionId, resourceGroup | where isnull(c) | summarize Count = count()")
        $first = { param($r, [string] $n) $x = @($r | Select-Object -First 1); if ($x.Count -gt 0) { [int](& $v $x[0] $n) } else { 0 } }
        & $saveOne ([ordered]@{ Resources = (& $first $tags 'Total'); TaggedOwnerAndEnvironment = (& $first $tags 'Tagged'); UnattachedDisks = (& $first $disks 'Count'); UnusedPublicIps = (& $first $pips 'Count'); NicsWithoutVm = (& $first $nics 'Count'); EmptyResourceGroups = (& $first $emptyRg 'Count') }) 'az-06-resources-summary'
        $locks = & $q "resources | where type == 'microsoft.authorization/locks' | project id, name, level = tostring(properties.level)"
        & $save @($locks | ForEach-Object { [ordered]@{ Id = (& $str $_.id); Name = (& $str $_.name); Level = (& $str $_.level); LockedScope = (([string]$_.id) -replace '/providers/Microsoft\.Authorization/locks/.*$', '') } }) 'az-06-locks' $true
        $vaults = & $q "resources | where type in~ ('microsoft.keyvault/vaults', 'microsoft.recoveryservices/vaults') | project id, name, type, subscriptionId, resourceGroup"
        & $save @($vaults | ForEach-Object { [ordered]@{ Id = (& $str $_.id); Name = (& $str $_.name); Type = (& $str $_.type); SubscriptionId = (& $str $_.subscriptionId); ResourceGroup = (& $str $_.resourceGroup) } }) 'az-06-vaults' $true
    } | Out-Null

    # ---------- 7. Data plane posture ----------
    Invoke-PostureStep -Label 'Key Vault, storage and SQL posture' -Folder $Folder -Script {
        $kv = & $q "resources | where type == 'microsoft.keyvault/vaults' | project id, name, subscriptionId, rbac = tobool(properties.enableRbacAuthorization), purge = tobool(properties.enablePurgeProtection), softDelete = tobool(properties.enableSoftDelete), publicNetworkAccess = tostring(properties.publicNetworkAccess), defaultAction = tostring(properties.networkAcls.defaultAction)"
        & $save @($kv | ForEach-Object { [ordered]@{ Id = (& $str $_.id); Name = (& $str $_.name); SubscriptionId = (& $str $_.subscriptionId); RbacAuthorization = $_.rbac; PurgeProtection = $_.purge; SoftDelete = $_.softDelete; PublicNetworkAccess = (& $str $_.publicNetworkAccess); DefaultAction = (& $str $_.defaultAction) } }) 'az-07-keyvaults' $true
        $st = & $q "resources | where type == 'microsoft.storage/storageaccounts' | project id, name, subscriptionId, sharedKey = tobool(properties.allowSharedKeyAccess), blobPublic = tobool(properties.allowBlobPublicAccess), httpsOnly = tobool(properties.supportsHttpsTrafficOnly), minTls = tostring(properties.minimumTlsVersion), publicNetworkAccess = tostring(properties.publicNetworkAccess)"
        & $save @($st | ForEach-Object { [ordered]@{ Id = (& $str $_.id); Name = (& $str $_.name); SubscriptionId = (& $str $_.subscriptionId); AllowSharedKeyAccess = $_.sharedKey; AllowBlobPublicAccess = $_.blobPublic; HttpsOnly = $_.httpsOnly; MinimumTlsVersion = (& $str $_.minTls); PublicNetworkAccess = (& $str $_.publicNetworkAccess) } }) 'az-07-storage' $true
        $sql = & $q "resources | where type == 'microsoft.sql/servers' | project id, name, subscriptionId, aadOnly = tobool(properties.administrators.azureADOnlyAuthentication), publicNetworkAccess = tostring(properties.publicNetworkAccess)"
        & $save @($sql | ForEach-Object { [ordered]@{ Id = (& $str $_.id); Name = (& $str $_.name); SubscriptionId = (& $str $_.subscriptionId); EntraOnlyAuthentication = $_.aadOnly; PublicNetworkAccess = (& $str $_.publicNetworkAccess) } }) 'az-07-sql-servers' $true
    } | Out-Null

    # ---------- 8. Entra Connect Health, 9. Entra diagnostic settings ----------
    Invoke-PostureStep -Label 'Entra Connect Health' -Folder $Folder -Script {
        # (verify) the ADHybridHealthService endpoint and its fields; it answers only for tenants with the agent registered
        $services = @(& $rest '/providers/Microsoft.ADHybridHealthService/services?api-version=2014-01-01')
        & $save @($services | ForEach-Object { [ordered]@{ Name = (& $v $_ 'serviceName'); Type = (& $v $_ 'type'); Health = (& $v $_ 'health'); ActiveAlerts = (& $v $_ 'activeAlerts'); MonitoringConfigurationsComputed = (& $v $_ 'monitoringConfigurationsComputed') } }) 'az-08-entra-connect-health' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Entra diagnostic settings' -Folder $Folder -Script {
        $settings = @(& $rest '/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview')
        & $save @($settings | ForEach-Object { [ordered]@{ Name = (& $v $_ 'name'); WorkspaceId = (& $v $_ 'properties.workspaceId'); EventHub = (& $v $_ 'properties.eventHubAuthorizationRuleId'); StorageAccountId = (& $v $_ 'properties.storageAccountId'); Categories = @(@(& $v $_ 'properties.logs') | Where-Object { (& $v $_ 'enabled') -eq $true } | ForEach-Object { [string](& $v $_ 'category') }) } }) 'az-09-entra-diagnostic-settings' $true
    } | Out-Null

    # ---------- 5b. Exposure, cost guard rails, backup vaults, Sentinel, Entra Domain Services ----------
    Invoke-PostureStep -Label 'Management ports open to the internet' -Folder $Folder -Script {
        # Inbound allow rules from anywhere on network security groups attached to something; ports judged here.
        $rules = & $q "resources | where type =~ 'microsoft.network/networksecuritygroups' | where array_length(properties.networkInterfaces) > 0 or array_length(properties.subnets) > 0 | mv-expand rule = properties.securityRules | where tostring(rule.properties.direction) =~ 'Inbound' and tostring(rule.properties.access) =~ 'Allow' | extend src = tostring(rule.properties.sourceAddressPrefix), srcs = tostring(rule.properties.sourceAddressPrefixes) | where src in~ ('*', 'Internet', '0.0.0.0/0', 'Any') or srcs has '0.0.0.0/0' or srcs has 'Internet' | project nsg = name, subscriptionId, resourceGroup, rule = tostring(rule.name), port = tostring(rule.properties.destinationPortRange), ports = tostring(rule.properties.destinationPortRanges)"
        $mgmt = @(22, 3389, 5985, 5986)
        $hits = foreach ($r in $rules) {
            $specs = @(@([string]$r.port) + @(([string]$r.ports) -replace '[\[\]"]', '' -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            $open = @($mgmt | Where-Object { $p = $_; @($specs | Where-Object { $_ -eq '*' -or $_ -eq [string]$p -or ($_ -match '^(\d+)-(\d+)$' -and [int]$Matches[1] -le $p -and [int]$Matches[2] -ge $p) }).Count -gt 0 })
            if ($open.Count) { [ordered]@{ Nsg = (& $str $r.nsg); SubscriptionId = (& $str $r.subscriptionId); ResourceGroup = (& $str $r.resourceGroup); Rule = (& $str $r.rule); Ports = ($open -join ', ') } }
        }
        & $save @($hits) 'az-12-open-management-ports' $true
    } | Out-Null
    $budgetCount = @{}
    Invoke-PostureStep -Label 'Subscription budgets' -Folder $Folder -Script {
        # Read once here and kept by subscription: the pay-as-you-go step below asks the same question.
        $rows = & $eachSub 'Subscription budgets' {
            param($s)
            $budgetCount[$s] = @(& $rest "/subscriptions/$s/providers/Microsoft.Consumption/budgets?api-version=2023-05-01").Count
            [ordered]@{ SubscriptionId = $s; Budgets = $budgetCount[$s] }
        }
        & $save @($rows) 'az-13-budgets' $true
        & $refusals 'Subscription budgets'
    } | Out-Null
    Invoke-PostureStep -Label 'Backup vault protection' -Folder $Folder -Script {
        # Soft delete keeps deleted backups recoverable; immutability stops backups being shortened or removed (verify the
        # property paths on Backup vaults).
        $bv = & $q "resources | where type in~ ('microsoft.recoveryservices/vaults', 'microsoft.dataprotection/backupvaults') | project name, type, subscriptionId, resourceGroup, softDelete = tostring(coalesce(properties.securitySettings.softDeleteSettings.softDeleteState, properties.securitySettings.softDeleteSettings.state)), immutability = tostring(properties.securitySettings.immutabilitySettings.state)"
        & $save @($bv | ForEach-Object { [ordered]@{ Name = (& $str $_.name); Type = (& $str $_.type); SubscriptionId = (& $str $_.subscriptionId); ResourceGroup = (& $str $_.resourceGroup); SoftDelete = (& $str $_.softDelete); Immutability = (& $str $_.immutability) } }) 'az-14-backup-vaults' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Microsoft Sentinel' -Folder $Folder -Script {
        # Workspaces with Sentinel, and which data connectors they have (verify: content hub connectors may report a different kind).
        $ws = & $q "resources | where type =~ 'microsoft.operationsmanagement/solutions' and name startswith 'SecurityInsights' | project workspaceId = tostring(properties.workspaceResourceId), subscriptionId"
        & $save @(@($ws | Where-Object { $_.workspaceId } | Select-Object -First 50) | ForEach-Object {
                $kinds = @(& $rest "$($_.workspaceId)/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2024-03-01" | ForEach-Object { & $str (& $v $_ 'kind') } | Sort-Object -Unique)
                [ordered]@{ Workspace = (Split-Path ([string]$_.workspaceId) -Leaf); SubscriptionId = (& $str $_.subscriptionId); Connectors = ($kinds -join ', ') }
            }) 'az-15-sentinel' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Entra Domain Services' -Folder $Folder -Script {
        $ds = & $q "resources | where type =~ 'microsoft.aad/domainservices' | project name, subscriptionId, s = properties.domainSecuritySettings"
        & $save @($ds | ForEach-Object { [ordered]@{ Name = (& $str $_.name); SubscriptionId = (& $str $_.subscriptionId); NtlmV1 = (& $str (& $v $_.s 'ntlmV1')); TlsV1 = (& $str (& $v $_.s 'tlsV1')); SyncNtlmPasswords = (& $str (& $v $_.s 'syncNtlmPasswords')); KerberosRc4Encryption = (& $str (& $v $_.s 'kerberosRc4Encryption')); KerberosArmoring = (& $str (& $v $_.s 'kerberosArmoring')); LdapSigning = (& $str (& $v $_.s 'ldapSigning')); ChannelBinding = (& $str (& $v $_.s 'channelBinding')) } }) 'az-16-entra-domain-services' $true
    } | Out-Null

    # ---------- 6. Microsoft 365 pay-as-you-go and Backup ----------
    Invoke-PostureStep -Label 'Microsoft 365 pay-as-you-go spend' -Folder $Folder -Script {
        # Which subscriptions pay for Microsoft 365 pay-as-you-go services (Backup, Archive, SharePoint Premium, Copilot
        # messages) over the last 30 days, and whether each has a budget. Service names are Cost Management's (verify).
        $to = [datetime]::UtcNow.Date; $from = $to.AddDays(-30)
        $query = [ordered]@{ type = 'ActualCost'; timeframe = 'Custom'; timePeriod = [ordered]@{ from = $from.ToString('yyyy-MM-ddT00:00:00Z'); to = $to.ToString('yyyy-MM-ddT00:00:00Z') }; dataset = [ordered]@{ granularity = 'None'; aggregation = [ordered]@{ totalCost = [ordered]@{ name = 'Cost'; function = 'Sum' } }; grouping = @([ordered]@{ type = 'Dimension'; name = 'ServiceName' }) } }
        $rows = & $eachSub 'Microsoft 365 pay-as-you-go spend' {
            param($s)
            $costs = @(Invoke-PostureCostQuery -Path "/subscriptions/$s/providers/Microsoft.CostManagement/query?api-version=2023-11-01" -Query $query)
            $m365 = @($costs | Where-Object { [string](& $v $_ 'ServiceName') -match 'Microsoft 365|SharePoint|Syntex|Purview|Copilot' -and [double](& $v $_ 'Cost') -gt 0 })
            if ($m365.Count -eq 0) { return }
            # The budgets step already counted them; asked again only when that step did not reach this subscription.
            $budgets = $(if ($budgetCount.ContainsKey($s)) { $budgetCount[$s] } else { @(& $rest "/subscriptions/$s/providers/Microsoft.Consumption/budgets?api-version=2023-05-01").Count })
            [ordered]@{ SubscriptionId = $s; Services = @($m365 | ForEach-Object { [ordered]@{ Name = [string](& $v $_ 'ServiceName'); Cost = [Math]::Round([double](& $v $_ 'Cost'), 2); Currency = [string](& $v $_ 'Currency') } }); Budgets = $budgets }
        }
        & $save @($rows) 'az-10-m365-payg'
        & $refusals 'Microsoft 365 pay-as-you-go spend'
    } | Out-Null

    # Which subscriptions answered every per-subscription read: written into the list now that the reads are done.
    Invoke-PostureStep -Label 'Azure subscriptions read in detail' -Folder $Folder -Script {
        if ($subs.Count -eq 0) { return }
        $final = @($subs | ForEach-Object {
                $row = [ordered]@{}; foreach ($k in $_.get_Keys()) { $row[$k] = $_[$k] }
                $id = [string]$row.SubscriptionId
                $row.DetailRead = ([string]$row.State -eq 'Enabled' -and -not $subErrors.ContainsKey($id))
                $row.DetailError = $(if ($subErrors.ContainsKey($id)) { ($subErrors[$id] -join ' | ') } else { $null })
                $row
            })
        & $save $final 'az-01-subscriptions' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Microsoft 365 Backup' -Folder $Folder -Script {
        # Microsoft 365 Backup through Graph: whether the service is on and which workloads have an active policy.
        $svc = Invoke-PostureGraphRequest -Uri 'solutions/backupRestore' -ApiVersion 'v1.0' -Single
        $active = { param([string] $kind) @(Invoke-PostureGraphRequest -Uri "solutions/backupRestore/$kind" -ApiVersion 'v1.0' | Where-Object { [string](& $v $_ 'status') -eq 'active' }).Count }
        & $saveOne ([ordered]@{ ServiceStatus = (& $v $svc 'serviceStatus.status'); SharePointPolicies = (& $active 'sharePointProtectionPolicies'); OneDrivePolicies = (& $active 'oneDriveForBusinessProtectionPolicies'); ExchangePolicies = (& $active 'exchangeProtectionPolicies') }) 'az-11-m365-backup'
    } | Out-Null

    $errorsPath = Join-Path (Get-PostureRunLayout -Folder $Folder).errors 'errors.txt'
    return @{ files = $files.ToArray(); errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath }); subscriptions = $subIds.Count }
}
