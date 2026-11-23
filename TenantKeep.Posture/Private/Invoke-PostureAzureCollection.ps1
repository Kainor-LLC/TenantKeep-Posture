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
        # joined here. A delegation whose definition cannot be read keeps its row, with its roles unknown. The Resource
        # Graph table is managedservicesresources, "services" in the plural; any other spelling is a bad request.
        $assignments = & $q "managedservicesresources | where type == 'microsoft.managedservices/registrationassignments' | project id, subscriptionId, resourceGroup, definitionId = tolower(tostring(properties.registrationDefinitionId))"
        $definitions = & $q "managedservicesresources | where type == 'microsoft.managedservices/registrationdefinitions' | project definitionId = tolower(id), offer = tostring(properties.registrationDefinitionName), managedByTenantId = tostring(properties.managedByTenantId), managedByTenantName = tostring(properties.managedByTenantName), authorizations = properties.authorizations, eligible = properties.eligibleAuthorizations"
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
    Invoke-PostureStep -Label 'Microsoft Sentinel configuration' -Folder $Folder -Script {
        # What each Sentinel workspace is set up to do with what it receives: detect, respond, keep, and watch
        # itself. One row per workspace, holding counts and the names of settings, never a rule's query or an
        # indicator. A part that cannot be read is named in NotRead and its fields stay empty, so a check has no
        # answer for it and never reads it as zero.
        $ws = @(& $q "resources | where type =~ 'microsoft.operationsmanagement/solutions' and name startswith 'SecurityInsights' | project workspaceId = tostring(properties.workspaceResourceId), subscriptionId" | Where-Object { $_.workspaceId } | Select-Object -First 50)
        # Listed once for every workspace: the Sentinel workbooks, the data collection rules with where they send,
        # and which Logic Apps are turned on (a playbook is one).
        $shared = @{ workbooks = $null; rules = $null; logicApps = $null }
        if ($ws.Count -gt 0) {
            try { $shared.workbooks = @(& $q "resources | where type =~ 'microsoft.insights/workbooks' | where tostring(properties.category) =~ 'sentinel' | project source = tolower(tostring(properties.sourceId))") } catch { Write-Verbose "Sentinel workbooks not read: $($_.Exception.Message)" }
            try { $shared.rules = @(& $q "resources | where type =~ 'microsoft.insights/datacollectionrules' | mv-expand destination = properties.destinations.logAnalytics | extend destinationName = tostring(destination.name), workspace = tolower(tostring(destination.workspaceResourceId)) | where isnotempty(workspace) | mv-expand flow = properties.dataFlows | where flow.destinations has destinationName | summarize flows = count() by id, workspace") } catch { Write-Verbose "Data collection rules not read: $($_.Exception.Message)" }
            try { $shared.logicApps = @(& $q "resources | where type =~ 'microsoft.logic/workflows' | project id = tolower(id), state = tostring(properties.state)") } catch { Write-Verbose "Logic Apps not read: $($_.Exception.Message)" }
        }
        $securityTables = @('SecurityEvent', 'SigninLogs', 'AuditLogs', 'AADNonInteractiveUserSignInLogs', 'AADServicePrincipalSignInLogs', 'OfficeActivity', 'SecurityAlert', 'SecurityIncident', 'CommonSecurityLog', 'Syslog', 'WindowsFirewall', 'DeviceLogonEvents', 'IdentityLogonEvents', 'EmailEvents', 'CloudAppEvents')
        $detectionTables = @('SigninLogs', 'AuditLogs', 'AADNonInteractiveUserSignInLogs', 'AADServicePrincipalSignInLogs', 'OfficeActivity', 'SecurityAlert', 'SecurityIncident', 'IdentityLogonEvents', 'EmailEvents', 'CloudAppEvents', 'SecurityEvent')
        $now = [datetime]::UtcNow
        & $save @($ws | ForEach-Object {
                $id = [string]$_.workspaceId; $key = $id.ToLowerInvariant(); $si = "$id/providers/Microsoft.SecurityInsights"
                $notRead = [System.Collections.Generic.List[string]]::new()
                $row = [ordered]@{ Workspace = (Split-Path $id -Leaf); SubscriptionId = (& $str $_.subscriptionId) }
                # Each part by itself: one refusal leaves the others read.
                $part = { param([string] $What, [scriptblock] $Read) try { & $Read } catch { $notRead.Add($What); Write-Verbose "Sentinel $What not read for $($row.Workspace): $($_.Exception.Message)" } }
                foreach ($field in 'RulesEnabled', 'RuleKinds', 'AutomationActive', 'PlaybookRules', 'PlaybooksOff', 'Watchlists', 'Ueba', 'UebaSources', 'ThreatIntelConnectors', 'ThreatIndicators', 'HealthLogs', 'RetentionDays', 'TableRetention', 'TablePlans', 'HuntingQueries', 'Bookmarks', 'Workbooks', 'CollectionRules', 'Solutions') { $row[$field] = $null }
                & $part 'analytics rules' {
                    $on = @(& $rest "$si/alertRules?api-version=2024-09-01" | Where-Object { (& $v $_ 'properties.enabled') -eq $true })
                    $row.RulesEnabled = $on.Count
                    $row.RuleKinds = (@($on | ForEach-Object { & $str (& $v $_ 'kind') } | Sort-Object -Unique) -join ', ')
                }
                & $part 'automation rules' {
                    # Active: turned on and not past its expiry.
                    $active = @(& $rest "$si/automationRules?api-version=2024-09-01" | Where-Object {
                            $expires = & $v $_ 'properties.triggeringLogic.expirationTimeUtc'
                            (& $v $_ 'properties.triggeringLogic.isEnabled') -eq $true -and (-not $expires -or (ConvertTo-PostureUtcDateTime $expires) -gt $now)
                        })
                    $playbooks = @($active | ForEach-Object { @(& $v $_ 'properties.actions') } | Where-Object { $_ -and [string](& $v $_ 'actionType') -eq 'RunPlaybook' } | ForEach-Object { ([string](& $v $_ 'actionConfiguration.logicAppResourceId')).ToLowerInvariant() } | Where-Object { $_ })
                    $row.AutomationActive = $active.Count
                    $row.PlaybookRules = $playbooks.Count
                    # A playbook the list of Logic Apps shows as turned off. One it does not show (a Standard Logic App) is not counted.
                    if ($null -ne $shared.logicApps) { $row.PlaybooksOff = @($playbooks | Where-Object { $p = $_; @($shared.logicApps | Where-Object { [string]$_.id -eq $p -and [string]$_.state -ne 'Enabled' }).Count -gt 0 }).Count }
                }
                & $part 'watchlists' { $row.Watchlists = @(& $rest "$si/watchlists?api-version=2024-09-01").Count }
                & $part 'UEBA' {
                    try { $ueba = @(& $rest "$si/settings/Ueba?api-version=2024-10-01-preview")[0]; $sources = @(@(& $v $ueba 'properties.dataSources') | Where-Object { $_ }); $row.Ueba = 'on'; $row.UebaSources = ($sources -join ', ') }
                    catch { if ([string]$_.Exception.Message -match 'returned 404') { $row.Ueba = 'off'; $row.UebaSources = '' } else { throw } }
                }
                & $part 'threat intelligence' {
                    $row.ThreatIntelConnectors = (@(& $rest "$si/dataConnectors?api-version=2024-03-01" | ForEach-Object { & $str (& $v $_ 'kind') } | Where-Object { $_ -in 'MicrosoftThreatIntelligence', 'ThreatIntelligence', 'ThreatIntelligenceTaxii' } | Sort-Object -Unique) -join ', ')
                    $total = 0
                    foreach ($m in @(& $rest "$si/threatIntelligence/main/metrics?api-version=2024-09-01")) { foreach ($source in @(& $v $m 'properties.sourceMetrics')) { if ($source) { $total += [int](& $v $source 'metricValue') } } }
                    $row.ThreatIndicators = $total
                }
                & $part 'health and audit logging' {
                    # Where the setting is made (verify on a live run): on Sentinel's own health resource, or on the workspace.
                    $settings = @(foreach ($scope in "$si/settings/SentinelHealth", $id) { try { & $rest "$scope/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview" } catch { if ([string]$_.Exception.Message -notmatch 'returned 40[04]') { throw } } })
                    $row.HealthLogs = $(if (@($settings | Where-Object { $_ -and (& $v $_ 'properties.workspaceId') -and @(@(& $v $_ 'properties.logs') | Where-Object { $_ -and (& $v $_ 'enabled') -eq $true }).Count -gt 0 }).Count -gt 0) { 'on' } else { 'off' })
                }
                & $part 'retention' {
                    $row.RetentionDays = [int](& $v (@(& $rest "$($id)?api-version=2023-09-01")[0]) 'properties.retentionInDays')
                    $tables = @(& $rest "$id/tables?api-version=2022-10-01")
                    # The days each security table the workspace has is kept in total, and the plan each detection table is on.
                    $row.TableRetention = (@($tables | Where-Object { [string](& $v $_ 'name') -in $securityTables -and $null -ne (& $v $_ 'properties.totalRetentionInDays') } | ForEach-Object { "$(& $v $_ 'name')=$([int](& $v $_ 'properties.totalRetentionInDays'))" }) -join '; ')
                    $row.TablePlans = (@($tables | Where-Object { [string](& $v $_ 'name') -in $detectionTables -and [string](& $v $_ 'properties.plan') } | ForEach-Object { "$(& $v $_ 'name')=$(& $v $_ 'properties.plan')" }) -join '; ')
                }
                & $part 'hunting' {
                    $row.HuntingQueries = @(& $rest "$id/savedSearches?api-version=2020-08-01" | Where-Object { [string](& $v $_ 'properties.category') -eq 'Hunting Queries' }).Count
                    $row.Bookmarks = @(& $rest "$si/bookmarks?api-version=2024-09-01").Count
                }
                & $part 'solutions' { $row.Solutions = (@(& $rest "$si/contentPackages?api-version=2024-09-01" | ForEach-Object { & $str (& $v $_ 'properties.displayName') } | Where-Object { $_ } | Sort-Object -Unique) -join '; ') }
                if ($null -ne $shared.workbooks) { $row.Workbooks = @($shared.workbooks | Where-Object { [string]$_.source -eq $key }).Count } else { $notRead.Add('workbooks') }
                if ($null -ne $shared.rules) { $row.CollectionRules = @($shared.rules | Where-Object { [string]$_.workspace -eq $key }).Count } else { $notRead.Add('data collection rules') }
                $row.NotRead = ($notRead -join ', ')
                $row
            }) 'az-22-sentinel-settings' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Network security policies' -Folder $Folder -Script {
        # Azure Firewall policies and the two kinds of web application firewall policy: what each does with what it
        # detects. Resource Graph gives the rule sets and custom rules as they are; what is kept is whether the ones
        # Microsoft's Zero Trust Assessment looks for are there and on, not the rules themselves.
        $fw = & $q "resources | where type =~ 'microsoft.network/firewallpolicies' | project name, subscriptionId, resourceGroup, tier = tostring(properties.sku.tier), threatIntelMode = tostring(properties.threatIntelMode), idpsMode = tostring(properties.intrusionDetection.mode), tlsCa = tostring(properties.transportSecurity.certificateAuthority.name), firewalls = coalesce(array_length(properties.firewalls), 0)"
        & $save @($fw | ForEach-Object {
                [ordered]@{ Name = (& $str $_.name); SubscriptionId = (& $str $_.subscriptionId); ResourceGroup = (& $str $_.resourceGroup); Tier = (& $str $_.tier); ThreatIntelMode = (& $str $_.threatIntelMode); IdpsMode = (& $str $_.idpsMode); TlsInspection = [bool](& $str $_.tlsCa); Firewalls = [int]$_.firewalls }
            }) 'az-18-firewall-policies' $true
        $count = { param($Rules, [scriptblock] $Test) @(@($Rules) | Where-Object { $_ } | Where-Object $Test).Count }
        $has = { param($Sets, [string[]] $Kind) [bool]@(@($Sets) | Where-Object { $_ -and [string]$_.ruleSetType -in $Kind }).Count }
        $appGw = & $q "resources | where type =~ 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies' | project name, subscriptionId, resourceGroup, attached = coalesce(array_length(properties.applicationGateways), 0), state = tostring(properties.policySettings.state), mode = tostring(properties.policySettings.mode), bodyCheck = tostring(properties.policySettings.requestBodyCheck), ruleSets = properties.managedRules.managedRuleSets, customRules = properties.customRules"
        $frontDoor = & $q "resources | where type =~ 'microsoft.network/frontdoorwebapplicationfirewallpolicies' | project name, subscriptionId, resourceGroup, sku = tostring(sku.name), attached = coalesce(array_length(properties.frontendEndpointLinks), 0) + coalesce(array_length(properties.securityPolicyLinks), 0), state = tostring(properties.policySettings.enabledState), mode = tostring(properties.policySettings.mode), bodyCheck = tostring(properties.policySettings.requestBodyCheck), ruleSets = properties.managedRules.managedRuleSets, customRules = properties.customRules.rules"
        $waf = @(
            @($appGw | ForEach-Object {
                    [ordered]@{
                        Kind = 'ApplicationGateway'; Name = (& $str $_.name); SubscriptionId = (& $str $_.subscriptionId); ResourceGroup = (& $str $_.resourceGroup); Sku = ''; Attached = [int]$_.attached
                        State = (& $str $_.state); Mode = (& $str $_.mode); RequestBodyCheck = [bool]((& $str $_.bodyCheck) -match '(?i)^(true|enabled)$')
                        DefaultRuleSet = (& $has $_.ruleSets @('Microsoft_DefaultRuleSet', 'OWASP')); BotRuleSet = (& $has $_.ruleSets @('Microsoft_BotManagerRuleSet')); HttpDdosRuleSet = (& $has $_.ruleSets @('Microsoft_HTTPDDoSRuleSet'))
                        RateLimitRules = (& $count $_.customRules { [string]$_.ruleType -eq 'RateLimitRule' -and [string]$_.state -eq 'Enabled' }); ChallengeRules = (& $count $_.customRules { [string]$_.action -eq 'JSChallenge' -and [string]$_.state -eq 'Enabled' }); CaptchaRules = 0
                    }
                })
            @($frontDoor | ForEach-Object {
                    [ordered]@{
                        Kind = 'FrontDoor'; Name = (& $str $_.name); SubscriptionId = (& $str $_.subscriptionId); ResourceGroup = (& $str $_.resourceGroup); Sku = (& $str $_.sku); Attached = [int]$_.attached
                        State = (& $str $_.state); Mode = (& $str $_.mode); RequestBodyCheck = [bool]((& $str $_.bodyCheck) -match '(?i)^(true|enabled)$')
                        DefaultRuleSet = (& $has $_.ruleSets @('Microsoft_DefaultRuleSet')); BotRuleSet = (& $has $_.ruleSets @('Microsoft_BotManagerRuleSet')); HttpDdosRuleSet = (& $has $_.ruleSets @('Microsoft_HTTPDDoSRuleSet'))
                        RateLimitRules = (& $count $_.customRules { [string]$_.ruleType -eq 'RateLimitRule' -and [string]$_.enabledState -eq 'Enabled' }); ChallengeRules = (& $count $_.customRules { [string]$_.action -eq 'JSChallenge' -and [string]$_.enabledState -eq 'Enabled' })
                        CaptchaRules = (& $count $_.customRules { [string]$_.action -eq 'Captcha' -and [string]$_.enabledState -eq 'Enabled' })
                    }
                })
        )
        & $save @($waf | Where-Object { $_ }) 'az-19-waf-policies' $true
    } | Out-Null
    # The public IPs found to be protected, kept for the diagnostic settings step that follows.
    $protectedIps = [System.Collections.Generic.List[object]]::new()
    Invoke-PostureStep -Label 'Public IP DDoS protection' -Folder $Folder -Script {
        # A public IP is protected when DDoS protection is on for the address itself, or when it inherits it from a
        # virtual network that has a DDoS protection plan. Which virtual network an address sits in is worked out from
        # what it is attached to: a network interface, a firewall, a bastion, a gateway, an application gateway, or a
        # load balancer (through the interfaces behind it). An address attached to nothing is left out, and one whose
        # network cannot be worked out is saved as unknown, not as unprotected. (verify the property paths live.)
        $ips = & $q "resources | where type =~ 'microsoft.network/publicipaddresses' | project id = tolower(id), name, subscriptionId, resourceGroup, mode = tostring(properties.ddosSettings.protectionMode), ipConfig = tolower(tostring(properties.ipConfiguration.id))"
        $attached = @($ips | Where-Object { & $str $_.ipConfig })
        $vnetOf = @{}; $nicOfBalancer = @{}; $vnetDdos = @{}; $vnetName = @{}
        $kindName = @{ networkinterfaces = 'network interface'; azurefirewalls = 'Azure Firewall'; loadbalancers = 'load balancer'; applicationgateways = 'application gateway'; bastionhosts = 'Bastion host'; virtualnetworkgateways = 'virtual network gateway' }
        if ($attached.Count -gt 0) {
            foreach ($row in @(& $q "resources | where type in~ ('microsoft.network/networkinterfaces', 'microsoft.network/azurefirewalls', 'microsoft.network/bastionhosts', 'microsoft.network/virtualnetworkgateways') | mv-expand ipc = properties.ipConfigurations | extend subnetId = tolower(tostring(ipc.properties.subnet.id)) | where isnotempty(subnetId) | project owner = tolower(id), vnet = tostring(split(subnetId, '/subnets/')[0]) | distinct owner, vnet")) { $vnetOf[(& $str $row.owner)] = (& $str $row.vnet) }
            foreach ($row in @(& $q "resources | where type =~ 'microsoft.network/applicationgateways' | mv-expand ipc = properties.gatewayIPConfigurations | extend subnetId = tolower(tostring(ipc.properties.subnet.id)) | where isnotempty(subnetId) | project owner = tolower(id), vnet = tostring(split(subnetId, '/subnets/')[0]) | distinct owner, vnet")) { $vnetOf[(& $str $row.owner)] = (& $str $row.vnet) }
            foreach ($row in @(& $q "resources | where type =~ 'microsoft.network/loadbalancers' | mv-expand pool = properties.backendAddressPools | mv-expand ipc = pool.properties.backendIPConfigurations | project owner = tolower(id), nic = tostring(split(tolower(tostring(ipc.id)), '/ipconfigurations/')[0]) | distinct owner, nic")) { if (-not $nicOfBalancer.ContainsKey((& $str $row.owner))) { $nicOfBalancer[(& $str $row.owner)] = (& $str $row.nic) } }
            foreach ($row in @(& $q "resources | where type =~ 'microsoft.network/virtualnetworks' | project vnet = tolower(id), name, ddos = tobool(properties.enableDdosProtection)")) { $vnetDdos[(& $str $row.vnet)] = [bool]($row.ddos -eq $true); $vnetName[(& $str $row.vnet)] = (& $str $row.name) }
        }
        & $save @($attached | ForEach-Object {
                $owner = [regex]::Replace((& $str $_.ipConfig), '/[a-z]*ipconfigurations/[^/]+$', '')
                $ownerType = (($owner -split '/providers/microsoft.network/')[-1] -split '/')[0]
                $vnet = $(if ($vnetOf.ContainsKey($owner)) { $vnetOf[$owner] } elseif ($nicOfBalancer.ContainsKey($owner) -and $vnetOf.ContainsKey($nicOfBalancer[$owner])) { $vnetOf[$nicOfBalancer[$owner]] } else { '' })
                $mode = $(if (& $str $_.mode) { & $str $_.mode } else { 'Disabled' })
                $protected = $(if ($mode -eq 'Enabled') { $true } elseif ($mode -ne 'VirtualNetworkInherited') { $false } elseif ($vnet -and $vnetDdos.ContainsKey($vnet)) { [bool]$vnetDdos[$vnet] } else { $null })
                if ($protected -eq $true) { $protectedIps.Add([pscustomobject]@{ id = (& $str $_.id); name = (& $str $_.name); subscriptionId = (& $str $_.subscriptionId); resourceGroup = (& $str $_.resourceGroup); kind = 'Public IP with DDoS protection' }) }
                [ordered]@{ Id = (& $str $_.id); Name = (& $str $_.name); SubscriptionId = (& $str $_.subscriptionId); ResourceGroup = (& $str $_.resourceGroup); ProtectionMode = $mode; AttachedTo = $(if ($kindName.ContainsKey($ownerType)) { $kindName[$ownerType] } else { $ownerType }); VirtualNetwork = $(if ($vnet -and $vnetName.ContainsKey($vnet)) { $vnetName[$vnet] } else { '' }); Protected = $protected }
            }) 'az-21-public-ip-ddos' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Network diagnostic settings' -Folder $Folder -Script {
        # Whether the things that see attacks write down what they see: each Azure Firewall, each Application Gateway
        # with a web application firewall, each Front Door profile and each public IP with DDoS protection, and whether
        # one of its diagnostic settings sends a log category to a workspace, a storage account or an event hub. One
        # request per resource, so the first 200 are read and the rest are counted.
        # The query only lists; which of them count is decided here. Asked of Resource Graph in one query (a computed
        # column named kind, filtered on), it answered BadRequest on a live tenant, 2026-11-23.
        $targets = @(& $q "resources | where type in~ ('microsoft.network/azurefirewalls', 'microsoft.network/applicationgateways', 'microsoft.cdn/profiles') | project id, name, type, subscriptionId, resourceGroup, tier = tostring(properties.sku.tier), skuName = tostring(sku.name)" | ForEach-Object {
                # Every Azure Firewall; an Application Gateway only when its tier has a web application firewall; a
                # CDN profile only when it is Front Door Standard or Premium.
                $found = $_
                $what = switch ((& $str $found.type).ToLowerInvariant()) {
                    'microsoft.network/azurefirewalls' { 'Azure Firewall' }
                    'microsoft.network/applicationgateways' { if ((& $str $found.tier) -like 'WAF*') { 'Application Gateway' } }
                    'microsoft.cdn/profiles' { if ((& $str $found.skuName) -in 'Standard_AzureFrontDoor', 'Premium_AzureFrontDoor') { 'Front Door' } }
                }
                if ($what) { [pscustomobject]@{ id = (& $str $found.id); name = (& $str $found.name); subscriptionId = (& $str $found.subscriptionId); resourceGroup = (& $str $found.resourceGroup); kind = $what } }
            })
        $targets += @($protectedIps.ToArray())
        $limit = 200
        $rows = @($targets | Select-Object -First $limit | ForEach-Object {
                $target = $_
                $row = [ordered]@{ Kind = (& $str $target.kind); Name = (& $str $target.name); SubscriptionId = (& $str $target.subscriptionId); ResourceGroup = (& $str $target.resourceGroup); Read = $true; Settings = 0; LogsToDestination = $false; Destinations = '' }
                try {
                    $settings = @(& $rest "$(& $str $target.id)/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview")
                    $sending = @($settings | Where-Object { $_ -and @(@(& $v $_ 'properties.logs') | Where-Object { $_ -and (& $v $_ 'enabled') -eq $true }).Count -gt 0 -and ((& $v $_ 'properties.workspaceId') -or (& $v $_ 'properties.storageAccountId') -or (& $v $_ 'properties.eventHubAuthorizationRuleId')) })
                    $row.Settings = $settings.Count
                    $row.LogsToDestination = [bool]($sending.Count -gt 0)
                    $row.Destinations = (@($(if (@($sending | Where-Object { & $v $_ 'properties.workspaceId' }).Count) { 'Log Analytics' }), $(if (@($sending | Where-Object { & $v $_ 'properties.storageAccountId' }).Count) { 'Storage' }), $(if (@($sending | Where-Object { & $v $_ 'properties.eventHubAuthorizationRuleId' }).Count) { 'Event Hub' })) | Where-Object { $_ }) -join ', '
                }
                catch { $row.Read = $false }
                $row
            })
        & $save $rows 'az-20-network-diagnostics' $true
        & $saveOne ([ordered]@{ Resources = $targets.Count; Read = @($rows | Where-Object { $_.Read }).Count; NotRead = @($rows | Where-Object { -not $_.Read }).Count; BeyondLimit = [Math]::Max(0, $targets.Count - $limit) }) 'az-20-network-diagnostics-summary'
    } | Out-Null
    Invoke-PostureStep -Label 'Entra Domain Services' -Folder $Folder -Script {
        $ds = & $q "resources | where type =~ 'microsoft.aad/domainservices' | project name, subscriptionId, s = properties.domainSecuritySettings"
        & $save @($ds | ForEach-Object { [ordered]@{ Name = (& $str $_.name); SubscriptionId = (& $str $_.subscriptionId); NtlmV1 = (& $str (& $v $_.s 'ntlmV1')); TlsV1 = (& $str (& $v $_.s 'tlsV1')); SyncNtlmPasswords = (& $str (& $v $_.s 'syncNtlmPasswords')); KerberosRc4Encryption = (& $str (& $v $_.s 'kerberosRc4Encryption')); KerberosArmoring = (& $str (& $v $_.s 'kerberosArmoring')); LdapSigning = (& $str (& $v $_.s 'ldapSigning')); ChannelBinding = (& $str (& $v $_.s 'channelBinding')) } }) 'az-16-entra-domain-services' $true
    } | Out-Null

    # ---------- 6. Microsoft 365 pay-as-you-go and Backup ----------
    # What the spend step learns for the Backup step: whether every subscription answered, and whether one pays for Backup.
    $payg = @{ known = $false; backup = $false }
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
        # Every subscription answered: the Backup step below can go by this.
        $payg.known = $subIds.Count -gt 0
        $payg.backup = @($rows | Where-Object { $_ } | ForEach-Object { $_['Services'] } | Where-Object { $_ -and [string]$_['Name'] -match 'Backup' }).Count -gt 0
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
        # Microsoft 365 Backup through Graph: which workloads have an active protection policy, and whether the service
        # is on. The policies are read with BackupRestore-Configuration.Read.All, which the module asks for. The
        # service's own status is behind another permission, BackupRestore-Control.Read.All, which Microsoft documents
        # for registered backup controller applications and the module does not ask for: a refusal there leaves the
        # status unknown (ServiceStatusRead false) and the step done. The check is then decided by the policies when
        # they already fail it, and has no answer otherwise.
        # Microsoft 365 Backup is paid for through an Azure subscription and no other way. Where every subscription
        # answered the spend read above and none was billed for Backup in the last 30 days, nothing is being backed up
        # by it: that is written down (Billed false, the policies not read) and Graph is not asked, since Graph
        # refuses this read to a tenant without the service and there would be an error row for a question already
        # answered. A subscription the account cannot see is not counted, which the check says with its verdict.
        if ($payg.known -and -not $payg.backup) {
            & $saveOne ([ordered]@{ ServiceStatus = $null; ServiceStatusRead = $false; Billed = $false; SubscriptionsRead = $subIds.Count; SharePointPolicies = $null; OneDrivePolicies = $null; ExchangePolicies = $null }) 'az-11-m365-backup'
            return
        }
        $active = { param([string] $kind) @(Invoke-PostureGraphRequest -Uri "solutions/backupRestore/$kind" -ApiVersion 'v1.0' | Where-Object { [string](& $v $_ 'status') -eq 'active' }).Count }
        $context = Get-MgContext
        $carries = [bool]($context -and 'BackupRestore-Configuration.Read.All' -in @($context.Scopes))
        try { $row = [ordered]@{ ServiceStatus = $null; ServiceStatusRead = $false; Billed = $(if ($payg.known) { $true } else { $null }); SharePointPolicies = (& $active 'sharePointProtectionPolicies'); OneDrivePolicies = (& $active 'oneDriveForBusinessProtectionPolicies'); ExchangePolicies = (& $active 'exchangeProtectionPolicies') } }
        catch {
            # Seen on a live run: a Global Administrator with the permission consented is refused the policies too.
            # With the permission on the sign-in there is nothing an admin can grant, so the step says that and does
            # not send anyone to grant a role. Without the permission the refusal is the ordinary one.
            if ($carries -and (Get-PostureHttpStatus -ErrorRecord $_) -eq 403) { throw 'Not readable with this sign-in: Microsoft 365 Backup refused the read of its protection policies although the sign-in carries BackupRestore-Configuration.Read.All. Microsoft documents these reads for registered backup controller applications, and a tenant that never turned the service on may answer the same way (verify).' }
            throw
        }
        try {
            $svc = Invoke-PostureGraphRequest -Uri 'solutions/backupRestore' -ApiVersion 'v1.0' -Single
            $row.ServiceStatus = (& $v $svc 'serviceStatus.status'); $row.ServiceStatusRead = $true
        }
        catch { if ((Get-PostureHttpStatus -ErrorRecord $_) -ne 403) { throw } }
        & $saveOne $row 'az-11-m365-backup'
    } | Out-Null

    $errorsPath = Join-Path (Get-PostureRunLayout -Folder $Folder).errors 'errors.txt'
    return @{ files = $files.ToArray(); errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath }); subscriptions = $subIds.Count }
}
