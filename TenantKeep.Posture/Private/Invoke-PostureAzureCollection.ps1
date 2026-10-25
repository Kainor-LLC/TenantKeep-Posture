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
                    [ordered]@{ SubscriptionId = (& $str $_.subscriptionId); Name = (& $str $_.name); State = (& $str $_.state); ManagementGroupChain = ($chain -join ' / '); ManagementGroupNames = $chainNames; AtTenantRoot = ($chain.Count -le 1) }
                })
            & $save $flat 'az-01-subscriptions' $true
            $flat
        })
    $subIds = @($subs | Where-Object { $_ -and $_.State -eq 'Enabled' } | ForEach-Object { $_.SubscriptionId } | Select-Object -First 200)
    Invoke-PostureStep -Label 'Azure management groups' -Folder $Folder -Script {
        $rows = & $q "resourcecontainers | where type == 'microsoft.management/managementgroups' | project name, displayName = tostring(properties.displayName), parent = tostring(properties.details.parent.name)"
        & $save @($rows | ForEach-Object { [ordered]@{ Name = (& $str $_.name); DisplayName = (& $str $_.displayName); Parent = (& $str $_.parent) } }) 'az-01-management-groups' $true
    } | Out-Null

    # ---------- 2. Defender for Cloud ----------
    Invoke-PostureStep -Label 'Defender for Cloud plans' -Folder $Folder -Script {
        $rows = foreach ($s in $subIds) {
            foreach ($p in @(& $rest "/subscriptions/$s/providers/Microsoft.Security/pricings?api-version=2024-01-01")) { [ordered]@{ SubscriptionId = $s; Plan = (& $v $p 'name'); Tier = (& $v $p 'properties.pricingTier'); SubPlan = (& $v $p 'properties.subPlan') } }
        }
        & $save @($rows) 'az-02-defender-pricings' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Defender for Cloud security contacts' -Folder $Folder -Script {
        # The 2023-12-01-preview shape carries notificationsSources (sourceType Alert with minimalSeverity) and isEnabled; older contacts carry alertNotifications. Both are read (live shape confirmed 2026-10-15).
        $rows = foreach ($s in $subIds) {
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

    # ---------- 4. Activity log export ----------
    Invoke-PostureStep -Label 'Activity log diagnostic settings' -Folder $Folder -Script {
        $rows = foreach ($s in $subIds) {
            $settings = @(& $rest "/subscriptions/$s/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview")
            if ($settings.Count -eq 0) { [ordered]@{ SubscriptionId = $s; Name = $null; WorkspaceId = $null; EventHub = $null; StorageAccountId = $null; Categories = 0 } }
            foreach ($d in $settings) { [ordered]@{ SubscriptionId = $s; Name = (& $v $d 'name'); WorkspaceId = (& $v $d 'properties.workspaceId'); EventHub = (& $v $d 'properties.eventHubAuthorizationRuleId'); StorageAccountId = (& $v $d 'properties.storageAccountId'); Categories = @(@(& $v $d 'properties.logs') | Where-Object { (& $v $_ 'enabled') -eq $true }).Count } }
        }
        & $save @($rows) 'az-04-activity-log-exports' $true
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
        $rows = foreach ($s in $subIds) {
            $answer = $(try { @(& $rest "/subscriptions/$s/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01") } catch { if ($_.Exception.Message -match 'InvalidResourceType|404') { @() } else { throw } })
            foreach ($a in $answer) { [ordered]@{ SubscriptionId = $s; EmailAddress = (& $v $a 'properties.emailAddress'); Role = (& $v $a 'properties.role') } }
        }
        & $save @($rows) 'az-05-classic-administrators' $true
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

    $errorsPath = Join-Path $Folder 'errors.txt'
    return @{ files = $files.ToArray(); errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath }); subscriptions = $subIds.Count }
}
