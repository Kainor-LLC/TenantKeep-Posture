# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-AzureFixtureQuery {
    <#
    .SYNOPSIS
        Synthetic Resource Graph answers by query text, for mocking Invoke-PostureAzureQuery. Every value is made up.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Query)

    $o = { param([hashtable] $h) [pscustomobject]$h }
    switch -Regex ($Query) {
        "microsoft\.resources/subscriptions'" { & $o @{ subscriptionId = 'sub-1'; name = 'Prod'; state = 'Enabled'; chain = @(@{ displayName = 'Landing zones'; name = 'lz' }, @{ displayName = 'Tenant Root Group'; name = 'root' }) }; & $o @{ subscriptionId = 'sub-2'; name = 'Sandbox'; state = 'Enabled'; chain = @(@{ displayName = 'Tenant Root Group'; name = 'root' }) }; break }
        "microsoft\.management/managementgroups'" { & $o @{ name = 'lz'; displayName = 'Landing zones'; parent = 'root' }; break }
        "microsoft\.security/securescores'" { & $o @{ subscriptionId = 'sub-1'; name = 'ascScore'; current = 30.5; max = 58; percentage = 0.53 }; break }
        "microsoft\.security/assessments'.*summarize Count" { & $o @{ subscriptionId = 'sub-1'; status = 'Unhealthy'; severity = 'High'; Count = 4 }; break }
        "microsoft\.security/assessments'" { & $o @{ displayName = 'Management ports should be closed'; severity = 'High'; Affected = 3 }; break }
        # Policy states: two subscriptions, and the assignments most resources break. More specific than the next rows, so first.
        "policyinsights/policystates'.*by subscriptionId" { & $o @{ subscriptionId = 'sub-1'; Resources = 40; NonCompliant = 12 }; & $o @{ subscriptionId = 'sub-2'; Resources = 10; NonCompliant = 3 }; break }
        "policyinsights/policystates'.*by assignmentId" { & $o @{ assignmentId = '/providers/microsoft.management/managementgroups/lz/providers/microsoft.authorization/policyassignments/mcsb'; assignment = 'mcsb'; Resources = 11 }; & $o @{ assignmentId = '/subscriptions/sub-2/providers/microsoft.authorization/policyassignments/tags'; assignment = 'tags'; Resources = 4 }; break }
        # Azure Lighthouse: a partner with Contributor on a subscription, one that only reads a resource group, and an assignment whose definition cannot be read.
        # Asked of any other table, Azure answers Bad Request (a live run met that with the table's name misspelt).
        "^(?!managedservicesresources \|).*managedservices/registration" { throw "Operation returned an invalid status code 'BadRequest'" }
        "managedservices/registrationassignments'" {
            & $o @{ id = '/subscriptions/sub-1/providers/Microsoft.ManagedServices/registrationAssignments/a1'; subscriptionId = 'sub-1'; resourceGroup = ''; definitionId = '/subscriptions/sub-1/providers/microsoft.managedservices/registrationdefinitions/d1' }
            & $o @{ id = '/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.ManagedServices/registrationAssignments/a2'; subscriptionId = 'sub-1'; resourceGroup = 'rg1'; definitionId = '/subscriptions/sub-1/providers/microsoft.managedservices/registrationdefinitions/d2' }
            & $o @{ id = '/subscriptions/sub-2/providers/Microsoft.ManagedServices/registrationAssignments/a3'; subscriptionId = 'sub-2'; resourceGroup = ''; definitionId = '/subscriptions/sub-2/providers/microsoft.managedservices/registrationdefinitions/gone' }
            break
        }
        "managedservices/registrationdefinitions'" {
            & $o @{ definitionId = '/subscriptions/sub-1/providers/microsoft.managedservices/registrationdefinitions/d1'; offer = 'Managed Azure'; managedByTenantId = '99999999-9999-9999-9999-999999999999'; managedByTenantName = 'Fabrikam Managed Services'; authorizations = @(@{ principalId = 'p1'; roleDefinitionId = 'b24988ac-6180-42a0-ab88-20f7382dd24c' }, @{ principalId = 'p2'; roleDefinitionId = '/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7' }); eligible = @() }
            & $o @{ definitionId = '/subscriptions/sub-1/providers/microsoft.managedservices/registrationdefinitions/d2'; offer = 'Monitoring'; managedByTenantId = '88888888-8888-8888-8888-888888888888'; managedByTenantName = 'Northwind Monitoring'; authorizations = @(@{ principalId = 'p3'; roleDefinitionId = '43d0d8ad-25c7-4714-9337-8ba259a9fe05' }); eligible = $null }
            break
        }
        "microsoft\.authorization/policyassignments'" { & $o @{ id = '/providers/Microsoft.Management/managementGroups/lz/providers/Microsoft.Authorization/policyAssignments/mcsb'; name = 'mcsb'; displayName = 'Microsoft cloud security benchmark'; scope = '/providers/Microsoft.Management/managementGroups/lz'; policyDefinitionId = '/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8'; enforcementMode = 'Default' }; & $o @{ id = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/tags'; name = 'tags'; displayName = 'Require owner tag'; scope = '/subscriptions/sub-1'; policyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/custom-tags'; enforcementMode = 'Default' }; break }
        "microsoft\.authorization/roledefinitions'" { & $o @{ id = '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635'; roleName = 'Owner'; roleType = 'BuiltInRole'; actions = @('*'); dataActions = @() }; & $o @{ id = '/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c'; roleName = 'Contributor'; roleType = 'BuiltInRole'; actions = @('*'); dataActions = @() }; & $o @{ id = '/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/custom-1'; roleName = 'Everything'; roleType = 'CustomRole'; actions = @('*'); dataActions = @() }; break }
        "microsoft\.authorization/roleassignments'" {
            & $o @{ id = 'ra1'; principalId = 'u1'; principalType = 'User'; roleDefinitionId = '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635'; scope = '/subscriptions/sub-1'; createdOn = '2025-01-01' }
            & $o @{ id = 'ra2'; principalId = 'u2'; principalType = 'User'; roleDefinitionId = '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635'; scope = '/'; createdOn = '2025-01-01' }
            & $o @{ id = 'ra3'; principalId = 'g1'; principalType = 'Group'; roleDefinitionId = '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635'; scope = '/subscriptions/sub-1'; createdOn = '2025-01-01' }
            & $o @{ id = 'ra4'; principalId = 'g2'; principalType = 'User'; roleDefinitionId = '/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c'; scope = '/subscriptions/sub-1/resourceGroups/rg1'; createdOn = '2025-01-01' }
            & $o @{ id = 'ra5'; principalId = 'sp9'; principalType = 'ServicePrincipal'; roleDefinitionId = '/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c'; scope = '/subscriptions/sub-1'; createdOn = '2025-01-01' }
            & $o @{ id = 'ra6'; principalId = 'gone'; principalType = 'Unknown'; roleDefinitionId = '/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c'; scope = '/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/st1'; createdOn = '2025-01-01' }
            break
        }
        'summarize Count = count\(\) by subscriptionId, type' { & $o @{ subscriptionId = 'sub-1'; type = 'microsoft.compute/virtualmachines'; Count = 3 }; & $o @{ subscriptionId = 'sub-1'; type = 'microsoft.storage/storageaccounts'; Count = 2 }; & $o @{ subscriptionId = 'sub-2'; type = 'microsoft.storage/storageaccounts'; Count = 1 }; break }
        'summarize Total = count\(\), Tagged' { & $o @{ Total = 20; Tagged = 15 }; break }
        "microsoft\.compute/disks'" { & $o @{ Count = 2 }; break }
        "microsoft\.network/publicipaddresses'" { & $o @{ Count = 0 }; break }
        "microsoft\.network/networkinterfaces'" { & $o @{ Count = 1 }; break }
        'subscriptions/resourcegroups' { & $o @{ Count = 0 }; break }
        "microsoft\.authorization/locks'" { & $o @{ id = '/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1/providers/Microsoft.Authorization/locks/keep'; name = 'keep'; level = 'CanNotDelete' }; break }
        "microsoft\.dataprotection/backupvaults'" { & $o @{ name = 'rsv1'; type = 'microsoft.recoveryservices/vaults'; subscriptionId = 'sub-1'; resourceGroup = 'rg1'; softDelete = 'AlwaysON'; immutability = 'Disabled' }; break }
        "microsoft\.network/networksecuritygroups'" { & $o @{ nsg = 'nsg-web'; subscriptionId = 'sub-1'; resourceGroup = 'rg1'; rule = 'allow-rdp'; port = '3389'; ports = '[]' }; & $o @{ nsg = 'nsg-web'; subscriptionId = 'sub-1'; resourceGroup = 'rg1'; rule = 'allow-https'; port = '443'; ports = '[]' }; & $o @{ nsg = 'nsg-app'; subscriptionId = 'sub-1'; resourceGroup = 'rg1'; rule = 'allow-range'; port = ''; ports = '["20-25","8080"]' }; break }
        "microsoft\.operationsmanagement/solutions'" { & $o @{ workspaceId = '/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/law-sec'; subscriptionId = 'sub-1' }; break }
        "microsoft\.aad/domainservices'" { @(); break }
        "microsoft\.recoveryservices/vaults'" { & $o @{ id = '/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1'; name = 'kv1'; type = 'microsoft.keyvault/vaults'; subscriptionId = 'sub-1'; resourceGroup = 'rg1' }; & $o @{ id = '/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.RecoveryServices/vaults/rsv1'; name = 'rsv1'; type = 'microsoft.recoveryservices/vaults'; subscriptionId = 'sub-1'; resourceGroup = 'rg1' }; break }
        "microsoft\.keyvault/vaults' \| project" { & $o @{ id = '/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1'; name = 'kv1'; subscriptionId = 'sub-1'; rbac = $true; purge = $true; softDelete = $true; publicNetworkAccess = 'Disabled'; defaultAction = 'Deny' }; & $o @{ id = '/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv2'; name = 'kv2'; subscriptionId = 'sub-1'; rbac = $false; purge = $false; softDelete = $true; publicNetworkAccess = 'Enabled'; defaultAction = 'Allow' }; break }
        "microsoft\.storage/storageaccounts' \| project" { & $o @{ id = 'st1'; name = 'st1'; subscriptionId = 'sub-1'; sharedKey = $false; blobPublic = $false; httpsOnly = $true; minTls = 'TLS1_2'; publicNetworkAccess = 'Enabled' }; & $o @{ id = 'st2'; name = 'legacy2019'; subscriptionId = 'sub-2'; sharedKey = $true; blobPublic = $true; httpsOnly = $true; minTls = 'TLS1_0'; publicNetworkAccess = 'Enabled' }; break }
        "microsoft\.sql/servers'" { @(); break }
        default { throw "Fixture has no Resource Graph answer for: $Query" }
    }
}

function Get-AzureFixtureRequest {
    <#
    .SYNOPSIS
        Synthetic Resource Manager answers by path, for mocking Invoke-PostureAzureRequest.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)

    # A subscription that refuses one read: TKP_AZ_REFUSE names the subscription, and its security contacts are denied.
    if ($env:TKP_AZ_REFUSE -and $Path -match "/subscriptions/$([regex]::Escape($env:TKP_AZ_REFUSE))/providers/Microsoft\.Security/securityContacts") { throw "GET $Path returned 403: AuthorizationFailed: the client does not have authorization to perform action Microsoft.Security/securityContacts/read" }
    switch -Regex ($Path) {
        '/subscriptions/sub-1/providers/Microsoft\.Security/pricings' { @{ name = 'VirtualMachines'; properties = @{ pricingTier = 'Standard'; subPlan = 'P2' } }, @{ name = 'StorageAccounts'; properties = @{ pricingTier = 'Free' } }, @{ name = 'Arm'; properties = @{ pricingTier = 'Standard' } }, @{ name = 'CloudPosture'; properties = @{ pricingTier = 'Free' } }; break }
        '/subscriptions/sub-2/providers/Microsoft\.Security/pricings' { @{ name = 'StorageAccounts'; properties = @{ pricingTier = 'Standard' } }, @{ name = 'Arm'; properties = @{ pricingTier = 'Free' } }; break }
        '/subscriptions/sub-1/providers/Microsoft\.Security/securityContacts' { @{ name = 'default'; properties = @{ emails = 'soc@contoso.example'; isEnabled = $true; alertNotifications = @{ state = 'On'; minimalSeverity = 'High' }; notificationsByRole = @{ roles = @('Owner') } } }; break }
        '/subscriptions/sub-2/providers/Microsoft\.Security/securityContacts' { @(); break }
        '/subscriptions/sub-1/providers/Microsoft\.Insights/diagnosticSettings' { @{ name = 'to-law'; properties = @{ workspaceId = '/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/law'; logs = @(@{ category = 'Administrative'; enabled = $true }, @{ category = 'Security'; enabled = $true }) } }; break }
        '/subscriptions/sub-2/providers/Microsoft\.Insights/diagnosticSettings' { @(); break }
        '/providers/Microsoft\.Authorization/classicAdministrators' { if ($Path -match 'sub-2') { @{ properties = @{ emailAddress = 'old@contoso.example'; role = 'CoAdministrator' } } } else { @() }; break }
        '/providers/Microsoft\.ADHybridHealthService/services' { @{ serviceName = 'AadSyncService-contoso'; type = 'AadSyncService'; health = 'Healthy'; activeAlerts = 0 }; break }
        '/providers/microsoft\.aadiam/diagnosticSettings' { @{ name = 'entra-to-law'; properties = @{ workspaceId = '/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/law'; logs = @(@{ category = 'AuditLogs'; enabled = $true }, @{ category = 'SignInLogs'; enabled = $true }, @{ category = 'ProvisioningLogs'; enabled = $false }) } }; break }
        '/providers/Microsoft\.Consumption/budgets' { @(); break }
        '/providers/Microsoft\.SecurityInsights/dataConnectors' { @{ kind = 'AzureActiveDirectory' }, @{ kind = 'Office365' }, @{ kind = 'MicrosoftThreatProtection' }; break }
        default { throw "Fixture has no Resource Manager answer for: $Path" }
    }
}
