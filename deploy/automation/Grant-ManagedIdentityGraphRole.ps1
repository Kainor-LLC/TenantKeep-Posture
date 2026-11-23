#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    One-time setup: grants the Automation account's managed identity the application roles the runbooks need.
.DESCRIPTION
    This is customer-side setup, run once by a Global Administrator or Privileged Role Administrator of the tenant.
    It is a write to the tenant, deliberately outside the module: the module itself never writes.

    Default: Policy.Read.All, Directory.Read.All, Group.Read.All (the Conditional Access cycle). With -IncludeMailSend
    also Mail.Send, which you then restrict to the sender mailbox with an Exchange application access policy:
      New-ApplicationAccessPolicy -AppId <identity appId> -PolicyScopeGroupId <mail-enabled security group holding the mailbox> -AccessRight RestrictAccess

    With -IncludePosture, everything the monthly posture cycle reads: the Graph application roles every collector uses
    (SharePointTenantSettings.Read.All among them, which is how the scheduled run reads the SharePoint tenant
    settings), Exchange.ManageAsApp on Office 365 Exchange Online (app-only Exchange and Purview), application_access
    on the Skype and Teams Tenant Admin API, and the Global Reader directory role on the identity (what Exchange,
    Purview and Teams app-only sign-ins map to for read access; verify Purview accepts Global Reader). Azure Reader
    and Security Reader on the subscriptions are printed as az commands, since they are ARM, not Graph.

    -IncludeSharePointAdminRead adds Sites.FullControl.All on SharePoint Online, and nothing grants it otherwise. It is
    what the SharePoint admin read needs (the site list, restricted search, the settings Graph does not carry), and
    there is no smaller application permission that lets it work (verify). It is also a standing permission to read
    and change every file in every site, held by an identity that runs unattended. The module only reads with it. Leave
    it out unless the report needs the site list from the scheduled run; an admin can add that part by hand with
    collectors/windows/Get-SpoBaseline.ps1 and Import-PostureEvidence instead.

    -IncludePowerBI grants no role and no permission. It puts the identity in a security group, TenantKeep Posture
    (Power BI read), creating the group when it is not there. Power BI lets a service principal call its read-only
    admin APIs when the tenant setting "Service principals can access read-only admin APIs" names a security group
    the principal is in; turning that setting on, for this group, is a step a Fabric administrator takes in the
    Fabric admin portal. The identity must hold no Power BI permission of its own, and this script gives it none.
    Power Platform has no such path and is not read on a schedule.

    Needs a delegated Graph session with AppRoleAssignment.ReadWrite.All and Application.Read.All; -IncludePosture also
    RoleManagement.ReadWrite.Directory for the Global Reader assignment, and -IncludePowerBI Group.ReadWrite.All.
.EXAMPLE
    Connect-MgGraph -TenantId <tenant> -Scopes AppRoleAssignment.ReadWrite.All, Application.Read.All, RoleManagement.ReadWrite.Directory
    ./Grant-ManagedIdentityGraphRole.ps1 -PrincipalId <automationPrincipalId output of the deployment> -IncludePosture
.EXAMPLE
    ./Grant-ManagedIdentityGraphRole.ps1 -PrincipalId <id> -IncludePosture -IncludeSharePointAdminRead

    Also grants Sites.FullControl.All on SharePoint Online, for the site list in the scheduled run. Read the note above first.
#>
[CmdletBinding(SupportsShouldProcess)]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'One-time admin script output is for the console.')]
param(
    [Parameter(Mandatory)] [string] $PrincipalId,
    [switch] $IncludeMailSend,
    [switch] $IncludePosture,
    [switch] $IncludeSharePointAdminRead,
    [switch] $IncludePowerBI
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ctx = Get-MgContext
if (-not $ctx) { throw 'Connect-MgGraph first, with AppRoleAssignment.ReadWrite.All and Application.Read.All.' }
$needed = @('AppRoleAssignment.ReadWrite.All', 'Application.Read.All') + @($(if ($IncludePosture) { 'RoleManagement.ReadWrite.Directory' })) + @($(if ($IncludePowerBI) { 'Group.ReadWrite.All' }))
foreach ($scope in $needed) { if (@($ctx.Scopes) -notcontains $scope) { throw "The Graph session is missing $scope." } }

$roles = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All')
if ($IncludeMailSend) { $roles += 'Mail.Send' }
# The posture collectors' Graph application roles: the same list Invoke-PostureCollection warns about when missing.
$postureGraphRoles = @(
    'User.Read.All', 'OnPremDirectorySynchronization.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All',
    'RoleManagement.Read.Directory', 'IdentityRiskyUser.Read.All', 'IdentityRiskEvent.Read.All',
    'DeviceManagementManagedDevices.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementServiceConfig.Read.All', 'DeviceManagementApps.Read.All',
    'BitLockerKey.ReadBasic.All', 'AttackSimulation.Read.All', 'AccessReview.Read.All', 'EntitlementManagement.Read.All', 'LifecycleWorkflows.Read.All',
    'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'AdministrativeUnit.Read.All', 'NetworkAccess.Read.All', 'BackupRestore-Configuration.Read.All', 'ThreatHunting.Read.All', 'SecurityIncident.Read.All', 'SecurityEvents.Read.All',
    'Organization.Read.All', 'Application.Read.All',
    # The SharePoint tenant settings, through Graph: the scheduled run's default read of them.
    'SharePointTenantSettings.Read.All',
    # Intune roles and multi-admin approval, Defender for Identity health, service health and Message Center,
    # and the signing certificates of federated domains.
    'DeviceManagementRBAC.Read.All', 'SecurityIdentitiesHealth.Read.All', 'ServiceHealth.Read.All', 'ServiceMessage.Read.All', 'Domain-InternalFederation.Read.All',
    # Agent identities, the blueprints they are made from and the blueprints' service principals: Microsoft lists
    # each only with a permission of its own.
    'AgentIdentity.Read.All', 'AgentIdentityBlueprint.Read.All', 'AgentIdentityBlueprintPrincipal.Read.All'
)
if ($IncludePosture) { $roles += $postureGraphRoles }

# Resource service principals and the application roles on each. Graph always; the others only with -IncludePosture.
$grants = [ordered]@{ '00000003-0000-0000-c000-000000000000' = @{ label = 'Microsoft Graph'; roles = $roles } }
if ($IncludePosture) {
    $grants['00000002-0000-0ff1-ce00-000000000000'] = @{ label = 'Office 365 Exchange Online'; roles = @('Exchange.ManageAsApp') }
    $grants['48ac35b8-9aa8-4d74-927d-1f4a14a0b239'] = @{ label = 'Skype and Teams Tenant Admin API'; roles = @('application_access') }
}
if ($IncludeSharePointAdminRead -and -not $IncludePosture) { throw '-IncludeSharePointAdminRead goes with -IncludePosture.' }
if ($IncludePosture -and $IncludeSharePointAdminRead) {
    Write-Warning 'Sites.FullControl.All on SharePoint Online is a standing permission to read and change every file in every site. The module only reads with it (the site list, restricted search), but the identity holds it for as long as the grant stands. Remove it when the scheduled run no longer needs the site list.'
    $grants['00000003-0000-0ff1-ce00-000000000000'] = @{ label = 'Office 365 SharePoint Online'; roles = @('Sites.FullControl.All') }
}
elseif ($IncludePosture) {
    Write-Host 'SharePoint: the scheduled run reads the tenant settings through Graph (SharePointTenantSettings.Read.All). The site list needs -IncludeSharePointAdminRead, which grants Sites.FullControl.All; without it those checks say not evaluated.'
}
$existing = @((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" -OutputType HashTable).value)
foreach ($appId in $grants.Keys) {
    $label = $grants[$appId].label
    $found = @((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$appId'&`$select=id,appRoles" -OutputType HashTable).value)
    if ($found.Count -eq 0) { Write-Warning "No service principal for $label in this tenant; its roles are skipped."; continue }
    $sp = $found[0]
    foreach ($role in $grants[$appId].roles) {
        $appRole = $sp.appRoles | Where-Object { $_.value -eq $role -and $_.allowedMemberTypes -contains 'Application' }
        if (-not $appRole) { throw "$label exposes no application role named $role." }
        if ($existing | Where-Object { $_.appRoleId -eq $appRole.id -and $_.resourceId -eq $sp.id }) { Write-Host "$label $role already granted"; continue }
        if ($PSCmdlet.ShouldProcess($PrincipalId, "Grant $label $role")) {
            $body = @{ principalId = $PrincipalId; resourceId = $sp.id; appRoleId = $appRole.id }
            $null = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" -Body $body -ContentType 'application/json'
            Write-Host "$label $role granted"
        }
    }
}

if ($IncludePosture) {
    # Global Reader on the identity: Exchange, Purview and Teams app-only sign-ins take their access from directory roles.
    $readerTemplate = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451'
    $defs = @((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=templateId eq '$readerTemplate'&`$select=id,displayName" -OutputType HashTable).value)
    if ($defs.Count -eq 0) { throw 'Global Reader role definition not found.' }
    $have = @((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$PrincipalId'" -OutputType HashTable).value | Where-Object { $_.roleDefinitionId -eq $defs[0].id })
    if ($have.Count -gt 0) { Write-Host 'Global Reader already assigned' }
    elseif ($PSCmdlet.ShouldProcess($PrincipalId, 'Assign the Global Reader directory role')) {
        $body = @{ principalId = $PrincipalId; roleDefinitionId = $defs[0].id; directoryScopeId = '/' }
        $null = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' -Body $body -ContentType 'application/json'
        Write-Host 'Global Reader assigned'
    }
    Write-Host @"

Azure, per subscription the posture run should read (ARM roles, not Graph):
  az role assignment create --assignee-object-id $PrincipalId --assignee-principal-type ServicePrincipal --role Reader --scope /subscriptions/<id>
  az role assignment create --assignee-object-id $PrincipalId --assignee-principal-type ServicePrincipal --role "Security Reader" --scope /subscriptions/<id>
Hybrid tenants: upload the Windows collector's ad-* files to the client container under hybrid/ before each run.
"@
}
if ($IncludePowerBI) {
    # Power BI: a security group and nothing else. The Fabric tenant setting that names it is a click only a Fabric
    # administrator can make, in the Fabric admin portal.
    $groupName = 'TenantKeep Posture (Power BI read)'
    $groups = @((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$groupName'&`$select=id,displayName,securityEnabled" -OutputType HashTable).value)
    $group = $(if ($groups.Count -gt 0) { $groups[0] } else { $null })
    if (-not $group -and $PSCmdlet.ShouldProcess($groupName, 'Create the security group')) {
        $body = @{ displayName = $groupName; description = 'The identity of the TenantKeep Posture scheduled run. Named in the Fabric tenant setting "Service principals can access read-only admin APIs" so the run can read the Power BI tenant settings. It grants nothing else.'; mailEnabled = $false; mailNickname = 'tenantkeep-posture-powerbi-read'; securityEnabled = $true }
        $group = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/groups' -Body $body -ContentType 'application/json' -OutputType HashTable
        Write-Host "Security group created: $groupName"
    }
    if ($group) {
        $members = @((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members?`$select=id" -OutputType HashTable).value)
        if (@($members | Where-Object { $_.id -eq $PrincipalId }).Count -gt 0) { Write-Host "The identity is already in $groupName" }
        elseif ($PSCmdlet.ShouldProcess($PrincipalId, "Add the identity to $groupName")) {
            $body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$PrincipalId" }
            $null = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members/`$ref" -Body $body -ContentType 'application/json'
            Write-Host "The identity was added to $groupName"
        }
    }
    Write-Host @"

Power BI, one step left, for a Fabric administrator:
  In the Fabric admin portal, open Tenant settings, Admin API settings, and turn on
  "Service principals can access read-only admin APIs" for Specific security groups: $groupName
  Nothing else is granted. The next scheduled run reads the Power BI tenant settings; Power Platform is read only by a signed-in run.
"@
}
Write-Host 'Done. Tokens issued to the identity from now on carry these roles. Azure keeps a managed identity''s token for up to a day, so a job started before then may run without the new ones: it names what it could not read, and the next run has them.'
