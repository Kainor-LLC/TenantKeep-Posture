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

    With -IncludePosture, everything the monthly posture cycle reads: the Graph application roles every collector uses,
    Exchange.ManageAsApp on Office 365 Exchange Online (app-only Exchange and Purview), Sites.FullControl.All on
    SharePoint Online (verify: the least application permission that lets Get-PnPTenant and site enumeration read),
    application_access on the Skype and Teams Tenant Admin API, and the Global Reader directory role on the identity
    (what Exchange, Purview and Teams app-only sign-ins map to for read access; verify Purview accepts Global Reader).
    Azure Reader and Security Reader on the subscriptions are printed as az commands, since they are ARM, not Graph.

    Needs a delegated Graph session with AppRoleAssignment.ReadWrite.All and Application.Read.All; -IncludePosture also
    RoleManagement.ReadWrite.Directory for the Global Reader assignment.
.EXAMPLE
    Connect-MgGraph -TenantId <tenant> -Scopes AppRoleAssignment.ReadWrite.All, Application.Read.All, RoleManagement.ReadWrite.Directory
    ./Grant-ManagedIdentityGraphRole.ps1 -PrincipalId <automationPrincipalId output of the deployment> -IncludePosture
#>
[CmdletBinding(SupportsShouldProcess)]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'One-time admin script output is for the console.')]
param(
    [Parameter(Mandatory)] [string] $PrincipalId,
    [switch] $IncludeMailSend,
    [switch] $IncludePosture
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ctx = Get-MgContext
if (-not $ctx) { throw 'Connect-MgGraph first, with AppRoleAssignment.ReadWrite.All and Application.Read.All.' }
$needed = @('AppRoleAssignment.ReadWrite.All', 'Application.Read.All') + @($(if ($IncludePosture) { 'RoleManagement.ReadWrite.Directory' }))
foreach ($scope in $needed) { if (@($ctx.Scopes) -notcontains $scope) { throw "The Graph session is missing $scope." } }

$roles = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All')
if ($IncludeMailSend) { $roles += 'Mail.Send' }
# The posture collectors' Graph application roles: the same list Invoke-PostureCollection warns about when missing.
$postureGraphRoles = @(
    'User.Read.All', 'OnPremDirectorySynchronization.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All',
    'RoleManagement.Read.Directory', 'IdentityRiskyUser.Read.All', 'IdentityRiskEvent.Read.All',
    'DeviceManagementManagedDevices.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementServiceConfig.Read.All', 'DeviceManagementApps.Read.All',
    'BitLockerKey.ReadBasic.All', 'AttackSimulation.Read.All', 'AccessReview.Read.All', 'EntitlementManagement.Read.All', 'LifecycleWorkflows.Read.All',
    'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'AdministrativeUnit.Read.All', 'ThreatHunting.Read.All', 'SecurityIncident.Read.All', 'SecurityEvents.Read.All',
    'Sites.Read.All', 'Organization.Read.All', 'Application.Read.All', 'Reports.Read.All'
)
if ($IncludePosture) { $roles += $postureGraphRoles }

# Resource service principals and the application roles on each. Graph always; the others only with -IncludePosture.
$grants = [ordered]@{ '00000003-0000-0000-c000-000000000000' = @{ label = 'Microsoft Graph'; roles = $roles } }
if ($IncludePosture) {
    $grants['00000002-0000-0ff1-ce00-000000000000'] = @{ label = 'Office 365 Exchange Online'; roles = @('Exchange.ManageAsApp') }
    $grants['00000003-0000-0ff1-ce00-000000000000'] = @{ label = 'Office 365 SharePoint Online'; roles = @('Sites.FullControl.All') }
    $grants['48ac35b8-9aa8-4d74-927d-1f4a14a0b239'] = @{ label = 'Skype and Teams Tenant Admin API'; roles = @('application_access') }
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
Write-Host 'Done. Tokens issued to the identity from now on carry these roles; a running job may need a few minutes.'
