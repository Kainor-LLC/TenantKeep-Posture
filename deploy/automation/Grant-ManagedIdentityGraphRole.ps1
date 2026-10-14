#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    One-time setup: grants the Automation account's managed identity the Graph application roles the runbook needs.
.DESCRIPTION
    This is customer-side setup, run once by a Global Administrator or Privileged Role Administrator of the tenant.
    It is a write to the tenant, deliberately outside the module: the module itself never writes.

    Roles granted: Policy.Read.All, Directory.Read.All, Group.Read.All. With -IncludeMailSend also Mail.Send, which
    you must then restrict to the sender mailbox with an Exchange application access policy:
      New-ApplicationAccessPolicy -AppId <identity appId> -PolicyScopeGroupId <sender mailbox> -AccessRight RestrictAccess

    Needs a delegated Graph session with AppRoleAssignment.ReadWrite.All and Application.Read.All.
.EXAMPLE
    Connect-MgGraph -TenantId <tenant> -Scopes AppRoleAssignment.ReadWrite.All, Application.Read.All
    ./Grant-ManagedIdentityGraphRole.ps1 -PrincipalId <automationPrincipalId output of the deployment>
#>
[CmdletBinding(SupportsShouldProcess)]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'One-time admin script output is for the console.')]
param(
    [Parameter(Mandatory)] [string] $PrincipalId,
    [switch] $IncludeMailSend
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ctx = Get-MgContext
if (-not $ctx) { throw 'Connect-MgGraph first, with AppRoleAssignment.ReadWrite.All and Application.Read.All.' }
foreach ($needed in 'AppRoleAssignment.ReadWrite.All', 'Application.Read.All') {
    if (@($ctx.Scopes) -notcontains $needed) { throw "The Graph session is missing $needed." }
}

$roles = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All')
if ($IncludeMailSend) { $roles += 'Mail.Send' }

$graphSp = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles" -OutputType HashTable).value[0]
$existing = @((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" -OutputType HashTable).value)

foreach ($role in $roles) {
    $appRole = $graphSp.appRoles | Where-Object { $_.value -eq $role -and $_.allowedMemberTypes -contains 'Application' }
    if (-not $appRole) { throw "Graph exposes no application role named $role." }
    if ($existing | Where-Object { $_.appRoleId -eq $appRole.id -and $_.resourceId -eq $graphSp.id }) {
        Write-Host "$role already granted"
        continue
    }
    if ($PSCmdlet.ShouldProcess($PrincipalId, "Grant $role")) {
        $body = @{ principalId = $PrincipalId; resourceId = $graphSp.id; appRoleId = $appRole.id }
        $null = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" -Body $body -ContentType 'application/json'
        Write-Host "$role granted"
    }
}
Write-Host 'Done. Tokens issued to the identity from now on carry these roles; a running job may need a few minutes.'
