#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Customer-side: lets named admins use TenantKeep Posture for SharePoint, the optional app that alone asks for
    SharePoint full control, without consenting it for the organisation. Also removes admins and turns the app off
    and on between runs.
.DESCRIPTION
    A write to the tenant, run by the customer's Global Administrator (or Privileged Role Administrator with
    Application Administrator), deliberately outside the module: the module itself never writes.

    What it does, in order, and only in the tenant the Graph session is in:
      1. Adds the app to the tenant (its service principal) when it is not there yet. Nothing is consented by this.
      2. Requires assignment, so an account that is not assigned cannot sign in to the app at all.
      3. For each -Admin: a delegated permission grant for that one account (SharePoint AllSites.FullControl, and
         openid profile offline_access User.Read on Graph for the sign-in), and an assignment to the app. Never an
         organisation-wide grant; one made by hand earlier is reported, not touched.
      4. For each -Remove: deletes that account's grants and assignment.
      5. -Disable turns sign-in to the app off (for the time between runs); -Enable turns it back on.
      6. Prints who holds access now.

    Delegated permissions never exceed the signed-in admin's own rights: the app reads as the admin who runs
    Start-PostureRun, who needs SharePoint Administrator for the SharePoint read (activate it in PIM for the run). The
    app has no secret or certificate, so nothing can use it unattended. Every SharePoint call the module makes goes
    through one function that accepts Get-PnP commands only; docs/security-review.md says how to check that in your
    own audit log afterwards.

    Needs a delegated Graph session in the customer tenant:
      Connect-MgGraph -TenantId <tenant id> -Scopes Application.ReadWrite.All, DelegatedPermissionGrant.ReadWrite.All, AppRoleAssignment.ReadWrite.All, User.Read.All -NoWelcome
.PARAMETER TenantId
    The tenant the Graph session must be in. The script refuses any other.
.PARAMETER Admin
    Accounts (user principal names) to grant the app to.
.PARAMETER Remove
    Accounts to take the app away from.
.PARAMETER Enable
    Turn sign-in to the app on (for a run).
.PARAMETER Disable
    Turn sign-in to the app off (between runs). Grants and assignments stay.
.PARAMETER ClientId
    The app id. Default: TenantKeep Posture for SharePoint from TenantKeep.Posture/app-sharepoint.json.
.EXAMPLE
    ./deploy/setup/Grant-PostureSharePointAccess.ps1 -TenantId <tenant id> -Admin spadmin@contoso.com
.EXAMPLE
    ./deploy/setup/Grant-PostureSharePointAccess.ps1 -TenantId <tenant id> -Disable

    Between runs: nobody can sign in to the app until -Enable.
#>
[CmdletBinding(SupportsShouldProcess)]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'One-time admin script output is for the console.')]
param(
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $TenantId,
    [ValidatePattern('^[^@\s]+@[^@\s]+$')] [string[]] $Admin = @(),
    [ValidatePattern('^[^@\s]+@[^@\s]+$')] [string[]] $Remove = @(),
    [switch] $Enable,
    [switch] $Disable,
    [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $ClientId,
    [string] $AppJsonPath = (Join-Path $PSScriptRoot '..' '..' 'TenantKeep.Posture' 'app-sharepoint.json')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Enable -and $Disable) { throw 'Pass -Enable or -Disable, not both.' }

$graph = 'https://graph.microsoft.com/v1.0'
$defaultAccess = '00000000-0000-0000-0000-000000000000'
$scopes = [ordered]@{ '00000003-0000-0ff1-ce00-000000000000' = 'AllSites.FullControl'; '00000003-0000-0000-c000-000000000000' = 'openid profile offline_access User.Read' }
function Get-GraphValue { param([string] $Uri) $r = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType HashTable; @($(if ($r -is [System.Collections.IDictionary] -and $r.Contains('value')) { $r['value'] } else { $r }) | Where-Object { $_ }) }
function Send-Graph { param([string] $Method, [string] $Uri, [hashtable] $Body) if ($Body) { Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body ($Body | ConvertTo-Json -Depth 5) -ContentType 'application/json' -OutputType HashTable } else { Invoke-MgGraphRequest -Method $Method -Uri $Uri -OutputType HashTable } }

$ctx = Get-MgContext
if (-not $ctx) { throw 'Connect-MgGraph first (see the help for the scopes).' }
if ([string]$ctx.TenantId -ne $TenantId) { throw "The Graph session is in tenant $($ctx.TenantId); this script only runs in $TenantId." }
$need = @('Application.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'User.Read.All')
$lacking = @($need | Where-Object { $_ -notin @($ctx.Scopes) })
if ($lacking.Count) { throw "The Graph session needs $($lacking -join ', ')." }

if (-not $ClientId) { $ClientId = [string](Get-Content -Raw -LiteralPath $AppJsonPath | ConvertFrom-Json -AsHashtable)['clientId'] }
if (-not $ClientId) { throw "$AppJsonPath carries no clientId yet: Kainor has not registered TenantKeep Posture for SharePoint in this build. Pass -ClientId." }

# 1. The app in this tenant.
$sp = @(Get-GraphValue "$graph/servicePrincipals?`$filter=appId eq '$ClientId'&`$select=id,displayName,accountEnabled,appRoleAssignmentRequired")
if ($sp.Count -eq 0) {
    if (-not $PSCmdlet.ShouldProcess($ClientId, 'Add TenantKeep Posture for SharePoint to this tenant (no consent)')) { return }
    $created = Send-Graph POST "$graph/servicePrincipals" @{ appId = $ClientId }
    $sp = @(@{ id = $created['id']; displayName = $created['displayName']; accountEnabled = $true; appRoleAssignmentRequired = $false })
    Write-Host "Added $($sp[0]['displayName']) to the tenant."
}
$spId = [string]$sp[0]['id']

# 2. Assignment required.
if ($sp[0]['appRoleAssignmentRequired'] -ne $true -and $PSCmdlet.ShouldProcess($spId, 'Require assignment')) {
    $null = Send-Graph PATCH "$graph/servicePrincipals/$spId" @{ appRoleAssignmentRequired = $true }
    Write-Host 'Assignment required: only the admins named here can sign in to the app.'
}

# 5 first, so a grant and an -Enable in one call leave the app usable.
if ($Enable -and $PSCmdlet.ShouldProcess($spId, 'Turn sign-in on')) { $null = Send-Graph PATCH "$graph/servicePrincipals/$spId" @{ accountEnabled = $true }; Write-Host 'Sign-in to the app is on.' }
if ($Disable -and $PSCmdlet.ShouldProcess($spId, 'Turn sign-in off')) { $null = Send-Graph PATCH "$graph/servicePrincipals/$spId" @{ accountEnabled = $false }; Write-Host 'Sign-in to the app is off until -Enable. Grants and assignments stay.' }

$resourceSp = @{}
foreach ($appId in $scopes.Keys) {
    $r = @(Get-GraphValue "$graph/servicePrincipals?`$filter=appId eq '$appId'&`$select=id,displayName")
    if ($r.Count -eq 0) { throw "No service principal for $appId in this tenant." }
    $resourceSp[$appId] = [string]$r[0]['id']
}
$userOf = { param([string] $Upn) $u = @(Get-GraphValue "$graph/users/$([uri]::EscapeDataString($Upn))?`$select=id,userPrincipalName"); if ($u.Count -eq 0) { throw "No user $Upn." }; $u[0] }
$grantsOf = { param([string] $UserId) @(Get-GraphValue "$graph/oauth2PermissionGrants?`$filter=clientId eq '$spId' and principalId eq '$UserId'") }

# 3. Grants and assignments, one account at a time.
foreach ($upn in $Admin) {
    $u = & $userOf $upn
    $have = & $grantsOf ([string]$u['id'])
    foreach ($appId in $scopes.Keys) {
        $want = $scopes[$appId]
        $g = @($have | Where-Object { [string]$_['resourceId'] -eq $resourceSp[$appId] })
        if ($g.Count -eq 0) {
            if ($PSCmdlet.ShouldProcess($upn, "Grant $want")) { $null = Send-Graph POST "$graph/oauth2PermissionGrants" @{ clientId = $spId; consentType = 'Principal'; principalId = [string]$u['id']; resourceId = $resourceSp[$appId]; scope = $want } }
        }
        else {
            $missing = @($want -split ' ' | Where-Object { $_ -notin @(([string]$g[0]['scope']) -split ' ') })
            if ($missing.Count -and $PSCmdlet.ShouldProcess($upn, "Add $($missing -join ' ') to the grant")) { $null = Send-Graph PATCH "$graph/oauth2PermissionGrants/$($g[0]['id'])" @{ scope = (@(([string]$g[0]['scope']) -split ' ' | Where-Object { $_ }) + $missing) -join ' ' } }
        }
    }
    $assigned = @(Get-GraphValue "$graph/users/$($u['id'])/appRoleAssignments?`$filter=resourceId eq $spId")
    if ($assigned.Count -eq 0 -and $PSCmdlet.ShouldProcess($upn, 'Assign to the app')) { $null = Send-Graph POST "$graph/users/$($u['id'])/appRoleAssignments" @{ principalId = [string]$u['id']; resourceId = $spId; appRoleId = $defaultAccess } }
    Write-Host "Granted to $upn."
}

# 4. Removals.
foreach ($upn in $Remove) {
    $u = & $userOf $upn
    foreach ($g in & $grantsOf ([string]$u['id'])) { if ($PSCmdlet.ShouldProcess($upn, "Remove the grant $($g['scope'])")) { $null = Send-Graph DELETE "$graph/oauth2PermissionGrants/$($g['id'])" } }
    foreach ($a in @(Get-GraphValue "$graph/users/$($u['id'])/appRoleAssignments?`$filter=resourceId eq $spId")) { if ($PSCmdlet.ShouldProcess($upn, 'Remove the assignment')) { $null = Send-Graph DELETE "$graph/users/$($u['id'])/appRoleAssignments/$($a['id'])" } }
    Write-Host "Removed from $upn."
}

# 6. Who holds it now.
$all = @(Get-GraphValue "$graph/oauth2PermissionGrants?`$filter=clientId eq '$spId'")
$org = @($all | Where-Object { [string]$_['consentType'] -eq 'AllPrincipals' })
if ($org.Count) { Write-Warning 'An organisation-wide grant exists for this app (made outside this script). It lets any assigned account use it; remove it under Enterprise applications, TenantKeep Posture for SharePoint, Permissions, if that was not intended.' }
$holders = @($all | Where-Object { [string]$_['consentType'] -eq 'Principal' -and [string]$_['resourceId'] -eq $resourceSp['00000003-0000-0ff1-ce00-000000000000'] } | ForEach-Object { [string]$_['principalId'] } | Sort-Object -Unique)
$names = @($holders | ForEach-Object { $x = @(Get-GraphValue "$graph/users/$($_)?`$select=userPrincipalName"); if ($x.Count) { [string]$x[0]['userPrincipalName'] } else { $_ } })
Write-Host ''
Write-Host "TenantKeep Posture for SharePoint ($ClientId): granted to $(if ($names.Count) { $names -join ', ' } else { 'nobody' })."
Write-Host 'Each of them needs SharePoint Administrator for the SharePoint read; make it eligible in PIM and activate it for the run.'
