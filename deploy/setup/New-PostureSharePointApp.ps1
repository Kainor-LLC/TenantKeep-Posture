#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    One-time setup: registers the Entra app that PnP.PowerShell needs for the SharePoint and Teams collector, with
    read-only delegated permissions, and records its ClientId in the org profile.
.DESCRIPTION
    Customer-side setup, run once per tenant by someone who can register applications and grant admin consent
    (Global Administrator, or Application Administrator plus Privileged Role Administrator for the consent). It is a
    write to the tenant, deliberately outside the module: the module itself never writes and never connects.

    What it does, in order:
      1. Checks for PnP.PowerShell 3.x.
      2. If a Graph session with Application.Read.All is open, looks for an app with the same name and reuses it.
      3. Otherwise registers the app through Register-PnPEntraIDAppForInteractiveLogin with delegated permissions only:
         SharePoint AllSites.FullControl, Graph User.Read, Sites.Read.All, Group.Read.All. Delegated FullControl is
         what the tenant admin reads (Get-PnPTenant, Get-PnPTenantSite) need; AllSites.Read was denied on a live
         tenant on 2026-10-14. Delegated means the app can do nothing the signed-in reader cannot. A browser window
         signs you in and then asks for admin consent.
      3b. With -ClientId and a Graph session holding Application.ReadWrite.All, adds the SharePoint permission to the
         existing registration instead (for an app registered with AllSites.Read), and prints the consent link.
      4. Writes sharePointClientId into profile.json when -ProfilePath is given, so the collection hint and the
         docs show the right command.
      5. Prints what is left to do by hand.

    Delegated permissions never exceed the signed-in user's own rights. The collector reads with the account that
    signs in; give that account SharePoint Administrator (or Global Reader plus SharePoint Administrator) and nothing
    more.
.PARAMETER Tenant
    The tenant's onmicrosoft.com name, for example contoso.onmicrosoft.com.
.PARAMETER ApplicationName
    Display name of the app registration. Default: Tenantkeep Posture (SharePoint read-only).
.PARAMETER ProfilePath
    profile.json to update with sharePointClientId.
.PARAMETER ClientId
    An existing registration's Application (client) id. Skips the registration and only records it and prints the
    remaining steps; for a rerun without a Graph session, or an app registered by hand.
.PARAMETER ReadOnlyPermission
    Request SharePoint AllSites.Read instead of AllSites.FullControl. Enough for site content reads, not for the tenant
    admin settings the collaboration checks need.
.PARAMETER DeviceLogin
    Use the device code flow instead of a browser window.
.EXAMPLE
    ./New-PostureSharePointApp.ps1 -Tenant contoso.onmicrosoft.com -ProfilePath ./clients/contoso/profile.json
.EXAMPLE
    Connect-MgGraph -TenantId <tenant> -Scopes Application.Read.All
    ./New-PostureSharePointApp.ps1 -Tenant contoso.onmicrosoft.com

    With a Graph session the script finds an existing registration by name and skips the creation.
#>
[CmdletBinding(SupportsShouldProcess)]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'One-time admin script output is for the console.')]
param(
    [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z0-9-]+\.onmicrosoft\.com$')] [string] $Tenant,
    [string] $ApplicationName = 'Tenantkeep Posture (SharePoint read-only)',
    [string] $ProfilePath,
    [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $ClientId,
    [switch] $ReadOnlyPermission,
    [switch] $DeviceLogin
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$pnp = Get-Module -ListAvailable PnP.PowerShell | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pnp -or $pnp.Version.Major -lt 3) { throw 'PnP.PowerShell 3.x is required: Install-Module PnP.PowerShell -Scope CurrentUser' }
Import-Module PnP.PowerShell -ErrorAction Stop

$sharePointPermissions = @($(if ($ReadOnlyPermission) { 'AllSites.Read' } else { 'AllSites.FullControl' }))
$graphPermissions = @('User.Read', 'Sites.Read.All', 'Group.Read.All')

# 2. Reuse an existing registration: the one given, or one a Graph session can see by name.
$ctx = $null
if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) { $ctx = Get-MgContext }
if ($clientId) { Write-Host "Using the existing registration $clientId; nothing created." }
if (-not $clientId -and $ctx -and @($ctx.Scopes) -contains 'Application.Read.All') {
    $escaped = $ApplicationName -replace "'", "''"
    $found = @((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$escaped'&`$select=appId,displayName" -OutputType HashTable).value)
    if ($found.Count -gt 0) {
        $clientId = [string]$found[0].appId
        Write-Host "Found an existing registration named '$ApplicationName' (ClientId $clientId); nothing created."
    }
}

# 3. Register.
if (-not $clientId) {
    if ($PSCmdlet.ShouldProcess($Tenant, "Register Entra app '$ApplicationName' with delegated $($sharePointPermissions -join ', '), $($graphPermissions -join ', ')")) {
        Write-Host "Registering '$ApplicationName' in $Tenant. A browser window will ask you to sign in, then to grant admin consent."
        $registerParams = @{ ApplicationName = $ApplicationName; Tenant = $Tenant; SharePointDelegatePermissions = $sharePointPermissions; GraphDelegatePermissions = $graphPermissions }
        if ($DeviceLogin) { $registerParams.DeviceLogin = $true }
        try { $result = Register-PnPEntraIDAppForInteractiveLogin @registerParams }
        catch {
            if ($_.Exception.Message -match 'already exist') { throw "An app named '$ApplicationName' already exists. Rerun with -ClientId <its Application (client) ID>, or with a Graph session that has Application.Read.All so it is found by name." }
            throw
        }
        # The cmdlet's output shape has changed between releases; take the ClientId from whichever property carries it, or from the text.
        foreach ($name in 'AzureAppId/ClientId', 'ClientId', 'AppId') {
            if ($null -ne $result -and $result.PSObject.Properties[$name] -and $result.$name) { $clientId = [string]$result.$name; break }
        }
        if (-not $clientId) {
            $m = [regex]::Match(($result | Out-String), '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
            if ($m.Success) { $clientId = $m.Value }
        }
        if (-not $clientId) { throw 'The registration returned no ClientId. Look the app up in Entra under App registrations and record its Application (client) ID in profile.json as sharePointClientId.' }
        Write-Host "Registered. ClientId $clientId"
    }
    else { return }
}

# 3b. Add the SharePoint permission to an existing registration when a Graph session can write applications.
$consentNeeded = $false
if ($clientId -and $ctx -and @($ctx.Scopes) -contains 'Application.ReadWrite.All') {
    $spoResource = '00000003-0000-0ff1-ce00-000000000000'   # Office 365 SharePoint Online
    $app = @((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$clientId'&`$select=id,requiredResourceAccess" -OutputType HashTable).value)
    if ($app.Count -eq 0) { throw "No application with appId $clientId in this tenant." }
    $spoSp = @((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$spoResource'&`$select=oauth2PermissionScopes" -OutputType HashTable).value)
    if ($spoSp.Count -eq 0) { throw 'The SharePoint Online service principal is not in this tenant.' }
    $required = @($app[0].requiredResourceAccess)
    $spoEntry = $required | Where-Object { $_.resourceAppId -eq $spoResource } | Select-Object -First 1
    if (-not $spoEntry) { $spoEntry = @{ resourceAppId = $spoResource; resourceAccess = @() }; $required += $spoEntry }
    $changed = $false
    foreach ($perm in $sharePointPermissions) {
        $scope = $spoSp[0].oauth2PermissionScopes | Where-Object { $_.value -eq $perm } | Select-Object -First 1
        if (-not $scope) { throw "SharePoint Online exposes no delegated permission named $perm." }
        if (@($spoEntry.resourceAccess | Where-Object { $_.id -eq $scope.id }).Count -eq 0) {
            $spoEntry.resourceAccess = @($spoEntry.resourceAccess) + @(@{ id = $scope.id; type = 'Scope' }); $changed = $true
        }
    }
    if ($changed -and $PSCmdlet.ShouldProcess($clientId, "Add delegated $($sharePointPermissions -join ', ') to the registration")) {
        $null = Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($app[0].id)" -Body @{ requiredResourceAccess = $required } -ContentType 'application/json'
        Write-Host "Added $($sharePointPermissions -join ', ') to the registration; admin consent is needed again."
        $consentNeeded = $true
    }
    elseif (-not $changed) { Write-Host "The registration already requests $($sharePointPermissions -join ', ')." }
}

# 4. Record it.
if ($ProfilePath) {
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ProfilePath)   # expands ~ and relative paths; .NET file APIs know neither
    $orgProfile = if (Test-Path -LiteralPath $full) { Get-Content -Raw -LiteralPath $full | ConvertFrom-Json -AsHashtable -Depth 10 } else { [ordered]@{ version = 1 } }
    $orgProfile['sharePointClientId'] = $clientId
    $orgProfile['updatedUtc'] = [datetime]::UtcNow.ToString('o')
    if ($PSCmdlet.ShouldProcess($full, 'Write sharePointClientId')) {
        [System.IO.File]::WriteAllText($full, (ConvertTo-Json -InputObject $orgProfile -Depth 10), [System.Text.UTF8Encoding]::new($false))
        Write-Host "sharePointClientId written to $full"
    }
}

# 5. What is left.
$short = $Tenant -replace '\.onmicrosoft\.com$', ''
Write-Host ''
Write-Host 'Remaining steps, by hand:'
Write-Host "  1. Admin consent. $(if ($consentNeeded) { 'The permission list changed, so grant consent again:' } else { 'If the consent page did not appear or you declined it, open:' })"
Write-Host "     https://login.microsoftonline.com/$Tenant/adminconsent?client_id=$clientId"
Write-Host '  2. The account that runs the collection needs the SharePoint Administrator role (Global Reader does not reach the tenant admin settings). Assign it through PIM if you have it.'
Write-Host '  3. If a Conditional Access policy blocks unknown apps or requires a compliant device, the app sign-in is subject to it like any other; run from a device that passes.'
Write-Host '  4. Connect before each collection, then run the collector:'
Write-Host "     Connect-PnPOnline -Url https://$short-admin.sharepoint.com -ClientId $clientId -Interactive"
Write-Host "     Connect-MicrosoftTeams"
Write-Host "     Invoke-PostureCollection -Collector SharePoint, Teams"
Write-Host '  5. The module never connects and never writes. Delete the app registration to revoke everything; nothing else is left behind.'
[pscustomobject]@{ ClientId = $clientId; ApplicationName = $ApplicationName; Tenant = $Tenant; SharePointPermissions = $sharePointPermissions; GraphPermissions = $graphPermissions }
