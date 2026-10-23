#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Kainor-side, once: registers the multi-tenant public client that Start-PostureRun signs in to, from the manifest
    the module ships (Tenantkeep.Posture/app.json), and marks it publisher verified.
.DESCRIPTION
    This is the one app registration behind the one sign-in (docs/plan-one-signin.md). It lives in the Kainor tenant
    and is used by every customer tenant after their admin consents once. It is a public client: no secret, no
    certificate, nothing to leak. Every permission is delegated and read-only, so a token is always the signed-in
    admin's, bounded by that admin's own roles.

    What it does, in order, and only against the Kainor tenant:
      1. Reads app.json: display name, redirect URIs and, per resource, the delegated scope values.
      2. Resolves every scope value to its id on the resource's service principal in this tenant. A value the
         resource does not expose is reported and left out; nothing is guessed.
      3. Creates the registration (signInAudience AzureADMultipleOrgs, public client with the loopback redirect, a
         web redirect for the consent page, the resolved requiredResourceAccess, publisher domain), or updates the
         same fields on the existing one with that name.
      4. With -PartnerId, calls setVerifiedPublisher so customers see "verified publisher" on the consent screen.
         Needs a Global Administrator who is also an account admin on the Partner Center account, signed in with MFA,
         and the publisher domain verified on both sides (verify: the Partner Global Account id is what Microsoft
         expects; a Location id fails with MPNGlobalAccountNotFound).
      5. Writes the client id back into app.json so the module and the docs carry it.

    Needs a delegated Graph session in the Kainor tenant with Application.ReadWrite.All:
      Connect-MgGraph -TenantId <kainor tenant id> -Scopes Application.ReadWrite.All -NoWelcome
.PARAMETER AppJsonPath
    The manifest to read and write back to. Default: Tenantkeep.Posture/app.json next to this repository's module.
.PARAMETER PartnerId
    The Partner Center Partner One id (Partner Global Account) for publisher verification. Omit to skip that step.
.PARAMETER TenantId
    The tenant the Graph session must be in. The script refuses any other.
.EXAMPLE
    Connect-MgGraph -TenantId 4470dc21-0000-0000-0000-000000000000 -Scopes Application.ReadWrite.All -NoWelcome
    ./deploy/setup/New-PostureClientApp.ps1 -TenantId 4470dc21-0000-0000-0000-000000000000 -PartnerId 1234567
#>
[CmdletBinding(SupportsShouldProcess)]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'One-time admin script output is for the console.')]
param(
    [string] $AppJsonPath = (Join-Path $PSScriptRoot '..' '..' 'Tenantkeep.Posture' 'app.json'),
    [ValidatePattern('^\d{5,10}$')] [string] $PartnerId,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $TenantId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$graph = 'https://graph.microsoft.com/v1.0'
function Get-GraphValue { param([string] $Uri) Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType HashTable }
function Send-GraphPost { param([string] $Uri, [hashtable] $Body) Invoke-MgGraphRequest -Method POST -Uri $Uri -Body ($Body | ConvertTo-Json -Depth 10) -ContentType 'application/json' -OutputType HashTable }
function Send-GraphPatch { param([string] $Uri, [hashtable] $Body) Invoke-MgGraphRequest -Method PATCH -Uri $Uri -Body ($Body | ConvertTo-Json -Depth 10) -ContentType 'application/json' -OutputType HashTable }

$ctx = Get-MgContext
if (-not $ctx) { throw 'Connect-MgGraph first, with Application.ReadWrite.All.' }
if ([string]$ctx.TenantId -ne $TenantId) { throw "The Graph session is in tenant $($ctx.TenantId); this script only runs in $TenantId." }
if ('Application.ReadWrite.All' -notin @($ctx.Scopes)) { throw 'The Graph session needs Application.ReadWrite.All.' }

# 1. The manifest.
$appJsonPath = (Resolve-Path -LiteralPath $AppJsonPath).Path
$manifest = Get-Content -LiteralPath $appJsonPath -Raw | ConvertFrom-Json -AsHashtable
$name = [string]$manifest['displayName']

# 2. Scope values to ids, per resource, from the service principals in this tenant.
$required = [System.Collections.Generic.List[hashtable]]::new()
foreach ($resource in @($manifest['resources'])) {
    $sps = @((Get-GraphValue "$graph/servicePrincipals?`$filter=appId eq '$($resource['appId'])'&`$select=id,displayName,oauth2PermissionScopes").value)
    if ($sps.Count -eq 0) { Write-Warning "No service principal for $($resource['label']) ($($resource['appId'])) in this tenant; its scopes are left out."; continue }
    $exposed = @{}
    foreach ($s in @($sps[0].oauth2PermissionScopes)) { $exposed[[string]$s.value] = [string]$s.id }
    $access = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($value in @($resource['scopes'])) {
        if ($exposed.ContainsKey($value)) { $access.Add(@{ id = $exposed[$value]; type = 'Scope' }) }
        else { Write-Warning "$($resource['label']) exposes no delegated scope '$value'; left out (verify the value)." }
    }
    if ($access.Count -gt 0) { $required.Add(@{ resourceAppId = [string]$resource['appId']; resourceAccess = @($access) }) }
    Write-Host ("{0}: {1} of {2} scopes resolved" -f $resource['label'], $access.Count, @($resource['scopes']).Count)
}

# 3. Create or update. Delegated only: type is always Scope, never Role. Public client: no credentials, ever.
$fields = @{
    displayName            = $name
    signInAudience         = 'AzureADMultipleOrgs'
    isFallbackPublicClient = $true
    publicClient           = @{ redirectUris = @([string]$manifest['redirectUri']) }
    web                    = @{ redirectUris = @([string]$manifest['consentRedirectUri']); implicitGrantSettings = @{ enableAccessTokenIssuance = $false; enableIdTokenIssuance = $false } }
    requiredResourceAccess = @($required)
    notes                  = [string]$manifest['notes']
    info                   = @{ privacyStatementUrl = 'https://tenantkeep.app/licensing/'; termsOfServiceUrl = 'https://tenantkeep.app/licensing/'; marketingUrl = 'https://tenantkeep.app/' }
}
$escaped = $name -replace "'", "''"
$apps = @((Get-GraphValue "$graph/applications?`$filter=displayName eq '$escaped'&`$select=id,appId,publisherDomain,verifiedPublisher").value)
if ($apps.Count -eq 0) {
    if ($PSCmdlet.ShouldProcess($name, 'Create the multi-tenant public client')) {
        $app = Send-GraphPost "$graph/applications" ($fields + @{ publisherDomain = [string]$manifest['publisherDomain'] })
        Write-Host "App registration created: $($app.appId)"
    }
    else { $app = @{ id = ''; appId = ''; verifiedPublisher = @{} } }
}
else {
    $app = $apps[0]
    if ($PSCmdlet.ShouldProcess($name, 'Update the registration to match app.json')) {
        $null = Send-GraphPatch "$graph/applications/$($app.id)" $fields
        Write-Host "App registration updated: $($app.appId)"
    }
}

# 4. Publisher verification, through Graph. Microsoft checks the signed-in user against the Partner Center account.
if ($PartnerId -and $app.id) {
    $have = [string]$(if ($app.ContainsKey('verifiedPublisher') -and $app.verifiedPublisher) { $app.verifiedPublisher.verifiedPublisherId })
    if ($have -eq $PartnerId) { Write-Host "Publisher already verified as partner $PartnerId" }
    elseif ($PSCmdlet.ShouldProcess($name, "Set verified publisher $PartnerId")) {
        $null = Send-GraphPost "$graph/applications/$($app.id)/setVerifiedPublisher" @{ verifiedPublisherId = $PartnerId }
        Write-Host "Publisher verified as partner $PartnerId"
    }
}

# 5. Record the client id where the module reads it.
if ($app.appId -and [string]$manifest['clientId'] -ne [string]$app.appId -and $PSCmdlet.ShouldProcess($appJsonPath, "Write clientId $($app.appId)")) {
    $raw = Get-Content -LiteralPath $appJsonPath -Raw
    $raw = $raw -replace '"clientId":\s*"[^"]*"', ('"clientId": "' + $app.appId + '"')
    Set-Content -LiteralPath $appJsonPath -Value $raw -NoNewline
    Write-Host "clientId written to $appJsonPath"
}

Write-Host @"

Done. Customers consent once with an admin account at:
  https://login.microsoftonline.com/organizations/adminconsent?client_id=$($app.appId)&redirect_uri=$([uri]::EscapeDataString([string]$manifest['consentRedirectUri']))
Start-PostureRun prints that link when a tenant has not consented yet. Nothing else is created anywhere.
"@
