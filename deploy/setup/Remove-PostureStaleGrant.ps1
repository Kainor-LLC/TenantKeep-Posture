#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Customer-side: takes away from the TenantKeep app, in this tenant, every delegated permission its published
    manifest (TenantKeep.Posture/app.json) no longer names. With -WhatIf it only lists them.
.DESCRIPTION
    The TenantKeep app holds read-only permissions on every API. Its manifest has named broader ones in the past:
    until 2026-11-23, Azure Service Management, the Teams admin API and, as an option, the Power Platform admin API,
    none of which offers a read-only permission. Those three moved to a second app, TenantKeep Posture for Azure,
    Teams and Power Platform.

    Taking a permission off a registration does not take it away from an organisation that already approved it:
    the grant stays in that organisation's directory, and a refresh token for the app can still be redeemed for it.
    This script removes those leftovers, so that what the app holds in this tenant is what its manifest says.

    A write to the tenant, run by the customer's own administrator, deliberately outside the module: the module
    itself never writes. What it does, in order, and only in the tenant the Graph session is in:
      1. Reads the manifest: for each API, the permissions Posture asks for (resources) and the ones the product
         sharing the app asks for (sharedWith).
      2. Reads the app's delegated permission grants in this tenant, organisation-wide and per account.
      3. For each grant, keeps every permission the manifest names for that API and removes any other. A grant
         left with nothing is deleted; otherwise it is updated to what remains.
      4. Says what was removed and what the app holds now. Where the registration itself lives in this tenant, it
         also says whether the registration still lists an API the manifest does not.

    It only removes. It never adds a permission, and running it again finds nothing to do. No read of the main app
    is lost. Azure, Teams and Power Platform are read through the second app afterwards, which an administrator
    approves from the link Start-PostureRun prints.

    Needs a delegated Graph session in the tenant, as Global Administrator, Privileged Role Administrator, Cloud
    Application Administrator or Application Administrator:
      Connect-MgGraph -TenantId <tenant id> -Scopes DelegatedPermissionGrant.ReadWrite.All, Application.Read.All -NoWelcome
.PARAMETER TenantId
    The tenant the Graph session must be in. The script refuses any other.
.PARAMETER AppJsonPath
    The manifest that says what the app may hold. Default: TenantKeep.Posture/app.json next to this repository's
    module.
.PARAMETER ClientId
    The app id. Default: the one the manifest records.
.EXAMPLE
    ./deploy/setup/Remove-PostureStaleGrant.ps1 -TenantId <tenant id> -WhatIf

    Lists what would be removed and changes nothing.
.EXAMPLE
    ./deploy/setup/Remove-PostureStaleGrant.ps1 -TenantId <tenant id>
#>
[CmdletBinding(SupportsShouldProcess)]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'One-time admin script output is for the console.')]
param(
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $TenantId,
    [string] $AppJsonPath = (Join-Path $PSScriptRoot '..' '..' 'TenantKeep.Posture' 'app.json'),
    [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $ClientId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$graph = 'https://graph.microsoft.com/v1.0'
$graphAppId = '00000003-0000-0000-c000-000000000000'
# What signing in needs. These carry no access to data and are kept on Microsoft Graph whether or not a manifest lists them.
$signInBasics = 'openid', 'profile', 'offline_access', 'email'
function Get-GraphList {
    param([string] $Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    while ($Uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType HashTable
        if ($page -is [System.Collections.IDictionary] -and $page.Contains('value')) { foreach ($item in @($page['value'])) { if ($item) { $items.Add($item) } } }
        elseif ($page) { $items.Add($page) }
        $Uri = [string]$(if ($page -is [System.Collections.IDictionary] -and $page.Contains('@odata.nextLink')) { $page['@odata.nextLink'] })
    }
    return $items.ToArray()
}

$ctx = Get-MgContext
if (-not $ctx) { throw 'Connect-MgGraph first (see the help for the scopes).' }
if ([string]$ctx.TenantId -ne $TenantId) { throw "The Graph session is in tenant $($ctx.TenantId); this script only runs in $TenantId." }
if ('DelegatedPermissionGrant.ReadWrite.All' -notin @($ctx.Scopes)) { throw 'The Graph session needs DelegatedPermissionGrant.ReadWrite.All, which is what removes a grant.' }
# Reading the app and the APIs: any one of these will do, so a session opened for the registration script works too.
if (@('Application.Read.All', 'Application.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All' | Where-Object { $_ -in @($ctx.Scopes) }).Count -eq 0) { throw 'The Graph session needs Application.Read.All.' }

# 1. What the manifest lets the app hold, per API.
$manifestPath = (Resolve-Path -LiteralPath $AppJsonPath).Path
$manifestFile = Split-Path $manifestPath -Leaf
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -AsHashtable
$name = [string]$manifest['displayName']
if (-not $ClientId) { $ClientId = [string]$manifest['clientId'] }
if (-not $ClientId) { throw "$manifestFile carries no clientId. Pass -ClientId." }
$shared = @($(if ($manifest.ContainsKey('sharedWith')) { $manifest['sharedWith'] }) | Where-Object { $_ })
$allowed = @{}
foreach ($resource in @($manifest['resources']) + @($shared | ForEach-Object { $_['resources'] })) {
    $key = ([string]$resource['appId']).ToLowerInvariant()
    if (-not $allowed.ContainsKey($key)) { $allowed[$key] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) }
    foreach ($value in @($resource['scopes'])) { $null = $allowed[$key].Add([string]$value) }
}
if (-not $allowed.ContainsKey($graphAppId)) { $allowed[$graphAppId] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) }
foreach ($value in $signInBasics) { $null = $allowed[$graphAppId].Add($value) }

# 2. The app and its grants in this tenant.
$sp = @(Get-GraphList "$graph/servicePrincipals?`$filter=appId eq '$ClientId'&`$select=id,displayName")
if ($sp.Count -eq 0) { Write-Host "$name ($ClientId) is not in this tenant: there is nothing to remove."; return }
$spId = [string]$sp[0]['id']
$grants = @(Get-GraphList "$graph/oauth2PermissionGrants?`$filter=clientId eq '$spId'")
$apiOf = @{}
$api = {
    param([string] $ResourceId)
    if (-not $apiOf.ContainsKey($ResourceId)) {
        $r = @(Get-GraphList "$graph/servicePrincipals/$($ResourceId)?`$select=appId,displayName")
        $apiOf[$ResourceId] = $(if ($r.Count -gt 0) { @{ appId = ([string]$r[0]['appId']).ToLowerInvariant(); name = [string]$r[0]['displayName'] } } else { @{ appId = ''; name = "an API this tenant no longer has ($ResourceId)" } })
    }
    $apiOf[$ResourceId]
}

# 3. Keep what the manifest names; remove the rest.
$removed = 0; $pending = 0
$holds = [ordered]@{}
foreach ($grant in $grants) {
    $on = & $api ([string]$grant['resourceId'])
    $whom = $(if ([string]$grant['consentType'] -eq 'AllPrincipals') { 'the organisation' } else { "one account (object id $([string]$grant['principalId']))" })
    $have = @(([string]$grant['scope']) -split '\s+' | Where-Object { $_ })
    $may = $(if ($on.appId -and $allowed.ContainsKey($on.appId)) { $allowed[$on.appId] } else { $null })
    $keep = @($have | Where-Object { $may -and $may.Contains($_) })
    $drop = @($have | Where-Object { -not ($may -and $may.Contains($_)) })
    if ($drop.Count -gt 0) {
        $target = "$($on.name), granted for $whom"
        if ($keep.Count -eq 0) {
            if ($PSCmdlet.ShouldProcess($target, "Remove the grant ($($drop -join ', '))")) {
                $null = Invoke-MgGraphRequest -Method DELETE -Uri "$graph/oauth2PermissionGrants/$([string]$grant['id'])"
                Write-Host "Removed from $($target): $($drop -join ', ')"
                $removed += $drop.Count
            }
            else { $pending += $drop.Count; $keep = $have }
        }
        elseif ($PSCmdlet.ShouldProcess($target, "Remove $($drop -join ', ') from the grant, keeping $($keep.Count) permission(s)")) {
            $null = Invoke-MgGraphRequest -Method PATCH -Uri "$graph/oauth2PermissionGrants/$([string]$grant['id'])" -Body (@{ scope = ($keep -join ' ') } | ConvertTo-Json) -ContentType 'application/json'
            Write-Host "Removed from $($target): $($drop -join ', ')"
            $removed += $drop.Count
        }
        else { $pending += $drop.Count; $keep = $have }
    }
    if ($keep.Count -gt 0) {
        if (-not $holds.Contains($on.name)) { $holds[$on.name] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) }
        foreach ($value in $keep) { $null = $holds[$on.name].Add($value) }
    }
}

# 4. What the app holds now, and the verdict.
Write-Host ''
if ($holds.Count -eq 0) { Write-Host "$name holds no delegated permission in this tenant." }
else {
    Write-Host "$name holds in this tenant$(if ($pending -gt 0) { ' (nothing was changed)' }):"
    foreach ($apiName in $holds.Keys) {
        $values = @($holds[$apiName] | Sort-Object)
        Write-Host ("  {0}: {1}" -f $apiName, $(if ($values.Count -le 6) { $values -join ', ' } else { "$($values.Count) permissions" }))
    }
}
# The registration itself, where it lives in this tenant: an API it still lists that the manifest does not.
$registration = @(Get-GraphList "$graph/applications?`$filter=appId eq '$ClientId'&`$select=id,requiredResourceAccess")
$listed = @($registration | ForEach-Object { $_['requiredResourceAccess'] } | Where-Object { $_ } | ForEach-Object { ([string]$_['resourceAppId']).ToLowerInvariant() })
$extra = @($listed | Where-Object { -not $allowed.ContainsKey($_) })
if ($extra.Count -gt 0) { Write-Warning "The registration still lists $($extra.Count) API(s) $manifestFile does not name ($($extra -join ', ')). Run deploy/setup/New-PostureClientApp.ps1 to bring the registration in line." }

if ($pending -gt 0) { Write-Host "Not clean yet: $pending permission(s) the manifest does not name are still granted. Run again without -WhatIf to remove them." -ForegroundColor Yellow }
elseif ($extra.Count -gt 0) { Write-Host "The grants in this tenant are clean$(if ($removed -gt 0) { " ($removed permission(s) removed)" }); the registration is not yet." -ForegroundColor Yellow }
else { Write-Host "Clean: in tenant $TenantId, $name holds only what $manifestFile names$(if ($removed -gt 0) { " ($removed permission(s) removed)" })." -ForegroundColor Green }
