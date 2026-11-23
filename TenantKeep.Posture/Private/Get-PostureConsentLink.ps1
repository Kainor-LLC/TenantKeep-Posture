# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureConsentLink {
    <#
    .SYNOPSIS
        The address where an administrator approves what TenantKeep Posture reads, for the organisation, once.
    .DESCRIPTION
        The link names each permission in app.json's resources: the ones Posture asks for and no others. The
        registration is shared with TenantKeep On-Call, whose permissions are registered on it too, so a link that
        asked for everything registered (.default, or the older adminconsent address) would have an administrator
        approve On-Call's reads, a LAPS password among them, for a customer who wanted a report.

        One link names the permissions of all three APIs Posture reads through (Microsoft Graph, the Teams admin API
        and Azure Service Management). Microsoft's page does not say that is allowed; it showed the approval screen
        for such a link on 2026-11-22. -Resource gives the link for one API alone.
    .PARAMETER TenantId
        The tenant's id or a domain of it. Anything else gives the address for any organisation.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string] $ClientId,
        [string] $TenantId,
        [System.Collections.IDictionary] $Manifest,
        [string] $Resource
    )

    $ErrorActionPreference = 'Stop'
    if (-not $Manifest) { $Manifest = Get-PostureAppManifest }
    if (-not $ClientId) { $ClientId = [string]$Manifest['clientId'] }
    $basics = 'openid', 'profile', 'offline_access'
    $scopes = [System.Collections.Generic.List[string]]::new()
    foreach ($r in @($Manifest['resources'])) {
        if ($Resource -and [string]$r['name'] -ne $Resource) { continue }
        # A basic sign-in scope is written bare; every other one as the API's address, a slash, and the name. Azure's
        # address ends in a slash itself, which is how Microsoft writes that one.
        foreach ($s in @($r['scopes'])) { if ($s -in $basics) { if (-not $scopes.Contains([string]$s)) { $scopes.Add([string]$s) } } else { $scopes.Add("$($r['audience'])/$s") } }
    }
    if ($scopes.Count -eq 0) { throw "app.json names no permission$(if ($Resource) { " for '$Resource'" })." }
    $tenant = $(if ($TenantId -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$' -or $TenantId -match '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$') { $TenantId } else { 'organizations' })
    "https://login.microsoftonline.com/$tenant/v2.0/adminconsent?client_id=$ClientId&scope=$([uri]::EscapeDataString(($scopes -join ' ')))&redirect_uri=$([uri]::EscapeDataString([string]$Manifest['consentRedirectUri']))&state=posture"
}
