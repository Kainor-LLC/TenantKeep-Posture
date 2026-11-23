# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureAppManifest {
    <#
    .SYNOPSIS
        Reads an app manifest: app.json, the multi-tenant public client every run signs in to; app-services.json
        (-Name services), the second app, for Azure, Teams and Power Platform; or app-sharepoint.json
        (-Name sharepoint), the optional app that alone asks for SharePoint full control.
    .DESCRIPTION
        The files ship inside the module (covered by the integrity manifest) and are also what
        deploy/setup/New-PostureClientApp.ps1 registers from, so the scopes an app asks for and the scopes the module
        requests at run time are one list.

        app.json is shared with TenantKeep On-Call and holds read-only permissions on every API. The three APIs that
        offer no read-only permission are in app-services.json, which Posture alone signs in to.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [ValidateSet('main', 'sharepoint', 'services')] [string] $Name = 'main',
        [string] $Path
    )

    $ErrorActionPreference = 'Stop'
    if (-not $Path) { $Path = Join-Path $script:ModuleRoot (@{ main = 'app.json'; sharepoint = 'app-sharepoint.json'; services = 'app-services.json' }[$Name]) }
    if (-not (Test-Path -LiteralPath $Path)) { throw "$(Split-Path $Path -Leaf) not found at $Path; the module folder is incomplete." }
    $manifest = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
    foreach ($key in 'displayName', 'clientId', 'redirectUri', 'consentRedirectUri', 'resources') {
        if (-not $manifest.ContainsKey($key)) { throw "$(Split-Path $Path -Leaf) is missing '$key'." }
    }
    $byName = @{}
    foreach ($r in @($manifest['resources'])) { $byName[[string]$r['name']] = $r }
    $manifest['byName'] = $byName
    $manifest['file'] = Split-Path $Path -Leaf
    return $manifest
}

function Get-PostureResourceApp {
    <#
    .SYNOPSIS
        Which sign-in a resource's token comes from: main (app.json), services (app-services.json: Azure, Teams and
        Power Platform) or sharepoint (app-sharepoint.json).
    .DESCRIPTION
        Graph is always the main sign-in's: the second app names Graph only so that a person can sign in to it.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Resource)

    $ErrorActionPreference = 'Stop'
    if ($Resource -eq 'graph') { return 'main' }
    if ($Resource -eq 'sharepoint') { return 'sharepoint' }
    if ((Get-PostureAppManifest -Name services)['byName'].ContainsKey($Resource)) { return 'services' }
    return 'main'
}
