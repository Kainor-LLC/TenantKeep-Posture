# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureAppManifest {
    <#
    .SYNOPSIS
        Reads an app manifest: app.json, the multi-tenant public client every run signs in to, or (-Name sharepoint)
        app-sharepoint.json, the optional second app that alone asks for SharePoint full control.
    .DESCRIPTION
        The files ship inside the module (covered by the integrity manifest) and are also what
        deploy/setup/New-PostureClientApp.ps1 registers from, so the scopes an app asks for and the scopes the module
        requests at run time are one list.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [ValidateSet('main', 'sharepoint')] [string] $Name = 'main',
        [string] $Path
    )

    $ErrorActionPreference = 'Stop'
    if (-not $Path) { $Path = Join-Path $script:ModuleRoot $(if ($Name -eq 'sharepoint') { 'app-sharepoint.json' } else { 'app.json' }) }
    if (-not (Test-Path -LiteralPath $Path)) { throw "$(Split-Path $Path -Leaf) not found at $Path; the module folder is incomplete." }
    $manifest = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
    foreach ($key in 'displayName', 'clientId', 'redirectUri', 'consentRedirectUri', 'resources') {
        if (-not $manifest.ContainsKey($key)) { throw "$(Split-Path $Path -Leaf) is missing '$key'." }
    }
    $byName = @{}
    foreach ($r in @($manifest['resources'])) { $byName[[string]$r['name']] = $r }
    $manifest['byName'] = $byName
    return $manifest
}
