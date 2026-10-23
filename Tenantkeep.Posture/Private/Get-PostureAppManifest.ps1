# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureAppManifest {
    <#
    .SYNOPSIS
        Reads app.json, the manifest of the one multi-tenant public client the module signs in to.
    .DESCRIPTION
        The file ships inside the module (covered by the integrity manifest) and is also what
        deploy/setup/New-PostureClientApp.ps1 registers from, so the scopes the app asks for and the scopes the module
        requests at run time are one list. Cached for the session.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([string] $Path = (Join-Path $script:ModuleRoot 'app.json'))

    $ErrorActionPreference = 'Stop'
    if (-not (Test-Path -LiteralPath $Path)) { throw "app.json not found at $Path; the module folder is incomplete." }
    $manifest = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
    foreach ($key in 'displayName', 'clientId', 'redirectUri', 'consentRedirectUri', 'resources') {
        if (-not $manifest.ContainsKey($key)) { throw "app.json is missing '$key'." }
    }
    $byName = @{}
    foreach ($r in @($manifest['resources'])) { $byName[[string]$r['name']] = $r }
    $manifest['byName'] = $byName
    return $manifest
}
