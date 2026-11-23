# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureConsentLink {
    <#
    .SYNOPSIS
        The address where an administrator approves what TenantKeep Posture reads, for the organisation, once.
    .DESCRIPTION
        The link names each permission in the manifest's resources: the ones Posture asks for and no others. The
        main registration (app.json) is shared with TenantKeep On-Call, whose permissions are registered on it too,
        so a link that asked for everything registered (.default, or the older adminconsent address) would have an
        administrator approve On-Call's reads, a LAPS password among them, for a customer who wanted a report.

        -App services gives the link for the second registration (app-services.json), through which Azure, Teams
        and Power Platform are read: those APIs have no read-only permission, so they are kept off the main one,
        which holds read-only permissions only. One link can name the permissions of several APIs; Microsoft's page
        does not say that is allowed, and it showed the approval screen for such links on 2026-11-22 and
        2026-11-23. -Resource gives the link for one API alone.

        A resource a manifest marks optional (Power BI on the main app, Power Platform on the second) is left out
        of that app's link, so a tenant that approved it earlier is not asked again and a customer who does not
        want those checks approves nothing for them. -Optional gives the link that names the optional resources
        and only them. On the second app every link also carries what signing in to it needs (the resource marked
        signIn), so each link is enough alone.
    .PARAMETER TenantId
        The tenant's id or a domain of it. Anything else gives the address for any organisation.
    .PARAMETER App
        main (the default), or services for the second registration.
    .PARAMETER Optional
        The link for the app's optional resources, in place of its main one.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string] $ClientId,
        [string] $TenantId,
        [ValidateSet('main', 'services')] [string] $App = 'main',
        [System.Collections.IDictionary] $Manifest,
        [string] $Resource,
        [switch] $Optional
    )

    $ErrorActionPreference = 'Stop'
    if (-not $Manifest) { $Manifest = Get-PostureAppManifest -Name $App }
    $file = [string]$(if ($Manifest.Contains('file')) { $Manifest['file'] } else { 'The manifest' })
    if (-not $ClientId) { $ClientId = [string]$Manifest['clientId'] }
    if (-not $ClientId) { throw "$file carries no client id yet: the registration has not been created (deploy/setup/New-PostureClientApp.ps1)." }
    $basics = 'openid', 'profile', 'offline_access'
    $scopes = [System.Collections.Generic.List[string]]::new()
    $named = 0
    foreach ($r in @($Manifest['resources'])) {
        # What signing in to the app needs goes in every link of that app; the rest is chosen by -Resource and -Optional.
        $isSignIn = [bool]($r -is [System.Collections.IDictionary] -and $r.Contains('signIn') -and $r['signIn'])
        if (-not $isSignIn) {
            if ($Resource -and [string]$r['name'] -ne $Resource) { continue }
            $isOptional = [bool]($r -is [System.Collections.IDictionary] -and $r.Contains('optional') -and $r['optional'])
            if (-not $Resource -and $isOptional -ne [bool]$Optional) { continue }
            $named++
        }
        # A basic sign-in scope is written bare; every other one as the API's address, a slash, and the name. Azure's
        # address ends in a slash itself, which is how Microsoft writes that one.
        foreach ($s in @($r['scopes'])) { if ($s -in $basics) { if (-not $scopes.Contains([string]$s)) { $scopes.Add([string]$s) } } else { $scopes.Add("$($r['audience'])/$s") } }
    }
    if ($named -eq 0) { throw "$file names no permission$(if ($Resource) { " for '$Resource'" } elseif ($Optional) { ' that is optional' })." }
    $tenant = $(if ($TenantId -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$' -or $TenantId -match '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$') { $TenantId } else { 'organizations' })
    "https://login.microsoftonline.com/$tenant/v2.0/adminconsent?client_id=$ClientId&scope=$([uri]::EscapeDataString(($scopes -join ' ')))&redirect_uri=$([uri]::EscapeDataString([string]$Manifest['consentRedirectUri']))&state=posture"
}
