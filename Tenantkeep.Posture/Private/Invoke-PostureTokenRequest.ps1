# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureTokenRequest {
    <#
    .SYNOPSIS
        The one HTTP boundary to the Microsoft identity platform: a form POST to login.microsoftonline.com.
    .DESCRIPTION
        Every token the module ever holds comes through here: the authorization code exchange, the device code
        request and poll, and the refresh grant per resource. Nothing else in the module talks to the identity
        platform, and nothing here talks to anything else. The response is returned as a hashtable; an error
        response becomes a thrown error that carries the AADSTS text so the caller can act on consent and
        interaction codes. The device code "authorization_pending" and "slow_down" states are returned, not thrown.
    .PARAMETER Endpoint
        token or devicecode.
    .PARAMETER TenantId
        Tenant id, domain, or organizations.
    .PARAMETER Form
        The form fields.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [ValidateSet('token', 'devicecode')] [string] $Endpoint,
        [Parameter(Mandatory)] [string] $TenantId,
        [Parameter(Mandatory)] [hashtable] $Form,
        [string] $Authority = 'https://login.microsoftonline.com'
    )

    $ErrorActionPreference = 'Stop'
    $uri = "$Authority/$TenantId/oauth2/v2.0/$Endpoint"
    $status = 0
    $response = Invoke-RestMethod -Method Post -Uri $uri -Body $Form -ContentType 'application/x-www-form-urlencoded' -SkipHttpErrorCheck -StatusCodeVariable status
    $result = @{}
    if ($response -is [System.Collections.IDictionary]) { foreach ($k in $response.Keys) { $result[[string]$k] = $response[$k] } }
    else { foreach ($p in $response.PSObject.Properties) { $result[$p.Name] = $p.Value } }
    if ($status -ge 400) {
        $code = [string]$(if ($result.ContainsKey('error')) { $result['error'] })
        if ($code -in 'authorization_pending', 'slow_down') { return $result }
        $detail = [string]$(if ($result.ContainsKey('error_description')) { $result['error_description'] } else { "HTTP $status" })
        throw "Sign-in failed ($code): $detail"
    }
    return $result
}
