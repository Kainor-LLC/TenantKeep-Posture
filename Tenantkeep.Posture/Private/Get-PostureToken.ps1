# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureResourceScope {
    <#
    .SYNOPSIS
        The scope string to request for a named resource from app.json, with {tenant} filled in.
    .DESCRIPTION
        Every resource is requested as <audience>/.default so the token carries exactly the delegated scopes the
        customer's admin consented to for that resource, nothing added at run time. SharePoint's audience is the
        tenant admin site and needs the tenant's onmicrosoft.com name.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Resource,
        [string] $TenantName
    )

    $ErrorActionPreference = 'Stop'
    $manifest = Get-PostureAppManifest
    if (-not $manifest['byName'].ContainsKey($Resource)) { throw "app.json names no resource '$Resource'. Known: $($manifest['byName'].Keys -join ', ')." }
    $audience = [string]$manifest['byName'][$Resource]['audience']
    if ($audience -like '*{tenant}*') {
        if (-not $TenantName) { throw "The $Resource audience needs the tenant name; sign in first so it can be read from the organization." }
        $audience = $audience.Replace('{tenant}', $TenantName)
    }
    return "$audience/.default"
}

function Get-PostureToken {
    <#
    .SYNOPSIS
        An access token for one resource from the session Connect-PostureSession opened.
    .DESCRIPTION
        Uses the refresh token held in memory to get a token for the resource's audience, and caches it until five
        minutes before it expires. A new refresh token in the response replaces the old one. Returns the token as a
        string by default; -AsSecureString for the modules that insist on one. Nothing is written to disk.
    #>
    [CmdletBinding()]
    [OutputType([string], [securestring])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'The token is already in memory as a string; the Graph SDK insists on a SecureString.')]
    param(
        [Parameter(Mandatory)] [string] $Resource,
        [switch] $AsSecureString,
        [switch] $Force
    )

    $ErrorActionPreference = 'Stop'
    $session = $script:PostureSession
    if (-not $session) { throw 'No session. Run Connect-PostureSession (or Start-PostureRun) first.' }
    $tokens = $session['tokens']
    $now = [datetime]::UtcNow
    if (-not $Force -and $tokens.ContainsKey($Resource) -and $tokens[$Resource]['expiresUtc'] -gt $now.AddMinutes(5)) {
        $token = [string]$tokens[$Resource]['accessToken']
    }
    else {
        $scope = Get-PostureResourceScope -Resource $Resource -TenantName $session['tenantName']
        $form = @{ grant_type = 'refresh_token'; client_id = $session['clientId']; refresh_token = $session['refreshToken']; scope = $scope }
        $response = Invoke-PostureTokenRequest -Endpoint token -TenantId $session['tenantId'] -Form $form
        if ($response.ContainsKey('refresh_token') -and $response['refresh_token']) { $session['refreshToken'] = [string]$response['refresh_token'] }
        $token = [string]$response['access_token']
        $tokens[$Resource] = @{ accessToken = $token; expiresUtc = $now.AddSeconds([int]$response['expires_in']); scope = [string]$(if ($response.ContainsKey('scope')) { $response['scope'] }) }
        Write-Verbose "Token for $Resource acquired, expires $($tokens[$Resource]['expiresUtc'].ToString('u'))."
    }
    if ($AsSecureString) { return (ConvertTo-SecureString -String $token -AsPlainText -Force) }
    return $token
}
