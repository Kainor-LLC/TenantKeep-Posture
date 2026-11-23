# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureResourceScope {
    <#
    .SYNOPSIS
        The scope string to request for a named resource, with {tenant} filled in: from app.json, from
        app-services.json for Azure, Teams and Power Platform, or from app-sharepoint.json for SharePoint.
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
    $manifest = Get-PostureAppManifest -Name (Get-PostureResourceApp -Resource $Resource)
    if (-not $manifest['byName'].ContainsKey($Resource)) { throw "$($manifest['file']) names no resource '$Resource'. Known: $($manifest['byName'].Keys -join ', ')." }
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
        minutes before it expires. A new refresh token in the response replaces the old one. Azure, Teams and Power
        Platform come from the second sign-in (Connect-PostureSession -Services) and its refresh token, SharePoint
        from its own (Connect-PostureSession -SharePoint). Returns the token as a string by default;
        -AsSecureString for the modules that insist on one. Nothing is written to disk.
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
    elseif (-not $session['refreshToken'] -and $session.ContainsKey('tokenPipe') -and $session['tokenPipe']) {
        # The second collection process holds no refresh token; the main process renews for it (Start-PostureTokenServer).
        $tokens[$Resource] = Request-PostureParentToken -Resource $Resource
        $token = [string]$tokens[$Resource]['accessToken']
        Write-Verbose "Token for $Resource renewed by the main process, expires $($tokens[$Resource]['expiresUtc'].ToString('u'))."
    }
    else {
        # Three sign-ins, each with its own app and refresh token: the main one (Graph, Power BI), the second app
        # (Azure, Teams, Power Platform: the APIs with no read-only permission, kept off the shared app) and
        # SharePoint's.
        $holderName = Get-PostureResourceApp -Resource $Resource
        $holder = $session
        if ($holderName -ne 'main') {
            if (-not $session.ContainsKey($holderName) -or -not $session[$holderName]) {
                if ($holderName -eq 'sharepoint') { throw 'SharePoint is read through its own sign-in: Connect-PostureSession -SharePoint (Start-PostureRun does it when the SharePoint app is granted to you).' }
                throw 'Azure, Teams and Power Platform are read through a second sign-in: Connect-PostureSession -Services (Start-PostureRun does it when the run reads one of them).'
            }
            $holder = $session[$holderName]
        }
        $scope = Get-PostureResourceScope -Resource $Resource -TenantName $session['tenantName']
        # A sign-in already known to have ended is not asked about again: this throws what was recorded.
        if ($script:PostureSessionEnded.ContainsKey($holderName)) { Restore-PostureSignIn -Session $session -Holder $holderName -Reason '' }
        $grant = { Invoke-PostureTokenRequest -Endpoint token -TenantId $session['tenantId'] -Form @{ grant_type = 'refresh_token'; client_id = $holder['clientId']; refresh_token = $holder['refreshToken']; scope = $scope } }
        try { $response = & $grant }
        catch {
            # Refused because the sign-in itself is over (a Conditional Access sign-in frequency, a revoked session):
            # no renewal works until the admin signs in again. Restore-PostureSignIn asks, when there is someone to
            # ask, and puts the new refresh token in the session; otherwise it records that the sign-in ended and
            # throws. Any other refusal is thrown as it came.
            if (-not (Test-PostureSignInEnded -Message ([string]$_.Exception.Message))) { throw }
            Restore-PostureSignIn -Session $session -Holder $holderName -Reason ([string]$_.Exception.Message)
            $response = & $grant
        }
        if ($response.ContainsKey('refresh_token') -and $response['refresh_token']) { $holder['refreshToken'] = [string]$response['refresh_token'] }
        $token = [string]$response['access_token']
        $tokens[$Resource] = @{ accessToken = $token; expiresUtc = $now.AddSeconds([int]$response['expires_in']); scope = [string]$(if ($response.ContainsKey('scope')) { $response['scope'] }) }
        Write-Verbose "Token for $Resource acquired, expires $($tokens[$Resource]['expiresUtc'].ToString('u'))."
    }
    if ($AsSecureString) { return (ConvertTo-SecureString -String $token -AsPlainText -Force) }
    return $token
}
