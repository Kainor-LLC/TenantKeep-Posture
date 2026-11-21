# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureSignIn {
    <#
    .SYNOPSIS
        The interactive part of a sign-in: the authorization code flow with PKCE on a loopback port, or the device code
        flow. Returns the token response; the caller decides what the tokens mean and how to word a failure.
    .PARAMETER LoginHint
        The account to sign in as. The second sign-in for SharePoint passes the run's account, so the browser goes
        straight through when that account is already signed in there.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Sign-in instructions are for the console.')]
    param(
        [Parameter(Mandatory)] [string] $ClientId,
        [Parameter(Mandatory)] [string] $Scope,
        [Parameter(Mandatory)] [string] $TenantId,
        [Parameter(Mandatory)] [string] $AppName,
        [string] $LoginHint,
        [switch] $DeviceCode,
        [switch] $NoBrowser,
        [int] $TimeoutSeconds = 300
    )

    $ErrorActionPreference = 'Stop'
    if ($DeviceCode) {
        $dc = Invoke-PostureTokenRequest -Endpoint devicecode -TenantId $TenantId -Form @{ client_id = $ClientId; scope = $Scope }
        Write-Host ''
        Write-Host ([string]$dc['message']) -ForegroundColor Cyan
        $interval = [int]$(if ($dc.ContainsKey('interval')) { $dc['interval'] } else { 5 })
        $deadline = [datetime]::UtcNow.AddSeconds([int]$dc['expires_in'])
        while ($true) {
            if ([datetime]::UtcNow -gt $deadline) { throw 'The device code expired before the sign-in completed. Run the command again.' }
            Start-Sleep -Seconds $interval
            $poll = Invoke-PostureTokenRequest -Endpoint token -TenantId $TenantId -Form @{ grant_type = 'urn:ietf:params:oauth:grant-type:device_code'; client_id = $ClientId; device_code = [string]$dc['device_code'] }
            if ($poll.ContainsKey('access_token')) { return $poll }
            if ([string]$poll['error'] -eq 'slow_down') { $interval += 5 }
        }
    }
    $verifierBytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($verifierBytes)
    $verifier = [Convert]::ToBase64String($verifierBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $challenge = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::ASCII.GetBytes($verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $state = [guid]::NewGuid().ToString('n')
    $loopback = New-PostureLoopbackListener
    $query = @(
        "client_id=$ClientId", 'response_type=code', "redirect_uri=$([uri]::EscapeDataString($loopback['redirectUri']))",
        "scope=$([uri]::EscapeDataString($Scope))", "state=$state", "code_challenge=$challenge", 'code_challenge_method=S256'
        $(if ($LoginHint) { "login_hint=$([uri]::EscapeDataString($LoginHint))" } else { 'prompt=select_account' })
    ) -join '&'
    $url = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?$query"
    $opened = $false
    if (-not $NoBrowser) {
        try { Start-Process $url; $opened = $true } catch { Write-Verbose "Browser did not open: $($_.Exception.Message)" }
    }
    Write-Host ''
    if ($opened) { Write-Host "Sign in to $AppName in the browser window that just opened." -ForegroundColor Cyan }
    else { Write-Host 'Open this address in a browser and sign in:' -ForegroundColor Cyan; Write-Host "  $url" }
    $code = Wait-PostureAuthCode -Loopback $loopback -State $state -TimeoutSeconds $TimeoutSeconds
    return (Invoke-PostureTokenRequest -Endpoint token -TenantId $TenantId -Form @{ grant_type = 'authorization_code'; client_id = $ClientId; code = $code; redirect_uri = $loopback['redirectUri']; code_verifier = $verifier; scope = $Scope })
}
