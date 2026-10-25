# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Connect-PostureSession {
    <#
    .SYNOPSIS
        One sign-in for every service the posture run reads. Opens the browser, holds the session in memory.
    .DESCRIPTION
        Signs the admin in to the TenantKeep Posture app (a multi-tenant public client with delegated, read-only
        permissions; see app.json and docs/plan-one-signin.md) with the authorization code flow and PKCE on a loopback
        port, in plain PowerShell. From that one sign-in the module gets a token for each service as it needs one
        (Get-PostureToken) and opens the Graph session right away. The refresh token lives in this process only and
        is never written to disk. Every token is the signed-in admin's, bounded by that admin's own roles.

        A tenant that has not consented to the app yet is told so, with the admin consent link. A Conditional Access
        policy that blocks the sign-in is reported with the app id, so the admin can allow it; the module does not
        work around it. Pass -TenantId to refuse a sign-in to any other tenant.
    .PARAMETER TenantId
        Tenant id or a verified domain. Default: organizations, which lets the admin pick the tenant in the browser.
        With a tenant id, the sign-in is refused if the account that signs in belongs to another tenant.
    .PARAMETER DeviceCode
        Use the device code flow: a code to type into a browser on another machine. For a box without a browser.
    .PARAMETER NoBrowser
        Print the sign-in URL instead of opening the browser.
    .PARAMETER ClientId
        A customer-owned app registration with the same delegated permissions, instead of the Kainor-owned one.
    .PARAMETER TimeoutSeconds
        How long to wait for the sign-in to come back. Default 300.
    .EXAMPLE
        Connect-PostureSession -TenantId contoso.onmicrosoft.com
        Invoke-PostureCollection -OutRoot ~/tenantkeep/evidence
    .EXAMPLE
        Connect-PostureSession -DeviceCode
    #>
    [CmdletBinding(DefaultParameterSetName = 'Browser')]
    [OutputType([hashtable])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Sign-in instructions are for the console.')]
    param(
        [ValidatePattern('^([0-9a-fA-F-]{36}|[A-Za-z0-9.-]+\.[A-Za-z]{2,}|organizations)$')] [string] $TenantId = 'organizations',
        [Parameter(ParameterSetName = 'DeviceCode')] [switch] $DeviceCode,
        [Parameter(ParameterSetName = 'Browser')] [switch] $NoBrowser,
        [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $ClientId,
        [ValidateRange(30, 1800)] [int] $TimeoutSeconds = 300
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $manifest = Get-PostureAppManifest
    $clientId = $(if ($ClientId) { $ClientId } else { [string]$manifest['clientId'] })
    if (-not $clientId) { throw 'app.json carries no clientId: this build has no app registration to sign in to. Pass -ClientId for a registration of your own.' }
    $scope = 'openid profile offline_access https://graph.microsoft.com/.default'
    $consentLink = "https://login.microsoftonline.com/organizations/adminconsent?client_id=$clientId&redirect_uri=$([uri]::EscapeDataString([string]$manifest['consentRedirectUri']))"

    try {
        if ($DeviceCode) {
            $dc = Invoke-PostureTokenRequest -Endpoint devicecode -TenantId $TenantId -Form @{ client_id = $clientId; scope = $scope }
            Write-Host ''
            Write-Host ([string]$dc['message']) -ForegroundColor Cyan
            $interval = [int]$(if ($dc.ContainsKey('interval')) { $dc['interval'] } else { 5 })
            $deadline = [datetime]::UtcNow.AddSeconds([int]$dc['expires_in'])
            $tokens = $null
            while (-not $tokens) {
                if ([datetime]::UtcNow -gt $deadline) { throw 'The device code expired before the sign-in completed. Run the command again.' }
                Start-Sleep -Seconds $interval
                $poll = Invoke-PostureTokenRequest -Endpoint token -TenantId $TenantId -Form @{ grant_type = 'urn:ietf:params:oauth:grant-type:device_code'; client_id = $clientId; device_code = [string]$dc['device_code'] }
                if ($poll.ContainsKey('access_token')) { $tokens = $poll }
                elseif ([string]$poll['error'] -eq 'slow_down') { $interval += 5 }
            }
        }
        else {
            $verifierBytes = [byte[]]::new(32)
            [System.Security.Cryptography.RandomNumberGenerator]::Fill($verifierBytes)
            $verifier = [Convert]::ToBase64String($verifierBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            $challenge = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::ASCII.GetBytes($verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            $state = [guid]::NewGuid().ToString('n')
            $loopback = New-PostureLoopbackListener
            $query = @(
                "client_id=$clientId", 'response_type=code', "redirect_uri=$([uri]::EscapeDataString($loopback['redirectUri']))",
                "scope=$([uri]::EscapeDataString($scope))", "state=$state", "code_challenge=$challenge", 'code_challenge_method=S256', 'prompt=select_account'
            ) -join '&'
            $url = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?$query"
            $opened = $false
            if (-not $NoBrowser) {
                try { Start-Process $url; $opened = $true } catch { Write-Verbose "Browser did not open: $($_.Exception.Message)" }
            }
            Write-Host ''
            if ($opened) { Write-Host 'Sign in to TenantKeep Posture in the browser window that just opened.' -ForegroundColor Cyan }
            else { Write-Host 'Open this address in a browser and sign in:' -ForegroundColor Cyan; Write-Host "  $url" }
            $code = Wait-PostureAuthCode -Loopback $loopback -State $state -TimeoutSeconds $TimeoutSeconds
            $tokens = Invoke-PostureTokenRequest -Endpoint token -TenantId $TenantId -Form @{ grant_type = 'authorization_code'; client_id = $clientId; code = $code; redirect_uri = $loopback['redirectUri']; code_verifier = $verifier; scope = $scope }
        }
    }
    catch {
        $text = $_.Exception.Message
        if ($text -match 'AADSTS65001|consent_required|AADSTS650') {
            throw "This tenant has not consented to TenantKeep Posture yet. An admin consents once, here: $consentLink  Then run the command again. ($text)"
        }
        if ($text -match 'AADSTS5300\d|AADSTS530032') {
            throw "A Conditional Access policy in this tenant blocked this sign-in to TenantKeep Posture (app id $clientId). The policy says what it wants: a compliant device, an approved app, or an exclusion for the admin running the report. Nothing was read. ($text)"
        }
        throw
    }

    $claims = ConvertFrom-PostureJwt -Token ([string]$tokens['access_token'])
    $tid = [string]$claims['tid']
    $account = [string]$(foreach ($k in 'upn', 'preferred_username', 'unique_name') { if ($claims.ContainsKey($k) -and $claims[$k]) { $claims[$k]; break } })
    if ($TenantId -match '^[0-9a-fA-F-]{36}$' -and $tid -ne $TenantId) { throw "Signed in to tenant $tid, but -TenantId $TenantId was asked for. Nothing was read; sign in with an account in that tenant." }
    $now = [datetime]::UtcNow
    $script:PostureSession = @{
        clientId     = $clientId
        tenantId     = $tid
        tenantName   = $null
        account      = $account
        refreshToken = [string]$tokens['refresh_token']
        signedInUtc  = $now
        tokens       = @{ graph = @{ accessToken = [string]$tokens['access_token']; expiresUtc = $now.AddSeconds([int]$tokens['expires_in']); scope = [string]$(if ($tokens.ContainsKey('scope')) { $tokens['scope'] }) } }
    }
    if (-not $script:PostureSession['refreshToken']) { throw 'The sign-in returned no refresh token (offline_access missing from consent?). Other services cannot be reached from it.' }

    Connect-PostureService -Name graph
    $null = Assert-PostureGraphScope -RequiredScope @('Directory.Read.All')
    $org = Invoke-PostureGraphRequest -ApiVersion v1.0 -Uri 'organization?$select=id,displayName,verifiedDomains' -Single
    $orgValue = $(if ($org -is [hashtable] -and $org.ContainsKey('value')) { @($org['value'])[0] } else { $org })
    $initial = @($orgValue['verifiedDomains'] | Where-Object { $_['isInitial'] -eq $true })
    if ($initial.Count -gt 0) { $script:PostureSession['tenantName'] = ([string]$initial[0]['name'] -replace '\.onmicrosoft\.com$', '') }
    $script:PostureSession['tenantDisplayName'] = [string]$orgValue['displayName']

    Write-Host "Signed in as $account to $($script:PostureSession['tenantDisplayName']) ($tid)." -ForegroundColor Green
    return @{
        tenantId          = $tid
        tenantName        = $script:PostureSession['tenantName']
        tenantDisplayName = $script:PostureSession['tenantDisplayName']
        account           = $account
        clientId          = $clientId
        scopes            = @(([string]$(if ($claims.ContainsKey('scp')) { $claims['scp'] })) -split ' ' | Where-Object { $_ } | Sort-Object)
        expiresUtc        = $script:PostureSession['tokens']['graph']['expiresUtc']
    }
}
