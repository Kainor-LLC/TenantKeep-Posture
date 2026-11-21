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

        -SharePoint adds the second, optional sign-in for the SharePoint admin read: TenantKeep Posture for SharePoint
        (app-sharepoint.json), the only app that asks for SharePoint full control. It is never consented for the whole
        organisation; deploy/setup/Grant-PostureSharePointAccess.ps1 grants it to named admins and requires
        assignment, so anyone else is refused. It signs in as the account already signed in, to the same tenant.
        Start-PostureRun does this on its own when the app is granted to that account.
    .PARAMETER TenantId
        Tenant id or a verified domain. Default: organizations, which lets the admin pick the tenant in the browser.
        With a tenant id, the sign-in is refused if the account that signs in belongs to another tenant.
    .PARAMETER DeviceCode
        Use the device code flow: a code to type into a browser on another machine. For a box without a browser.
    .PARAMETER NoBrowser
        Print the sign-in URL instead of opening the browser.
    .PARAMETER ClientId
        A customer-owned app registration with the same delegated permissions, instead of the Kainor-owned one. With
        -SharePoint, the customer-owned SharePoint registration (deploy/setup/New-PostureSharePointApp.ps1).
    .PARAMETER SharePoint
        Sign in to TenantKeep Posture for SharePoint as well, after the main sign-in, for the SharePoint admin read.
    .PARAMETER TimeoutSeconds
        How long to wait for the sign-in to come back. Default 300.
    .EXAMPLE
        Connect-PostureSession -TenantId contoso.onmicrosoft.com
        Invoke-PostureCollection -OutRoot ~/tenantkeep/evidence
    .EXAMPLE
        Connect-PostureSession -DeviceCode
    .EXAMPLE
        Connect-PostureSession -TenantId contoso.onmicrosoft.com
        Connect-PostureSession -SharePoint
    #>
    [CmdletBinding(DefaultParameterSetName = 'Browser')]
    [OutputType([hashtable])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Sign-in instructions are for the console.')]
    param(
        [ValidatePattern('^([0-9a-fA-F-]{36}|[A-Za-z0-9.-]+\.[A-Za-z]{2,}|organizations)$')] [string] $TenantId = 'organizations',
        [Parameter(ParameterSetName = 'DeviceCode')] [switch] $DeviceCode,
        [Parameter(ParameterSetName = 'Browser')] [switch] $NoBrowser,
        [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $ClientId,
        [ValidateRange(30, 1800)] [int] $TimeoutSeconds = 300,
        [switch] $SharePoint
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest
    if ($SharePoint) { return (Connect-PostureSharePointSession -ClientId $ClientId -DeviceCode:$DeviceCode -NoBrowser:$NoBrowser -TimeoutSeconds $TimeoutSeconds) }

    $manifest = Get-PostureAppManifest
    $clientId = $(if ($ClientId) { $ClientId } else { [string]$manifest['clientId'] })
    if (-not $clientId) { throw 'app.json carries no clientId: this build has no app registration to sign in to. Pass -ClientId for a registration of your own.' }
    $scope = 'openid profile offline_access https://graph.microsoft.com/.default'
    $consentLink = "https://login.microsoftonline.com/organizations/adminconsent?client_id=$clientId&redirect_uri=$([uri]::EscapeDataString([string]$manifest['consentRedirectUri']))"

    $signIn = @{ ClientId = $clientId; Scope = $scope; TenantId = $TenantId; AppName = 'TenantKeep Posture'; DeviceCode = $DeviceCode; NoBrowser = $NoBrowser; TimeoutSeconds = $TimeoutSeconds }
    try { $tokens = Invoke-PostureSignIn @signIn }
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
        # For a sign-in that ends during a long run (Restore-PostureSignIn): whether someone can be asked to sign in
        # again and how, and how many times that has happened.
        interactive  = (Test-PostureInteractive)
        signInMode   = $(if ($DeviceCode) { 'device' } elseif ($NoBrowser) { 'nobrowser' } else { 'browser' })
        signInsRenewed = 0
        # Who the account is to Conditional Access, from its token: its id and the roles it holds now. Read only to
        # say beforehand which sign-in frequency applies to it (Get-PostureSignInFrequencyNotice).
        objectId     = [string]$(if ($claims.ContainsKey('oid')) { $claims['oid'] })
        roleTemplateIds = @($(if ($claims.ContainsKey('wids')) { $claims['wids'] }) | Where-Object { $_ } | ForEach-Object { [string]$_ })
        tokens       = @{ graph = @{ accessToken = [string]$tokens['access_token']; expiresUtc = $now.AddSeconds([int]$tokens['expires_in']); scope = [string]$(if ($tokens.ContainsKey('scope')) { $tokens['scope'] }) } }
    }
    if (-not $script:PostureSession['refreshToken']) { throw 'The sign-in returned no refresh token (offline_access missing from consent?). Other services cannot be reached from it.' }
    # A new sign-in: whatever was recorded about an earlier one having ended no longer holds.
    $script:PostureSessionEnded.Clear()

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
