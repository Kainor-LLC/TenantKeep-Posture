# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# The second sign-in of a run: TenantKeep Posture for Azure, Teams and Power Platform (app-services.json).
#
# Azure Service Management, the Teams admin API and the Power Platform admin API each offer one delegated permission,
# to act as the signed-in administrator, and no read-only one. The main app (app.json) is shared with TenantKeep
# On-Call and holds read-only permissions on every API: a refresh token for a registration can be redeemed for any
# API the tenant granted that registration, so one broader permission anywhere on it would make "read permissions
# only" untrue. These three therefore live on an app that Posture alone signs in to, approved separately. What the
# module does with its tokens is held to reads by the request entry points and their guard tests.

function Test-PostureServicesAccess {
    <#
    .SYNOPSIS
        Whether this tenant has the second app at all, read through Graph before the second sign-in: a tenant that
        never approved it sees no second browser window, only the reason and the link.
    .DESCRIPTION
        One read of the app's service principal (Directory.Read.All, which the main sign-in holds). When it cannot
        be read the answer is unknown and the caller may try the sign-in.
    .OUTPUTS
        @{ status = 'present' | 'absent' | 'disabled' | 'unknown'; reason = <text> }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string] $ClientId,
        [string] $TenantId
    )

    $ErrorActionPreference = 'Stop'
    $manifest = Get-PostureAppManifest -Name services
    $name = [string]$manifest['displayName']
    if (-not $ClientId) { $ClientId = [string]$manifest['clientId'] }
    if (-not $ClientId) { return @{ status = 'absent'; reason = "This build carries no app id for $name yet, so the run's sign-in cannot read them." } }
    $link = Get-PostureConsentLink -App services -ClientId $ClientId -TenantId $TenantId
    try {
        $answer = Invoke-PostureGraphRequest -ApiVersion v1.0 -Uri "servicePrincipals?`$filter=appId eq '$ClientId'&`$select=id,accountEnabled" -Single
        $sp = @($(if ($answer -is [System.Collections.IDictionary] -and $answer.Contains('value')) { $answer['value'] } else { $answer }) | Where-Object { $_ })
        if ($sp.Count -eq 0) { return @{ status = 'absent'; reason = "This organisation has not approved $name, the app they are read through. An administrator approves it once, here: $link" } }
        if ($sp[0]['accountEnabled'] -eq $false) { return @{ status = 'disabled'; reason = "$name is turned off in this organisation (sign-in is disabled on its enterprise application). Turn it on to read them." } }
        return @{ status = 'present'; reason = '' }
    }
    catch { return @{ status = 'unknown'; reason = "Could not read whether $name is in this organisation: $($_.Exception.Message)" } }
}

function Get-PostureServicesSkipReason {
    <#
    .SYNOPSIS
        Why a run is not collecting Azure or Teams, in words, from what the sign-in service answered when the token
        was asked for. An organisation that approved the second app without that API gets the link for it alone.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [ValidateSet('Azure', 'Teams')] [string] $Collector,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Message,
        [string] $TenantId
    )

    $ErrorActionPreference = 'Stop'
    $said = ($Message -replace '\s*[\r\n]+\s*', ' ').Trim()
    # AADSTS65001: no consent. AADSTS650057 and AADSTS70011: the permission is not one this app holds in the tenant
    # (verify the last two on a live run; the wording is from Microsoft's error list).
    if ($said -match 'AADSTS65001|AADSTS650057|AADSTS70011|consent') {
        $link = $(try { Get-PostureConsentLink -App services -TenantId $TenantId -Resource $Collector.ToLowerInvariant() } catch { '' })
        if ($link) { return "$Collector not read: this organisation has not approved the $Collector read. An administrator approves it once, here: $link" }
    }
    return "$Collector sign-in failed: $said"
}

function Connect-PostureServicesSession {
    <#
    .SYNOPSIS
        The second sign-in, to TenantKeep Posture for Azure, Teams and Power Platform, as the account and tenant of
        the session already open. Holds its refresh token beside the main one, in memory only; Get-PostureToken uses
        it for azure, teams and powerplatform.
    .DESCRIPTION
        The browser step asks only to sign the administrator in, as the main sign-in does. A token for each of the
        three APIs is asked for when a collector needs it, so an API the organisation did not approve fails alone,
        with its reason, and the others are read.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Sign-in confirmation is for the console.')]
    param(
        [string] $ClientId,
        [switch] $DeviceCode,
        [switch] $NoBrowser,
        [int] $TimeoutSeconds = 300
    )

    $ErrorActionPreference = 'Stop'
    $session = $script:PostureSession
    if (-not $session -or -not $session['refreshToken']) { throw 'Sign in first (Connect-PostureSession), then add Azure, Teams and Power Platform with Connect-PostureSession -Services.' }
    $manifest = Get-PostureAppManifest -Name services
    $name = [string]$manifest['displayName']
    $clientId = $(if ($ClientId) { $ClientId } else { [string]$manifest['clientId'] })
    if (-not $clientId) { throw "This build carries no app id for $name yet. Pass -ClientId for a registration of your own with the permissions app-services.json lists." }
    $account = [string]$session['account']
    $tenantId = [string]$session['tenantId']
    $link = Get-PostureConsentLink -App services -ClientId $clientId -TenantId $tenantId
    try { $tokens = Invoke-PostureSignIn -ClientId $clientId -Scope 'openid profile offline_access https://graph.microsoft.com/User.Read' -TenantId $tenantId -AppName $name -LoginHint $account -DeviceCode:$DeviceCode -NoBrowser:$NoBrowser -TimeoutSeconds $TimeoutSeconds }
    catch {
        $text = $_.Exception.Message
        if ($text -match 'AADSTS65001|AADSTS90094|AADSTS90008|consent_required|AADSTS650\d\d|AADSTS700016') { throw "This organisation has not approved $name yet. An administrator approves it once, here: $link ($text)" }
        if ($text -match 'AADSTS50105') { throw "$account is not assigned to $name in this organisation. An administrator assigns the account on its enterprise application. ($text)" }
        if ($text -match 'AADSTS7000112') { throw "$name is turned off in this organisation (sign-in is disabled on its enterprise application). ($text)" }
        if ($text -match 'AADSTS5300\d|AADSTS530032') { throw "A Conditional Access policy blocked the sign-in to $name (app id $clientId). The policy says what it wants; nothing was read. ($text)" }
        throw
    }
    $claims = ConvertFrom-PostureJwt -Token ([string]$tokens['access_token'])
    $who = [string]$(foreach ($k in 'upn', 'preferred_username', 'unique_name') { if ($claims.ContainsKey($k) -and $claims[$k]) { $claims[$k]; break } })
    if ([string]$claims['tid'] -ne $tenantId) { throw "The second sign-in went to tenant $($claims['tid']), not the run's tenant $tenantId. Nothing was read." }
    if ($who -and -not [string]::Equals($who, $account, [System.StringComparison]::OrdinalIgnoreCase)) { throw "The second sign-in was as $who, but the run is signed in as $account. Sign in as $account." }
    if (-not $tokens['refresh_token']) { throw "The sign-in to $name returned no refresh token (offline_access missing from the grant?)." }
    $session['services'] = @{ clientId = $clientId; refreshToken = [string]$tokens['refresh_token']; account = $who }
    $null = $script:PostureSessionEnded.Remove('services')
    # The browser's token is a Graph token of this app, which nothing reads with. A token cached for one of the three
    # APIs belongs to an earlier sign-in and is asked for again.
    foreach ($resource in @($manifest['byName'].get_Keys())) { $null = $session['tokens'].Remove($(if ($resource -eq 'graph') { 'graph@services' } else { $resource })) }
    Write-Host "Azure, Teams and Power Platform: signed in as $account through $name." -ForegroundColor Green
    return @{ account = $account; clientId = $clientId }
}
