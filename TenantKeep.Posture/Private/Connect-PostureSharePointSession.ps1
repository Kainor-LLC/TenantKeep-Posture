# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureSharePointClientId {
    <#
    .SYNOPSIS
        The app the SharePoint admin read signs in to: the customer's own registration when the profile names one
        (sharePointClientId, from deploy/setup/New-PostureSharePointApp.ps1), otherwise TenantKeep Posture for
        SharePoint from app-sharepoint.json. Empty when neither exists.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([System.Collections.IDictionary] $OrgProfile)

    $ErrorActionPreference = 'Stop'
    if ($OrgProfile -and $OrgProfile.Contains('sharePointClientId') -and [string]$OrgProfile['sharePointClientId']) { return [string]$OrgProfile['sharePointClientId'] }
    return [string](Get-PostureAppManifest -Name sharepoint)['clientId']
}

function Test-PostureSharePointAccess {
    <#
    .SYNOPSIS
        Whether the signed-in admin can use the SharePoint app in this tenant, read through Graph before any second
        sign-in: the app is in the tenant, turned on, and holds a SharePoint grant for this admin or for everyone.
    .DESCRIPTION
        Reads the service principal and its delegated permission grants (Directory.Read.All). A tenant that never set
        the app up gets no second browser window, only a note in run health. When the grants cannot be read the answer
        is unknown and the caller may try the sign-in.
    .OUTPUTS
        @{ status = 'granted' | 'absent' | 'disabled' | 'notGranted' | 'unknown'; reason = <text> }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $ClientId)

    $ErrorActionPreference = 'Stop'
    $how = 'A Global Administrator grants it to named admins with deploy/setup/Grant-PostureSharePointAccess.ps1; or run collectors/windows/Get-SpoBaseline.ps1 and bring its files in with Import-PostureEvidence. Until then the SharePoint checks use what Graph returns.'
    $first = { param([string] $Uri) $r = Invoke-PostureGraphRequest -ApiVersion v1.0 -Uri $Uri -Single; @($(if ($r -is [System.Collections.IDictionary] -and $r.Contains('value')) { $r['value'] } else { $r }) | Where-Object { $_ }) }
    try {
        $sp = @(& $first "servicePrincipals?`$filter=appId eq '$ClientId'&`$select=id,accountEnabled,appRoleAssignmentRequired")
        if ($sp.Count -eq 0) { return @{ status = 'absent'; reason = "The SharePoint app ($ClientId) is not set up in this tenant. $how" } }
        if ($sp[0]['accountEnabled'] -eq $false) { return @{ status = 'disabled'; reason = "The SharePoint app is turned off in this tenant (sign-in disabled between runs). Turn it on for the run: deploy/setup/Grant-PostureSharePointAccess.ps1 -Enable." } }
        $spo = @(& $first "servicePrincipals?`$filter=appId eq '00000003-0000-0ff1-ce00-000000000000'&`$select=id")
        $me = Invoke-PostureGraphRequest -ApiVersion v1.0 -Uri 'me?$select=id' -Single
        $grants = @(& $first "oauth2PermissionGrants?`$filter=clientId eq '$($sp[0]['id'])'")
        $mine = @($grants | Where-Object {
                ($spo.Count -eq 0 -or [string]$_['resourceId'] -eq [string]$spo[0]['id']) -and [string]$_['scope'] -match '\bAllSites\.FullControl\b' -and
                ([string]$_['consentType'] -eq 'AllPrincipals' -or [string]$_['principalId'] -eq [string]$me['id'])
            })
        if ($mine.Count -eq 0) { return @{ status = 'notGranted'; reason = "The SharePoint app is in this tenant but not granted to the account signed in. $how" } }
        return @{ status = 'granted'; reason = '' }
    }
    catch { return @{ status = 'unknown'; reason = "Could not read the SharePoint app's grants: $($_.Exception.Message)" } }
}

function Connect-PostureSharePointSession {
    <#
    .SYNOPSIS
        The second sign-in, to the SharePoint app, as the account and tenant of the session already open. Holds its
        refresh token beside the main one, in memory only; Get-PostureToken -Resource sharepoint uses it.
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
    if (-not $session -or -not $session['refreshToken']) { throw 'Sign in first (Connect-PostureSession), then add SharePoint with Connect-PostureSession -SharePoint.' }
    if (-not $session['tenantName']) { throw 'The session has no tenant name, which the SharePoint admin address needs.' }
    $clientId = $(if ($ClientId) { $ClientId } else { [string](Get-PostureAppManifest -Name sharepoint)['clientId'] })
    if (-not $clientId) { throw 'This build carries no app id for TenantKeep Posture for SharePoint. Pass -ClientId for a registration of your own (deploy/setup/New-PostureSharePointApp.ps1).' }
    $account = [string]$session['account']
    $scope = "openid profile offline_access $(Get-PostureResourceScope -Resource sharepoint -TenantName $session['tenantName'])"
    $grant = "A Global Administrator grants it with deploy/setup/Grant-PostureSharePointAccess.ps1 -Admin $account."
    try { $tokens = Invoke-PostureSignIn -ClientId $clientId -Scope $scope -TenantId ([string]$session['tenantId']) -AppName 'TenantKeep Posture for SharePoint' -LoginHint $account -DeviceCode:$DeviceCode -NoBrowser:$NoBrowser -TimeoutSeconds $TimeoutSeconds }
    catch {
        $text = $_.Exception.Message
        if ($text -match 'AADSTS50105') { throw "$account is not assigned to TenantKeep Posture for SharePoint in this tenant. $grant ($text)" }
        if ($text -match 'AADSTS65001|AADSTS90094|AADSTS90008|consent_required|AADSTS650') { throw "TenantKeep Posture for SharePoint is not granted to $account in this tenant. $grant ($text)" }
        if ($text -match 'AADSTS7000112') { throw "TenantKeep Posture for SharePoint is turned off in this tenant. Turn it on for the run with deploy/setup/Grant-PostureSharePointAccess.ps1 -Enable. ($text)" }
        if ($text -match 'AADSTS700016') { throw "TenantKeep Posture for SharePoint is not set up in this tenant. $grant ($text)" }
        if ($text -match 'AADSTS5300\d|AADSTS530032') { throw "A Conditional Access policy blocked the sign-in to TenantKeep Posture for SharePoint (app id $clientId). ($text)" }
        throw
    }
    $claims = ConvertFrom-PostureJwt -Token ([string]$tokens['access_token'])
    $who = [string]$(foreach ($k in 'upn', 'preferred_username', 'unique_name') { if ($claims.ContainsKey($k) -and $claims[$k]) { $claims[$k]; break } })
    if ([string]$claims['tid'] -ne [string]$session['tenantId']) { throw "The SharePoint sign-in went to tenant $($claims['tid']), not the run's tenant $($session['tenantId']). Nothing was read." }
    if ($who -and -not [string]::Equals($who, $account, [System.StringComparison]::OrdinalIgnoreCase)) { throw "The SharePoint sign-in was as $who, but the run is signed in as $account. Sign in as $account." }
    if (-not $tokens['refresh_token']) { throw 'The SharePoint sign-in returned no refresh token (offline_access missing from the grant?).' }
    $now = [datetime]::UtcNow
    $session['sharepoint'] = @{ clientId = $clientId; refreshToken = [string]$tokens['refresh_token']; account = $who }
    $null = $script:PostureSessionEnded.Remove('sharepoint')
    $session['tokens']['sharepoint'] = @{ accessToken = [string]$tokens['access_token']; expiresUtc = $now.AddSeconds([int]$tokens['expires_in']); scope = [string]$(if ($tokens.ContainsKey('scope')) { $tokens['scope'] }) }
    Write-Host "SharePoint admin read signed in as $account through TenantKeep Posture for SharePoint." -ForegroundColor Green
    return @{ account = $account; clientId = $clientId; expiresUtc = $session['tokens']['sharepoint']['expiresUtc'] }
}
