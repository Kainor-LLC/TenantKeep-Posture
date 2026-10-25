# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Assert-PostureGraphScope {
    <#
    .SYNOPSIS
        Throws unless there is a Graph session that carries every required scope.
    .DESCRIPTION
        Cmdlets never connect on their own (CLAUDE.md). This check runs before any Graph call so a half-scoped session
        fails up front instead of partway through a run. App-only sessions expose role names in the same Scopes list.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string[]] $RequiredScope = @(),
        [string[]] $AnyOfScope = @()
    )

    $ErrorActionPreference = 'Stop'

    $context = Get-MgContext
    if (-not $context) {
        throw "No Microsoft Graph session. Run: Connect-MgGraph -Scopes $(@(@($RequiredScope) + @($AnyOfScope)) -join ', ') -NoWelcome"
    }

    $granted = @($context.Scopes)
    $tenantId = [string]$context.TenantId
    $account = [string]$context.Account
    # After Connect-MgGraph -AccessToken the context may carry no scopes, tenant or account (verify per SDK version); the
    # broker's own Graph token says what was granted.
    if ($script:PostureSession -and $script:PostureSession['tokens'].ContainsKey('graph')) {
        $claims = ConvertFrom-PostureJwt -Token ([string]$script:PostureSession['tokens']['graph']['accessToken'])
        if ($granted.Count -eq 0 -and $claims.ContainsKey('scp')) { $granted = @(([string]$claims['scp']) -split ' ' | Where-Object { $_ }) }
        if (-not $tenantId) { $tenantId = [string]$claims['tid'] }
        if (-not $account) { $account = [string]$script:PostureSession['account'] }
    }
    $missing = @($RequiredScope | Where-Object { $_ -notin $granted })
    if ($missing.Count -gt 0) {
        throw "Graph session is missing scope(s): $($missing -join ', '). Reconnect with: Connect-MgGraph -Scopes $($RequiredScope -join ', ') -NoWelcome"
    }
    if ($AnyOfScope.Count -gt 0 -and @($AnyOfScope | Where-Object { $_ -in $granted }).Count -eq 0) {
        throw "Graph session needs one of: $($AnyOfScope -join ', '). Reconnect with: Connect-MgGraph -Scopes $($AnyOfScope[0]) -NoWelcome"
    }

    return @{
        TenantId = $tenantId
        Account  = $account
        AuthType = [string]$context.AuthType
        Scopes   = $granted
    }
}
