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
        [Parameter(Mandatory)] [string[]] $RequiredScope
    )

    $ErrorActionPreference = 'Stop'

    $context = Get-MgContext
    if (-not $context) {
        throw "No Microsoft Graph session. Run: Connect-MgGraph -Scopes $($RequiredScope -join ', ') -NoWelcome"
    }

    $granted = @($context.Scopes)
    $missing = @($RequiredScope | Where-Object { $_ -notin $granted })
    if ($missing.Count -gt 0) {
        throw "Graph session is missing scope(s): $($missing -join ', '). Reconnect with: Connect-MgGraph -Scopes $($RequiredScope -join ', ') -NoWelcome"
    }

    return @{
        TenantId = $context.TenantId
        Account  = $context.Account
        AuthType = [string]$context.AuthType
        Scopes   = $granted
    }
}
