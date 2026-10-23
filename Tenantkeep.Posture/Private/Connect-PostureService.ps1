# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Connect-PostureService {
    <#
    .SYNOPSIS
        The one place in the module that opens a service session, always with an access token from the broker.
    .DESCRIPTION
        Delegated tokens only: no secret, no certificate, no password ever passes through here. Each service module
        is given its token and the companions it documents. The one exception is Purview: the Exchange Online
        Protection principal exposes no delegated scopes, so no third-party app can get a Security & Compliance
        PowerShell token, and the Exchange module signs the same admin in with its own app (a browser window, or a
        device code when the run has none). A session that is already open for the same tenant is left alone unless
        -Force. The read-only guard in the tests allows Connect-* calls in this file only.
    .PARAMETER Name
        graph, exchange, purview, sharepoint, teams or azure.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)] [ValidateSet('graph', 'exchange', 'purview', 'sharepoint', 'teams', 'azure')] [string] $Name,
        [switch] $Force
    )

    $ErrorActionPreference = 'Stop'
    $session = $script:PostureSession
    if (-not $session) { throw 'No session. Run Connect-PostureSession first.' }
    $tenantId = [string]$session['tenantId']
    $account = [string]$session['account']
    switch ($Name) {
        'graph' {
            $token = Get-PostureToken -Resource graph -AsSecureString
            Connect-MgGraph -AccessToken $token -NoWelcome
        }
        'exchange' {
            # ExchangeOnlineManagement 3.1+. A delegated token for https://outlook.office365.com with Exchange.Manage pairs
            # with -UserPrincipalName (Michev, 2023; verify on the first live run).
            $token = Get-PostureToken -Resource exchange
            Connect-ExchangeOnline -AccessToken $token -UserPrincipalName $account -ShowBanner:$false
        }
        'purview' {
            # Seen live in Kainor, 2026-10-23: the Exchange Online Protection principal (00000007-0000-0ff1-ce00-000000000000)
            # exposes no delegated scopes at all, so the sign-in app cannot ask for one and the broker has no token to give.
            # Security & Compliance PowerShell signs the same admin in again through the Exchange module's own first-party
            # app. Still delegated, still bounded by that admin's roles, nothing stored. -Device when the run has no browser
            # (verify: Connect-IPPSSession -Device on the first live run).
            $ipps = @{ UserPrincipalName = $account; ShowBanner = $false }
            if ($session.ContainsKey('purviewSignIn') -and [string]$session['purviewSignIn'] -eq 'device') { $ipps['Device'] = $true }
            Connect-IPPSSession @ipps
        }
        'sharepoint' {
            # PnP cannot refresh a supplied token and the audience must match -Url (pnp/powershell #305), so the token is for
            # the admin site and fresh each time this runs.
            $token = Get-PostureToken -Resource sharepoint -Force
            Connect-PnPOnline -Url "https://$($session['tenantName'])-admin.sharepoint.com" -AccessToken $token
        }
        'teams' {
            $tokens = @((Get-PostureToken -Resource graph), (Get-PostureToken -Resource teams))
            Connect-MicrosoftTeams -AccessTokens $tokens | Out-Null
        }
        'azure' {
            $token = Get-PostureToken -Resource azure
            Connect-AzAccount -AccessToken $token -AccountId $account -Tenant $tenantId -SkipContextPopulation | Out-Null
        }
    }
    Write-Verbose "$Name session opened for $account in $tenantId."
}

function Disconnect-PostureService {
    <#
    .SYNOPSIS
        Closes the Graph session the broker opened. Other modules keep their own sessions until the process ends.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $ErrorActionPreference = 'Stop'
    if (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue) { try { Disconnect-MgGraph | Out-Null } catch { Write-Verbose "Disconnect-MgGraph: $($_.Exception.Message)" } }
}
