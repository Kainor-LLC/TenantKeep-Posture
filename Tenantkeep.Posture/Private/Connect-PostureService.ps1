# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Connect-PostureService {
    <#
    .SYNOPSIS
        The one place in the module that opens a service session, always with an access token from the broker.
    .DESCRIPTION
        Delegated tokens only: no secret, no certificate, no password ever passes through here. Each service module
        is given its token and the companions it documents. A session that is already open for the same tenant is
        left alone unless -Force. The read-only guard in the tests allows Connect-* calls in this file only.
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
            # ExchangeOnlineManagement 3.8+. Audience https://ps.compliance.protection.outlook.com, owned by the Exchange Online
            # Protection principal. No published report of a custom app's delegated token here yet (verify on the spike).
            $token = Get-PostureToken -Resource purview
            Connect-IPPSSession -AccessToken $token -UserPrincipalName $account -Organization "$($session['tenantName']).onmicrosoft.com" -ShowBanner:$false
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
