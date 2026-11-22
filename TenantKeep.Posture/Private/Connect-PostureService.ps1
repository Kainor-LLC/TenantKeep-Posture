# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# The services the broker connected with a token of its own, which Update-PostureServiceSession renews.
$script:PostureConnected = @{}
# Start-PostureRun -TeamsAppSignIn asks for the Teams module's own sign-in; set once it has been made in this run.
$script:PostureTeamsAppSignIn = $false
$script:PostureTeamsOwnSession = $false

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
            # Since 2026-11-20 Exchange signs in like Purview, through the Exchange module's own first-party app, so the
            # TenantKeep Posture app asks for no Exchange permission: the only delegated one, Exchange.Manage, reads
            # "Manage Exchange configuration" on the consent screen. Same admin, delegated, bounded by that admin's roles;
            # the module renews its own tokens through a long run, and Purview has usually signed the same admin in
            # through the same module just before, so there is no second prompt (verify on the first live run).
            $exo = @{ UserPrincipalName = $account; ShowBanner = $false }
            if ($session.ContainsKey('purviewSignIn') -and [string]$session['purviewSignIn'] -eq 'device') { $exo['Device'] = $true }
            Connect-ExchangeOnline @exo
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
            # -Scope Process: the context and its token live in this process only, never in the saved Az context, so a run
            # neither stores the token nor replaces the admin's own default context.
            Connect-AzAccount -AccessToken $token -AccountId $account -Tenant $tenantId -SkipContextPopulation -Scope Process | Out-Null
        }
    }
    # Exchange and Purview sign in through the Exchange module, which renews its own tokens.
    if ($Name -notin 'purview', 'exchange') { $script:PostureConnected[$Name] = $true }
    Write-Verbose "$Name session opened for $account in $tenantId."
}

function Connect-PostureTeamsOwnSession {
    <#
    .SYNOPSIS
        Signs the Teams module in through Microsoft's own Teams app, by device code, for the two reads the one
        sign-in cannot make (Get-M365UnifiedTenantSettings and Get-AllM365TeamsApps).
    .DESCRIPTION
        Those two cmdlets ask the Teams module for a token to a Microsoft 365 service (substrate.office.com) that a
        session opened with access tokens does not carry, and that no permission on the TenantKeep Posture app
        provides. The module's own sign-in can get it. Still delegated, still bounded by the admin's own roles,
        nothing stored by this module. Asked for with Start-PostureRun -TeamsAppSignIn, never otherwise: it is a
        second sign-in, and it comes when the run reaches Teams, near its end. The session must be the run's tenant
        and, when the module says who signed in, the run's account; any other is closed again and refused.
    #>
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'A sign-in prompt is for the person at the console.')]
    param()

    $ErrorActionPreference = 'Stop'
    $session = $script:PostureSession
    if (-not $session) { throw 'There is no sign-in to match the Teams sign-in to.' }
    Write-Host ''
    Write-Host "Teams asks for a sign-in of its own, to read the app settings. Sign in as $([string]$session['account']); the address and the code follow." -ForegroundColor Cyan
    try { $null = Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue } catch { Write-Verbose 'No Teams session to close first.' }
    $result = Connect-MicrosoftTeams -TenantId ([string]$session['tenantId']) -UseDeviceAuthentication
    $tenant = [string]$(if ($result -and $result.PSObject.Properties['TenantId']) { $result.TenantId })
    $account = [string]$(if ($result -and $result.PSObject.Properties['Account']) { $result.Account })
    $wrongTenant = $tenant -and $tenant -ne [string]$session['tenantId']
    $wrongAccount = $account -match '@' -and $account -ne [string]$session['account']
    if ($wrongTenant -or $wrongAccount) {
        try { $null = Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue } catch { Write-Verbose 'The mismatched Teams session did not close cleanly.' }
        throw "The Teams sign-in was $(if ($wrongAccount) { $account } else { "to tenant $tenant" }), not the run's ($([string]$session['account']) in $([string]$session['tenantId'])). It was closed and nothing was read with it."
    }
    $script:PostureTeamsOwnSession = $true
}

function Update-PostureServiceSession {
    <#
    .SYNOPSIS
        Before a call to a service the broker connected: when its access token has under ten minutes left, renew it
        and connect again, so a collection that runs for hours does not fail on an expired token. PnP, Teams and
        Azure cannot renew a token they were handed; Graph renews on a 401 in its wrapper; Exchange and Purview sign
        in through the Exchange module, which renews its own.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)] [ValidateSet('sharepoint', 'teams', 'azure')] [string] $Name)

    $ErrorActionPreference = 'Stop'
    $session = $script:PostureSession
    if (-not $session -or -not $script:PostureConnected.ContainsKey($Name)) { return }
    # A Teams session the module opened by itself renews by itself; connecting again with tokens would replace it.
    if ($Name -eq 'teams' -and $script:PostureTeamsOwnSession) { return }
    if (-not ($session['refreshToken'] -or ($session.ContainsKey('tokenPipe') -and $session['tokenPipe']))) { return }
    $resources = $(if ($Name -eq 'teams') { @('graph', 'teams') } else { @($Name) })
    $soon = [datetime]::UtcNow.AddMinutes(10)
    $stale = @($resources | Where-Object { -not $session['tokens'].ContainsKey($_) -or $session['tokens'][$_]['expiresUtc'] -le $soon })
    if ($stale.Count -eq 0) { return }
    if (-not $PSCmdlet.ShouldProcess($Name, 'Renew the token and connect again')) { return }
    foreach ($r in $stale) { $null = Get-PostureToken -Resource $r -Force }
    Write-Verbose "$Name token near expiry; connecting again with a fresh one."
    Connect-PostureService -Name $Name
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
