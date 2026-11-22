# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# The services the broker connected with a token of its own, which Update-PostureServiceSession renews.
$script:PostureConnected = @{}
# Start-PostureRun -TeamsAppSignIn asks for the Teams module's own sign-in; set once it has been made in this run.
$script:PostureTeamsAppSignIn = $false
$script:PostureTeamsOwnSession = $false
# What that sign-in was refused with, so the second read of a run gets the same answer and no second prompt.
$script:PostureTeamsOwnSessionRefused = $null

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

function Test-PostureTeamsBrowserSignIn {
    <#
    .SYNOPSIS
        Whether the Teams module can sign in through a browser here. On Windows it can. Elsewhere its browser
        sign-in fails loading a Windows library (docs/collection.md), which leaves the device code.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    [bool]$IsWindows
}

function Connect-PostureTeamsOwnSession {
    <#
    .SYNOPSIS
        Signs the Teams module in through Microsoft's own Teams app, for the two reads the one sign-in cannot make
        (Get-M365UnifiedTenantSettings and Get-AllM365TeamsApps): in the browser on Windows, by device code elsewhere.
    .DESCRIPTION
        Those two cmdlets ask the Teams module for a token to a Microsoft 365 service (substrate.office.com) that a
        session opened with access tokens does not carry, and that no permission on the TenantKeep Posture app
        provides. The module's own sign-in can get it. Still delegated, still bounded by the admin's own roles,
        nothing stored by this module. Asked for with Start-PostureRun -TeamsAppSignIn, never otherwise: it is a
        second sign-in, and it comes when the run reaches Teams, near its end. The session must be the run's tenant
        and, when the module says who signed in, the run's account; any other is closed again and refused.

        A tenant's Conditional Access can refuse the sign-in, most often by blocking device code sign-in, which is
        the only kind the Teams module can make outside Windows (seen live 2026-11-22: AADSTS53003 on macOS). That
        is the tenant's policy working, so it is said as a read this sign-in cannot make, with nothing to change in
        the run. A refusal is remembered for the rest of the run: the second read gets the same answer instead of a
        second prompt. Whatever went wrong, the session the run had is put back.
    #>
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'A sign-in prompt is for the person at the console.')]
    param()

    $ErrorActionPreference = 'Stop'
    $session = $script:PostureSession
    if (-not $session) { throw 'There is no sign-in to match the Teams sign-in to.' }
    if ($script:PostureTeamsOwnSessionRefused) { throw $script:PostureTeamsOwnSessionRefused }
    $tenantId = [string]$session['tenantId']; $runAccount = [string]$session['account']
    $browser = Test-PostureTeamsBrowserSignIn
    Write-Host ''
    Write-Host "Teams asks for a sign-in of its own, to read the app settings. Sign in as $runAccount$(if ($browser) { ' in the browser window that opens.' } else { '; the address and the code follow.' })" -ForegroundColor Cyan
    try { $null = Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue } catch { Write-Verbose 'No Teams session to close first.' }
    $refused = $null; $remember = $false; $result = $null
    try {
        if ($browser) { $result = Connect-MicrosoftTeams -TenantId $tenantId -AccountId $runAccount }
        else { $result = Connect-MicrosoftTeams -TenantId $tenantId -UseDeviceAuthentication }
    }
    catch {
        $said = ([string]$_.Exception.Message -replace '\s*[\r\n]+\s*', ' ').Trim()
        $remember = $true
        if ($said -match '(?i)AADSTS53\d{3,4}|conditional access') {
            $refused = "Not readable with this sign-in: Conditional Access in this tenant refused the Teams module's own sign-in$(if (-not $browser) { ', which outside Windows can only be made with a device code' }). That is the tenant's policy working, and nothing in the run changes it.$(if (-not $browser) { ' On Windows the Teams module signs in through the browser instead, so these two reads can be collected there with -TeamsAppSignIn.' })"
        }
        elseif ($browser) { $refused = "The Teams sign-in for the app settings was not completed: $said Run again with -TeamsAppSignIn and finish the sign-in in the browser." }
        else { $refused = "The Teams sign-in for the app settings was not completed: $said If the code ran out, run again with -TeamsAppSignIn and enter it. If the browser said the sign-in does not meet the tenant's criteria, Conditional Access blocks device code sign-in in this tenant and running again will say the same: these two reads can be collected on Windows, where the Teams module signs in through the browser." }
    }
    if (-not $refused) {
        $tenant = [string]$(if ($result -and $result.PSObject.Properties['TenantId']) { $result.TenantId })
        $account = [string]$(if ($result -and $result.PSObject.Properties['Account']) { $result.Account })
        $wrongTenant = $tenant -and $tenant -ne $tenantId
        $wrongAccount = $account -match '@' -and $account -ne $runAccount
        if ($wrongTenant -or $wrongAccount) {
            try { $null = Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue } catch { Write-Verbose 'The mismatched Teams session did not close cleanly.' }
            # Not remembered: picking the right account at the next prompt fixes it.
            $refused = "The Teams sign-in was $(if ($wrongAccount) { $account } else { "to tenant $tenant" }), not the run's ($runAccount in $tenantId). It was closed and nothing was read with it."
        }
    }
    if ($refused) {
        # The run's own Teams session was closed to make room for this one; put it back.
        try { Connect-PostureService -Name teams } catch { Write-Verbose "The run's Teams session was not restored: $($_.Exception.Message)" }
        if ($remember) { $script:PostureTeamsOwnSessionRefused = $refused }
        throw $refused
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
