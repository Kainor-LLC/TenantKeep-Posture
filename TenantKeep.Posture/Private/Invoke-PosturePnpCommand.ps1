# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Test-PosturePnpSession {
    <#
    .SYNOPSIS
        True when a PnP.PowerShell connection to a SharePoint admin site is open. Never connects.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $ErrorActionPreference = 'Stop'
    if (-not (Get-Command -Name Get-PnPConnection -ErrorAction SilentlyContinue)) { return $false }
    $c = $null
    try { $c = Get-PnPConnection -ErrorAction Stop } catch { return $false }
    return [bool]($c -and [string]$c.Url -match '(?i)-admin\.sharepoint\.')
}

function Invoke-PosturePnpCommand {
    <#
    .SYNOPSIS
        The single entry point for PnP.PowerShell cmdlets: Get-PnP* only, by name, so tests can mock one function.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [ValidatePattern('^Get-PnP[A-Za-z0-9]+$')] [string] $Name,
        [hashtable] $Parameters = @{}
    )

    $ErrorActionPreference = 'Stop'
    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) { throw "$Name is not available; import PnP.PowerShell and connect first." }
    return @(& $Name @Parameters)
}

function Test-PostureTeamsSession {
    <#
    .SYNOPSIS
        True when a MicrosoftTeams session is open (Get-CsTenant answers). Never connects.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $ErrorActionPreference = 'Stop'
    if (-not (Get-Command -Name Get-CsTenant -ErrorAction SilentlyContinue)) { return $false }
    try { $null = Get-CsTenant -ErrorAction Stop; return $true } catch { return $false }
}

function Invoke-PostureTeamsCommand {
    <#
    .SYNOPSIS
        The single entry point for MicrosoftTeams cmdlets: Get-Cs* and Get-Team* only, by name.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [ValidatePattern('^Get-(Cs|Team)[A-Za-z0-9]*$')] [string] $Name,
        [hashtable] $Parameters = @{}
    )

    $ErrorActionPreference = 'Stop'
    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) { throw "$Name is not available; import MicrosoftTeams and connect first." }
    return @(& $Name @Parameters)
}
