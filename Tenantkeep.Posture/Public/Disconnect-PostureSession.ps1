# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Disconnect-PostureSession {
    <#
    .SYNOPSIS
        Forgets the session Connect-PostureSession opened: refresh token and every cached access token.
    .DESCRIPTION
        The tokens were only ever in this process's memory; this clears them and closes the Graph session. The other
        service modules keep their own sessions until they are disconnected or the process ends.
    .EXAMPLE
        Disconnect-PostureSession
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    if ($script:PostureSession) {
        $script:PostureSession['refreshToken'] = ''
        $script:PostureSession['tokens'] = @{}
    }
    $script:PostureSession = $null
    Disconnect-PostureService
}
