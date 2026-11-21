# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# Fresh access tokens for the second collection process, so an Exchange collection that runs for hours keeps going
# while the refresh token never leaves this process. A background thread answers on a named pipe that only the
# current user can open (PipeOptions.CurrentUserOnly, on Windows and on Unix), and only to a caller that presents the
# run's one-time secret, which the child receives over standard input with its first tokens. Each answer is one
# access token for one of the resources the child was allowed.

# The running token service, kept so a new sign-in in the main thread can give it the new refresh token.
$script:PostureTokenServer = $null

function Start-PostureTokenServer {
    <#
    .SYNOPSIS
        Starts the token service for the second process. Returns @{ pipe; secret; job } for the child's request and
        for Stop-PostureTokenServer.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string[]] $Resource
    )

    $ErrorActionPreference = 'Stop'
    if (-not $script:PostureSession -or -not $script:PostureSession['refreshToken']) { return $null }
    $pipe = "tenantkeep-$([guid]::NewGuid().ToString('n'))"
    $secret = [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    if (-not $PSCmdlet.ShouldProcess($pipe, 'Serve access tokens to the second process')) { return $null }
    # The thread has its own copy of the session: same process, never written anywhere. The copy is synchronized,
    # because one other thread writes to it: when the sign-in ends and the admin signs in again in the main thread,
    # the new refresh token is put here too (Restore-PostureSignIn). The thread itself never asks anyone anything.
    $copy = [hashtable]::Synchronized(@{}); foreach ($k in $script:PostureSession.Keys) { $copy[$k] = $script:PostureSession[$k] }
    $copy['tokens'] = @{}; foreach ($k in $script:PostureSession['tokens'].Keys) { $copy['tokens'][$k] = $script:PostureSession['tokens'][$k].Clone() }
    $copy['serviceThread'] = $true; $copy['interactive'] = $false
    $psd1 = Join-Path $script:ModuleRoot 'TenantKeep.Posture.psd1'
    $job = Start-ThreadJob -Name $pipe -ScriptBlock {
        Import-Module $using:psd1 -Force
        & (Get-Module TenantKeep.Posture) Invoke-PostureTokenService -Session $using:copy -Pipe $using:pipe -Secret $using:secret -Resource $using:Resource
    }
    $script:PostureTokenServer = @{ pipe = $pipe; secret = $secret; job = $job; session = $copy }
    return $script:PostureTokenServer
}

function Invoke-PostureTokenService {
    <#
    .SYNOPSIS
        The token service's loop, in its thread: one request per connection, "<secret> <resource>" in, one JSON line
        out; "<secret> stop" ends it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Session,
        [Parameter(Mandatory)] [string] $Pipe,
        [Parameter(Mandatory)] [string] $Secret,
        [Parameter(Mandatory)] [string[]] $Resource
    )

    $ErrorActionPreference = 'Stop'
    $script:PostureSession = $Session
    while ($true) {
        $server = [System.IO.Pipes.NamedPipeServerStream]::new($Pipe, [System.IO.Pipes.PipeDirection]::InOut, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::CurrentUserOnly)
        try {
            $server.WaitForConnection()
            $reader = [System.IO.StreamReader]::new($server); $writer = [System.IO.StreamWriter]::new($server); $writer.AutoFlush = $true
            $line = [string]$reader.ReadLine()
            $given, $what = $line -split ' ', 2
            # Constant-time comparison of the secret.
            $ok = [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals([System.Text.Encoding]::UTF8.GetBytes([string]$given), [System.Text.Encoding]::UTF8.GetBytes($Secret))
            if (-not $ok) { $writer.WriteLine('{"error":"refused"}'); continue }
            if ($what -eq 'stop') { $writer.WriteLine('{"stopped":true}'); return }
            if ($what -notin $Resource) { $writer.WriteLine('{"error":"not a resource this process may ask for"}'); continue }
            try {
                $token = Get-PostureToken -Resource $what
                $writer.WriteLine((@{ accessToken = $token; expiresUtc = $script:PostureSession['tokens'][$what]['expiresUtc'].ToString('o') } | ConvertTo-Json -Compress))
            }
            catch { $writer.WriteLine((@{ error = [string]$_.Exception.Message } | ConvertTo-Json -Compress)) }
        }
        finally { $server.Dispose() }
    }
}

function Stop-PostureTokenServer {
    <#
    .SYNOPSIS
        Ends the token service once the second process has finished.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([hashtable] $Server)

    if (-not $Server) { return }
    if (-not $PSCmdlet.ShouldProcess($Server.pipe, 'Stop the token service')) { return }
    if ($script:PostureTokenServer -and $script:PostureTokenServer['pipe'] -eq $Server.pipe) { $script:PostureTokenServer = $null }
    try { $null = Request-PosturePipeMessage -Pipe $Server.pipe -Message "$($Server.secret) stop" -TimeoutMs 3000 } catch { Write-Verbose "Token service already stopped: $($_.Exception.Message)" }
    try { $null = Wait-Job -Job $Server.job -Timeout 5; Remove-Job -Job $Server.job -Force } catch { Write-Verbose 'Token service job already gone.' }
}

function Request-PosturePipeMessage {
    <#
    .SYNOPSIS
        Sends one line to the token service and returns its JSON answer as a hashtable.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Pipe,
        [Parameter(Mandatory)] [string] $Message,
        [int] $TimeoutMs = 30000
    )

    $ErrorActionPreference = 'Stop'
    $client = [System.IO.Pipes.NamedPipeClientStream]::new('.', $Pipe, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::CurrentUserOnly)
    try {
        $client.Connect($TimeoutMs)
        $writer = [System.IO.StreamWriter]::new($client); $writer.AutoFlush = $true
        $reader = [System.IO.StreamReader]::new($client)
        $writer.WriteLine($Message)
        $answer = $reader.ReadLine()
        return ($answer | ConvertFrom-Json -AsHashtable)
    }
    finally { $client.Dispose() }
}

function Request-PostureParentToken {
    <#
    .SYNOPSIS
        In the second process: a fresh access token for a resource from the main process's token service.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Resource)

    $ErrorActionPreference = 'Stop'
    $session = $script:PostureSession
    $answer = Request-PosturePipeMessage -Pipe ([string]$session['tokenPipe']) -Message "$([string]$session['tokenSecret']) $Resource"
    if ($answer.ContainsKey('error')) { throw "The main process could not renew the $Resource token: $($answer['error'])" }
    return @{ accessToken = [string]$answer['accessToken']; expiresUtc = (ConvertTo-PostureUtcDateTime $answer['expiresUtc']); scope = '' }
}
