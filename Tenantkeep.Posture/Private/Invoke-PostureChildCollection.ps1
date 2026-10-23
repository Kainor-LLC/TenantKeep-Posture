# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Start-PostureChildCollection {
    <#
    .SYNOPSIS
        Runs the Exchange and Purview collectors in a fresh PowerShell process, handing it tokens over standard input.
    .DESCRIPTION
        ExchangeOnlineManagement and PnP.PowerShell do not share a process well on macOS (docs/collection.md), so
        Start-PostureRun gives Exchange and Purview their own process. The child gets access tokens only (never the
        refresh token), as one JSON document on standard input: not an argument, not an environment variable, not a
        file. Its console output is the parent's console. The exit code says whether every named collector ran.
    .PARAMETER Request
        tokens (graph, exchange, purview), account, tenantId, tenantName, folder, profilePath, collectors.
    .PARAMETER Command
        The command the child runs. Default: import this module and run Invoke-PostureChildCollection in it.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)] [hashtable] $Request,
        [string] $Command
    )

    $ErrorActionPreference = 'Stop'
    $psd1 = Join-Path $script:ModuleRoot 'Tenantkeep.Posture.psd1'
    if (-not $Command) { $Command = "Import-Module '$($psd1 -replace "'", "''")' -ErrorAction Stop; & (Get-Module Tenantkeep.Posture) { Invoke-PostureChildCollection }" }
    $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if (-not $PSCmdlet.ShouldProcess($exe, "Start a collection process for $($Request['collectors'] -join ', ')")) { return 0 }
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $exe
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    foreach ($a in '-NoProfile', '-NonInteractive', '-Command', $Command) { $psi.ArgumentList.Add($a) }
    $process = [System.Diagnostics.Process]::Start($psi)
    try {
        $process.StandardInput.Write(($Request | ConvertTo-Json -Depth 10 -Compress))
        $process.StandardInput.Close()
        $process.WaitForExit()
        return $process.ExitCode
    }
    finally { $process.Dispose() }
}

function Invoke-PostureChildCollection {
    <#
    .SYNOPSIS
        The child side: reads the request from standard input, opens the sessions with the tokens, collects.
    .DESCRIPTION
        Sets up the module's session with the given access tokens and no refresh token, so a token that expires
        mid-way is a clear error rather than a silent re-acquire. Each collector is its own try; the process exits
        non-zero when any named collector failed, after running the others.
    .PARAMETER InputJson
        The request as JSON. Default: everything on standard input.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Progress lines for the console the parent shares.')]
    param([string] $InputJson)

    $ErrorActionPreference = 'Stop'
    if (-not $InputJson) { $InputJson = [Console]::In.ReadToEnd() }
    $request = $InputJson | ConvertFrom-Json -AsHashtable -Depth 10
    $tokens = @{}
    $now = [datetime]::UtcNow
    foreach ($name in @($request['tokens'].Keys)) {
        $t = $request['tokens'][$name]
        $tokens[$name] = @{ accessToken = [string]$t['accessToken']; expiresUtc = (ConvertTo-PostureUtcDateTime -Value $t['expiresUtc']); scope = '' }
        if ($tokens[$name]['expiresUtc'] -le $now) { throw "The $name token handed to this process has already expired." }
    }
    $script:PostureSession = @{
        clientId = [string]$request['clientId']; tenantId = [string]$request['tenantId']; tenantName = [string]$request['tenantName']
        account = [string]$request['account']; refreshToken = ''; signedInUtc = $now; tokens = $tokens
    }
    Connect-PostureService -Name graph
    $failed = 0
    $profileParam = @{}
    if ($request['profilePath'] -and (Test-Path -LiteralPath $request['profilePath'])) { $profileParam.ProfilePath = [string]$request['profilePath'] }
    foreach ($collector in @($request['collectors'])) {
        $service = $collector.ToLowerInvariant()
        try {
            Connect-PostureService -Name $service
            Invoke-PostureCollection -Collector $collector -SkipCaSnapshot -OutputFolder $request['folder'] @profileParam | Out-Null
            Write-Host "$collector collected"
        }
        catch {
            $failed++
            Write-Host "$collector failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    return $failed
}
