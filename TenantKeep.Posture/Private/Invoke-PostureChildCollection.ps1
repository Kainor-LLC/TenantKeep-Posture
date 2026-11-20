# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Start-PostureChildCollection {
    <#
    .SYNOPSIS
        Runs the Exchange and Purview collectors in a fresh PowerShell process, handing it tokens over standard input.
    .DESCRIPTION
        ExchangeOnlineManagement and PnP.PowerShell do not share a process well on macOS (docs/collection.md), so
        Start-PostureRun gives Exchange and Purview their own process. The child gets access tokens only (never the
        refresh token), as one JSON document on standard input: not an argument, not an environment variable, not a
        file. It shares the parent's console, so a Purview device code or sign-in prompt reaches the admin, and is
        otherwise quiet: its progress goes to a file the parent draws. The exit code says whether every named
        collector ran.
    .PARAMETER Request
        tokens (graph), account, tenantId, tenantName, folder, profilePath, collectors, purviewSignIn
        (browser or device), progressFile and estimates (optional).
    .PARAMETER Command
        The command the child runs. Default: import this module and run Invoke-PostureChildCollection in it.
    .PARAMETER NoWait
        Return the running process instead of its exit code (Wait-PostureChildCollection waits for it), so the
        parent collects at the same time.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([int], [System.Diagnostics.Process])]
    param(
        [Parameter(Mandatory)] [hashtable] $Request,
        [string] $Command,
        [switch] $NoWait
    )

    $ErrorActionPreference = 'Stop'
    $psd1 = Join-Path $script:ModuleRoot 'TenantKeep.Posture.psd1'
    # The failed-collector count becomes the exit code; without the exit it would only print (a stray 0 on the first live run).
    if (-not $Command) { $Command = "Import-Module '$($psd1 -replace "'", "''")' -ErrorAction Stop; exit [int](& (Get-Module TenantKeep.Posture) { Invoke-PostureChildCollection })" }
    $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if (-not $PSCmdlet.ShouldProcess($exe, "Start a collection process for $($Request['collectors'] -join ', ')")) { return 0 }
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $exe
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    # Not -NonInteractive: the Purview sign-in in the child opens a browser through the Exchange module (verify live).
    foreach ($a in '-NoProfile', '-Command', $Command) { $psi.ArgumentList.Add($a) }
    $process = [System.Diagnostics.Process]::Start($psi)
    $process.StandardInput.Write(($Request | ConvertTo-Json -Depth 10 -Compress))
    $process.StandardInput.Close()
    if ($NoWait) { return $process }
    return (Wait-PostureChildCollection -Process $process)
}

function Wait-PostureChildCollection {
    <#
    .SYNOPSIS
        Waits for the second process, redrawing the progress display (its bar comes from its progress file), and
        returns its exit code.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)] [System.Diagnostics.Process] $Process)

    $ErrorActionPreference = 'Stop'
    try {
        while (-not $Process.WaitForExit(1000)) { Write-PostureProgress -Force }
        $Process.WaitForExit()
        return $Process.ExitCode
    }
    finally { $Process.Dispose() }
}

function Invoke-PostureChildCollection {
    <#
    .SYNOPSIS
        The child side: reads the request from standard input, opens the sessions with the tokens, collects.
    .DESCRIPTION
        Sets up the module's session with the given access tokens and no refresh token. A token near expiry is
        renewed by asking the main process's token service (tokenPipe and tokenSecret in the request); without one, a
        token that expires mid-way is a clear error. Purview goes first: its sign-in is the one that may
        need the admin, so it comes while they are still at the screen, and the run needs nothing from them after.
        Each collector is its own try; a failure is written to errors.txt and the process exits non-zero after
        running the others.
    .PARAMETER InputJson
        The request as JSON. Default: everything on standard input.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([string] $InputJson)

    $ErrorActionPreference = 'Stop'
    # Quiet on the shared console: step failures are in errors.txt and progress is in the file the parent draws.
    $WarningPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
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
        purviewSignIn = [string]$(if ($request.ContainsKey('purviewSignIn')) { $request['purviewSignIn'] } else { 'browser' })
        # Fresh tokens come from the main process's token service; this process never holds a refresh token.
        tokenPipe = [string]$(if ($request.ContainsKey('tokenPipe')) { $request['tokenPipe'] }); tokenSecret = [string]$(if ($request.ContainsKey('tokenSecret')) { $request['tokenSecret'] })
    }
    $order = @('Purview', 'Exchange' | Where-Object { $_ -in @($request['collectors']) })
    $folder = [string]$request['folder']
    if ($request.ContainsKey('progressFile') -and $request['progressFile']) {
        $estimate = @{}; if ($request.ContainsKey('estimates') -and $request['estimates']) { foreach ($k in @($request['estimates'].Keys)) { $estimate[$k] = $request['estimates'][$k] } }
        Start-PostureProgress -Phase $order -Estimate $estimate -File ([string]$request['progressFile']) -Confirm:$false
    }
    Connect-PostureService -Name graph
    $failed = 0
    $profileParam = @{}
    if ($request['profilePath'] -and (Test-Path -LiteralPath $request['profilePath'])) { $profileParam.ProfilePath = [string]$request['profilePath'] }
    try {
        foreach ($collector in $order) {
            try {
                Set-PostureProgressPhase -Name $collector -Label $(if ($collector -eq 'Purview') { 'waiting for the Purview sign-in' } else { 'connecting' }) -Confirm:$false
                Connect-PostureService -Name $collector.ToLowerInvariant()
                Invoke-PostureCollection -Collector $collector -SkipCaSnapshot -OutputFolder $folder @profileParam | Out-Null
            }
            catch {
                $failed++
                $message = (([string]$_.Exception.Message) -replace '\s*[\r\n]+\s*', ' ').Trim()
                if ($folder -and (Test-Path -LiteralPath $folder)) {
                    Invoke-PostureFolderLock -Folder $folder -Script { Add-Content -Path (Join-Path (Get-PostureRunLayout -Folder $folder).errors 'errors.txt') -Value "$collector collector :: $message" }
                    Write-PostureStepFailure -Folder $folder -Label "$collector collector" -Collector $collector -Message $message -Confirm:$false
                }
            }
        }
    }
    finally { Complete-PostureProgress -Confirm:$false }
    return $failed
}
