# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function New-PostureLoopbackListener {
    <#
    .SYNOPSIS
        Opens an HTTP listener on a free loopback port for the sign-in redirect.
    .DESCRIPTION
        The app registration carries http://localhost with no port; the identity platform matches any port on it.
        A free port is taken from the system so two runs on one machine never collide.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param()

    $ErrorActionPreference = 'Stop'
    $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $probe.Start()
    $port = ([System.Net.IPEndPoint]$probe.LocalEndpoint).Port
    $probe.Stop()
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add("http://localhost:$port/")
    if ($PSCmdlet.ShouldProcess("localhost:$port", 'Listen for the sign-in redirect')) { $listener.Start() }
    return @{ listener = $listener; port = $port; redirectUri = "http://localhost:$port" }
}

function Wait-PostureAuthCode {
    <#
    .SYNOPSIS
        Waits for the browser to come back to the loopback listener with the authorization code.
    .DESCRIPTION
        One request is accepted. The state must match the one sent to the authorize endpoint, otherwise the code is
        discarded. The browser gets a one-line page and can be closed. The listener is always stopped.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [hashtable] $Loopback,
        [Parameter(Mandatory)] [string] $State,
        [int] $TimeoutSeconds = 300
    )

    $ErrorActionPreference = 'Stop'
    $listener = [System.Net.HttpListener]$Loopback.listener
    try {
        $task = $listener.GetContextAsync()
        if (-not $task.Wait([timespan]::FromSeconds($TimeoutSeconds))) { throw "No sign-in came back within $TimeoutSeconds seconds. Run the command again, or use -DeviceCode on a machine without a browser." }
        $context = $task.Result
        $query = $context.Request.QueryString
        $error1 = [string]$query['error']
        $code = [string]$query['code']
        $ok = (-not $error1) -and $code -and ([string]$query['state'] -eq $State)
        $html = if ($ok) { '<!doctype html><title>Tenantkeep Posture</title><body style="font-family:system-ui;margin:3rem"><h1>Signed in</h1><p>You can close this window and go back to the terminal.</p></body>' }
        else { '<!doctype html><title>Tenantkeep Posture</title><body style="font-family:system-ui;margin:3rem"><h1>Sign-in did not complete</h1><p>Go back to the terminal for the reason.</p></body>' }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($html)
        $context.Response.ContentType = 'text/html; charset=utf-8'
        $context.Response.ContentLength64 = $bytes.Length
        $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $context.Response.Close()
        if ($error1) { throw "Sign-in failed ($error1): $([string]$query['error_description'])" }
        if (-not $code) { throw 'The redirect carried no authorization code.' }
        if ([string]$query['state'] -ne $State) { throw 'The redirect carried an unexpected state value; the code was discarded.' }
        return $code
    }
    finally {
        try { $listener.Stop(); $listener.Close() } catch { Write-Verbose "Listener close: $($_.Exception.Message)" }
    }
}
