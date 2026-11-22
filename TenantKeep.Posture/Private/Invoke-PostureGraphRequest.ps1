# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# How hard a Graph read keeps trying: retries per page for throttling and transient failures, the longest single
# wait, and how many times an expired access token is renewed from the sign-in before giving up. Tests set the
# waits to zero.
$script:PostureGraphRetry = @{ maxAttempts = 8; maxWaitSeconds = 300; baseSeconds = 2; maxTokenRenewals = 5 }

function Invoke-PostureGraphRequest {
    <#
    .SYNOPSIS
        The single Graph entry point for the module. Wraps Invoke-MgGraphRequest, follows @odata.nextLink, returns raw hashtables.
    .DESCRIPTION
        Every Graph call in the module goes through here so that tests can mock one function and so the read-only guard
        in the module tests has one place to look. Responses are returned as hashtables (wire JSON, untouched casing).
        Collection responses are flattened: all pages of 'value' are returned as one array, or, with -OnPage, handed to
        the caller one page at a time and never held together, which is how tenants with hundreds of thousands of
        objects and millions of sign-ins are read.

        Built to run for hours: a page that is throttled (429) or fails transiently (5xx, a timeout, a dropped
        connection) is requested again after the Retry-After Graph sends, or an exponential wait with jitter, up to
        PostureGraphRetry.maxAttempts times. An access token that expires part-way through is renewed from the
        sign-in's refresh token and the same page is requested again. Only a failure that persists past all of that
        is thrown, and it carries the nextLink it stopped at (-StartAt resumes there).
    .PARAMETER Uri
        Relative Graph URI, for example 'identity/conditionalAccess/policies'. Absolute URIs are passed through.
    .PARAMETER Method
        GET by default. POST is only permitted for query-style endpoints; see CLAUDE.md.
    .PARAMETER Body
        Request body for POST, as a hashtable.
    .PARAMETER ApiVersion
        v1.0 or beta. Mandatory: every call pins its version (CLAUDE.md) and the set used is recorded in metadata.json.
    .PARAMETER Single
        Return the single object as-is instead of unwrapping 'value'.
    .PARAMETER OnPage
        Called with each page's items and @{ number; count; nextLink } instead of collecting them; the function then
        returns the number of items read. A page is handed over only once it arrived whole.
    .PARAMETER StartAt
        A nextLink to continue from (a checkpoint), in place of Uri's first page.
    .PARAMETER Label
        What the progress line calls this read, for example 'Users'.
    #>
    [CmdletBinding()]
    [OutputType([hashtable], [object[]], [long])]
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [ValidateSet('GET', 'POST')] [string] $Method = 'GET',
        [hashtable] $Body,
        [Parameter(Mandatory)] [ValidateSet('v1.0', 'beta')] [string] $ApiVersion,
        [switch] $Single,
        [scriptblock] $OnPage,
        [string] $StartAt,
        [string] $Label,
        # Request headers, for the few reads that need one (ConsistencyLevel: eventual on a count).
        [hashtable] $Headers
    )

    $ErrorActionPreference = 'Stop'

    # Every local here carries the graph prefix on purpose. An -OnPage block runs inside this function, so a name it
    # reads from its own caller ($total, $items, $page, $next) would find this function's variable of that name
    # first: a collector's counter called $total once came back as this function's row count.
    $graphUrl = if ($Uri -match '^https?://') { $Uri } else { "https://graph.microsoft.com/$ApiVersion/$($Uri.TrimStart('/'))" }
    $null = $script:GraphApiVersionsUsed.Add($ApiVersion)

    # Not $( ): a subexpression unrolls an empty list to nothing.
    $graphItems = $null
    if (-not $OnPage) { $graphItems = [System.Collections.Generic.List[object]]::new() }
    $graphNext = $(if ($StartAt) { $StartAt } else { $graphUrl })
    $graphPage = 0; [long]$graphTotal = 0
    while ($graphNext) {
        $graphResponse = Invoke-PostureGraphPage -Url $graphNext -Method $Method -Body $Body -Headers $Headers
        if ($Single -or -not $graphResponse.ContainsKey('value')) { return $graphResponse }
        $graphPage++
        $graphValues = @($graphResponse.value)
        $graphTotal += $graphValues.Count
        $graphFollowing = if ($graphResponse.ContainsKey('@odata.nextLink')) { [string]$graphResponse.'@odata.nextLink' } else { $null }
        if ($OnPage) { & $OnPage $graphValues @{ number = $graphPage; count = $graphTotal; nextLink = $graphFollowing } }
        else { foreach ($graphValue in $graphValues) { $graphItems.Add($graphValue) } }
        if ($graphFollowing -and $graphPage -ge 2 -and $script:PostureProgress) {
            $script:PostureProgress.label = "$(if ($Label) { $Label } else { 'reading' }): page $graphPage, $('{0:N0}' -f $graphTotal) so far"
            Write-PostureProgress
        }
        $graphNext = $graphFollowing
    }
    if ($OnPage) { return $graphTotal }
    return $graphItems.ToArray()
}

function Invoke-PostureGraphStream {
    <#
    .SYNOPSIS
        One Graph GET whose answer is a file's bytes, not JSON (an image of the company branding). Returns the bytes,
        or $null when Graph has none (404, or an empty answer).
    .DESCRIPTION
        The version is pinned and recorded and the call is counted, like every other read. The answer is written to
        a temporary file and read back, never kept on disk, and refused above -MaxBytes: what comes back is the
        tenant's to choose.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [ValidateSet('v1.0', 'beta')] [string] $ApiVersion,
        [ValidateRange(1, 5242880)] [int] $MaxBytes = 524288
    )

    $ErrorActionPreference = 'Stop'
    $url = "https://graph.microsoft.com/$ApiVersion/$($Uri.TrimStart('/'))"
    $null = $script:GraphApiVersionsUsed.Add($ApiVersion)
    Add-PostureCallRecord -Service graph -Method GET -Target $url
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-stream-$([guid]::NewGuid().ToString('n'))"
    try {
        Write-Verbose "GET $url"
        try { $null = Invoke-MgGraphRequest -Method GET -Uri $url -OutputFilePath $temp -ErrorAction Stop }
        catch { if ((Get-PostureHttpStatus -ErrorRecord $_) -eq 404) { return $null }; throw }
        if (-not (Test-Path -LiteralPath $temp -PathType Leaf)) { return $null }
        $length = ([System.IO.FileInfo]$temp).Length
        if ($length -eq 0) { return $null }
        if ($length -gt $MaxBytes) { throw "$Uri answered $length bytes, more than the $MaxBytes this read keeps." }
        return , [System.IO.File]::ReadAllBytes($temp)
    }
    finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue } }
}

function Invoke-PostureGraphPage {
    <#
    .SYNOPSIS
        One Graph request with the retry policy: throttling and transient failures waited out, an expired token
        renewed. Throws only what persists, with Graph's own message and the URL it stopped at.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Url,
        [string] $Method = 'GET',
        [hashtable] $Body,
        [hashtable] $Headers
    )

    $ErrorActionPreference = 'Stop'
    $policy = $script:PostureGraphRetry
    $attempt = 0; $renewals = 0
    # The ledger counts the page once, however many retries it takes; a batch counts each request inside it too.
    Add-PostureCallRecord -Service graph -Method $Method -Target $Url
    if ($Body -and $Body.Contains('requests')) { foreach ($inner in @($Body['requests'])) { Add-PostureCallRecord -Service graph -Method ([string]$inner['method']) -Target "$(([uri]$Url).Segments[1])$(([string]$inner['url']).TrimStart('/'))" } }
    while ($true) {
        $attempt++
        $params = @{ Uri = $Url; Method = $Method; OutputType = 'HashTable'; ErrorAction = 'Stop' }
        if ($Body) { $params.Body = ($Body | ConvertTo-Json -Depth 20 -Compress); $params.ContentType = 'application/json' }
        if ($Headers -and $Headers.Count -gt 0) { $params.Headers = $Headers }
        Write-Verbose "$Method $Url"
        try { return (Invoke-MgGraphRequest @params) }
        catch {
            $err = $_
            $status = Get-PostureHttpStatus -ErrorRecord $err
            $detail = $(if ($err.ErrorDetails) { [string]$err.ErrorDetails.Message } else { '' })
            # An expired access token: renew it from the sign-in and ask again (hours-long reads outlive one token).
            if ($status -eq 401 -and $renewals -lt $policy.maxTokenRenewals -and $script:PostureSession -and ($script:PostureSession['refreshToken'] -or ($script:PostureSession.ContainsKey('tokenPipe') -and $script:PostureSession['tokenPipe']))) {
                $renewals++
                Write-Verbose "Graph token refused (401); renewing it ($renewals of $($policy.maxTokenRenewals))."
                $null = Get-PostureToken -Resource graph -Force
                Connect-PostureService -Name graph
                $attempt--
                continue
            }
            $transient = $status -in 429, 500, 502, 503, 504 -or ($status -eq 0 -and (Test-PostureTransientError -ErrorRecord $err))
            if ($transient -and $attempt -lt $policy.maxAttempts) {
                $wait = Get-PostureRetryDelay -ErrorRecord $err -Attempt $attempt
                Write-Verbose "Graph answered $(if ($status) { $status } else { 'no response' }) for $Url; waiting $([int]$wait) s (attempt $attempt of $($policy.maxAttempts))."
                if ($script:PostureProgress) { $script:PostureProgress.label = "waiting $([int]$wait) s: Microsoft asked to slow down ($(if ($status) { $status } else { 'no response' }))"; Write-PostureProgress -Force }
                if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]($wait * 1000)) }
                continue
            }
            # The SDK's message is only the status; Graph's own error text is in the response body.
            $graphMessage = $null
            $i = $detail.IndexOf('{')
            if ($i -ge 0) {
                try {
                    $errorBody = ConvertFrom-Json $detail.Substring($i)
                    # Graph proper puts it in error.message; the Intune service answers with a top-level Message.
                    $graphMessage = if ($errorBody.PSObject.Properties['error']) { [string]$errorBody.error.message } elseif ($errorBody.PSObject.Properties['Message']) { ([string]$errorBody.Message -split ' - ')[0] } else { $null }
                }
                catch { $graphMessage = $null }
            }
            $what = "$Method $Url"
            $tries = $(if ($attempt -gt 1) { " after $attempt attempts" } else { '' })
            if ($graphMessage) { throw "$($err.Exception.Message) [$what]$tries $graphMessage" }
            throw "$($err.Exception.Message) [$what]$tries"
        }
    }
}

function Get-PostureHttpStatus {
    <#
    .SYNOPSIS
        The HTTP status of a failed Graph request, from the response when the SDK kept it, else from the message
        text ("... does not indicate success: TooManyRequests (Too Many Requests)"). 0 when there was no response.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)] [System.Management.Automation.ErrorRecord] $ErrorRecord)

    $ex = $ErrorRecord.Exception
    foreach ($candidate in @($ex, $ex.InnerException)) {
        if ($candidate -and $candidate.PSObject.Properties['Response'] -and $candidate.Response -and $candidate.Response.PSObject.Properties['StatusCode']) {
            try { return [int]$candidate.Response.StatusCode } catch { Write-Verbose 'No status on the response.' }
        }
        if ($candidate -and $candidate.PSObject.Properties['StatusCode'] -and $candidate.StatusCode) { try { return [int]$candidate.StatusCode } catch { Write-Verbose 'No status code.' } }
    }
    $names = @{ TooManyRequests = 429; ServiceUnavailable = 503; GatewayTimeout = 504; BadGateway = 502; InternalServerError = 500; Unauthorized = 401; Forbidden = 403; NotFound = 404; BadRequest = 400 }
    $m = [regex]::Match([string]$ex.Message, 'does not indicate success: (\w+)')
    if ($m.Success -and $names.ContainsKey($m.Groups[1].Value)) { return $names[$m.Groups[1].Value] }
    $n = [regex]::Match([string]$ex.Message, '\b(4\d\d|5\d\d)\b')
    if ($n.Success) { return [int]$n.Groups[1].Value }
    return 0
}

function Test-PostureTransientError {
    <#
    .SYNOPSIS
        A failure with no HTTP answer that is worth trying again: a timeout, a dropped or refused connection, DNS.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [System.Management.Automation.ErrorRecord] $ErrorRecord)

    $ex = $ErrorRecord.Exception
    while ($ex) {
        if ($ex -is [System.Net.Http.HttpRequestException] -or $ex -is [System.IO.IOException] -or $ex -is [System.TimeoutException] -or $ex -is [System.Threading.Tasks.TaskCanceledException] -or $ex -is [System.Net.Sockets.SocketException]) { return $true }
        $ex = $ex.InnerException
    }
    return [bool]([string]$ErrorRecord.Exception.Message -match '(?i)(timed out|timeout|connection (was )?(reset|closed|refused)|No such host|temporarily unavailable)')
}

function Get-PostureRetryDelay {
    <#
    .SYNOPSIS
        Seconds to wait before the next attempt: Graph's Retry-After when it sent one, else 2^attempt times the base
        with jitter, never more than PostureGraphRetry.maxWaitSeconds.
    #>
    [CmdletBinding()]
    [OutputType([double])]
    param(
        [Parameter(Mandatory)] [System.Management.Automation.ErrorRecord] $ErrorRecord,
        [Parameter(Mandatory)] [int] $Attempt
    )

    $policy = $script:PostureGraphRetry
    $after = $null
    foreach ($candidate in @($ErrorRecord.Exception, $ErrorRecord.Exception.InnerException)) {
        if (-not ($candidate -and $candidate.PSObject.Properties['Response'] -and $candidate.Response)) { continue }
        try {
            $ra = $candidate.Response.Headers.RetryAfter
            if ($ra -and $ra.Delta) { $after = $ra.Delta.TotalSeconds } elseif ($ra -and $ra.Date) { $after = ($ra.Date.UtcDateTime - [datetime]::UtcNow).TotalSeconds }
        }
        catch { Write-Verbose 'No Retry-After header.' }
    }
    if ($null -eq $after) { $after = $policy.baseSeconds * [Math]::Pow(2, $Attempt - 1) * (0.75 + 0.5 * (Get-Random -Minimum 0.0 -Maximum 1.0)) }
    return [double][Math]::Min([Math]::Max(0, $after), $policy.maxWaitSeconds)
}
