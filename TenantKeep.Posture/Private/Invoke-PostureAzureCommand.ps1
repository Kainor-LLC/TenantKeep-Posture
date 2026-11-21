# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Test-PostureAzureSession {
    <#
    .SYNOPSIS
        True when an Az.Accounts context is signed in (Connect-AzAccount). Never connects. With -TenantId, only when
        that context is in that tenant: Az saves its context between sessions, so the current one can belong to a
        tenant signed in to days ago.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string] $TenantId)

    $ErrorActionPreference = 'Stop'
    if (-not (Get-Command -Name Get-AzContext -ErrorAction SilentlyContinue)) { return $false }
    $c = $null
    try { $c = Get-AzContext -ErrorAction Stop } catch { return $false }
    if (-not ($c -and $c.Account -and $c.Tenant)) { return $false }
    if ($TenantId -and [string]$c.Tenant.Id -ne $TenantId) { return $false }
    # A context can outlive its tokens (the cache dies, the session stays listed); prove it with one small read, which
    # works for every context type including one built from a supplied access token.
    Add-PostureCallRecord -Service azure -Method GET -Target '/subscriptions'
    try { $r = Invoke-AzRestMethod -Method GET -Path '/subscriptions?api-version=2022-12-01' -ErrorAction Stop; return ($r.StatusCode -lt 400) } catch { return $false }
}

function Invoke-PostureAzureRest {
    <#
    .SYNOPSIS
        One Azure Resource Manager request with the retry policy: throttling (429) and a busy or failing service
        (500, 502, 503, 504) are waited out, after Retry-After when the answer carries one. Returns the response
        whatever its status once the attempts are used; the caller decides what a refusal means.
    .DESCRIPTION
        Resource Manager throttles per subscription and per tenant. A run over hundreds of subscriptions meets the
        limit sooner or later, and without this one 429 failed a whole step.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Parameter)

    $policy = $script:PostureGraphRetry
    for ($attempt = 1; ; $attempt++) {
        $response = Invoke-AzRestMethod @Parameter -ErrorAction Stop
        if ([int]$response.StatusCode -notin 429, 500, 502, 503, 504 -or $attempt -ge $policy.maxAttempts) { return $response }
        $asked = 0
        try {
            $headers = $(if ($response.PSObject.Properties['Headers']) { $response.Headers })
            if ($headers -and $headers.PSObject.Properties['RetryAfter'] -and $headers.RetryAfter -and $headers.RetryAfter.Delta) { $asked = [int]$headers.RetryAfter.Delta.TotalSeconds }
        }
        catch { $asked = 0 }
        $delay = [Math]::Min($policy.maxWaitSeconds, [Math]::Max($asked, $policy.baseSeconds * [Math]::Pow(2, $attempt - 1)))
        Write-Verbose "Azure answered $([int]$response.StatusCode); waiting $([int]$delay) s (attempt $attempt of $($policy.maxAttempts))."
        if ($script:PostureProgress) { $script:PostureProgress.label = "waiting $([int]$delay) s: Azure asked to slow down ($([int]$response.StatusCode))"; Write-PostureProgress -Force }
        if ($delay -gt 0) { Start-Sleep -Seconds $delay }
    }
}

function Invoke-PostureAzureQuery {
    <#
    .SYNOPSIS
        The single entry point for Azure Resource Graph: one KQL query at tenant scope, paged through the skip token.
        Reads only; Resource Graph has no write surface.
    .DESCRIPTION
        Resource Graph gives a skip token only when the rows carry an id to page by. A full page with no token is
        followed by asking for the rows after it by position (-Skip), until a page comes back short. An answer
        Resource Graph itself marks as truncated, with no way to page it, is an error: a short list must not be
        read as the whole one. (verify) live: -Skip paging and the truncation flag, plan check 6.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [string] $Query,
        [ValidateRange(1, 1000)] [int] $PageSize = 1000
    )

    $ErrorActionPreference = 'Stop'
    Update-PostureServiceSession -Name azure
    if (-not (Get-Command -Name Search-AzGraph -ErrorAction SilentlyContinue)) { throw 'Search-AzGraph is not available; install Az.ResourceGraph and connect first.' }
    $items = [System.Collections.Generic.List[object]]::new()
    $token = $null; $skip = 0
    do {
        $params = @{ Query = $Query; First = $PageSize; UseTenantScope = $true; ErrorAction = 'Stop' }
        if ($token) { $params.SkipToken = $token } elseif ($skip -gt 0) { $params.Skip = $skip }
        Add-PostureCallRecord -Service azure -Method query -Target "Resource Graph: $((($Query -split '\|')[0]).Trim())"
        $page = Search-AzGraph @params
        $got = 0
        foreach ($row in @($page)) { if ($null -ne $row) { $items.Add($row); $got++ } }
        $token = $(if ($page -and $page.PSObject.Properties['SkipToken']) { $page.SkipToken } else { $null })
        $skip = $(if (-not $token -and $got -ge $PageSize) { $items.Count } else { 0 })
        if (-not $token -and $skip -eq 0 -and $page -and $page.PSObject.Properties['ResultTruncated'] -and [string]$page.ResultTruncated -eq 'true') {
            throw "Resource Graph cut the answer short after $($items.Count) rows and gave no way to page it: $((($Query -split '\|')[0]).Trim())"
        }
        if ($items.Count -gt 5000000) { throw 'Resource Graph returned more than five million rows for one query; stopping.' }
    } while ($token -or $skip -gt 0)
    return $items.ToArray()
}

function Invoke-PostureAzureRequest {
    <#
    .SYNOPSIS
        The single entry point for Azure Resource Manager REST reads: GET only, the JSON body parsed, nextLink followed.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [switch] $Single
    )

    $ErrorActionPreference = 'Stop'
    Update-PostureServiceSession -Name azure
    if (-not (Get-Command -Name Invoke-AzRestMethod -ErrorAction SilentlyContinue)) { throw 'Invoke-AzRestMethod is not available; install Az.Accounts and connect first.' }
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Path
    while ($next) {
        $params = $(if ($next -match '^https?://') { @{ Uri = $next } } else { @{ Path = $next } })
        Add-PostureCallRecord -Service azure -Method GET -Target $next
        $params.Method = 'GET'
        $response = Invoke-PostureAzureRest -Parameter $params
        if ($response.StatusCode -ge 400) { throw "GET $next returned $($response.StatusCode): $(([string]$response.Content).Substring(0, [Math]::Min(300, ([string]$response.Content).Length)))" }
        $body = $(if ($response.Content) { ConvertFrom-Json -InputObject $response.Content -AsHashtable -Depth 30 } else { @{} })
        if ($Single -or -not ($body -is [System.Collections.IDictionary] -and $body.ContainsKey('value'))) { return $body }
        foreach ($v in $body.value) { $items.Add($v) }
        $next = $(if ($body.ContainsKey('nextLink')) { $body.nextLink } else { $null })
    }
    return $items.ToArray()
}

function Invoke-PostureCostQuery {
    <#
    .SYNOPSIS
        A Cost Management query, the one Azure read that is a POST: Microsoft.CostManagement/query takes the question
        in the body and changes nothing. Any other path is refused, so this cannot become a way to write.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [ValidatePattern('^/subscriptions/[^/?]+/providers/Microsoft\.CostManagement/query\?api-version=[0-9-]+(-preview)?$')] [string] $Path,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Query
    )

    $ErrorActionPreference = 'Stop'
    Update-PostureServiceSession -Name azure
    if (-not (Get-Command -Name Invoke-AzRestMethod -ErrorAction SilentlyContinue)) { throw 'Invoke-AzRestMethod is not available; install Az.Accounts and connect first.' }
    $payload = ConvertTo-Json -InputObject $Query -Depth 10 -Compress
    $response = Invoke-PostureAzureRest -Parameter @{ Method = 'POST'; Path = $Path; Payload = $payload }   # posture:read-only-post (Cost Management query)
    Add-PostureCallRecord -Service azure -Method POST -Target $Path   # posture:read-only-post (the ledger entry for the query above)
    if ($response.StatusCode -ge 400) { throw "Cost query on $Path returned $($response.StatusCode): $(([string]$response.Content).Substring(0, [Math]::Min(300, ([string]$response.Content).Length)))" }
    $body = ConvertFrom-Json -InputObject $response.Content -AsHashtable -Depth 30
    $cols = @($body.properties.columns | ForEach-Object { [string]$_.name })
    return @(@($body.properties.rows) | ForEach-Object { $row = $_; $o = [ordered]@{}; for ($i = 0; $i -lt $cols.Count; $i++) { $o[$cols[$i]] = $row[$i] }; $o })
}
