# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Test-PostureAzureSession {
    <#
    .SYNOPSIS
        True when an Az.Accounts context is signed in (Connect-AzAccount). Never connects.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $ErrorActionPreference = 'Stop'
    if (-not (Get-Command -Name Get-AzContext -ErrorAction SilentlyContinue)) { return $false }
    $c = $null
    try { $c = Get-AzContext -ErrorAction Stop } catch { return $false }
    if (-not ($c -and $c.Account -and $c.Tenant)) { return $false }
    # A context can outlive its tokens (the cache dies, the session stays listed); prove it with one small read, which
    # works for every context type including one built from a supplied access token.
    Add-PostureCallRecord -Service azure -Method GET -Target '/subscriptions'
    try { $r = Invoke-AzRestMethod -Method GET -Path '/subscriptions?api-version=2022-12-01' -ErrorAction Stop; return ($r.StatusCode -lt 400) } catch { return $false }
}

function Invoke-PostureAzureQuery {
    <#
    .SYNOPSIS
        The single entry point for Azure Resource Graph: one KQL query at tenant scope, paged through the skip token.
        Reads only; Resource Graph has no write surface.
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
    $token = $null
    do {
        $params = @{ Query = $Query; First = $PageSize; UseTenantScope = $true; ErrorAction = 'Stop' }
        if ($token) { $params.SkipToken = $token }
        Add-PostureCallRecord -Service azure -Method query -Target "Resource Graph: $((($Query -split '\|')[0]).Trim())"
        $page = Search-AzGraph @params
        foreach ($row in @($page)) { if ($null -ne $row) { $items.Add($row) } }
        $token = $(if ($page -and $page.PSObject.Properties['SkipToken']) { $page.SkipToken } else { $null })
    } while ($token)
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
        $response = Invoke-AzRestMethod -Method GET @params -ErrorAction Stop
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
    $response = Invoke-AzRestMethod -Method POST -Path $Path -Payload $payload -ErrorAction Stop   # posture:read-only-post (Cost Management query)
    Add-PostureCallRecord -Service azure -Method POST -Target $Path   # posture:read-only-post (the ledger entry for the query above)
    if ($response.StatusCode -ge 400) { throw "Cost query on $Path returned $($response.StatusCode): $(([string]$response.Content).Substring(0, [Math]::Min(300, ([string]$response.Content).Length)))" }
    $body = ConvertFrom-Json -InputObject $response.Content -AsHashtable -Depth 30
    $cols = @($body.properties.columns | ForEach-Object { [string]$_.name })
    return @(@($body.properties.rows) | ForEach-Object { $row = $_; $o = [ordered]@{}; for ($i = 0; $i -lt $cols.Count; $i++) { $o[$cols[$i]] = $row[$i] }; $o })
}
