# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureGraphRequest {
    <#
    .SYNOPSIS
        The single Graph entry point for the module. Wraps Invoke-MgGraphRequest, follows @odata.nextLink, returns raw hashtables.
    .DESCRIPTION
        Every Graph call in the module goes through here so that tests can mock one function and so the read-only guard
        in the module tests has one place to look. Responses are returned as hashtables (wire JSON, untouched casing).
        Collection responses are flattened: all pages of 'value' are returned as one array.
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
    #>
    [CmdletBinding()]
    [OutputType([hashtable], [object[]])]
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [ValidateSet('GET', 'POST')] [string] $Method = 'GET',
        [hashtable] $Body,
        [Parameter(Mandatory)] [ValidateSet('v1.0', 'beta')] [string] $ApiVersion,
        [switch] $Single
    )

    $ErrorActionPreference = 'Stop'

    $url = if ($Uri -match '^https?://') { $Uri } else { "https://graph.microsoft.com/$ApiVersion/$($Uri.TrimStart('/'))" }
    $null = $script:GraphApiVersionsUsed.Add($ApiVersion)

    $items = [System.Collections.Generic.List[object]]::new()
    $next = $url
    while ($next) {
        $params = @{ Uri = $next; Method = $Method; OutputType = 'HashTable'; ErrorAction = 'Stop' }
        if ($Body) { $params.Body = ($Body | ConvertTo-Json -Depth 20 -Compress); $params.ContentType = 'application/json' }
        Write-Verbose "$Method $next"
        try { $response = Invoke-MgGraphRequest @params }
        catch {
            # The SDK's message is only the status; Graph's own error text is in the response body.
            $detail = $(if ($_.ErrorDetails) { [string]$_.ErrorDetails.Message } else { '' })
            $graphMessage = $null
            $i = $detail.IndexOf('{"error"')
            if ($i -ge 0) { try { $graphMessage = (ConvertFrom-Json $detail.Substring($i)).error.message } catch { $graphMessage = $null } }
            $what = "$Method $next"
            if ($graphMessage) { throw "$($_.Exception.Message) [$what] $graphMessage" }
            throw "$($_.Exception.Message) [$what]"
        }

        if ($Single -or -not $response.ContainsKey('value')) { return $response }

        foreach ($v in $response.value) { $items.Add($v) }
        $next = if ($response.ContainsKey('@odata.nextLink')) { $response.'@odata.nextLink' } else { $null }
    }
    return $items.ToArray()
}
