# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Resolve-PostureDirectoryObject {
    <#
    .SYNOPSIS
        Resolves directory object IDs (users, groups, service principals) to display name and type in batches of 1000.
    .DESCRIPTION
        Uses the getByIds query endpoint. It is a POST on the wire but reads only; it is the documented way to look
        up many IDs in one call. IDs absent from the response are not in the directory any more and are returned
        with deleted = $true. Returns a hashtable keyed by ID.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Id,
        [string[]] $Type = @('user', 'group', 'servicePrincipal')
    )

    $ErrorActionPreference = 'Stop'
    $result = @{}
    if ($Id.Count -eq 0) { return $result }

    $batchSize = 1000
    for ($i = 0; $i -lt $Id.Count; $i += $batchSize) {
        $batch = $Id[$i..([Math]::Min($i + $batchSize, $Id.Count) - 1)]
        $body = @{ ids = @($batch); types = @($Type) }
        $found = @(Invoke-PostureGraphRequest -Uri 'directoryObjects/getByIds' -Method 'POST' -Body $body -ApiVersion 'v1.0')   # posture:read-only-post
        foreach ($obj in $found) {
            $odataType = [string]$obj['@odata.type']
            $entry = [ordered]@{
                displayName = Get-PostureValue $obj 'displayName'
                type        = $odataType -replace '^#microsoft\.graph\.', ''
                deleted     = $false
            }
            $upn = Get-PostureValue $obj 'userPrincipalName'
            if ($upn) { $entry.userPrincipalName = $upn }
            $appId = Get-PostureValue $obj 'appId'
            if ($appId) { $entry.appId = $appId }
            $result[[string]$obj.id] = $entry
        }
    }

    foreach ($wanted in $Id) {
        if (-not $result.ContainsKey($wanted)) {
            $result[$wanted] = [ordered]@{ displayName = $null; type = 'unknown'; deleted = $true }
        }
    }
    return $result
}
