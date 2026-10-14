# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Import-PostureBrand {
    <#
    .SYNOPSIS
        Loads brand.json (spec 7.5) merged over the free-tier defaults. Without a path, returns the defaults.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [string] $Path
    )

    $ErrorActionPreference = 'Stop'

    $brand = [ordered]@{
        preparedBy      = [ordered]@{ name = 'Tenantkeep Posture'; logo = $null; contact = $null }
        client          = [ordered]@{ name = $null; logo = $null }
        colors          = [ordered]@{ primary = '#1F3A5F'; accent = '#E8A33D' }
        font            = 'Inter, Helvetica, Arial, sans-serif'
        confidentiality = $null
        footer          = 'Prepared with Tenantkeep Posture'
        caNamePattern   = $null
    }
    if (-not $Path) { return $brand }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "brand.json not found: $Path" }
    $custom = ConvertFrom-Json -InputObject (Get-Content -LiteralPath $Path -Raw) -AsHashtable
    foreach ($key in $custom.Keys) {
        if ($brand[$key] -is [System.Collections.IDictionary] -and $custom[$key] -is [System.Collections.IDictionary]) {
            foreach ($sub in $custom[$key].Keys) { $brand[$key][$sub] = $custom[$key][$sub] }
        }
        else { $brand[$key] = $custom[$key] }
    }
    return $brand
}
