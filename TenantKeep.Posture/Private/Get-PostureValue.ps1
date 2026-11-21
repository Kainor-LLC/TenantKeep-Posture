# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureValue {
    <#
    .SYNOPSIS
        Walks a dotted path through nested hashtables from Graph wire JSON. Returns $null for any missing segment.
    .DESCRIPTION
        Graph omits properties it has no value for, and Set-StrictMode makes a missing member an error. Every read
        of a nested policy property goes through here so a sparse policy never throws. A key that itself contains
        a dot, such as '@odata.type', is found as it is written before the path is walked: asked for by this
        function it used to come back empty, which left the type and the IP ranges out of the named locations table.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter()] [AllowNull()] [object] $Object,
        [Parameter(Mandatory)] [string] $Path
    )

    $ErrorActionPreference = 'Stop'
    if ($Object -is [System.Collections.IDictionary] -and $Path.Contains('.') -and $Object.Contains($Path)) { return $Object[$Path] }
    $current = $Object
    foreach ($segment in $Path.Split('.')) {
        if ($null -eq $current) { return $null }
        if ($current -is [System.Collections.IDictionary]) {
            if (-not $current.Contains($segment)) { return $null }
            $current = $current[$segment]
        }
        elseif ($current.PSObject.Properties.Name -contains $segment) {
            $current = $current.$segment
        }
        else {
            return $null
        }
    }
    return $current
}
