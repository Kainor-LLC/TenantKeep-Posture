# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureValue {
    <#
    .SYNOPSIS
        Walks a dotted path through nested hashtables from Graph wire JSON. Returns $null for any missing segment.
    .DESCRIPTION
        Graph omits properties it has no value for, and Set-StrictMode makes a missing member an error. Every read
        of a nested policy property goes through here so a sparse policy never throws. Keys that themselves contain
        a dot, such as '@odata.type', must be read with the indexer instead.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter()] [AllowNull()] [object] $Object,
        [Parameter(Mandatory)] [string] $Path
    )

    $ErrorActionPreference = 'Stop'
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
