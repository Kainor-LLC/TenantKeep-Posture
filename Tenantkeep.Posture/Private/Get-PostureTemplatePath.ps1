# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureTemplatePath {
    <#
    .SYNOPSIS
        Finds a file under templates/: inside the module folder once packaged, or beside it in the repo.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Name
    )

    $ErrorActionPreference = 'Stop'
    $candidates = @(
        (Join-Path $script:ModuleRoot 'templates' $Name)
        (Join-Path $script:ModuleRoot '..' 'templates' $Name)
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c -PathType Leaf) { return (Resolve-Path -LiteralPath $c).Path }
    }
    throw "Template '$Name' not found in $($candidates -join ' or ')"
}
