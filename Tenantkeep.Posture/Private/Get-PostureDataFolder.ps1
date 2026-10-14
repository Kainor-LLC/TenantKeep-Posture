# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureDataFolder {
    <#
    .SYNOPSIS
        Finds a data folder shipped with the product (checks, baselines, templates): inside the module once packaged, or beside it in the repo.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [ValidateSet('checks', 'baselines', 'templates', 'schedules')] [string] $Name
    )

    $ErrorActionPreference = 'Stop'
    $candidates = @((Join-Path $script:ModuleRoot $Name), (Join-Path $script:ModuleRoot '..' $Name))
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c -PathType Container) { return (Resolve-Path -LiteralPath $c).Path }
    }
    throw "Data folder '$Name' not found in $($candidates -join ' or ')"
}
