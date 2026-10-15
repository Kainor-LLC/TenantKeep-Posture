# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Write-PostureDiscovery {
    <#
    .SYNOPSIS
        Prints what the profile discovery found and where, so the person running the wizard can see what it will not ask.
    #>
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive wizard output.')]
    param(
        [Parameter(Mandatory)] [hashtable] $Discovery,
        [Parameter()] [AllowEmptyCollection()] [string[]] $Keys = @()
    )

    $ErrorActionPreference = 'Stop'
    if ($Keys.Count -eq 0) { return }
    Write-Host ''
    Write-Host "Discovered from $($Discovery.evidence):" -ForegroundColor Cyan
    foreach ($k in $Keys) {
        $value = $Discovery.facts[$k]
        $text = $(if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) { (@($value) -join ', ') } else { [string]$value })
        Write-Host ("  {0,-22} {1}" -f $k, $text)
        if ($Discovery.sources.Contains($k)) { Write-Host "    from $($Discovery.sources[$k])" -ForegroundColor DarkGray }
    }
    Write-Host '  Pass -AskAll to be asked these too; a parameter always wins.' -ForegroundColor DarkGray
}
