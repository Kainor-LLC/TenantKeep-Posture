# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Write-PostureEvidence {
    <#
    .SYNOPSIS
        Writes a JSON evidence file (full fidelity, depth 20, UTF-8 no BOM) and prints one line with the row count.
    .DESCRIPTION
        Mirrors Save-Evidence from the audit plan's Appendix A. Arrays are written as arrays even when they hold one
        item, so downstream readers never have to special-case a single object.
    .PARAMETER InputObject
        The object or collection to write. Pass -AsArray when a collection is expected.
    .PARAMETER Csv
        Also write <Name>.csv. Only for flat data.
    #>
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Per-file progress line is a user-facing CLI convention from the audit plan.')]
    [OutputType([string])]
    param(
        [Parameter()] [AllowNull()] [object] $InputObject,
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [string] $Name,
        [switch] $AsArray,
        [switch] $Csv,
        [switch] $Quiet
    )

    $ErrorActionPreference = 'Stop'

    $path = Join-Path $Folder "$Name.json"
    # -InputObject keeps an empty collection as [] instead of writing an empty file.
    $data = if ($AsArray) { , @($InputObject) } else { $InputObject }
    $json = ConvertTo-Json -InputObject $data -Depth 20
    [System.IO.File]::WriteAllText($path, $json, [System.Text.UTF8Encoding]::new($false))

    if ($Csv -and $AsArray) {
        @($InputObject) | Export-Csv -Path (Join-Path $Folder "$Name.csv") -NoTypeInformation
    }

    $count = if ($AsArray) { @($InputObject).Count } else { 1 }
    if (-not $Quiet) { Write-Host ('{0,-42} {1,7:N0}' -f "$Name.json", $count) }
    return $path
}
