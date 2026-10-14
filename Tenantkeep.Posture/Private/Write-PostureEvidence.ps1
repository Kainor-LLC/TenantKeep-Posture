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
    # -InputObject keeps an empty collection as [] instead of writing an empty file; nulls never make it into a list.
    $items = @(@($InputObject) | Where-Object { $null -ne $_ })
    $data = if ($AsArray) { , $items } else { $InputObject }
    if ($null -eq $data) { $data = @{} }
    $json = ConvertTo-Json -InputObject $data -Depth 20
    [System.IO.File]::WriteAllText($path, $json, [System.Text.UTF8Encoding]::new($false))

    if ($Csv -and $AsArray) {
        $csvPath = Join-Path $Folder "$Name.csv"
        if ($items.Count -eq 0) { [System.IO.File]::WriteAllText($csvPath, '', [System.Text.UTF8Encoding]::new($false)) }
        else {
            # Export-Csv wants objects with properties; dictionaries make it throw a null reference.
            @($items | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [pscustomobject]$_ } else { $_ } }) | Export-Csv -Path $csvPath -NoTypeInformation
        }
    }

    $count = if ($AsArray) { $items.Count } else { 1 }
    if (-not $Quiet) { Write-Host ('{0,-42} {1,7:N0}' -f "$Name.json", $count) }
    return $path
}
