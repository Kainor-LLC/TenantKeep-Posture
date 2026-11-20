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

function Open-PostureEvidenceStream {
    <#
    .SYNOPSIS
        Starts a JSON array evidence file (and optionally its CSV) that rows are appended to one at a time, so a
        file with hundreds of thousands of rows is never held in memory or built as one string. Close it with
        Close-PostureEvidenceStream; until then the file is incomplete, which a reader treats as not collected.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [string] $Name,
        [switch] $Csv
    )

    $ErrorActionPreference = 'Stop'
    $path = Join-Path $Folder "$Name.json"
    if (-not $PSCmdlet.ShouldProcess($path, 'Write evidence')) { return $null }
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $json = [System.IO.StreamWriter]::new($path, $false, $utf8, 1MB)
    $json.Write('[')
    $csvWriter = $(if ($Csv) { [System.IO.StreamWriter]::new((Join-Path $Folder "$Name.csv"), $false, $utf8, 1MB) } else { $null })
    return @{ name = $Name; path = $path; json = $json; csv = $csvWriter; columns = $null; count = [long]0 }
}

function Add-PostureEvidenceRow {
    <#
    .SYNOPSIS
        Appends one row (a dictionary) to an open evidence stream. The CSV columns are the first row's keys.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Stream,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Row
    )

    if ($Stream.count -gt 0) { $Stream.json.Write(',') }
    $Stream.json.Write("`n")
    $Stream.json.Write((ConvertTo-Json -InputObject $Row -Depth 20 -Compress))
    if ($Stream.csv) {
        $quote = { param($value) $s = $(if ($null -eq $value) { '' } elseif ($value -is [bool]) { $(if ($value) { 'True' } else { 'False' }) } else { [string]$value }); '"' + $s.Replace('"', '""') + '"' }
        if (-not $Stream.columns) {
            $Stream.columns = @($Row.Keys)
            $Stream.csv.WriteLine((@($Stream.columns | ForEach-Object { & $quote $_ }) -join ','))
        }
        $Stream.csv.WriteLine((@($Stream.columns | ForEach-Object { & $quote $Row[$_] }) -join ','))
    }
    $Stream.count++
}

function Close-PostureEvidenceStream {
    <#
    .SYNOPSIS
        Finishes an evidence stream, prints the row count line every evidence file gets, returns the JSON path.
    #>
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Per-file progress line is a user-facing CLI convention from the audit plan.')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [hashtable] $Stream,
        [switch] $Quiet
    )

    $Stream.json.Write("`n]")
    $Stream.json.Dispose()
    if ($Stream.csv) { $Stream.csv.Dispose() }
    if (-not $Quiet) { Write-Host ('{0,-42} {1,7:N0}' -f "$($Stream.name).json", $Stream.count) }
    return $Stream.path
}

function Stop-PostureEvidenceStream {
    <#
    .SYNOPSIS
        Abandons an evidence stream after a failure: closes the files and removes them, so no half-written JSON is
        left for a reader to trip over. The step's failure is what gets reported.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([hashtable] $Stream)

    if (-not $Stream) { return }
    if (-not $PSCmdlet.ShouldProcess($Stream.path, 'Remove the incomplete evidence file')) { return }
    try { $Stream.json.Dispose() } catch { Write-Verbose 'JSON writer already closed.' }
    if ($Stream.csv) { try { $Stream.csv.Dispose() } catch { Write-Verbose 'CSV writer already closed.' } }
    foreach ($p in @($Stream.path, [System.IO.Path]::ChangeExtension($Stream.path, '.csv'))) { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force } }
}
