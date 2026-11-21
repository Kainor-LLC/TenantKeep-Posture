# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# Evidence is written whole or not at all. Every writer here writes <name>.json.part and <name>.csv.part and renames
# them when the file is complete, so a run that is killed part-way (sleep, a crash, the machine running out of
# memory, a job stopped by its host) never leaves half a list under a name a check would read. Readers open only
# the final names; a .part file is a list that was being written when the run stopped.

function Write-PostureEvidence {
    <#
    .SYNOPSIS
        Writes a JSON evidence file (full fidelity, depth 20, UTF-8 no BOM) and prints one line with the row count.
    .DESCRIPTION
        Mirrors Save-Evidence from the audit plan's Appendix A. Arrays are written as arrays even when they hold one
        item, so downstream readers never have to special-case a single object. The file appears under its name only
        once it is complete.
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
    $csvPath = Join-Path $Folder "$Name.csv"
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    # -InputObject keeps an empty collection as [] instead of writing an empty file; nulls never make it into a list.
    $items = @(@($InputObject) | Where-Object { $null -ne $_ })
    $data = if ($AsArray) { , $items } else { $InputObject }
    if ($null -eq $data) { $data = @{} }
    $json = ConvertTo-Json -InputObject $data -Depth 20
    $withCsv = [bool]($Csv -and $AsArray)
    try {
        [System.IO.File]::WriteAllText("$path.part", $json, $utf8)
        if ($withCsv) {
            if ($items.Count -eq 0) { [System.IO.File]::WriteAllText("$csvPath.part", '', $utf8) }
            else {
                # Export-Csv wants objects with properties; dictionaries make it throw a null reference. Dates go in
                # as ISO 8601 UTC text (ConvertTo-PostureCsvDate): Export-Csv would write them with no zone.
                @(foreach ($item in $items) {
                        if ($item -isnot [System.Collections.IDictionary]) { $item; continue }
                        $copy = [ordered]@{}
                        foreach ($k in $item.get_Keys()) { $val = $item[$k]; $copy[[string]$k] = $(if ($val -is [datetime] -or $val -is [System.DateTimeOffset]) { ConvertTo-PostureCsvDate -Value $val } else { $val }) }
                        [pscustomobject]$copy
                    }) | Export-Csv -Path "$csvPath.part"
            }
            [System.IO.File]::Move("$csvPath.part", $csvPath, $true)
        }
        [System.IO.File]::Move("$path.part", $path, $true)
    }
    catch {
        foreach ($p in "$path.part", "$csvPath.part") { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force } }
        throw
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
        Close-PostureEvidenceStream: until then the rows are in <name>.json.part and <name>.csv.part, which no
        reader opens, so an unfinished list reads as not collected.
    .DESCRIPTION
        Opening removes the list an earlier attempt left under the same name: a second attempt that fails must not
        leave the first attempt's file to be read as this one's.
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
    $csvPath = Join-Path $Folder "$Name.csv"
    if (-not $PSCmdlet.ShouldProcess($path, 'Write evidence')) { return $null }
    foreach ($p in $path, $csvPath, "$path.part", "$csvPath.part") { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force } }
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $json = [System.IO.StreamWriter]::new("$path.part", $false, $utf8, 1MB)
    $json.Write('[')
    $csvWriter = $(if ($Csv) { [System.IO.StreamWriter]::new("$csvPath.part", $false, $utf8, 1MB) } else { $null })
    return @{ name = $Name; path = $path; csvPath = $csvPath; json = $json; csv = $csvWriter; columns = $null; count = [long]0 }
}

function ConvertTo-PostureCsvDate {
    <#
    .SYNOPSIS
        A date as the CSV evidence carries it: ISO 8601 in UTC with the Z, to the fraction of a second it has.
    .DESCRIPTION
        A date written as plain text has no zone ("11/15/2026 02:03:22"), and whoever reads it back has to guess
        one. The JSON twin always had the zone; the CSV now says the same thing.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [object] $Value)

    return (ConvertTo-PostureUtcDateTime $Value).ToString('yyyy-MM-ddTHH:mm:ss.FFFFFFFZ', [cultureinfo]::InvariantCulture)
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
        $quote = { param($value) $s = $(if ($null -eq $value) { '' } elseif ($value -is [bool]) { $(if ($value) { 'True' } else { 'False' }) } elseif ($value -is [datetime] -or $value -is [System.DateTimeOffset]) { ConvertTo-PostureCsvDate -Value $value } else { [string]$value }); '"' + $s.Replace('"', '""') + '"' }
        if (-not $Stream.columns) {
            # get_Keys(), not .Keys: on a dictionary PowerShell answers .Keys with the entry named Keys when the row has one.
            $Stream.columns = @($Row.get_Keys())
            $Stream.csv.WriteLine((@($Stream.columns | ForEach-Object { & $quote $_ }) -join ','))
        }
        $Stream.csv.WriteLine((@($Stream.columns | ForEach-Object { & $quote $Row[$_] }) -join ','))
    }
    $Stream.count++
}

function Close-PostureEvidenceStream {
    <#
    .SYNOPSIS
        Finishes an evidence stream: the files take their names, the row count line every evidence file gets is
        printed, and the JSON path is returned.
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
    if ($Stream.csv) { $Stream.csv.Dispose(); [System.IO.File]::Move("$($Stream.csvPath).part", $Stream.csvPath, $true) }
    [System.IO.File]::Move("$($Stream.path).part", $Stream.path, $true)
    if (-not $Quiet) { Write-Host ('{0,-42} {1,7:N0}' -f "$($Stream.name).json", $Stream.count) }
    return $Stream.path
}

function Stop-PostureEvidenceStream {
    <#
    .SYNOPSIS
        Abandons an evidence stream after a failure: closes the writers and removes what they wrote. The step's
        failure is what gets reported.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([hashtable] $Stream)

    if (-not $Stream) { return }
    if (-not $PSCmdlet.ShouldProcess($Stream.path, 'Remove the incomplete evidence file')) { return }
    try { $Stream.json.Dispose() } catch { Write-Verbose 'JSON writer already closed.' }
    if ($Stream.csv) { try { $Stream.csv.Dispose() } catch { Write-Verbose 'CSV writer already closed.' } }
    foreach ($p in "$($Stream.path).part", "$($Stream.csvPath).part") { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force } }
}

function Get-PostureUnfinishedEvidence {
    <#
    .SYNOPSIS
        The evidence lists that were being written when a run stopped: the names of the .part files in a folder,
        without the extensions. Empty for a run that ended normally.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [string] $Folder)

    if (-not (Test-Path -LiteralPath $Folder -PathType Container)) { return @() }
    return @(Get-ChildItem -LiteralPath $Folder -File -Filter '*.part' | ForEach-Object { $_.Name -replace '\.(json|csv)\.part$', '' } | Sort-Object -Unique)
}
