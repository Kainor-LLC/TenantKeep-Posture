# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# Parsed evidence files, shared by every fact provider and the report model in one evaluation, so a file several
# domains read is parsed once. Only files up to PostureEvidenceCacheLimit are kept: a list with a row per user,
# device or site is read a row at a time (Read-PostureEvidenceRow), and if something does load one whole it must
# not stay in memory for the rest of the run.
$script:PostureEvidenceCache = @{}
$script:PostureEvidenceCacheLimit = 8MB

function Read-PostureEvidenceFile {
    <#
    .SYNOPSIS
        One evidence file, parsed (hashtables, depth 20): $null when it is missing, an empty array when it is empty.
        Cached by path, size and write time until Clear-PostureEvidenceCache, unless the file is larger than
        PostureEvidenceCacheLimit (8 MB): that one is parsed again each time it is asked for, and never kept.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [string] $Name
    )

    $f = Join-Path $Folder "$Name.json"
    $item = Get-Item -LiteralPath $f -ErrorAction SilentlyContinue
    if (-not $item) { return $null }
    $key = "$($item.FullName)|$($item.Length)|$($item.LastWriteTimeUtc.Ticks)"
    if ($script:PostureEvidenceCache.ContainsKey($key)) { return , $script:PostureEvidenceCache[$key] }
    $text = [System.IO.File]::ReadAllText($item.FullName)
    $parsed = $(if ([string]::IsNullOrWhiteSpace($text)) { $null } else { ConvertFrom-Json -InputObject $text -AsHashtable -Depth 20 })
    $text = $null
    # An empty JSON array parses to nothing; keep it distinct from a missing file.
    if ($null -eq $parsed) { $parsed = @() }
    if ($item.Length -le $script:PostureEvidenceCacheLimit) { $script:PostureEvidenceCache[$key] = $parsed }
    return , $parsed
}

function Clear-PostureEvidenceCache {
    <#
    .SYNOPSIS
        Lets the parsed evidence go once an evaluation and its report are done.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess('evidence cache', 'Clear')) { $script:PostureEvidenceCache = @{}; [System.GC]::Collect() }
}

function Find-PostureEvidenceRow {
    <#
    .SYNOPSIS
        The rows of an evidence file whose -Key is one of -Value, as a hashtable keyed by that value, read a row at a
        time from the file's CSV so a 300,000-row list is never loaded to find a handful. $null when the file was not
        collected. Falls back to the JSON (through the cache) when there is no CSV.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Key,
        [AllowEmptyCollection()] [string[]] $Value = @()
    )

    $csv = Join-Path $Folder "$Name.csv"
    $json = Join-Path $Folder "$Name.json"
    if (-not (Test-Path -LiteralPath $csv) -and -not (Test-Path -LiteralPath $json)) { return $null }
    $want = [System.Collections.Generic.HashSet[string]]::new([string[]]@($Value | Where-Object { $_ }), [System.StringComparer]::OrdinalIgnoreCase)
    $out = @{}
    if ($want.Count -eq 0) { return $out }
    if (Test-Path -LiteralPath $csv) {
        # Fields only, no object per row: a handful of rows out of hundreds of thousands is one array index and one
        # set lookup for each row that is not wanted. The parser knows quoted fields, doubled quotes and line
        # breaks inside a field, as Export-Csv and the stream writer write them.
        $parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new($csv, [System.Text.Encoding]::UTF8)
        try {
            $parser.SetDelimiters(','); $parser.HasFieldsEnclosedInQuotes = $true; $parser.TrimWhiteSpace = $false
            if ($parser.EndOfData) { return $out }
            $columns = $parser.ReadFields()
            $at = [array]::IndexOf($columns, $Key)
            if ($at -lt 0) { foreach ($i in 0..($columns.Count - 1)) { if ([string]::Equals($columns[$i], $Key, [System.StringComparison]::OrdinalIgnoreCase)) { $at = $i; break } } }
            if ($at -lt 0) { return $out }
            while (-not $parser.EndOfData) {
                $fields = $parser.ReadFields()
                if ($at -ge $fields.Count) { continue }
                $k = $fields[$at]
                if (-not $k -or -not $want.Contains($k)) { continue }
                $row = [ordered]@{}
                for ($i = 0; $i -lt $columns.Count; $i++) { $row[$columns[$i]] = $(if ($i -lt $fields.Count) { $fields[$i] } else { '' }) }
                $out[$k] = [pscustomobject]$row
            }
        }
        finally { $parser.Dispose() }
        return $out
    }
    # Assigned first: the reader returns the array wrapped so an empty one survives, and @( ) around it would keep the wrapper.
    $all = Read-PostureEvidenceFile -Folder $Folder -Name $Name
    foreach ($row in $all) { if ($row -is [System.Collections.IDictionary]) { $k = [string]$row[$Key]; if ($k -and $want.Contains($k)) { $out[$k] = $row } } }
    return $out
}

function Read-PostureEvidenceRow {
    <#
    .SYNOPSIS
        Hands every row of an evidence list to -OnRow, a row at a time from its CSV, so a check over hundreds of
        thousands of devices or users keeps memory flat; through the cached JSON when there is no CSV. Returns
        $false when the file was not collected. CSV values are text: test booleans with Test-PostureTrue.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [scriptblock] $OnRow
    )

    $csv = Join-Path $Folder "$Name.csv"
    if (Test-Path -LiteralPath $csv) {
        # An empty list writes an empty CSV, which Import-Csv reads as no rows. A process block, not ForEach-Object:
        # the same rows for a fifth less time, which is seconds on a list of hundreds of thousands.
        Import-Csv -LiteralPath $csv | & { process { & $OnRow $_ } }
        return $true
    }
    $all = Read-PostureEvidenceFile -Folder $Folder -Name $Name
    if ($null -eq $all) { return $false }
    foreach ($row in $all) { if ($row) { & $OnRow $row } }
    return $true
}

function Test-PostureTrue {
    <#
    .SYNOPSIS
        True for $true and for the text True, as a CSV row carries it.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] [object] $Value)
    return ($Value -is [bool] -and $Value) -or ([string]$Value -eq 'True')
}
