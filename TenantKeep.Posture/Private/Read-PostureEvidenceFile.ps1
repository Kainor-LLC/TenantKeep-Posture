# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# Parsed evidence files, shared by every fact provider and the report model in one evaluation, so a large file
# (06-users.json for a tenant of hundreds of thousands) is read and parsed once instead of once per domain.
$script:PostureEvidenceCache = @{}

function Read-PostureEvidenceFile {
    <#
    .SYNOPSIS
        One evidence file, parsed (hashtables, depth 20): $null when it is missing, an empty array when it is empty.
        Cached by path, size and write time until Clear-PostureEvidenceCache.
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
    $script:PostureEvidenceCache[$key] = $parsed
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
