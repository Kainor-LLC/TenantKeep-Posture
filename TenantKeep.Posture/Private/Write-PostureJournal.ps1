# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# The run's journal: logs/journal.jsonl, one line for everything a collection did, in the order it happened. A step
# started, finished or failed; a file was written, with its rows and bytes; a collector finished. It is appended
# under the folder's lock, so the processes that collect into one folder at the same time share it.
#
# What reads it:
#   - Resume-PostureRun: a collector the journal says finished is not collected again, even when the process that
#     ran it died before it wrote collection.json.
#   - The evidence readers: a file left from an earlier attempt, whose step ran again and did not write it, is not
#     read as this attempt's evidence (Get-PostureStaleEvidence).
#   - Run Health: what was started and never finished.
# A run folder without a journal (made before 2026-11-21, or by a collector run on its own outside
# Invoke-PostureCollection) is read as before: every file in it is taken as it is.
$script:PostureJournalFolder = $null
$script:PostureCurrentStep = $null
$script:PostureStaleCache = @{}

function Write-PostureJournal {
    <#
    .SYNOPSIS
        Appends one entry to the run's journal. Does nothing when no collection has opened a journal for the folder.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Entry
    )

    if (-not $script:PostureJournalFolder) { return }
    $layout = Get-PostureRunLayout -Folder $Folder
    if ($layout.evidence -ne (Get-PostureRunLayout -Folder $script:PostureJournalFolder).evidence) { return }
    $line = [ordered]@{ timeUtc = [datetime]::UtcNow.ToString('o'); process = $PID }
    foreach ($k in $Entry.get_Keys()) { $line[[string]$k] = $Entry[$k] }
    $text = ConvertTo-Json -InputObject $line -Compress -Depth 6
    # A journal that cannot be written must never stop the collection it describes.
    try { Invoke-PostureFolderLock -Folder $Folder -Script { Add-Content -LiteralPath (Join-Path $layout.logs 'journal.jsonl') -Value $text } }
    catch { Write-Verbose "Journal entry not written: $($_.Exception.Message)" }
}

function Read-PostureJournal {
    <#
    .SYNOPSIS
        The journal's entries in order, each a dictionary. Empty when the run has no journal; a line that does not
        parse (a process killed while writing it) is left out.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [string] $Folder)

    $path = Join-Path (Get-PostureRunLayout -Folder $Folder).logs 'journal.jsonl'
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($line in [System.IO.File]::ReadLines($path)) {
        if (-not $line.Trim()) { continue }
        try { $entries.Add((ConvertFrom-Json -InputObject $line -AsHashtable -Depth 6)) } catch { Write-Verbose 'A journal line did not parse and is left out.' }
    }
    return $entries.ToArray()
}

function Get-PostureJournalState {
    <#
    .SYNOPSIS
        What the journal adds up to: present, the latest state of every step (state, attempt start, cause), the
        collectors that finished, and for every evidence file the step that wrote it last and when in the order.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Folder)

    $state = @{ present = $false; steps = @{}; collectors = @{}; files = @{} }
    $entries = @(Read-PostureJournal -Folder $Folder)
    if ($entries.Count -eq 0) { return $state }
    $state.present = $true
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $e = $entries[$i]
        switch ([string]$e['kind']) {
            'step' {
                $key = "$([string]$e['collector'])|$([string]$e['step'])"
                if (-not $state.steps.ContainsKey($key)) { $state.steps[$key] = @{ collector = [string]$e['collector']; step = [string]$e['step']; state = $null; started = -1; cause = $null; message = $null; doneUtc = $null; key = $null; files = [System.Collections.Generic.List[object]]::new() } }
                $s = $state.steps[$key]
                # A step that was kept (done in an earlier attempt, its files as it left them) is still done, when it was done.
                if ([string]$e['state'] -eq 'kept') { continue }
                $s.state = [string]$e['state']
                if ($s.state -eq 'started') { $s.started = $i; $s.cause = $null; $s.message = $null; $s.doneUtc = $null; $s.key = $null; $s.files = [System.Collections.Generic.List[object]]::new() }
                elseif ($s.state -eq 'failed') { $s.cause = [string]$e['cause']; $s.message = [string]$e['message'] }
                elseif ($s.state -eq 'done') { $s.doneUtc = [string]$e['timeUtc']; $s.key = [string]$e['key'] }
            }
            'collector' { $state.collectors[[string]$e['collector']] = @{ state = [string]$e['state']; at = $i; timeUtc = [string]$e['timeUtc'] } }
            'file' {
                $state.files[[string]$e['name']] = @{ step = [string]$e['step']; collector = [string]$e['collector']; at = $i; rows = $e['rows']; bytes = $e['bytes'] }
                # Under its step too, for the attempt that is running: what a done step wrote is what must still be there to keep it.
                $owner = "$([string]$e['collector'])|$([string]$e['step'])"
                if ($e['step'] -and $state.steps.ContainsKey($owner)) { $state.steps[$owner].files.Add(@{ name = [string]$e['name']; rows = $e['rows']; bytes = $e['bytes'] }) }
            }
        }
    }
    return $state
}

function Get-PostureKeptStep {
    <#
    .SYNOPSIS
        Whether a long step's earlier result in this run can be kept instead of reading it again: the record of
        what it wrote (files, when it finished), or nothing.
    .DESCRIPTION
        A step is kept when all of this holds:
          - a collection is running into this folder and its journal says the step's latest attempt finished;
          - it finished under the same key (-Key: what the step's result depends on besides the tenant, such as
            who holds a role or how many days count as stale);
          - it finished less than a day ago ($script:PostureKeepHours), so a run never mixes last week's list
            with today's;
          - every file it wrote is still there, the length it was when written.
        Otherwise the step runs again. A run with no journal keeps nothing.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [string] $Label,
        [string] $Key = ''
    )

    if (-not $script:PostureJournalFolder) { return $null }
    $layout = Get-PostureRunLayout -Folder $Folder
    if ($layout.evidence -ne (Get-PostureRunLayout -Folder $script:PostureJournalFolder).evidence) { return $null }
    $step = (Get-PostureJournalState -Folder $Folder).steps["$([string]$script:PostureCurrentCollector)|$Label"]
    if (-not $step -or $step.state -ne 'done' -or [string]$step.key -ne $Key -or $step.files.Count -eq 0) { return $null }
    $done = [datetime]::MinValue
    if (-not [datetime]::TryParse([string]$step.doneUtc, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$done)) { return $null }
    if (([datetime]::UtcNow - $done).TotalHours -gt $script:PostureKeepHours) { return $null }
    # The last record of each name: a step may write a file twice.
    $latest = [ordered]@{}
    foreach ($f in $step.files) { $latest[[string]$f.name] = $f }
    foreach ($f in $latest.get_Values()) {
        $item = Get-Item -LiteralPath (Join-Path $layout.evidence "$([string]$f.name).json") -ErrorAction SilentlyContinue
        if (-not $item -or $item.Length -ne [long]$f.bytes) { return $null }
    }
    return @{ step = $Label; doneUtc = $done; files = @($latest.get_Values()) }
}

function Get-PostureStaleEvidence {
    <#
    .SYNOPSIS
        The evidence files in the folder that are left from an earlier attempt: names (no extension) whose step ran
        again later and did not write them. Empty for a run with no journal.
    .DESCRIPTION
        A step that ran and failed leaves the file its earlier attempt wrote. Read as it is, that file answers
        today's checks with last week's tenant, or with the tenant before the permission was taken away. A file
        is current when it was written during the latest attempt of its step, whether or not the step then
        finished (a step may write what it could read and then fail on purpose, saying what it could not).
        Cached by the journal's size and time, because every evidence read asks.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [string] $Folder)

    $layout = Get-PostureRunLayout -Folder $Folder
    $path = Join-Path $layout.logs 'journal.jsonl'
    $item = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if (-not $item) { return @() }
    $key = "$($item.FullName)|$($item.Length)|$($item.LastWriteTimeUtc.Ticks)"
    if ($script:PostureStaleCache.ContainsKey($key)) { return $script:PostureStaleCache[$key] }
    $state = Get-PostureJournalState -Folder $Folder
    $stale = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $state.files.get_Keys()) {
        $file = $state.files[$name]
        if (-not $file.step) { continue }
        $step = $state.steps["$($file.collector)|$($file.step)"]
        if ($step -and $step.started -gt $file.at) { $stale.Add(($name -replace '\.(json|csv)$', '')) }
    }
    $result = [string[]]@($stale | Sort-Object -Unique)
    $script:PostureStaleCache.Clear()
    $script:PostureStaleCache[$key] = $result
    return $result
}
