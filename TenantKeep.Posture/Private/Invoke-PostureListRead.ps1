# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# A long Graph list that carries on where it stopped. The users of a large tenant are thousands of pages and an hour
# or more of reading; a sign-in that ends, a network that drops or a process that is killed in page 2,400 used to
# cost all of it. Every few pages the read now saves a cursor (logs/cursor-<list>.json): the link to the next page,
# how far each file being written has got, and the tallies the step keeps. The next attempt cuts the files back to
# the cursor, puts the tallies back and asks Graph for the next page.
#
# What makes a cursor safe to carry on from:
#   - It is a snapshot at a page boundary: the files, the tallies and the link were saved together, the files
#     first, and the cursor is written whole or not at all.
#   - It is for the same request (URI and API version) and the same inputs (-ListKey: what the step's tallies
#     depend on that is not in the list itself, such as who holds a role).
#   - It is less than a day old ($script:PostureKeepHours). An older one is dropped and the list is read again,
#     so a run never joins last week's first half to today's second half.
#   - Graph still honours the link. When it refuses it, that list alone starts over.
$script:PostureKeepHours = 24

function ConvertFrom-PostureJsonExact {
    <#
    .SYNOPSIS
        JSON text as ordered dictionaries, lists and plain values, with every string left a string.
    .DESCRIPTION
        ConvertFrom-Json turns any string that looks like a date into a DateTime, which changes how a row saved in
        a cursor is written out afterwards. A cursor has to give back what it was given.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter(Mandatory)] [string] $Json)

    $document = [System.Text.Json.JsonDocument]::Parse($Json)
    try { return , (ConvertFrom-PostureJsonElement -Element $document.RootElement) }
    finally { $document.Dispose() }
}

function ConvertFrom-PostureJsonElement {
    <#
    .SYNOPSIS
        One JSON element as a PowerShell value: an object as an ordered dictionary, an array as a list, a whole
        number as a long, any other number as a double.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter(Mandatory)] [System.Text.Json.JsonElement] $Element)

    switch ($Element.ValueKind) {
        ([System.Text.Json.JsonValueKind]::Object) {
            $object = [ordered]@{}
            foreach ($property in $Element.EnumerateObject()) { $object[$property.Name] = ConvertFrom-PostureJsonElement -Element $property.Value }
            return $object
        }
        ([System.Text.Json.JsonValueKind]::Array) {
            $list = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $Element.EnumerateArray()) { $list.Add((ConvertFrom-PostureJsonElement -Element $item)) }
            return , $list
        }
        ([System.Text.Json.JsonValueKind]::String) { return $Element.GetString() }
        ([System.Text.Json.JsonValueKind]::Number) {
            [long]$whole = 0
            if ($Element.GetRawText() -notmatch '[.eE]' -and $Element.TryGetInt64([ref]$whole)) { return $whole }
            return $Element.GetDouble()
        }
        ([System.Text.Json.JsonValueKind]::True) { return $true }
        ([System.Text.Json.JsonValueKind]::False) { return $false }
        default { return $null }
    }
}

function Get-PostureSetKey {
    <#
    .SYNOPSIS
        A short key for a set of names (who holds a role, say): the same set gives the same key whatever its order
        or case. A step puts it in its -ListKey and -KeepKey, so what it read is kept only while the set is the same.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [AllowEmptyCollection()] [object] $Value)

    $names = @(@($Value) | Where-Object { $null -ne $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($names -join "`n"))
    return "$($names.Count):" + [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes), 0, 8)
}

function Get-PostureListCursor {
    <#
    .SYNOPSIS
        The cursor a list read left in the run, when there is one that can still be carried on from: it parses, it is
        less than a day old, and every file it points into is there and at least as long as the cursor says.
        Nothing otherwise.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.IDictionary])]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [string] $ListName
    )

    $path = Join-Path (Get-PostureRunLayout -Folder $Folder).logs "cursor-$ListName.json"
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try { $cursor = ConvertFrom-PostureJsonExact -Json ([System.IO.File]::ReadAllText($path)) } catch { return $null }
    if ($cursor -isnot [System.Collections.IDictionary] -or [string]$cursor['list'] -ne $ListName -or -not $cursor['nextLink']) { return $null }
    $saved = [datetime]::MinValue
    if (-not [datetime]::TryParse([string]$cursor['savedUtc'], [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$saved)) { return $null }
    if (([datetime]::UtcNow - $saved).TotalHours -gt $script:PostureKeepHours) { return $null }
    foreach ($mark in @($cursor['streams'])) {
        $json = Join-Path $Folder "$([string]$mark['name']).json.part"
        if (-not (Test-Path -LiteralPath $json) -or (Get-Item -LiteralPath $json).Length -lt [long]$mark['jsonBytes']) { return $null }
        if ($null -ne $mark['csvBytes']) {
            $csv = Join-Path $Folder "$([string]$mark['name']).csv.part"
            if (-not (Test-Path -LiteralPath $csv) -or (Get-Item -LiteralPath $csv).Length -lt [long]$mark['csvBytes']) { return $null }
        }
    }
    return $cursor
}

function Invoke-PostureListRead {
    <#
    .SYNOPSIS
        Reads a paged Graph list into evidence streams a page at a time, saving a cursor every few pages, and
        carries on from the cursor an earlier attempt left. Returns @{ files; pages; resumed; restarted }.
    .DESCRIPTION
        -ListOnPage is called with each page's items, the page's @{ number; count; nextLink } and the open streams
        by name; it writes rows with Add-PostureEvidenceRow and counts into the dictionaries and lists named in
        -ListState. Those are saved with the cursor and put back, in place, when a read carries on, so the step
        goes on counting as if it had never stopped. A value in -ListState must be a dictionary, a list or a set
        of strings, holding only what JSON holds (text, numbers, true and false, and more of the same).

        Every parameter and local here starts with "list" on purpose. The page block runs inside this function,
        so a name it shares with the step that wrote it would be this function's value, not the step's.

        When the read fails, what was written stays in the .part files with the cursor, for the next attempt.
        Without a cursor (the failure came in the first pages) the unfinished files are removed, as before.
    .PARAMETER ListKey
        What the step's tallies depend on besides the list itself. A cursor saved under another key is not used.
    .PARAMETER ListOnResume
        Called with the streams after a cursor is restored and before the next page is asked for, for anything
        the step rebuilds itself instead of keeping in -ListState.
    #>
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'One line that says a list is carrying on from where it stopped, a user-facing CLI convention.')]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [string] $ListName,
        [Parameter(Mandatory)] [string] $ListUri,
        [Parameter(Mandatory)] [ValidateSet('v1.0', 'beta')] [string] $ListApi,
        [string] $ListLabel,
        [Parameter(Mandatory)] [string[]] $ListStream,
        [System.Collections.IDictionary] $ListState = @{},
        [string] $ListKey = '',
        [Parameter(Mandatory)] [scriptblock] $ListOnPage,
        [scriptblock] $ListOnResume,
        [hashtable] $ListHeaders,
        [ValidateRange(1, 1000)] [int] $ListEvery = 10
    )

    $ErrorActionPreference = 'Stop'
    # Refused here, before anything is read: a tally a cursor cannot put back would go on counting from the wrong
    # number after a restart, and nothing would say so.
    foreach ($listTally in @($ListState.get_Keys())) {
        $listInto = $ListState[$listTally]
        if ($listInto -isnot [System.Collections.IDictionary] -and $listInto -isnot [System.Collections.Generic.HashSet[string]] -and $listInto -isnot [System.Collections.IList]) {
            throw "The tally '$listTally' of $ListName is a $(if ($null -eq $listInto) { 'null' } else { $listInto.GetType().Name }). A cursor restores dictionaries, lists and sets of strings: keep a count inside a dictionary."
        }
    }
    $listCursorPath = Join-Path (Get-PostureRunLayout -Folder $Folder).logs "cursor-$ListName.json"
    $listStreams = @{}
    $listRun = @{ pages = 0; sinceSave = 0; lastSave = [datetime]::UtcNow; sinceStart = 0; resumed = $false; restarted = $false; saved = $false }
    # The tallies as the step handed them over, to put back if a list has to start over.
    $listInitial = ConvertFrom-PostureJsonExact -Json (ConvertTo-Json -InputObject $ListState -Depth 20 -Compress)
    $listRestore = {
        param($listFrom)
        foreach ($listTally in @($ListState.get_Keys())) {
            $listInto = $ListState[$listTally]
            $listSaved = $(if ($listFrom -is [System.Collections.IDictionary] -and $listFrom.Contains($listTally)) { $listFrom[$listTally] } else { $null })
            if ($listInto -is [System.Collections.IDictionary]) { $listInto.Clear(); if ($listSaved -is [System.Collections.IDictionary]) { foreach ($listEntry in @($listSaved.get_Keys())) { $listInto[$listEntry] = $listSaved[$listEntry] } } }
            elseif ($listInto -is [System.Collections.Generic.HashSet[string]]) { $listInto.Clear(); foreach ($listItem in @($listSaved)) { $null = $listInto.Add([string]$listItem) } }
            else { $listInto.Clear(); foreach ($listItem in @($listSaved)) { $null = $listInto.Add($listItem) } }
        }
    }
    $listOpenFresh = {
        foreach ($listOne in @($listStreams.get_Values())) { Stop-PostureEvidenceStream -Stream $listOne -Confirm:$false }
        $listStreams.Clear()
        if (Test-Path -LiteralPath $listCursorPath) { Remove-Item -LiteralPath $listCursorPath -Force }
        foreach ($listOne in $ListStream) { $listStreams[$listOne] = Open-PostureEvidenceStream -Folder $Folder -Name $listOne -Csv -Confirm:$false }
        $listRun.saved = $false
    }
    $listSaveCursor = {
        param([string] $listNext)
        # The files first, then the cursor that points into them: a cursor never points past what is on disk.
        $listMarks = @(foreach ($listOne in $ListStream) { Get-PostureEvidenceStreamMark -Stream $listStreams[$listOne] })
        Save-PostureJsonFile -Path $listCursorPath -Confirm:$false -InputObject ([ordered]@{
                list = $ListName; uri = $ListUri; api = $ListApi; key = $ListKey; savedUtc = [datetime]::UtcNow.ToString('o'); pages = $listRun.pages
                nextLink = $listNext; streams = $listMarks; state = $ListState
            })
        $listRun.sinceSave = 0; $listRun.lastSave = [datetime]::UtcNow; $listRun.saved = $true
    }
    $listPageBlock = {
        param($listPage, $listInfo)
        & $ListOnPage $listPage $listInfo $listStreams
        $listRun.pages++; $listRun.sinceSave++; $listRun.sinceStart++
        if ($listInfo.nextLink -and ($listRun.sinceSave -ge $ListEvery -or ([datetime]::UtcNow - $listRun.lastSave).TotalSeconds -ge 60)) { & $listSaveCursor ([string]$listInfo.nextLink) }
    }

    # Carry on from a cursor when there is one for this request and these inputs.
    $listStart = $null
    $listCursor = Get-PostureListCursor -Folder $Folder -ListName $ListName
    if ($listCursor -and [string]$listCursor['uri'] -eq $ListUri -and [string]$listCursor['api'] -eq $ListApi -and [string]$listCursor['key'] -eq $ListKey -and
        (@($listCursor['streams'] | ForEach-Object { [string]$_['name'] }) -join '|') -eq ($ListStream -join '|')) {
        try {
            foreach ($listMark in @($listCursor['streams'])) { $listStreams[[string]$listMark['name']] = Resume-PostureEvidenceStream -Folder $Folder -Mark $listMark }
            & $listRestore $listCursor['state']
            if ($ListOnResume) { & $ListOnResume $listStreams }
            $listStart = [string]$listCursor['nextLink']
            $listRun.pages = [int]$listCursor['pages']; $listRun.resumed = $true; $listRun.saved = $true
            $listRows = [long](@($listCursor['streams'])[0]['count'])
            Write-Host "$(if ($ListLabel) { $ListLabel } else { $ListName }): carrying on from page $('{0:N0}' -f ($listRun.pages + 1)) ($('{0:N0}' -f $listRows) rows already read)"
            Write-PostureJournal -Folder $Folder -Entry @{ kind = 'list'; state = 'resumed'; list = $ListName; collector = [string]$script:PostureCurrentCollector; step = [string]$script:PostureCurrentStep; pages = $listRun.pages; rows = $listRows }
        }
        catch {
            Write-Verbose "$ListName could not carry on from its cursor ($($_.Exception.Message)); reading it from the start."
            & $listRestore $listInitial
            $listStart = $null; $listRun.pages = 0; $listRun.resumed = $false
        }
    }
    if (-not $listStart) { & $listOpenFresh }

    try {
        # The API version is written on each call, not carried in the splat: every Graph call in the module names
        # its version where it is made (a test reads the source for it).
        $listArgs = @{ Uri = $ListUri; Label = $(if ($ListLabel) { $ListLabel } else { $ListName }); OnPage = $listPageBlock }
        if ($ListHeaders) { $listArgs.Headers = $ListHeaders }
        try {
            if ($listStart) { $null = Invoke-PostureGraphRequest @listArgs -ApiVersion $ListApi -StartAt $listStart } else { $null = Invoke-PostureGraphRequest @listArgs -ApiVersion $ListApi }
        }
        catch {
            # A link Graph no longer honours starts this list over: Graph answers Bad Request, Not Found or Gone to
            # the first request after carrying on. (verify) which of the three an expired link gets; all are taken.
            # The status is read from the words of the answer, never from a number that happens to be in the link.
            # Anything else, and anything after a page has come back, is the read's failure and keeps the cursor.
            $listRefused = [regex]::Match([string]$_.Exception.Message, 'does not indicate success: (BadRequest|NotFound|Gone)\b')
            if (-not ($listStart -and $listRun.sinceStart -eq 0 -and $listRefused.Success)) { throw }
            $listStatus = $listRefused.Groups[1].Value
            Write-Warning "$(if ($ListLabel) { $ListLabel } else { $ListName }): Microsoft Graph no longer accepts the page link the read stopped at; reading this list from the start."
            Write-PostureJournal -Folder $Folder -Entry @{ kind = 'list'; state = 'restarted'; list = $ListName; collector = [string]$script:PostureCurrentCollector; step = [string]$script:PostureCurrentStep; status = $listStatus }
            & $listRestore $listInitial
            & $listOpenFresh
            $listRun.pages = 0; $listRun.resumed = $false; $listRun.restarted = $true
            $null = Invoke-PostureGraphRequest @listArgs -ApiVersion $ListApi
        }
        $listFiles = @(foreach ($listOne in $ListStream) { Close-PostureEvidenceStream -Stream $listStreams[$listOne] })
        if (Test-Path -LiteralPath $listCursorPath) { Remove-Item -LiteralPath $listCursorPath -Force }
        return @{ files = $listFiles; pages = $listRun.pages; resumed = $listRun.resumed; restarted = $listRun.restarted }
    }
    catch {
        # With a cursor on disk, what was read stays for the next attempt to carry on from. Without one there is
        # nothing to carry on from, and the unfinished files go.
        foreach ($listOne in @($listStreams.get_Values())) {
            if ($listRun.saved) { Suspend-PostureEvidenceStream -Stream $listOne } else { Stop-PostureEvidenceStream -Stream $listOne -Confirm:$false }
        }
        throw
    }
}
