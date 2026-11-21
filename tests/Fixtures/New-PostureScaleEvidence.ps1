# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.

# A made-up tenant at a size the demo is not: the demo run (fernquill.example) with its large lists grown to a given
# number of users. The rows are written with the module's own evidence writers, so every file has the exact shape
# the collectors write. Synthetic data only; nothing here touches a tenant.
function New-PostureScaleEvidence {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test fixture: writes made-up files under a path the test owns.')]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [int] $Users = 20000,
        # Personal sites added to the site list, as a collection with -IncludeOneDriveSites writes them.
        [int] $OneDrives = 0
    )

    $ErrorActionPreference = 'Stop'
    $made = & (Join-Path $PSScriptRoot '..' '..' 'samples' 'demo' 'New-PostureDemoRun.ps1') -Path $Path
    $ev = $made.Evidence
    $module = Get-Module TenantKeep.Posture
    if (-not $module) { throw 'Import TenantKeep.Posture before calling New-PostureScaleEvidence.' }
    # The other lists in proportion to the users, as the review's 300,000-user tenant had them.
    $devices = [int]($Users / 6); $groups = [int]($Users / 6); $sites = [int]($Users / 15); $mailboxes = [int]($Users / 10)

    $guid = [regex]'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $nameFields = [System.Collections.Generic.HashSet[string]]::new([string[]]@('DisplayName', 'DeviceName', 'Title', 'UserDisplayName', 'SerialNumber', 'Name', 'OwnerName'), [System.StringComparer]::OrdinalIgnoreCase)
    # One template row, made the row of generation $Gen: ids, sign-in names, addresses and names stay unique.
    $scale = {
        param([System.Collections.IDictionary] $Template, [int] $Gen)
        $row = [ordered]@{}
        foreach ($entry in $Template.GetEnumerator()) {
            $k = [string]$entry.Key; $val = $entry.Value
            if ($Gen -gt 0 -and $val -is [string] -and $val) {
                if ($guid.IsMatch($val)) { $val = ('{0:x8}' -f $Gen) + $val.Substring(8) }
                elseif ($val.Contains('@')) { $val = $val.Replace('@', ".g$Gen@") }
                elseif ($val.StartsWith('https://')) { $val = "$val-g$Gen" }
                elseif ($nameFields.Contains($k)) { $val = "$val g$Gen" }
            }
            $row[$k] = $val
        }
        # Graph's own flag: the copies are not administrators.
        if ($Gen -gt 0 -and $row.Contains('IsAdmin')) { $row['IsAdmin'] = $false }
        $row
    }
    $templates = { param([string] $Name) @(Get-Content -Raw -LiteralPath (Join-Path $ev "$Name.json") | ConvertFrom-Json -AsHashtable -Depth 20) }
    $written = [ordered]@{}

    # The lists the collectors stream a row at a time.
    $stream = {
        param([string] $Name, [int] $Count)
        $rows = @(& $templates $Name)
        if ($rows.Count -eq 0) { return }
        & $module {
            param($ev, $Name, $Count, $rows, $scale)
            $s = Open-PostureEvidenceStream -Folder $ev -Name $Name -Csv -Confirm:$false
            try { for ($i = 0; $i -lt $Count; $i++) { Add-PostureEvidenceRow -Stream $s -Row (& $scale $rows[$i % $rows.Count] ([int][Math]::Floor($i / $rows.Count))) } }
            catch { Stop-PostureEvidenceStream -Stream $s -Confirm:$false; throw }
            $null = Close-PostureEvidenceStream -Stream $s -Quiet
        } $ev $Name $Count $rows $scale
        $written[$Name] = $Count
    }
    # The lists the collectors still build in memory and write in one piece.
    $whole = {
        param([string] $Name, [int] $Count)
        $rows = @(& $templates $Name)
        if ($rows.Count -eq 0) { return }
        $all = [System.Collections.Generic.List[object]]::new($Count)
        for ($i = 0; $i -lt $Count; $i++) { $all.Add((& $scale $rows[$i % $rows.Count] ([int][Math]::Floor($i / $rows.Count)))) }
        & $module { param($ev, $Name, $all) $null = Write-PostureEvidence -Folder $ev -Name $Name -InputObject $all.ToArray() -AsArray -Csv -Quiet } $ev $Name $all
        $written[$Name] = $Count
    }

    & $stream '06-users' $Users
    & $stream '06-users-guests' ([int]($Users / 10))
    & $stream '05-auth-registration' $Users
    & $stream '07-groups' $groups
    & $stream '08-entra-devices' ([int]($devices * 1.2))
    & $stream '09-intune-managed-devices' $devices
    & $stream 'exo-09-mailboxes' $mailboxes
    & $stream 'exo-10-cas-mailboxes' $mailboxes
    & $stream 'exo-12-remote-powershell-users' $Users
    if ($OneDrives -le 0) { & $stream 'spo-sites' $sites }
    else {
        # Sites first, then a OneDrive for each of the first $OneDrives users, in the one list.
        $all = @(& $templates 'spo-sites')
        $shared = @($all | Where-Object { -not $_.IsOneDrive }); $personal = @($all | Where-Object { $_.IsOneDrive })
        if ($personal.Count -eq 0) { $personal = @($shared | Select-Object -First 1 | ForEach-Object { $copy = [ordered]@{}; foreach ($e in $_.GetEnumerator()) { $copy[[string]$e.Key] = $e.Value }; $copy.IsOneDrive = $true; $copy.Template = 'SPSPERS#10'; $copy }) }
        & $module {
            param($ev, $sites, $OneDrives, $shared, $personal, $scale)
            $s = Open-PostureEvidenceStream -Folder $ev -Name 'spo-sites' -Csv -Confirm:$false
            try {
                for ($i = 0; $i -lt $sites; $i++) { Add-PostureEvidenceRow -Stream $s -Row (& $scale $shared[$i % $shared.Count] ([int][Math]::Floor($i / $shared.Count))) }
                for ($i = 0; $i -lt $OneDrives; $i++) { Add-PostureEvidenceRow -Stream $s -Row (& $scale $personal[$i % $personal.Count] ([int][Math]::Floor($i / $personal.Count) + 1)) }
            }
            catch { Stop-PostureEvidenceStream -Stream $s -Confirm:$false; throw }
            $null = Close-PostureEvidenceStream -Stream $s -Quiet
        } $ev $sites $OneDrives $shared $personal $scale
        $written['spo-sites'] = $sites + $OneDrives
    }
    & $whole '09-autopilot-devices' ([int]($devices * 0.6))
    & $whole '08-bitlocker-keys-by-device' ([int]($devices * 0.8))
    & $whole 'def-01-devices' $devices
    & $whole 'def-02-av-state' $devices
    & $whole '10-service-principals' ([int]($Users / 30))

    # The users summary the collector writes beside the list, so the facts see the same totals.
    $summaryPath = Join-Path $ev '06-users-summary.json'
    $summary = Get-Content -Raw -LiteralPath $summaryPath | ConvertFrom-Json -AsHashtable
    $factor = $Users / [double]$summary['Total']
    foreach ($k in @($summary.get_Keys())) { if (($summary[$k] -is [long] -or $summary[$k] -is [int]) -and $k -ne 'StaleDays') { $summary[$k] = [int]([double]$summary[$k] * $factor) } }
    [System.IO.File]::WriteAllText($summaryPath, (ConvertTo-Json -InputObject $summary -Depth 5))

    [pscustomobject]@{ Path = $made.Path; Evidence = $ev; Client = $made.Client; Users = $Users; Rows = $written; EvidenceMB = [Math]::Round((Get-ChildItem -LiteralPath $ev -File | Measure-Object Length -Sum).Sum / 1MB, 1) }
}
