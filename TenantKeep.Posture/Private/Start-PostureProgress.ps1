# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# Run progress: which domain is collecting, which step, how long so far and roughly how long is left. Every
# collection step (Invoke-PostureStep) advances it; with no run started these functions do nothing, so the
# collectors behave the same when called on their own.

# Rough seconds and step counts per phase for a first run, before this tenant has timings of its own (verify:
# taken from the Kainor and first-customer runs of October 2026; a large tenant takes longer, which the rate
# correction below picks up as soon as a phase is under way).
$script:PostureProgressDefaults = [ordered]@{
    ConditionalAccess = @{ seconds = 30; steps = 1; label = 'Conditional Access' }
    Entra             = @{ seconds = 240; steps = 26; label = 'Entra ID' }
    Intune            = @{ seconds = 180; steps = 18; label = 'Intune' }
    Defender          = @{ seconds = 120; steps = 6; label = 'Defender' }
    Azure             = @{ seconds = 120; steps = 13; label = 'Azure' }
    SharePoint        = @{ seconds = 300; steps = 3; label = 'SharePoint and OneDrive' }
    Teams             = @{ seconds = 60; steps = 1; label = 'Teams' }
    Purview           = @{ seconds = 180; steps = 1; label = 'Purview' }
    Exchange          = @{ seconds = 300; steps = 5; label = 'Exchange Online' }
    Second            = @{ seconds = 1; steps = 1; label = 'Exchange and Purview' }
    Report            = @{ seconds = 40; steps = 1; label = 'Profile and report' }
}
$script:PostureProgress = $null
$script:PostureStepCount = 0

function Start-PostureProgress {
    <#
    .SYNOPSIS
        Starts the progress display for a run: the phases in order, each with its expected seconds and steps.
        -File writes the state to a file instead of the console (the second process; the parent draws it).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string[]] $Phase,
        [hashtable] $Estimate = @{},
        [string] $File,
        [string] $ChildFile,
        [string] $Activity = 'TenantKeep Posture'
    )

    $ErrorActionPreference = 'Stop'
    if (-not $PSCmdlet.ShouldProcess($Activity, 'Show progress')) { return }
    $phases = [System.Collections.Generic.List[hashtable]]::new()
    $fromRun = $false
    foreach ($name in $Phase) {
        $d = $(if ($script:PostureProgressDefaults.Contains($name)) { $script:PostureProgressDefaults[$name] } else { @{ seconds = 60; steps = 1; label = $name } })
        $e = $(if ($Estimate.ContainsKey($name)) { $fromRun = $true; $Estimate[$name] } else { $d })
        $phases.Add(@{ name = $name; label = $d.label; seconds = [double][Math]::Max(1, [double]$e.seconds); steps = [int][Math]::Max(1, [int]$e.steps); done = $false; startedUtc = $null; stepsDone = 0 })
    }
    $script:PostureProgress = @{
        activity = $Activity; startedUtc = [datetime]::UtcNow; phases = $phases; current = -1; label = ''
        file = $File; childFile = $ChildFile; fromRun = $fromRun; lastDraw = [datetime]::MinValue
    }
    Write-PostureProgress -Force
}

function Set-PostureProgressPhase {
    <#
    .SYNOPSIS
        Moves the display to a phase: the ones before it count as done. Nothing happens when no run is shown.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [string] $Label
    )

    $ErrorActionPreference = 'Stop'
    $p = $script:PostureProgress
    if (-not $p) { return }
    if (-not $PSCmdlet.ShouldProcess($Name, 'Show phase')) { return }
    $index = -1
    for ($i = 0; $i -lt $p.phases.Count; $i++) { if ($p.phases[$i].name -eq $Name) { $index = $i; break } }
    if ($index -lt 0) { return }
    for ($i = 0; $i -lt $index; $i++) { $p.phases[$i].done = $true }
    $p.current = $index
    $p.phases[$index].startedUtc = [datetime]::UtcNow
    $p.phases[$index].stepsDone = 0
    $p.label = $(if ($Label) { $Label } else { 'starting' })
    Write-PostureProgress -Force
}

function Step-PostureProgress {
    <#
    .SYNOPSIS
        One collection step starts: counts it for the run timings and redraws the display with its label.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)] [string] $Label)

    $ErrorActionPreference = 'Stop'
    $script:PostureStepCount++
    $p = $script:PostureProgress
    if (-not $p -or $p.current -lt 0) { return }
    if (-not $PSCmdlet.ShouldProcess($Label, 'Show step')) { return }
    $p.phases[$p.current].stepsDone++
    $p.label = $Label
    Write-PostureProgress
}

function Get-PostureProgressState {
    <#
    .SYNOPSIS
        Elapsed and remaining seconds, the percentage and the current phase, from the phases' estimates. The
        remaining time of the phase under way is corrected by its own pace once a step or two has run.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $p = $script:PostureProgress
    $now = [datetime]::UtcNow
    $remaining = 0.0
    for ($i = 0; $i -lt $p.phases.Count; $i++) {
        $ph = $p.phases[$i]
        if ($ph.done) { continue }
        if ($i -eq $p.current -and $ph.startedUtc) {
            $elapsed = ($now - $ph.startedUtc).TotalSeconds
            $fraction = [Math]::Min(0.95, $ph.stepsDone / $ph.steps)
            $byPace = $(if ($ph.stepsDone -ge 2 -and $fraction -gt 0) { $elapsed / $fraction * (1 - $fraction) } else { $null })
            $byEstimate = [Math]::Max(0, $ph.seconds - $elapsed)
            $remaining += $(if ($null -ne $byPace) { [Math]::Max($byPace, 5) } else { [Math]::Max($byEstimate, 5) })
        }
        elseif ($i -gt $p.current) { $remaining += $ph.seconds }
    }
    $elapsedAll = ($now - $p.startedUtc).TotalSeconds
    $child = $null
    if ($p.childFile -and (Test-Path -LiteralPath $p.childFile)) {
        try { $child = Get-Content -Raw -LiteralPath $p.childFile | ConvertFrom-Json -AsHashtable } catch { $child = $null }
        # The second process runs alongside: the run ends when the slower of the two does.
        if ($child -and $child['state'] -ne 'done') { $remaining = [Math]::Max($remaining, [double]$child['secondsRemaining']) }
    }
    $percent = $(if ($elapsedAll + $remaining -gt 0) { [int][Math]::Min(99, 100 * $elapsedAll / ($elapsedAll + $remaining)) } else { 0 })
    $phase = $(if ($p.current -ge 0) { $p.phases[$p.current] } else { $null })
    return @{
        elapsed = $elapsedAll; remaining = $remaining; percent = $percent; child = $child
        phase = $(if ($phase) { $phase.label } else { 'Starting' }); phaseIndex = $p.current + 1; phaseCount = $p.phases.Count; label = $p.label
    }
}

function Format-PostureDuration {
    <#
    .SYNOPSIS
        Seconds as "4m 10s" or "1h 05m".
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([double] $Seconds)
    $t = [timespan]::FromSeconds([Math]::Max(0, [Math]::Round($Seconds)))
    if ($t.TotalHours -ge 1) { return '{0}h {1:00}m' -f [int][Math]::Floor($t.TotalHours), $t.Minutes }
    if ($t.TotalMinutes -ge 1) { return '{0}m {1:00}s' -f [int][Math]::Floor($t.TotalMinutes), $t.Seconds }
    return '{0}s' -f $t.Seconds
}

function Write-PostureProgress {
    <#
    .SYNOPSIS
        Draws the run's progress bar (and the second process's, from its file), or writes the state to the file
        in the second process. At most four redraws a second unless forced.
    #>
    [CmdletBinding()]
    param([switch] $Force)

    $p = $script:PostureProgress
    if (-not $p) { return }
    $now = [datetime]::UtcNow
    if (-not $Force -and ($now - $p.lastDraw).TotalMilliseconds -lt 250) { return }
    $p.lastDraw = $now
    $s = Get-PostureProgressState
    $left = $(if ($p.fromRun) { "about $(Format-PostureDuration $s.remaining) left" } else { "about $(Format-PostureDuration $s.remaining) left (first run, rough)" })
    if ($p.file) {
        $doc = [ordered]@{ state = 'running'; phase = $s.phase; label = $s.label; percent = $s.percent; secondsRemaining = [int]$s.remaining; updatedUtc = $now.ToString('o') }
        if ($p.Contains('state') -and $p.state) { $doc.state = $p.state }
        $tmp = "$($p.file).tmp"
        try { Set-Content -LiteralPath $tmp -Value ($doc | ConvertTo-Json -Compress); Move-Item -LiteralPath $tmp -Destination $p.file -Force } catch { Write-Verbose "Progress file not written: $($_.Exception.Message)" }
        return
    }
    $status = "$($s.phase) ($($s.phaseIndex) of $($s.phaseCount)): $($s.label)"
    Write-Progress -Id 1 -Activity $p.activity -Status $status -PercentComplete $s.percent -CurrentOperation "$(Format-PostureDuration $s.elapsed) so far, $left"
    if ($s.child) {
        $c = $s.child
        if ($c['state'] -eq 'done') { Write-Progress -Id 2 -ParentId 1 -Activity 'Exchange and Purview (second process)' -Completed }
        else { Write-Progress -Id 2 -ParentId 1 -Activity 'Exchange and Purview (second process)' -Status "$($c['phase']): $($c['label'])" -PercentComplete ([int]$c['percent']) }
    }
}

function Complete-PostureProgress {
    <#
    .SYNOPSIS
        Ends the display. In the second process, writes the final state so the parent's bar closes.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $p = $script:PostureProgress
    if (-not $p) { return }
    if (-not $PSCmdlet.ShouldProcess($p.activity, 'End progress')) { return }
    if ($p.file) { $p.state = 'done'; foreach ($ph in $p.phases) { $ph.done = $true }; Write-PostureProgress -Force }
    else { Write-Progress -Id 2 -Activity 'Exchange and Purview (second process)' -Completed; Write-Progress -Id 1 -Activity $p.activity -Completed }
    $script:PostureProgress = $null
}

function Get-PostureRunEstimate {
    <#
    .SYNOPSIS
        Seconds and steps per phase from the newest earlier run of this tenant that recorded timings, for the
        progress estimate. Empty when there is none.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $OutRoot,
        [Parameter(Mandatory)] [string] $TenantId
    )

    $ErrorActionPreference = 'Stop'
    $out = @{}
    if (-not (Test-Path -LiteralPath $OutRoot -PathType Container)) { return $out }
    foreach ($run in @(Get-ChildItem -LiteralPath $OutRoot -Directory | Where-Object { $_.Name -match '^\d{8}-\d{4}$' } | Sort-Object Name -Descending)) {
        $m = Join-Path $run.FullName 'collection.json'
        if (-not (Test-Path -LiteralPath $m)) { continue }
        try { $doc = Get-Content -Raw -LiteralPath $m | ConvertFrom-Json -AsHashtable -Depth 10 } catch { continue }
        if ([string]$doc['tenantId'] -ne $TenantId -or -not ($doc.Contains('timings') -and $doc['timings'])) { continue }
        foreach ($k in @($doc['timings'].Keys)) { $out[$k] = @{ seconds = [double]$doc['timings'][$k]['seconds']; steps = [int]$doc['timings'][$k]['steps'] } }
        return $out
    }
    return $out
}
