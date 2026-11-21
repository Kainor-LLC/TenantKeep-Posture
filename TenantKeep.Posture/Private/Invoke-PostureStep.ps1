# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureStep {
    <#
    .SYNOPSIS
        Runs one collection step. A failure is logged to errors.txt in the run folder, and to errors.jsonl with its
        cause and the role it needs (requirements.json), and the run continues.
    .DESCRIPTION
        Mirrors Invoke-Step from the audit plan's Appendix A. Permission errors on one endpoint must not abort a
        whole snapshot. Returns the step's output; on failure it returns nothing, so callers wrap the call in @().

        With -KeepDone, a step that already finished in this run is not run again when the run is resumed: the
        long lists (users, devices, mailboxes, sites) are hours of reading, and a run that stopped after them, or
        that is collected again for one small step that was refused, should not pay for them twice.
        Get-PostureKeptStep says when a result can be kept. -WhenKept is then called with the record of what the
        step wrote, to put back what later steps need from it; if it throws, the step runs after all.
    .PARAMETER KeepKey
        What the step's result depends on besides the tenant (who holds a role, how many days count as stale). A
        result recorded under another key is not kept.
    #>
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'One line that says a list was kept from earlier in the run, a user-facing CLI convention.')]
    param(
        [Parameter(Mandatory)] [string] $Label,
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [scriptblock] $Script,
        [switch] $KeepDone,
        [string] $KeepKey = '',
        [scriptblock] $WhenKept
    )

    $ErrorActionPreference = 'Stop'
    Step-PostureProgress -Label $Label
    $script:PostureLastCall = ''

    if ($KeepDone) {
        $keptStep = Get-PostureKeptStep -Folder $Folder -Label $Label -Key $KeepKey
        if ($keptStep) {
            try {
                if ($WhenKept) { $null = & $WhenKept $keptStep }
                Write-PostureJournal -Folder $Folder -Entry @{ kind = 'step'; state = 'kept'; collector = [string]$script:PostureCurrentCollector; step = $Label; readUtc = $keptStep.doneUtc.ToString('o') }
                Write-Host ('{0,-42} kept, read {1} UTC' -f $Label, $keptStep.doneUtc.ToString('yyyy-MM-dd HH:mm'))
                return
            }
            catch { Write-Verbose "$Label could not be kept ($($_.Exception.Message)); reading it again." }
        }
    }

    # The journal: started, then done or failed. Files the step writes are recorded under its label, and the label
    # of a step that runs inside another is restored when it ends.
    $outerStep = $script:PostureCurrentStep
    $script:PostureCurrentStep = $Label
    $stepClock = [System.Diagnostics.Stopwatch]::StartNew()
    Write-PostureJournal -Folder $Folder -Entry @{ kind = 'step'; state = 'started'; collector = [string]$script:PostureCurrentCollector; step = $Label }
    try {
        $stepOutput = & $Script
        Write-PostureJournal -Folder $Folder -Entry @{ kind = 'step'; state = 'done'; collector = [string]$script:PostureCurrentCollector; step = $Label; seconds = [Math]::Round($stepClock.Elapsed.TotalSeconds, 1); key = $KeepKey }
        $script:PostureCurrentStep = $outerStep
        return $stepOutput
    }
    catch {
        # One line per failure in errors.txt, whatever the exception text contains.
        $message = (([string]$_.Exception.Message) -replace '\s*[\r\n]+\s*', ' ').Trim()
        if ($message.Length -gt 600) { $message = $message.Substring(0, 600) + '...' }
        Write-Verbose "$Label failed at $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())`n$($_.ScriptStackTrace)"
        Write-Warning "$Label failed: $message"
        Invoke-PostureFolderLock -Folder $Folder -Script { Add-Content -Path (Join-Path (Get-PostureRunLayout -Folder $Folder).errors 'errors.txt') -Value "$Label :: $message" }
        # Where it stopped and the request it was making, for whoever is asked to look (Get-PostureSupportDetail).
        $where = @(([string]$_.ScriptStackTrace) -split "`n" | Where-Object { $_ } | Select-Object -First 4 | ForEach-Object { $_.Trim().Replace([string]$script:ModuleRoot, '<module>') })
        Write-PostureStepFailure -Folder $Folder -Label $Label -Message $message -Where $where -Request ([string]$script:PostureLastCall) -Confirm:$false
        Write-PostureJournal -Folder $Folder -Entry @{ kind = 'step'; state = 'failed'; collector = [string]$script:PostureCurrentCollector; step = $Label; seconds = [Math]::Round($stepClock.Elapsed.TotalSeconds, 1); cause = (Get-PostureFailureCause -Message $message); message = $message }
        $script:PostureCurrentStep = $outerStep
        return
    }
}
