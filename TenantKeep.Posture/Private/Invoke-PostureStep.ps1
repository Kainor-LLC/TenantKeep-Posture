# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureStep {
    <#
    .SYNOPSIS
        Runs one collection step. A failure is logged to errors.txt in the run folder, and to errors.jsonl with its
        cause and the role it needs (requirements.json), and the run continues.
    .DESCRIPTION
        Mirrors Invoke-Step from the audit plan's Appendix A. Permission errors on one endpoint must not abort a
        whole snapshot. Returns the step's output; on failure it returns nothing, so callers wrap the call in @().
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Label,
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [scriptblock] $Script
    )

    $ErrorActionPreference = 'Stop'
    Step-PostureProgress -Label $Label
    $script:PostureLastCall = ''

    # The journal: started, then done or failed. Files the step writes are recorded under its label, and the label
    # of a step that runs inside another is restored when it ends.
    $outerStep = $script:PostureCurrentStep
    $script:PostureCurrentStep = $Label
    $stepClock = [System.Diagnostics.Stopwatch]::StartNew()
    Write-PostureJournal -Folder $Folder -Entry @{ kind = 'step'; state = 'started'; collector = [string]$script:PostureCurrentCollector; step = $Label }
    try {
        $stepOutput = & $Script
        Write-PostureJournal -Folder $Folder -Entry @{ kind = 'step'; state = 'done'; collector = [string]$script:PostureCurrentCollector; step = $Label; seconds = [Math]::Round($stepClock.Elapsed.TotalSeconds, 1) }
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
