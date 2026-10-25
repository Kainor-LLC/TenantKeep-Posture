# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureStep {
    <#
    .SYNOPSIS
        Runs one collection step. A failure is logged to errors.txt in the run folder and the run continues.
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

    try {
        return & $Script
    }
    catch {
        # One line per failure in errors.txt, whatever the exception text contains.
        $message = (([string]$_.Exception.Message) -replace '\s*[\r\n]+\s*', ' ').Trim()
        if ($message.Length -gt 600) { $message = $message.Substring(0, 600) + '...' }
        Write-Verbose "$Label failed at $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())`n$($_.ScriptStackTrace)"
        Write-Warning "$Label failed: $message"
        Add-Content -Path (Join-Path $Folder 'errors.txt') -Value "$Label :: $message"
        return
    }
}
