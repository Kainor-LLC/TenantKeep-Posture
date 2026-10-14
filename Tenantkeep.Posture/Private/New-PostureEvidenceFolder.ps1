# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function New-PostureEvidenceFolder {
    <#
    .SYNOPSIS
        Creates <OutRoot>/<yyyyMMdd-HHmm>[-<Suffix>]/ and starts a transcript in it (audit plan Appendix A convention).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $OutRoot,
        [string] $Suffix,
        [datetime] $Timestamp = (Get-Date),
        [switch] $NoTranscript
    )

    $ErrorActionPreference = 'Stop'

    $stamp = $Timestamp.ToString('yyyyMMdd-HHmm')
    $folder = Join-Path $OutRoot $(if ($Suffix) { "$stamp-$Suffix" } else { $stamp })
    if ($PSCmdlet.ShouldProcess($folder, 'Create evidence folder')) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        if (-not $NoTranscript) {
            try { Start-Transcript -Path (Join-Path $folder 'transcript.txt') -Append | Out-Null }
            catch { Write-Verbose "Transcript not started: $($_.Exception.Message)" }
        }
    }
    return $folder
}
