# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureFolderLock {
    <#
    .SYNOPSIS
        Runs a script block while holding the run folder's lock file, so the two collection processes that write
        into one folder at the same time (errors.txt, the collection.json merge) never interleave.
    .DESCRIPTION
        The lock is an exclusive handle on .tenantkeep.lock in the folder; the other process waits for it, up to
        -TimeoutSeconds, then runs anyway rather than lose its write.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [scriptblock] $Script,
        [int] $TimeoutSeconds = 30
    )

    $ErrorActionPreference = 'Stop'
    $path = Join-Path $Folder '.tenantkeep.lock'
    $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
    $handle = $null
    while (-not $handle) {
        try { $handle = [System.IO.File]::Open($path, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) }
        catch [System.IO.IOException] {
            if ([datetime]::UtcNow -ge $deadline) { Write-Verbose "Lock on $path not taken in $TimeoutSeconds s; writing without it."; break }
            Start-Sleep -Milliseconds 100
        }
    }
    try { return & $Script }
    finally { if ($handle) { $handle.Dispose() } }
}
