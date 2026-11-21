# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# The lock files this process holds now, so a block that holds one can ask for it again.
$script:PostureLocksHeld = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

function Invoke-PostureFolderLock {
    <#
    .SYNOPSIS
        Runs a script block while holding the run folder's lock file, so the two collection processes that write
        into one folder at the same time (errors.txt, the collection.json merge) never interleave.
    .DESCRIPTION
        The lock is an exclusive handle on .tenantkeep.lock in the run's logs folder; the other process waits for it, up to
        -TimeoutSeconds, then runs anyway rather than lose its write. A block that already holds the lock in this
        process and asks again (the manifest writer, whose file write adds a line to the journal) runs at once:
        the handle is exclusive even against its own process, so asking twice would wait out the whole timeout.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [scriptblock] $Script,
        [int] $TimeoutSeconds = 30
    )

    $ErrorActionPreference = 'Stop'
    # In the run's logs folder, so the processes collecting into evidence/ and the ones writing errors/ share it.
    $logs = (Get-PostureRunLayout -Folder $Folder).logs
    if (-not (Test-Path -LiteralPath $logs)) { New-Item -ItemType Directory -Path $logs -Force | Out-Null }
    $path = Join-Path $logs '.tenantkeep.lock'
    if ($script:PostureLocksHeld.Contains($path)) { return & $Script }
    $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
    $handle = $null
    while (-not $handle) {
        try { $handle = [System.IO.File]::Open($path, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) }
        catch [System.IO.IOException] {
            if ([datetime]::UtcNow -ge $deadline) { Write-Verbose "Lock on $path not taken in $TimeoutSeconds s; writing without it."; break }
            Start-Sleep -Milliseconds 100
        }
    }
    if ($handle) { $null = $script:PostureLocksHeld.Add($path) }
    try { return & $Script }
    finally { if ($handle) { $null = $script:PostureLocksHeld.Remove($path); $handle.Dispose() } }
}
