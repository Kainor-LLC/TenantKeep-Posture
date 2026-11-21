# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# Before a run collects: how big the tenant is, and what that means for the run. Three small reads, then a few
# lines on the console, so a run of hours on a large tenant is expected and not found out.

function Get-PostureTenantSize {
    <#
    .SYNOPSIS
        How many users, devices and groups the tenant has: @{ users; devices; groups }, each a count or $null when
        Graph would not say. Three requests, each for one object and the count.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $size = @{ users = $null; devices = $null; groups = $null }
    foreach ($what in 'users', 'devices', 'groups') {
        try {
            $first = Invoke-PostureGraphRequest -Uri "$what`?`$count=true&`$select=id&`$top=1" -ApiVersion 'v1.0' -Single -Headers @{ ConsistencyLevel = 'eventual' }
            if ($first -is [System.Collections.IDictionary] -and $first.Contains('@odata.count')) { $size[$what] = [long]$first['@odata.count'] }
        }
        catch { Write-Verbose "Count of $what not available: $($_.Exception.Message)" }
    }
    return $size
}

function Get-PostureRunPreview {
    <#
    .SYNOPSIS
        The lines a run prints before it collects, from the tenant's size and what was asked for: the counts, how
        many requests the long lists are, what is read as a sample, and what is left out unless asked for.
    .DESCRIPTION
        Requests, not minutes: how long a request takes is Microsoft's to decide on the day, and the progress line
        gives the time once the run has measured it. The page sizes are the ones the collectors ask for: 999 a
        page, and 120 for the user list when sign-in activity is read (verify the cap on a large tenant).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Size,
        [string[]] $Collector = @(),
        [switch] $FullPerUserMfa,
        [switch] $IncludeOneDriveSites
    )

    $n = { param($count) if ($null -eq $count) { 'an unknown number of' } else { '{0:N0}' -f [long]$count } }
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("Tenant size:   $(& $n $Size['users']) users, $(& $n $Size['devices']) devices, $(& $n $Size['groups']) groups.")
    $users = $(if ($null -ne $Size['users']) { [long]$Size['users'] } else { 0 })
    if ('Entra' -in $Collector -and $users -gt 5000) {
        $lines.Add("  The user list is about $('{0:N0}' -f [Math]::Ceiling($users / 120)) requests and the registration report about $('{0:N0}' -f [Math]::Ceiling($users / 999)). Each is written as it arrives; one that stops carries on from where it stopped.")
        if ($FullPerUserMfa) { $lines.Add("  Per-user MFA is read for every member, a request for each twenty: about $('{0:N0}' -f [Math]::Ceiling($users / 20)) requests.") }
        else { $lines.Add('  Per-user MFA is read for a sample: every administrator and 1,000 other members. -FullPerUserMfa reads everyone.') }
    }
    if ('SharePoint' -in $Collector -and $users -gt 5000 -and -not $IncludeOneDriveSites) { $lines.Add('  OneDrive sites are not listed: there is one for each user, and no check reads them.') }
    if ($users -gt 20000) { $lines.Add('  At this size the run takes hours. It can be stopped and resumed: Resume-PostureRun carries on in the same run, and lists that finished are not read again.') }
    return $lines.ToArray()
}

function Set-PostureFolderPrivate {
    <#
    .SYNOPSIS
        Makes a run or client folder the owner's alone, where the platform has file modes: rwx for the owner and
        nothing for anyone else (700). Returns what it did: 'set', 'already', 'windows' or 'failed'.
    .DESCRIPTION
        A run folder holds every user, device, mailbox and site of a tenant. On macOS and Linux a new folder is
        readable by everyone on the machine unless told otherwise; files inside a 700 folder cannot be reached by
        anyone else whatever their own mode. On Windows nothing is changed: a folder under the user's profile is
        already the user's (with SYSTEM and Administrators) by the profile's own permissions, and a folder
        somewhere else keeps what its parent grants, which is the admin's to decide (docs/footprint.md). This
        never stops a run: a mode that cannot be set is a verbose line.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Path)

    if ($IsWindows) { return 'windows' }
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return 'failed' }
        $owner = [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite -bor [System.IO.UnixFileMode]::UserExecute
        if ([System.IO.File]::GetUnixFileMode($Path) -eq $owner) { return 'already' }
        if (-not $PSCmdlet.ShouldProcess($Path, 'Make the folder the owner''s alone (mode 700)')) { return 'failed' }
        [System.IO.File]::SetUnixFileMode($Path, $owner)
        return 'set'
    }
    catch { Write-Verbose "Folder permissions not set on $($Path): $($_.Exception.Message)"; return 'failed' }
}
