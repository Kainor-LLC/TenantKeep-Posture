# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Enable-PostureKeepAwake {
    <#
    .SYNOPSIS
        Keeps the machine from idle sleep while a run collects, the way the operating system expects to be asked.
        Returns a handle for Disable-PostureKeepAwake, or $null when nothing on this machine can do it.
    .DESCRIPTION
        macOS: caffeinate -i -s, tied to this process with -w, so it ends with PowerShell even after a crash
        (-s only holds on mains power; on battery -i still stops idle sleep). Linux: systemd-inhibit around a
        process that ends with this one. Windows: SetThreadExecutionState on this thread, the documented call for
        "the system is in use" (Windows-only, marked here; the only Win32 call outside collectors/windows/).
        A closed laptop lid still sleeps everywhere: that is the user's decision and not overridden.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [ValidateSet('auto', 'macOS', 'Linux', 'Windows')] [string] $Platform = 'auto'
    )

    $ErrorActionPreference = 'Stop'
    if ($Platform -eq 'auto') { $Platform = $(if ($IsMacOS) { 'macOS' } elseif ($IsWindows) { 'Windows' } else { 'Linux' }) }
    try {
        switch ($Platform) {
            'macOS' {
                if (-not (Get-Command caffeinate -CommandType Application -ErrorAction SilentlyContinue)) { return $null }
                $p = Start-Process -FilePath 'caffeinate' -ArgumentList @('-i', '-s', '-w', [string]$PID) -PassThru -NoNewWindow
                return @{ method = 'caffeinate'; process = $p }
            }
            'Linux' {
                if (-not (Get-Command systemd-inhibit -CommandType Application -ErrorAction SilentlyContinue)) { return $null }
                $p = Start-Process -FilePath 'systemd-inhibit' -ArgumentList @('--what=idle:sleep', '--who=TenantKeep Posture', '--why=Collecting the assessment', '--mode=block', 'tail', "--pid=$PID", '-f', '/dev/null') -PassThru -NoNewWindow
                return @{ method = 'systemd-inhibit'; process = $p }
            }
            'Windows' {
                # Windows-only: ES_CONTINUOUS | ES_SYSTEM_REQUIRED until reset on this thread.
                if (-not ('TenantKeep.Posture.Power' -as [type])) {
                    Add-Type -Namespace 'TenantKeep.Posture' -Name 'Power' -MemberDefinition '[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint esFlags);'
                }
                $null = [TenantKeep.Posture.Power]::SetThreadExecutionState([uint32]'0x80000001')
                return @{ method = 'SetThreadExecutionState'; process = $null }
            }
        }
    }
    catch { Write-Verbose "Keep-awake not available: $($_.Exception.Message)"; return $null }
}

function Disable-PostureKeepAwake {
    <#
    .SYNOPSIS
        Lets the machine sleep again: ends the helper process, or clears the Windows execution state.
    #>
    [CmdletBinding()]
    param([hashtable] $Handle)

    $ErrorActionPreference = 'Stop'
    if (-not $Handle) { return }
    try {
        if ($Handle['process']) { if (-not $Handle['process'].HasExited) { $Handle['process'].Kill() } }
        elseif ($Handle['method'] -eq 'SetThreadExecutionState') { $null = [TenantKeep.Posture.Power]::SetThreadExecutionState([uint32]'0x80000000') }
    }
    catch { Write-Verbose "Keep-awake not released cleanly: $($_.Exception.Message)" }
}
