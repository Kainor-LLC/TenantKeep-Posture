# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureRequirement {
    <#
    .SYNOPSIS
        What the collectors need on this machine, against what they were tested with.
    .DESCRIPTION
        One row per service module: the collectors that use it, the version installed here, the version the live
        runs proved, and a status. Missing means the collectors that need it are skipped with the install line.
        Older means the module runs but the version is untested; the row says what to update. Nothing is installed
        or changed by this cmdlet. Every run records the versions it used in collection.json, so a support question
        can start from the facts.
    .PARAMETER Name
        One or more module names; default every module the collectors use.
    .EXAMPLE
        Get-PostureRequirement | Format-Table Name, Installed, Tested, Status, Collectors
    .EXAMPLE
        Get-PostureRequirement | Where-Object Status -ne ok | ForEach-Object Install
    .LINK
        docs/guide.md
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([string[]] $Name)

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    foreach ($row in Get-PostureModuleRequirement -Name $Name) {
        $check = Test-PostureModuleRequirement -Name $row.name
        [pscustomobject]@{
            Name       = $check.name
            Installed  = $(if ($check.installed) { [string]$check.installed } else { '' })
            Tested     = [string]$check.tested
            Status     = $check.status
            Collectors = $check.collectors
            Install    = $check.install
            Note       = $check.note
            PowerShell = $PSVersionTable.PSVersion.ToString()
        }
    }
}
