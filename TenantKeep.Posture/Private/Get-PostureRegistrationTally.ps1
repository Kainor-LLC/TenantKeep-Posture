# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Add-PostureRegistrationTally {
    <#
    .SYNOPSIS
        Counts one row of the authentication methods registration report into the numbers the report reads from it.
    .DESCRIPTION
        Users (everyone who is not a guest), SsprEnabled (the policy lets them reset their own password), Phishable
        (no device-bound, phishing-resistant method registered: the list AU-008 uses) and PhishableAdmins (those of
        them who hold a role, by Graph's own flag or by the role holders). The Entra collector calls this for every
        row as it writes the list; Get-PostureRegistrationTally calls it for a run made before the summary carried
        the counts. One definition, so the two agree.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Tally,
        [Parameter(Mandatory)] [object] $Row,
        [AllowNull()] [object] $AdminUpns
    )

    if ([string](Get-PostureValue $Row 'UserType') -eq 'guest') { return }
    $Tally.Users++
    if (Test-PostureTrue (Get-PostureValue $Row 'IsSsprEnabled')) { $Tally.SsprEnabled++ }
    foreach ($method in ([string](Get-PostureValue $Row 'MethodsRegistered')).Split(';')) { if ($method -and $method -in $script:PostureDeviceBoundMethods) { return } }
    $Tally.Phishable++
    if ((Test-PostureTrue (Get-PostureValue $Row 'IsAdmin')) -or ($AdminUpns -and $AdminUpns.Contains([string](Get-PostureValue $Row 'UserPrincipalName')))) { $Tally.PhishableAdmins++ }
}

function Get-PostureRegistrationTally {
    <#
    .SYNOPSIS
        The registration report's counts for an evidence folder, without loading the report: Users, SsprEnabled,
        Phishable, PhishableAdmins, and source ('summary' or 'list'). $null when the report was not collected.
    .DESCRIPTION
        Read from 05-auth-registration-summary, where the collector writes them from its own pass over the report
        (since 2026-11-21). For an older run the list is read once, a row at a time. The list has a row per user:
        loaded whole it was most of the report's memory on a large tenant.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Folder
    )

    $ErrorActionPreference = 'Stop'
    $summary = Read-PostureEvidenceFile -Folder $Folder -Name '05-auth-registration-summary'
    $written = Get-PostureValue $summary 'Tally'
    if ($written) {
        return @{ Users = [int](Get-PostureValue $written 'Users'); SsprEnabled = [int](Get-PostureValue $written 'SsprEnabled'); Phishable = [int](Get-PostureValue $written 'Phishable'); PhishableAdmins = [int](Get-PostureValue $written 'PhishableAdmins'); source = 'summary' }
    }
    $tally = @{ Users = 0; SsprEnabled = 0; Phishable = 0; PhishableAdmins = 0; source = 'list' }
    $admins = (Get-PostureRoleHolder -Folder $Folder).upns
    $read = Read-PostureEvidenceRow -Folder $Folder -Name '05-auth-registration' -OnRow { param($row) Add-PostureRegistrationTally -Tally $tally -Row $row -AdminUpns $admins }
    if (-not $read) { return $null }
    return $tally
}
