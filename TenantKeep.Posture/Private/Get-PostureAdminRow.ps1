# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureAdminRow {
    <#
    .SYNOPSIS
        The administrators' rows of the registration report or the users list, without loading the list.
    .DESCRIPTION
        The collector writes them to their own small file (05-auth-registration-admins, 06-users-admins). A run
        from before those files has only the full list, which has a row per user: it is read a row at a time and
        the rows of the people who hold a role are kept (Get-PostureRoleHolder, and Graph's own IsAdmin flag where
        the row has one). $null when neither file is in the folder.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [ValidateSet('Registration', 'Users')] [string] $List
    )

    $ErrorActionPreference = 'Stop'
    $name = @{ Registration = @('05-auth-registration-admins', '05-auth-registration'); Users = @('06-users-admins', '06-users') }[$List]
    $rows = Read-PostureEvidenceFile -Folder $Folder -Name $name[0]
    if ($null -ne $rows) { return , @($rows | Where-Object { $_ }) }
    $admins = (Get-PostureRoleHolder -Folder $Folder).upns
    $kept = [System.Collections.Generic.List[object]]::new()
    $read = Read-PostureEvidenceRow -Folder $Folder -Name $name[1] -OnRow {
        param($row)
        if ((Test-PostureTrue (Get-PostureValue $row 'IsAdmin')) -or $admins.Contains([string](Get-PostureValue $row 'UserPrincipalName'))) { $kept.Add($row) }
    }
    if (-not $read) { return $null }
    return , $kept.ToArray()
}
