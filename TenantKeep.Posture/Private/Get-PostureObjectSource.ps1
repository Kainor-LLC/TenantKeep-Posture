# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureObjectSource {
    <#
    .SYNOPSIS
        Where a user or group is managed, from read-only properties: ActiveDirectory (synced, changed in AD),
        EntraFromAD (came from AD, source of authority switched to Entra) or Cloud (created in Entra).
    .DESCRIPTION
        Microsoft's own flag for the switch (onPremisesSyncBehavior isCloudManaged) needs a write permission to read,
        which the module does not take. Microsoft documents that after the switch onPremisesSyncEnabled is empty, as
        it is for an object created in the cloud; the switched object keeps the identifiers it had in AD. So: sync on
        means AD; sync empty with an AD security identifier means switched to Entra; neither means cloud. (verify: on a
        tenant that has switched a group, the identifier stays.)
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowNull()] [System.Collections.IDictionary] $Object)

    if (-not $Object) { return 'Cloud' }
    if ($Object.Contains('onPremisesSyncEnabled') -and $Object['onPremisesSyncEnabled'] -eq $true) { return 'ActiveDirectory' }
    if ($Object.Contains('onPremisesSecurityIdentifier') -and $Object['onPremisesSecurityIdentifier']) { return 'EntraFromAD' }
    return 'Cloud'
}
