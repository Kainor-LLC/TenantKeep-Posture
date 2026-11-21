# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Read-PostureSharePointSetting {
    <#
    .SYNOPSIS
        The SharePoint tenant settings for the fact providers: the SharePoint admin read when it was collected, otherwise
        the part of them Graph returns, under the same property names.
    .DESCRIPTION
        spo-tenant-settings.json comes from the SharePoint admin read (the SharePoint app or the Windows collector) and
        holds everything. spo-tenant-settings-graph.json comes from Graph's admin/sharepoint/settings with a read-only
        scope and holds less: the tenant sharing level, the domain lists and restriction mode, legacy authentication,
        resharing by guests and the invited account match. Read through here, a check can tell which source it got
        (source admin or graph) and say exactly what is missing when only Graph was read.
    .OUTPUTS
        @{ source = 'admin' | 'graph'; settings = <dictionary> }, or $null when neither file is in the folder.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Evidence)

    $ErrorActionPreference = 'Stop'
    $admin = Read-PostureEvidenceFile -Folder $Evidence -Name 'spo-tenant-settings'
    if ($null -ne $admin) { return @{ source = 'admin'; settings = $admin } }
    $g = Read-PostureEvidenceFile -Folder $Evidence -Name 'spo-tenant-settings-graph'
    if ($null -eq $g) { return $null }
    # Graph's enums are the admin read's with a lower-case first letter (externalUserSharingOnly, allowList).
    $pascal = { param($x) $s = [string]$x; if ($s) { $s.Substring(0, 1).ToUpperInvariant() + $s.Substring(1) } else { $s } }
    $value = { param([string] $Name) Get-PostureValue $g $Name }
    $resharing = & $value 'isResharingByExternalUsersEnabled'
    $settings = [ordered]@{
        SharingCapability                          = (& $pascal (& $value 'sharingCapability'))
        SharingDomainRestrictionMode               = (& $pascal (& $value 'sharingDomainRestrictionMode'))
        SharingAllowedDomainList                   = (@(& $value 'sharingAllowedDomainList') | Where-Object { $_ }) -join ' '
        SharingBlockedDomainList                   = (@(& $value 'sharingBlockedDomainList') | Where-Object { $_ }) -join ' '
        LegacyAuthProtocolsEnabled                 = (& $value 'isLegacyAuthProtocolsEnabled')
        PreventExternalUsersFromResharing          = $(if ($null -ne $resharing) { -not [bool]$resharing } else { $null })
        RequireAcceptingAccountMatchInvitedAccount = (& $value 'isRequireAcceptingUserToMatchInvitedUserEnabled')
    }
    return @{ source = 'graph'; settings = $settings }
}
