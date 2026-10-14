# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureSharePointCollection {
    <#
    .SYNOPSIS
        The A.3 SharePoint collector through PnP.PowerShell: tenant sharing and access settings, and the site list
        with sharing capability, ownership, label and lock state.
    .DESCRIPTION
        Needs a Connect-PnPOnline session to the tenant admin site, opened with the app registration from
        deploy/setup/New-PostureSharePointApp.ps1 and an account holding SharePoint Administrator. Never connects.
        -SkipSiteEnumeration leaves out Get-PnPTenantSite, which takes 30 minutes and more at 20k OneDrives.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [switch] $SkipSiteEnumeration
    )

    $ErrorActionPreference = 'Stop'
    $files = [System.Collections.Generic.List[string]]::new()
    $save = { param($Data, [string] $Name, [bool] $Csv = $false) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data -AsArray -Csv:$Csv)) }
    $saveOne = { param($Data, [string] $Name) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data)) }
    $pnp = { param([string] $Name, [hashtable] $Params = @{}) @(Invoke-PosturePnpCommand -Name $Name -Parameters $Params) }
    $prop = { param($o, [string] $n) if ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    $groupId = { param($o) $g = [string](& $prop $o 'GroupId'); if ($g -and $g -ne [guid]::Empty.ToString()) { $g } else { '' } }

    Invoke-PostureStep -Label 'SharePoint tenant settings' -Folder $Folder -Script {
        $props = @('SharingCapability', 'DefaultSharingLinkType', 'DefaultLinkPermission', 'RequireAnonymousLinksExpireInDays', 'FileAnonymousLinkType', 'FolderAnonymousLinkType', 'OneDriveSharingCapability',
            'SharingDomainRestrictionMode', 'SharingAllowedDomainList', 'SharingBlockedDomainList', 'ExternalUserExpirationRequired', 'ExternalUserExpireInDays', 'ShowEveryoneClaim', 'ShowEveryoneExceptExternalUsersClaim',
            'ShowAllUsersClaim', 'LegacyAuthProtocolsEnabled', 'ConditionalAccessPolicy', 'EnableRestrictedAccessControl', 'EnableAzureADB2BIntegration', 'PreventExternalUsersFromResharing', 'NotifyOwnersWhenItemsReshared',
            'RequireAcceptingAccountMatchInvitedAccount', 'DisallowInfectedFileDownload', 'ShowPeoplePickerSuggestionsForGuestUsers', 'EnableAIPIntegration', 'BlockUserInfoVisibilityInOneDrive', 'OneDriveLoopSharingCapability', 'CoreSharingCapability')
        $t = @(& $pnp 'Get-PnPTenant')
        $row = $(if ($t.Count -gt 0) { $t[0] | ConvertTo-PostureFlatObject -Property $props } else { [ordered]@{} })
        & $saveOne $row 'spo-tenant-settings'
    } | Out-Null

    if (-not $SkipSiteEnumeration) {
        Invoke-PostureStep -Label 'SharePoint sites' -Folder $Folder -Script {
            $sites = @(& $pnp 'Get-PnPTenantSite' @{ IncludeOneDriveSites = $true; Detailed = $true })
            $rows = @($sites | Where-Object { $_ } | ForEach-Object {
                    [ordered]@{
                        Url = [string]$_.Url; Title = [string]$_.Title; Template = [string]$_.Template; SharingCapability = [string]$_.SharingCapability; StorageUsageCurrent = $_.StorageUsageCurrent
                        LastContentModifiedDate = $_.LastContentModifiedDate; Owner = [string]$_.Owner; OwnerEmail = [string](& $prop $_ 'OwnerEmail'); OwnerLoginName = [string](& $prop $_ 'OwnerLoginName'); OwnerName = [string](& $prop $_ 'OwnerName')
                        GroupId = (& $groupId $_); SensitivityLabel = [string]$_.SensitivityLabel; LockState = [string]$_.LockState
                        RestrictedAccessControl = $_.RestrictedAccessControl; DenyAddAndCustomizePages = [string]$_.DenyAddAndCustomizePages; IsOneDrive = ([string]$_.Template -like 'SPSPERS*')
                        IsSystem = ([string]$_.Template -match '^(SRCHCEN|SPSMSITEHOST|APPCATALOG|POINTPUBLISHINGHUB|POINTPUBLISHINGTOPIC|EDISC|REDIRECTSITE|TEAMCHANNEL|SPSPERS|BDR|OFFILE|STS#-1)')
                    }
                })
            # Ownerless: a site that is not group-connected (the group's owners decide those), not a system site, and
            # reports no owner in any of the four owner properties. (verify) which of the four Get-PnPTenantSite fills for modern sites.
            $ownerless = @($rows | Where-Object { -not $_.IsOneDrive -and -not $_.IsSystem -and -not $_.GroupId -and -not ($_.Owner -or $_.OwnerEmail -or $_.OwnerLoginName -or $_.OwnerName) })
            foreach ($r in $rows) { $r.Ownerless = ($ownerless -contains $r) }
            & $save $rows 'spo-sites' $true
            $teamSites = @($rows | Where-Object { -not $_.IsOneDrive })
            & $saveOne ([ordered]@{
                    Total = $rows.Count; OneDrives = @($rows | Where-Object { $_.IsOneDrive }).Count; Sites = $teamSites.Count
                    ByTemplate = @($teamSites | Group-Object { $_.Template } | ForEach-Object { [ordered]@{ Name = $_.Name; Count = $_.Count } })
                    AnonymousSharingAllowed = @($teamSites | Where-Object { $_.SharingCapability -eq 'ExternalUserAndGuestSharing' }).Count
                    Ownerless = $ownerless.Count
                    Labeled = @($teamSites | Where-Object { $_.SensitivityLabel }).Count
                    RestrictedAccessControl = @($teamSites | Where-Object { $_.RestrictedAccessControl -eq $true }).Count
                }) 'spo-sites-summary'
        } | Out-Null
    }

    $errorsPath = Join-Path $Folder 'errors.txt'
    return @{ files = $files.ToArray(); errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath }) }
}
