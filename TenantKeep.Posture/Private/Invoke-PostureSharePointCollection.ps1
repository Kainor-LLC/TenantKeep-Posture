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

    Invoke-PostureStep -Label 'Restricted SharePoint Search' -Folder $Folder -Script {
        # Copilot readiness C9. Get-PnPTenantRestrictedSearchMode answers Disabled, Enabled, or (PnP 3.2.0, a tenant that never set it) the sentence
        # "Restricted search mode is currently not set."; the mode is kept as written and read in Get-PostureCopilotFact. The allow list is a separate read.
        $mode = @(& $pnp 'Get-PnPTenantRestrictedSearchMode')
        $allowed = $(try { @(& $pnp 'Get-PnPTenantRestrictedSearchAllowedList') } catch { @() })
        & $saveOne ([ordered]@{ Mode = [string]$(if ($mode.Count -gt 0) { $mode[0] } else { '' }); AllowedSites = @($allowed | Where-Object { $_ }).Count }) 'spo-restricted-search'
    } | Out-Null

    if (-not $SkipSiteEnumeration) {
        # Streamed: rows written one at a time with the ownerless flag worked out per row and the summary tallied. PnP
        # still hands the whole list over at once (Get-PnPTenantSite has no paging), so this saves the copies, not that one.
        Invoke-PostureStep -Label 'SharePoint sites' -Folder $Folder -Script {
            $sum = [ordered]@{ Total = 0; OneDrives = 0; Sites = 0; AnonymousSharingAllowed = 0; Ownerless = 0; Labeled = 0; RestrictedAccessControl = 0 }
            $byTemplate = @{}
            $stream = Open-PostureEvidenceStream -Folder $Folder -Name 'spo-sites' -Csv -Confirm:$false
            try {
                Invoke-PosturePnpCommand -Name 'Get-PnPTenantSite' -Parameters @{ IncludeOneDriveSites = $true; Detailed = $true } -OnItem {
                    param($site)
                    if (-not $site) { return }
                    $row = [ordered]@{
                        Url = [string]$site.Url; Title = [string]$site.Title; Template = [string]$site.Template; SharingCapability = [string]$site.SharingCapability; StorageUsageCurrent = $site.StorageUsageCurrent
                        LastContentModifiedDate = $site.LastContentModifiedDate; Owner = [string]$site.Owner; OwnerEmail = [string](& $prop $site 'OwnerEmail'); OwnerLoginName = [string](& $prop $site 'OwnerLoginName'); OwnerName = [string](& $prop $site 'OwnerName')
                        GroupId = (& $groupId $site); SensitivityLabel = [string]$site.SensitivityLabel; LockState = [string]$site.LockState
                        RestrictedAccessControl = $site.RestrictedAccessControl; RestrictContentOrgWideSearch = (& $prop $site 'RestrictContentOrgWideSearch'); DenyAddAndCustomizePages = [string]$site.DenyAddAndCustomizePages; IsOneDrive = ([string]$site.Template -like 'SPSPERS*')
                        IsSystem = ([string]$site.Template -match '^(SRCHCEN|SPSMSITEHOST|APPCATALOG|POINTPUBLISHINGHUB|POINTPUBLISHINGTOPIC|EDISC|REDIRECTSITE|TEAMCHANNEL|SPSPERS|BDR|OFFILE|STS#-1)')
                    }
                    # Ownerless: a site that is not group-connected (the group's owners decide those), not a system site, and
                    # reports no owner in any of the four owner properties. (verify) which of the four Get-PnPTenantSite fills for modern sites.
                    $row.Ownerless = (-not $row.IsOneDrive -and -not $row.IsSystem -and -not $row.GroupId -and -not ($row.Owner -or $row.OwnerEmail -or $row.OwnerLoginName -or $row.OwnerName))
                    Add-PostureEvidenceRow -Stream $stream -Row $row
                    $sum.Total++
                    if ($row.IsOneDrive) { $sum.OneDrives++; return }
                    $sum.Sites++
                    $t = $row.Template; $byTemplate[$t] = 1 + $(if ($byTemplate.ContainsKey($t)) { $byTemplate[$t] } else { 0 })
                    if ($row.SharingCapability -eq 'ExternalUserAndGuestSharing') { $sum.AnonymousSharingAllowed++ }
                    if ($row.Ownerless) { $sum.Ownerless++ }
                    if ($row.SensitivityLabel) { $sum.Labeled++ }
                    if ($row.RestrictedAccessControl -eq $true) { $sum.RestrictedAccessControl++ }
                }
                $files.Add((Close-PostureEvidenceStream -Stream $stream))
            }
            catch { Stop-PostureEvidenceStream -Stream $stream -Confirm:$false; throw }
            $sum.ByTemplate = @($byTemplate.Keys | ForEach-Object { [ordered]@{ Name = $_; Count = $byTemplate[$_] } })
            & $saveOne $sum 'spo-sites-summary'
        } | Out-Null
    }

    $errorsPath = Join-Path $Folder 'errors.txt'
    return @{ files = $files.ToArray(); errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath }) }
}
