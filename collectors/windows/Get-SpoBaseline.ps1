#Requires -Version 5.1
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Windows-only, read-only SharePoint collector on Microsoft's own SharePoint Online Management Shell: the SharePoint
    admin read without any third-party app or consent. Run it as a SharePoint admin on Windows (a cloud PC is fine),
    then bring the folder into the run on any machine with Import-PostureEvidence.
.DESCRIPTION
    Needs the Microsoft.Online.SharePoint.PowerShell module and an account holding SharePoint Administrator (activate it
    in PIM for the few minutes this takes). It signs in through Microsoft's SharePoint Online Management Shell sign-in;
    TenantKeep has no app in this path. Only Get-SPO commands run, plus Connect-SPOService and Disconnect-SPOService;
    a test in the repository fails the build on any other SharePoint command in this file.

    It writes the files the SharePoint checks read, with the same names and properties as the module's own SharePoint
    collector: spo-tenant-settings.json, spo-restricted-search.json, spo-sites.csv and spo-sites-summary.json, plus
    errors.txt, a transcript, and bundle.json (tenant, collector, versions, a SHA-256 per file), which
    Import-PostureEvidence checks before it copies anything into a run.

    Before reading, the tenant id behind -Tenant is looked up in Microsoft's public sign-in metadata and compared with
    -TenantId; the script refuses a mismatch, so evidence never lands in the wrong tenant's run.

    Under PowerShell 7 the module is loaded through Windows PowerShell compatibility (verify: recent versions also load
    natively). How Microsoft's management shell signs in may change; this script does not depend on its app id.
.PARAMETER Tenant
    The tenant name, the part before .onmicrosoft.com (contoso for contoso.onmicrosoft.com).
.PARAMETER TenantId
    The tenant id the run belongs to. The script refuses to read another tenant.
.PARAMETER OutputPath
    Folder to write into. Default: .\spo-baseline-<yyyyMMdd-HHmm>.
.PARAMETER SkipSiteEnumeration
    Leaves out the site list (Get-SPOSite), which takes 30 minutes and more at 20,000 OneDrives.
.EXAMPLE
    .\Get-SpoBaseline.ps1 -Tenant contoso -TenantId 00000000-0000-0000-0000-000000000000 -OutputPath C:\audit\spo
    Then, where the run lives: Import-PostureEvidence -Path C:\audit\spo -Run ~/tenantkeep/evidence/20261120-0957
#>
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive script; the console is the only host and the output is a progress listing')]
param(
    [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z0-9-]+$')] [string] $Tenant,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $TenantId,
    [string] $OutputPath = (Join-Path (Get-Location) "spo-baseline-$((Get-Date).ToString('yyyyMMdd-HHmm'))"),
    [switch] $SkipSiteEnumeration
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$moduleName = 'Microsoft.Online.SharePoint.PowerShell'
$available = @(Get-Module -ListAvailable $moduleName | Sort-Object Version -Descending)
if ($available.Count -eq 0) { throw "The $moduleName module is required: Install-Module $moduleName -Scope CurrentUser" }

# The tenant behind the name, from Microsoft's public sign-in metadata, before anything is read.
$metadata = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$Tenant.onmicrosoft.com/v2.0/.well-known/openid-configuration"
$found = $(if ([string]$metadata.issuer -match '/([0-9a-fA-F-]{36})/') { $Matches[1] } else { '' })
if ($found -ne $TenantId) { throw "$Tenant.onmicrosoft.com is tenant $found, not $TenantId. Nothing was read." }

if ($PSVersionTable.PSEdition -eq 'Core') { Import-Module $moduleName -UseWindowsPowerShell -WarningAction SilentlyContinue } else { Import-Module $moduleName -DisableNameChecking }

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$out = (Resolve-Path -LiteralPath $OutputPath).Path
$errorsPath = Join-Path $out 'errors.txt'
$now = (Get-Date).ToUniversalTime()
$written = New-Object System.Collections.Generic.List[string]

function Save-Evidence {
    param([Parameter(Mandatory)] [string] $Name, [Parameter(Mandatory)] [object] $InputObject)
    $json = ConvertTo-Json -InputObject $InputObject -Depth 10
    [System.IO.File]::WriteAllText((Join-Path $out "$Name.json"), $json, (New-Object System.Text.UTF8Encoding $false))
    $written.Add("$Name.json")
    Write-Host ('{0,-40} written' -f "$Name.json")
}
function Invoke-Step {
    param([Parameter(Mandatory)] [string] $Label, [Parameter(Mandatory)] [scriptblock] $Script)
    try { & $Script }
    catch {
        $message = (([string]$_.Exception.Message) -replace '\s*[\r\n]+\s*', ' ').Trim()
        Add-Content -Path $errorsPath -Value "SharePoint (Windows collector) $Label :: $message"
        Write-Warning "$Label failed: $message"
    }
}
# A property when the object has it (older module versions lack some), as a plain value: enums as their names,
# lists joined by spaces, as the module's own collector writes them.
function Get-Plain {
    param($Object, [string] $Name)
    $p = $Object.PSObject.Properties[$Name]
    if (-not $p -or $null -eq $p.Value) { return $null }
    $v = $p.Value
    if ($v -is [enum]) { return $v.ToString() }
    if ($v -is [datetime]) { return $v.ToUniversalTime().ToString('o') }
    if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) { return (@($v) | ForEach-Object { [string]$_ }) -join ' ' }
    return $v
}

Start-Transcript -Path (Join-Path $out 'transcript.txt') -Append | Out-Null
try {
    Connect-SPOService -Url "https://$Tenant-admin.sharepoint.com"

    Invoke-Step 'Tenant settings' {
        $props = @('SharingCapability', 'DefaultSharingLinkType', 'DefaultLinkPermission', 'RequireAnonymousLinksExpireInDays', 'FileAnonymousLinkType', 'FolderAnonymousLinkType', 'OneDriveSharingCapability',
            'SharingDomainRestrictionMode', 'SharingAllowedDomainList', 'SharingBlockedDomainList', 'ExternalUserExpirationRequired', 'ExternalUserExpireInDays', 'ShowEveryoneClaim', 'ShowEveryoneExceptExternalUsersClaim',
            'ShowAllUsersClaim', 'LegacyAuthProtocolsEnabled', 'ConditionalAccessPolicy', 'EnableRestrictedAccessControl', 'EnableAzureADB2BIntegration', 'PreventExternalUsersFromResharing', 'NotifyOwnersWhenItemsReshared',
            'RequireAcceptingAccountMatchInvitedAccount', 'DisallowInfectedFileDownload', 'ShowPeoplePickerSuggestionsForGuestUsers', 'EnableAIPIntegration', 'BlockUserInfoVisibilityInOneDrive', 'OneDriveLoopSharingCapability', 'CoreSharingCapability')
        $t = Get-SPOTenant
        $row = [ordered]@{}
        foreach ($p in $props) { $row[$p] = Get-Plain $t $p }
        Save-Evidence -Name 'spo-tenant-settings' -InputObject $row
    }

    Invoke-Step 'Restricted SharePoint Search' {
        $mode = Get-SPOTenantRestrictedSearchMode
        $modeText = $(if ($mode -and $mode.PSObject.Properties['Mode']) { [string]$mode.Mode } else { [string]$mode })
        $allowed = @(); try { $allowed = @(Get-SPOTenantRestrictedSearchAllowedList) } catch { $allowed = @() }
        Save-Evidence -Name 'spo-restricted-search' -InputObject ([ordered]@{ Mode = $modeText; AllowedSites = @($allowed | Where-Object { $_ }).Count })
    }

    if (-not $SkipSiteEnumeration) {
        Invoke-Step 'Sites' {
            $sum = [ordered]@{ Total = 0; OneDrives = 0; Sites = 0; AnonymousSharingAllowed = 0; Ownerless = 0; Labeled = 0; RestrictedAccessControl = 0 }
            $byTemplate = @{}
            $system = '^(SRCHCEN|SPSMSITEHOST|APPCATALOG|POINTPUBLISHINGHUB|POINTPUBLISHINGTOPIC|EDISC|REDIRECTSITE|TEAMCHANNEL|SPSPERS|BDR|OFFILE|STS#-1)'
            $csv = Join-Path $out 'spo-sites.csv'
            $rows = Get-SPOSite -Limit All -IncludePersonalSite $true | ForEach-Object {
                $site = $_
                $group = [string](Get-Plain $site 'GroupId'); if ($group -eq [guid]::Empty.ToString()) { $group = '' }
                $template = [string](Get-Plain $site 'Template')
                $row = [ordered]@{
                    Url = [string]$site.Url; Title = [string](Get-Plain $site 'Title'); Template = $template; SharingCapability = [string](Get-Plain $site 'SharingCapability'); StorageUsageCurrent = Get-Plain $site 'StorageUsageCurrent'
                    LastContentModifiedDate = Get-Plain $site 'LastContentModifiedDate'; Owner = [string](Get-Plain $site 'Owner'); OwnerEmail = [string](Get-Plain $site 'OwnerEmail'); OwnerLoginName = [string](Get-Plain $site 'OwnerLoginName'); OwnerName = [string](Get-Plain $site 'OwnerName')
                    GroupId = $group; SensitivityLabel = [string](Get-Plain $site 'SensitivityLabel'); LockState = [string](Get-Plain $site 'LockState')
                    RestrictedAccessControl = Get-Plain $site 'RestrictedAccessControl'; RestrictContentOrgWideSearch = Get-Plain $site 'RestrictContentOrgWideSearch'; DenyAddAndCustomizePages = [string](Get-Plain $site 'DenyAddAndCustomizePages')
                    IsOneDrive = ($template -like 'SPSPERS*'); IsSystem = ($template -match $system)
                }
                # Ownerless, as the module's collector decides it: not group-connected, not a system site, no owner at all.
                $row.Ownerless = (-not $row.IsOneDrive -and -not $row.IsSystem -and -not $row.GroupId -and -not ($row.Owner -or $row.OwnerEmail -or $row.OwnerLoginName -or $row.OwnerName))
                $sum.Total++
                if ($row.IsOneDrive) { $sum.OneDrives++ }
                else {
                    $sum.Sites++
                    $byTemplate[$template] = 1 + $(if ($byTemplate.ContainsKey($template)) { $byTemplate[$template] } else { 0 })
                    if ($row.SharingCapability -eq 'ExternalUserAndGuestSharing') { $sum.AnonymousSharingAllowed++ }
                    if ($row.Ownerless) { $sum.Ownerless++ }
                    if ($row.SensitivityLabel) { $sum.Labeled++ }
                    if ($row.RestrictedAccessControl -eq $true) { $sum.RestrictedAccessControl++ }
                }
                [pscustomobject]$row
            }
            @($rows) | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
            $written.Add('spo-sites.csv')
            Write-Host ('{0,-40} {1,6}' -f 'spo-sites.csv', $sum.Total)
            $sum.ByTemplate = @($byTemplate.Keys | ForEach-Object { [ordered]@{ Name = $_; Count = $byTemplate[$_] } })
            Save-Evidence -Name 'spo-sites-summary' -InputObject $sum
        }
    }
}
finally {
    try { Disconnect-SPOService } catch { Write-Verbose 'Disconnect-SPOService: no session to close.' }
    Stop-Transcript | Out-Null
}

# bundle.json: what Import-PostureEvidence checks before it copies a file into a run.
$files = @($written | ForEach-Object { [ordered]@{ name = $_; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $out $_)).Hash.ToLowerInvariant() } })
$bundle = [ordered]@{
    kind = 'sharepoint'; collector = 'Get-SpoBaseline.ps1'; schema = 1; tenantId = $TenantId; tenantName = "$Tenant.onmicrosoft.com"
    collectedUtc = $now.ToString('o'); account = [string]$env:USERNAME; shellModuleVersion = [string]$available[0].Version; powershell = [string]$PSVersionTable.PSVersion
    files = $files
}
[System.IO.File]::WriteAllText((Join-Path $out 'bundle.json'), (ConvertTo-Json -InputObject $bundle -Depth 5), (New-Object System.Text.UTF8Encoding $false))
Write-Host ''
Write-Host "Done: $out"
Write-Host "Bring it into the run: Import-PostureEvidence -Path '$out' -Run <run folder>"
