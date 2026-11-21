# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureTeamsCollection {
    <#
    .SYNOPSIS
        The A.3 Teams collector through the MicrosoftTeams module: federation, client configuration, the global
        meeting policy, external access policies, app permission policies, guest messaging, and under app centric
        management the org-wide app settings and every app's availability.
    .DESCRIPTION
        Needs a Connect-MicrosoftTeams session (Teams Administrator or Global Reader). Never connects. Rich policy
        objects are projected to scalars and string lists before they are written.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Folder)

    $ErrorActionPreference = 'Stop'
    $files = [System.Collections.Generic.List[string]]::new()
    $save = { param($Data, [string] $Name, [bool] $Csv = $false) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data -AsArray -Csv:$Csv)) }
    $saveOne = { param($Data, [string] $Name) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data)) }
    $teams = { param([string] $Name, [hashtable] $Params = @{}) @(Invoke-PostureTeamsCommand -Name $Name -Parameters $Params) }

    $steps = @(
        ('Teams federation', 'Get-CsTenantFederationConfiguration', @{}, 'teams-federation', $true),
        ('Teams client configuration', 'Get-CsTeamsClientConfiguration', @{}, 'teams-client-config', $true),
        ('Teams global meeting policy', 'Get-CsTeamsMeetingPolicy', @{ Identity = 'Global' }, 'teams-meeting-policy-global', $true),
        ('Teams external access policies', 'Get-CsExternalAccessPolicy', @{}, 'teams-external-access', $false),
        ('Teams app permission policies', 'Get-CsTeamsAppPermissionPolicy', @{}, 'teams-app-permission-policies', $false),
        ('Teams guest messaging', 'Get-CsTeamsGuestMessagingConfiguration', @{}, 'teams-guest-messaging', $true),
        ('Teams messaging policies', 'Get-CsTeamsMessagingPolicy', @{}, 'teams-messaging-policies', $false)
    )
    foreach ($step in $steps) {
        $label, $cmd, $params, $name, $single = $step
        Invoke-PostureStep -Label $label -Folder $Folder -Script {
            $objects = & $teams $cmd $params
            $rows = @($objects | Where-Object { $_ } | ForEach-Object { $_ | ConvertTo-PostureFlatObject })
            if ($single) { & $saveOne $(if ($rows.Count -gt 0) { $rows[0] } else { [ordered]@{} }) $name } else { & $save $rows $name $false }
        } | Out-Null
    }

    # App centric management, which Microsoft moved tenants to from April 2025: each app is available to everyone, to
    # named users and groups, or to no one, and an org-wide setting per kind of app decides the default for new ones.
    Invoke-PostureStep -Label 'Teams org-wide app settings' -Folder $Folder -Script {
        $rows = @(& $teams 'Get-M365UnifiedTenantSettings' | Where-Object { $_ } | ForEach-Object {
                [ordered]@{ SettingName = [string](Get-PostureValue $_ 'SettingName'); SettingValue = [string](Get-PostureValue $_ 'SettingValue'); Users = (@(Get-PostureValue $_ 'Users') -join ';'); Groups = (@(Get-PostureValue $_ 'Groups') -join ';') }
            })
        & $save $rows 'teams-app-settings' $false
    } | Out-Null
    Invoke-PostureStep -Label 'Teams app availability' -Folder $Folder -Script {
        $rows = @(& $teams 'Get-AllM365TeamsApps' | Where-Object { $_ } | ForEach-Object {
                [ordered]@{
                    Id = [string](Get-PostureValue $_ 'Id'); AppName = [string](Get-PostureValue $_ 'AppName'); IsBlocked = [string](Get-PostureValue $_ 'IsBlocked')
                    AvailableTo = [string](Get-PostureValue $_ 'AvailableTo.AssignmentType'); AvailableToChangedUtc = [string](Get-PostureValue $_ 'AvailableTo.LastUpdatedTimestamp')
                    InstalledFor = [string](Get-PostureValue $_ 'InstalledFor.AppInstallType')
                }
            })
        & $save $rows 'teams-app-availability' $true
    } | Out-Null

    $errorsPath = Join-Path (Get-PostureRunLayout -Folder $Folder).errors 'errors.txt'
    return @{ files = $files.ToArray(); errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath }) }
}
