# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureTeamsCollection {
    <#
    .SYNOPSIS
        The A.3 Teams collector through the MicrosoftTeams module: federation, client configuration, the global
        meeting policy, external access policies, app permission policies and guest messaging.
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

    $errorsPath = Join-Path $Folder 'errors.txt'
    return @{ files = $files.ToArray(); errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath }) }
}
