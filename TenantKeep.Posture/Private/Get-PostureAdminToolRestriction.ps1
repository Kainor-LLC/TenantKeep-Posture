# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# Microsoft's command-line and query tools that reach a whole tenant as whoever signs in. Their app ids are fixed
# across tenants (verify each against the tenant's enterprise applications).
$script:PostureAdminTools = [ordered]@{
    '14d82eec-204b-4c2f-b7e8-296a70dab67e' = 'Microsoft Graph Command Line Tools (Graph PowerShell)'
    'de8bc8b5-d9f9-48b1-a8ad-b748da725064' = 'Graph Explorer'
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = 'Microsoft Azure CLI'
    '1950a258-227b-4e31-a9cf-717495945fc2' = 'Microsoft Azure PowerShell'
    'fb78d390-0c51-40cd-8e17-fdbfab77341b' = 'Exchange Online PowerShell'
    '9bc3ab49-b65d-410a-85ad-de819febfddc' = 'SharePoint Online Management Shell'
    '12128f48-ec9e-42f0-b203-ea49fb6af367' = 'Microsoft Teams PowerShell'
}

function Get-PostureAdminToolRestriction {
    <#
    .SYNOPSIS
        For each of Microsoft's admin command-line tools, whether everyone in the tenant can sign in to it: restricted
        when its enterprise app requires assignment or is turned off, or when an enabled Conditional Access policy
        blocks it for everyone (exclusions for administrators allowed). The Azure tools also count as restricted when
        a policy blocks Windows Azure Service Management, the API they call.
    .OUTPUTS
        One row per tool (appId, name, restricted, how, detail), restricted being $null when only a policy could close
        the tool and policies.json was not collected; nothing when the service principal list was not
        collected.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [string] $Evidence)

    $ErrorActionPreference = 'Stop'
    $sps = Read-PostureEvidenceFile -Folder $Evidence -Name '10-service-principals'
    if ($null -eq $sps) { return $null }
    $byAppId = @{}; foreach ($sp in @($sps | Where-Object { $_ })) { $byAppId[[string](Get-PostureValue $sp 'AppId')] = $sp }
    $pol = Read-PostureEvidenceFile -Folder $Evidence -Name 'policies'
    $items = @($(if ($pol -is [System.Collections.IDictionary] -and $pol.Contains('value')) { $pol['value'] } else { $pol }) | Where-Object { $_ })
    $blockedApps = @{}
    foreach ($p in @($items | Where-Object { [string](Get-PostureValue $_ 'state') -eq 'enabled' -and @(Get-PostureValue $_ 'grantControls.builtInControls') -contains 'block' -and @(Get-PostureValue $_ 'conditions.users.includeUsers') -contains 'All' })) {
        foreach ($a in @(Get-PostureValue $p 'conditions.applications.includeApplications')) { $blockedApps[[string]$a] = [string](Get-PostureValue $p 'displayName') }
    }
    $azureApi = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
    return @($script:PostureAdminTools.Keys | ForEach-Object {
            $id = $_; $sp = $(if ($byAppId.ContainsKey($id)) { $byAppId[$id] } else { $null })
            $how = $(
                if ($sp -and (Get-PostureValue $sp 'AppRoleAssignmentRequired') -eq $true) { 'assignment required' }
                elseif ($sp -and (Get-PostureValue $sp 'AccountEnabled') -eq $false) { 'turned off' }
                elseif ($blockedApps.ContainsKey($id)) { "blocked by '$($blockedApps[$id])'" }
                elseif ($id -in '04b07795-8ddb-461a-bbee-02f9e1bf7b46', '1950a258-227b-4e31-a9cf-717495945fc2' -and $blockedApps.ContainsKey($azureApi)) { "Azure management blocked by '$($blockedApps[$azureApi])'" }
                else { '' })
            [ordered]@{
                # Closed by assignment, by being turned off or by a policy; open; or unknown ($null) when nothing on the
                # app closes it and the Conditional Access snapshot, which could, was not collected.
                appId = $id; name = $script:PostureAdminTools[$id]; restricted = $(if ($how) { $true } elseif ($null -eq $pol) { $null } else { $false }); how = $how
                detail = $(if ($how) { $how } elseif ($null -eq $pol) { 'not closed on the app itself; whether a Conditional Access policy blocks it is unknown without the snapshot' } elseif ($sp) { 'anyone can sign in: assignment not required' } else { 'no enterprise app in the tenant yet: the first person to sign in creates it, open to everyone' })
            }
        })
}
