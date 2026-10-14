# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Resolve-PostureCaName {
    <#
    .SYNOPSIS
        Builds the resolved-names.json dictionary: every referenced ID to { displayName, type, deleted }.
    .DESCRIPTION
        Users, groups and service principals resolve through getByIds. Roles resolve from the role definitions
        list (built-in role definition ids equal the template ids policies use). Applications are app ids and
        resolve through service principals. Locations, strengths and contexts resolve from the exported
        collections. Built-in values and user actions get a fixed label. Anything not found is flagged deleted.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [hashtable] $Reference,
        [AllowEmptyCollection()] [object[]] $Location = @(),
        [AllowEmptyCollection()] [object[]] $Strength = @(),
        [AllowEmptyCollection()] [object[]] $Context = @()
    )

    $ErrorActionPreference = 'Stop'
    $names = @{}

    $builtInLabels = @{
        'All'                   = 'All (built-in)'
        'None'                  = 'None (built-in)'
        'GuestsOrExternalUsers' = 'All guest and external users (built-in)'
        'Office365'             = 'Office 365 (built-in app group)'
        'MicrosoftAdminPortals' = 'Microsoft Admin Portals (built-in app group)'
        'AllTrusted'            = 'All trusted locations (built-in)'
        'ServicePrincipalsInMyTenant' = 'All workload identities in the tenant (built-in)'
    }
    foreach ($v in $Reference['builtIn']) {
        $names[$v] = [ordered]@{ displayName = $builtInLabels[$v]; type = 'builtIn'; deleted = $false }
    }

    $userActionLabels = @{
        'urn:user:registersecurityinfo' = 'Register security information'
        'urn:user:registerdevice'       = 'Register or join devices'
    }
    foreach ($v in $Reference['userActions']) {
        $label = if ($userActionLabels.ContainsKey($v)) { $userActionLabels[$v] } else { $v }
        $names[$v] = [ordered]@{ displayName = $label; type = 'userAction'; deleted = $false }
    }

    # Directory objects in one batched lookup.
    $directoryIds = @($Reference['users']) + @($Reference['groups']) + @($Reference['servicePrincipals'])
    if ($directoryIds.Count -gt 0) {
        $found = Resolve-PostureDirectoryObject -Id $directoryIds
        foreach ($id in $directoryIds) {
            $entry = $found[$id]
            if ($entry['deleted']) {
                $expected = if ($Reference['users'].Contains($id)) { 'user' } elseif ($Reference['groups'].Contains($id)) { 'group' } else { 'servicePrincipal' }
                $entry['type'] = $expected
            }
            $names[$id] = $entry
        }
    }

    # Roles: policies reference role template ids; built-in role definition ids are the same values.
    if ($Reference['roles'].Count -gt 0) {
        $roleDefs = @(Invoke-PostureGraphRequest -Uri 'roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn,templateId' -ApiVersion 'v1.0')
        $roleById = @{}
        foreach ($r in $roleDefs) {
            $roleById[[string]$r.id] = $r
            $tid = Get-PostureValue $r 'templateId'
            if ($tid) { $roleById[[string]$tid] = $r }
        }
        foreach ($id in $Reference['roles']) {
            if ($roleById.ContainsKey($id)) {
                $names[$id] = [ordered]@{ displayName = $roleById[$id].displayName; type = 'role'; deleted = $false; isBuiltIn = [bool](Get-PostureValue $roleById[$id] 'isBuiltIn') }
            }
            else {
                $names[$id] = [ordered]@{ displayName = $null; type = 'role'; deleted = $true }
            }
        }
    }

    # Applications: app ids, resolved through service principals in batches.
    $appIds = @($Reference['applications'])
    if ($appIds.Count -gt 0) {
        $spByAppId = @{}
        $batchSize = 15
        for ($i = 0; $i -lt $appIds.Count; $i += $batchSize) {
            $batch = $appIds[$i..([Math]::Min($i + $batchSize, $appIds.Count) - 1)]
            $list = ($batch | ForEach-Object { "'$_'" }) -join ','
            $uri = "servicePrincipals?`$filter=appId in ($list)&`$select=id,appId,displayName,servicePrincipalType"
            foreach ($sp in @(Invoke-PostureGraphRequest -Uri $uri -ApiVersion 'v1.0')) { $spByAppId[[string]$sp.appId] = $sp }
        }
        foreach ($id in $appIds) {
            if ($spByAppId.ContainsKey($id)) {
                $sp = $spByAppId[$id]
                $names[$id] = [ordered]@{ displayName = $sp.displayName; type = 'application'; deleted = $false; servicePrincipalId = [string]$sp.id; servicePrincipalType = Get-PostureValue $sp 'servicePrincipalType' }
            }
            else {
                $names[$id] = [ordered]@{ displayName = $null; type = 'application'; deleted = $true }
            }
        }
    }

    $local = @(
        @{ Bucket = 'locations'; Type = 'namedLocation'; Items = $Location }
        @{ Bucket = 'authenticationStrengths'; Type = 'authenticationStrength'; Items = $Strength }
        @{ Bucket = 'authenticationContexts'; Type = 'authenticationContext'; Items = $Context }
    )
    foreach ($set in $local) {
        $byId = @{}
        foreach ($item in $set.Items) { $byId[[string]$item.id] = $item }
        foreach ($id in $Reference[$set.Bucket]) {
            if ($byId.ContainsKey($id)) {
                $names[$id] = [ordered]@{ displayName = $byId[$id].displayName; type = $set.Type; deleted = $false }
            }
            else {
                $names[$id] = [ordered]@{ displayName = $null; type = $set.Type; deleted = $true }
            }
        }
    }

    $ordered = [ordered]@{}
    foreach ($key in ($names.Keys | Sort-Object)) { $ordered[$key] = $names[$key] }
    return $ordered
}
