# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureCaReference {
    <#
    .SYNOPSIS
        Collects every ID referenced by a set of Conditional Access policies, grouped by what kind of thing it names.
    .DESCRIPTION
        Walks assignments, target resources, conditions and grant controls. Special values such as 'All',
        'GuestsOrExternalUsers', 'Office365' or 'AllTrusted' are kept in their own bucket so they resolve to a
        built-in label instead of a directory lookup. Returns a hashtable of HashSet[string] per bucket.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Policy
    )

    $ErrorActionPreference = 'Stop'

    $buckets = @{}
    foreach ($name in 'users', 'groups', 'roles', 'servicePrincipals', 'applications', 'userActions', 'authenticationContexts', 'locations', 'authenticationStrengths', 'builtIn') {
        $buckets[$name] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }

    $builtIn = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($v in 'All', 'None', 'GuestsOrExternalUsers', 'Office365', 'MicrosoftAdminPortals', 'AllTrusted') { $null = $builtIn.Add($v) }

    $add = {
        param([string] $Bucket, [object] $Values)
        foreach ($v in @($Values)) {
            if ([string]::IsNullOrWhiteSpace([string]$v)) { continue }
            if ($builtIn.Contains([string]$v)) { $null = $buckets['builtIn'].Add([string]$v) }
            else { $null = $buckets[$Bucket].Add([string]$v) }
        }
    }

    foreach ($p in $Policy) {
        & $add 'users'  (Get-PostureValue $p 'conditions.users.includeUsers')
        & $add 'users'  (Get-PostureValue $p 'conditions.users.excludeUsers')
        & $add 'groups' (Get-PostureValue $p 'conditions.users.includeGroups')
        & $add 'groups' (Get-PostureValue $p 'conditions.users.excludeGroups')
        & $add 'roles'  (Get-PostureValue $p 'conditions.users.includeRoles')
        & $add 'roles'  (Get-PostureValue $p 'conditions.users.excludeRoles')

        & $add 'servicePrincipals' (Get-PostureValue $p 'conditions.clientApplications.includeServicePrincipals')
        & $add 'servicePrincipals' (Get-PostureValue $p 'conditions.clientApplications.excludeServicePrincipals')

        & $add 'applications'           (Get-PostureValue $p 'conditions.applications.includeApplications')
        & $add 'applications'           (Get-PostureValue $p 'conditions.applications.excludeApplications')
        & $add 'userActions'            (Get-PostureValue $p 'conditions.applications.includeUserActions')
        & $add 'authenticationContexts' (Get-PostureValue $p 'conditions.applications.includeAuthenticationContextClassReferences')

        & $add 'locations' (Get-PostureValue $p 'conditions.locations.includeLocations')
        & $add 'locations' (Get-PostureValue $p 'conditions.locations.excludeLocations')

        & $add 'authenticationStrengths' (Get-PostureValue $p 'grantControls.authenticationStrength.id')
    }

    return $buckets
}
