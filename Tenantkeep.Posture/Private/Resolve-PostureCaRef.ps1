# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Resolve-PostureCaRef {
    <#
    .SYNOPSIS
        Turns one referenced id into { id, name, type, deleted, memberCount } using the snapshot's resolved-names and group-scope.
    .DESCRIPTION
        Never throws on an unknown id: it is reported as type 'unknown' with the id as its name, so a document can
        always be rendered from a partial snapshot.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Snapshot,
        [Parameter(Mandatory)] [string] $Id,
        [string] $ExpectedType = 'unknown'
    )

    $ErrorActionPreference = 'Stop'

    $entry = $Snapshot.ResolvedNames[$Id]
    $ref = [ordered]@{ id = $Id; name = $Id; type = $ExpectedType; deleted = $false; memberCount = $null }
    if ($entry) {
        $ref.type = if ($entry.type) { [string]$entry.type } else { $ExpectedType }
        $ref.deleted = [bool](Get-PostureValue $entry 'deleted')
        $ref.name = if ($ref.deleted) { "<deleted $($ref.type) $Id>" } elseif ($entry.displayName) { [string]$entry.displayName } else { $Id }
        $upn = Get-PostureValue $entry 'userPrincipalName'
        if ($upn) { $ref.userPrincipalName = $upn }
    }
    else {
        $ref.name = "<unknown $Id>"
    }

    if ($Snapshot.GroupScope.ContainsKey($Id)) {
        $scope = $Snapshot.GroupScope[$Id]
        $ref.memberCount = Get-PostureValue $scope 'memberCount'
    }
    return $ref
}
