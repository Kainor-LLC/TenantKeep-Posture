# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureGroupScope {
    <#
    .SYNOPSIS
        Member count and a SHA-256 of the sorted transitive member list for one group. Members only with -IncludeMembers.
    .DESCRIPTION
        Conditional Access evaluates nested groups, so the transitive member list is what a policy really covers.
        The hash lets Compare-PostureCaSnapshot detect scope drift between two runs without storing who is in the
        group. With -IncludeMembers the member ids, types, display names and UPNs are stored as well.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $GroupId,
        [switch] $IncludeMembers
    )

    $ErrorActionPreference = 'Stop'

    $uri = if ($IncludeMembers) { "groups/$GroupId/transitiveMembers?`$top=999" }
    else { "groups/$GroupId/transitiveMembers?`$select=id&`$top=999" }
    $members = @(Invoke-PostureGraphRequest -Uri $uri -ApiVersion 'v1.0')

    [string[]] $ids = @($members | ForEach-Object { [string]$_.id })
    [System.Array]::Sort($ids, [System.StringComparer]::Ordinal)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($ids -join "`n"))
    $hash = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()

    $scope = [ordered]@{
        groupId       = $GroupId
        memberCount   = $ids.Count
        memberHash    = $hash
        hashAlgorithm = 'sha256(sorted transitive member ids joined by LF)'
    }
    if ($IncludeMembers) {
        $scope.members = @($members | ForEach-Object {
                $m = [ordered]@{
                    id          = [string]$_.id
                    type        = ([string]$_['@odata.type']) -replace '^#microsoft\.graph\.', ''
                    displayName = Get-PostureValue $_ 'displayName'
                }
                $upn = Get-PostureValue $_ 'userPrincipalName'
                if ($upn) { $m.userPrincipalName = $upn }
                $m
            } | Sort-Object { $_.id })
    }
    return $scope
}
