# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureGroupScope {
    <#
    .SYNOPSIS
        Member count and a SHA-256 of the sorted transitive member list for one group. Members only with -IncludeMembers.
    .DESCRIPTION
        Conditional Access evaluates nested groups, so the transitive member list is what a policy really covers.
        The hash lets Compare-PostureCaSnapshot detect scope drift between two runs without storing who is in the
        group. With -IncludeMembers the member ids, types, display names and UPNs are stored as well.

        The members are never held as objects for the hash: each page gives up its ids as text, the ids are sorted,
        and the hash is fed one id at a time. The bytes hashed are the ids joined by a line feed, as they always
        were, so a hash from an earlier version still compares.

        A group over -LargeGroupThreshold members (50,000) is counted and not hashed: one request asks Graph for
        the count, where the hash would take a page per 999 members on every run (301 pages for a group of 300,000,
        which is "all users" in a large tenant). memberHash is then empty and hashSkipped says why; the diff
        compares such a group by its count. -HashLargeGroups hashes it all the same, and -IncludeMembers reads
        every member whatever the size.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $GroupId,
        [switch] $IncludeMembers,
        [switch] $HashLargeGroups,
        [int] $LargeGroupThreshold = 50000
    )

    $ErrorActionPreference = 'Stop'
    $algorithm = 'sha256(sorted transitive member ids joined by LF)'

    if (-not $IncludeMembers -and -not $HashLargeGroups) {
        # One request for the size. The count is an advanced query (ConsistencyLevel: eventual), so it can trail a
        # change by a few minutes. When Graph does not answer it, the group is read as before.
        # (verify) live: $count=true on transitiveMembers with $top=1.
        $counted = $null
        try {
            $first = Invoke-PostureGraphRequest -Uri "groups/$GroupId/transitiveMembers?`$count=true&`$select=id&`$top=1" -ApiVersion 'v1.0' -Single -Headers @{ ConsistencyLevel = 'eventual' }
            if ($first -is [System.Collections.IDictionary] -and $first.Contains('@odata.count')) { $counted = [long]$first['@odata.count'] }
        }
        catch { Write-Verbose "Count of group $GroupId not available: $($_.Exception.Message)" }
        if ($null -ne $counted -and $counted -gt $LargeGroupThreshold) {
            return [ordered]@{
                groupId       = $GroupId
                memberCount   = $counted
                memberHash    = $null
                hashAlgorithm = $algorithm
                hashSkipped   = "More than $LargeGroupThreshold members: counted, not hashed. -HashLargeGroups hashes it; the diff compares it by its count."
            }
        }
    }

    $ids = [System.Collections.Generic.List[string]]::new()
    $members = $null
    if ($IncludeMembers) {
        $members = @(Invoke-PostureGraphRequest -Uri "groups/$GroupId/transitiveMembers?`$top=999" -ApiVersion 'v1.0')
        foreach ($m in $members) { $ids.Add([string]$m.id) }
    }
    else {
        $null = Invoke-PostureGraphRequest -Uri "groups/$GroupId/transitiveMembers?`$select=id&`$top=999" -ApiVersion 'v1.0' -Label 'Group members' -OnPage { param($page) foreach ($m in $page) { $ids.Add([string]$m['id']) } }
    }
    $ids.Sort([System.StringComparer]::Ordinal)
    $sha = [System.Security.Cryptography.IncrementalHash]::CreateHash([System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try {
        $lineFeed = [byte[]]@(10)
        for ($i = 0; $i -lt $ids.Count; $i++) {
            if ($i -gt 0) { $sha.AppendData($lineFeed) }
            $sha.AppendData([System.Text.Encoding]::UTF8.GetBytes($ids[$i]))
        }
        $hash = [System.Convert]::ToHexString($sha.GetHashAndReset()).ToLowerInvariant()
    }
    finally { $sha.Dispose() }

    $scope = [ordered]@{
        groupId       = $GroupId
        memberCount   = $ids.Count
        memberHash    = $hash
        hashAlgorithm = $algorithm
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
