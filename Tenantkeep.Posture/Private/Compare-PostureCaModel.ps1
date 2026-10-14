# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Compare-PostureCaModel {
    <#
    .SYNOPSIS
        The diff engine behind Compare-PostureCaSnapshot (spec 5.3): policies, locations, strengths, contexts, scope drift.
    .DESCRIPTION
        Takes two Import-PostureCaSnapshot objects. Policies are matched by id and classified as added, removed,
        renamed, stateChanged or modified (a policy can be several of these). Field-level changes come from the
        resolved policy model, so they read with names rather than ids. Risk-relevant changes are evaluated by
        Get-PostureCaRiskChange on the result.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Before,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $After,
        [string[]] $BreakGlass
    )

    $ErrorActionPreference = 'Stop'

    $beforeModels = @{}; foreach ($m in @(ConvertTo-PostureCaPolicyModel -Snapshot $Before)) { $beforeModels[$m.id] = $m }
    $afterModels = @{}; foreach ($m in @(ConvertTo-PostureCaPolicyModel -Snapshot $After)) { $afterModels[$m.id] = $m }

    # Policies
    $added = @(); $removed = @(); $changed = @()
    foreach ($id in ($afterModels.Keys | Sort-Object)) {
        if (-not $beforeModels.ContainsKey($id)) { $added += , [ordered]@{ id = $id; name = $afterModels[$id].name; state = $afterModels[$id].state; after = $afterModels[$id] } }
    }
    foreach ($id in ($beforeModels.Keys | Sort-Object)) {
        if (-not $afterModels.ContainsKey($id)) { $removed += , [ordered]@{ id = $id; name = $beforeModels[$id].name; state = $beforeModels[$id].state; before = $beforeModels[$id] } }
    }
    foreach ($id in ($beforeModels.Keys | Sort-Object)) {
        if (-not $afterModels.ContainsKey($id)) { continue }
        $b = $beforeModels[$id]; $a = $afterModels[$id]
        $fields = @(Compare-PostureCaFlatMap -Before (ConvertTo-PostureCaFlatMap $b) -After (ConvertTo-PostureCaFlatMap $a))
        $renamed = $b.name -cne $a.name
        $stateChanged = $b.state -ne $a.state
        if (-not ($renamed -or $stateChanged -or $fields.Count -gt 0)) { continue }
        $changed += , [ordered]@{
            id           = $id
            name         = $a.name
            nameBefore   = $b.name
            renamed      = $renamed
            stateChanged = $stateChanged
            stateBefore  = $b.state
            stateAfter   = $a.state
            modified     = ($fields.Count -gt 0)
            fields       = $fields
            modifiedBefore = $b.modified
            modifiedAfter  = $a.modified
            before       = $b
            after        = $a
        }
    }

    # Collections keyed by id: named locations, strengths, contexts
    $collection = {
        param([object[]] $B, [object[]] $A, [string] $Label)
        $bById = @{}; foreach ($x in $B) { $bById[[string]$x.id] = $x }
        $aById = @{}; foreach ($x in $A) { $aById[[string]$x.id] = $x }
        $cAdded = @(foreach ($k in ($aById.Keys | Sort-Object)) { if (-not $bById.ContainsKey($k)) { [ordered]@{ id = $k; name = [string](Get-PostureValue $aById[$k] 'displayName'); after = $aById[$k] } } })
        $cRemoved = @(foreach ($k in ($bById.Keys | Sort-Object)) { if (-not $aById.ContainsKey($k)) { [ordered]@{ id = $k; name = [string](Get-PostureValue $bById[$k] 'displayName'); before = $bById[$k] } } })
        $cChanged = @(foreach ($k in ($bById.Keys | Sort-Object)) {
                if (-not $aById.ContainsKey($k)) { continue }
                $f = @(Compare-PostureCaFlatMap -Before (ConvertTo-PostureCaFlatMap $bById[$k] -Exclude @('createdDateTime', 'modifiedDateTime')) -After (ConvertTo-PostureCaFlatMap $aById[$k] -Exclude @('createdDateTime', 'modifiedDateTime')))
                if ($f.Count -gt 0) { [ordered]@{ id = $k; name = [string](Get-PostureValue $aById[$k] 'displayName'); fields = $f; before = $bById[$k]; after = $aById[$k] } }
            })
        [ordered]@{ label = $Label; added = $cAdded; removed = $cRemoved; changed = $cChanged }
    }
    $locations = & $collection $Before.NamedLocations $After.NamedLocations 'Named locations'
    $strengths = & $collection $Before.AuthStrengths $After.AuthStrengths 'Authentication strengths'
    $contexts = & $collection $Before.AuthContexts $After.AuthContexts 'Authentication context'

    # Scope drift
    $groupIds = @($Before.GroupScope.Keys) + @($After.GroupScope.Keys) | Sort-Object -Unique
    $scope = @(foreach ($gid in $groupIds) {
            $bs = $Before.GroupScope[$gid]; $as = $After.GroupScope[$gid]
            $bCount = if ($bs) { Get-PostureValue $bs 'memberCount' } else { $null }
            $aCount = if ($as) { Get-PostureValue $as 'memberCount' } else { $null }
            $bHash = if ($bs) { Get-PostureValue $bs 'memberHash' } else { $null }
            $aHash = if ($as) { Get-PostureValue $as 'memberHash' } else { $null }
            if ($bHash -eq $aHash -and $bCount -eq $aCount) { continue }
            $ref = Resolve-PostureCaRef -Snapshot $After -Id $gid -ExpectedType 'group'
            if ($ref.deleted -or $ref.type -eq 'unknown') { $ref = Resolve-PostureCaRef -Snapshot $Before -Id $gid -ExpectedType 'group' }
            $entry = [ordered]@{
                groupId = $gid; name = $ref.name
                countBefore = $bCount; countAfter = $aCount
                delta = $(if ($null -ne $bCount -and $null -ne $aCount) { $aCount - $bCount } else { $null })
                hashChanged = ($bHash -ne $aHash)
                membersAdded = @(); membersRemoved = @(); memberDetail = $false
            }
            $bm = if ($bs -and $bs.Contains('members')) { @($bs.members) } else { $null }
            $am = if ($as -and $as.Contains('members')) { @($as.members) } else { $null }
            if ($null -ne $bm -and $null -ne $am) {
                $entry.memberDetail = $true
                $bIds = @{}; foreach ($m in $bm) { $bIds[[string]$m.id] = $m }
                $aIds = @{}; foreach ($m in $am) { $aIds[[string]$m.id] = $m }
                $entry.membersAdded = @(foreach ($k in ($aIds.Keys | Sort-Object)) { if (-not $bIds.ContainsKey($k)) { $aIds[$k] } })
                $entry.membersRemoved = @(foreach ($k in ($bIds.Keys | Sort-Object)) { if (-not $aIds.ContainsKey($k)) { $bIds[$k] } })
            }
            $entry
        })

    $result = [ordered]@{
        before    = [ordered]@{ path = $Before.Path; timestampUtc = Get-PostureValue $Before.Metadata 'timestampUtc'; tenantId = Get-PostureValue $Before.Metadata 'tenantId'; policyCount = $beforeModels.Count }
        after     = [ordered]@{ path = $After.Path; timestampUtc = Get-PostureValue $After.Metadata 'timestampUtc'; tenantId = Get-PostureValue $After.Metadata 'tenantId'; policyCount = $afterModels.Count }
        policies  = [ordered]@{ added = @($added); removed = @($removed); changed = @($changed) }
        locations = $locations
        strengths = $strengths
        contexts  = $contexts
        scope     = $scope
        risk      = @()
    }
    $riskParams = @{ Diff = $result }
    if ($BreakGlass) { $riskParams.BreakGlass = $BreakGlass }
    $result.risk = @(Get-PostureCaRiskChange @riskParams)
    return $result
}
