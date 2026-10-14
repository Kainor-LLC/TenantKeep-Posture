# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function ConvertTo-PostureCaFlatMap {
    <#
    .SYNOPSIS
        Flattens a policy model (or any Graph object) into dotted path -> string, so two versions can be diffed field by field.
    .DESCRIPTION
        Lists of resolved references become their sorted names, lists of scalars are sorted and joined, lists of
        objects become sorted canonical JSON, dictionaries recurse, scalars become strings, nulls become empty strings. Keys in -Exclude are skipped
        at any depth; by default that is the bookkeeping the model carries (raw, summary, healthFlags, timestamps).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter()] [AllowNull()] [object] $Object,
        [string] $Prefix = '',
        [string[]] $Exclude = @('raw', 'summary', 'healthFlags', 'stateLabel', 'created', 'modified', 'createdDateTime', 'modifiedDateTime', 'id', 'name', 'state')
    )

    $ErrorActionPreference = 'Stop'
    $map = [ordered]@{}

    $isRef = { param($x) ($x -is [System.Collections.IDictionary]) -and $x.Contains('id') -and $x.Contains('name') -and $x.Contains('type') }
    $refLabel = { param($r) [string]$r.name }
    # Arrays of objects (ip ranges, guest types) become one canonical JSON string per item, sorted, so a reordered
    # list is not a change and an added item reads as one line rather than a cascade of index shifts.
    $canon = {
        param($v)
        if ($v -is [System.Collections.IDictionary]) {
            $o = [ordered]@{}
            foreach ($k in ($v.Keys | Sort-Object)) { $o[[string]$k] = & $canon $v[$k] }
            return $o
        }
        if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { return , @(@($v) | ForEach-Object { & $canon $_ }) }
        return $v
    }

    $walk = {
        param([object] $Value, [string] $Path)
        if ($null -eq $Value) { $map[$Path] = ''; return }
        if ($Value -is [string] -or $Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [datetime]) {
            $map[$Path] = if ($Value -is [datetime]) { $Value.ToString('o') } else { [string]$Value }
            return
        }
        if ($Value -is [System.Collections.IDictionary]) {
            if (& $isRef $Value) { $map[$Path] = & $refLabel $Value; return }
            foreach ($k in $Value.Keys) {
                if ($k -in $Exclude) { continue }
                & $walk $Value[$k] $(if ($Path) { "$Path.$k" } else { [string]$k })
            }
            return
        }
        if ($Value -is [System.Collections.IEnumerable]) {
            $items = @($Value)
            if ($items.Count -eq 0) { $map[$Path] = ''; return }
            if (@($items | Where-Object { & $isRef $_ }).Count -eq $items.Count) {
                $map[$Path] = (@($items | ForEach-Object { & $refLabel $_ }) | Sort-Object) -join '; '
                return
            }
            if (@($items | Where-Object { $_ -is [System.Collections.IDictionary] -or ($_ -is [System.Collections.IEnumerable] -and $_ -isnot [string]) }).Count -eq 0) {
                $map[$Path] = (@($items | ForEach-Object { [string]$_ }) | Sort-Object) -join '; '
                return
            }
            $map[$Path] = (@($items | ForEach-Object { ConvertTo-Json -InputObject (& $canon $_) -Depth 20 -Compress }) | Sort-Object) -join '; '
            return
        }
        $map[$Path] = [string]$Value
    }

    & $walk $Object $Prefix
    return $map
}

function Compare-PostureCaFlatMap {
    <#
    .SYNOPSIS
        Field-level differences between two flat maps: path, before, after. Paths present on one side only count as changed.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Before,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $After
    )

    $ErrorActionPreference = 'Stop'
    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($k in $Before.Keys) { $paths.Add([string]$k) }
    foreach ($k in $After.Keys) { if (-not $Before.Contains($k)) { $paths.Add([string]$k) } }
    $changes = foreach ($p in $paths) {
        $b = if ($Before.Contains($p)) { [string]$Before[$p] } else { '' }
        $a = if ($After.Contains($p)) { [string]$After[$p] } else { '' }
        if ($b -cne $a) { [ordered]@{ path = $p; before = $b; after = $a } }
    }
    return @($changes)
}
