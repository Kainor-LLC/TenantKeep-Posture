# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureReferenceCoverage {
    <#
    .SYNOPSIS
        How much of each public reference the catalog covers: every item with the checks that name it, or the
        reason no check does.
    .DESCRIPTION
        A reference file (checks/references/<name>.json) lists every item of one public reference, such as each
        policy of CISA's SCuBA baselines, and under notCovered the items no check covers, each with a reason:
        planned (a check is still to be written), noReadApi (Microsoft offers no read-only way to see the setting)
        or outOfScope (it does not apply to the tenants this report is for). A check names an item in the
        frameworks key or the references key the file's checkKeys give.

        A reference marked passThrough is one whose every item reaches the report whether a check names it or not:
        Microsoft Secure Score, whose open actions the report lists from Microsoft's own evaluation. There an item
        with no check needs no reason and is counted as passThrough.

        Returns one entry per reference: name, title, version, counts (total, covered, planned, noReadApi,
        outOfScope, passThrough), items (id, text, checks, reason, note) and problems. A problem is an item with neither a check
        nor a reason, an item with both, a reason outside the three, a note left empty, a notCovered id the
        reference does not have, or a check naming an id the reference does not have (a policy renumbered or
        retired since). The catalog test fails on any problem, so the count of what is covered cannot drift.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Catalog)

    $ErrorActionPreference = 'Stop'
    $reasons = 'planned', 'noReadApi', 'outOfScope'
    $out = [System.Collections.Generic.List[object]]::new()
    $references = $(if ($Catalog.Contains('references') -and $Catalog['references']) { $Catalog['references'] } else { @{} })
    foreach ($name in @($references.get_Keys())) {
        $doc = $references[$name]
        $items = $doc['items']
        $notCovered = $doc['notCovered']
        $frameworkKey = [string]$doc['checkKeys']['framework']
        $referenceKey = [string]$doc['checkKeys']['reference']
        $problems = [System.Collections.Generic.List[string]]::new()

        # Which checks name which ids. The built-in catalog only: a customer's own checks are not measured.
        $namedBy = @{}
        foreach ($check in @($Catalog['checks'])) {
            if (-not $check -or ($check.Contains('custom') -and $check['custom'])) { continue }
            $ids = [System.Collections.Generic.List[string]]::new()
            if ($frameworkKey -and $check['frameworks'] -is [System.Collections.IDictionary] -and $check['frameworks'].Contains($frameworkKey) -and $check['frameworks'][$frameworkKey]) { $ids.Add([string]$check['frameworks'][$frameworkKey]) }
            if ($referenceKey -and $check.Contains('references') -and $check['references'] -is [System.Collections.IDictionary] -and $check['references'].Contains($referenceKey)) { foreach ($id in @($check['references'][$referenceKey])) { $ids.Add([string]$id) } }
            foreach ($id in @($ids | Sort-Object -Unique)) {
                if (-not $items.Contains($id)) { $problems.Add("$($check['id']) names $id, which $name $($doc['version']) does not have"); continue }
                if (-not $namedBy.ContainsKey($id)) { $namedBy[$id] = [System.Collections.Generic.List[string]]::new() }
                $namedBy[$id].Add([string]$check['id'])
            }
        }
        foreach ($id in @($notCovered.get_Keys())) { if (-not $items.Contains($id)) { $problems.Add("notCovered lists $id, which $name $($doc['version']) does not have") } }

        $passThrough = [bool]($doc.Contains('passThrough') -and $doc['passThrough'])
        $counts = [ordered]@{ total = 0; covered = 0; planned = 0; noReadApi = 0; outOfScope = 0; passThrough = 0 }
        $rows = foreach ($id in @($items.get_Keys())) {
            $counts.total++
            $checks = @($(if ($namedBy.ContainsKey($id)) { $namedBy[$id] }))
            $entry = $(if ($notCovered.Contains($id)) { $notCovered[$id] } else { $null })
            $reason = $(if ($entry) { [string]$entry['reason'] } else { '' })
            $note = $(if ($entry) { [string]$entry['note'] } else { '' })
            if ($checks.Count -gt 0 -and $entry) { $problems.Add("$id is named by $($checks -join ', ') and also listed as not covered") }
            elseif ($checks.Count -gt 0) { $counts.covered++ }
            elseif (-not $entry -and $passThrough) { $counts.passThrough++ }
            elseif (-not $entry) { $problems.Add("$id has no check and no reason") }
            elseif ($reason -notin $reasons) { $problems.Add("$id has the reason '$reason'; expected $($reasons -join ', ')") }
            elseif ([string]::IsNullOrWhiteSpace($note)) { $problems.Add("$id is not covered and its note is empty") }
            else { $counts[$reason]++ }
            [ordered]@{ id = $id; text = [string]$items[$id]; checks = $checks; reason = $reason; note = $note }
        }
        $out.Add([ordered]@{ name = [string]$name; title = [string]$doc['title']; version = [string]$doc['version']; source = [string]$doc['source']; counts = $counts; items = @($rows); problems = @($problems) })
    }
    $out.ToArray()
}
