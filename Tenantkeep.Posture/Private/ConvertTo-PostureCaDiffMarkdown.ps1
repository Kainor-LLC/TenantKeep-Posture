# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function ConvertTo-PostureCaDiffMarkdown {
    <#
    .SYNOPSIS
        Renders a Compare-PostureCaSnapshot report model as email-ready Markdown, risk-relevant changes first.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Report
    )

    $ErrorActionPreference = 'Stop'
    $sb = [System.Text.StringBuilder]::new()
    $line = { param([string] $Text = '') $null = $sb.AppendLine($Text) }
    $esc = { param([object] $Text) ([string]$Text).Replace('|', '\|').Replace("`r", '').Replace("`n", ' ') }
    $fmtDate = { param($Value) $u = ConvertTo-PostureUtcDateTime $Value; if ($u) { $u.ToString('yyyy-MM-dd HH:mm') + ' UTC' } else { 'unknown' } }
    $table = {
        param([string[]] $Headers, [object[]] $Rows)
        & $line "| $($Headers -join ' | ') |"
        & $line "|$(@($Headers | ForEach-Object { '---' }) -join '|')|"
        foreach ($r in $Rows) { & $line "| $(@($r | ForEach-Object { & $esc $_ }) -join ' | ') |" }
        & $line
    }
    $stateLabel = @{ enabled = 'Enabled'; reportOnly = 'Report-only'; disabled = 'Disabled' }
    $st = { param($s) if ($stateLabel.ContainsKey([string]$s)) { $stateLabel[[string]$s] } else { [string]$s } }
    $blank = { param($v) if ([string]::IsNullOrEmpty([string]$v)) { '(empty)' } else { [string]$v } }

    $r = $Report; $d = $r.diff; $b = $r.brand
    & $line "# $($r.title)"
    & $line
    $prepared = [string]$b.preparedBy.name
    if ($b.client.name) { $prepared += " for $($b.client.name)" }
    & $line "Prepared by $prepared. Before: $(& $fmtDate $d.before.timestampUtc) ($($d.before.policyCount) policies). After: $(& $fmtDate $d.after.timestampUtc) ($($d.after.policyCount) policies). Tenant ``$($d.after.tenantId)``. Generated $(& $fmtDate $r.generatedUtc) with Tenantkeep.Posture $($r.moduleVersion)."
    if ($b.confidentiality) { & $line; & $line "*$($b.confidentiality)*" }
    & $line

    & $line '## Risk-relevant changes'
    & $line
    if (@($d.risk).Count -eq 0) { & $line 'None.'; & $line }
    else {
        & $line "**$(@($d.risk).Count) change(s) need a look.**"
        & $line
        & $table @('Rule', 'Subject', 'Detail') @($d.risk | ForEach-Object { , @($_.rule, $_.subject, $_.detail) })
    }

    & $line '## Summary'
    & $line
    $c = $r.counts
    & $table @('Added', 'Removed', 'Renamed', 'State changed', 'Modified', 'Locations', 'Strengths', 'Contexts', 'Groups drifted') @(, @($c.added, $c.removed, $c.renamed, $c.stateChanged, $c.modified, $c.locations, $c.strengths, $c.contexts, $c.scope))
    if ($r.noChanges) { & $line 'No differences between the two snapshots.'; & $line }

    & $line '## Policies added'
    & $line
    if (@($d.policies.added).Count -eq 0) { & $line 'None.'; & $line }
    else { & $table @('Policy', 'State', 'Summary') @($d.policies.added | ForEach-Object { , @($_.name, (& $st $_.state), $_.after.summary) }) }

    & $line '## Policies removed'
    & $line
    if (@($d.policies.removed).Count -eq 0) { & $line 'None.'; & $line }
    else { & $table @('Policy', 'State', 'Summary') @($d.policies.removed | ForEach-Object { , @($_.name, (& $st $_.state), $_.before.summary) }) }

    & $line '## Policies changed'
    & $line
    if (@($d.policies.changed).Count -eq 0) { & $line 'None.'; & $line }
    foreach ($p in @($d.policies.changed)) {
        & $line "### $(& $esc $p.name)"
        & $line
        if ($p.renamed) { & $line "- Renamed from **$(& $esc $p.nameBefore)**" }
        if ($p.stateChanged) { & $line "- State: **$(& $st $p.stateBefore)** to **$(& $st $p.stateAfter)**" }
        & $line "- Last modified: $(& $fmtDate $p.modifiedBefore) to $(& $fmtDate $p.modifiedAfter)"
        & $line "- Now: $(& $esc $p.after.summary)"
        & $line
        if (@($p.fields).Count -gt 0) { & $table @('Field', 'Before', 'After') @($p.fields | ForEach-Object { , @($_.path, (& $blank $_.before), (& $blank $_.after)) }) }
    }

    foreach ($coll in @($d.locations, $d.strengths, $d.contexts)) {
        & $line "## $($coll.label)"
        & $line
        if (@($coll.added).Count + @($coll.removed).Count + @($coll.changed).Count -eq 0) { & $line 'No changes.'; & $line; continue }
        if (@($coll.added).Count -gt 0) { & $line "Added: $(@($coll.added | ForEach-Object { & $esc $_.name }) -join ', ')"; & $line }
        if (@($coll.removed).Count -gt 0) { & $line "Removed: $(@($coll.removed | ForEach-Object { & $esc $_.name }) -join ', ')"; & $line }
        foreach ($x in @($coll.changed)) {
            & $line "### $(& $esc $x.name)"
            & $line
            & $table @('Field', 'Before', 'After') @($x.fields | ForEach-Object { , @($_.path, (& $blank $_.before), (& $blank $_.after)) })
        }
    }

    & $line '## Scope drift'
    & $line
    if (@($d.scope).Count -eq 0) { & $line 'No referenced group changed.'; & $line }
    else {
        $rows = foreach ($g in @($d.scope)) {
            $added = if ($g.memberDetail) { @($g.membersAdded | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } }) -join ', ' } else { 'n/a (no -IncludeMembers)' }
            $removed = if ($g.memberDetail) { @($g.membersRemoved | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } }) -join ', ' } else { 'n/a (no -IncludeMembers)' }
            $delta = if ($null -ne $g.delta) { ('{0:+#;-#;0}' -f $g.delta) } else { '?' }
            , @($g.name, $g.countBefore, $g.countAfter, $delta, $added, $removed)
        }
        & $table @('Group', 'Before', 'After', 'Delta', 'Members added', 'Members removed') @($rows)
    }

    & $line '## Appendix'
    & $line
    & $table @('Field', 'Value') @(, @('Before snapshot', $d.before.path), @('After snapshot', $d.after.path), @('Break-glass accounts', $(if ($r.breakGlass) { $r.breakGlass -join ', ' } else { 'name heuristic (break-glass, emergency)' })))
    if ($b.footer) { & $line '---'; & $line; & $line $b.footer }
    return $sb.ToString()
}
