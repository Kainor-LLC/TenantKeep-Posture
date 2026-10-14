# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function ConvertTo-PostureCaDiffHtml {
    <#
    .SYNOPSIS
        Renders a Compare-PostureCaSnapshot report model as one self-contained HTML file, risk-relevant changes first.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Report
    )

    $ErrorActionPreference = 'Stop'
    $sb = [System.Text.StringBuilder]::new()
    $w = { param([string] $Text = '') $null = $sb.AppendLine($Text) }
    $h = { param([object] $Text) [System.Net.WebUtility]::HtmlEncode([string]$Text) }
    $fmtDate = { param($Value) $u = ConvertTo-PostureUtcDateTime $Value; if ($u) { $u.ToString('yyyy-MM-dd HH:mm') + ' UTC' } else { 'unknown' } }
    $stateLabel = @{ enabled = 'Enabled'; reportOnly = 'Report-only'; disabled = 'Disabled' }
    $st = { param($s) if ($stateLabel.ContainsKey([string]$s)) { $stateLabel[[string]$s] } else { [string]$s } }
    $blank = { param($v) if ([string]::IsNullOrEmpty([string]$v)) { '<em>(empty)</em>' } else { & $h $v } }
    $fieldTable = {
        param($Fields)
        & $w '<table class="diff"><thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead><tbody>'
        foreach ($f in @($Fields)) { & $w "<tr><td><code>$(& $h $f.path)</code></td><td class=`"before`">$(& $blank $f.before)</td><td class=`"after`">$(& $blank $f.after)</td></tr>" }
        & $w '</tbody></table>'
    }
    $safeColor = { param([string] $c, [string] $fallback) if ($c -match '^#[0-9A-Fa-f]{3,8}$') { $c } else { $fallback } }

    $r = $Report; $d = $r.diff; $b = $r.brand; $c = $r.counts
    $css = Get-Content -LiteralPath (Get-PostureTemplatePath -Name 'ca-document.css') -Raw
    $font = if ($b.font) { [string]$b.font } else { 'Inter, Helvetica, Arial, sans-serif' }
    $override = ":root { --primary: $(& $safeColor ([string]$b.colors.primary) '#1F3A5F'); --accent: $(& $safeColor ([string]$b.colors.accent) '#E8A33D'); --font: $(& $h ($font -replace '[^A-Za-z0-9 ,\-]', '')); }"

    & $w '<!DOCTYPE html>'
    & $w '<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
    & $w "<meta http-equiv=`"Content-Security-Policy`" content=`"default-src 'none'; img-src data:; style-src 'unsafe-inline'`">"
    & $w "<title>$(& $h $r.title)</title>"
    & $w "<style>`n$css`n$override`n</style></head><body>"
    & $w '<header class="doc"><div class="brand"><div>'
    & $w "<h1>$(& $h $r.title)</h1>"
    $prepared = [string]$b.preparedBy.name
    if ($b.client.name) { $prepared += " for $($b.client.name)" }
    & $w "<div class=`"meta`">Prepared by $(& $h $prepared). Before: $(& $fmtDate $d.before.timestampUtc) ($($d.before.policyCount) policies). After: $(& $fmtDate $d.after.timestampUtc) ($($d.after.policyCount) policies). Tenant <code>$(& $h $d.after.tenantId)</code>. Generated $(& $fmtDate $r.generatedUtc) with Tenantkeep.Posture $(& $h $r.moduleVersion).</div>"
    if ($b.confidentiality) { & $w "<div class=`"confidential`">$(& $h $b.confidentiality)</div>" }
    & $w '</div></div></header><main>'

    & $w '<section id="risk"><h2>Risk-relevant changes</h2>'
    if (@($d.risk).Count -eq 0) { & $w '<p>None.</p>' }
    else {
        & $w "<div class=`"notice`"><strong>$(@($d.risk).Count) change(s) need a look.</strong></div>"
        & $w '<table class="risk"><thead><tr><th>Rule</th><th>Subject</th><th>Detail</th></tr></thead><tbody>'
        foreach ($x in @($d.risk)) { & $w "<tr><td>$(& $h $x.rule)</td><td>$(& $h $x.subject)</td><td>$(& $h $x.detail)</td></tr>" }
        & $w '</tbody></table>'
    }
    & $w '</section>'

    & $w '<section id="summary"><h2>Summary</h2><div class="stats">'
    foreach ($pair in @(@('Added', $c.added), @('Removed', $c.removed), @('Renamed', $c.renamed), @('State changed', $c.stateChanged), @('Modified', $c.modified), @('Locations', $c.locations), @('Strengths', $c.strengths), @('Contexts', $c.contexts), @('Groups drifted', $c.scope))) {
        & $w "<div class=`"stat`"><div class=`"n`">$($pair[1])</div><div class=`"l`">$($pair[0])</div></div>"
    }
    & $w '</div>'
    if ($r.noChanges) { & $w '<p>No differences between the two snapshots.</p>' }
    & $w '</section>'

    foreach ($set in @(@('added', 'Policies added', 'after'), @('removed', 'Policies removed', 'before'))) {
        $key, $title, $side = $set
        & $w "<section id=`"policies-$key`"><h2>$title</h2>"
        $items = @($d.policies[$key])
        if ($items.Count -eq 0) { & $w '<p>None.</p>' }
        else {
            & $w '<table><thead><tr><th>Policy</th><th>State</th><th>Summary</th></tr></thead><tbody>'
            foreach ($p in $items) { & $w "<tr><td class=`"$key`">$(& $h $p.name)</td><td>$(& $h (& $st $p.state))</td><td>$(& $h $p[$side].summary)</td></tr>" }
            & $w '</tbody></table>'
        }
        & $w '</section>'
    }

    & $w '<section id="policies-changed"><h2>Policies changed</h2>'
    if (@($d.policies.changed).Count -eq 0) { & $w '<p>None.</p>' }
    foreach ($p in @($d.policies.changed)) {
        & $w "<article class=`"policy`"><h3>$(& $h $p.name)<span class=`"badge $(& $h $p.stateAfter)`">$(& $h (& $st $p.stateAfter))</span></h3><ul>"
        if ($p.renamed) { & $w "<li>Renamed from <strong>$(& $h $p.nameBefore)</strong></li>" }
        if ($p.stateChanged) { & $w "<li>State: <strong>$(& $h (& $st $p.stateBefore))</strong> to <strong>$(& $h (& $st $p.stateAfter))</strong></li>" }
        & $w "<li>Last modified: $(& $fmtDate $p.modifiedBefore) to $(& $fmtDate $p.modifiedAfter)</li>"
        & $w "<li>Now: $(& $h $p.after.summary)</li></ul>"
        if (@($p.fields).Count -gt 0) { & $fieldTable $p.fields }
        & $w '</article>'
    }
    & $w '</section>'

    foreach ($coll in @($d.locations, $d.strengths, $d.contexts)) {
        & $w "<section><h2>$(& $h $coll.label)</h2>"
        if (@($coll.added).Count + @($coll.removed).Count + @($coll.changed).Count -eq 0) { & $w '<p>No changes.</p></section>'; continue }
        if (@($coll.added).Count -gt 0) { & $w "<p>Added: <span class=`"added`">$(& $h (@($coll.added | ForEach-Object { $_.name }) -join ', '))</span></p>" }
        if (@($coll.removed).Count -gt 0) { & $w "<p>Removed: <span class=`"removed`">$(& $h (@($coll.removed | ForEach-Object { $_.name }) -join ', '))</span></p>" }
        foreach ($x in @($coll.changed)) { & $w "<h3>$(& $h $x.name)</h3>"; & $fieldTable $x.fields }
        & $w '</section>'
    }

    & $w '<section id="scope"><h2>Scope drift</h2>'
    if (@($d.scope).Count -eq 0) { & $w '<p>No referenced group changed.</p>' }
    else {
        & $w '<table><thead><tr><th>Group</th><th>Before</th><th>After</th><th>Delta</th><th>Members added</th><th>Members removed</th></tr></thead><tbody>'
        foreach ($g in @($d.scope)) {
            $label = { param($m) if ($m.userPrincipalName) { $m.userPrincipalName } else { $m.displayName } }
            $added = if ($g.memberDetail) { @($g.membersAdded | ForEach-Object { & $label $_ }) -join ', ' } else { 'n/a (no -IncludeMembers)' }
            $removed = if ($g.memberDetail) { @($g.membersRemoved | ForEach-Object { & $label $_ }) -join ', ' } else { 'n/a (no -IncludeMembers)' }
            $delta = if ($null -ne $g.delta) { ('{0:+#;-#;0}' -f $g.delta) } else { '?' }
            & $w "<tr><td>$(& $h $g.name)</td><td>$(& $h $g.countBefore)</td><td>$(& $h $g.countAfter)</td><td>$(& $h $delta)</td><td class=`"added`">$(& $h $added)</td><td class=`"removed`">$(& $h $removed)</td></tr>"
        }
        & $w '</tbody></table>'
    }
    & $w '</section>'

    & $w '<section id="appendix"><h2>Appendix</h2><table class="kv"><tbody>'
    & $w "<tr><th>Before snapshot</th><td>$(& $h $d.before.path)</td></tr><tr><th>After snapshot</th><td>$(& $h $d.after.path)</td></tr>"
    & $w "<tr><th>Break-glass accounts</th><td>$(& $h $(if ($r.breakGlass) { $r.breakGlass -join ', ' } else { 'name heuristic (break-glass, emergency)' }))</td></tr>"
    & $w '</tbody></table></section></main>'
    if ($b.footer) { & $w "<footer class=`"doc`">$(& $h $b.footer)</footer>" }
    & $w '</body></html>'
    return $sb.ToString()
}
