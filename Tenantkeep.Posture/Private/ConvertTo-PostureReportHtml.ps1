# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function ConvertTo-PostureReportHtml {
    <#
    .SYNOPSIS
        Renders the report model as one self-contained interactive HTML file (spec 7): inline CSS and JS from
        templates/, embedded JSON blocks, every view rendered server-side so the page reads without scripts.
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
    $num = { param($x, [string] $suffix = '') if ($null -eq $x) { 'not collected yet' } else { "$x$suffix" } }
    $statusLabel = @{ pass = 'Pass'; fail = 'Fail'; notEvaluated = 'Not evaluated'; notApplicable = 'Not applicable'; acceptedRisk = 'Accepted risk'; coveredBy = 'Covered by' }
    $safeColor = { param([string] $c, [string] $fallback) if ($c -match '^#[0-9A-Fa-f]{3,8}$') { $c } else { $fallback } }
    $jsonBlock = { param([string] $Id, $Data) $json = (ConvertTo-Json -InputObject $Data -Depth 20 -Compress) -replace '</', '<\/'; "<script type=`"application/json`" id=`"$Id`">$json</script>" }
    $logoDataUri = {
        param([object] $Path)
        if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
        $ext = [System.IO.Path]::GetExtension([string]$Path).ToLowerInvariant()
        $mime = @{ '.svg' = 'image/svg+xml'; '.png' = 'image/png'; '.jpg' = 'image/jpeg'; '.jpeg' = 'image/jpeg'; '.gif' = 'image/gif'; '.webp' = 'image/webp' }[$ext]
        if (-not $mime) { return $null }
        'data:' + $mime + ';base64,' + [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($Path))
    }

    $r = $Report; $b = $r.brand
    $css = Get-Content -LiteralPath (Get-PostureTemplatePath -Name 'report.css') -Raw
    $js = Get-Content -LiteralPath (Get-PostureTemplatePath -Name 'report.js') -Raw
    $font = if ($b.font) { [string]$b.font } else { 'Inter, Helvetica, Arial, sans-serif' }
    $override = ":root { --primary: $(& $safeColor ([string]$b.colors.primary) '#1F3A5F'); --accent: $(& $safeColor ([string]$b.colors.accent) '#E8A33D'); --font: $(& $h ($font -replace '[^A-Za-z0-9 ,\-]', '')); }"

    & $w '<!DOCTYPE html>'
    & $w '<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
    & $w "<meta http-equiv=`"Content-Security-Policy`" content=`"default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'`">"
    & $w "<title>$(& $h $r.title)</title>"
    & $w "<style>`n$css`n$override`n</style></head>"
    & $w "<body data-template=`"$(& $h $r.template)`">"

    # Header and toolbar
    & $w '<header class="doc"><div>'
    $logo = & $logoDataUri (Get-PostureValue $b 'preparedBy.logo'); if (-not $logo) { $logo = & $logoDataUri (Get-PostureValue $b 'client.logo') }
    if ($logo) { & $w "<img class=`"logo`" alt=`"logo`" src=`"$logo`">" }
    & $w "<h1>$(& $h $r.title)</h1>"
    $prepared = [string]$b.preparedBy.name; if ($b.client.name) { $prepared += " for $($b.client.name)" }
    & $w "<div class=`"meta`">Prepared by $(& $h $prepared). Tenant $(if ($r.tenantName) { & $h "$($r.tenantName) " })<code>$(& $h $r.tenantId)</code>. Evidence collected $(& $fmtDate $r.collectedUtc). Generated $(& $fmtDate $r.generatedUtc) with Tenantkeep.Posture $(& $h $r.appendix.moduleVersion), catalog $(& $h $r.appendix.catalogVersion), baseline $(& $h $r.appendix.baseline).</div>"
    if ($b.confidentiality) { & $w "<div class=`"confidential`">$(& $h $b.confidentiality)</div>" }
    & $w '</div><div class="toolbar"><button type="button" id="toggle-exec" aria-pressed="false">Executive mode</button><button type="button" id="print">Print</button><button type="button" id="export-checks" class="tech">Export checks CSV</button></div></header>'

    # Navigation
    $viewList = @(@('overview', 'Overview', $true), @('domains', 'Domains', $true), @('checks', 'Checks explorer', $true), @('admins', 'Who are your admins', $true), @('exposure', 'External exposure', $false), @('copilot', 'Copilot readiness', [bool]($r.copilot -and $r.copilot.present)), @('ca', 'Conditional Access', [bool]$r.ca), @('recommendations', 'Recommendations', $true), @('trend', 'Trend', [bool]$r.trend), @('licensing', 'Licensing and value', $false), @('appendix', 'Appendix', $true))
    & $w '<nav class="views" aria-label="Views">'
    foreach ($vw in $viewList) { & $w "<a href=`"#$($vw[0])`"$(if (-not $vw[2]) { ' class="na"' })>$(& $h $vw[1])</a>" }
    & $w '</nav><main>'

    # Overview
    & $w '<section class="view active" id="overview"><h2>Overview</h2>'
    & $w "<div class=`"score`"><div class=`"grade`">$(& $h $r.score.grade)</div><div><div class=`"value`">Posture score $(& $num $r.score.value)</div><div class=`"method`">$(& $h $r.score.method) $($r.score.evaluated) checks scored.</div></div></div>"
    $hl = $r.headline
    & $w '<div class="stats">'
    foreach ($pair in @(@('MFA registered', (& $num $hl.mfaRegisteredPct '%')), @('Admins on phishing-resistant auth', (& $num $hl.adminsPhishingResistantPct '%')), @('Permanent Global Admins', (& $num $hl.permanentGlobalAdmins)), @('Intune compliance', (& $num $hl.intuneCompliancePct '%')), @('External sharing exposure', (& $num $hl.externalExposure)), @('Copilot readiness', $(if ($hl.copilotBlocked) { 'Blocked' } else { & $num $hl.copilotReadinessPct '%' })))) {
        $naClass = if ($pair[1] -eq 'not collected yet') { ' na' } else { '' }
        & $w ('<div class="stat' + $naClass + '"><div class="n">' + (& $h $pair[1]) + '</div><div class="l">' + (& $h $pair[0]) + '</div></div>')
    }
    & $w '</div>'
    $c = $r.counts
    $countStats = @(@('Pass', $c.pass), @('Fail', $c.fail), @('Accepted risk', $c.acceptedRisk), @('Covered by', $c.coveredBy), @('Not evaluated', $c.notEvaluated), @('Not applicable', $c.notApplicable)) | ForEach-Object { '<div class="stat"><div class="n">' + $_[1] + '</div><div class="l">' + $_[0] + '</div></div>' }
    & $w ('<div class="stats">' + ($countStats -join '') + '</div>')
    & $w '<h3>Top risks</h3>'
    if (@($r.topRisks).Count -eq 0) { & $w '<p>No failed checks.</p>' }
    else {
        & $w '<ol>'
        foreach ($t in $r.topRisks) {
            $aff = if ($t.affectedCount -gt 0) { ' <span class="tech">' + $t.affectedCount + ' affected</span>' } else { '' }
            & $w ('<li><a href="#checks" data-check="' + (& $h $t.id) + '"><strong>' + (& $h $t.id) + ' ' + (& $h $t.title) + '</strong></a> <span class="sev ' + (& $h $t.severity) + '">' + (& $h $t.severity) + '</span>' + $aff + ' <span class="tech">' + (& $h $t.narrative) + '</span></li>')
        }
        & $w '</ol>'
    }
    & $w '<h3>What we recommend this quarter</h3><ul>'
    foreach ($bucket in $r.recommendations.Keys) {
        $items = @($r.recommendations[$bucket]); if ($items.Count -eq 0) { continue }
        $links = @($items | ForEach-Object { '<a href="#recommendations" data-check="' + (& $h $_.id) + '">' + (& $h $_.id) + '</a> ' + (& $h $_.title) }) -join '; '
        & $w ('<li><strong>' + (& $h $bucket) + '</strong>: ' + $links + '</li>')
    }
    & $w '</ul>'
    if (@($r.domainsNotCollected).Count -gt 0) { & $w "<div class=`"notice`">Not collected yet: $(& $h (@($r.domainsNotCollected | ForEach-Object { $_.label }) -join ', ')). Scores cover the collected domains only.</div>" }
    & $w '</section>'

    # Domains
    & $w '<section class="view" id="domains"><h2>Domain scorecards</h2><div class="cards">'
    foreach ($d in $r.domains) {
        & $w "<div class=`"card`"><h3>$(& $h $d.label)</h3><div><strong>$(& $num $d.score)</strong> <span class=`"tech`">pass $($d.counts.pass), fail $($d.counts.fail), accepted $($d.counts.acceptedRisk), covered $($d.counts.coveredBy), not evaluated $($d.counts.notEvaluated)</span></div><div class=`"bar`"><i style=`"width:$(if ($null -ne $d.score) { $d.score } else { 0 })%`"></i></div><p>$(& $h $d.narrative)</p></div>"
    }
    foreach ($d in $r.domainsNotCollected) { & $w "<div class=`"card na`"><h3>$(& $h $d.label)</h3><p>Not collected yet.$(if ($d.reason) { " $(& $h $d.reason)" })</p></div>" }
    & $w '</div>'
    foreach ($d in $r.domains) {
        & $w "<h3>$(& $h $d.label)</h3><table><thead><tr><th>Check</th><th>Title</th><th>Status</th><th>Severity</th><th class=`"tech`">License</th><th>Detail</th></tr></thead><tbody>"
        foreach ($x in $d.checks) {
            $detail = if ($x.affectedCount -gt 0) { (@($x.affected | Select-Object -First 5 | ForEach-Object { $_.name }) -join ', ') + $(if ($x.affectedCount -gt 5) { " and $($x.affectedCount - 5) more" }) } elseif ($x.reason) { $x.reason } else { '' }
            & $w "<tr data-check=`"$(& $h $x.id)`"><td><code>$(& $h $x.id)</code></td><td>$(& $h $x.title)</td><td><span class=`"status $(& $h $x.status)`">$(& $h $statusLabel[$x.status])</span></td><td><span class=`"sev $(& $h $x.severity)`">$(& $h $x.severity)</span></td><td class=`"tech`">$(& $h (@($r.catalogText[$x.id].license) -join ', '))</td><td>$(& $h $detail)</td></tr>"
        }
        & $w '</tbody></table>'
    }
    & $w '</section>'

    # Checks explorer
    $domainsPresent = @($r.domains | ForEach-Object { $_.key })
    & $w '<section class="view" id="checks"><h2>Checks explorer</h2><div class="filters">'
    & $w '<input id="filter-search" type="search" placeholder="Search" aria-label="Search checks">'
    $statusOptions = @($statusLabel.Keys | ForEach-Object { '<option value="' + $_ + '">' + $statusLabel[$_] + '</option>' }) -join ''
    $domainOptions = @($domainsPresent | ForEach-Object { '<option value="' + $_ + '">' + $_ + '</option>' }) -join ''
    & $w ('<select id="filter-status" aria-label="Status"><option value="">Any status</option>' + $statusOptions + '</select>')
    & $w ('<select id="filter-domain" aria-label="Domain"><option value="">Any domain</option>' + $domainOptions + '</select>')
    & $w '<select id="filter-severity" aria-label="Severity"><option value="">Any severity</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select>'
    & $w '<span id="checks-count"></span></div>'
    & $w '<table id="checks-table"><thead><tr><th>Check</th><th>Domain</th><th>Title</th><th>Status</th><th>Severity</th><th class="tech">License</th><th>Affected</th></tr></thead><tbody>'
    foreach ($x in @($r.results | Sort-Object { $_.id })) {
        & $w "<tr data-check=`"$(& $h $x.id)`" data-status=`"$(& $h $x.status)`" data-domain=`"$(& $h $x.domain)`" data-severity=`"$(& $h $x.severity)`"><td><code>$(& $h $x.id)</code></td><td>$(& $h $x.domain)</td><td>$(& $h $x.title)</td><td><span class=`"status $(& $h $x.status)`">$(& $h $statusLabel[$x.status])</span></td><td><span class=`"sev $(& $h $x.severity)`">$(& $h $x.severity)</span></td><td class=`"tech`">$(& $h (@($r.catalogText[$x.id].license) -join ', '))</td><td>$($x.affectedCount)</td></tr>"
    }
    & $w '</tbody></table><p class="tech">Click a row for the narrative, remediation, affected objects and the exception snippet.</p></section>'

    # Admins
    & $w '<section class="view" id="admins"><h2>Who are your admins</h2>'
    if (@($r.admins).Count -eq 0) { & $w '<p class="na-panel">Role assignments were not collected.</p>' }
    else {
        & $w '<table><thead><tr><th>Name</th><th>Type</th><th>Permanent roles</th><th>Eligible roles</th><th>Strongest MFA method</th><th>Last sign-in</th><th class="tech">Synced from AD</th><th class="tech">Licenses</th></tr></thead><tbody>'
        foreach ($a in $r.admins) { & $w "<tr><td>$(& $h $a.name)<br><span class=`"tech`"><code>$(& $h $a.upn)</code></span></td><td>$(& $h $a.type)</td><td>$(& $h ($a.permanent -join ', '))</td><td>$(& $h ($a.eligible -join ', '))</td><td>$(& $h $a.strongestMethod)</td><td>$(& $h $(if ($a.lastSignIn) { $a.lastSignIn } else { 'unknown' }))</td><td class=`"tech`">$(if ($a.synced) { 'yes' } else { 'no' })</td><td class=`"tech`">$(& $h $a.licenses)</td></tr>" }
        & $w '</tbody></table>'
    }
    & $w '</section>'

    $naViews = @(@('exposure', 'External exposure', 'Guests by domain, sharing links, anonymous links and Teams federation come from the SharePoint and Teams collector (A.3), not collected yet.'), @('copilot', 'Copilot readiness', 'The 18 gates (spec 4.7) need the collaboration, labeling and governance evidence, not collected yet.'), @('trend', 'Trend', 'Headline numbers and domain scores across runs appear once a previous run exists in the same evidence root.'), @('licensing', 'Licensing and value', 'Unassigned and overlapping licenses need the full collection set; the licenses present are in the profile appendix.'))
    if ($r.copilot -and $r.copilot.present) { $naViews = @($naViews | Where-Object { $_[0] -ne 'copilot' }) }
    if ($r.trend) { $naViews = @($naViews | Where-Object { $_[0] -ne 'trend' }) }
    foreach ($na in $naViews) {
        & $w "<section class=`"view`" id=`"$($na[0])`"><h2>$(& $h $na[1])</h2><p class=`"na-panel`">$(& $h $na[2])</p></section>"
    }

    # Trend since the previous run.
    if ($r.trend) {
        $tr = $r.trend
        $signed = { param($d) if ($null -eq $d) { 'n/a' } elseif ($d -ge 0) { "+$d" } else { "$d" } }
        & $w "<section class=`"view`" id=`"trend`"><h2>Trend since $(& $h (& $fmtDate $tr.previousCheckedUtc))</h2>"
        & $w "<p><strong>Score $(& $num $tr.scoreBefore) to $(& $num $tr.scoreAfter)</strong> ($(& $signed $tr.scoreDelta)). $(@($tr.newFailures).Count) check(s) started failing, $(@($tr.resolved).Count) resolved, $(@($tr.affectedMoved).Count) moved.</p>"
        foreach ($pair in @(@('Started failing', $tr.newFailures), @('Resolved', $tr.resolved))) {
            if (@($pair[1]).Count -eq 0) { continue }
            & $w "<h3>$($pair[0])</h3><ul>"
            foreach ($x in $pair[1]) { & $w "<li><strong>$(& $h $x.id)</strong> $(& $h $x.title) <span class=`"muted`">($(& $h $x.severity), $(& $h $x.detail))</span></li>" }
            & $w '</ul>'
        }
        if (@($tr.affectedMoved).Count -gt 0) {
            & $w '<h3>Affected counts moved</h3><table><thead><tr><th>Check</th><th>Before</th><th>After</th></tr></thead><tbody>'
            foreach ($x in $tr.affectedMoved) { & $w "<tr><td>$(& $h $x.id) $(& $h $x.title)</td><td>$($x.before)</td><td>$($x.after)</td></tr>" }
            & $w '</tbody></table>'
        }
        & $w '<h3>Domains</h3><table><thead><tr><th>Domain</th><th>Before</th><th>After</th><th>Delta</th></tr></thead><tbody>'
        foreach ($d in $tr.domains) { & $w "<tr><td>$(& $h $d.label)</td><td>$(& $num $d.before)</td><td>$(& $num $d.after)</td><td>$(& $signed $d.delta)</td></tr>" }
        & $w '</tbody></table></section>'
    }

    # Copilot readiness (spec 4.7): the page the client reads first.
    if ($r.copilot -and $r.copilot.present) {
        $cp = $r.copilot
        & $w '<section class="view" id="copilot"><h2>Copilot readiness</h2>'
        if ($cp.blocked) { & $w "<p class=`"banner blocked`"><strong>Blocked.</strong> $(@($cp.blockedBy).Count) hard gate(s) not passed: $(& $h (@($cp.blockedBy | ForEach-Object { "$($_.code) $($_.title) ($($_.status))" }) -join '; ')).</p>" }
        else { & $w "<p class=`"banner ready`"><strong>Readiness $(& $num $cp.readinessPct '%').</strong> Every hard gate passes; $($cp.passed) of $($cp.evaluated) evaluated gates pass.</p>" }
        & $w '<table><thead><tr><th>Gate</th><th>Hard</th><th>Status</th><th>Title</th><th>Affected</th></tr></thead><tbody>'
        foreach ($g in $cp.gates) { & $w "<tr class=`"st-$($g.status)`"><td>$(& $h $g.code)</td><td>$(if ($g.hard) { 'yes' })</td><td>$(& $h $g.status)</td><td>$(& $h $g.title)</td><td>$(if ($g.affectedCount -gt 0) { $g.affectedCount })</td></tr>" }
        & $w '</tbody></table>'
        if (@($cp.notEvaluated).Count -gt 0) { & $w "<p class=`"muted`">Not evaluated: $(& $h (@($cp.notEvaluated | ForEach-Object { "$($_.code): $($_.reason)" }) -join ' '))</p>" }
        & $w "<p>$(& $h $cp.narrative)</p></section>"
    }

    # Conditional Access
    & $w '<section class="view" id="ca"><h2>Conditional Access</h2>'
    if (-not $r.ca) { & $w '<p class="na-panel">No Conditional Access snapshot in the evidence folder.</p>' }
    else {
        & $w "<p>$(@($r.ca.policies).Count) policies, $($r.ca.flagCount) health flag(s). The full documentation with per-policy pages is <code>ca-document.html</code> next to the snapshot.</p>"
        $cols = @($r.ca.matrix.columns)
        & $w ('<div class="scroll"><table class="matrix"><thead><tr><th>Policy</th>' + (@($cols | ForEach-Object { "<th>$(& $h $_.label)</th>" }) -join '') + '</tr></thead><tbody>')
        foreach ($row in $r.ca.matrix.rows) {
            $cells = @($cols | ForEach-Object { $cv = $row.cells[$_.key]; if ($cv) { '<td class="on">' + (& $h $cv) + '</td>' } else { '<td></td>' } }) -join ''
            & $w ('<tr><td>' + (& $h $row.name) + '</td>' + $cells + '</tr>')
        }
        & $w '</tbody></table></div>'
        foreach ($p in $r.ca.policies) {
            $flags = if (@($p.healthFlags).Count -gt 0) { '<p class="tech">Flags: ' + (& $h (@($p.healthFlags | ForEach-Object { $_.code + ': ' + $_.message }) -join ' ')) + '</p>' } else { '' }
            & $w ('<div class="policy"><strong>' + (& $h $p.name) + '</strong><span class="badge ' + (& $h $p.state) + '">' + (& $h $p.stateLabel) + '</span><p>' + (& $h $p.summary) + '</p>' + $flags + '</div>')
        }
    }
    & $w '</section>'

    # Recommendations
    & $w '<section class="view" id="recommendations"><h2>Recommendations</h2>'
    foreach ($bucket in $r.recommendations.Keys) {
        $items = @($r.recommendations[$bucket])
        & $w "<div class=`"bucket`"><h3>$(& $h $bucket) <span class=`"tech`">($($items.Count))</span></h3>"
        if ($items.Count -eq 0) { & $w '<p>Nothing in this bucket.</p>' }
        foreach ($x in $items) { & $w "<div class=`"rec`"><div class=`"title`"><a href=`"#checks`" data-check=`"$(& $h $x.id)`">$(& $h $x.id) $(& $h $x.title)</a> <span class=`"sev $(& $h $x.severity)`">$(& $h $x.severity)</span> <span class=`"tech`">$(& $h $x.domain)$(if ($x.license.Count -gt 0) { ", needs $(& $h ($x.license -join ' or '))" })$(if ($x.affectedCount -gt 0) { ", $($x.affectedCount) affected" })</span></div><div>$(& $h $x.remediation) <a href=`"$(& $h $x.learn)`">Learn</a></div></div>" }
        & $w '</div>'
    }
    & $w '</section>'

    # Appendix
    $a = $r.appendix
    & $w '<section class="view" id="appendix"><h2>Appendix</h2><table><tbody>'
    foreach ($pair in @(@('Catalog version', $a.catalogVersion), @('Baseline', $a.baseline), @('Profile', $a.profile), @('Evidence folder', $a.evidence), @('Collectors', ($r.collectors -join ', ')), @('Scopes', ($a.scopes -join ', ')), @('Graph API versions', ($a.graphApiVersions -join ', ')), @('Module version', $a.moduleVersion))) { & $w "<tr><th>$(& $h $pair[0])</th><td>$(& $h $pair[1])</td></tr>" }
    & $w '</tbody></table>'
    if ($a.profileAnswers) {
        & $w '<h3>Profile</h3><table><tbody>'
        foreach ($k in $a.profileAnswers.Keys) { $val = $a.profileAnswers[$k]; $text = if ($val -is [System.Collections.IDictionary]) { (@($val.Keys | ForEach-Object { "$_=$($val[$_])" }) -join '; ') } elseif ($val -is [array]) { $val -join ', ' } else { [string]$val }; & $w "<tr><th>$(& $h $k)</th><td>$(& $h $text)</td></tr>" }
        & $w '</tbody></table>'
    }
    & $w '<h3>Exceptions</h3>'
    if (@($a.exceptions).Count -eq 0) { & $w '<p>None.</p>' }
    else { & $w '<table><thead><tr><th>Check</th><th>Object</th><th>Justification</th><th>Owner</th><th>Approver</th><th>Expires</th></tr></thead><tbody>'; foreach ($e in $a.exceptions) { & $w "<tr><td>$(& $h $e.check)</td><td>$(& $h $e.object)</td><td>$(& $h $e.justification)</td><td>$(& $h $e.owner)</td><td>$(& $h $e.approver)</td><td>$(if ($e.expires) { $e.expires.ToString('yyyy-MM-dd') })$(if ($e.expired) { ' (expired)' })</td></tr>" }; & $w '</tbody></table>' }
    & $w '<h3>Checks not evaluated</h3>'
    if (@($a.notEvaluated).Count -eq 0) { & $w '<p>None.</p>' }
    else { & $w '<table><thead><tr><th>Check</th><th>Title</th><th>Status</th><th>Why</th></tr></thead><tbody>'; foreach ($n in $a.notEvaluated) { & $w "<tr data-check=`"$(& $h $n.id)`"><td><code>$(& $h $n.id)</code></td><td>$(& $h $n.title)</td><td>$(& $h $statusLabel[$n.status])</td><td>$(& $h $n.reason)</td></tr>" }; & $w '</tbody></table>' }
    & $w "<h3 class=`"tech`">Evidence index</h3><p class=`"tech`">$(& $h ($a.evidenceFiles -join ', '))</p>"
    if (@($a.errors).Count -gt 0) { & $w '<h3>Collection errors</h3><ul>'; foreach ($e in $a.errors) { & $w "<li>$(& $h $e)</li>" }; & $w '</ul>' }
    & $w '</section></main>'
    & $w '<aside id="drawer" aria-label="Check detail"></aside>'
    if ($b.footer) { & $w "<footer class=`"doc`">$(& $h $b.footer)</footer>" }

    # Embedded data, then the behaviour.
    & $w (& $jsonBlock 'data-results' @($r.results | ForEach-Object { [ordered]@{ id = $_.id; domain = $_.domain; title = $_.title; status = $_.status; severity = $_.severity; reason = $_.reason; affected = @($_.affected); affectedCount = $_.affectedCount; evidence = @($_.evidence); thresholds = $_.thresholds } }))
    & $w (& $jsonBlock 'data-catalog' $r.catalogText)
    & $w "<script>`n$js`n</script>"
    & $w '</body></html>'
    return $sb.ToString()
}
