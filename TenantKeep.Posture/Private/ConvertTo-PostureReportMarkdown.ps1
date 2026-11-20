# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function ConvertTo-PostureReportMarkdown {
    <#
    .SYNOPSIS
        Renders the report model as Markdown: cover, executive summary, scorecards, admins, recommendations, CA, appendix.
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
    $effortWord = @{ S = 'quick fix'; M = 'planned change'; L = 'project' }
    $fmtDate = { param($Value) $u = ConvertTo-PostureUtcDateTime $Value; if ($u) { $u.ToString('yyyy-MM-dd HH:mm') + ' UTC' } else { 'unknown' } }
    $table = {
        param([string[]] $Headers, [object[]] $Rows)
        & $line "| $($Headers -join ' | ') |"
        & $line "|$(@($Headers | ForEach-Object { '---' }) -join '|')|"
        foreach ($r in $Rows) { & $line "| $(@($r | ForEach-Object { & $esc $_ }) -join ' | ') |" }
        & $line
    }
    $statusLabel = @{ pass = 'Pass'; fail = 'Fail'; notEvaluated = 'Not evaluated'; notApplicable = 'Not applicable'; acceptedRisk = 'Accepted risk'; coveredBy = 'Covered by' }
    $num = { param($x, [string] $suffix = '') if ($null -eq $x) { 'not collected yet' } else { "$x$suffix" } }
    $r = $Report; $b = $r.brand; $exec = ($r.template -eq 'Executive')

    & $line "# $($r.title)"
    & $line
    $prepared = [string]$b.preparedBy.name
    if ($b.client.name) { $prepared += " for $($b.client.name)" }
    & $line "Prepared by $prepared. Tenant $(if ($r.tenantName) { "$($r.tenantName) " })``$($r.tenantId)``. Evidence collected $(& $fmtDate $r.collectedUtc). Report generated $(& $fmtDate $r.generatedUtc) with TenantKeep.Posture $($r.appendix.moduleVersion), catalog $($r.appendix.catalogVersion), baseline $($r.appendix.baseline). $($r.template) template.$(if ($r.licence -and $r.licence.licensed) { " Licensed to $($r.licence.customer), $($r.licence.tier) tier, until $(& $fmtDate $r.licence.expiresUtc)." })$(if ($r.build) { " $($r.build.detail)" })"
    if ($r.licence -and -not ($r.licence.licensed -and $r.licence.tier -eq 'full')) { & $line ''; & $line "**Licence:** $(if ($r.licence.reason) { $r.licence.reason } else { 'not licensed' })" }
    if ($r.build -and $r.build.state -eq 'modified') { & $line ''; & $line "**Build:** $($r.build.detail) This report was not produced by an intact TenantKeep release." }
    if ($b.confidentiality) { & $line; & $line "*$($b.confidentiality)*" }
    & $line

    # The ranked list first: a person or a model reading only the top of the file gets what to do, in order.
    if ($r.Contains('findings') -and $r.findings -and @($r.findings.findings).Count -gt 0) {
        & $line '## What to fix first'
        & $line
        & $line 'Every failing check, most important first: severity, then effort (quick fixes first), then how many objects it affects. The full detail is in findings.json beside this file.'
        & $line
        foreach ($f in @($r.findings.findings)) {
            & $line "$($f.rank). **$($f.id) $(& $esc $f.title)** ($($f.severity)$(if ($f.effort) { ", $($effortWord[[string]$f.effort])" })$(if ($f.category -eq 'improve') { ', improvement' })$(if ($f.affectedCount -gt 0) { ", $($f.affectedCount) affected" })). $(& $esc $f.howToFix)"
        }
        & $line
    }
    & $line '## Executive summary'
    & $line
    & $line "**Posture score $(& $num $r.score.value) ($($r.score.grade)).** $($r.score.method) $($r.score.evaluated) checks scored."
    & $line
    $h = $r.headline
    & $table @('MFA registered', 'Admins on phishing-resistant auth', 'Permanent Global Admins', 'Intune compliance', 'External sharing exposure', 'Copilot readiness') @(, @((& $num $h.mfaRegisteredPct '%'), (& $num $h.adminsPhishingResistantPct '%'), (& $num $h.permanentGlobalAdmins), (& $num $h.intuneCompliancePct '%'), (& $num $h.externalExposure), $(if ($h.copilotBlocked) { 'Blocked' } else { & $num $h.copilotReadinessPct '%' })))
    $c = $r.counts
    & $line "Checks: $($c.pass) pass, $($c.fail) fail, $($c.acceptedRisk) accepted risk, $($c.coveredBy) covered by a third party, $($c.notEvaluated) not evaluated, $($c.notApplicable) not applicable."
    & $line
    if ($r.copilot -and $r.copilot.present) {
        $cp = $r.copilot
        & $line '### Copilot readiness'
        & $line
        if ($cp.blocked) { & $line "**Blocked.** $(@($cp.blockedBy).Count) hard gate(s) not passed: $(@($cp.blockedBy | ForEach-Object { "$($_.code) $(& $esc $_.title) ($($_.status))" }) -join '; ')." }
        else { & $line "**Readiness $(& $num $cp.readinessPct '%').** Every hard gate passes; $($cp.passed) of $($cp.evaluated) evaluated gates pass." }
        & $line
        & $table @('Gate', 'Hard', 'Status', 'Title') @($cp.gates | ForEach-Object { , @($_.code, $(if ($_.hard) { 'yes' } else { '' }), $_.status, (& $esc $_.title)) })
        if (@($cp.notEvaluated).Count -gt 0) { & $line "Not evaluated: $(@($cp.notEvaluated | ForEach-Object { "$($_.code) ($(& $esc $_.reason))" }) -join '; ')."; & $line }
        & $line (& $esc $cp.narrative)
        & $line
    }
    & $line '### Top risks'
    & $line
    if (@($r.topRisks).Count -eq 0) { & $line 'No failed checks.'; & $line }
    else { $i = 0; foreach ($t in $r.topRisks) { $i++; & $line "$i. **$($t.id) $(& $esc $t.title)** ($($t.severity)$(if ($t.affectedCount -gt 0) { ", $($t.affectedCount) affected" })). $(& $esc $t.narrative)"; & $line } }
    & $line '### What we recommend this quarter'
    & $line
    foreach ($bucket in $r.recommendations.Keys) {
        $items = @($r.recommendations[$bucket])
        if ($items.Count -eq 0) { continue }
        & $line "- **$bucket**: $(@($items | ForEach-Object { "$($_.id) $(& $esc $_.title)" }) -join '; ')"
    }
    & $line

    if ($r.trend) {
        $tr = $r.trend
        & $line "## Trend since $(& $fmtDate $tr.previousCheckedUtc)"
        & $line
        $signed = { param($d) if ($null -eq $d) { 'n/a' } elseif ($d -ge 0) { "+$d" } else { "$d" } }
        & $line "Score $(& $num $tr.scoreBefore) to $(& $num $tr.scoreAfter) ($(& $signed $tr.scoreDelta)). $(@($tr.newFailures).Count) check(s) started failing, $(@($tr.resolved).Count) resolved, $(@($tr.affectedMoved).Count) moved."
        & $line
        if (@($tr.newFailures).Count -gt 0) { & $line ('**Started failing:** ' + (@($tr.newFailures | ForEach-Object { "$($_.id) $(& $esc $_.title) ($($_.detail))" }) -join '; ')); & $line }
        if (@($tr.resolved).Count -gt 0) { & $line ('**Resolved:** ' + (@($tr.resolved | ForEach-Object { "$($_.id) $(& $esc $_.title)" }) -join '; ')); & $line }
        if (@($tr.affectedMoved).Count -gt 0) { & $line ('**Affected counts moved:** ' + (@($tr.affectedMoved | ForEach-Object { "$($_.id) $($_.before) to $($_.after)" }) -join '; ')); & $line }
        & $table @('Domain', 'Before', 'After', 'Delta') @($tr.domains | ForEach-Object { , @((& $esc $_.label), (& $num $_.before), (& $num $_.after), (& $signed $_.delta)) })
    }
    & $line '## Domain scorecards'
    & $line
    foreach ($d in $r.domains) {
        & $line "### $($d.label)"
        & $line
        & $line "Score $(& $num $d.score). $($d.narrative) Pass $($d.counts.pass), fail $($d.counts.fail), accepted risk $($d.counts.acceptedRisk), covered $($d.counts.coveredBy), not evaluated $($d.counts.notEvaluated), not applicable $($d.counts.notApplicable)."
        & $line
        $rows = foreach ($x in $d.checks) {
            $detail = if ($x.affectedCount -gt 0) { (@($x.affected | Select-Object -First 5 | ForEach-Object { $_.name }) -join ', ') + $(if ($x.affectedCount -gt 5) { " and $($x.affectedCount - 5) more" }) } elseif ($x.reason) { $x.reason } else { '' }
            if ($exec) { , @($x.id, $x.title, $statusLabel[$x.status], $x.severity) } else { , @($x.id, $x.title, $statusLabel[$x.status], $x.severity, (@($r.catalogText[$x.id].license) -join ', '), $detail) }
        }
        if ($exec) { & $table @('Check', 'Title', 'Status', 'Severity') @($rows) } else { & $table @('Check', 'Title', 'Status', 'Severity', 'License', 'Detail') @($rows) }
    }
    if (@($r.domainsNotCollected).Count -gt 0) {
        & $line "Not collected yet: $(@($r.domainsNotCollected | ForEach-Object { $_.label }) -join ', ')."
        & $line
    }

    & $line '## Who are your admins'
    & $line
    if (@($r.admins).Count -eq 0) { & $line 'Role assignments were not collected.'; & $line }
    else {
        & $table @('Name', 'Type', 'Permanent roles', 'Eligible roles', 'Strongest MFA method', 'Last sign-in', 'Synced from AD', 'Licenses') @($r.admins | ForEach-Object { , @($_.name, $_.type, ($_.permanent -join ', '), ($_.eligible -join ', '), $_.strongestMethod, $(if ($_.lastSignIn) { $_.lastSignIn } else { 'unknown' }), $(if ($_.synced) { 'yes' } else { 'no' }), $(if ($null -ne $_.licenses) { $_.licenses } else { '' })) })
    }

    & $line '## Recommendations'
    & $line
    if ($r.Contains('doToday') -and @($r.doToday).Count -gt 0) {
        & $line '### Do today'
        & $line
        & $line 'Quick fixes that users will not notice or will barely notice.'
        & $line
        foreach ($d in $r.doToday) { & $line "- **$($d.id) $(& $esc $d.title)** ($($d.severity)): $(& $esc $d.userImpact['text'])" }
        & $line
    }
    if ($r.Contains('chains') -and @($r.chains).Count -gt 0) {
        & $line '### Control chains'
        & $line
        & $line 'Controls that protect only together. A chain breaks at its first failing link.'
        & $line
        foreach ($ch in $r.chains) {
            $state = $(switch ($ch.status) { 'pass' { 'holds' } 'broken' { "broken at $($ch.brokenAt)" } default { 'incomplete' } })
            & $line "- **$(& $esc $ch.name)** ($state): $(@($ch.links | ForEach-Object { "$($_.check) $($_.status)" }) -join ' > ')"
        }
        & $line
    }
    foreach ($bucket in $r.recommendations.Keys) {
        $items = @($r.recommendations[$bucket])
        & $line "### $bucket"
        & $line
        if ($items.Count -eq 0) { & $line 'Nothing in this bucket.'; & $line; continue }
        foreach ($x in $items) {
            & $line "#### $($x.id) $(& $esc $x.title)"
            & $line
            & $line "$($x.severity)$(if ($x.effort) { ", $($effortWord[[string]$x.effort])" })$(if ($x.category -eq 'improve') { ', improvement' }), $($x.domain)$(if ($x.license.Count -gt 0) { ", needs $($x.license -join ' or ')" })$(if ($x.affectedCount -gt 0) { ", $($x.affectedCount) affected" })."
            & $line
            $lf = $(if ($r.Contains('labels') -and $r.labels) { $r.labels } else { @{ facts = @{}; thresholds = @{} } })
            $found = @(@($x.observed.Keys | ForEach-Object { "$(if ($lf.facts.Contains($_)) { $lf.facts[$_] } else { $_ }): $(if ($x.observed[$_] -is [bool]) { if ($x.observed[$_]) { 'yes' } else { 'no' } } else { $x.observed[$_] })" }) + @($(if ($x.thresholds) { $x.thresholds.Keys | ForEach-Object { "$(if ($lf.thresholds.Contains($_)) { $lf.thresholds[$_] } else { "threshold $_" }): $($x.thresholds[$_])" } })))
            if ($x.reason) { & $line "Found: $(& $esc $x.reason)"; & $line }
            if ($found.Count) { & $line "Values: $(& $esc ($found -join '; '))"; & $line }
            & $line "Why it matters: $(& $esc $x.why)"
            & $line
            if (@($x.steps).Count -gt 1) { $n = 0; foreach ($st in $x.steps) { $n++; & $line "$n. $(& $esc $st)" } }
            else { & $line (& $esc $x.remediation) }
            & $line
            if ($x.userImpact) { & $line "What users notice ($($x.userImpact['level'])): $(& $esc $x.userImpact['text'])"; & $line }
            & $line "[Learn]($($x.learn))$(if ($x.deepLink) { " [Portal]($($x.deepLink))" })"
            & $line
        }
    }

    if ($r.Contains('inventory') -and @($r.inventory).Count) {
        & $line '## Inventory'
        & $line
        & $line 'What the tenant has, read from the evidence. No pass or fail here.'
        & $line
        foreach ($s in $r.inventory) {
            & $line "### $($s.title) ($($s.total))"
            & $line
            if ($s.note) { & $line (& $esc $s.note); & $line }
            if (@($s.rows).Count) { & $table @($s.columns) @($s.rows | Select-Object -First 50 | ForEach-Object { $row = $_; , @($s.columns | ForEach-Object { [string]$row[$_] }) }) }
            if ($s.total -gt 50) { & $line "The first 50 of $($s.total); report.html has up to 500."; & $line }
        }
    }

    & $line '## Conditional Access'
    & $line
    if (-not $r.ca) { & $line 'No Conditional Access snapshot in the evidence folder.'; & $line }
    else {
        & $line "$(@($r.ca.policies).Count) policies, $($r.ca.flagCount) health flag(s). The full documentation is in ca-document.html next to the snapshot."
        & $line
        $cols = @($r.ca.matrix.columns)
        & $table (@('Policy') + @($cols | ForEach-Object { $_.label })) @($r.ca.matrix.rows | ForEach-Object { $row = $_; , (@($row.name) + @($cols | ForEach-Object { $row.cells[$_.key] })) })
        if (-not $exec) {
            foreach ($p in $r.ca.policies) { & $line "- **$(& $esc $p.name)** [$($p.stateLabel)]: $(& $esc $p.summary)$(if (@($p.healthFlags).Count -gt 0) { " Flags: $(@($p.healthFlags | ForEach-Object { $_.code }) -join ', ')." })" }
            & $line
        }
    }

    if ($r.crosswalk) {
        & $line "## Framework crosswalk: $($r.crosswalk.baseline) ($($r.crosswalk.framework))"
        & $line
        & $line 'Reference numbers only; the framework text is not reproduced. Each row lists the checks that map to the group or control, with their results.'
        & $line
        foreach ($e in $r.crosswalk.entries) {
            & $line "### $(& $esc $e.name) ($($e.pass) pass, $($e.fail) fail)"
            & $line
            if (@($e.checks).Count -eq 0) { & $line 'No check maps here yet.'; & $line; continue }
            & $table @('Reference', 'Check', 'Status', 'Severity') @($e.checks | ForEach-Object { , @($_.reference, "$($_.id) $(& $esc $_.title)", $_.status, $_.severity) })
        }
    }
    & $line '## Appendix'
    & $line
    $a = $r.appendix
    & $table @('Field', 'Value') @(, @('Catalog version', $a.catalogVersion), @('Baseline', $a.baseline), @('Profile', $a.profile), @('Evidence folder', $a.evidence), @('Collectors', ($r.collectors -join ', ')), @('Scopes', ($a.scopes -join ', ')), @('Graph API versions', ($a.graphApiVersions -join ', ')), @('Module version', $a.moduleVersion), @('Build', $a.build), @('Licence', $a.licence))
    if ($a.profileAnswers) {
        & $line '### Profile'
        & $line
        & $table @('Answer', 'Value') @($a.profileAnswers.Keys | ForEach-Object { $k = $_; $val = $a.profileAnswers[$k]; , @($k, $(if ($val -is [System.Collections.IDictionary]) { (@($val.Keys | ForEach-Object { "$_=$($val[$_])" }) -join '; ') } elseif ($val -is [array]) { $val -join ', ' } else { [string]$val })) })
    }
    & $line '### Exceptions'
    & $line
    if (@($a.exceptions).Count -eq 0) { & $line 'None.'; & $line }
    else { & $table @('Check', 'Object', 'Justification', 'Owner', 'Approver', 'Expires', 'Expired') @($a.exceptions | ForEach-Object { , @($_.check, $_.object, $_.justification, $_.owner, $_.approver, $(if ($_.expires) { $_.expires.ToString('yyyy-MM-dd') } else { '' }), $(if ($_.expired) { 'yes' } else { 'no' })) }) }
    & $line '### Checks not evaluated'
    & $line
    if (@($a.notEvaluated).Count -eq 0) { & $line 'None.'; & $line }
    else { & $table @('Check', 'Title', 'Status', 'Why') @($a.notEvaluated | ForEach-Object { , @($_.id, $_.title, $statusLabel[$_.status], $_.reason) }) }
    & $line '### Evidence index'
    & $line
    & $line (($a.evidenceFiles | ForEach-Object { "``$_``" }) -join ', ')
    & $line
    $rh = $r.runHealth
    if ($rh -and @($rh.failures).Count -gt 0) {
        & $line '### Run health'
        & $line
        & $line "$(@($rh.failures).Count) step(s) could not be read. After granting a role, collect only what failed: ``$($rh.resume)``"
        & $line
        & $table @('Domain', 'Step', 'Why', 'What to do') @($rh.failures | ForEach-Object { , @($_.collector, $_.step, $_.causeLabel, $_.advice) })
    }
    if (@($a.errors).Count -gt 0) { & $line '### Collection errors'; & $line; foreach ($e in $a.errors) { & $line "- $(& $esc $e)" }; & $line }
    if ($b.footer) { & $line '---'; & $line; & $line $b.footer }
    return $sb.ToString()
}
