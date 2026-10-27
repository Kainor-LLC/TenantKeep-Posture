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
    $frameworkLabel = [ordered]@{ 'nist-csf-2' = 'NIST CSF 2.0'; iso27001 = 'ISO 27001:2022'; cmmc = 'CMMC 2.0 and NIST 800-171'; 'cisa-scuba' = 'CISA SCuBA'; hipaa = 'HIPAA'; pci = 'PCI DSS'; soc2 = 'SOC 2'; 'nist-800-171' = 'NIST 800-171' }
    $methodLabel = [ordered]@{
        microsoftAuthenticatorPush = 'Microsoft Authenticator (push)'; microsoftAuthenticatorPasswordless = 'Microsoft Authenticator (passwordless)'; microsoftAuthenticatorAuthenticationMode = 'Microsoft Authenticator'
        softwareOneTimePasscode = 'Authenticator app code'; hardwareOneTimePasscode = 'Hardware token code'; mobilePhone = 'Phone (text or call)'; alternateMobilePhone = 'Alternate phone'; officePhone = 'Office phone'
        email = 'Email'; securityQuestion = 'Security questions'; fido2SecurityKey = 'FIDO2 security key'; passKeyDeviceBound = 'Passkey (device-bound)'; passKeyDeviceBoundAuthenticator = 'Passkey in Authenticator'; passKeyDeviceBoundWindowsHello = 'Passkey in Windows Hello'
        windowsHelloForBusiness = 'Windows Hello for Business'; temporaryAccessPass = 'Temporary Access Pass'; macOsSecureEnclaveKey = 'macOS platform credential'; x509Certificate = 'Certificate'; nothing = 'nothing'
    }
    $thresholdLabel = [ordered]@{
        maxPermanentGlobalAdmins = 'Maximum permanent Global Administrators'; staleDeviceDays = 'Stale device after (days)'; maxExclusionGroupMembers = 'Maximum members in an exclusion group'; inactiveGuestDays = 'Inactive guest after (days)'
        reportOnlyMaxDays = 'Report-only policy, maximum age (days)'; disabledMaxDays = 'Disabled policy, maximum age (days)'; criticalCveMaxAgeDays = 'Critical vulnerability, maximum age (days)'; namePattern = 'Policy name pattern'
        maxDomainAdmins = 'Maximum Domain Admins'; maxKrbtgtAgeDays = 'krbtgt password, maximum age (days)'; maxAdminPasswordAgeDays = 'Admin password, maximum age (days)'; minLapsPct = 'Minimum LAPS coverage (%)'; minPasswordLength = 'Minimum password length'; maxSsoKeyAgeDays = 'Seamless SSO key, maximum age (days)'
        minEffectivePct = 'Minimum effective coverage (%)'; maxAnonymousLinkDays = 'Anonymous link, maximum life (days)'; maxGuestExpireDays = 'Guest access, maximum life (days)'; maxOwnersPerSubscription = 'Maximum Owners per subscription'; minTaggedPct = 'Minimum tagged resources (%)'; maxUserResourceScopeAssignments = 'Maximum user assignments at resource scope'
    }
    $humanize = { param([string] $t) if (-not $t) { return '' }; $out = $t; foreach ($k in $methodLabel.Keys) { $out = [regex]::Replace($out, "(?<![A-Za-z])$([regex]::Escape($k))(?![A-Za-z])", [string]$methodLabel[$k]) }; $out -replace ';', ', ' }
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
    $domainLabel = @{}; foreach ($d in @($r.domains) + @($r.domainsNotCollected)) { $domainLabel[[string]$d.key] = [string]$d.label }
    $dl = { param([string] $k) if ($domainLabel.ContainsKey($k)) { $domainLabel[$k] } else { $k } }
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
    if ($r.licence -and -not ($r.licence.licensed -and $r.licence.tier -eq 'full')) {
        $trialLink = "https://tenantkeep.app/trial/?tenant=$([uri]::EscapeDataString([string]$r.tenantId))"
        & $w "<div class=`"banner warn`">Licence: $(& $h $(if ($r.licence.reason) { $r.licence.reason } else { 'not licensed' })) Every domain for 30 days, free: <a href=`"$(& $h $trialLink)`" target=`"_blank`" rel=`"noopener`">request a trial</a>.</div>"
    }
    elseif ($r.licence -and $r.licence.Contains('trial') -and $r.licence.trial) {
        $ends = $(try { (ConvertTo-PostureUtcDateTime $r.licence.expiresUtc).ToString('yyyy-MM-dd') } catch { [string]$r.licence.expiresUtc })
        & $w "<div class=`"banner warn`">Trial licence for $(& $h $r.licence.customer), ends $(& $h $ends). <a href=`"https://tenantkeep.app/#pricing`" target=`"_blank`" rel=`"noopener`">Licences and pricing</a>.</div>"
    }
    if ($r.build -and $r.build.state -eq 'modified') { & $w "<div class=`"banner err`">$(& $h $r.build.detail) This report was not produced by an intact TenantKeep release.</div>" }
    & $w "<div class=`"meta`">Prepared by $(& $h $prepared). Tenant $(if ($r.tenantName) { & $h "$($r.tenantName) " })<code>$(& $h $r.tenantId)</code>. Evidence collected $(& $fmtDate $r.collectedUtc). Generated $(& $fmtDate $r.generatedUtc) with TenantKeep.Posture $(& $h $r.appendix.moduleVersion), catalog $(& $h $r.appendix.catalogVersion), baseline $(& $h $r.appendix.baseline).$(if ($r.licence -and $r.licence.licensed) { " Licensed to $(& $h $r.licence.customer), $(& $h $r.licence.tier) tier, until $(& $fmtDate $r.licence.expiresUtc)." })$(if ($r.build) { " $(& $h $r.build.detail)" })</div>"
    if ($b.confidentiality) { & $w "<div class=`"confidential`">$(& $h $b.confidentiality)</div>" }
    & $w '</div><div class="toolbar"><button type="button" id="toggle-exec" aria-pressed="false">Executive Mode</button><button type="button" id="print">Print</button><button type="button" id="export-checks" class="tech">Export Checks CSV</button></div></header>'

    # Navigation
    $viewList = @(@('overview', 'Overview', $true), @('domains', 'Domains', $true), @('checks', 'Checks Explorer', $true), @('register', 'Risk Register', $true), @('admins', 'Your Administrators', $true), @('exposure', 'External Exposure', $false), @('copilot', 'Copilot Readiness', [bool]($r.copilot -and $r.copilot.present)), @('ca', 'Conditional Access', [bool]$r.ca), @('recommendations', 'Recommendations', $true), @('crosswalk', 'Crosswalk', [bool]$r.crosswalk), @('trend', 'Trend', [bool]$r.trend), @('settings', 'Settings', $true), @('licensing', 'Licensing and Value', $false), @('appendix', 'Appendix', $true))
    & $w '<nav class="views" aria-label="Views">'
    foreach ($vw in $viewList) { & $w "<a href=`"#$($vw[0])`"$(if (-not $vw[2]) { ' class="na"' })>$(& $h $vw[1])</a>" }
    & $w '</nav><main>'

    # Overview
    & $w '<section class="view active" id="overview"><h2>Overview</h2>'
    & $w "<div class=`"score`"><div class=`"grade`" id=`"score-grade`">$(& $h $r.score.grade)</div><div><div class=`"value`" id=`"score-value`">Posture score $(& $num $r.score.value)</div><div class=`"method`">$(& $h $r.score.method) $($r.score.evaluated) checks scored.</div><div class=`"live`" id=`"score-live`"></div></div></div>"
    $hl = $r.headline
    & $w '<div class="stats">'
    foreach ($pair in @(@('MFA Registered', (& $num $hl.mfaRegisteredPct '%')), @('Administrators on Phishing-Resistant MFA', (& $num $hl.adminsPhishingResistantPct '%')), @('Permanent Global Administrators', (& $num $hl.permanentGlobalAdmins)), @('Intune Compliance', (& $num $hl.intuneCompliancePct '%')), @('External Sharing Exposure', (& $num $hl.externalExposure)), @('Copilot Readiness', $(if ($hl.copilotBlocked) { 'Blocked' } else { & $num $hl.copilotReadinessPct '%' })))) {
        $naClass = if ($pair[1] -eq 'not collected yet') { ' na' } else { '' }
        & $w ('<div class="stat' + $naClass + '"><div class="n">' + (& $h $pair[1]) + '</div><div class="l">' + (& $h $pair[0]) + '</div></div>')
    }
    & $w '</div>'
    $c = $r.counts
    $countStats = @(@('Pass', $c.pass, 'pass'), @('Fail', $c.fail, 'fail'), @('Accepted Risk', $c.acceptedRisk, 'acceptedRisk'), @('Covered by a Third Party', $c.coveredBy, 'coveredBy'), @('Not Evaluated', $c.notEvaluated, 'notEvaluated'), @('Not Applicable', $c.notApplicable, 'notApplicable')) | ForEach-Object { '<div class="stat"><div class="n" id="count-' + $_[2] + '">' + $_[1] + '</div><div class="l">' + $_[0] + '</div></div>' }
    & $w ('<div class="stats">' + ($countStats -join '') + '</div>')
    & $w '<h3>Top Risks</h3>'
    if (@($r.topRisks).Count -eq 0) { & $w '<p>No failed checks.</p>' }
    else {
        & $w '<ol>'
        foreach ($t in $r.topRisks) {
            $aff = if ($t.affectedCount -gt 0) { ' <span class="tech">' + $t.affectedCount + ' affected</span>' } else { '' }
            & $w ('<li><a href="#checks" data-check="' + (& $h $t.id) + '"><strong>' + (& $h $t.id) + ' ' + (& $h $t.title) + '</strong></a> <span class="sev ' + (& $h $t.severity) + '">' + (& $h $t.severity) + '</span>' + $aff + ' <span class="tech">' + (& $h $t.narrative) + '</span></li>')
        }
        & $w '</ol>'
    }
    & $w '<h3>What We Recommend This Quarter</h3><ul>'
    foreach ($bucket in $r.recommendations.Keys) {
        $items = @($r.recommendations[$bucket]); if ($items.Count -eq 0) { continue }
        $links = @($items | ForEach-Object { '<a href="#recommendations" data-check="' + (& $h $_.id) + '">' + (& $h $_.id) + '</a> ' + (& $h $_.title) }) -join '; '
        & $w ('<li><strong>' + (& $h $bucket) + '</strong>: ' + $links + '</li>')
    }
    & $w '</ul>'
    if (@($r.domainsNotCollected).Count -gt 0) { & $w "<div class=`"notice`">Not collected yet: $(& $h (@($r.domainsNotCollected | ForEach-Object { $_.label }) -join ', ')). Scores cover the collected domains only.</div>" }
    & $w '</section>'

    # Domains
    & $w '<section class="view" id="domains"><h2>Domain Scorecards</h2><div class="cards">'
    foreach ($d in $r.domains) {
        & $w "<div class=`"card`"><h3>$(& $h $d.label)</h3><div><strong data-domain-score=`"$(& $h $d.key)`">$(& $num $d.score)</strong> <span class=`"tech`">$($d.counts.pass) pass, $($d.counts.fail) fail, $($d.counts.acceptedRisk) accepted, $($d.counts.coveredBy) covered, $($d.counts.notEvaluated) not evaluated</span></div><div class=`"bar`"><i style=`"width:$(if ($null -ne $d.score) { $d.score } else { 0 })%`"></i></div><p>$(& $h $d.narrative)</p></div>"
    }
    foreach ($d in $r.domainsNotCollected) { & $w "<div class=`"card na`"><h3>$(& $h $d.label)</h3><p>Not collected yet.$(if ($d.reason) { " $(& $h $d.reason)" })</p></div>" }
    & $w '</div>'
    foreach ($d in $r.domains) {
        & $w "<h3>$(& $h $d.label)</h3><table><thead><tr><th>Check</th><th>Title</th><th>Status</th><th>Severity</th><th class=`"tech`">Licence Needed</th><th>Detail</th></tr></thead><tbody>"
        foreach ($x in $d.checks) {
            $detail = if ($x.affectedCount -gt 0) { (@($x.affected | Select-Object -First 5 | ForEach-Object { $_.name }) -join ', ') + $(if ($x.affectedCount -gt 5) { " and $($x.affectedCount - 5) more" }) } elseif ($x.reason) { $x.reason } else { '' }
            & $w "<tr data-check=`"$(& $h $x.id)`"><td><code>$(& $h $x.id)</code></td><td>$(& $h $x.title)</td><td><span class=`"status $(& $h $x.status)`">$(& $h $statusLabel[$x.status])</span></td><td><span class=`"sev $(& $h $x.severity)`">$(& $h $x.severity)</span></td><td class=`"tech`">$(& $h (@($r.catalogText[$x.id].license) -join ', '))</td><td data-human>$(& $h (& $humanize $detail))</td></tr>"
        }
        & $w '</tbody></table>'
    }
    & $w '</section>'

    # Checks explorer
    $domainsPresent = @($r.domains | ForEach-Object { $_.key })
    & $w '<section class="view" id="checks"><h2>Checks Explorer</h2><div class="filters">'
    & $w '<input id="filter-search" type="search" placeholder="Search" aria-label="Search checks">'
    $statusOptions = @($statusLabel.Keys | ForEach-Object { '<option value="' + $_ + '">' + $statusLabel[$_] + '</option>' }) -join ''
    $domainOptions = @($domainsPresent | ForEach-Object { '<option value="' + $_ + '">' + (& $h (& $dl $_)) + '</option>' }) -join ''
    & $w ('<select id="filter-status" aria-label="Status"><option value="">Any status</option>' + $statusOptions + '</select>')
    & $w ('<select id="filter-domain" aria-label="Domain"><option value="">Any domain</option>' + $domainOptions + '</select>')
    & $w '<select id="filter-severity" aria-label="Severity"><option value="">Any severity</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select>'
    & $w '<span id="checks-count"></span></div>'
    & $w '<table id="checks-table"><thead><tr><th>Check</th><th>Domain</th><th>Title</th><th>Status</th><th>Severity</th><th class="tech">Licence Needed</th><th>Affected</th></tr></thead><tbody>'
    foreach ($x in @($r.results | Sort-Object { $_.id })) {
        & $w "<tr data-check=`"$(& $h $x.id)`" data-status=`"$(& $h $x.status)`" data-domain=`"$(& $h $x.domain)`" data-severity=`"$(& $h $x.severity)`"><td><code>$(& $h $x.id)</code></td><td>$(& $h (& $dl $x.domain))</td><td>$(& $h $x.title)</td><td><span class=`"status $(& $h $x.status)`">$(& $h $statusLabel[$x.status])</span></td><td><span class=`"sev $(& $h $x.severity)`">$(& $h $x.severity)</span></td><td class=`"tech`">$(& $h (@($r.catalogText[$x.id].license) -join ', '))</td><td data-affected-count>$($x.affectedCount)</td></tr>"
    }
    & $w '</tbody></table><p class="tech">Select a row for the narrative, the remediation, the affected objects and the exception form.</p></section>'

    # Risk register: every failing or accepted check with the register fields, editable in the page and saved to findings.csv.
    $saveBar = ''
    & $w '<section class="view" id="register"><h2>Risk Register</h2>'
    & $w '<p>Every failing and accepted check, with the owner, status, effort and dependency the register tracks between runs. Record exceptions from a check''s detail panel; edits here and there are written to the client folder with Save, and the next run keeps them.</p>'
    & $w $saveBar
    & $w '<p class="tech" id="register-count"></p><div class="scroll"><table id="register-table"><thead><tr><th>Check</th><th>Finding</th><th>Severity</th><th>Status</th><th>Owner</th><th>Register Status</th><th>Effort</th><th>Dependency</th><th>Notes</th></tr></thead><tbody id="register-body"></tbody></table></div></section>'

    # Admins
    & $w '<section class="view" id="admins"><h2>Your Administrators</h2>'
    if (@($r.admins).Count -eq 0) { & $w '<p class="na-panel">Role assignments were not collected.</p>' }
    else {
        & $w '<table><thead><tr><th>Name</th><th>Type</th><th>Permanent Roles</th><th>Eligible Roles</th><th>Strongest MFA Method</th><th>Last Sign-In</th><th class="tech">Synced from AD</th><th class="tech">Licences</th></tr></thead><tbody>'
        foreach ($a in $r.admins) { & $w "<tr><td>$(& $h $a.name)<br><span class=`"tech`"><code>$(& $h $a.upn)</code></span></td><td>$(& $h $a.type)</td><td>$(& $h ($a.permanent -join ', '))</td><td>$(& $h ($a.eligible -join ', '))</td><td>$(& $h $a.strongestMethod)</td><td>$(& $h $(if ($a.lastSignIn) { $a.lastSignIn } else { 'unknown' }))</td><td class=`"tech`">$(if ($a.synced) { 'yes' } else { 'no' })</td><td class=`"tech`">$(& $h $a.licenses)</td></tr>" }
        & $w '</tbody></table>'
    }
    & $w '</section>'

    $naViews = @(@('exposure', 'External Exposure', 'Guests by domain, sharing links, anonymous links and Teams federation come from the SharePoint and Teams collectors, not collected yet.'), @('copilot', 'Copilot Readiness', 'The Copilot readiness gates need the collaboration, labelling and governance evidence, not collected yet.'), @('trend', 'Trend', 'Headline numbers and domain scores across runs appear once a previous run exists in the same evidence root.'), @('licensing', 'Licensing and Value', 'Unassigned and overlapping licences need the full collection set; the licences present are in the profile appendix.'))
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
        & $w '<section class="view" id="copilot"><h2>Copilot Readiness</h2>'
        if ($cp.blocked) { & $w "<p class=`"banner blocked`"><strong>Blocked.</strong> $(@($cp.blockedBy).Count) hard gate(s) not passed: $(& $h (@($cp.blockedBy | ForEach-Object { "$($_.code) $($_.title) ($($statusLabel[$_.status]))" }) -join '; ')).</p>" }
        else { & $w "<p class=`"banner ready`"><strong>Readiness $(& $num $cp.readinessPct '%').</strong> Every hard gate passes; $($cp.passed) of $($cp.evaluated) evaluated gates pass.</p>" }
        & $w '<table><thead><tr><th>Gate</th><th>Hard Gate</th><th>Status</th><th>Title</th><th>Affected</th></tr></thead><tbody>'
        foreach ($g in $cp.gates) { & $w "<tr class=`"st-$($g.status)`" data-check=`"$(& $h $g.id)`"><td>$(& $h $g.code)</td><td>$(if ($g.hard) { 'Yes' })</td><td><span class=`"status $(& $h $g.status)`">$(& $h $statusLabel[$g.status])</span></td><td>$(& $h $g.title)</td><td>$(if ($g.affectedCount -gt 0) { $g.affectedCount })</td></tr>" }
        & $w '</tbody></table>'
        if (@($cp.notEvaluated).Count -gt 0) { & $w "<p class=`"muted`">Not evaluated: $(& $h (@($cp.notEvaluated | ForEach-Object { "$($_.code): $($_.reason)" }) -join ' '))</p>" }
        & $w "<p>$(& $h $cp.narrative)</p></section>"
    }

    # Conditional Access
    & $w '<section class="view" id="ca"><h2>Conditional Access</h2>'
    if (-not $r.ca) { & $w '<p class="na-panel">No Conditional Access snapshot in the evidence folder.</p>' }
    else {
        & $w "<p>$(@($r.ca.policies).Count) policies, $($r.ca.flagCount) health flag(s). The full documentation with a page per policy is <code>ca-document.html</code> next to the snapshot.</p>"
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
        foreach ($x in $items) { $portal = $(if ($x.deepLink) { ' <a href="' + (& $h $x.deepLink) + '" target="_blank" rel="noopener">Open in Portal</a>' } else { '' }); & $w "<div class=`"rec`"><div class=`"title`"><a href=`"#checks`" data-check=`"$(& $h $x.id)`">$(& $h $x.id) $(& $h $x.title)</a> <span class=`"sev $(& $h $x.severity)`">$(& $h $x.severity)</span> <span class=`"tech`">$(& $h (& $dl $x.domain))$(if ($x.license.Count -gt 0) { ", needs $(& $h ($x.license -join ' or '))" })$(if ($x.affectedCount -gt 0) { ", $($x.affectedCount) affected" })</span></div><div>$(& $h $x.remediation) <a href=`"$(& $h $x.learn)`" target=`"_blank`" rel=`"noopener`">Microsoft Learn</a>$portal</div></div>" }
        & $w '</div>'
    }
    & $w '</section>'

    # Appendix
    $a = $r.appendix
    if ($r.crosswalk) {
        & $w "<section class=`"view`" id=`"crosswalk`"><h2>Framework Crosswalk: $(& $h $(if ($frameworkLabel.Contains([string]$r.crosswalk.framework)) { $frameworkLabel[[string]$r.crosswalk.framework] } else { $r.crosswalk.framework }))</h2>"
        & $w '<p class="muted">Reference numbers only; the framework text is not reproduced.</p>'
        foreach ($e in $r.crosswalk.entries) {
            & $w "<h3>$(& $h $e.name) <span class=`"muted`">($($e.pass) pass, $($e.fail) fail)</span></h3>"
            if (@($e.checks).Count -eq 0) { & $w '<p class="muted">No check maps here yet.</p>'; continue }
            & $w '<table><thead><tr><th>Reference</th><th>Check</th><th>Status</th><th>Severity</th></tr></thead><tbody>'
            foreach ($c in $e.checks) { & $w "<tr class=`"st-$($c.status)`" data-check=`"$(& $h $c.id)`"><td>$(& $h $c.reference)</td><td>$(& $h $c.id) $(& $h $c.title)</td><td><span class=`"status $(& $h $c.status)`">$(& $h $statusLabel[$c.status])</span></td><td><span class=`"sev $(& $h $c.severity)`">$(& $h $c.severity)</span></td></tr>" }
            & $w '</tbody></table>'
        }
        & $w '</section>'
    }
    & $w '<section class="view" id="settings"><h2>Settings</h2>'
    & $w '<p>The tenant profile the checks read: thresholds, third-party controls, break-glass accounts, frameworks and audience. Changes are saved to profile.json in the client folder and take effect on the next run.</p>'
    & $w $saveBar
    & $w '<div id="settings-form"></div></section>'
    & $w '<section class="view" id="appendix"><h2>Appendix</h2><table><tbody>'
    foreach ($pair in @(@('Catalog Version', $a.catalogVersion), @('Baseline', $a.baseline), @('Profile', $a.profile), @('Evidence Folder', $a.evidence), @('Collectors', ($r.collectors -join ', ')), @('Scopes', ($a.scopes -join ', ')), @('Graph API Versions', ($a.graphApiVersions -join ', ')), @('Module Version', $a.moduleVersion), @('Build', $a.build), @('Licence', $a.licence))) { & $w "<tr><th>$(& $h $pair[0])</th><td>$(& $h $pair[1])</td></tr>" }
    & $w '</tbody></table>'
    if ($a.profileAnswers) {
        & $w '<h3>Profile</h3><table><tbody>'
        foreach ($k in $a.profileAnswers.Keys) { $val = $a.profileAnswers[$k]; $text = if ($val -is [System.Collections.IDictionary]) { (@($val.Keys | ForEach-Object { "$_=$($val[$_])" }) -join '; ') } elseif ($val -is [array]) { $val -join ', ' } else { [string]$val }; & $w "<tr><th>$(& $h $k)</th><td>$(& $h $text)</td></tr>" }
        & $w '</tbody></table>'
    }
    & $w '<h3>Exceptions</h3>'
    if (@($a.exceptions).Count -eq 0) { & $w '<p>None.</p>' }
    else { & $w '<table><thead><tr><th>Check</th><th>Object</th><th>Justification</th><th>Owner</th><th>Approver</th><th>Expires</th></tr></thead><tbody>'; foreach ($e in $a.exceptions) { & $w "<tr><td>$(& $h $e.check)</td><td>$(& $h $e.object)</td><td>$(& $h $e.justification)</td><td>$(& $h $e.owner)</td><td>$(& $h $e.approver)</td><td>$(if ($e.expires) { $e.expires.ToString('yyyy-MM-dd') })$(if ($e.expired) { ' (expired)' })</td></tr>" }; & $w '</tbody></table>' }
    & $w '<h3>Checks Not Evaluated</h3>'
    if (@($a.notEvaluated).Count -eq 0) { & $w '<p>None.</p>' }
    else { & $w '<table><thead><tr><th>Check</th><th>Title</th><th>Status</th><th>Why</th></tr></thead><tbody>'; foreach ($n in $a.notEvaluated) { & $w "<tr data-check=`"$(& $h $n.id)`"><td><code>$(& $h $n.id)</code></td><td>$(& $h $n.title)</td><td>$(& $h $statusLabel[$n.status])</td><td>$(& $h $n.reason)</td></tr>" }; & $w '</tbody></table>' }
    & $w "<h3 class=`"tech`">Evidence Index</h3><p class=`"chips tech`">$(@($a.evidenceFiles | ForEach-Object { '<span class="chip">' + (& $h $_) + '</span>' }) -join '')</p>"
    if (@($a.errors).Count -gt 0) { & $w '<h3>Collection Errors</h3><ul>'; foreach ($e in $a.errors) { & $w "<li>$(& $h $e)</li>" }; & $w '</ul>' }
    & $w '</section></main>'
    & $w '<aside id="drawer" aria-label="Check detail"></aside>'
    & $w '<div id="savedock" class="savebar savedock" aria-label="Save changes"><span class="folder"><button type="button" data-pick>Choose Client Folder</button></span><button type="button" class="primary" data-save disabled>Save</button><button type="button" data-download>Download Files Instead</button><span class="state"></span><div class="result hint"></div></div>'
    & $w '<div id="toast" class="toast" role="status"></div>'
    if ($b.footer) { & $w "<footer class=`"doc`">$(& $h $b.footer)</footer>" }

    # Embedded data, then the behaviour.
    & $w (& $jsonBlock 'data-results' @($r.results | ForEach-Object { [ordered]@{ id = $_.id; domain = $_.domain; title = $_.title; status = $_.status; severity = $_.severity; reason = $_.reason; affected = @($_.affected); affectedCount = $_.affectedCount; evidence = @($_.evidence); thresholds = $_.thresholds } }))
    & $w (& $jsonBlock 'data-catalog' $r.catalogText)
    & $w (& $jsonBlock 'data-exceptions' @($r.exceptions))
    & $w (& $jsonBlock 'data-profile' $r.profileModel)
    & $w (& $jsonBlock 'data-register' @($r.register))
    & $w (& $jsonBlock 'data-meta' ([ordered]@{ tenantId = $r.tenantId; clientName = $r.clientName; generatedUtc = $r.generatedUtc; licenceId = $(if ($r.licence) { $r.licence.licenceId } else { $null }) }))
    & $w (& $jsonBlock 'data-labels' ([ordered]@{ status = $statusLabel; domains = $domainLabel; frameworks = $frameworkLabel; methods = $methodLabel; thresholds = $thresholdLabel }))
    & $w "<script>`n$js`n</script>"
    & $w '</body></html>'
    return $sb.ToString()
}
