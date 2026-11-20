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
    # The catalog's plain labels (checks/facts.json) win over the names above and over words made from a fact's name.
    $catLabels = $(if ($Report.Contains('labels') -and $Report.labels) { $Report.labels } else { @{ facts = @{}; thresholds = @{} } })
    foreach ($k in @($catLabels.thresholds.Keys)) { $thresholdLabel[$k] = $catLabels.thresholds[$k] }
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
    & $w '<!-- For tools and AI: the ranked findings are the JSON in <script id="tenantkeep-findings"> at the end of this page (the same as findings.json beside it). Read its "about" field first. -->'
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
    $viewList = @(@('overview', 'Overview', $true), @('recommendations', 'Recommendations', $true), @('domains', 'Domains', $true), @('checks', 'Checks Explorer', $true), @('admins', 'Your Administrators', $true), @('exposure', 'External Exposure', $false), @('copilot', 'Copilot Readiness', [bool]($r.copilot -and $r.copilot.present)), @('ca', 'Conditional Access', [bool]$r.ca), @('inventory', 'Inventory', [bool]($r.Contains('inventory') -and @($r.inventory | Where-Object { $_.total -gt 0 }).Count)), @('crosswalk', 'Crosswalk', [bool]$r.crosswalk), @('trend', 'Trend', [bool]$r.trend), @('licensing', 'Licensing', [bool]$r.licensing), @('health', 'Run Health', $true), @('appendix', 'Appendix', $true))
    & $w '<nav class="views" aria-label="Views">'
    foreach ($vw in $viewList) { & $w "<a href=`"#$($vw[0])`"$(if (-not $vw[2]) { ' class="na"' })>$(& $h $vw[1])</a>" }
    & $w '</nav><main>'

    # Overview
    & $w '<section class="view active" id="overview"><h2>Overview</h2>'
    $rh = $r.runHealth
    if ($rh -and @($rh.failures).Count -gt 0) {
        $parts = @($rh.byCause.Keys | ForEach-Object { "$($rh.byCause[$_]) $($_.ToLowerInvariant())" }) -join ', '
        & $w "<div class=`"banner warn`"><strong>$(@($rh.failures).Count) step(s) could not be read</strong> ($(& $h $parts)). The checks that depend on them say not evaluated. <a href=`"#health`">Run Health</a> says what to grant and how to collect just those again.</div>"
    }
    & $w "<div class=`"score`"><div class=`"grade`" id=`"score-grade`">$(& $h $r.score.grade)</div><div><div class=`"value`" id=`"score-value`">Posture score $(& $num $r.score.value)</div><div class=`"method`">$(& $h $r.score.method) $($r.score.evaluated) checks scored.</div></div></div>"
    # Header tiles and a passed-of-evaluated row per domain, each a link into its checks.
    $ch = $(if ($r.Contains('charts') -and $r.charts) { $r.charts } else { [ordered]@{} })
    if ($ch.Contains('tiles') -and @($ch.tiles).Count) {
        & $w ('<div class="tiles">' + (@($ch.tiles | ForEach-Object { '<div class="tile"><div class="n">' + (& $h (Format-PostureChartNumber $_.value)) + '</div><div class="l">' + (& $h $_.label) + '</div>' + $(if ($_.sub) { '<div class="s">' + (& $h $_.sub) + '</div>' }) + '</div>' }) -join '') + '</div>')
    }
    if (@($r.domains).Count) {
        & $w '<div class="pillars">'
        foreach ($d in $r.domains) {
            $ev = [int]$d.counts.pass + [int]$d.counts.fail + [int]$d.counts.acceptedRisk + [int]$d.counts.coveredBy
            $held = [int]$d.counts.pass + [int]$d.counts.acceptedRisk + [int]$d.counts.coveredBy
            $bar = ConvertTo-PostureBarChart -Thin -Name $d.label -Segment @(@{ label = 'Pass, accepted or covered'; value = $held; tone = 'ok' }, @{ label = 'Fail'; value = [int]$d.counts.fail; tone = 'err' })
            & $w ('<a class="pillar" href="#checks" data-filter-domain="' + (& $h $d.key) + '"><span class="name">' + (& $h $d.label) + '</span><span class="frac">' + $held + ' of ' + $ev + '</span>' + $bar + '</a>')
        }
        & $w '</div>'
    }
    $hl = $r.headline
    & $w '<div class="stats">'
    foreach ($pair in @(@('MFA Registered', (& $num $hl.mfaRegisteredPct '%')), @('Administrators on Phishing-Resistant MFA', (& $num $hl.adminsPhishingResistantPct '%')), @('Permanent Global Administrators', (& $num $hl.permanentGlobalAdmins)), @('Intune Compliance', (& $num $hl.intuneCompliancePct '%')), @('External Sharing Exposure', (& $num $hl.externalExposure)), @('Copilot Readiness', $(if ($hl.copilotBlocked) { 'Blocked' } else { & $num $hl.copilotReadinessPct '%' })))) {
        $naClass = if ($pair[1] -eq 'not collected yet') { ' na' } else { '' }
        & $w ('<div class="stat' + $naClass + '"><div class="n">' + (& $h $pair[1]) + '</div><div class="l">' + (& $h $pair[0]) + '</div></div>')
    }
    & $w '</div>'
    $overviewCharts = @()
    if ($ch.Contains('authUsers')) { $overviewCharts += ConvertTo-PostureChartCard -Class 'wide' -Title 'How Members Sign In' -Takeaway $ch.authUsers.takeaway -ViewAllDomain 'auth' -Body (ConvertTo-PostureSankeyChart -Name 'Members by strongest sign-in method' -Column $ch.authUsers.column -Flow $ch.authUsers.flow) }
    if ($ch.Contains('signInCa')) { $overviewCharts += ConvertTo-PostureChartCard -Class 'wide' -Title 'Sign-ins Through Conditional Access' -Takeaway $ch.signInCa.takeaway -ViewAllDomain 'ca' -Body (ConvertTo-PostureSankeyChart -Name 'Successful sign-ins by Conditional Access and MFA' -Height 200 -Column $ch.signInCa.column -Flow $ch.signInCa.flow) }
    if ($ch.Contains('compliance')) { $overviewCharts += ConvertTo-PostureChartCard -Title 'Device Compliance' -Takeaway $ch.compliance.takeaway -ViewAllDomain 'devices' -Body (ConvertTo-PostureDonutChart -Name 'Device compliance' -CenterLabel 'devices' -Segment $ch.compliance.segment) }
    if ($ch.Contains('authAdmins')) { $overviewCharts += ConvertTo-PostureChartCard -Title 'Administrators by Sign-in Strength' -Takeaway $ch.authAdmins.takeaway -ViewAllDomain 'identity' -Body (ConvertTo-PostureBarChart -Name 'Administrators by strongest method' -Segment $ch.authAdmins.segment) }
    # Defence in depth: each layer set as rings.
    foreach ($ls in @($(if ($r.Contains('layers')) { $r.layers }))) { $overviewCharts += ConvertTo-PostureChartCard -Title $ls.name -Takeaway $ls.takeaway -ViewAllDomain $ls.domain -Body (ConvertTo-PostureRingChart -Name $ls.name -Layer $ls.layers) }
    $c0 = $r.counts
    $overviewCharts += ConvertTo-PostureChartCard -Title 'Check Results' -Takeaway "$($c0.pass) of $([int]$c0.pass + [int]$c0.fail + [int]$c0.acceptedRisk + [int]$c0.coveredBy) evaluated checks pass; $($c0.notEvaluated) could not be evaluated." -Body (ConvertTo-PostureBarChart -Name 'Check results' -Segment @(@{ label = 'Pass'; value = $c0.pass; tone = 'ok' }, @{ label = 'Fail'; value = $c0.fail; tone = 'err' }, @{ label = 'Accepted or covered'; value = ([int]$c0.acceptedRisk + [int]$c0.coveredBy); tone = 'c1' }, @{ label = 'Not evaluated'; value = $c0.notEvaluated; tone = 'na' }))
    & $w ('<div class="charts">' + ($overviewCharts -join '') + '</div>')
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
    # One card per priority, one finding per line: the first six, then a link to the rest.
    $when = [ordered]@{ 'Stop the bleeding' = 'Critical. This week.'; 'Foundations' = 'High. This quarter.'; 'Program workstreams' = 'Medium. Planned work.'; 'Later' = 'Low. When time allows.' }
    & $w '<h3>What We Recommend This Quarter</h3><div class="buckets">'
    foreach ($bucket in $r.recommendations.Keys) {
        $items = @($r.recommendations[$bucket]); if ($items.Count -eq 0) { continue }
        $lines = @($items | Select-Object -First 6 | ForEach-Object { '<li><a href="#recommendations" data-check="' + (& $h $_.id) + '"><code>' + (& $h $_.id) + '</code> ' + (& $h $_.title) + '</a>' + $(if ($_.affectedCount -gt 0) { ' <span class="tech">' + $_.affectedCount + ' affected</span>' }) + '</li>' }) -join ''
        $more = $(if ($items.Count -gt 6) { '<p class="more"><a href="#recommendations">and ' + ($items.Count - 6) + ' more</a></p>' } else { '' })
        & $w ('<div class="bucket-card"><h4>' + (& $h $bucket) + ' <span class="count">' + $items.Count + '</span></h4><p class="hint">' + (& $h $when[$bucket]) + '</p><ul class="rec-list">' + $lines + '</ul>' + $more + '</div>')
    }
    & $w '</div>'
    if (@($r.domainsNotCollected).Count -gt 0) { & $w "<div class=`"notice`">Not collected yet: $(& $h (@($r.domainsNotCollected | ForEach-Object { $_.label }) -join ', ')). Scores cover the collected domains only.</div>" }
    & $w '</section>'

    # Domains
    & $w '<section class="view" id="domains"><h2>Domain Scorecards</h2>'
    $areas = [ordered]@{ Identity = @(); Access = @(); Devices = @() }
    if ($ch.Contains('authUsers')) { $areas.Identity += ConvertTo-PostureChartCard -Class 'wide' -Title 'Members by Sign-in Method' -Takeaway $ch.authUsers.takeaway -ViewAllDomain 'auth' -Body (ConvertTo-PostureSankeyChart -Name 'Members by strongest sign-in method' -Column $ch.authUsers.column -Flow $ch.authUsers.flow) }
    if ($ch.Contains('authAdmins')) { $areas.Identity += ConvertTo-PostureChartCard -Title 'Administrators by Sign-in Strength' -Takeaway $ch.authAdmins.takeaway -ViewAllDomain 'identity' -Body (ConvertTo-PostureDonutChart -Name 'Administrators by strongest method' -CenterLabel 'admins' -Segment $ch.authAdmins.segment) }
    if ($ch.Contains('signInCa')) { $areas.Access += ConvertTo-PostureChartCard -Class 'wide' -Title 'Sign-ins Through Conditional Access' -Takeaway $ch.signInCa.takeaway -ViewAllDomain 'ca' -Body (ConvertTo-PostureSankeyChart -Name 'Successful sign-ins by Conditional Access and MFA' -Height 200 -Column $ch.signInCa.column -Flow $ch.signInCa.flow) }
    if ($ch.Contains('signInDevice')) { $areas.Access += ConvertTo-PostureChartCard -Class 'wide' -Title 'Sign-ins by Device Trust' -Takeaway $ch.signInDevice.takeaway -ViewAllDomain 'devices' -Body (ConvertTo-PostureSankeyChart -Name 'Successful sign-ins by device' -Height 200 -Column $ch.signInDevice.column -Flow $ch.signInDevice.flow) }
    if ($ch.Contains('devices')) { $areas.Devices += ConvertTo-PostureChartCard -Class 'wide' -Title 'Managed Devices by Platform, Join Type and Compliance' -Takeaway $ch.devices.takeaway -ViewAllDomain 'devices' -Body (ConvertTo-PostureSankeyChart -Name 'Managed devices' -Column $ch.devices.column -Flow $ch.devices.flow) }
    if ($ch.Contains('compliance')) { $areas.Devices += ConvertTo-PostureChartCard -Title 'Device Compliance' -Takeaway $ch.compliance.takeaway -ViewAllDomain 'devices' -Body (ConvertTo-PostureDonutChart -Name 'Device compliance' -CenterLabel 'devices' -Segment $ch.compliance.segment) }
    if ($ch.Contains('ownership')) { $areas.Devices += ConvertTo-PostureChartCard -Title 'Device Ownership' -Takeaway $ch.ownership.takeaway -ViewAllDomain 'devices' -Body (ConvertTo-PostureDonutChart -Name 'Device ownership' -CenterLabel 'devices' -Segment $ch.ownership.segment) }
    if ($ch.Contains('antivirus')) { $areas.Devices += ConvertTo-PostureChartCard -Title 'Defender Antivirus Mode' -Takeaway $ch.antivirus.takeaway -ViewAllDomain 'endpoint' -Body (ConvertTo-PostureDonutChart -Name 'Defender Antivirus mode' -CenterLabel 'devices' -Segment $ch.antivirus.segment) }
    foreach ($a in $areas.Keys) { if (@($areas[$a]).Count) { & $w ('<h3>' + (& $h $a) + '</h3><div class="charts">' + (@($areas[$a]) -join '') + '</div>') } }
    & $w '<h3>Scorecards</h3><div class="cards">'
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
    & $w '</tbody></table><p class="tech">Select a row for the narrative, the remediation and the affected objects.</p></section>'

    # Admins
    & $w '<section class="view" id="admins"><h2>Your Administrators</h2>'
    if (@($r.admins).Count -eq 0) { & $w '<p class="na-panel">Role assignments were not collected.</p>' }
    else {
        & $w '<table><thead><tr><th>Name</th><th>Type</th><th>Permanent Roles</th><th>Eligible Roles</th><th>Strongest MFA Method</th><th>Last Sign-In</th><th class="tech">Synced from AD</th><th class="tech">Licences</th></tr></thead><tbody>'
        foreach ($a in $r.admins) { & $w "<tr><td>$(& $h $a.name)<br><span class=`"tech`"><code>$(& $h $a.upn)</code></span></td><td>$(& $h $a.type)</td><td>$(& $h ($a.permanent -join ', '))</td><td>$(& $h ($a.eligible -join ', '))</td><td>$(& $h $a.strongestMethod)</td><td>$(& $h $(if ($a.lastSignIn) { $a.lastSignIn } else { 'unknown' }))</td><td class=`"tech`">$(if ($a.synced) { 'yes' } else { 'no' })</td><td class=`"tech`">$(& $h $a.licenses)</td></tr>" }
        & $w '</tbody></table>'
    }
    & $w '</section>'

    $naViews = @(@('exposure', 'External Exposure', 'Guests by domain, sharing links, anonymous links and Teams federation come from the SharePoint and Teams collectors, not collected yet.'), @('copilot', 'Copilot Readiness', 'The Copilot readiness gates need the collaboration, labelling and governance evidence, not collected yet.'), @('trend', 'Trend', 'Headline numbers and domain scores across runs appear once a previous run exists in the same evidence root.'), @('licensing', 'Licensing', 'The subscribed licences were not collected (01-subscribed-skus.json, from the Entra collector).'))
    if ($r.copilot -and $r.copilot.present) { $naViews = @($naViews | Where-Object { $_[0] -ne 'copilot' }) }
    if ($r.trend) { $naViews = @($naViews | Where-Object { $_[0] -ne 'trend' }) }
    if ($r.licensing) { $naViews = @($naViews | Where-Object { $_[0] -ne 'licensing' }) }
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

    # Recommendations: a card per failed check, what was found in this tenant, why it matters, what it affects and
    # the steps to fix it; improvements read as suggestions. Then what already passes, per domain.
    $effortLabel = @{ S = 'Quick fix'; M = 'Planned change'; L = 'Project' }
    $factLabel = { param([string] $k) if ($catLabels.facts.Contains($k)) { return [string]$catLabels.facts[$k] }; $t = ($k -creplace '([a-z0-9])([A-Z])', '$1 $2') -creplace '([A-Z]+)([A-Z][a-z])', '$1 $2'; $t.Substring(0, 1).ToUpperInvariant() + $t.Substring(1).ToLowerInvariant() -replace '\b(mfa|ca|spo|dlp|pim|sspr|tap|dkim|dmarc|spf|mde|edr|av|os|ip|id|url|api|smtp|imap|pop|ews|tls|ssl)\b', { $_.Value.ToUpperInvariant() } -replace '\bpct\b', '(%)' }
    $factValue = { param($v) if ($v -is [bool]) { if ($v) { 'yes' } else { 'no' } } elseif ($null -eq $v -or "$v" -eq '') { 'none' } elseif ($v -is [ValueType]) { & $num $v } else { [string]$v } }
    $allRecs = @($r.recommendations.Values | ForEach-Object { $_ })
    $fixes = @($allRecs | Where-Object { $_.category -ne 'improve' }).Count
    & $w '<section class="view" id="recommendations"><h2>Recommendations</h2>'
    & $w "<p class=`"lede`">$fixes finding(s) to fix and $($allRecs.Count - $fixes) improvement(s), most urgent first. Within each priority the quick fixes come first, then what affects the most. Each card has the steps, the portal page and the Microsoft Learn article.</p>"
    # Do today: quick fixes users will barely notice, the place to start.
    if ($r.Contains('doToday') -and @($r.doToday).Count -gt 0) {
        # Ten at most: a list for one day. The rest carry the same chips on their cards.
        $li = @($r.doToday | Select-Object -First 10 | ForEach-Object { '<li><span class="sev ' + (& $h $_.severity) + '">' + (& $h $_.severity) + '</span> <a href="#rec-' + (& $h $_.id) + '"><code>' + (& $h $_.id) + '</code> ' + (& $h $_.title) + '</a><span class="muted">' + (& $h $_.userImpact['text']) + '</span></li>' }) -join ''
        & $w ('<div class="do-today"><h3>Do Today <span class="count">' + @($r.doToday).Count + '</span></h3><p class="hint">Quick fixes that users will not notice or will barely notice: a setting each, under an hour. The most severe first.</p><ul>' + $li + '</ul>' + $(if (@($r.doToday).Count -gt 10) { '<p class="hint">' + (@($r.doToday).Count - 10) + ' more like these below, marked Quick fix and User impact: none or low.</p>' }) + '</div>')
    }
    # Control chains: checks that only protect together, one card each with the broken link marked.
    if ($r.Contains('chains') -and @($r.chains).Count -gt 0) {
        $chainLabel = @{ pass = 'Holds'; broken = 'Broken'; notEvaluated = 'Incomplete' }
        $chainClass = @{ pass = 'pass'; broken = 'fail'; notEvaluated = 'notEvaluated' }
        & $w '<h3>Control Chains</h3><p class="hint">Some controls protect only when the others in their chain hold. A chain breaks at its first failing link; fix that link first.</p><div class="chains">'
        foreach ($ch in $r.chains) {
            $li = @($ch.links | ForEach-Object { '<li class="link st-' + (& $h $_.status) + $(if ($_.check -eq $ch.brokenAt) { ' broken-at' }) + '"><span class="status ' + (& $h $_.status) + '">' + (& $h $statusLabel[[string]$_.status]) + '</span><a href="#checks" data-check="' + (& $h $_.check) + '"><code>' + (& $h $_.check) + '</code> ' + (& $h $_.title) + '</a><span class="role">' + (& $h $_.role) + '</span></li>' }) -join ''
            $state = (& $h $chainLabel[[string]$ch.status]) + $(if ($ch.brokenAt) { ' at ' + (& $h $ch.brokenAt) } else { '' })
            & $w ('<article class="chain st-' + (& $h $ch.status) + '" id="chain-' + (& $h $ch.id) + '"><header><span class="status ' + $chainClass[[string]$ch.status] + '">' + $state + '</span> <span class="muted">' + $ch.held + ' of ' + @($ch.links).Count + ' links hold</span><h4 class="finding-title">' + (& $h $ch.name) + '</h4></header><ol class="chain-links">' + $li + '</ol><p class="muted">' + (& $h $ch.why) + '</p></article>')
        }
        & $w '</div>'
    }
    foreach ($bucket in $r.recommendations.Keys) {
        $items = @($r.recommendations[$bucket])
        & $w "<div class=`"bucket`"><h3>$(& $h $bucket) <span class=`"count`">$($items.Count)</span> <span class=`"hint`">$(& $h $when[$bucket])</span></h3>"
        if ($items.Count -eq 0) { & $w '<p class="muted">Nothing in this bucket.</p>' }
        foreach ($x in $items) {
            $chips = '<span class="sev ' + (& $h $x.severity) + '">' + (& $h $x.severity) + '</span>'
            if ($x.effort) { $chips += '<span class="chip effort-' + (& $h $x.effort) + '">' + (& $h $effortLabel[[string]$x.effort]) + '</span>' }
            if ($x.category -eq 'improve') { $chips += '<span class="chip improve">Improvement</span>' }
            if ($x.userImpact) { $chips += '<span class="chip ui-' + (& $h $x.userImpact['level']) + '">User impact: ' + (& $h $x.userImpact['level']) + '</span>' }
            $chips += '<span class="chip">' + (& $h (& $dl $x.domain)) + '</span>'
            if (@($x.license).Count -gt 0) { $chips += '<span class="chip">Needs ' + (& $h (@($x.license) -join ' or ')) + '</span>' }
            $found = @()
            if ($x.reason) { $found += '<p>' + (& $h $x.reason) + '</p>' }
            $obs = @($x.observed.Keys | ForEach-Object { '<li>' + (& $h (& $factLabel $_)) + ': <strong>' + (& $h (& $factValue $x.observed[$_])) + '</strong></li>' })
            $thr = @(@($(if ($x.thresholds) { $x.thresholds.Keys })) | ForEach-Object { '<li class="muted">' + (& $h $(if ($thresholdLabel.Contains($_)) { $thresholdLabel[$_] } else { & $factLabel $_ })) + ': ' + (& $h (& $factValue $x.thresholds[$_])) + '</li>' })
            if ($obs.Count -or $thr.Count) { $found += '<ul class="observed">' + ($obs -join '') + ($thr -join '') + '</ul>' }
            if ($x.affectedCount -gt 0) { $found += '<p>' + (& $num $x.affectedCount) + ' affected.</p>' }
            if (-not $found.Count) { $found += '<p>The setting does not meet the check. The steps below say what it should be.</p>' }
            $affected = ''
            if ($x.affectedCount -gt 0) {
                $li = @($x.affected | ForEach-Object { $n = $(if ($_ -is [System.Collections.IDictionary]) { [string]$_['name'] } else { [string]$_ }); $dt = $(if ($_ -is [System.Collections.IDictionary] -and $_.Contains('detail')) { [string]$_['detail'] } else { '' }); '<li>' + (& $h $n) + $(if ($dt) { ' <span class="muted">(' + (& $h (& $humanize $dt)) + ')</span>' }) + '</li>' }) -join ''
                $rest = $(if ($x.affectedCount -gt @($x.affected).Count) { '<p class="hint">The first ' + @($x.affected).Count + ' of ' + (& $num $x.affectedCount) + '. All of them are in affected/' + (& $h $x.id) + '.csv.</p>' } else { '' })
                $affected = '<details class="affected-list"><summary>Affected (' + (& $num $x.affectedCount) + ')</summary><ul>' + $li + '</ul>' + $rest + '</details>'
            }
            $fix = $(if (@($x.steps).Count -gt 1) { '<ol class="steps">' + (@($x.steps | ForEach-Object { '<li>' + (& $h $_) + '</li>' }) -join '') + '</ol>' } else { '<p>' + (& $h $x.remediation) + '</p>' })
            $links = @()
            if ($x.deepLink) { $links += '<a class="btn" href="' + (& $h $x.deepLink) + '" target="_blank" rel="noopener">Open in Portal</a>' }
            if ($x.learn) { $links += '<a class="btn" href="' + (& $h $x.learn) + '" target="_blank" rel="noopener">Microsoft Learn</a>' }
            $links += '<a class="btn" href="#checks" data-check="' + (& $h $x.id) + '">Details and Accept Risk</a>'
            $fw = @($x.frameworks.Keys | Where-Object { $x.frameworks[$_] } | ForEach-Object { '<span class="chip">' + (& $h $(if ($frameworkLabel.Contains($_)) { $frameworkLabel[$_] } else { $_ })) + ' ' + (& $h $x.frameworks[$_]) + '</span>' }) -join ''
            & $w ('<article class="finding' + $(if ($x.category -eq 'improve') { ' improve' }) + ' sev-' + (& $h $x.severity) + '" id="rec-' + (& $h $x.id) + '"><header><p class="chips">' + $chips + '</p><h4 class="finding-title"><code>' + (& $h $x.id) + '</code> ' + (& $h $x.title) + '</h4></header>' +
                '<div class="finding-grid"><div><h5>What We Found</h5>' + ($found -join '') + $affected + '</div><div><h5>Why It Matters</h5><p>' + (& $h $x.why) + '</p></div></div>' +
                '<h5>How To Fix</h5>' + $fix + $(if ($x.userImpact) { '<p class="user-impact"><strong>What users notice:</strong> ' + (& $h $x.userImpact['text']) + '</p>' }) + '<p class="links">' + ($links -join ' ') + '</p>' + $(if ($fw) { '<p class="chips tech">' + $fw + '</p>' }) + '</article>')
        }
        & $w '</div>'
    }
    if ($r.alreadyGood -and @($r.alreadyGood.Keys).Count -gt 0) {
        $goodCount = @($r.alreadyGood.Values | ForEach-Object { $_ }).Count
        & $w "<h3>What's Already Good <span class=`"count`">$goodCount</span></h3><div class=`"good-list`">"
        foreach ($d in $r.alreadyGood.Keys) {
            $li = @($r.alreadyGood[$d] | ForEach-Object { '<li><a href="#checks" data-check="' + (& $h $_.id) + '"><code>' + (& $h $_.id) + '</code> ' + (& $h $_.title) + '</a></li>' }) -join ''
            & $w ('<details><summary>' + (& $h (& $dl $d)) + ' <span class="count">' + @($r.alreadyGood[$d]).Count + '</span></summary><ul>' + $li + '</ul></details>')
        }
        & $w '</div>'
    }
    & $w '</section>'

    # Inventory: what the tenant has, as tables, each naming the evidence it came from.
    & $w '<section class="view" id="inventory"><h2>Inventory</h2><p class="lede">What the tenant has, read from the evidence: no pass or fail here. The checks judge these; this is the list to plan from.</p>'
    $invList = @($(if ($r.Contains('inventory')) { $r.inventory }))
    if ($invList.Count) {
        & $w ('<p class="chips">' + (@($invList | ForEach-Object { '<a class="chip" href="#inv-' + (& $h $_.key) + '">' + (& $h $_.title) + ' <span class="count">' + $_.total + '</span></a>' }) -join '') + '</p>')
    }
    foreach ($s in $invList) {
        & $w ('<h3 id="inv-' + (& $h $s.key) + '">' + (& $h $s.title) + ' <span class="count">' + $s.total + '</span></h3>')
        if ($s.note) { & $w ('<p class="hint">' + (& $h $s.note) + '</p>') }
        if (@($s.rows).Count) {
            & $w ('<div class="scroll"><table class="inventory"><thead><tr>' + (@($s.columns | ForEach-Object { '<th>' + (& $h $_) + '</th>' }) -join '') + '</tr></thead><tbody>')
            foreach ($row in $s.rows) { & $w ('<tr>' + (@($s.columns | ForEach-Object { '<td>' + (& $h ([string]$row[$_])) + '</td>' }) -join '') + '</tr>') }
            & $w '</tbody></table></div>'
        }
        & $w ('<p class="tech chips">' + (@($s.source | ForEach-Object { '<span class="chip">' + (& $h $_) + '</span>' }) -join '') + '</p>')
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
    # Licensing: what the tenant holds and uses, what each goal needs, and what to add. No prices anywhere.
    if ($r.licensing) {
        $la = $(if ($r.Contains('licenseAdvice')) { $r.licenseAdvice } else { $null })
        & $w '<section class="view" id="licensing"><h2>Licensing</h2><p class="lede">What the tenant holds, what is switched on, what each security goal needs, and the smallest change that covers the goals. No prices: take the answer to your Microsoft partner.</p>'
        if ($la) {
            $ad = $la.advice
            $goalNames = @{}; foreach ($g in $la.goals) { $goalNames[[string]$g.id] = $g.name }
            $forWhat = $(if ($ad.goalSource -eq 'profile') { 'the goals in your profile' } else { 'the core goals (set your own with New-PostureProfile -Goal)' })
            & $w ('<div class="advisor"><h3>What To Add</h3><p class="hint">For ' + (& $h $forWhat) + ': ' + (& $h (@($ad.goals | ForEach-Object { $goalNames[[string]$_] }) -join '; ')) + '.</p>')
            if ($ad.met) { & $w '<p class="banner ready"><strong>Covered.</strong> The licences you hold include every feature these goals need. The work is configuration: see Recommendations.</p>' }
            else {
                & $w ('<p>Missing: ' + (& $h (@($ad.missing | ForEach-Object { @($_) -join ' or ' }) -join '; ')) + '.</p><div class="advice-options">')
                if (@($ad.addOns).Count) {
                    $li = @($ad.addOns | ForEach-Object { '<li><strong>' + (& $h $_.name) + '</strong> <span class="muted">adds ' + (& $h (@($_.adds) -join ', ')) + '</span>' + $(if ($_.verify) { ' <span class="tech">(verify: ' + (& $h $_.verify) + ')</span>' }) + '</li>' }) -join ''
                    & $w ('<div class="advice-card"><h4>Fewest add-ons</h4><ul>' + $li + '</ul><p class="hint">On top of what you have, for ' + $ad.seats + ' licensed users.</p></div>')
                }
                if ($ad.upgrade) { & $w ('<div class="advice-card"><h4>One bundle instead</h4><p><strong>' + (& $h $ad.upgrade.name) + '</strong> covers these goals on its own, in place of your current suite.</p></div>') }
                & $w '</div>'
                foreach ($pq in @($ad.prerequisite)) { & $w ('<p class="hint">' + (& $h $pq) + '</p>') }
            }
            & $w ('<p class="hint">' + (& $h $ad.note) + '</p></div>')
        }
        # Seats per SKU.
        $seatRows = @($r.licensing | Where-Object { $_.purchased -gt 0 })
        if ($seatRows.Count) {
            $bars = @($seatRows | Select-Object -First 12 | ForEach-Object { '<div class="seat-row"><span class="seat-name"><code>' + (& $h $_.sku) + '</code></span><span class="seat-frac">' + $_.assigned + ' of ' + $_.purchased + '</span>' + (ConvertTo-PostureBarChart -Thin -Name $_.sku -Segment @(@{ label = 'Assigned'; value = $_.assigned; tone = 'c1' }, @{ label = 'Free'; value = $_.available; tone = 'na' })) + '</div>' }) -join ''
            $free = [int](@($seatRows | ForEach-Object { $_.available }) | Measure-Object -Sum).Sum
            & $w ('<div class="charts">' + (ConvertTo-PostureChartCard -Class 'wide' -Title 'Seats Assigned' -Takeaway "$free paid seats are not assigned to anyone." -Body ('<div class="seats">' + $bars + '</div>' + (ConvertTo-PostureChartTable -Header @('Licence', 'Purchased', 'Assigned', 'Free', 'Status') -Row @($r.licensing | ForEach-Object { , @($_.sku, $_.purchased, $_.assigned, $_.available, $_.status) })))) + '</div>')
        }
        if ($la) {
            $stLabel = @{ owned = 'Owned'; partial = 'Partly assigned'; missing = 'Not owned' }
            $stClass = @{ owned = 'pass'; partial = 'acceptedRisk'; missing = 'notApplicable' }
            & $w '<h3>Features</h3><p class="hint">Partly assigned: bought, but switched on for fewer people than hold a licence. Sometimes deliberate (Entra ID P2 for administrators only), often an oversight.</p><table><thead><tr><th>Feature</th><th>Status</th><th>What it unlocks</th></tr></thead><tbody>'
            foreach ($f in @($la.features | Sort-Object { @{ partial = 0; owned = 1; missing = 2 }[[string]$_.status] }, { $_.name })) {
                $who = $(if ($f.status -eq 'partial') { ' <span class="muted">' + $f.users + ' of ' + $f.licensedUsers + ' users</span>' } else { '' })
                & $w ('<tr><td>' + (& $h $f.name) + '</td><td><span class="status ' + $stClass[[string]$f.status] + '">' + (& $h $stLabel[[string]$f.status]) + '</span>' + $who + '</td><td>' + (& $h $f.what) + '</td></tr>')
            }
            & $w '</tbody></table>'
            $metCount = @($la.goals | Where-Object { $_.met }).Count
            & $w ('<h3>Goals <span class="count">' + $metCount + ' of ' + @($la.goals).Count + ' covered</span></h3><label class="goal-filter"><input type="checkbox" id="goals-unmet-only"> Show only goals not covered</label><div class="goal-cards">')
            foreach ($g in $la.goals) {
                $miss = $(if ($g.met) { '<p class="muted">Covered by what you hold.</p>' } else { '<p>Needs ' + (& $h (@($g.missing | ForEach-Object { @($_) -join ' or ' }) -join ', and ')) + '.</p>' })
                & $w ('<div class="goal-card ' + $(if ($g.met) { 'met' } else { 'unmet' }) + '"><span class="status-dot t-' + $(if ($g.met) { 'ok' } else { 'err' }) + '" aria-hidden="true">' + $(if ($g.met) { [string][char]0x2713 } else { [string][char]0x2715 }) + '</span><div><strong>' + (& $h $g.name) + '</strong>' + $(if ($g.core) { ' <span class="chip">core</span>' }) + '<p class="hint">' + (& $h $g.what) + '</p>' + $miss + '</div></div>')
            }
            & $w '</div>'
            if (@($la.notEvaluated).Count) {
                & $w '<h3>Checks Waiting on a Licence</h3><p class="hint">These were not evaluated because the tenant does not hold what they need.</p><ul>'
                foreach ($ne in $la.notEvaluated) { & $w ('<li><strong>Needs ' + (& $h $ne.needs) + '</strong>: ' + (@($ne.checks | ForEach-Object { '<a href="#checks" data-check="' + (& $h $_.id) + '"><code>' + (& $h $_.id) + '</code> ' + (& $h $_.title) + '</a>' }) -join '; ') + '</li>') }
                & $w '</ul>'
            }
        }
        else {
            & $w '<table><thead><tr><th>Licence (SKU)</th><th>Purchased</th><th>Assigned</th><th>Free</th><th class="tech">Status</th></tr></thead><tbody>'
            foreach ($l in $r.licensing) { & $w "<tr><td><code>$(& $h $l.sku)</code></td><td>$($l.purchased)</td><td>$($l.assigned)</td><td>$($l.available)</td><td class=`"tech`">$(& $h $l.status)</td></tr>" }
            & $w '</tbody></table>'
        }
        & $w '</section>'
    }

    # Crosswalk without a framework baseline: say how to get one, so the link does not fall back to the overview.
    if (-not $r.crosswalk) {
        & $w '<section class="view" id="crosswalk"><h2>Framework Crosswalk</h2><p class="na-panel">The crosswalk maps each control of a framework to the checks that answer it. Build the report with a framework baseline to see it, for example <code>New-PostureReport -Evidence &lt;run folder&gt; -Baseline nist-csf-2</code>. Baselines: nist-csf-2, iso-27001-2022, nist-800-171, cmmc-2, cisa-scuba, hipaa, copilot-readiness.</p></section>'
    }

    # Run health: what failed, why, and what to grant.
    & $w '<section class="view" id="health"><h2>Run Health</h2>'
    if (-not $rh -or @($rh.failures).Count -eq 0) { & $w '<p class="banner ready"><strong>Every collection step ran.</strong> Nothing to grant and nothing to collect again.</p>' }
    else {
        & $w "<p>$(@($rh.failures).Count) step(s) could not be read. Each row says why and what to do. After granting a role, collect only what failed, into the same run, then refresh this page:</p>"
        & $w "<div class=`"cmd`"><code id=`"cmd-resume`">$(& $h $rh.resume)</code><button type=`"button`" data-copy=`"cmd-resume`">Copy</button></div>"
        & $w '<table><thead><tr><th>Domain</th><th>Step</th><th>Why</th><th>What To Do</th></tr></thead><tbody>'
        foreach ($f in $rh.failures) {
            & $w "<tr class=`"cause-$(& $h $f.cause)`"><td>$(& $h $(if ($f.collector) { $f.collector } else { 'Run' }))</td><td>$(& $h $f.step)</td><td><span class=`"status fail`">$(& $h $f.causeLabel)</span></td><td>$(& $h $f.advice)<details class=`"tech`"><summary>Microsoft's message</summary><code>$(& $h $f.message)</code></details></td></tr>"
        }
        & $w '</tbody></table>'
    }
    & $w '</section>'
    & $w '<section class="view" id="appendix"><h2>Appendix</h2><table><tbody>'
    foreach ($pair in @(@('Catalog Version', $a.catalogVersion), @('Baseline', $a.baseline), @('Profile', $a.profile), @('Evidence Folder', $a.evidence), @('Collectors', ($r.collectors -join ', ')), @('Scopes', ($a.scopes -join ', ')), @('Graph API Versions', ($a.graphApiVersions -join ', ')), @('Module Version', $a.moduleVersion), @('Build', $a.build), @('Licence', $a.licence))) { & $w "<tr><th>$(& $h $pair[0])</th><td>$(& $h $pair[1])</td></tr>" }
    & $w '</tbody></table>'
    if ($a.profileAnswers) {
        & $w '<h3>Profile</h3><table><tbody>'
        foreach ($k in $a.profileAnswers.Keys) { $val = $a.profileAnswers[$k]; $text = if ($val -is [System.Collections.IDictionary]) { (@($val.Keys | ForEach-Object { "$_=$($val[$_])" }) -join '; ') } elseif ($val -is [array]) { $val -join ', ' } else { [string]$val }; & $w "<tr><th>$(& $h $k)</th><td>$(& $h $text)</td></tr>" }
        & $w '</tbody></table>'
    }
    if ($r.runAs) {
        $ra = $r.runAs
        & $w '<h3>Who Ran It</h3><table><tbody>'
        & $w "<tr><th>Account</th><td>$(& $h $ra.account)</td></tr>"
        & $w "<tr><th>Directory roles at the time</th><td>$(& $h $(if (@($ra.roles).Count) { @($ra.roles) -join ', ' } else { 'none active (PIM roles count once activated)' }))</td></tr>"
        & $w "<tr><th>Checked</th><td>$(& $fmtDate $ra.checkedUtc)</td></tr>"
        & $w '</tbody></table>'
        if (@($ra.coverage).Count) {
            & $w '<table><thead><tr><th>Domain</th><th>Role Check</th><th>Detail</th></tr></thead><tbody>'
            foreach ($c in $ra.coverage) { & $w "<tr><td>$(& $h $c.collector)</td><td>$(& $h $c.status)</td><td>$(& $h $c.detail)</td></tr>" }
            & $w '</tbody></table>'
        }
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
    & $w '<div id="toast" class="toast" role="status"></div>'
    if ($b.footer) { & $w "<footer class=`"doc`">$(& $h $b.footer)</footer>" }

    # Embedded data, then the behaviour.
    # At most 500 affected objects per check in the page; affected/<id>.csv beside the report has them all.
    & $w (& $jsonBlock 'data-results' @($r.results | ForEach-Object { [ordered]@{ id = $_.id; domain = $_.domain; title = $_.title; status = $_.status; severity = $_.severity; reason = $_.reason; affected = @($_.affected | Select-Object -First 500); affectedCount = $_.affectedCount; evidence = @($_.evidence); thresholds = $_.thresholds; observed = $(if ($_.Contains('observed')) { $_.observed } else { $null }) } }))
    & $w (& $jsonBlock 'data-catalog' $r.catalogText)
    & $w (& $jsonBlock 'data-exceptions' @($r.exceptions))
    & $w (& $jsonBlock 'data-attestations' $r.attestations)
    & $w (& $jsonBlock 'data-meta' ([ordered]@{ tenantId = $r.tenantId; clientName = $r.clientName; generatedUtc = $r.generatedUtc; licenceId = $(if ($r.licence) { $r.licence.licenceId } else { $null }) }))
    if ($r.Contains('findings') -and $r.findings) { & $w (& $jsonBlock 'tenantkeep-findings' $r.findings) }
    & $w (& $jsonBlock 'data-labels' ([ordered]@{ facts = $catLabels.facts; status = $statusLabel; domains = $domainLabel; frameworks = $frameworkLabel; methods = $methodLabel; thresholds = $thresholdLabel }))
    & $w "<script>`n$js`n</script>"
    & $w '</body></html>'
    return $sb.ToString()
}
