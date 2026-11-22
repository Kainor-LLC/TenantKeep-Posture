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
    $jsonBlock = { param([string] $Id, $Data) $json = (ConvertTo-Json -InputObject $Data -Depth 20 -Compress -EscapeHandling EscapeHtml) -replace '</', '<\/'; "<script type=`"application/json`" id=`"$Id`">$json</script>" }
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
    $js = (Get-Content -LiteralPath (Get-PostureTemplatePath -Name 'licensing.js') -Raw) + "`n" + (Get-Content -LiteralPath (Get-PostureTemplatePath -Name 'report.js') -Raw)
    $font = if ($b.font) { [string]$b.font } else { 'Inter, Helvetica, Arial, sans-serif' }
    $override = ":root { --primary: $(& $safeColor ([string]$b.colors.primary) '#1F3A5F'); --accent: $(& $safeColor ([string]$b.colors.accent) '#E8A33D'); --font: $(& $h ($font -replace '[^A-Za-z0-9 ,\-]', '')); }"

    & $w '<!DOCTYPE html>'
    & $w '<!-- For tools and AI: the ranked findings are the JSON in <script id="tenantkeep-findings"> at the end of this page (the same as findings.json beside it). Read its "about" field first. -->'
    & $w '<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
    & $w "<meta http-equiv=`"Content-Security-Policy`" content=`"default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'`">"
    & $w "<title>$(& $h $r.title)</title>"
    # The logo at the top and the icon on the browser tab. A logo in brand.json wins (an MSP's choice is never
    # overridden); then the organisation's own, from its Entra company branding (the model carries it in a paid tier
    # and never in a redacted copy); then the TenantKeep mark, but only under TenantKeep's own name: a report
    # prepared under another name and given no logo shows none, as before.
    $brandLogo = & $logoDataUri (Get-PostureValue $b 'preparedBy.logo'); if (-not $brandLogo) { $brandLogo = & $logoDataUri (Get-PostureValue $b 'client.logo') }
    $brandIcon = & $logoDataUri (Get-PostureValue $b 'preparedBy.icon')
    $ownName = [string]$b.preparedBy.name -eq 'TenantKeep Posture'
    $mark = $(if ($ownName) { & $logoDataUri (Get-PostureTemplatePath -Name 'tenantkeep-mark.png') } else { $null })
    $tenantBanner = [string]$(if ($r.Contains('tenantLogo') -and $r.tenantLogo) { $r.tenantLogo['banner'] })
    $tenantIcon = [string]$(if ($r.Contains('tenantLogo') -and $r.tenantLogo) { $r.tenantLogo['icon'] })
    $imageUri = { param([string] $u) if ($u -match '^data:image/(png|jpeg|gif|x-icon|svg\+xml|webp);base64,[A-Za-z0-9+/]+={0,2}$') { $u } else { $null } }
    $logo = $null; $logoClass = 'logo'; $logoAlt = ''
    if ($brandLogo) { $logo = $brandLogo; $logoClass = 'logo plate'; $logoAlt = "$([string]$b.preparedBy.name) logo" }
    elseif (& $imageUri $tenantBanner) { $logo = $tenantBanner; $logoClass = 'logo plate'; $logoAlt = "$([string]$r.clientName) logo" }
    elseif ($mark) { $logo = $mark; $logoClass = 'logo mark'; $logoAlt = 'TenantKeep' }
    $icon = @($brandIcon, $brandLogo, (& $imageUri $tenantIcon), $mark | Where-Object { $_ }) | Select-Object -First 1
    if ($icon) { & $w "<link rel=`"icon`" href=`"$icon`">" }
    & $w "<style>`n$css`n$override`n</style></head>"
    & $w "<body data-template=`"$(& $h $r.template)`">"

    # Header and toolbar
    & $w '<header class="doc"><div>'
    if ($logo) { & $w "<img class=`"$logoClass`" alt=`"$(& $h $logoAlt)`" src=`"$logo`">" }
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
    $viewList = @(@('overview', 'Overview', $true), @('recommendations', 'Recommendations', $true), @('domains', 'Domains', $true), @('checks', 'Checks Explorer', $true), @('admins', 'Your Administrators', $true), @('exposure', 'External Exposure', $false), @('copilot', 'Copilot Readiness', [bool]($r.copilot -and $r.copilot.present)), @('ca', 'Conditional Access', [bool]$r.ca), @('inventory', 'Inventory', [bool]($r.Contains('inventory') -and @($r.inventory | Where-Object { $_.total -gt 0 }).Count)), @('crosswalk', 'Crosswalk', [bool]$r.crosswalk), @('attack', 'ATT&CK Coverage', [bool]($r.Contains('attack') -and $r.attack)), @('trend', 'Trend', [bool]$r.trend), @('licensing', 'Licensing', [bool]$r.licensing), @('health', 'Run Health', $true), @('appendix', 'Appendix', $true))
    & $w '<nav class="views" aria-label="Views">'
    foreach ($vw in $viewList) { & $w "<a href=`"#$($vw[0])`"$(if (-not $vw[2]) { ' class="na"' })>$(& $h $vw[1])</a>" }
    & $w '</nav><main>'

    # Overview
    & $w '<section class="view active" id="overview"><h2>Overview</h2>'
    $rh = $r.runHealth
    if ($rh -and $rh.Contains('notFinished') -and @($rh.notFinished).Count -gt 0) {
        & $w "<div class=`"banner warn`"><strong>The collection stopped before the end.</strong> $(& $h (@($rh.notFinished) -join ', ')) did not finish, and the checks that depend on them say not evaluated. <a href=`"#health`">Run Health</a> has the command that collects only what is missing.</div>"
    }
    if ($rh -and @($rh.failures).Count -gt 0) {
        $parts = @($rh.byCause.Keys | ForEach-Object { "$($rh.byCause[$_]) $($_.ToLowerInvariant())" }) -join ', '
        & $w "<div class=`"banner warn`"><strong>$(@($rh.failures).Count) step(s) could not be read</strong> ($(& $h $parts)). The checks that depend on them say not evaluated. <a href=`"#health`">Run Health</a> says why for each$(if (@($rh.failures | Where-Object { [string]$_.cause -in 'permission', 'token', 'throttled', 'network', 'module', 'unknown' }).Count -gt 0) { ', what to grant, and how to collect just those again' } else { '; none of them is fixed by collecting again' }).</div>"
    }
    # What the assessment still lacks, each piece with who can add it and how. The rows are data (the completion
    # block of checks/catalog.json through Get-PostureCompletion); nothing here knows a check or a collector.
    $todo = @($(if ($r.Contains('completion')) { $r.completion }))
    if ($todo.Count -gt 0) {
        & $w '<details class="complete" open><summary><strong>To Complete This Assessment</strong></summary>'
        & $w "<p class=`"hint`">$($todo.Count) piece$(if ($todo.Count -ne 1) { 's are' } else { ' is' }) not in this run. The checks that wait for each say not evaluated; nothing is guessed. Each row says who can add it and how.</p>"
        & $w '<table><thead><tr><th>What Is Missing</th><th>Checks Waiting</th><th>Who</th><th>Where</th><th>How</th></tr></thead><tbody>'
        $n = 0
        foreach ($t in $todo) {
            $n++
            $what = (& $h $t.title) + $(if ($t.note) { '<br><span class="hint">' + (& $h $t.note) + '</span>' } else { '' })
            $how = '<div class="cmd"><code id="cmd-complete-' + $n + '">' + (& $h $t.get) + '</code><button type="button" data-copy="cmd-complete-' + $n + '">Copy</button></div>' + $(if ($t.bring) { '<span class="hint">Then: ' + (& $h $t.bring) + '</span>' } else { '' })
            & $w ('<tr><td>' + $what + '</td><td>' + $(if ($null -ne $t.checks) { [string]$t.checks } else { '' }) + '</td><td>' + (& $h $t.who) + '</td><td>' + (& $h $t.where) + '</td><td>' + $how + '</td></tr>')
        }
        & $w '</tbody></table></details>'
    }
    # The score as a ring with its change, target and projection; its history; open findings by severity; the attack
    # path; the accepted-risk ledger.
    $st = $(if ($r.Contains('story') -and $r.story) { $r.story } else { [ordered]@{} })
    $delta = $(if ($r.trend) { $r.trend.scoreDelta } elseif ($st.Contains('history') -and @($st.history).Count -ge 2) { @($st.history)[-1].value - @($st.history)[-2].value } else { $null })
    $storyCards = @()
    $proj = $(if ($st.Contains('projected')) { $st.projected } else { $null })
    $storyCards += ConvertTo-PostureChartCard -Title 'Posture Score' -Takeaway "$($r.score.value) of 100, grade $($r.score.grade).$(if ($null -ne $proj -and $proj -gt $r.score.value) { " Fixing the top five recommendations brings it to $proj." })" -Body ((ConvertTo-PostureScoreRing -Value $r.score.value -Delta $delta -Projected $proj -Grade $r.score.grade) + '<p class="hint">' + (& $h "$($r.score.method) $($r.score.evaluated) checks scored.") + '</p>')
    if ($st.Contains('history') -and @($st.history).Count -ge 2) {
        $first = @($st.history)[0].value; $lastV = @($st.history)[-1].value
        $storyCards += ConvertTo-PostureChartCard -Title 'Score Over Time' -Takeaway "From $first to $lastV over $(@($st.history).Count) runs." -Body (ConvertTo-PostureLineChart -Name 'Posture score by run' -Percent -Point @($st.history))
    }
    $sevOpen = @('Critical', 'High', 'Medium', 'Low' | ForEach-Object { $sv = $_; [ordered]@{ label = $sv; value = @($r.results | Where-Object { $_.status -eq 'fail' -and $_.severity -eq $sv }).Count; tone = @{ Critical = 'err'; High = 'warn'; Medium = 'c1'; Low = 'na' }[$sv] } })
    $storyCards += ConvertTo-PostureChartCard -Title 'Open Findings by Severity' -Takeaway "$(@($sevOpen)[0].value) critical and $(@($sevOpen)[1].value) high findings are open." -Body (ConvertTo-PostureRankedBarChart -Name 'Open findings by severity' -KeepOrder -Item $sevOpen) -ViewAllLabel 'Go to Recommendations'
    if ($st.Contains('funnel') -and $st.funnel) { $storyCards += ConvertTo-PostureChartCard -Title 'Attack Path: Phishing to Admin' -Takeaway $st.funnel.takeaway -ViewAllDomain 'auth' -Body (ConvertTo-PostureRankedBarChart -Name 'Attack path' -KeepOrder -Item @($st.funnel.steps | ForEach-Object { [ordered]@{ label = $_.label; value = $_.value; tone = 'err' } })) }
    if ($st.Contains('ledger') -and $st.ledger) { $storyCards += ConvertTo-PostureChartCard -Title 'Accepted Risks by Expiry' -Takeaway "$($st.ledger.total) accepted risk(s); $($st.ledger.buckets['Expired']) expired and $($st.ledger.buckets['Within 30 days']) expire within 30 days." -Body (ConvertTo-PostureRankedBarChart -Name 'Accepted risks by expiry' -KeepOrder -Item @($st.ledger.buckets.Keys | ForEach-Object { [ordered]@{ label = $_; value = $st.ledger.buckets[$_]; tone = $(if ($_ -eq 'Expired') { 'err' } elseif ($_ -eq 'Within 30 days') { 'warn' } else { 'c1' }) } })) }
    & $w ('<div class="charts story">' + ($storyCards -join '') + '</div>')
    # Outcomes a board asks about, each a score with its trend across runs.
    if ($st.Contains('outcomes') -and @($st.outcomes).Count) {
        $oc = @($st.outcomes | ForEach-Object {
                $tone = $(if ($_.score -ge 80) { 'ok' } elseif ($_.score -ge 60) { 'warn' } else { 'err' })
                $prev = $(if (@($_.trend).Count -ge 2) { @($_.trend)[-2] } else { $null })
                $chg = $(if ($null -eq $prev) { '' } elseif ($_.score -gt $prev) { "+$($_.score - $prev) since the last run" } elseif ($_.score -lt $prev) { "$($_.score - $prev) since the last run" } else { 'no change since the last run' })
                '<div class="outcome"><div class="outcome-head"><span class="outcome-name">' + (& $h $_.name) + '</span><span class="status-dot t-' + $tone + '" aria-hidden="true">' + $(if ($tone -eq 'ok') { [string][char]0x2713 } elseif ($tone -eq 'warn') { '!' } else { [string][char]0x2715 }) + '</span></div><div class="outcome-score"><span class="n">' + $_.score + '</span><span class="muted">of 100, target 80</span>' + (ConvertTo-PostureSparkline -Name $_.name -Value @($_.trend)) + '</div><p class="hint">' + (& $h $_.what) + '</p><p class="hint">' + $(if (@($_.failing).Count) { @($_.failing).Count.ToString() + ' failing: ' + (@($_.failing | Select-Object -First 4 | ForEach-Object { '<a href="#rec-' + (& $h $_.id) + '">' + (& $h $_.id) + '</a>' }) -join ', ') } else { 'Every check passes.' }) + $(if ($chg) { ' <span class="muted">' + (& $h $chg) + '</span>' }) + '</p></div>'
            }) -join ''
        & $w ('<h3>Outcomes</h3><div class="outcomes">' + $oc + '</div>')
    }
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
    # Defence in depth: each layer set as rings, in a row of their own (they are one kind of card and one height).
    $layerCards = @()
    foreach ($ls in @($(if ($r.Contains('layers')) { $r.layers }))) { $layerCards += ConvertTo-PostureChartCard -Title $ls.name -Takeaway $ls.takeaway -ViewAllDomain $ls.domain -Body (ConvertTo-PostureRingChart -Name $ls.name -Layer $ls.layers) }
    $c0 = $r.counts
    $overviewCharts += ConvertTo-PostureChartCard -Title 'Check Results' -Takeaway "$($c0.pass) of $([int]$c0.pass + [int]$c0.fail + [int]$c0.acceptedRisk + [int]$c0.coveredBy) evaluated checks pass; $($c0.notEvaluated) could not be evaluated." -Body (ConvertTo-PostureBarChart -Name 'Check results' -Segment @(@{ label = 'Pass'; value = $c0.pass; tone = 'ok' }, @{ label = 'Fail'; value = $c0.fail; tone = 'err' }, @{ label = 'Accepted or covered'; value = ([int]$c0.acceptedRisk + [int]$c0.coveredBy); tone = 'c1' }, @{ label = 'Not evaluated'; value = $c0.notEvaluated; tone = 'na' }))
    & $w ('<div class="charts">' + ($overviewCharts -join '') + '</div>')
    if (@($layerCards).Count) { & $w ('<h3>Defence in Depth</h3><div class="charts">' + ($layerCards -join '') + '</div>') }
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
    $areas = [ordered]@{ Identity = @(); Access = @(); Devices = @(); Endpoint = @(); Email = @(); 'Collaboration and Data' = @(); Operations = @(); 'User Experience' = @(); 'Network Access' = @(); Azure = @(); Hybrid = @() }
    if ($ch.Contains('authUsers')) { $areas.Identity += ConvertTo-PostureChartCard -Class 'wide' -Title 'Members by Sign-in Method' -Takeaway $ch.authUsers.takeaway -ViewAllDomain 'auth' -Body (ConvertTo-PostureSankeyChart -Name 'Members by strongest sign-in method' -Column $ch.authUsers.column -Flow $ch.authUsers.flow) }
    if ($ch.Contains('authAdmins')) { $areas.Identity += ConvertTo-PostureChartCard -Title 'Administrators by Sign-in Strength' -Takeaway $ch.authAdmins.takeaway -ViewAllDomain 'identity' -Body (ConvertTo-PostureDonutChart -Name 'Administrators by strongest method' -CenterLabel 'admins' -Segment $ch.authAdmins.segment) }
    if ($ch.Contains('signInCa')) { $areas.Access += ConvertTo-PostureChartCard -Class 'wide' -Title 'Sign-ins Through Conditional Access' -Takeaway $ch.signInCa.takeaway -ViewAllDomain 'ca' -Body (ConvertTo-PostureSankeyChart -Name 'Successful sign-ins by Conditional Access and MFA' -Height 200 -Column $ch.signInCa.column -Flow $ch.signInCa.flow) }
    if ($ch.Contains('signInDevice')) { $areas.Access += ConvertTo-PostureChartCard -Class 'wide' -Title 'Sign-ins by Device Trust' -Takeaway $ch.signInDevice.takeaway -ViewAllDomain 'devices' -Body (ConvertTo-PostureSankeyChart -Name 'Successful sign-ins by device' -Height 200 -Column $ch.signInDevice.column -Flow $ch.signInDevice.flow) }
    if ($ch.Contains('devices')) { $areas.Devices += ConvertTo-PostureChartCard -Class 'wide' -Title 'Managed Devices by Platform, Join Type and Compliance' -Takeaway $ch.devices.takeaway -ViewAllDomain 'devices' -Body (ConvertTo-PostureSankeyChart -Name 'Managed devices' -Column $ch.devices.column -Flow $ch.devices.flow) }
    if ($ch.Contains('compliance')) { $areas.Devices += ConvertTo-PostureChartCard -Title 'Device Compliance' -Takeaway $ch.compliance.takeaway -ViewAllDomain 'devices' -Body (ConvertTo-PostureDonutChart -Name 'Device compliance' -CenterLabel 'devices' -Segment $ch.compliance.segment) }
    if ($ch.Contains('ownership')) { $areas.Devices += ConvertTo-PostureChartCard -Title 'Device Ownership' -Takeaway $ch.ownership.takeaway -ViewAllDomain 'devices' -Body (ConvertTo-PostureDonutChart -Name 'Device ownership' -CenterLabel 'devices' -Segment $ch.ownership.segment) }
    if ($ch.Contains('deviceManagement')) { $areas.Devices += ConvertTo-PostureChartCard -Title 'Windows Devices by Who Manages Them' -Takeaway $ch.deviceManagement.takeaway -ViewAllDomain 'devices' -Body (ConvertTo-PostureDonutChart -Name 'Windows devices by management' -CenterLabel 'Windows' -Segment $ch.deviceManagement.segment) }
    if ($ch.Contains('coManagement')) {
        $rowsHtml = @($ch.coManagement.rows | ForEach-Object { '<div class="pillar"><span class="name">' + (& $h $_.label) + '</span><span class="frac">' + $_.onIntune + ' of ' + ($_.onIntune + $_.onConfigMgr) + ' on Intune</span>' + (ConvertTo-PostureBarChart -Thin -Name $_.label -Segment @(@{ label = 'On Intune'; value = $_.onIntune; tone = 'ok' }, @{ label = 'On Configuration Manager'; value = $_.onConfigMgr; tone = 'warn' })) + '</div>' }) -join ''
        $areas.Devices += ConvertTo-PostureChartCard -Class 'wide' -Title 'Co-management Workloads' -Takeaway $ch.coManagement.takeaway -ViewAllDomain 'devices' -Body ('<div class="pillars">' + $rowsHtml + '</div>' + (ConvertTo-PostureChartLegend -Item @(@{ label = 'On Intune'; tone = 'ok' }, @{ label = 'On Configuration Manager'; tone = 'warn' })))
    }
    if ($ch.Contains('macCompliance')) { $areas.Devices += ConvertTo-PostureChartCard -Title 'Macs on a Partner MDM' -Takeaway $ch.macCompliance.takeaway -ViewAllDomain 'devices' -Body (ConvertTo-PostureDonutChart -Name 'Macs by compliance in Entra' -CenterLabel 'Macs' -Segment $ch.macCompliance.segment) }
    if ($ch.Contains('antivirus')) { $areas.Devices += ConvertTo-PostureChartCard -Title 'Defender Antivirus Mode' -Takeaway $ch.antivirus.takeaway -ViewAllDomain 'endpoint' -Body (ConvertTo-PostureDonutChart -Name 'Defender Antivirus mode' -CenterLabel 'devices' -Segment $ch.antivirus.segment) }
    $rank = { param([string] $Title, [string] $Key, [string] $Domain, [switch] $Keep) if ($ch.Contains($Key)) { ConvertTo-PostureChartCard -Title $Title -Takeaway $ch[$Key].takeaway -ViewAllDomain $Domain -Body (ConvertTo-PostureRankedBarChart -Name $Title -KeepOrder:$Keep -Item @($ch[$Key].item)) } }
    $roleSec = @($(if ($r.Contains('inventory')) { $r.inventory | Where-Object { $_.key -eq 'roles' -and $_.total -gt 0 } }))
    if ($roleSec.Count) {
        $rows = @($roleSec[0].rows | Select-Object -First 8)
        $body = '<div class="seats">' + (@($rows | ForEach-Object { '<div class="seat-row"><span class="seat-name">' + (& $h $_.Role) + '</span><span class="seat-frac">' + $_.Permanent + ' permanent, ' + $_.Eligible + ' eligible</span>' + (ConvertTo-PostureBarChart -Thin -Name $_.Role -Segment @(@{ label = 'Permanent'; value = [int]$_.Permanent; tone = 'err' }, @{ label = 'Activated now'; value = [int]$_.'Activated now'; tone = 'warn' }, @{ label = 'Eligible'; value = [int]$_.Eligible; tone = 'ok' })) + '</div>' }) -join '') + '</div>' + (ConvertTo-PostureChartLegend -Item @(@{ label = 'Permanent'; tone = 'err' }, @{ label = 'Activated now'; tone = 'warn' }, @{ label = 'Eligible through PIM'; tone = 'ok' }))
        $perm = [int](@($roleSec[0].rows | ForEach-Object { [int]$_.Permanent }) | Measure-Object -Sum).Sum
        $areas.Identity += ConvertTo-PostureChartCard -Title 'Privileged Roles' -Takeaway "$perm permanent privileged assignment(s); eligible ones are activated when needed." -ViewAllDomain 'identity' -Body $body
    }
    if ($ch.Contains('identitySource') -and @($ch.identitySource.rows).Count) {
        $legendItems = @(@{ label = 'Managed in AD'; tone = 'c3' }, @{ label = 'Moved from AD to Entra'; tone = 'c2' }, @{ label = 'Created in Entra'; tone = 'c1' })
        $rowsHtml = @($ch.identitySource.rows | ForEach-Object { $tot = [int](($_.segment | ForEach-Object { $_.value } | Measure-Object -Sum).Sum); '<div class="pillar"><span class="name">' + (& $h $_.label) + '</span><span class="frac">' + $tot + '</span>' + (ConvertTo-PostureBarChart -Thin -Name $_.label -Segment $_.segment) + '</div>' }) -join ''
        $areas.Identity += ConvertTo-PostureChartCard -Title 'Who Manages Users and Groups' -Takeaway $ch.identitySource.takeaway -ViewAllDomain 'hybrid' -Body ('<div class="pillars">' + $rowsHtml + '</div>' + (ConvertTo-PostureChartLegend -Item $legendItems))
    }
    $areas.Identity += & $rank 'Guests by Last Sign-in' 'guestAge' 'identity' -Keep
    $areas.Identity += & $rank 'Risky Users' 'riskyUsers' 'identity' -Keep
    if ($ch.Contains('signInsByDay')) { $areas.Access += ConvertTo-PostureChartCard -Title 'Sign-ins by Day' -Takeaway $ch.signInsByDay.takeaway -ViewAllDomain 'identity' -Body (ConvertTo-PostureLineChart -Name 'Sign-ins by day' -Point @($ch.signInsByDay.point)) }
    $areas.Access += & $rank 'Sign-ins by Country' 'signInCountries' 'ca'
    $areas.Access += & $rank 'Failed Sign-ins by Error' 'signInFailures' 'identity'
    $areas.Devices += & $rank 'Windows Builds' 'windowsBuilds' 'devices'
    if ($ch.Contains('encryption')) { $areas.Devices += ConvertTo-PostureChartCard -Title 'Disk Encryption' -Takeaway $ch.encryption.takeaway -ViewAllDomain 'devices' -Body (ConvertTo-PostureDonutChart -Name 'Disk encryption' -CenterLabel 'devices' -Segment $ch.encryption.segment) }
    $areas.Devices += & $rank 'Last Check-in' 'checkIn' 'devices' -Keep
    if ($ch.Contains('asr')) { $areas.Endpoint += ConvertTo-PostureChartCard -Title 'Attack Surface Reduction Rules' -Takeaway $ch.asr.takeaway -ViewAllDomain 'endpoint' -Body (ConvertTo-PostureBarChart -Name 'ASR rules by mode' -Segment $ch.asr.segment) }
    $areas.Endpoint += & $rank 'Critical Vulnerabilities' 'vulnerabilities' 'endpoint' -Keep
    if ($ch.Contains('incidentsWeekly')) { $areas.Endpoint += ConvertTo-PostureChartCard -Title 'Defender Incidents per Week' -Takeaway $ch.incidentsWeekly.takeaway -ViewAllDomain 'endpoint' -Body (ConvertTo-PostureLineChart -Name 'Defender incidents per week' -Point @($ch.incidentsWeekly.point)) }
    $mailSec = @($(if ($r.Contains('inventory')) { $r.inventory | Where-Object { $_.key -eq 'mail-domains' -and $_.total -gt 0 } }))
    if ($mailSec.Count) {
        $toneOf = { param([string] $col, [string] $val) switch -Regex ($val) { '^(on|hard fail.*|reject|published|Microsoft.*)$' { 'ok' } '^(soft fail.*|quarantine)$' { 'warn' } '^(not read)$' { 'na' } default { 'err' } } }
        $cols = @('DKIM', 'SPF', 'DMARC', 'MTA-STS')
        $grid = '<div class="scroll"><table class="mailgrid"><thead><tr><th>Domain</th>' + (@($cols | ForEach-Object { '<th>' + $_ + '</th>' }) -join '') + '</tr></thead><tbody>' + (@($mailSec[0].rows | Where-Object { $_.Domain -notlike '*.onmicrosoft.com' } | ForEach-Object { $row = $_; '<tr><td>' + (& $h $row.Domain) + '</td>' + (@($cols | ForEach-Object { $t = & $toneOf $_ ([string]$row[$_]); '<td><span class="cell t-' + $t + '"><span class="status-dot t-' + $t + '" aria-hidden="true">' + $(switch ($t) { 'ok' { [string][char]0x2713 } 'warn' { '!' } 'na' { [string][char]0x2013 } default { [string][char]0x2715 } }) + '</span>' + (& $h $row[$_]) + '</span></td>' }) -join '') + '</tr>' }) -join '') + '</tbody></table></div>'
        $gaps = @($mailSec[0].rows | Where-Object { $_.Domain -notlike '*.onmicrosoft.com' -and ($_.DMARC -notin 'reject', 'quarantine' -or $_.DKIM -ne 'on' -or $_.SPF -notlike 'hard fail*') }).Count
        $areas.Email += ConvertTo-PostureChartCard -Class 'wide' -Title 'Email Authentication by Domain' -Takeaway "$gaps custom domain(s) short of DKIM on, SPF hard fail and DMARC at quarantine or reject." -ViewAllDomain 'email' -Body $grid
    }
    $areas.'Collaboration and Data' += & $rank 'Sites by Sharing Level' 'siteSharing' 'collaboration' -Keep
    if ($ch.Contains('sensitivityExposure')) { $se = $ch.sensitivityExposure; $areas.'Collaboration and Data' += ConvertTo-PostureChartCard -Class 'wide' -Title 'Sensitivity Against Exposure' -Takeaway $se.takeaway -ViewAllDomain 'collaboration' -Body (ConvertTo-PostureHeatmap -Name 'Sites by sensitivity label and sharing level' -Row @($se.rows) -Column @($se.columns) -Cell $se.cells) }
    if ($ch.Contains('topExposed')) {
        $te = @($ch.topExposed.sites)
        $body = '<div class="seats">' + (@($te | ForEach-Object { $tot = $_.anyone + $_.org + $_.eeeu + $_.everyone; '<div class="seat-row"><span class="seat-name">' + (& $h $_.name) + '</span><span class="seat-frac">' + $tot + '</span>' + (ConvertTo-PostureBarChart -Thin -Name $_.name -Segment @(@{ label = 'Anyone links'; value = $_.anyone; tone = 'err' }, @{ label = 'Organisation-wide links'; value = $_.org; tone = 'warn' }, @{ label = 'Everyone except external users'; value = $_.eeeu; tone = 'c1' }, @{ label = 'Everyone'; value = $_.everyone; tone = 'c5' })) + '</div>' }) -join '') + '</div>' + (ConvertTo-PostureChartLegend -Item @(@{ label = 'Anyone links'; tone = 'err' }, @{ label = 'Organisation-wide links'; tone = 'warn' }, @{ label = 'Everyone except external users'; tone = 'c1' }, @{ label = 'Everyone'; tone = 'c5' })) + (ConvertTo-PostureChartTable -Header @('Site', 'Anyone links', 'Organisation-wide links', 'Everyone except external', 'Everyone') -Row @($te | ForEach-Object { , @($_.name, $_.anyone, $_.org, $_.eeeu, $_.everyone) }))
        $areas.'Collaboration and Data' += ConvertTo-PostureChartCard -Class 'wide' -Title 'Most Exposed Sites' -Takeaway $ch.topExposed.takeaway -ViewAllDomain 'collaboration' -Body $body
    }
    $areas.'Collaboration and Data' += & $rank 'DLP Policies by Mode' 'dlpModes' 'purview' -Keep
    $areas.Operations += & $rank 'Secure Score Against Averages' 'secureScore' 'operations' -Keep
    if ($ch.Contains('secureScoreCategories')) {
        $rowsHtml = @($ch.secureScoreCategories.rows | ForEach-Object { '<div class="pillar"><span class="name">' + (& $h $_.label) + '</span><span class="frac">' + $_.earned + ' of ' + ($_.earned + $_.available) + '</span>' + (ConvertTo-PostureBarChart -Thin -Name $_.label -Segment @(@{ label = 'Earned'; value = $_.earned; tone = 'ok' }, @{ label = 'Available'; value = $_.available; tone = 'na' })) + '</div>' }) -join ''
        $areas.Operations += ConvertTo-PostureChartCard -Title 'Secure Score by Category' -Takeaway $ch.secureScoreCategories.takeaway -ViewAllDomain 'operations' -Body ('<div class="pillars">' + $rowsHtml + '</div>' + (ConvertTo-PostureChartLegend -Item @(@{ label = 'Earned'; tone = 'ok' }, @{ label = 'Available'; tone = 'na' })))
    }
    if ($ch.Contains('secureScoreActions')) {
        $tbl = '<table><thead><tr><th>Action</th><th>Category</th><th>Points</th><th>Cost</th><th>User Impact</th></tr></thead><tbody>' + (@($ch.secureScoreActions.rows | ForEach-Object { '<tr><td>' + $(if ($_.url) { '<a href="' + (& $h $_.url) + '" target="_blank" rel="noopener">' + (& $h $_.title) + '</a>' } else { & $h $_.title }) + '</td><td>' + (& $h $_.category) + '</td><td>' + $_.points + '</td><td>' + (& $h $_.cost) + '</td><td>' + (& $h $_.userImpact) + '</td></tr>' }) -join '') + '</tbody></table>'
        $areas.Operations += ConvertTo-PostureChartCard -Class 'wide' -Title 'Top Secure Score Improvements' -Takeaway $ch.secureScoreActions.takeaway -ViewAllDomain 'operations' -Body $tbl
    }
    # Journeys: each a strip of steps, a step on, off or not known with the check behind it.
    $dot = @{ on = @('ok', [string][char]0x2713); off = @('err', [string][char]0x2715); unknown = @('na', [string][char]0x2013) }
    foreach ($j in @($(if ($r.Contains('journeys')) { $r.journeys }))) {
        $stepsHtml = @($j.steps | ForEach-Object { '<li class="step ' + $_.state + '"><a href="#checks" data-check="' + (& $h $_.check) + '" title="' + (& $h "$($_.check): $($statusLabel[[string]$_.status])") + '"><span class="status-dot t-' + $dot[$_.state][0] + '" aria-hidden="true">' + $dot[$_.state][1] + '</span><span class="label">' + (& $h $_.label) + '</span></a></li>' }) -join ''
        $areas['User Experience'] += ConvertTo-PostureChartCard -Class 'wide' -Title $j.name -Takeaway $(if ($j.known -eq 0) { "Not read yet: the next collection fills these steps in. $($j.why)" } else { "$($j.on) of $(@($j.steps).Count) steps work on their own$(if ($j.known -lt @($j.steps).Count) { "; $(@($j.steps).Count - $j.known) not read yet" }). $($j.why)" }) -ViewAllDomain $j.domain -Body ('<ol class="journey">' + $stepsHtml + '</ol>')
    }
    $statusList = { param($rows, [scriptblock] $IsGood) '<ul class="status-list">' + (@($rows | ForEach-Object { $good = & $IsGood $_; '<li><span class="status-dot t-' + $(if ($good) { 'ok' } else { 'err' }) + '" aria-hidden="true">' + $(if ($good) { [string][char]0x2713 } else { [string][char]0x2715 }) + '</span><span>' + (& $h $_.label) + $(if ($_.Contains('value')) { ' <strong>' + $_.value + '</strong>' }) + ' <span class="muted">' + (& $h $_.detail) + '</span></span></li>' }) -join '') + '</ul>' }
    if ($ch.Contains('networkProfiles')) { $areas['Network Access'] += ConvertTo-PostureChartCard -Title 'Global Secure Access' -Takeaway $ch.networkProfiles.takeaway -ViewAllDomain 'network' -Body (& $statusList $ch.networkProfiles.rows { param($x) $x.on }) }
    if ($ch.Contains('privilegedGroups')) { $areas.Hybrid += ConvertTo-PostureChartCard -Title 'Privileged Group Members' -Takeaway $ch.privilegedGroups.takeaway -ViewAllDomain 'hybrid' -Body (ConvertTo-PostureRankedBarChart -Name 'Privileged group members' -Item @($ch.privilegedGroups.item)) }
    if ($ch.Contains('keyAges')) { $areas.Hybrid += ConvertTo-PostureChartCard -Title 'Key Ages' -Takeaway $ch.keyAges.takeaway -ViewAllDomain 'hybrid' -Body (ConvertTo-PostureRankedBarChart -Name 'Key ages' -KeepOrder -ValueSuffix ' days' -Item @($ch.keyAges.item)) }
    if ($ch.Contains('adExposure') -and @($ch.adExposure.rows).Count) { $areas.Hybrid += ConvertTo-PostureChartCard -Title 'Active Directory Exposure' -Takeaway $ch.adExposure.takeaway -ViewAllDomain 'hybrid' -Body (& $statusList $ch.adExposure.rows { param($x) [int]$x.value -eq 0 }) }
    if ($ch.Contains('azureSecureScore')) { $areas.Azure += ConvertTo-PostureChartCard -Title 'Defender for Cloud Secure Score' -Takeaway $ch.azureSecureScore.takeaway -ViewAllDomain 'azure' -Body (ConvertTo-PostureRankedBarChart -Name 'Defender for Cloud secure score' -ValueSuffix '%' -Item @($ch.azureSecureScore.item)) }
    if ($ch.Contains('azureRecommendations')) { $areas.Azure += ConvertTo-PostureChartCard -Title 'Open Recommendations by Severity' -Takeaway $ch.azureRecommendations.takeaway -ViewAllDomain 'azure' -Body (ConvertTo-PostureBarChart -Name 'Open Defender for Cloud recommendations' -Segment $ch.azureRecommendations.segment) }
    if ($ch.Contains('azureTopRecommendations')) {
        $tbl = '<table><thead><tr><th>Recommendation</th><th>Severity</th><th>Resources</th></tr></thead><tbody>' + (@($ch.azureTopRecommendations.rows | ForEach-Object { '<tr><td>' + (& $h $_.title) + '</td><td><span class="sev ' + (& $h $_.severity) + '">' + (& $h $_.severity) + '</span></td><td>' + $_.affected + '</td></tr>' }) -join '') + '</tbody></table><p class="hint"><a href="https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/5" target="_blank" rel="noopener">Each recommendation and its fix steps in Defender for Cloud</a></p>'
        $areas.Azure += ConvertTo-PostureChartCard -Class 'wide' -Title 'Top Defender for Cloud Recommendations' -Takeaway 'The recommendations affecting the most resources.' -ViewAllDomain 'azure' -Body $tbl
    }
    foreach ($a in @($areas.Keys)) { $areas[$a] = @($areas[$a] | Where-Object { $_ }) }
    # The tab opens on the scorecards; the charts follow, a section for each domain, folded until asked for (forty
    # charts at once is a long scroll). Written after the cards below.
    & $w '<div class="cards">'
    foreach ($d in $r.domains) {
        # When a domain's evidence was read apart from the run (Active Directory), the card says when.
        $evidenceNote = $(if ($d.Contains('evidenceNote') -and $d.evidenceNote) { '<p class="hint">' + (& $h $d.evidenceNote) + '</p>' } else { '' })
        & $w "<div class=`"card`"><h3>$(& $h $d.label)</h3><div><strong data-domain-score=`"$(& $h $d.key)`">$(& $num $d.score)</strong> <span class=`"tech`">$($d.counts.pass) pass, $($d.counts.fail) fail, $($d.counts.acceptedRisk) accepted, $($d.counts.coveredBy) covered, $($d.counts.notEvaluated) not evaluated</span></div><div class=`"bar`"><i style=`"width:$(if ($null -ne $d.score) { $d.score } else { 0 })%`"></i></div><p>$(& $h $d.narrative)</p>$evidenceNote</div>"
    }
    foreach ($d in $r.domainsNotCollected) { & $w "<div class=`"card na`"><h3>$(& $h $d.label)</h3><p>Not collected yet.$(if ($d.reason) { " $(& $h $d.reason)" })</p></div>" }
    & $w '</div>'
    $withCharts = @($areas.Keys | Where-Object { @($areas[$_]).Count })
    if ($withCharts.Count) {
        # The button opens or folds every section; printing opens them all, and so does ?areas=open (report.js).
        & $w '<div class="area-head"><h3>Charts by Domain</h3><button type="button" class="fold-toggle" data-fold="details.area" aria-expanded="false">Open all</button></div>'
        foreach ($a in $withCharts) {
            $n = @($areas[$a]).Count
            & $w ('<details class="area"><summary><span class="area-name">' + (& $h $a) + '</span><span class="hint">' + "$n chart$(if ($n -ne 1) { 's' })" + '</span></summary><div class="charts">' + (@($areas[$a]) -join '') + '</div></details>')
        }
    }
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
        if ($tr.catalogChanged) { & $w "<p class=`"hint`">The check catalog changed between these runs ($(& $h $tr.catalogBefore) to $(& $h $tr.catalogAfter)), so the two scores are not measured the same way. $(& $h (@($tr.catalogNotes) -join ' '))</p>" }
        foreach ($pair in @(@('Started failing', $tr.newFailures), @('Resolved', $tr.resolved))) {
            if (@($pair[1]).Count -eq 0) { continue }
            & $w "<h3>$($pair[0])</h3><ul>"
            foreach ($x in $pair[1]) { & $w "<li><strong>$(& $h $x.id)</strong> $(& $h $x.title) <span class=`"muted`">($(& $h $x.severity), $(& $h $x.detail))</span></li>" }
            & $w '</ul>'
        }
        if (@($tr.logicChanged).Count -gt 0) {
            & $w '<h3>Changed with the catalog</h3><p class="hint">The check changed between the two runs. These are not new failures or fixes in the tenant.</p><ul>'
            foreach ($x in $tr.logicChanged) { & $w "<li><strong>$(& $h $x.id)</strong> $(& $h $x.title) <span class=`"muted`">($(& $h $x.before) to $(& $h $x.after))</span><br>$(& $h $x.detail)</li>" }
            & $w '</ul>'
        }
        if (@($tr.lostAnswer).Count -gt 0) {
            & $w '<h3>No answer in this run</h3><p class="hint">These had a pass or a fail before and could not be judged this time. That is neither a fix nor a failure.</p><ul>'
            foreach ($x in $tr.lostAnswer) { & $w "<li><strong>$(& $h $x.id)</strong> $(& $h $x.title) <span class=`"muted`">(was $(& $h $x.was))</span><br>$(& $h $x.detail)</li>" }
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
    # Quick wins: open findings by effort and by what users will notice; then the roadmap in 30, 60, 90 day lanes.
    if ($r.Contains('story') -and $r.story -and $r.story.quickWins) {
        $qw = $r.story.quickWins
        $impLabel = [ordered]@{ none = 'Users notice nothing'; low = 'Users barely notice'; medium = 'Users notice'; high = 'Big change for users' }
        $efLabel = [ordered]@{ S = 'Quick fix'; M = 'Planned change'; L = 'Project' }
        $cells = '<div class="qw-grid" role="table" aria-label="Open findings by effort and user impact"><div class="qw-corner" role="columnheader"></div>' + (@($efLabel.Keys | ForEach-Object { '<div class="qw-col" role="columnheader">' + (& $h $efLabel[$_]) + '</div>' }) -join '')
        foreach ($imp in $impLabel.Keys) {
            $cells += '<div class="qw-row" role="rowheader">' + (& $h $impLabel[$imp]) + '</div>'
            foreach ($ef in $efLabel.Keys) {
                $items = @($qw["$imp|$ef"])
                $best = ($imp -in 'none', 'low' -and $ef -eq 'S')
                $cells += '<div class="qw-cell' + $(if ($best) { ' best' }) + $(if (-not $items.Count) { ' empty' }) + '" role="cell"><span class="qw-count">' + $items.Count + '</span>' + (@($items | Select-Object -First 6 | ForEach-Object { '<a href="#rec-' + (& $h $_.id) + '" class="qw-chip sev-' + (& $h $_.severity) + '" title="' + (& $h $_.title) + '">' + (& $h $_.id) + '</a>' }) -join '') + $(if ($items.Count -gt 6) { '<span class="muted"> +' + ($items.Count - 6) + '</span>' }) + '</div>'
            }
        }
        $cells += '</div>'
        $rm = $r.story.roadmap
        $lanes = '<div class="lanes">' + ((@(@('now', 'Now: next 30 days', 'Critical findings, and high ones that are quick'), @('next', 'Next: 60 days', 'High findings that take planning, quick medium ones'), @('later', 'Later: 90 days', 'The rest, in priority order')) | ForEach-Object { $k = $_[0]; '<div class="lane"><h4>' + (& $h $_[1]) + ' <span class="count">' + @($rm[$k]).Count + '</span></h4><p class="hint">' + (& $h $_[2]) + '</p><ul>' + (@($rm[$k] | Select-Object -First 12 | ForEach-Object { '<li><span class="sev ' + (& $h $_.severity) + '">' + (& $h $_.severity) + '</span> <a href="#rec-' + (& $h $_.id) + '">' + (& $h $_.title) + '</a></li>' }) -join '') + '</ul>' + $(if (@($rm[$k]).Count -gt 12) { '<p class="hint">and ' + (@($rm[$k]).Count - 12) + ' more</p>' }) + '</div>' }) -join '') + '</div>'
        & $w ('<div class="charts">' + (ConvertTo-PostureChartCard -Class 'wide' -Title 'Quick Wins' -Takeaway "$(@($qw['none|S']).Count + @($qw['low|S']).Count) open findings are quick fixes users will barely notice: the top left corner." -Body $cells) + (ConvertTo-PostureChartCard -Class 'wide' -Title 'Roadmap' -Takeaway "$(@($rm.now).Count) for the next 30 days, $(@($rm.next).Count) for 60, $(@($rm.later).Count) for 90." -Body $lanes) + '</div>')
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
                $listed = $(if ($x.Contains('affectedListed')) { [int]$x.affectedListed } else { [int]$x.affectedCount })
                $where = $(if ($listed -lt [int]$x.affectedCount) { 'The run lists ' + (& $num $listed) + ' at most for this check; those are in affected/' + (& $h $x.id) + '.csv.' } else { 'All of them are in affected/' + (& $h $x.id) + '.csv.' })
                $rest = $(if ($x.affectedCount -gt @($x.affected).Count) { '<p class="hint">The first ' + @($x.affected).Count + ' of ' + (& $num $x.affectedCount) + '. ' + $where + '</p>' } else { '' })
                $affected = '<details class="affected-list"><summary>Affected (' + (& $num $x.affectedCount) + ')</summary><ul>' + $li + '</ul>' + $rest + '</details>'
            }
            $fix = $(if (@($x.steps).Count -gt 1) { '<ol class="steps">' + (@($x.steps | ForEach-Object { '<li>' + (& $h $_) + '</li>' }) -join '') + '</ol>' } else { '<p>' + (& $h $x.remediation) + '</p>' })
            $links = @()
            if ($x.deepLink) { $links += '<a class="btn" href="' + (& $h $x.deepLink) + '" target="_blank" rel="noopener">Open in Portal</a>' }
            if ($x.learn) { $links += '<a class="btn" href="' + (& $h $x.learn) + '" target="_blank" rel="noopener">Microsoft Learn</a>' }
            $links += '<a class="btn" href="#checks" data-check="' + (& $h $x.id) + '">Details and Accept Risk</a>'
            $fw = @($x.frameworks.Keys | Where-Object { $x.frameworks[$_] } | ForEach-Object { '<span class="chip">' + (& $h $(if ($frameworkLabel.Contains($_)) { $frameworkLabel[$_] } else { $_ })) + ' ' + (& $h $x.frameworks[$_]) + '</span>' }) -join ''
            if ($x.Contains('attack')) { $fw += @($x.attack | ForEach-Object { '<a class="chip attack" href="' + (& $h $_.url) + '" target="_blank" rel="noopener" title="' + (& $h $_.name) + '">ATT&amp;CK ' + (& $h $_.id) + '</a>' }) -join '' }
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
        $cov = @($r.crosswalk.entries | Where-Object { ([int]$_.pass + [int]$_.fail) -gt 0 } | ForEach-Object { [ordered]@{ label = $_.name; value = [Math]::Round(100 * [int]$_.pass / ([int]$_.pass + [int]$_.fail)); tone = 'c1' } })
        if ($cov.Count) { & $w ('<div class="charts">' + (ConvertTo-PostureChartCard -Class 'wide' -Title 'Coverage by Group' -Takeaway "Share of mapped checks that pass, per group." -Body (ConvertTo-PostureRankedBarChart -Name 'Framework coverage' -KeepOrder -Top 30 -ValueSuffix '%' -Item $cov)) + '</div>') }
        foreach ($e in $r.crosswalk.entries) {
            & $w "<h3>$(& $h $e.name) <span class=`"muted`">($($e.pass) pass, $($e.fail) fail)</span></h3>"
            if (@($e.checks).Count -eq 0) { & $w '<p class="muted">No check maps here yet.</p>'; continue }
            & $w '<table><thead><tr><th>Reference</th><th>Check</th><th>Status</th><th>Severity</th></tr></thead><tbody>'
            foreach ($c in $e.checks) { & $w "<tr class=`"st-$($c.status)`" data-check=`"$(& $h $c.id)`"><td>$(& $h $c.reference)</td><td>$(& $h $c.id) $(& $h $c.title)</td><td><span class=`"status $(& $h $c.status)`">$(& $h $statusLabel[$c.status])</span></td><td><span class=`"sev $(& $h $c.severity)`">$(& $h $c.severity)</span></td></tr>" }
            & $w '</tbody></table>'
        }
        & $w '</section>'
    }
    # ATT&CK coverage: the techniques the evaluated checks name, under each tactic, with how their checks stand.
    if ($r.Contains('attack') -and $r.attack) {
        $at = $r.attack
        $stand = [ordered]@{ gap = @('err', [string][char]0x2715, 'Gap'); accepted = @('warn', '!', 'Accepted risk'); covered = @('ok', [string][char]0x2713, 'Covered'); unchecked = @('na', [string][char]0x2013, 'Not checked') }
        & $w ('<section class="view" id="attack"><h2>ATT&amp;CK Coverage</h2><p class="lede">Each check names the MITRE ATT&amp;CK techniques it helps stop or detect. These are the ' + $at.techniques + ' techniques this run''s checks address, under each tactic, with how their checks stand. Covered means those checks pass: the risk is lower, not gone, and ATT&amp;CK does not list every way in.</p>')
        $seg = @('covered', 'accepted', 'gap', 'unchecked' | ForEach-Object { @{ label = $stand[$_][2]; value = [int]$at.totals[$_]; tone = $stand[$_][0] } })
        $worst = @($at.tactics | Sort-Object { - [int]$_.counts.gap }, { $_.name } | Select-Object -First 1)
        $takeaway = $(if ([int]$at.totals.gap) { "$($at.totals.gap) of $($at.techniques) techniques have a failing check; $($worst[0].name) has the most ($($worst[0].counts.gap))." } else { "No technique the checks address has a failing check." })
        $rows = @($at.tactics | ForEach-Object {
                $t = $_; $ev = [int]$t.counts.covered + [int]$t.counts.accepted + [int]$t.counts.gap
                $bar = ConvertTo-PostureBarChart -Thin -Name $t.name -Segment @('covered', 'accepted', 'gap', 'unchecked' | ForEach-Object { @{ label = $stand[$_][2]; value = [int]$t.counts[$_]; tone = $stand[$_][0] } })
                '<a class="pillar" href="#attack-' + (& $h $t.key) + '"><span class="name">' + (& $h $t.name) + '</span><span class="frac">' + $t.counts.covered + ' of ' + $ev + ' covered</span>' + $bar + '</a>'
            }) -join ''
        & $w ('<div class="charts">' + (ConvertTo-PostureChartCard -Title 'Techniques by Standing' -Takeaway $takeaway -Body (ConvertTo-PostureDonutChart -Name 'ATT&CK techniques by standing' -CenterLabel 'techniques' -Segment $seg)) + (ConvertTo-PostureChartCard -Class 'span2' -Title 'Tactics' -Takeaway 'Techniques covered of those evaluated, per tactic. A technique under two tactics counts in both.' -Body ('<div class="pillars">' + $rows + '</div>' + (ConvertTo-PostureChartLegend -Item $seg))) + '</div>')
        # Failing checks first on each technique, eight at most; the drawer behind each check has the rest of the story.
        $checkRank = @{ fail = 0; acceptedRisk = 1; notEvaluated = 2; pass = 3; coveredBy = 3 }
        # A section for each tactic in the order of an attack, folded until asked for, its techniques across the page.
        # A column for each tactic left the short ones standing beside the long ones with holes under them.
        & $w '<div class="area-head"><h3>Techniques by Tactic</h3><button type="button" class="fold-toggle" data-fold="details.attack-tactic" aria-expanded="false">Open all</button></div>'
        & $w '<div class="attack-matrix">'
        foreach ($t in $at.tactics) {
            $items = @($t.techniques | ForEach-Object {
                    $x = $_; $st = $stand[[string]$x.status]; $n = @($x.checks).Count
                    $ordered = @($x.checks | Sort-Object { $checkRank[[string]$_.status] }, { $_.id })
                    $checkLinks = (@($ordered | Select-Object -First 8 | ForEach-Object { '<a href="#checks" data-check="' + (& $h $_.id) + '" class="qw-chip st-' + (& $h $_.status) + '" title="' + (& $h "$($_.title): $($statusLabel[[string]$_.status])") + '">' + (& $h $_.id) + '</a>' }) -join ' ') + $(if ($n -gt 8) { ' <span class="muted">+' + ($n - 8) + '</span>' })
                    '<li class="attack-tech"><span class="status-dot t-' + $st[0] + '" aria-hidden="true">' + $st[1] + '</span><div><a href="' + (& $h $x.url) + '" target="_blank" rel="noopener"><code>' + (& $h $x.id) + '</code> ' + (& $h $x.name) + '</a><p class="hint">' + $st[2] + ': ' + $x.pass + ' of ' + $n + ' check' + $(if ($n -ne 1) { 's' }) + ' pass</p><p class="attack-checks">' + $checkLinks + '</p></div></li>'
                }) -join ''
            $evaluated = [int]$t.counts.covered + [int]$t.counts.accepted + [int]$t.counts.gap
            $standing = "$($t.counts.covered) of $evaluated covered" + $(if ([int]$t.counts.gap -gt 0) { ", $($t.counts.gap) with a failing check" } else { '' })
            & $w ('<details class="attack-tactic" id="attack-' + (& $h $t.key) + '"><summary><span class="area-name">' + (& $h $t.name) + '</span><span class="muted tech">' + (& $h $t.id) + '</span><span class="hint">' + (& $h $standing) + '</span></summary><ul>' + $items + '</ul></details>')
        }
        & $w '</div>'
        & $w ('<p class="hint tech">MITRE ATT&amp;CK ' + (& $h $at.version) + ', Enterprise. ' + (& $h $at.notice) + '</p></section>')
    }
    # Licensing: what the tenant holds and uses, what each goal needs, and what to add. No prices anywhere.
    if ($r.licensing) {
        $la = $(if ($r.Contains('licenseAdvice')) { $r.licenseAdvice } else { $null })
        & $w '<section class="view" id="licensing"><h2>Licensing</h2><p class="lede">What the tenant holds, what is switched on, what each security goal needs, and the combination of licences that covers the goals. Take the answer to your Microsoft partner.</p>'
        if ($la) {
            $ad = $la.advice
            $goalNames = @{}; foreach ($g in $la.goals) { $goalNames[[string]$g.id] = $g.name }
            $forWhat = $(if ($ad.goalSource -eq 'profile') { 'the goals in your profile' } else { 'the core goals (set your own with New-PostureProfile -Goal)' })
            & $w ('<div class="advisor"><h3>What To Add</h3><p class="hint" id="advice-for">For ' + (& $h $forWhat) + ': ' + (& $h (@($ad.goals | ForEach-Object { $goalNames[[string]$_] }) -join '; ')) + '.</p>')
            # Controls: change the goals or say another product covers a category; the page recomputes, nothing is saved.
            $catLabel = [ordered]@{ edr = 'Endpoint detection and response (instead of Defender for Endpoint)'; email = 'Email security (instead of Defender for Office 365)'; swg = 'Secure web gateway (instead of Entra Internet Access)'; ztna = 'Zero trust network access (instead of Entra Private Access)'; mdm = 'Device management (instead of Intune)' }
            $tp = $(if ($la.Contains('page')) { $la.page.thirdParty } else { @{} })
            $ctl = '<details class="advisor-controls"><summary>Change the goals or the products you already use</summary><div class="ctl-grid"><fieldset><legend>Goals</legend>' + (@($la.goals | ForEach-Object { '<label><input type="checkbox" class="adv-goal" value="' + (& $h $_.id) + '"' + $(if ($_.id -in @($ad.goals)) { ' checked' }) + '> ' + (& $h $_.name) + '</label>' }) -join '') + '</fieldset><fieldset><legend>Covered by another product</legend>' + (@($catLabel.Keys | ForEach-Object { $vn = $(if ($tp.Contains($_) -and $tp[$_] -and $tp[$_] -ne 'none') { [string]$tp[$_] } else { '' }); '<label class="adv-vendor"><input type="checkbox" class="adv-cat" value="' + $_ + '"' + $(if ($vn) { ' checked' }) + '> ' + (& $h $catLabel[$_]) + ' <input type="text" class="adv-name" data-cat="' + $_ + '" value="' + (& $h $vn) + '" placeholder="product name" aria-label="Product for ' + $_ + '"></label>' }) -join '') + '</fieldset></div><p class="hint">Nothing here is saved. To keep a change, set it in the profile: New-PostureProfile -Goal ... -ThirdParty @{ edr = ''CrowdStrike'' }.</p></details>'
            & $w $ctl
            & $w '<div id="advice-live">'
            if ($ad.met) { & $w '<p class="banner ready"><strong>Covered.</strong> The licences you hold include every feature these goals need. The work is configuration: see Recommendations.</p>' }
            else {
                & $w ('<p>Missing: ' + (& $h (@($ad.missing | ForEach-Object { @($_) -join ' or ' }) -join '; ')) + '.</p>')
                $rec = $ad.recommended
                if (-not $rec) { & $w '<p class="banner">No combination of the licences this report knows covers these goals together. Take the missing features above to your Microsoft partner.</p>' }
                else {
                    # One combination, each licence with the reason it is there. No price, no rank, no alternatives.
                    $parts = '<div class="advice-card advice-rec"><h4><span class="chip">Recommended</span> ' + (& $h $rec.title) + '</h4><ul class="advice-skus">'
                    foreach ($l in @($rec.licences)) {
                        $parts += '<li><strong>' + (& $h $l.name) + '</strong> <code class="tech">' + (& $h $l.sku) + '</code>' + $(if ($l.verify) { ' <span class="tech">(verify: ' + (& $h $l.verify) + ')</span>' })
                        if (@($l.covers).Count) { $parts += '<br><span class="adv-why">Covers: ' + (& $h (@($l.covers) -join '; ')) + '.</span>' }
                        if (@($l.neededBy).Count) { $parts += '<br><span class="adv-why">Needed first by ' + (& $h (@($l.neededBy) -join ', ')) + '.</span>' }
                        if (@($l.brings).Count) { $parts += '<br><span class="muted">Brings ' + (& $h (@($l.brings) -join ', ')) + '.</span>' }
                        $parts += '</li>'
                    }
                    $parts += '</ul>'
                    if (@($rec.replaces).Count) { $parts += '<p><strong>Takes the place of</strong> ' + (& $h (@($rec.replaces | ForEach-Object { $_.name }) -join ', ')) + ': ' + (& $h ([string]@($rec.replaces)[0].by)) + ' includes what ' + $(if (@($rec.replaces).Count -gt 1) { 'they bring' } else { 'it brings' }) + ' for these goals.</p>' }
                    if (@($rec.keeps).Count) { $parts += '<p><strong>Stays as it is</strong> ' + (& $h (@($rec.keeps) -join ', ')) + '.</p>' }
                    if (@($rec.noLonger).Count) { $parts += '<p><strong>No longer included after the move</strong> ' + (& $h (@($rec.noLonger) -join ', ')) + '.</p>' }
                    if (@($rec.redundant).Count) { $parts += '<p class="muted"><strong>Overlaps with a product you use</strong> ' + (& $h (@($rec.redundant | ForEach-Object { "$($_.name) ($($_.vendor))" }) -join ', ')) + '.</p>' }
                    if (@($rec.alsoIncludes).Count) { $parts += '<p class="muted"><strong>Also includes</strong> ' + (& $h (@($rec.alsoIncludes) -join ', ')) + '.</p>' }
                    & $w ($parts + '</div>')
                }
                & $w ('<p class="hint">For ' + $ad.seats + ' licensed users. Eligibility and terms are your Microsoft partner''s to confirm.</p>')
                foreach ($pq in @($ad.prerequisite)) { & $w ('<p class="hint">' + (& $h $pq) + '</p>') }
            }
            & $w '</div>'
            # Licences held today where one includes all of another: a fact about what is held, whatever the goals.
            if (@($ad.heldOverlap).Count) {
                & $w '<h4 class="adv-sub">Licences You Hold That Overlap</h4><ul class="advice-overlap">'
                foreach ($ho in @($ad.heldOverlap)) { & $w ('<li>Everything in <strong>' + (& $h $ho.licence) + '</strong> is also in <strong>' + (& $h $ho.includedIn) + '</strong>. A user who holds ' + (& $h $ho.includedIn) + ' does not need ' + (& $h $ho.licence) + ' as well; keep it only for users who do not.</li>') }
                & $w '</ul>'
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
            $stLabel = @{ owned = 'Owned'; partial = 'Partly assigned'; missing = 'Not owned'; covered = 'Covered by' }
            $stClass = @{ owned = 'pass'; partial = 'acceptedRisk'; missing = 'notApplicable'; covered = 'coveredBy' }
            & $w '<h3>Features</h3><p class="hint">Partly assigned: bought, but switched on for fewer people than hold a licence. Sometimes deliberate (Entra ID P2 for administrators only), often an oversight.</p><table><thead><tr><th>Feature</th><th>Status</th><th>What it unlocks</th></tr></thead><tbody>'
            foreach ($f in @($la.features | Sort-Object { if ($_.kind -eq 'value') { 1 } else { 0 } }, { @{ partial = 0; owned = 1; covered = 2; missing = 3 }[[string]$_.status] }, { $_.name })) {
                $who = $(if ($f.status -eq 'partial') { ' <span class="muted">' + $f.users + ' of ' + $f.licensedUsers + ' users</span>' } elseif ($f.status -eq 'covered') { ' <span class="muted">' + (& $h $f.vendor) + '</span>' } elseif ($f.kind -eq 'value') { ' <span class="muted">not security</span>' } else { '' })
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
    # Every source an assessment can draw on and where this run stands with each. Always there: "To Complete This
    # Assessment" speaks only when a check waits, so without this a run that lacks nothing explains nothing.
    $sources = @($(if ($rh -and $rh.Contains('sources')) { $rh.sources }))
    if ($sources.Count -gt 0) {
        $sourceLabel = @{ collected = @('pass', 'Collected'); notCollected = @('notEvaluated', 'Not collected'); notNeeded = @('notApplicable', 'Not needed here') }
        & $w '<h3>Where This Run''s Evidence Comes From</h3>'
        & $w '<p class="hint">Every source the assessment can draw on. Most are read by the run itself; a few are collected somewhere else and brought in, and those are asked for only when a check needs them.</p>'
        & $w '<table><thead><tr><th>Source</th><th>In This Run</th><th>Detail</th></tr></thead><tbody>'
        foreach ($x in $sources) {
            $label = $sourceLabel[[string]$x.state]
            & $w ('<tr><td>' + (& $h $x.title) + '</td><td><span class="status ' + $label[0] + '">' + $label[1] + '</span></td><td>' + (& $h $x.detail) + '</td></tr>')
        }
        & $w '</tbody></table>'
    }
    # Where the collection stopped, from the run's journal: the steps it was in, the domains that did not finish,
    # files left from an earlier attempt and writes that were cut short. None of these is read as evidence.
    $stopped = @($(if ($rh -and $rh.Contains('stoppedIn')) { $rh.stoppedIn })); $unfinished = @($(if ($rh -and $rh.Contains('notFinished')) { $rh.notFinished }))
    $staleFiles = @($(if ($rh -and $rh.Contains('stale')) { $rh.stale })); $cutShort = @($(if ($rh -and $rh.Contains('cutShort')) { $rh.cutShort }))
    $notAttempted = @($(if ($rh -and $rh.Contains('notAttempted')) { $rh.notAttempted }))
    $interrupted = ($stopped.Count + $unfinished.Count + $staleFiles.Count + $cutShort.Count + $notAttempted.Count) -gt 0
    if ($interrupted) {
        & $w '<h3>Where the Collection Stopped</h3>'
        if ($unfinished.Count) { & $w "<p class=`"banner warn`"><strong>$($unfinished.Count) domain(s) did not finish: $(& $h ($unfinished -join ', ')).</strong> The process stopped before the end. Their checks say not evaluated. This collects only what is missing, into the same run:</p><div class=`"cmd`"><code id=`"cmd-resume-stopped`">$(& $h $rh.resume)</code><button type=`"button`" data-copy=`"cmd-resume-stopped`">Copy</button></div>" }
        if ($stopped.Count) {
            & $w '<p>Steps that started and never finished:</p><table><thead><tr><th>Domain</th><th>Step</th></tr></thead><tbody>'
            foreach ($x in $stopped) { & $w "<tr><td>$(& $h $(if ($x.collector) { $x.collector } else { 'Run' }))</td><td>$(& $h $x.step)</td></tr>" }
            & $w '</tbody></table>'
        }
        if ($notAttempted.Count) {
            & $w "<p>$($notAttempted.Count) step(s) were not attempted, because the sign-in they depend on had ended:</p><table><thead><tr><th>Domain</th><th>Step</th></tr></thead><tbody>"
            foreach ($x in $notAttempted) { & $w "<tr><td>$(& $h $x.collector)</td><td>$(& $h $x.step)</td></tr>" }
            & $w '</tbody></table>'
        }
        if ($staleFiles.Count) {
            & $w '<p>Files left from an earlier attempt. The step that writes each ran again and did not write it, so the file is not read and the checks that need it say not evaluated:</p><table><thead><tr><th>File</th><th>Domain</th><th>Step</th></tr></thead><tbody>'
            foreach ($x in $staleFiles) { & $w "<tr><td><code>$(& $h $x.file)</code></td><td>$(& $h $x.collector)</td><td>$(& $h $x.step)</td></tr>" }
            & $w '</tbody></table>'
        }
        if ($cutShort.Count) { & $w "<p>$($cutShort.Count) file(s) were not finished and are never read: $(@($cutShort | ForEach-Object { '<code>' + (& $h $_) + '</code>' }) -join ', '). Collecting the domain again within a day carries on a long list from where it stopped; otherwise the list is read again.</p>" }
    }
    if (-not $rh -or @($rh.failures).Count -eq 0) { if (-not $interrupted) { & $w '<p class="banner ready"><strong>Every collection step ran.</strong> Nothing to grant and nothing to collect again.</p>' } }
    else {
        # The command to collect again is offered only when collecting again can change something: a licence the
        # tenant does not have, or a read Microsoft does not give the sign-in, says the same the second time.
        $canRetry = @($rh.failures | Where-Object { [string]$_.cause -in 'permission', 'token', 'throttled', 'network', 'module', 'unknown' }).Count
        if ($canRetry -gt 0) {
            & $w "<p>$(@($rh.failures).Count) step(s) could not be read. Each row says why and what to do. After granting a role, collect only what failed, into the same run, then refresh this page:</p>"
            & $w "<div class=`"cmd`"><code id=`"cmd-resume`">$(& $h $rh.resume)</code><button type=`"button`" data-copy=`"cmd-resume`">Copy</button></div>"
        }
        else { & $w "<p>$(@($rh.failures).Count) step(s) could not be read. Each row says why. None of them is fixed by collecting again: each waits for a licence the tenant does not have, or for a read Microsoft does not give this sign-in.</p>" }
        & $w '<table><thead><tr><th>Domain</th><th>Step</th><th>Why</th><th>What To Do</th></tr></thead><tbody>'
        foreach ($f in $rh.failures) {
            & $w "<tr class=`"cause-$(& $h $f.cause)`"><td>$(& $h $(if ($f.collector) { $f.collector } else { 'Run' }))</td><td>$(& $h $f.step)</td><td><span class=`"status fail`">$(& $h $f.causeLabel)</span></td><td>$(& $h $f.advice)<details class=`"tech`"><summary>The message</summary><code>$(& $h $f.message)</code></details></td></tr>"
        }
        & $w '</tbody></table>'
        # For support: each failure as text with the tenant's names taken out, one at a time or all together.
        $supportBlocks = @($rh.failures | Where-Object { $_.Contains('support') -and $_.support } | ForEach-Object { [string]$_.support })
        if ($supportBlocks.Count) {
            & $w '<h3>Send a Failure for Support</h3><p class="hint">Each block says where the step stopped, the request it was making, and Microsoft''s message, with names, addresses and ids taken out. Read it before sending. For every log in the run at once, redacted the same way: <code>Export-PostureDiagnostics</code>.</p>'
            & $w ('<div class="cmd"><code id="cmd-diagnostics">' + (& $h $rh.diagnostics) + '</code><button type="button" data-copy="cmd-diagnostics">Copy</button></div>')
            & $w ('<pre class="support-text" id="support-all" hidden>' + (& $h ($supportBlocks -join "`n`n")) + '</pre><p><button type="button" data-copy="support-all">Copy All ' + $supportBlocks.Count + ' for Support</button></p>')
            $i = 0
            foreach ($f in @($rh.failures | Where-Object { $_.Contains('support') -and $_.support })) {
                $i++
                & $w ('<details class="support"><summary>' + (& $h "$(if ($f.collector) { $f.collector } else { 'Run' }): $($f.step)") + '</summary><pre class="support-text" id="support-' + $i + '">' + (& $h $f.support) + '</pre><button type="button" data-copy="support-' + $i + '">Copy for Support</button></details>')
            }
        }
    }
    if ($rh -and $rh.Contains('judgedOnPart') -and @($rh.judgedOnPart).Count) {
        & $w "<h3>Judged on Part of the Data</h3><p>$(@($rh.judgedOnPart).Count) check(s) have an answer from part of what the tenant holds: a sample, a list with a ceiling, or the part that could be read. Each says how much. A check that passed on part of the data and could have failed on the rest says not evaluated instead and is not in this list.</p>"
        & $w '<table><thead><tr><th>Check</th><th>Title</th><th>Status</th><th>How Much Was Read</th></tr></thead><tbody>'
        foreach ($x in $rh.judgedOnPart) { & $w "<tr data-check=`"$(& $h $x.id)`"><td><code>$(& $h $x.id)</code></td><td>$(& $h $x.title)</td><td><span class=`"status $(& $h $x.status)`">$(if ($x.status -eq 'pass') { 'Pass' } else { 'Fail' })</span></td><td>$(& $h $x.note)</td></tr>" }
        & $w '</tbody></table>'
    }
    if ($rh -and $rh.Contains('calls') -and $rh.calls) {
        $cs = $rh.calls
        & $w '<h3>What This Run Did</h3>'
        if (@($cs.unexpected).Count) { & $w ('<p class="banner blocked"><strong>' + @($cs.unexpected).Count + ' call(s) were not reads.</strong> This should never happen; the module allows reads only. Listed below and in ' + (& $h $cs.file) + '.</p>') }
        else { & $w ('<p class="banner ready"><strong>Every one of the ' + (& $num $cs.total) + ' requests was a read.</strong> GET requests, Get- commands and queries only; nothing was written to the tenant. Each is counted in ' + (& $h $cs.file) + ' in the run folder, with ids and accounts replaced by placeholders.</p>') }
        & $w '<table><thead><tr><th>Service</th><th>Requests</th><th>Different Calls</th><th>Most Frequent</th></tr></thead><tbody>'
        foreach ($s in $cs.services) { & $w ("<tr><td>$(& $h $s.label)</td><td>$(& $num $s.requests)</td><td>$($s.targets)</td><td class=`"tech`">" + (@($s.top | Select-Object -First 4 | ForEach-Object { (& $h "$($_.method) $($_.target)") + " ($(& $num $_.count))" }) -join '<br>') + '</td></tr>') }
        & $w '</tbody></table>'
        if (@($cs.unexpected).Count) {
            & $w '<table><thead><tr><th>Service</th><th>Method</th><th>Target</th><th>Count</th></tr></thead><tbody>'
            foreach ($u in $cs.unexpected) { & $w "<tr class=`"st-fail`"><td>$(& $h $u.service)</td><td>$(& $h $u.method)</td><td class=`"tech`">$(& $h $u.target)</td><td>$($u.count)</td></tr>" }
            & $w '</tbody></table>'
        }
    }
    if ($rh -and $rh.Contains('serviceHealth') -and $null -ne $rh.serviceHealth) {
        $open = @($rh.serviceHealth)
        & $w '<h3>Microsoft Service Health When This Run Was Made</h3>'
        if ($open.Count -eq 0) { & $w '<p>Microsoft reported no open incident or advisory for this tenant.</p>' }
        else {
            $incidents = @($open | Where-Object { $_.kind -eq 'incident' }).Count
            & $w "<p>Microsoft had $incidents incident(s) and $($open.Count - $incidents) advisory(ies) open for this tenant. They are Microsoft's to fix and no check is judged by them; they are listed because an incident on the day can explain a step that failed.</p>"
            & $w '<table><thead><tr><th>Service</th><th>Kind</th><th>What</th><th>Status</th></tr></thead><tbody>'
            foreach ($x in $open) { & $w "<tr><td>$(& $h $x.service)</td><td>$(& $h $(if ($x.kind -eq 'incident') { 'Incident' } else { 'Advisory' }))</td><td><code>$(& $h $x.id)</code> $(& $h $x.title)</td><td>$(& $h $x.status)</td></tr>" }
            & $w '</tbody></table>'
        }
    }
    if ($rh -and $rh.Contains('imports') -and @($rh.imports).Count) {
        & $w '<h3>Evidence Brought In From Another Machine</h3><table><thead><tr><th>What</th><th>Collector</th><th>Collected</th><th>By</th><th>Files</th><th>Checked</th></tr></thead><tbody>'
        foreach ($i in $rh.imports) { & $w "<tr><td>$(& $h $i.label)</td><td>$(& $h $i.collector)</td><td>$(& $h $i.collectedUtc)</td><td>$(& $h $i.account)</td><td>$($i.files)</td><td>$(& $h $(if ($i.checked -eq 'sha256') { 'Every file against its SHA-256' } else { 'File names only' }))$(if ($i.Contains('tenantCheck') -and $i.tenantCheck) { '<br><span class="tech">Tenant: ' + (& $h $i.tenantCheck) + '</span>' })</td></tr>" }
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
    & $w (& $jsonBlock 'data-results' @($r.results | ForEach-Object { [ordered]@{ id = $_.id; domain = $_.domain; title = $_.title; status = $_.status; severity = $_.severity; reason = $_.reason; affected = @($_.affected | Select-Object -First 500); affectedCount = $_.affectedCount; affectedListed = $(if ($_.Contains('affectedListed')) { [int]$_.affectedListed } else { @($_.affected).Count }); evidence = @($_.evidence); thresholds = $_.thresholds; observed = $(if ($_.Contains('observed')) { $_.observed } else { $null }) } }))
    & $w (& $jsonBlock 'data-catalog' $r.catalogText)
    & $w (& $jsonBlock 'data-exceptions' @($r.exceptions))
    & $w (& $jsonBlock 'data-attestations' $r.attestations)
    & $w (& $jsonBlock 'data-meta' ([ordered]@{ tenantId = $r.tenantId; clientName = $r.clientName; generatedUtc = $r.generatedUtc; licenceId = $(if ($r.licence) { $r.licence.licenceId } else { $null }) }))
    if ($r.Contains('findings') -and $r.findings) { & $w (& $jsonBlock 'tenantkeep-findings' $r.findings) }
    if ($r.Contains('licenseAdvice') -and $r.licenseAdvice -and $r.licenseAdvice.Contains('page')) { & $w (& $jsonBlock 'data-licensing' $r.licenseAdvice.page) }
    & $w (& $jsonBlock 'data-labels' ([ordered]@{ facts = $catLabels.facts; status = $statusLabel; domains = $domainLabel; frameworks = $frameworkLabel; methods = $methodLabel; thresholds = $thresholdLabel }))
    & $w "<script>`n$js`n</script>"
    & $w '</body></html>'
    return $sb.ToString()
}
