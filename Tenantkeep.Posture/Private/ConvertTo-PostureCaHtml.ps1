# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function ConvertTo-PostureCaHtml {
    <#
    .SYNOPSIS
        Renders the CA document model as one self-contained HTML file: inline CSS, no scripts, no remote resources.
    .DESCRIPTION
        Spec 7.1: works offline, passes strict content security policies, prints cleanly. Light and dark themes
        follow the system preference. Brand colors and font come from brand.json; a logo is inlined as a data URI
        when the file exists.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Document
    )

    $ErrorActionPreference = 'Stop'
    $sb = [System.Text.StringBuilder]::new()
    $w = { param([string] $Text = '') $null = $sb.AppendLine($Text) }
    $h = { param([object] $Text) [System.Net.WebUtility]::HtmlEncode([string]$Text) }
    $fmtDate = { param($Value) $u = ConvertTo-PostureUtcDateTime $Value; if ($u) { $u.ToString('yyyy-MM-dd HH:mm') + ' UTC' } else { 'unknown' } }
    $refList = {
        param($Refs)
        $items = @($Refs | ForEach-Object {
                $label = & $h $_.name
                if ($null -ne $_.memberCount) { $label += " ($($_.memberCount) members)" }
                if ($_.deleted) { "<span class=`"deleted`">$label</span>" } else { $label }
            })
        if ($items.Count -eq 0) { 'none' } else { $items -join ', ' }
    }
    $slug = { param([string] $Text) 'p-' + (($Text.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')) }
    $logoDataUri = {
        param([object] $Path)
        if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
        $ext = [System.IO.Path]::GetExtension([string]$Path).ToLowerInvariant()
        $mime = @{ '.svg' = 'image/svg+xml'; '.png' = 'image/png'; '.jpg' = 'image/jpeg'; '.jpeg' = 'image/jpeg'; '.gif' = 'image/gif'; '.webp' = 'image/webp' }[$ext]
        if (-not $mime) { return $null }
        'data:' + $mime + ';base64,' + [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($Path))
    }

    $d = $Document; $b = $d.brand; $s = $d.stats
    $css = Get-Content -LiteralPath (Get-PostureTemplatePath -Name 'ca-document.css') -Raw
    $primary = if ($b.colors.primary) { [string]$b.colors.primary } else { '#1F3A5F' }
    $accent = if ($b.colors.accent) { [string]$b.colors.accent } else { '#E8A33D' }
    $font = if ($b.font) { [string]$b.font } else { 'Inter, Helvetica, Arial, sans-serif' }
    $safeColor = { param([string] $c, [string] $fallback) if ($c -match '^#[0-9A-Fa-f]{3,8}$') { $c } else { $fallback } }
    $override = ":root { --primary: $(& $safeColor $primary '#1F3A5F'); --accent: $(& $safeColor $accent '#E8A33D'); --font: $(& $h ($font -replace '[^A-Za-z0-9 ,\-]', '')); }"

    & $w '<!DOCTYPE html>'
    & $w '<html lang="en">'
    & $w '<head>'
    & $w '<meta charset="utf-8">'
    & $w '<meta name="viewport" content="width=device-width, initial-scale=1">'
    & $w "<meta http-equiv=`"Content-Security-Policy`" content=`"default-src 'none'; img-src data:; style-src 'unsafe-inline'`">"
    & $w "<title>$(& $h $d.title)</title>"
    & $w "<style>`n$css`n$override`n</style>"
    & $w '</head>'
    & $w '<body>'

    # Header
    & $w '<header class="doc">'
    & $w '<div class="brand">'
    $logo = & $logoDataUri (Get-PostureValue $b 'preparedBy.logo')
    if (-not $logo) { $logo = & $logoDataUri (Get-PostureValue $b 'client.logo') }
    if ($logo) { & $w "<img class=`"logo`" alt=`"logo`" src=`"$logo`">" }
    & $w "<div><h1>$(& $h $d.title)</h1>"
    $prepared = [string]$b.preparedBy.name
    if ($b.client.name) { $prepared += " for $($b.client.name)" }
    & $w "<div class=`"meta`">Prepared by $(& $h $prepared). Snapshot taken $(& $fmtDate $d.snapshot.timestampUtc) by $(& $h $d.snapshot.account) in tenant <code>$(& $h $d.snapshot.tenantId)</code>. Generated $(& $fmtDate $d.generatedUtc) with Tenantkeep.Posture $(& $h $d.snapshot.moduleVersion).</div>"
    if ($b.confidentiality) { & $w "<div class=`"confidential`">$(& $h $b.confidentiality)</div>" }
    & $w '</div></div>'
    & $w '</header>'
    & $w '<main>'

    # TOC
    & $w '<nav class="toc"><strong>Contents</strong><ul>'
    foreach ($item in @(@('summary', 'Summary'), @('health', 'Health flags'), @('matrix', 'Policy matrix'), @('naming', 'Naming convention'), @('coverage', 'Coverage findings'), @('policies', 'Policies'), @('locations', 'Named locations'), @('strengths', 'Authentication strengths'), @('contexts', 'Authentication context'), @('appendix', 'Appendix: snapshot'))) {
        & $w "<li><a href=`"#$($item[0])`">$($item[1])</a></li>"
    }
    & $w '</ul></nav>'

    # Summary
    & $w '<section id="summary"><h2>Summary</h2><div class="stats">'
    foreach ($pair in @(@('Policies', $s.total), @('Enabled', $s.enabled), @('Report-only', $s.reportOnly), @('Disabled', $s.disabled), @('Errors', $s.flagsError), @('Warnings', $s.flagsWarning), @('Info', $s.flagsInfo))) {
        & $w "<div class=`"stat`"><div class=`"n`">$($pair[1])</div><div class=`"l`">$($pair[0])</div></div>"
    }
    & $w '</div>'
    if (@($d.snapshot.errors).Count -gt 0) {
        & $w "<div class=`"notice`"><strong>Snapshot errors.</strong> $(@($d.snapshot.errors).Count) collection step(s) failed; see errors.txt in the snapshot folder. Sections that depend on them may be incomplete.</div>"
    }
    & $w '</section>'

    # Health flags
    & $w '<section id="health"><h2>Health flags</h2>'
    $flagRows = @(foreach ($p in $d.policies) { foreach ($f in @($p.healthFlags)) { , @($p, $f) } })
    if ($flagRows.Count -eq 0) { & $w '<p>No health flags.</p>' }
    else {
        & $w '<table><thead><tr><th>Policy</th><th>Flag</th><th>Severity</th><th>Detail</th></tr></thead><tbody>'
        foreach ($row in $flagRows) {
            $p, $f = $row
            & $w "<tr><td><a href=`"#$(& $slug $p.name)`">$(& $h $p.name)</a></td><td><code>$(& $h $f.code)</code></td><td><span class=`"sev $(& $h $f.severity)`">$(& $h $f.severity)</span></td><td>$(& $h $f.message)</td></tr>"
        }
        & $w '</tbody></table>'
    }
    & $w '</section>'

    # Matrix
    & $w '<section id="matrix"><h2>Policy matrix</h2>'
    $cols = @($d.matrix.columns)
    $headerCells = @($cols | ForEach-Object { "<th>$(& $h $_.label)</th>" }) -join ''
    & $w ('<div class="scroll"><table class="matrix"><thead><tr><th>Policy</th>' + $headerCells + '</tr></thead><tbody>')
    foreach ($r in $d.matrix.rows) {
        $cells = @($cols | ForEach-Object { $v = $r.cells[$_.key]; if ($v) { "<td class=`"on`">$(& $h $v)</td>" } else { '<td></td>' } })
        & $w "<tr><td><a href=`"#$(& $slug $r.name)`">$(& $h $r.name)</a></td>$($cells -join '')</tr>"
    }
    & $w '</tbody></table></div></section>'

    # Naming
    & $w '<section id="naming"><h2>Naming convention</h2>'
    if ($d.naming) {
        & $w "<p>Pattern: <code>$(& $h $d.naming.pattern)</code>. $(@($d.naming.conforming).Count) of $($s.total) policies conform.</p>"
        if (@($d.naming.nonConforming).Count -gt 0) {
            & $w '<table><thead><tr><th>Current name</th><th>Proposed name</th></tr></thead><tbody>'
            foreach ($n in $d.naming.nonConforming) { & $w "<tr><td>$(& $h $n.name)</td><td>$(& $h $n.proposedName)</td></tr>" }
            & $w '</tbody></table>'
            & $w "<p>Proposed names follow <code>$(& $h $d.naming.format)</code>; adjust the description part by hand.</p>"
        }
    }
    else { & $w '<p>No naming pattern configured. Pass -NamePattern or set caNamePattern in brand.json.</p>' }
    & $w '</section>'

    # Coverage
    & $w '<section id="coverage"><h2>Coverage findings</h2>'
    & $w '<p>The Conditional Access checks from the posture catalog (legacy auth blocked, MFA for all users, phishing-resistant strength for admins, risk policies, device compliance, break-glass exclusions and the rest) are evaluated by <code>Invoke-PostureChecks</code> and rendered here once the check engine ships. This document covers configuration and health, not coverage.</p>'
    & $w '</section>'

    # Policies
    & $w '<section id="policies" class="policies"><h2>Policies</h2>'
    foreach ($p in $d.policies) {
        $a = $p.assignments; $t = $p.targets; $c = $p.conditions; $g = $p.grant; $se = $p.session
        & $w "<article class=`"policy`" id=`"$(& $slug $p.name)`">"
        & $w "<h3>$(& $h $p.name)<span class=`"badge $(& $h $p.state)`">$(& $h $p.stateLabel)</span></h3>"
        & $w "<p class=`"summary`">$(& $h $p.summary)</p>"
        & $w "<table class=`"kv`"><tbody><tr><th>ID</th><td><code>$(& $h $p.id)</code></td></tr><tr><th>Created</th><td>$(& $fmtDate $p.created)</td></tr><tr><th>Last modified</th><td>$(& $fmtDate $p.modified)</td></tr></tbody></table>"

        & $w '<h4>Assignments</h4><ul>'
        & $w "<li>Include users: $(& $refList $a.includeUsers)</li><li>Exclude users: $(& $refList $a.excludeUsers)</li>"
        & $w "<li>Include groups: $(& $refList $a.includeGroups)</li><li>Exclude groups: $(& $refList $a.excludeGroups)</li>"
        & $w "<li>Include roles: $(& $refList $a.includeRoles)</li><li>Exclude roles: $(& $refList $a.excludeRoles)</li>"
        if ($a.includeGuestsOrExternal) { & $w "<li>Include guests or external users: $(& $h (@($a.includeGuestsOrExternal.guestOrExternalUserTypes) -join ', '))</li>" }
        if ($a.excludeGuestsOrExternal) { & $w "<li>Exclude guests or external users: $(& $h (@($a.excludeGuestsOrExternal.guestOrExternalUserTypes) -join ', '))</li>" }
        if (@($a.includeServicePrincipals).Count -gt 0 -or @($a.excludeServicePrincipals).Count -gt 0) {
            & $w "<li>Include workload identities: $(& $refList $a.includeServicePrincipals)</li><li>Exclude workload identities: $(& $refList $a.excludeServicePrincipals)</li>"
        }
        & $w '</ul>'

        & $w '<h4>Target resources</h4><ul>'
        & $w "<li>Include apps: $(& $refList $t.includeApplications)</li><li>Exclude apps: $(& $refList $t.excludeApplications)</li>"
        if (@($t.userActions).Count -gt 0) { & $w "<li>User actions: $(& $refList $t.userActions)</li>" }
        if (@($t.authenticationContexts).Count -gt 0) { & $w "<li>Authentication context: $(& $refList $t.authenticationContexts)</li>" }
        if ($t.applicationFilter) { & $w "<li>Application filter ($(& $h $t.applicationFilter.mode)): <code>$(& $h $t.applicationFilter.rule)</code></li>" }
        & $w '</ul>'

        & $w '<h4>Conditions</h4><ul>'
        & $w "<li>Client app types: $(if (@($c.clientAppTypes).Count -gt 0) { & $h (@($c.clientAppTypes) -join ', ') } else { 'not configured' })</li>"
        $plat = if (@($c.includePlatforms).Count -gt 0) { "include $(@($c.includePlatforms) -join ', ')" + $(if (@($c.excludePlatforms).Count -gt 0) { "; exclude $(@($c.excludePlatforms) -join ', ')" }) } else { 'any' }
        & $w "<li>Platforms: $(& $h $plat)</li>"
        & $w "<li>Locations: $(if (@($c.includeLocations).Count -gt 0) { "include $(& $refList $c.includeLocations); exclude $(& $refList $c.excludeLocations)" } else { 'any' })</li>"
        & $w "<li>Sign-in risk: $(if (@($c.signInRiskLevels).Count -gt 0) { & $h (@($c.signInRiskLevels) -join ', ') } else { 'not configured' })</li>"
        & $w "<li>User risk: $(if (@($c.userRiskLevels).Count -gt 0) { & $h (@($c.userRiskLevels) -join ', ') } else { 'not configured' })</li>"
        if ($c.insiderRiskLevels) { & $w "<li>Insider risk: $(& $h $c.insiderRiskLevels)</li>" }
        if ($c.deviceFilter) { & $w "<li>Device filter ($(& $h $c.deviceFilter.mode)): <code>$(& $h $c.deviceFilter.rule)</code></li>" }
        & $w '</ul>'

        & $w '<h4>Grant controls</h4><ul>'
        if (@($g.builtInControls).Count -eq 0 -and -not $g.authenticationStrength -and @($g.termsOfUse).Count -eq 0) { & $w '<li>None</li>' }
        else {
            & $w "<li>Operator: $(& $h $(if ($g.operator) { $g.operator } else { 'n/a' }))</li>"
            if (@($g.builtInControls).Count -gt 0) { & $w "<li>Controls: $(& $h (@($g.builtInControls) -join ', '))</li>" }
            if ($g.authenticationStrength) {
                $st = $g.authenticationStrength
                $stLabel = & $h $st.name
                if ($st.deleted) { $stLabel = '<span class="deleted">' + $stLabel + '</span>' }
                & $w "<li>Authentication strength: $stLabel"
                if (@($st.allowedCombinations).Count -gt 0) { & $w "<ul><li>Allowed methods: $(& $h (@($st.allowedCombinations) -join '; '))</li></ul>" }
                & $w '</li>'
            }
            if (@($g.termsOfUse).Count -gt 0) { & $w "<li>Terms of use: $(& $h (@($g.termsOfUse) -join ', '))</li>" }
        }
        & $w '</ul>'

        & $w '<h4>Session controls</h4><ul>'
        $sessionItems = [System.Collections.Generic.List[string]]::new()
        if ($se.signInFrequency -and $se.signInFrequency.isEnabled) {
            $sf = $se.signInFrequency
            $sessionItems.Add("Sign-in frequency: $(if ($sf.frequencyInterval -eq 'everyTime') { 'every time' } else { "$($sf.value) $($sf.type)" })")
        }
        if ($se.persistentBrowser -and $se.persistentBrowser.isEnabled) { $sessionItems.Add("Persistent browser: $($se.persistentBrowser.mode)") }
        if ($se.applicationEnforcedRestrictions -and $se.applicationEnforcedRestrictions.isEnabled) { $sessionItems.Add('App-enforced restrictions: enabled') }
        if ($se.cloudAppSecurity -and $se.cloudAppSecurity.isEnabled) { $sessionItems.Add("Defender for Cloud Apps: $($se.cloudAppSecurity.cloudAppSecurityType)") }
        if ($se.continuousAccessEvaluation) { $sessionItems.Add("Continuous access evaluation: $($se.continuousAccessEvaluation.mode)") }
        if ($se.secureSignInSession -and $se.secureSignInSession.isEnabled) { $sessionItems.Add('Token protection: enabled') }
        if ($se.disableResilienceDefaults) { $sessionItems.Add('Resilience defaults: disabled') }
        if ($sessionItems.Count -eq 0) { & $w '<li>None</li>' } else { foreach ($i in $sessionItems) { & $w "<li>$(& $h $i)</li>" } }
        & $w '</ul>'

        & $w '<h4>Health flags</h4><ul>'
        if (@($p.healthFlags).Count -eq 0) { & $w '<li>None</li>' }
        else { foreach ($f in $p.healthFlags) { & $w "<li><span class=`"sev $(& $h $f.severity)`">$(& $h $f.severity)</span> <code>$(& $h $f.code)</code> $(& $h $f.message)</li>" } }
        & $w '</ul>'
        & $w '</article>'
    }
    & $w '</section>'

    # Named locations
    & $w '<section id="locations"><h2>Named locations</h2>'
    if (@($d.namedLocations).Count -eq 0) { & $w '<p>None.</p>' }
    else {
        & $w '<table><thead><tr><th>Name</th><th>Type</th><th>Trusted</th><th>Ranges or countries</th><th>ID</th></tr></thead><tbody>'
        foreach ($l in $d.namedLocations) {
            $type = ([string](Get-PostureValue $l '@odata.type')) -replace '^#microsoft\.graph\.', ''
            $detail = if ($type -eq 'ipNamedLocation') { @(Get-PostureValue $l 'ipRanges' | ForEach-Object { $_.cidrAddress }) -join ', ' } else { @(Get-PostureValue $l 'countriesAndRegions') -join ', ' }
            & $w "<tr><td>$(& $h $l.displayName)</td><td>$(& $h $type)</td><td>$(if (Get-PostureValue $l 'isTrusted') { 'yes' } else { 'no' })</td><td>$(& $h $detail)</td><td><code>$(& $h $l.id)</code></td></tr>"
        }
        & $w '</tbody></table>'
    }
    & $w '</section>'

    # Strengths
    & $w '<section id="strengths"><h2>Authentication strengths</h2>'
    if (@($d.authStrengths).Count -eq 0) { & $w '<p>None.</p>' }
    else {
        & $w '<table><thead><tr><th>Name</th><th>Type</th><th>Allowed combinations</th></tr></thead><tbody>'
        foreach ($st in $d.authStrengths) { & $w "<tr><td>$(& $h $st.displayName)</td><td>$(& $h (Get-PostureValue $st 'policyType'))</td><td>$(& $h (@(Get-PostureValue $st 'allowedCombinations') -join '; '))</td></tr>" }
        & $w '</tbody></table>'
    }
    & $w '</section>'

    # Contexts
    & $w '<section id="contexts"><h2>Authentication context</h2>'
    if (@($d.authContexts).Count -eq 0) { & $w '<p>None.</p>' }
    else {
        & $w '<table><thead><tr><th>ID</th><th>Name</th><th>Description</th><th>Available</th></tr></thead><tbody>'
        foreach ($ctx in $d.authContexts) { & $w "<tr><td><code>$(& $h $ctx.id)</code></td><td>$(& $h $ctx.displayName)</td><td>$(& $h (Get-PostureValue $ctx 'description'))</td><td>$(& $h (Get-PostureValue $ctx 'isAvailable'))</td></tr>" }
        & $w '</tbody></table>'
    }
    & $w '</section>'

    # Appendix
    & $w '<section id="appendix"><h2>Appendix: snapshot</h2><table class="kv"><tbody>'
    foreach ($pair in @(
            @('Snapshot folder', $d.snapshot.path), @('Tenant', $d.snapshot.tenantId), @('Account', $d.snapshot.account)
            @('Scopes', (@($d.snapshot.scopes) -join ', ')), @('Graph API versions', (@($d.snapshot.graphApiVersions) -join ', '))
            @('Module version', $d.snapshot.moduleVersion), @('Exclusion group threshold', $d.options.exclusionGroupThreshold)
            @('Report-only threshold (days)', $d.options.reportOnlyDays), @('Disabled threshold (days)', $d.options.disabledDays)
        )) {
        & $w "<tr><th>$(& $h $pair[0])</th><td>$(& $h $pair[1])</td></tr>"
    }
    & $w '</tbody></table></section>'

    & $w '</main>'
    if ($b.footer) { & $w "<footer class=`"doc`">$(& $h $b.footer)</footer>" }
    & $w '</body>'
    & $w '</html>'
    return $sb.ToString()
}
