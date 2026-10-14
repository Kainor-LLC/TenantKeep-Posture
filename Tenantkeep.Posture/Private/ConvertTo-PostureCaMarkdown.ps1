# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function ConvertTo-PostureCaMarkdown {
    <#
    .SYNOPSIS
        Renders the CA document model (built by New-PostureCaDocument) as Markdown.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Document
    )

    $ErrorActionPreference = 'Stop'
    $sb = [System.Text.StringBuilder]::new()
    $line = { param([string] $Text = '') $null = $sb.AppendLine($Text) }
    $esc = { param([object] $Text) ([string]$Text).Replace('|', '\|').Replace("`r", '').Replace("`n", ' ') }
    $names = { param($Refs) $items = @($Refs | ForEach-Object { if ($null -ne $_.memberCount) { "$($_.name) ($($_.memberCount) members)" } else { $_.name } }); if ($items.Count -eq 0) { 'none' } else { & $esc ($items -join ', ') } }
    $fmtDate = { param($Value) $u = ConvertTo-PostureUtcDateTime $Value; if ($u) { $u.ToString('yyyy-MM-dd HH:mm') + ' UTC' } else { 'unknown' } }
    $table = {
        param([string[]] $Headers, [object[]] $Rows)
        & $line "| $($Headers -join ' | ') |"
        & $line "|$(@($Headers | ForEach-Object { '---' }) -join '|')|"
        foreach ($r in $Rows) { & $line "| $(@($r | ForEach-Object { & $esc $_ }) -join ' | ') |" }
        & $line
    }

    $d = $Document
    $b = $d.brand
    $s = $d.stats

    & $line "# $($d.title)"
    & $line
    $prepared = $b.preparedBy.name
    if ($b.client.name) { $prepared = "$prepared for $($b.client.name)" }
    & $line "Prepared by $prepared. Snapshot taken $(& $fmtDate $d.snapshot.timestampUtc) by $($d.snapshot.account) in tenant ``$($d.snapshot.tenantId)``. Document generated $(& $fmtDate $d.generatedUtc) with Tenantkeep.Posture $($d.snapshot.moduleVersion)."
    if ($b.confidentiality) { & $line; & $line "*$($b.confidentiality)*" }
    & $line

    & $line '## Summary'
    & $line
    & $table -Headers @('Policies', 'Enabled', 'Report-only', 'Disabled', 'Errors', 'Warnings', 'Info') -Rows @(, @($s.total, $s.enabled, $s.reportOnly, $s.disabled, $s.flagsError, $s.flagsWarning, $s.flagsInfo))
    if (@($d.snapshot.errors).Count -gt 0) {
        & $line "**Snapshot errors.** $(@($d.snapshot.errors).Count) collection step(s) failed; see errors.txt in the snapshot folder. Sections that depend on them may be incomplete."
        & $line
    }

    & $line '## Health flags'
    & $line
    $flagRows = foreach ($p in $d.policies) { foreach ($f in @($p.healthFlags)) { , @($p.name, $f.code, $f.severity, $f.message) } }
    if (@($flagRows).Count -eq 0) { & $line 'No health flags.'; & $line }
    else { & $table @('Policy', 'Flag', 'Severity', 'Detail') @($flagRows) }

    & $line '## Policy matrix'
    & $line
    $cols = @($d.matrix.columns)
    $headers = @('Policy') + @($cols | ForEach-Object { $_.label })
    $rows = foreach ($r in $d.matrix.rows) { , (@($r.name) + @($cols | ForEach-Object { $r.cells[$_.key] })) }
    & $table $headers @($rows)

    & $line '## Naming convention'
    & $line
    if ($d.naming) {
        & $line "Pattern: ``$($d.naming.pattern)``. $(@($d.naming.conforming).Count) of $($s.total) policies conform."
        & $line
        if (@($d.naming.nonConforming).Count -gt 0) {
            & $table @('Current name', 'Proposed name') @($d.naming.nonConforming | ForEach-Object { , @($_.name, $_.proposedName) })
            & $line "Proposed names follow ``$($d.naming.format)``; adjust the description part by hand."
            & $line
        }
    }
    else { & $line 'No naming pattern configured. Pass -NamePattern or set caNamePattern in brand.json.'; & $line }

    & $line '## Coverage findings'
    & $line
    if ($d.coverage) {
        $run = $d.coverage.run; $cc = $run.counts
        & $line "Catalog $($run.catalogVersion), baseline $($run.baseline). Pass $($cc.pass), fail $($cc.fail), not evaluated $($cc.notEvaluated), not applicable $($cc.notApplicable), accepted risk $($cc.acceptedRisk), covered by a third party $($cc.coveredBy)."
        & $line
        $statusLabel = @{ pass = 'Pass'; fail = 'Fail'; notEvaluated = 'Not evaluated'; notApplicable = 'Not applicable'; acceptedRisk = 'Accepted risk'; coveredBy = 'Covered by' }
        $rows = foreach ($r in $run.results) {
            $detail = if ($r.affectedCount -gt 0) { (@($r.affected | ForEach-Object { $_.name }) -join ', ') } elseif ($r.reason) { $r.reason } else { '' }
            , @($r.id, $r.title, $statusLabel[$r.status], $r.severity, $detail)
        }
        & $table @('Check', 'Title', 'Status', 'Severity', 'Detail') @($rows)
        $failed = @($run.results | Where-Object { $_.status -eq 'fail' })
        if ($failed.Count -gt 0) {
            & $line '### What to fix'
            & $line
            foreach ($r in $failed) {
                $t = $d.coverage.text[$r.id]
                & $line "**$($r.id) $(& $esc $r.title)** ($($r.severity))"
                & $line
                & $line (& $esc $t.narrative)
                & $line
                & $line "Remediation: $(& $esc $t.remediation) [Learn]($($t.learn))"
                & $line
            }
        }
    }
    else { & $line 'Checks were skipped for this document (-SkipChecks). Run Invoke-PostureChecks on the snapshot for the coverage findings.'; & $line }

    & $line '## Policies'
    & $line
    foreach ($p in $d.policies) {
        $a = $p.assignments; $t = $p.targets; $c = $p.conditions; $g = $p.grant; $se = $p.session
        & $line "### $(& $esc $p.name)"
        & $line
        & $line "**$(& $esc $p.summary)**"
        & $line
        & $table @('Field', 'Value') @(
            , @('ID', $p.id)
            , @('State', $p.stateLabel)
            , @('Created', (& $fmtDate $p.created))
            , @('Last modified', (& $fmtDate $p.modified))
        )
        & $line '#### Assignments'
        & $line
        & $line "- Include users: $(& $names $a.includeUsers)"
        & $line "- Exclude users: $(& $names $a.excludeUsers)"
        & $line "- Include groups: $(& $names $a.includeGroups)"
        & $line "- Exclude groups: $(& $names $a.excludeGroups)"
        & $line "- Include roles: $(& $names $a.includeRoles)"
        & $line "- Exclude roles: $(& $names $a.excludeRoles)"
        if ($a.includeGuestsOrExternal) { & $line "- Include guests or external users: $(& $esc (@($a.includeGuestsOrExternal.guestOrExternalUserTypes) -join ', '))" }
        if ($a.excludeGuestsOrExternal) { & $line "- Exclude guests or external users: $(& $esc (@($a.excludeGuestsOrExternal.guestOrExternalUserTypes) -join ', '))" }
        if (@($a.includeServicePrincipals).Count -gt 0 -or @($a.excludeServicePrincipals).Count -gt 0) {
            & $line "- Include workload identities: $(& $names $a.includeServicePrincipals)"
            & $line "- Exclude workload identities: $(& $names $a.excludeServicePrincipals)"
        }
        & $line
        & $line '#### Target resources'
        & $line
        & $line "- Include apps: $(& $names $t.includeApplications)"
        & $line "- Exclude apps: $(& $names $t.excludeApplications)"
        if (@($t.userActions).Count -gt 0) { & $line "- User actions: $(& $names $t.userActions)" }
        if (@($t.authenticationContexts).Count -gt 0) { & $line "- Authentication context: $(& $names $t.authenticationContexts)" }
        if ($t.applicationFilter) { & $line "- Application filter ($($t.applicationFilter.mode)): ``$(& $esc $t.applicationFilter.rule)``" }
        & $line
        & $line '#### Conditions'
        & $line
        & $line "- Client app types: $(if (@($c.clientAppTypes).Count -gt 0) { @($c.clientAppTypes) -join ', ' } else { 'not configured' })"
        & $line "- Platforms: $(if (@($c.includePlatforms).Count -gt 0) { "include $(@($c.includePlatforms) -join ', ')" + $(if (@($c.excludePlatforms).Count -gt 0) { "; exclude $(@($c.excludePlatforms) -join ', ')" }) } else { 'any' })"
        & $line "- Locations: $(if (@($c.includeLocations).Count -gt 0) { "include $(& $names $c.includeLocations); exclude $(& $names $c.excludeLocations)" } else { 'any' })"
        & $line "- Sign-in risk: $(if (@($c.signInRiskLevels).Count -gt 0) { @($c.signInRiskLevels) -join ', ' } else { 'not configured' })"
        & $line "- User risk: $(if (@($c.userRiskLevels).Count -gt 0) { @($c.userRiskLevels) -join ', ' } else { 'not configured' })"
        if ($c.insiderRiskLevels) { & $line "- Insider risk: $(& $esc $c.insiderRiskLevels)" }
        if ($c.deviceFilter) { & $line "- Device filter ($($c.deviceFilter.mode)): ``$(& $esc $c.deviceFilter.rule)``" }
        & $line
        & $line '#### Grant controls'
        & $line
        if (@($g.builtInControls).Count -eq 0 -and -not $g.authenticationStrength -and @($g.termsOfUse).Count -eq 0) { & $line '- None' }
        else {
            & $line "- Operator: $(if ($g.operator) { $g.operator } else { 'n/a' })"
            if (@($g.builtInControls).Count -gt 0) { & $line "- Controls: $(@($g.builtInControls) -join ', ')" }
            if ($g.authenticationStrength) {
                & $line "- Authentication strength: $(& $esc $g.authenticationStrength.name)"
                if (@($g.authenticationStrength.allowedCombinations).Count -gt 0) { & $line "  - Allowed methods: $(@($g.authenticationStrength.allowedCombinations) -join '; ')" }
            }
            if (@($g.termsOfUse).Count -gt 0) { & $line "- Terms of use: $(@($g.termsOfUse) -join ', ')" }
        }
        & $line
        & $line '#### Session controls'
        & $line
        $sessionLines = [System.Collections.Generic.List[string]]::new()
        if ($se.signInFrequency -and $se.signInFrequency.isEnabled) {
            $sf = $se.signInFrequency
            $sessionLines.Add("- Sign-in frequency: $(if ($sf.frequencyInterval -eq 'everyTime') { 'every time' } else { "$($sf.value) $($sf.type)" })")
        }
        if ($se.persistentBrowser -and $se.persistentBrowser.isEnabled) { $sessionLines.Add("- Persistent browser: $($se.persistentBrowser.mode)") }
        if ($se.applicationEnforcedRestrictions -and $se.applicationEnforcedRestrictions.isEnabled) { $sessionLines.Add('- App-enforced restrictions: enabled') }
        if ($se.cloudAppSecurity -and $se.cloudAppSecurity.isEnabled) { $sessionLines.Add("- Defender for Cloud Apps: $($se.cloudAppSecurity.cloudAppSecurityType)") }
        if ($se.continuousAccessEvaluation) { $sessionLines.Add("- Continuous access evaluation: $($se.continuousAccessEvaluation.mode)") }
        if ($se.secureSignInSession -and $se.secureSignInSession.isEnabled) { $sessionLines.Add('- Token protection: enabled') }
        if ($se.disableResilienceDefaults) { $sessionLines.Add('- Resilience defaults: disabled') }
        if ($sessionLines.Count -eq 0) { & $line '- None' } else { foreach ($l in $sessionLines) { & $line $l } }
        & $line
        & $line '#### Health flags'
        & $line
        if (@($p.healthFlags).Count -eq 0) { & $line '- None' }
        else { foreach ($f in $p.healthFlags) { & $line "- **$($f.severity)** ``$($f.code)``: $(& $esc $f.message)" } }
        & $line
    }

    & $line '## Named locations'
    & $line
    if (@($d.namedLocations).Count -eq 0) { & $line 'None.'; & $line }
    else {
        $rows = foreach ($l in $d.namedLocations) {
            $type = ([string](Get-PostureValue $l '@odata.type')) -replace '^#microsoft\.graph\.', ''
            $detail = if ($type -eq 'ipNamedLocation') { @(Get-PostureValue $l 'ipRanges' | ForEach-Object { $_.cidrAddress }) -join ', ' } else { @(Get-PostureValue $l 'countriesAndRegions') -join ', ' }
            , @($l.displayName, $type, $(if (Get-PostureValue $l 'isTrusted') { 'yes' } else { 'no' }), $detail, $l.id)
        }
        & $table @('Name', 'Type', 'Trusted', 'Ranges or countries', 'ID') @($rows)
    }

    & $line '## Authentication strengths'
    & $line
    if (@($d.authStrengths).Count -eq 0) { & $line 'None.'; & $line }
    else { & $table @('Name', 'Type', 'Allowed combinations') @($d.authStrengths | ForEach-Object { , @($_.displayName, (Get-PostureValue $_ 'policyType'), (@(Get-PostureValue $_ 'allowedCombinations') -join '; ')) }) }

    & $line '## Authentication context'
    & $line
    if (@($d.authContexts).Count -eq 0) { & $line 'None.'; & $line }
    else { & $table @('ID', 'Name', 'Description', 'Available') @($d.authContexts | ForEach-Object { , @($_.id, $_.displayName, (Get-PostureValue $_ 'description'), (Get-PostureValue $_ 'isAvailable')) }) }

    & $line '## Appendix: snapshot'
    & $line
    & $table @('Field', 'Value') @(
        , @('Snapshot folder', $d.snapshot.path)
        , @('Tenant', $d.snapshot.tenantId)
        , @('Account', $d.snapshot.account)
        , @('Scopes', (@($d.snapshot.scopes) -join ', '))
        , @('Graph API versions', (@($d.snapshot.graphApiVersions) -join ', '))
        , @('Module version', $d.snapshot.moduleVersion)
        , @('Exclusion group threshold', $d.options.exclusionGroupThreshold)
        , @('Report-only threshold (days)', $d.options.reportOnlyDays)
        , @('Disabled threshold (days)', $d.options.disabledDays)
    )
    if ($b.footer) { & $line '---'; & $line; & $line $b.footer }

    return $sb.ToString()
}
