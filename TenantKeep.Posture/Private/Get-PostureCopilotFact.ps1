# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureCopilotFact {
    <#
    .SYNOPSIS
        Fact provider for the copilot domain (spec 4.7): the readiness gates, read from the evidence the other
        collectors already wrote. Audit log, SharePoint Advanced Management licence, sharing defaults, labels,
        restricted access control on the top tier, restricted search, access reviews and packages, DLP for the
        Copilot location, ownerless sites, and the deployed-ahead-of-baseline status.
    .DESCRIPTION
        The gates with no collector yet (oversharing baseline from the SAM reports, restricted content discovery, site
        access reviews, DSPM for AI, Copilot settings) come back not evaluated with the reason. The label inheritance
        test is a profile answer (operations.copilotLabelInheritanceTestedUtc). Profile read: licenses, copilot,
        operations. Thresholds read: anonymousLinkMaxDays.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [Parameter()] [System.Collections.IDictionary] $OrgProfile = @{},
        [Parameter()] [System.Collections.IDictionary] $Thresholds = @{},
        [datetime] $AsOf = [datetime]::UtcNow
    )

    $ErrorActionPreference = 'Stop'
    $t = @{ anonymousLinkMaxDays = 30 }
    foreach ($k in @($Thresholds.Keys)) { $t[$k] = $Thresholds[$k] }
    # Parsed once per evaluation and shared with the other domains (Read-PostureEvidenceFile); a missing file is
    # $null, an empty one an empty array.
    $load = {
        param([string] $Name)
        $parsed = Read-PostureEvidenceFile -Folder $Evidence -Name $Name
        if ($null -eq $parsed) { return $null }
        if ($parsed -is [array] -and $parsed.Count -eq 0) { return , @() }
        return $parsed
    }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $rows = { param($o) @($o | Where-Object { $_ }) }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    $lic = @($OrgProfile['licenses'] | Where-Object { $_ })
    $ops = $(if ($OrgProfile.Contains('operations') -and $OrgProfile['operations']) { $OrgProfile['operations'] } else { @{} })

    $spoRead = Read-PostureSharePointSetting -Evidence $Evidence
    $spo = $(if ($spoRead) { $spoRead.settings } else { $null }); $audit = & $load 'exo-01-audit-config'; $labels = & $load 'pv-01-sensitivity-labels'
    if ($null -eq $spo -and $null -eq $audit -and $null -eq $labels) { return @{ available = $false; reason = 'No SharePoint, Exchange or Purview evidence in the folder; the Copilot gates read all three.' } }

    # C1 audit log
    if ($null -eq $audit) { $notEvaluated['CP-001'] = 'exo-01-audit-config.json was not collected (Exchange collector).' }
    else { $facts.auditLogEnabled = (& $v $audit 'UnifiedAuditLogIngestionEnabled') -eq $true }

    # C2 SAM, C17 deployed ahead
    $facts.samLicensed = [bool](@($lic | Where-Object { $_ -eq 'SAM' }).Count -gt 0)
    $facts.copilotLicensed = [bool](@($lic | Where-Object { $_ -eq 'Copilot' }).Count -gt 0)
    $facts.copilotStatus = [string]$(if ($OrgProfile.Contains('copilot')) { $OrgProfile['copilot'] })
    if (@($lic).Count -eq 0) { $notEvaluated['CP-002'] = 'No licences in the profile; run New-PostureProfile -Evidence to discover them.' }

    # C3 oversharing baseline and C17 deployed-ahead read the data access governance reports the admin downloads into the
    # client folder (imports/sam-dag); C10, C14 and C15 have no read API and read a dated attestation from the profile
    # (profile.attestations, recorded with Set-PostureAttestation; the check's panel copies the command). Nothing here is guessed.
    $maxAge = [int]$(if ($t.Contains('attestationMaxDays')) { $t.attestationMaxDays } else { 90 })
    $baselineMax = [int]$(if ($t.Contains('oversharingBaselineMaxDays')) { $t.oversharingBaselineMaxDays } else { 90 })
    $clientFolder = $(if ($OrgProfile.Contains('path') -and $OrgProfile['path']) { Split-Path -Parent ([string]$OrgProfile['path']) } else { $null })
    $importFolder = $(if ($clientFolder) { Join-Path $clientFolder 'imports' 'sam-dag' } else { $null })
    $reports = @($(if ($importFolder -and (Test-Path -LiteralPath $importFolder)) { Get-ChildItem -LiteralPath $importFolder -File | Where-Object { $_.Extension -in '.csv', '.xlsx', '.json' } }))
    $facts.overSharingBaselineRecent = $false; $facts.samReportCount = $reports.Count
    if ($reports.Count -eq 0) {
        $where = $(if ($importFolder) { $importFolder } else { 'the client folder (no profile.json path known)' })
        $notEvaluated['CP-003'] = "No data access governance report found. In the SharePoint admin center, run the Data access governance reports and save the downloaded CSV files into $where; the next run reads the newest one."
        $notEvaluated['CP-017'] = "Deployed-ahead cannot be dated without the oversharing baseline (see C3); Copilot status in the profile is '$([string]$(if ($OrgProfile.Contains('copilot')) { $OrgProfile['copilot'] }))'."
    }
    else {
        # The report's date: from the file name when it carries one (yyyy-MM-dd or yyyyMMdd), else when the file was written.
        $dates = foreach ($f in $reports) { $m = [regex]::Match($f.Name, '(20\d{2})[-_]?(\d{2})[-_]?(\d{2})'); if ($m.Success) { try { [datetime]::new([int]$m.Groups[1].Value, [int]$m.Groups[2].Value, [int]$m.Groups[3].Value, 0, 0, 0, [System.DateTimeKind]::Utc) } catch { $f.LastWriteTimeUtc } } else { $f.LastWriteTimeUtc } }
        $newest = ($dates | Sort-Object -Descending | Select-Object -First 1)
        $facts.overSharingBaselineRunUtc = $newest.ToString('o'); $facts.overSharingBaselineAgeDays = [int]([datetime]::UtcNow - $newest).TotalDays
        $facts.overSharingBaselineRecent = $facts.overSharingBaselineAgeDays -le $baselineMax
    }
    $notEvaluated['CP-008'] = 'Restricted content discovery per site is not collected yet (verify the PnP site property).'
    $facts.pendingSitesWithoutRcd = 0
    $att = $(if ($OrgProfile.Contains('attestations') -and $OrgProfile['attestations']) { $OrgProfile['attestations'] } else { @{} })
    $attested = { param([string] $key) $d = ConvertTo-PostureUtcDateTime $(if ($att.Contains($key)) { $att[$key] } else { $null }); if ($d) { ([datetime]::UtcNow - $d).TotalDays -le $maxAge } else { $null } }
    foreach ($pair in @(@('CP-010', 'siteAccessReviewsStartedUtc', 'siteAccessReviewsStarted', 'Record the date site access reviews were started from the data access governance reports (Set-PostureAttestation; this check''s panel copies the command).'), @('CP-014', 'dspmReviewedUtc', 'dspmReviewed', 'DSPM for AI has no read API. Record the date it was reviewed (Set-PostureAttestation; this check''s panel copies the command).'), @('CP-015', 'copilotSettingsReviewedUtc', 'copilotSettingsGoverned', 'Copilot admin settings have no read API yet. Record the date they were reviewed (Set-PostureAttestation; this check''s panel copies the command).'))) {
        $ok = & $attested $pair[1]
        if ($null -eq $ok) { $notEvaluated[$pair[0]] = $pair[3]; $facts[$pair[2]] = $false }
        else { $facts[$pair[2]] = [bool]$ok; if (-not $ok) { $facts["$($pair[2])Stale"] = $true } }
    }

    # C4, C5, C9 from SharePoint
    $adminRead = 'It needs the SharePoint admin read: the TenantKeep SharePoint app for named admins (deploy/setup/Grant-PostureSharePointAccess.ps1), or the Windows collector (collectors/windows/Get-SpoBaseline.ps1) brought in with Import-PostureEvidence.'
    if ($null -eq $spo) { foreach ($id in 'CP-004', 'CP-005', 'CP-009') { $notEvaluated[$id] = 'No SharePoint settings were collected: the Entra collector reads them through Graph (SharePointTenantSettings.Read.All); check errors.txt.' } }
    elseif ($spoRead.source -eq 'graph') {
        # Graph has the tenant sharing level, so Anyone links answer when the tenant rules them out; the rest does not.
        if ([string](& $v $spo 'SharingCapability') -ne 'ExternalUserAndGuestSharing') { $facts.anonymousLinksControlled = $true }
        else { $notEvaluated['CP-005'] = "Graph's SharePoint settings do not include the Anyone link expiry. $adminRead" }
        $notEvaluated['CP-004'] = "Graph's SharePoint settings do not include the default sharing link. $adminRead"
        $notEvaluated['CP-009'] = "Graph does not report Restricted SharePoint Search. $adminRead"
    }
    else {
        $facts.defaultLinkSpecificPeople = [string](& $v $spo 'DefaultSharingLinkType') -eq 'Direct'
        $cap = [string](& $v $spo 'SharingCapability'); $days = & $v $spo 'RequireAnonymousLinksExpireInDays'
        $facts.anonymousLinksControlled = ($cap -ne 'ExternalUserAndGuestSharing') -or ($null -ne $days -and [int]$days -ge 1 -and [int]$days -le [int]$t.anonymousLinkMaxDays)
        $search = & $load 'spo-restricted-search'
        if ($null -eq $search) { $notEvaluated['CP-009'] = 'spo-restricted-search.json was not collected: run the SharePoint collector again, which now reads the restricted search mode.' }
        else {
            $mode = [string](& $v $search 'Mode')
            $facts.restrictedSearchMode = $mode
            $facts.restrictedSearchAllowListSites = [int](& $v $search 'AllowedSites')
            if ([string]::IsNullOrWhiteSpace($mode)) { $notEvaluated['CP-009'] = 'spo-restricted-search.json holds no mode: run the SharePoint collector again.' }
            else {
                # PnP answers Disabled, Enabled, or on a tenant that never set it "Restricted search mode is currently not set.", which is off.
                # Off is the end state; on with an allow list is the stopgap and passes; on with an empty list blocks search for everyone and is a finding.
                $on = $mode -match '(?i)\b(enabled|on)\b'
                $facts.restrictedSearchOk = (-not $on) -or $facts.restrictedSearchAllowListSites -gt 0
            }
        }
    }

    # C6 labels, C7 RAC on the top tier, C18 ownerless
    # Whether the site list was collected; its rows are read a row at a time where a check needs them.
    $sitesCollected = (Test-Path -LiteralPath (Join-Path $Evidence 'spo-sites.json')) -or (Test-Path -LiteralPath (Join-Path $Evidence 'spo-sites.csv')); $siteSummary = & $load 'spo-sites-summary'
    if ($null -eq $labels) { foreach ($id in 'CP-006', 'CP-007') { $notEvaluated[$id] = 'pv-01-sensitivity-labels.json was not collected (Purview collector).' } }
    else {
        $l = @(& $rows $labels | Where-Object { $_.Disabled -ne $true })
        $policies = & $load 'pv-01-label-policies'
        # No labels is not published; labels with the policies not collected is unknown.
        $facts.labelsPublished = $(if ($l.Count -eq 0) { $false } elseif ($null -eq $policies) { $null } else { @(& $rows $policies | Where-Object { $_.Enabled -ne $false }).Count -gt 0 })
        $settings = { param($x) (@(@(Get-PostureValue $x 'Settings') | ForEach-Object { [string]$_ }) -join ' ') }   # Settings is absent on older collections
        $encrypting = @($l | Where-Object { $_.EncryptionEnabled -eq $true -or (& $settings $_) -match '(?i)\[encryptionenabled, ?true\]' })
        $facts.encryptingLabels = $encrypting.Count
        $facts.containerLabels = @($l | Where-Object { $_.SiteAndGroupProtectionEnabled -eq $true -or (& $settings $_) -match '(?i)\[siteandgroupprotectionenabled, ?true\]' -or [string](Get-PostureValue $_ 'ContentType') -match '(?i)Site|UnifiedGroup' }).Count
        # Top tier: the encrypting label with the highest priority number (Purview orders them low to high).
        $top = @($encrypting | Sort-Object { [int]$_.Priority } -Descending | Select-Object -First 1)
        $facts.topTierLabel = $(if ($top.Count -gt 0) { [string]$top[0].DisplayName } else { $null })
        if (-not $sitesCollected) { $notEvaluated['CP-007'] = 'spo-sites.json was not collected (SharePoint collector without -SkipSiteEnumeration).' }
        elseif ($top.Count -eq 0) { $notEvaluated['CP-007'] = 'No encrypting sensitivity label defines a top tier yet (C6).' }
        else {
            # A row at a time: only the sites carrying the top-tier label are kept.
            $topSites = [System.Collections.Generic.List[object]]::new()
            $null = Read-PostureEvidenceRow -Folder $Evidence -Name 'spo-sites' -OnRow { param($_row) if (-not (Test-PostureTrue $_row.IsOneDrive) -and ([string]$_row.SensitivityLabel -eq [string]$top[0].Guid -or [string]$_row.SensitivityLabel -eq [string]$top[0].DisplayName)) { $topSites.Add($_row) } }
            $facts.topTierSites = $topSites.Count
            $noRac = @($topSites | Where-Object { -not (Test-PostureTrue $_.RestrictedAccessControl) })
            $facts.topTierSitesWithoutRac = $noRac.Count
            $affected.topTierSitesWithoutRac = @($noRac | ForEach-Object { [ordered]@{ name = [string]$_.Url; detail = "labeled $($top[0].DisplayName), restricted access control off" } })
        }
    }
    if ($null -eq $siteSummary) { $notEvaluated['CP-018'] = 'spo-sites-summary.json was not collected (SharePoint collector).' }
    else { $facts.ownerlessSites = [int](& $v $siteSummary 'Ownerless') }

    # C11, C12 from governance evidence
    $reviews = & $load 'gov-01-access-reviews'
    if ($null -eq $reviews) { $notEvaluated['CP-011'] = 'gov-01-access-reviews.json was not collected (Entra collector; AccessReview.Read.All).' }
    else {
        $active = @(& $rows $reviews | Where-Object { $_.Recurring -eq $true -and [string]$_.Status -notin @('Completed', 'Canceled') })
        $facts.recurringRoleReviews = @($active | Where-Object { [string]$_.ScopeQuery -match 'roleManagement/directory|privilegedAccess|roleAssignment' }).Count
        $facts.recurringGuestReviews = @($active | Where-Object { [string]$_.ScopeQuery -match "userType eq 'Guest'|userType eq ''Guest''|/guest" }).Count
        $facts.recurringReviewsOk = $facts.recurringRoleReviews -gt 0 -and $facts.recurringGuestReviews -gt 0
    }
    $packages = & $load 'gov-02-access-packages-summary'
    if ($null -eq $packages) { $notEvaluated['CP-012'] = 'gov-02-access-packages-summary.json was not collected (Entra collector; EntitlementManagement.Read.All).' }
    else { $facts.accessPackages = [int](& $v $packages 'Packages') }

    # C13 DLP for the Copilot location. (verify) how Get-DlpCompliancePolicy exposes the Microsoft 365 Copilot location
    $dlp = & $load 'pv-02-dlp-policies'
    if ($null -eq $dlp) { $notEvaluated['CP-013'] = 'pv-02-dlp-policies.json was not collected (Purview collector).' }
    else {
        # Microsoft Learn (New-DlpCompliancePolicy, 2026-11-21): the Copilot location is workload Applications, location
        # 470f2276-e011-4e9d-a6ec-20768be3a4b0, enforcement plane CopilotExperiences. The location id or the plane decides when
        # the evidence carries them (verify that Get-DlpCompliancePolicy returns Locations and EnforcementPlanes); older
        # evidence falls back to the Applications workload, seen on a live tenant 2026-10-15, or a value naming Copilot.
        $copilotId = '470f2276-e011-4e9d-a6ec-20768be3a4b0'
        $copilotDlp = @(& $rows $dlp | Where-Object { $_.Enabled -ne $false -and [string]$_.Mode -match '(?i)^Enable' } | Where-Object {
                $located = (@(Get-PostureValue $_ 'Locations') -join ' ') + ' ' + (@(Get-PostureValue $_ 'EnforcementPlanes') -join ' ')
                if ($located.Trim()) { $located -match "(?i)$copilotId|CopilotExperiences" }
                else { [string]$_.Workload -match '(?i)Applications' -or (@($_.Values | ForEach-Object { [string]$_ }) -join ' ') -match '(?i)copilot' }
            })
        $facts.dlpPoliciesForCopilot = $copilotDlp.Count
    }

    # C16 label inheritance test from the profile
    $tested = ConvertTo-PostureUtcDateTime $(if ($ops.Contains('copilotLabelInheritanceTestedUtc')) { $ops['copilotLabelInheritanceTestedUtc'] })
    $facts.labelInheritanceTested = [bool]$tested
    if (-not $OrgProfile['present']) { $notEvaluated['CP-016'] = 'No profile; the label inheritance test is recorded there.' }

    # Roll-up for the report: hard gates and readiness. The engine sets statuses; this is the summary the page leads with.
    $facts.hardGates = @('CP-001', 'CP-002', 'CP-003', 'CP-004', 'CP-006')

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('spo-tenant-settings.json', 'pv-01-sensitivity-labels.json', 'exo-01-audit-config.json') }
}
