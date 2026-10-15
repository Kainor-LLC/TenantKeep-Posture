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
    $load = {
        param([string] $Name)
        $f = Join-Path $Evidence "$Name.json"
        if (-not (Test-Path -LiteralPath $f)) { return $null }
        $text = Get-Content -Raw -LiteralPath $f
        if ([string]::IsNullOrWhiteSpace($text)) { return , @() }
        $parsed = ConvertFrom-Json -InputObject $text -AsHashtable -Depth 20
        if ($null -eq $parsed) { return , @() }
        return $parsed
    }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $rows = { param($o) @($o | Where-Object { $_ }) }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    $lic = @($OrgProfile['licenses'] | Where-Object { $_ })
    $ops = $(if ($OrgProfile.Contains('operations') -and $OrgProfile['operations']) { $OrgProfile['operations'] } else { @{} })

    $spo = & $load 'spo-tenant-settings'; $audit = & $load 'exo-01-audit-config'; $labels = & $load 'pv-01-sensitivity-labels'
    if ($null -eq $spo -and $null -eq $audit -and $null -eq $labels) { return @{ available = $false; reason = 'No SharePoint, Exchange or Purview evidence in the folder; the Copilot gates read all three.' } }

    # C1 audit log
    if ($null -eq $audit) { $notEvaluated['CP-001'] = 'exo-01-audit-config.json was not collected (Exchange collector).' }
    else { $facts.auditLogEnabled = (& $v $audit 'UnifiedAuditLogIngestionEnabled') -eq $true }

    # C2 SAM, C17 deployed ahead
    $facts.samLicensed = [bool](@($lic | Where-Object { $_ -eq 'SAM' }).Count -gt 0)
    $facts.copilotLicensed = [bool](@($lic | Where-Object { $_ -eq 'Copilot' }).Count -gt 0)
    $facts.copilotStatus = [string]$(if ($OrgProfile.Contains('copilot')) { $OrgProfile['copilot'] })
    if (@($lic).Count -eq 0) { $notEvaluated['CP-002'] = 'No licences in the profile; run New-PostureProfile -Evidence to discover them.' }

    # C3 oversharing baseline, C8 restricted content discovery, C10 site access reviews, C14 DSPM, C15 settings: no collector yet
    $notEvaluated['CP-003'] = 'The data access governance reports (SharePoint Advanced Management) are not collected yet; run the oversharing baseline in the SharePoint admin center and import it.'
    $notEvaluated['CP-008'] = 'Restricted content discovery per site is not collected yet (verify the PnP site property).'
    $notEvaluated['CP-017'] = "The oversharing baseline is not collected yet, so deployed-ahead cannot be dated; Copilot status in the profile is '$([string]$(if ($OrgProfile.Contains('copilot')) { $OrgProfile['copilot'] }))'."
    $facts.overSharingBaselineRecent = $false
    $facts.pendingSitesWithoutRcd = 0
    $notEvaluated['CP-010'] = 'Site access reviews initiated from the data access governance reports are not collected yet.'
    $notEvaluated['CP-014'] = 'DSPM for AI has no read API; record the review as portal evidence.'
    $notEvaluated['CP-015'] = 'Copilot admin settings (web grounding, agents, connectors) have no read API yet (verify).'

    # C4, C5, C9 from SharePoint
    if ($null -eq $spo) { foreach ($id in 'CP-004', 'CP-005', 'CP-009') { $notEvaluated[$id] = 'spo-tenant-settings.json was not collected (SharePoint collector).' } }
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
            # Off is the end state; on with an allow list is the stopgap and passes; on with an empty list blocks search for everyone and is a finding.
            $facts.restrictedSearchOk = ($mode -match '(?i)disabled|off') -or $facts.restrictedSearchAllowListSites -gt 0
        }
    }

    # C6 labels, C7 RAC on the top tier, C18 ownerless
    $sites = & $load 'spo-sites'; $siteSummary = & $load 'spo-sites-summary'
    if ($null -eq $labels) { foreach ($id in 'CP-006', 'CP-007') { $notEvaluated[$id] = 'pv-01-sensitivity-labels.json was not collected (Purview collector).' } }
    else {
        $l = @(& $rows $labels | Where-Object { $_.Disabled -ne $true })
        $policies = & $load 'pv-01-label-policies'
        $facts.labelsPublished = ($l.Count -gt 0) -and ($null -ne $policies -and @(& $rows $policies | Where-Object { $_.Enabled -ne $false }).Count -gt 0)
        $settings = { param($x) (@(@(Get-PostureValue $x 'Settings') | ForEach-Object { [string]$_ }) -join ' ') }   # Settings is absent on older collections
        $encrypting = @($l | Where-Object { $_.EncryptionEnabled -eq $true -or (& $settings $_) -match '(?i)\[encryptionenabled, ?true\]' })
        $facts.encryptingLabels = $encrypting.Count
        $facts.containerLabels = @($l | Where-Object { $_.SiteAndGroupProtectionEnabled -eq $true -or (& $settings $_) -match '(?i)\[siteandgroupprotectionenabled, ?true\]' -or [string](Get-PostureValue $_ 'ContentType') -match '(?i)Site|UnifiedGroup' }).Count
        # Top tier: the encrypting label with the highest priority number (Purview orders them low to high).
        $top = @($encrypting | Sort-Object { [int]$_.Priority } -Descending | Select-Object -First 1)
        $facts.topTierLabel = $(if ($top.Count -gt 0) { [string]$top[0].DisplayName } else { $null })
        if ($null -eq $sites) { $notEvaluated['CP-007'] = 'spo-sites.json was not collected (SharePoint collector without -SkipSiteEnumeration).' }
        elseif ($top.Count -eq 0) { $notEvaluated['CP-007'] = 'No encrypting sensitivity label defines a top tier yet (C6).' }
        else {
            $topSites = @(& $rows $sites | Where-Object { -not $_.IsOneDrive -and ([string]$_.SensitivityLabel -eq [string]$top[0].Guid -or [string]$_.SensitivityLabel -eq [string]$top[0].DisplayName) })
            $facts.topTierSites = $topSites.Count
            $noRac = @($topSites | Where-Object { $_.RestrictedAccessControl -ne $true })
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
        # The Copilot location shows as the Applications workload on a live tenant (2026-10-15); a value naming Copilot counts too.
        $copilotDlp = @(& $rows $dlp | Where-Object { $_.Enabled -ne $false -and [string]$_.Mode -match '(?i)^Enable' } | Where-Object { [string]$_.Workload -match '(?i)Applications' -or (@($_.Values | ForEach-Object { [string]$_ }) -join ' ') -match '(?i)copilot' })
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
