# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureOperationsFact {
    <#
    .SYNOPSIS
        Fact provider for the operations domain (spec 4.9 and the scores of 4.12): SIEM and backup decisions, the
        break-glass test and Message Center owner from the profile's operations answers, Secure Score against
        Microsoft's comparative average, and the expiry calendar built from the evidence already collected.
    .DESCRIPTION
        The expiry calendar gathers everything with a date: application credentials (10-app-registrations), SAML
        signing certificates (10-service-principals), the Apple push certificate, VPP tokens and ADE tokens
        (09-apple-*), trial subscriptions and subscriptions in their grace period (01-subscriptions). Thresholds
        read: expiryWarningDays, breakGlassTestMaxDays, maxSecureScoreDropPoints. Profile read: thirdParty.siem, thirdParty.backup,
        operations.breakGlassTestedUtc, operations.messageCenterOwner. Entra Connect Health waits for the Azure collector.
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
    $t = @{ expiryWarningDays = 30; breakGlassTestMaxDays = 180; maxSecureScoreDropPoints = 5; messageCenterWarningDays = 30 }
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
    # Checks judged on part of the data: the engine turns a pass into no answer and puts a note on a fail.
    $partial = @{}

    # Answers from the profile (the questionnaire half: nothing in the tenant says who owns the Message Center).
    $present = [bool]$OrgProfile['present']
    $third = $(if ($OrgProfile.Contains('thirdParty') -and $OrgProfile['thirdParty']) { $OrgProfile['thirdParty'] } else { @{} })
    $ops = $(if ($OrgProfile.Contains('operations') -and $OrgProfile['operations']) { $OrgProfile['operations'] } else { @{} })
    $siem = [string]$(if ($third.Contains('siem')) { $third['siem'] })
    $backup = [string]$(if ($third.Contains('backup')) { $third['backup'] })
    $facts.siemVendor = $siem
    $facts.siemInPlace = [bool]($siem -and $siem -ne 'none')
    $facts.backupDecision = $backup
    $facts.backupDecisionRecorded = [bool]($backup -and $backup -ne 'none')
    $tested = ConvertTo-PostureUtcDateTime $(if ($ops.Contains('breakGlassTestedUtc')) { $ops['breakGlassTestedUtc'] })
    $facts.breakGlassTestedUtc = $(if ($tested) { $tested.ToString('o') } else { $null })
    $facts.breakGlassTestAgeDays = $(if ($tested) { [int][Math]::Floor(($AsOf - $tested).TotalDays) } else { $null })
    $facts.breakGlassTestedRecently = [bool]($tested -and $facts.breakGlassTestAgeDays -le [int]$t.breakGlassTestMaxDays)
    $owner = [string]$(if ($ops.Contains('messageCenterOwner')) { $ops['messageCenterOwner'] })
    $facts.messageCenterOwner = $owner
    $facts.messageCenterOwnerNamed = [bool]$owner
    if (-not $present) { foreach ($id in 'OP-001', 'OP-002', 'OP-003', 'OP-004') { $notEvaluated[$id] = 'No profile: the operations answers (SIEM, backup, break-glass test, Message Center owner) come from New-PostureProfile.' } }

    # Microsoft 365 Backup (OP-008), read by the Azure collector: on, and protecting all three workloads.
    $mb = & $load 'az-11-m365-backup'
    if ($null -eq $mb) {
        # A run that tried and was refused with the permission in hand has nothing to grant; say that, not "grant".
        $backupRefused = @(Read-PostureRunFailure -Folder $Evidence | Where-Object { $_ -and [string]$_['step'] -eq 'Microsoft 365 Backup' -and [string]$_['cause'] -eq 'notReadable' }).Count -gt 0
        $notEvaluated['OP-008'] = $(if ($backupRefused) { 'Microsoft 365 Backup could not be read with this sign-in (Run Health says why). A backup product named in the profile covers this check.' } else { 'az-11-m365-backup.json was not collected (the Azure collector reads it; set the profile''s azure answer and grant BackupRestore-Configuration.Read.All).' })
    }
    else {
        # The service's status is behind a permission the module does not ask for. When it was not read it is unknown:
        # the policies alone fail the check when a workload has none, and the check has no answer when all three have.
        $backupStatus = [string](& $v $mb 'ServiceStatus')
        $facts.m365BackupEnabled = $(if ($backupStatus) { $backupStatus -eq 'enabled' } else { $null })
        $facts.m365BackupWorkloadsProtected = @('SharePointPolicies', 'OneDrivePolicies', 'ExchangePolicies' | Where-Object { [int](& $v $mb $_) -gt 0 }).Count
    }

    # Secure Score against the comparative average (OP-005)
    $ss = & $load 'def-06-secure-score'
    if ($null -eq $ss -or (& $v $ss 'Present') -ne $true) { $notEvaluated['OP-005'] = 'def-06-secure-score.json was not collected (Invoke-PostureCollection -Collector Defender; needs SecurityEvents.Read.All).' }
    else {
        $facts.secureScore = [double](& $v $ss 'CurrentScore'); $facts.secureScoreMax = [double](& $v $ss 'MaxScore')
        $facts.secureScorePct = $(if ($facts.secureScoreMax -gt 0) { [Math]::Round(100.0 * $facts.secureScore / $facts.secureScoreMax, 1) } else { $null })
        $avg = @(& $rows (& $v $ss 'AverageComparativeScores') | Where-Object { [string]$_.Basis -eq 'AllTenants' } | Select-Object -First 1)
        $facts.secureScoreAllTenantsAverage = $(if ($avg.Count -gt 0) { [double]$avg[0].AverageScore } else { $null })
        # Microsoft's comparative averages read as a percentage of the maximum (54.04 against a score of 1,033 of
        # 1,226 points on a live tenant), so the tenant's percentage is what compares (verify against Graph docs).
        $facts.secureScoreAtOrAboveAverage = [bool]($null -ne $facts.secureScoreAllTenantsAverage -and $null -ne $facts.secureScorePct -and $facts.secureScorePct -ge $facts.secureScoreAllTenantsAverage)
        if ($null -eq $facts.secureScoreAllTenantsAverage) { $notEvaluated['OP-005'] = 'Secure Score carries no all-tenant comparative average.' }
    }

    # Secure Score over the days Microsoft keeps (OP-009): how far the score has fallen from its highest point in
    # that time, as a percentage of the maximum, since the maximum moves when Microsoft adds a control.
    $history = & $load 'def-06-secure-score-history'
    if ($null -eq $history) { $notEvaluated['OP-009'] = 'def-06-secure-score-history.json was not collected (Invoke-PostureCollection -Collector Defender; needs SecurityEvents.Read.All).' }
    else {
        $points = @(& $rows $history | ForEach-Object { $day = ConvertTo-PostureUtcDateTime (& $v $_ 'Date'); $max = [double](& $v $_ 'MaxScore'); if ($day -and $max -gt 0) { [ordered]@{ date = $day; pct = [Math]::Round(100.0 * [double](& $v $_ 'CurrentScore') / $max, 1) } } } | Sort-Object { $_.date })
        $facts.secureScoreHistoryDays = $points.Count
        if ($points.Count -lt 7) { $notEvaluated['OP-009'] = "Secure Score has $($points.Count) day(s) of history in this run; a week is needed to say whether it has fallen." }
        else {
            $peak = @($points | Sort-Object { $_.pct } -Descending)[0]
            $facts.secureScorePeakPct = $peak.pct
            $facts.secureScorePeakDate = $peak.date.ToString('yyyy-MM-dd')
            $facts.secureScoreDropPoints = [Math]::Round([Math]::Max(0, $peak.pct - $points[-1].pct), 1)
            $facts.secureScoreHistory = @($points | ForEach-Object { [ordered]@{ label = $_.date.ToString('yyyy-MM-dd'); value = $_.pct } })
        }
    }

    # Subscriptions (OP-010): one that is past its term is in a grace period (Warning), then suspended, then locked
    # out, and the features it pays for go with it. A subscription that was deleted is gone and is not counted.
    $subs = & $load '01-subscriptions'
    if ($null -eq $subs) { $notEvaluated['OP-010'] = '01-subscriptions.json was not collected (Invoke-PostureCollection -Collector Entra).' }
    else {
        $allSubs = @(& $rows $subs | Where-Object { [string](& $v $_ 'Status') -ne 'Deleted' })
        $pastTerm = @($allSubs | Where-Object { [string](& $v $_ 'Status') -in 'Warning', 'Suspended', 'LockedOut' })
        $facts.subscriptions = $allSubs.Count
        $facts.trialSubscriptions = @($allSubs | Where-Object { (& $v $_ 'IsTrial') -eq $true -and [string](& $v $_ 'Status') -eq 'Enabled' }).Count
        $facts.subscriptionsPastTerm = $pastTerm.Count
        $stateWords = @{ Warning = 'in its grace period'; Suspended = 'suspended'; LockedOut = 'locked out' }
        $affected.subscriptionsPastTerm = @($pastTerm | ForEach-Object {
                $next = ConvertTo-PostureUtcDateTime (& $v $_ 'NextLifecycleDateTime')
                [ordered]@{ name = [string](& $v $_ 'SkuPartNumber'); detail = "$($stateWords[[string](& $v $_ 'Status')]), $([int](& $v $_ 'TotalLicenses')) licence(s)$(if ($next) { "; next change $($next.ToString('yyyy-MM-dd'))" })" }
            })
    }

    # Expiry calendar (OP-006): everything with a date, soonest first.
    $calendar = [System.Collections.Generic.List[object]]::new()
    $add = { param([string] $Kind, [string] $Name, $When) $d = ConvertTo-PostureUtcDateTime $When; if ($d) { $calendar.Add([ordered]@{ kind = $Kind; name = $Name; expiresUtc = $d.ToString('o'); days = [int][Math]::Floor(($d - $AsOf).TotalDays) }) } }
    $sources = 0
    $apps = & $load '10-app-registrations'
    if ($null -ne $apps) { $sources++; foreach ($a in @(& $rows $apps)) { & $add 'Application credential' ([string]$a.DisplayName) $a.EarliestExpiry } }
    $sps = & $load '10-service-principals'
    if ($null -ne $sps) { $sources++; foreach ($s in @(& $rows $sps | Where-Object { $_.SamlCertExpiry -and [string]$_.PreferredSingleSignOnMode -eq 'saml' })) { & $add 'SAML signing certificate' ([string]$s.DisplayName) $s.SamlCertExpiry } }
    $apns = & $load '09-apple-push-cert'
    if ($null -ne $apns) { $sources++; if ((& $v $apns 'Present') -eq $true) { & $add 'Apple push certificate' ([string](& $v $apns 'AppleIdentifier')) (& $v $apns 'ExpirationDateTime') } }
    $vpp = & $load '09-apple-vpp-tokens'
    if ($null -ne $vpp) { $sources++; foreach ($x in @(& $rows $vpp)) { & $add 'Apple VPP token' ([string]$x.OrganizationName) $x.ExpirationDateTime } }
    $ade = & $load '09-apple-ade-tokens'
    if ($null -ne $ade) { $sources++; foreach ($x in @(& $rows $ade)) { & $add 'Apple ADE token' ([string](& $v $x 'TokenName')) (& $v $x 'TokenExpirationDateTime') } }
    # A trial ends on its date, and a subscription in its grace period is suspended on its date. A paid
    # subscription that is in good standing is not on the calendar: its date is its next renewal.
    if ($null -ne $subs) {
        $sources++
        foreach ($x in @(& $rows $subs)) {
            $status = [string](& $v $x 'Status')
            if ((& $v $x 'IsTrial') -eq $true -and $status -eq 'Enabled') { & $add 'Trial subscription' ([string](& $v $x 'SkuPartNumber')) (& $v $x 'NextLifecycleDateTime') }
            elseif ($status -eq 'Warning') { & $add 'Subscription in its grace period' ([string](& $v $x 'SkuPartNumber')) (& $v $x 'NextLifecycleDateTime') }
        }
    }
    # The token-signing certificate of each federated domain. One that could not be read is not a date that is
    # far off: the calendar is then everything else, and says so.
    $federation = & $load '01-federation-settings'
    if ($null -ne $federation) {
        $sources++
        $unread = 0
        foreach ($x in @(& $rows $federation)) {
            $expires = & $v $x 'SigningCertificateExpiry'
            if ($expires) { & $add 'Federation signing certificate' ([string](& $v $x 'Domain')) $expires } else { $unread++ }
        }
        if ($unread -gt 0) {
            $partial['OP-006'] = @{
                note     = "The signing certificate of $unread federated domain(s) could not be read; the calendar is everything else."
                noAnswer = "Nothing that was read is near its date, but the signing certificate of $unread federated domain(s) could not be read."
            }
        }
    }
    $sorted = @($calendar | Sort-Object { $_.days })
    $facts.expiryCalendarEntries = $sorted.Count
    $facts.expiryCalendarSources = $sources
    $soon = @($sorted | Where-Object { $_.days -le [int]$t.expiryWarningDays })
    $facts.expiringWithinWarning = $soon.Count
    $facts.expiryCalendar = @($sorted | Select-Object -First 50)
    $affected.expiringWithinWarning = @($soon | ForEach-Object { [ordered]@{ name = "$($_.kind): $($_.name)"; detail = $(if ($_.days -lt 0) { "expired $(-$_.days) day(s) ago" } else { "expires in $($_.days) day(s)" }) } })
    if ($sources -eq 0) { $notEvaluated['OP-006'] = 'None of the expiry sources were collected (app registrations, service principals, Apple certificates and tokens, subscriptions, federation settings).' }

    # Message Center (OP-011): the posts with a date to act by that falls inside the warning window. Each is
    # Microsoft saying something changes on that day unless the organisation does something first.
    $posts = & $load '12-message-center'
    if ($null -eq $posts) { $notEvaluated['OP-011'] = '12-message-center.json was not collected (Invoke-PostureCollection -Collector Entra; needs ServiceMessage.Read.All).' }
    else {
        $due = @(& $rows $posts | ForEach-Object {
                $by = ConvertTo-PostureUtcDateTime (& $v $_ 'ActionRequiredByDateTime')
                if ($by) { $days = [int][Math]::Floor(($by - $AsOf).TotalDays); if ($days -ge 0 -and $days -le [int]$t.messageCenterWarningDays) { [ordered]@{ name = "$([string](& $v $_ 'Id')): $([string](& $v $_ 'Title'))"; detail = "act by $($by.ToString('yyyy-MM-dd')), in $days day(s)$(if ([string](& $v $_ 'Services')) { "; $(([string](& $v $_ 'Services')) -replace ';', ', ')" })"; days = $days } } }
            } | Sort-Object { $_.days })
        $facts.messageCenterActionsDue = $due.Count
        $affected.messageCenterActionsDue = @($due | ForEach-Object { [ordered]@{ name = $_.name; detail = $_.detail } })
    }

    # Service health: what Microsoft had open when the run was made. Reported, never judged: it is not the tenant's posture.
    $health = & $load '12-service-health'
    if ($null -ne $health) {
        $facts.serviceIncidentsOpen = @(& $rows $health | Where-Object { [string](& $v $_ 'Classification') -eq 'incident' }).Count
        $facts.serviceAdvisoriesOpen = @(& $rows $health | Where-Object { [string](& $v $_ 'Classification') -ne 'incident' }).Count
    }

    # Entra Connect Health (OP-007) from the Azure collector. (verify) the service fields
    $health = & $load 'az-08-entra-connect-health'
    if ($null -eq $health) { $notEvaluated['OP-007'] = 'az-08-entra-connect-health.json was not collected (Invoke-PostureCollection -Collector Azure).' }
    else {
        $services = @(& $rows $health)
        $facts.entraConnectHealthServices = $services.Count
        $facts.entraConnectHealthActiveAlerts = @($services | ForEach-Object { [int]$(if ($null -ne $_.ActiveAlerts) { $_.ActiveAlerts } else { 0 }) } | Measure-Object -Sum).Sum
        $facts.entraConnectHealthEnabled = $services.Count -gt 0
    }

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; partial = $partial; evidence = @('10-app-registrations.json', 'def-06-secure-score.json', 'def-06-secure-score-history.json', '01-subscriptions.json', '12-message-center.json') }
}
