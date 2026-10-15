# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureOperationsFact {
    <#
    .SYNOPSIS
        Fact provider for the operations domain (spec 4.9 and the scores of 4.12): SIEM and backup decisions, the
        break-glass test and Message Center owner from the profile's operations answers, Secure Score against
        Microsoft's comparative average, and the expiry calendar built from the evidence already collected.
    .DESCRIPTION
        The expiry calendar gathers everything with a date: application credentials (10-app-registrations), SAML
        signing certificates (10-service-principals), the Apple push certificate and VPP tokens (09-apple-*). Thresholds
        read: expiryWarningDays, breakGlassTestMaxDays. Profile read: thirdParty.siem, thirdParty.backup,
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
    $t = @{ expiryWarningDays = 30; breakGlassTestMaxDays = 180 }
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

    # Secure Score against the comparative average (OP-005)
    $ss = & $load 'def-06-secure-score'
    if ($null -eq $ss -or (& $v $ss 'Present') -ne $true) { $notEvaluated['OP-005'] = 'def-06-secure-score.json was not collected (Invoke-PostureCollection -Collector Defender; needs SecurityEvents.Read.All).' }
    else {
        $facts.secureScore = [double](& $v $ss 'CurrentScore'); $facts.secureScoreMax = [double](& $v $ss 'MaxScore')
        $facts.secureScorePct = $(if ($facts.secureScoreMax -gt 0) { [Math]::Round(100.0 * $facts.secureScore / $facts.secureScoreMax, 1) } else { $null })
        $avg = @(& $rows (& $v $ss 'AverageComparativeScores') | Where-Object { [string]$_.Basis -eq 'AllTenants' } | Select-Object -First 1)
        $facts.secureScoreAllTenantsAverage = $(if ($avg.Count -gt 0) { [double]$avg[0].AverageScore } else { $null })
        $facts.secureScoreAtOrAboveAverage = [bool]($null -ne $facts.secureScoreAllTenantsAverage -and $facts.secureScore -ge $facts.secureScoreAllTenantsAverage)
        if ($null -eq $facts.secureScoreAllTenantsAverage) { $notEvaluated['OP-005'] = 'Secure Score carries no all-tenant comparative average.' }
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
    $sorted = @($calendar | Sort-Object { $_.days })
    $facts.expiryCalendarEntries = $sorted.Count
    $facts.expiryCalendarSources = $sources
    $soon = @($sorted | Where-Object { $_.days -le [int]$t.expiryWarningDays })
    $facts.expiringWithinWarning = $soon.Count
    $facts.expiryCalendar = @($sorted | Select-Object -First 50)
    $affected.expiringWithinWarning = @($soon | ForEach-Object { [ordered]@{ name = "$($_.kind): $($_.name)"; detail = $(if ($_.days -lt 0) { "expired $(-$_.days) day(s) ago" } else { "expires in $($_.days) day(s)" }) } })
    if ($sources -eq 0) { $notEvaluated['OP-006'] = 'None of the expiry sources were collected (app registrations, service principals, Apple certificates).' }

    # Entra Connect Health (OP-007) waits for the Azure collector.
    $notEvaluated['OP-007'] = 'Entra Connect Health is read through Azure (spec 4.13); the Azure collector is not built yet.'

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('10-app-registrations.json', 'def-06-secure-score.json') }
}
