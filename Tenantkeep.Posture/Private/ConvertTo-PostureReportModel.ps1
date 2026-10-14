# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function ConvertTo-PostureReportModel {
    <#
    .SYNOPSIS
        Builds the report model every renderer reads (spec 3 and 7): score, headline numbers, domain scorecards,
        the admins table, recommendations in the four buckets, CA pages and the appendix.
    .DESCRIPTION
        Input is an engine run (Invoke-PostureCheckEvaluation output), the catalog, the evidence folder, the
        profile, exceptions and brand. Score method: weighted pass rate over evaluated checks, Critical 4, High 3,
        Medium 2, Low 1; accepted risk counts as pass and is marked. Grades: A 90+, B 80+, C 70+, D 60+, F below.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Run,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Catalog,
        [Parameter(Mandatory)] [string] $Evidence,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $OrgProfile,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Brand,
        [AllowEmptyCollection()] [object[]] $Exception = @(),
        [string] $Template = 'Full',
        [datetime] $GeneratedUtc = [datetime]::UtcNow
    )

    $ErrorActionPreference = 'Stop'
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
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
    $byId = @{}; foreach ($c in $Catalog.checks) { $byId[[string]$c['id']] = $c }
    $results = @($Run.results)

    # Score
    $weight = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }
    $scored = @($results | Where-Object { $_.status -in @('pass', 'fail', 'acceptedRisk') })
    $earned = 0; $possible = 0
    foreach ($r in $scored) { $w = $weight[[string]$r.severity]; if (-not $w) { $w = 1 }; $possible += $w; if ($r.status -ne 'fail') { $earned += $w } }
    $score = if ($possible -gt 0) { [Math]::Round(100.0 * $earned / $possible) } else { $null }
    $grade = if ($null -eq $score) { 'n/a' } elseif ($score -ge 90) { 'A' } elseif ($score -ge 80) { 'B' } elseif ($score -ge 70) { 'C' } elseif ($score -ge 60) { 'D' } else { 'F' }

    # Domain labels in report order (spec 3), those present in the catalog first.
    $domainLabels = [ordered]@{
        identity = 'Identity and privileged access'; auth = 'Authentication methods'; ca = 'Conditional Access'; devices = 'Devices'
        endpoint = 'Endpoint security'; email = 'Email security'; purview = 'Data protection'; collaboration = 'Collaboration and oversharing'
        copilot = 'Copilot readiness'; governance = 'Governance and lifecycle'; operations = 'Operations and monitoring'; azure = 'Azure'; hybrid = 'Hybrid identity and on-premises AD'
    }
    $notCollected = [System.Collections.Generic.List[object]]::new()
    $domains = foreach ($d in $domainLabels.Keys) {
        $dr = @($results | Where-Object { $_.domain -eq $d })
        if ($dr.Count -eq 0) { continue }
        # Every check unevaluated means the evidence for the domain is not there; list it as not collected, with the reason.
        if (@($dr | Where-Object { $_.status -notin @('notEvaluated', 'notApplicable') }).Count -eq 0) {
            $notCollected.Add([ordered]@{ key = $d; label = $domainLabels[$d]; reason = [string](@($dr | ForEach-Object { $_.reason } | Where-Object { $_ })[0]) })
            continue
        }
        $counts = [ordered]@{}
        foreach ($st in 'pass', 'fail', 'notEvaluated', 'notApplicable', 'acceptedRisk', 'coveredBy') { $counts[$st] = @($dr | Where-Object { $_.status -eq $st }).Count }
        $ds = @($dr | Where-Object { $_.status -in @('pass', 'fail', 'acceptedRisk') })
        $de = 0; $dp = 0
        foreach ($r in $ds) { $w = $weight[[string]$r.severity]; if (-not $w) { $w = 1 }; $dp += $w; if ($r.status -ne 'fail') { $de += $w } }
        $dinfo = $Run.domains[$d]
        [ordered]@{
            key       = $d
            label     = $domainLabels[$d]
            score     = $(if ($dp -gt 0) { [Math]::Round(100.0 * $de / $dp) } else { $null })
            counts    = $counts
            available = $(if ($dinfo) { [bool]$dinfo.available } else { $false })
            reason    = $(if ($dinfo) { $dinfo.reason } else { 'No results' })
            checks    = @($dr | Sort-Object { @{ fail = 0; acceptedRisk = 1; notEvaluated = 2; coveredBy = 3; notApplicable = 4; pass = 5 }[[string]$_.status] }, { @{ Critical = 0; High = 1; Medium = 2; Low = 3 }[[string]$_.severity] }, { $_.id })
            narrative = $(switch ($counts.fail) { 0 { 'Every evaluated check passes.' } 1 { 'One check fails; see the table.' } default { "$($counts.fail) checks fail, starting with the highest severity." } })
        }
    }
    $domainsNotCollected = @($domainLabels.Keys | Where-Object { $_ -notin @($domains | ForEach-Object { $_.key }) } | ForEach-Object { $k = $_; $hit = @($notCollected | Where-Object { $_.key -eq $k }); if ($hit.Count -gt 0) { $hit[0] } else { [ordered]@{ key = $k; label = $domainLabels[$k]; reason = 'Not in the catalog yet' } } })

    # Headline numbers (spec 3). Null means not collected yet.
    $authFacts = if ($Run.domains['auth']) { $Run.domains['auth'].facts } else { @{} }
    $idFacts = if ($Run.domains['identity']) { $Run.domains['identity'].facts } else { @{} }
    $devFacts = if ($Run.domains['devices']) { $Run.domains['devices'].facts } else { @{} }
    $admins = [double](& $v $authFacts 'admins'); $without = [double](& $v $authFacts 'adminsWithoutPhishingResistant')
    $headline = [ordered]@{
        mfaRegisteredPct         = & $v $authFacts 'mfaRegisteredPct'
        adminsPhishingResistantPct = $(if ($admins -gt 0) { [Math]::Round(100.0 * ($admins - $without) / $admins, 1) } else { $null })
        permanentGlobalAdmins    = & $v $idFacts 'globalAdmins'
        intuneCompliancePct      = & $v $devFacts 'intuneCompliancePct'
        externalExposure         = $null
        copilotReadinessPct      = $null
    }

    # Top risks: failed checks by severity weight, five of them.
    $topRisks = @($results | Where-Object { $_.status -eq 'fail' } | Sort-Object { -$weight[[string]$_.severity] }, { $_.id } | Select-Object -First 5 | ForEach-Object {
            [ordered]@{ id = $_.id; title = $_.title; severity = $_.severity; domain = $_.domain; affectedCount = $_.affectedCount; narrative = [string]$byId[$_.id]['narrative'] }
        })

    # Recommendations in the audit plan's buckets (section 5): severity maps to urgency until effort and license data exist per check.
    $bucketOf = @{ Critical = 'Stop the bleeding'; High = 'Foundations'; Medium = 'Program workstreams'; Low = 'Later' }
    $recommendations = [ordered]@{}
    foreach ($b in 'Stop the bleeding', 'Foundations', 'Program workstreams', 'Later') { $recommendations[$b] = @() }
    foreach ($r in @($results | Where-Object { $_.status -eq 'fail' } | Sort-Object { -$weight[[string]$_.severity] }, { $_.id })) {
        $c = $byId[$r.id]
        $recommendations[$bucketOf[[string]$r.severity]] += , [ordered]@{
            id = $r.id; title = $r.title; severity = $r.severity; domain = $r.domain; affectedCount = $r.affectedCount
            remediation = [string]$c['remediation']; learn = [string]$c['learn']; license = @($c['license'])
        }
    }

    # Who are your admins (spec 7.2): roles joined to registration and users.
    $active = & $load '04-role-assignments-active'
    $eligible = & $load '04-role-assignments-pim-eligible'
    $reg = & $load '05-auth-registration'
    $users = & $load '06-users'
    $regByUpn = @{}; foreach ($r in @($reg | Where-Object { $_ })) { $regByUpn[[string]$r.UserPrincipalName] = $r }
    $userByUpn = @{}; foreach ($u in @($users | Where-Object { $_ })) { $userByUpn[[string]$u.UserPrincipalName] = $u }
    $strongest = {
        param([string] $methods)
        $m = @($methods -split ';' | Where-Object { $_ })
        if ($m | Where-Object { $_ -match 'fido2|passKey|x509' }) { return 'Phishing-resistant' }
        if ($m -contains 'windowsHelloForBusiness') { return 'Windows Hello for Business' }
        if ($m | Where-Object { $_ -match 'microsoftAuthenticator' }) { return 'Authenticator' }
        if ($m | Where-Object { $_ -match 'softwareOath|hardwareOath' }) { return 'OATH token' }
        if ($m -contains 'mobilePhone' -or $m -contains 'alternateMobilePhone' -or $m -contains 'officePhone') { return 'Phone' }
        return 'None'
    }
    $adminRows = @{}
    foreach ($a in @(@($active | Where-Object { $_ }) + @($eligible | Where-Object { $_ }))) {
        $key = "$($a.PrincipalType)|$($a.PrincipalId)"
        if (-not $adminRows.ContainsKey($key)) {
            $upn = [string]$a.PrincipalUpn
            $u = $userByUpn[$upn]; $rg = $regByUpn[$upn]
            $adminRows[$key] = [ordered]@{
                name = $a.PrincipalName; upn = $upn; type = $a.PrincipalType; roles = @(); permanent = @(); eligible = @()
                strongestMethod = $(if ($rg) { & $strongest ([string]$rg.MethodsRegistered) } elseif ($a.PrincipalType -eq 'user') { 'Unknown' } else { 'n/a' })
                lastSignIn = $(if ($u -and $u.LastInteractiveSignIn) { (ConvertTo-PostureUtcDateTime $u.LastInteractiveSignIn).ToString('yyyy-MM-dd') } else { $null })
                synced = [bool]($a.PrincipalSynced -eq $true)
                licenses = $(if ($u) { [int]$u.LicenseCount } else { $null })
            }
        }
        $row = $adminRows[$key]
        $row.roles = @($row.roles + $a.Role | Select-Object -Unique)
        if ($a.AssignmentType -eq 'Eligible') { $row.eligible = @($row.eligible + $a.Role | Select-Object -Unique) } else { $row.permanent = @($row.permanent + $a.Role | Select-Object -Unique) }
    }
    $adminsTable = @($adminRows.Values | Sort-Object { -($_.permanent -contains 'Global Administrator') }, { $_.name })

    # Conditional Access pages from the snapshot in the same folder, when present.
    $ca = $null
    if (Test-Path -LiteralPath (Join-Path $Evidence 'policies.json')) {
        $snap = Import-PostureCaSnapshot -Path $Evidence
        $thr = $OrgProfile.thresholds
        $mp = @{ Snapshot = $snap }
        if ($thr -and $thr.Contains('maxExclusionGroupMembers')) { $mp.ExclusionGroupThreshold = [int]$thr.maxExclusionGroupMembers }
        if ($thr -and $thr.Contains('reportOnlyMaxDays')) { $mp.ReportOnlyDays = [int]$thr.reportOnlyMaxDays }
        if ($thr -and $thr.Contains('namePattern') -and $thr.namePattern) { $mp.NamePattern = [string]$thr.namePattern }
        $policies = @(ConvertTo-PostureCaPolicyModel @mp)
        $ca = [ordered]@{
            policies = @($policies | ForEach-Object { [ordered]@{ id = $_.id; name = $_.name; state = $_.state; stateLabel = $_.stateLabel; summary = $_.summary; healthFlags = @($_.healthFlags) } })
            matrix   = Get-PostureCaMatrix -Policy $policies
            flagCount = @($policies | ForEach-Object { @($_.healthFlags) }).Count
        }
    }

    $catalogText = [ordered]@{}
    foreach ($c in $Catalog.checks) { $catalogText[[string]$c['id']] = [ordered]@{ narrative = [string]$c['narrative']; remediation = [string]$c['remediation']; learn = [string]$c['learn']; license = @($c['license']); frameworks = $c['frameworks']; evidence = @($c['evidence']) } }

    $collection = & $load 'collection'
    $tenantId = $(if ($collection) { & $v $collection 'tenantId' } else { & $v (& $load 'metadata') 'tenantId' })
    $org = & $load '01-organization'
    $tenantName = $(if ($org) { [string](& $v @($org)[0] 'displayName') } else { $null })
    $clientName = $(if ($Brand.client.name) { [string]$Brand.client.name } elseif ($OrgProfile.clientName) { [string]$OrgProfile.clientName } elseif ($tenantName) { $tenantName } else { [string]$tenantId })

    return [ordered]@{
        title        = "Microsoft security posture report: $clientName"
        clientName   = $clientName
        tenantId     = $tenantId
        tenantName   = $tenantName
        template     = $Template
        brand        = $Brand
        generatedUtc = $GeneratedUtc
        collectedUtc = $(if ($collection) { & $v $collection 'timestampUtc' } else { $null })
        collectors   = @($(if ($collection) { & $v $collection 'collectors' } else { @() }))
        score        = [ordered]@{ value = $score; grade = $grade; method = 'Weighted pass rate over evaluated checks: Critical 4, High 3, Medium 2, Low 1. Accepted risk counts as a pass and is marked. Not evaluated and not applicable checks are excluded.'; evaluated = $scored.Count; earned = $earned; possible = $possible }
        headline     = $headline
        counts       = $Run.counts
        topRisks     = $topRisks
        domains      = @($domains)
        domainsNotCollected = $domainsNotCollected
        recommendations = $recommendations
        admins       = $adminsTable
        ca           = $ca
        results      = $results
        catalogText  = $catalogText
        appendix     = [ordered]@{
            catalogVersion = $Run.catalogVersion; baseline = $Run.baseline; profile = $Run.profile; profilePresent = [bool]$OrgProfile.present
            profileAnswers = $(if ($OrgProfile.present) { [ordered]@{ licenses = @($OrgProfile.licenses); platforms = @($OrgProfile.platforms); identityModel = $OrgProfile.identityModel; byod = $OrgProfile.byod; externalCollaboration = $OrgProfile.externalCollaboration; copilot = $OrgProfile.copilot; azure = $OrgProfile.azure; thirdParty = $OrgProfile.thirdParty; frameworks = @($OrgProfile.frameworks); thresholds = $OrgProfile.thresholds; breakGlass = @($OrgProfile.breakGlass) } } else { $null })
            exceptions = @($Exception)
            evidence = $Evidence
            scopes = @($(if ($collection) { & $v $collection 'scopes' } else { @() }))
            graphApiVersions = @($(if ($collection) { & $v $collection 'graphApiVersions' } else { @() }))
            evidenceFiles = @(Get-ChildItem -LiteralPath $Evidence -File | Where-Object { $_.Extension -in '.json', '.csv' } | ForEach-Object { $_.Name } | Sort-Object)
            errors = @($(if ($collection) { & $v $collection 'errors' } else { @() }))
            notEvaluated = @($results | Where-Object { $_.status -in @('notEvaluated', 'notApplicable') } | ForEach-Object { [ordered]@{ id = $_.id; title = $_.title; status = $_.status; reason = $_.reason } })
            moduleVersion = $script:ModuleVersion
        }
    }
}
