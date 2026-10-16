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
        [System.Collections.IDictionary] $Previous,
        [System.Collections.IDictionary] $BaselineModel,
        [System.Collections.IDictionary] $Entitlement,
        [AllowEmptyCollection()] [object[]] $Register = @(),
        [datetime] $GeneratedUtc = [datetime]::UtcNow
    )

    $ErrorActionPreference = 'Stop'
    # Second verification of the licence, independent of the engine's record (docs/licensing.md, Hardening).
    if (-not $Entitlement) { $Entitlement = Get-PostureEntitlement -Evidence $Evidence }
    $Entitlement = Confirm-PostureEntitlement -Entitlement $Entitlement
    $Run = [ordered]@{} + $Run
    $Run.results = Limit-PostureResultsToEntitlement -Results @($Run.results) -Entitlement $Entitlement
    $Run.entitlement = ConvertTo-PostureEntitlementRecord -Entitlement $Entitlement
    $buildState = $(if (Get-Variable -Name PostureBuildState -Scope Script -ValueOnly -ErrorAction SilentlyContinue) { $script:PostureBuildState } else { @{ state = 'development'; detail = 'Development build: no signed release manifest.'; version = $script:ModuleVersion; changed = @() } })
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
        copilotBlocked           = $false
    }

    # Copilot readiness (spec 4.7): hard gates must all pass before the page shows anything but Blocked; readiness is
    # passed gates over evaluated gates, with the not-evaluated rows listed. Statuses come from the engine; the gate
    # codes and hard flags from the catalog.
    $copilot = $null
    $cpResults = @($results | Where-Object { $_.domain -eq 'copilot' })
    if ($cpResults.Count -gt 0) {
        $gates = @($cpResults | ForEach-Object {
                $g = $byId[$_.id]['gate']
                [ordered]@{ id = $_.id; code = [string]$(if ($g) { $g['code'] }); hard = [bool]$(if ($g) { $g['hard'] }); title = $_.title; status = $_.status; reason = $_.reason; affectedCount = $_.affectedCount }
            } | Sort-Object { [int](($_.code -replace '\D', '') + 0) })
        $hard = @($gates | Where-Object { $_.hard })
        $hardNotPassed = @($hard | Where-Object { $_.status -notin @('pass', 'acceptedRisk', 'coveredBy') })
        $evaluated = @($gates | Where-Object { $_.status -in @('pass', 'fail', 'acceptedRisk', 'coveredBy') })
        $passed = @($evaluated | Where-Object { $_.status -ne 'fail' })
        $present = @($gates | Where-Object { $_.status -notin @('notEvaluated', 'notApplicable') }).Count -gt 0
        $copilot = [ordered]@{
            present      = $present
            blocked      = ($hardNotPassed.Count -gt 0)
            blockedBy    = @($hardNotPassed)
            readinessPct = $(if ($evaluated.Count -gt 0) { [Math]::Round(100.0 * $passed.Count / $evaluated.Count) } else { $null })
            evaluated    = $evaluated.Count
            passed       = $passed.Count
            notEvaluated = @($gates | Where-Object { $_.status -eq 'notEvaluated' })
            hardGates    = @($hard)
            gates        = @($gates)
            narrative    = 'Restricted access control, restricted content discovery and restricted SharePoint search are stopgaps: they let Copilot be turned on while site owners clean up. The end state is correct permissions, labels that encrypt the top tier, and reviews that keep both true.'
        }
    }

    if ($copilot -and $copilot.present) { $headline.copilotReadinessPct = $copilot.readinessPct; $headline.copilotBlocked = $copilot.blocked }

    # Trend since an earlier run (spec 3, 9): score and domain deltas, checks that started or stopped failing, affected counts that moved.
    $trend = $null
    if ($Previous -and $Previous.Contains('results')) {
        $prevResults = @($Previous['results'] | Where-Object { $_ })
        $prevById = @{}; foreach ($pr in $prevResults) { $prevById[[string]$pr['id']] = $pr }
        $prevScored = @($prevResults | Where-Object { [string]$_['status'] -in @('pass', 'fail', 'acceptedRisk') })
        $pe = 0; $pp = 0
        foreach ($pr in $prevScored) { $w = $weight[[string]$pr['severity']]; if (-not $w) { $w = 1 }; $pp += $w; if ([string]$pr['status'] -ne 'fail') { $pe += $w } }
        $prevScore = $(if ($pp -gt 0) { [Math]::Round(100.0 * $pe / $pp) } else { $null })
        $newFailures = @(); $resolved = @(); $moved = @()
        foreach ($r in $results) {
            $pr = $prevById[[string]$r.id]
            if (-not $pr) { if ($r.status -eq 'fail') { $newFailures += , [ordered]@{ id = $r.id; title = $r.title; severity = $r.severity; detail = 'new check, failing' } }; continue }
            $was = [string]$pr['status']
            if ($r.status -eq 'fail' -and $was -ne 'fail') { $newFailures += , [ordered]@{ id = $r.id; title = $r.title; severity = $r.severity; detail = "was $was" } }
            elseif ($r.status -ne 'fail' -and $was -eq 'fail') { $resolved += , [ordered]@{ id = $r.id; title = $r.title; severity = $r.severity; detail = "now $($r.status)" } }
            elseif ($r.status -eq 'fail' -and [int]$r.affectedCount -ne [int]$pr['affectedCount']) { $moved += , [ordered]@{ id = $r.id; title = $r.title; severity = $r.severity; before = [int]$pr['affectedCount']; after = [int]$r.affectedCount } }
        }
        $domainDeltas = foreach ($d in $domains) {
            $pd = @($prevScored | Where-Object { [string]$_['domain'] -eq $d.key })
            $de2 = 0; $dp2 = 0
            foreach ($pr in $pd) { $w = $weight[[string]$pr['severity']]; if (-not $w) { $w = 1 }; $dp2 += $w; if ([string]$pr['status'] -ne 'fail') { $de2 += $w } }
            $before = $(if ($dp2 -gt 0) { [Math]::Round(100.0 * $de2 / $dp2) } else { $null })
            [ordered]@{ key = $d.key; label = $d.label; before = $before; after = $d.score; delta = $(if ($null -ne $before -and $null -ne $d.score) { $d.score - $before } else { $null }) }
        }
        $trend = [ordered]@{
            previousCheckedUtc = [string]$(if ($Previous.Contains('checkedUtc')) { $Previous['checkedUtc'] } elseif ($prevResults.Count -gt 0) { $prevResults[0]['checkedUtc'] })
            previousEvidence   = [string]$(if ($Previous.Contains('evidence')) { $Previous['evidence'] })
            scoreBefore        = $prevScore
            scoreAfter         = $score
            scoreDelta         = $(if ($null -ne $prevScore -and $null -ne $score) { $score - $prevScore } else { $null })
            newFailures        = @($newFailures | Sort-Object { -$weight[[string]$_.severity] }, { $_.id })
            resolved           = @($resolved | Sort-Object { -$weight[[string]$_.severity] }, { $_.id })
            affectedMoved      = @($moved | Sort-Object { -[Math]::Abs($_.after - $_.before) }, { $_.id })
            domains            = @($domainDeltas)
        }
    }

    # Framework crosswalk (spec 10.6): the baseline's groups or the customer's control names, each with the checks that map there.
    $crosswalk = $null
    if ($BaselineModel -and $BaselineModel.Contains('crosswalk') -and $BaselineModel['crosswalk']) {
        $cw = $BaselineModel['crosswalk']
        $key = [string]$cw['framework']
        $refOf = { param($r) $c = $byId[[string]$r.id]; if ($c -and $c['frameworks'] -and $c['frameworks'].Contains($key)) { [string]$c['frameworks'][$key] } else { '' } }
        $rowsOf = { param([string[]] $refs, [bool] $prefix) @($results | Where-Object { $ref = & $refOf $_; $ref -and (@($refs | Where-Object { if ($prefix) { $ref -like "$_*" } else { $ref -eq $_ } }).Count -gt 0) } | ForEach-Object { [ordered]@{ id = $_.id; title = $_.title; status = $_.status; severity = $_.severity; reference = (& $refOf $_) } } | Sort-Object { $_.reference }, { $_.id }) }
        $entries = [System.Collections.Generic.List[object]]::new()
        if ($cw.Contains('controls') -and $cw['controls']) {
            foreach ($control in @($cw['controls'].Keys)) { $rowsC = & $rowsOf @($cw['controls'][$control] | ForEach-Object { [string]$_ }) $false; $entries.Add([ordered]@{ name = [string]$control; references = @($cw['controls'][$control]); checks = @($rowsC); pass = @($rowsC | Where-Object { $_.status -in @('pass', 'acceptedRisk', 'coveredBy') }).Count; fail = @($rowsC | Where-Object { $_.status -eq 'fail' }).Count }) }
        }
        elseif ($cw.Contains('groups') -and $cw['groups']) {
            foreach ($g in @($cw['groups'].Keys)) { $rowsG = & $rowsOf @([string]$g) $true; $entries.Add([ordered]@{ name = "$g $($cw['groups'][$g])"; references = @($g); checks = @($rowsG); pass = @($rowsG | Where-Object { $_.status -in @('pass', 'acceptedRisk', 'coveredBy') }).Count; fail = @($rowsG | Where-Object { $_.status -eq 'fail' }).Count }) }
        }
        $crosswalk = [ordered]@{ framework = $key; baseline = [string]$BaselineModel['name']; entries = @($entries) }
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
            remediation = [string]$c['remediation']; learn = [string]$c['learn']; deepLink = [string]$c['deepLink']; license = @($c['license'])
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
    foreach ($c in $Catalog.checks) { $catalogText[[string]$c['id']] = [ordered]@{ narrative = [string]$c['narrative']; remediation = [string]$c['remediation']; learn = [string]$c['learn']; deepLink = [string]$c['deepLink']; license = @($c['license']); frameworks = $c['frameworks']; evidence = @($c['evidence']); input = $(if ($c.Contains('input')) { $c['input'] } else { $null }) } }

    $collection = & $load 'collection'
    $tenantId = $(if ($collection) { & $v $collection 'tenantId' } else { & $v (& $load 'metadata') 'tenantId' })
    $org = & $load '01-organization'
    $tenantName = $(if ($org) { [string](& $v @($org)[0] 'displayName') } else { $null })
    $clientName = $(if ($Brand.client.name) { [string]$Brand.client.name } elseif ($OrgProfile.clientName) { [string]$OrgProfile.clientName } elseif ($tenantName) { $tenantName } else { [string]$tenantId })

    return [ordered]@{
        title        = "Microsoft Security Posture Report: $clientName"
        clientName   = $clientName
        tenantId     = $tenantId
        tenantName   = $tenantName
        template     = $Template
        brand        = $Brand
        generatedUtc = $GeneratedUtc
        collectedUtc = $(if ($collection) { & $v $collection 'timestampUtc' } else { $null })
        collectors   = @($(if ($collection) { & $v $collection 'collectors' } else { @() }))
        licence      = $Run.entitlement
        register     = @($Register)
        profileModel = [ordered]@{ clientName = $OrgProfile.clientName; tenantId = $OrgProfile.tenantId; licenses = @($OrgProfile.licenses); platforms = @($OrgProfile.platforms); identityModel = $OrgProfile.identityModel; byod = $OrgProfile.byod; externalCollaboration = $OrgProfile.externalCollaboration; copilot = $OrgProfile.copilot; azure = $OrgProfile.azure; thirdParty = $OrgProfile.thirdParty; frameworks = @($OrgProfile.frameworks); thresholds = $OrgProfile.thresholds; breakGlass = @($OrgProfile.breakGlass); audience = $OrgProfile.audience; cadence = $OrgProfile.cadence; operations = $OrgProfile.operations; attestations = $OrgProfile.attestations }
        exceptions   = @($Exception | ForEach-Object { [ordered]@{ check = $_.check; object = $_.object; justification = $_.justification; owner = $_.owner; approver = $_.approver; expires = $(if ($_.expires) { $_.expires.ToString('yyyy-MM-dd') } else { $null }) } })
        build        = [ordered]@{ state = [string]$buildState.state; detail = [string]$buildState.detail; version = [string]$buildState.version }
        score        = [ordered]@{ value = $score; grade = $grade; method = 'Weighted pass rate over evaluated checks: Critical 4, High 3, Medium 2, Low 1. Accepted risk counts as a pass and is marked. Not evaluated and not applicable checks are excluded.'; evaluated = $scored.Count; earned = $earned; possible = $possible }
        headline     = $headline
        counts       = $Run.counts
        topRisks     = $topRisks
        domains      = @($domains)
        domainsNotCollected = $domainsNotCollected
        recommendations = $recommendations
        admins       = $adminsTable
        ca           = $ca
        copilot      = $copilot
        trend        = $trend
        crosswalk    = $crosswalk
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
            build = [string]$buildState.detail
            licence = $(if ($Run.entitlement.licensed) { "$($Run.entitlement.tier) tier, licence $($Run.entitlement.licenceId), $($Run.entitlement.customer), expires $($Run.entitlement.expiresUtc)" } else { "none: $($Run.entitlement.reason)" })
        }
    }
}
