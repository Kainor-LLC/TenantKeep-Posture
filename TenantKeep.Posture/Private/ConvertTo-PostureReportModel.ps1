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
    # Parsed once per evaluation and shared with the other domains (Read-PostureEvidenceFile); a missing file is
    # $null, an empty one an empty array.
    $load = {
        param([string] $Name)
        $parsed = Read-PostureEvidenceFile -Folder $Evidence -Name $Name
        if ($null -eq $parsed) { return $null }
        if ($parsed -is [array] -and $parsed.Count -eq 0) { return , @() }
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
    # Domains in report order with their labels, from checks/catalog.json; a custom catalog without the list falls
    # back to the domains its checks name.
    $domainLabels = [ordered]@{}
    if ($Catalog.Contains('domains') -and $Catalog['domains'] -and @($Catalog['domains'].Keys).Count) { foreach ($k in $Catalog['domains'].Keys) { $domainLabels[$k] = $Catalog['domains'][$k] } }
    foreach ($c in $Catalog.checks) { $dk = [string]$c['domain']; if ($dk -and -not $domainLabels.Contains($dk)) { $domainLabels[$dk] = $dk } }
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
    # A number the check itself could not stand behind (a group that holds a role was not opened, so the count is
    # a floor) is not a headline.
    $noAnswer = @{}; foreach ($x in @($results | Where-Object { $_.id -in 'AU-008', 'ID-001' -and $_.status -eq 'notEvaluated' })) { $noAnswer[[string]$x.id] = $true }
    $headline = [ordered]@{
        mfaRegisteredPct         = & $v $authFacts 'mfaRegisteredPct'
        adminsPhishingResistantPct = $(if ($admins -gt 0 -and -not $noAnswer.ContainsKey('AU-008')) { [Math]::Round(100.0 * ($admins - $without) / $admins, 1) } else { $null })
        permanentGlobalAdmins    = $(if ($noAnswer.ContainsKey('ID-001')) { $null } else { & $v $idFacts 'globalAdmins' })
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
        # The catalog each run was judged with. When they differ a result can move because the check changed and
        # the tenant did not: the catalog says which checks and why (catalog.json, changes), and those are listed
        # apart, never as a new failure or a fix.
        $catalogBefore = [string]$(if ($Previous.Contains('catalogVersion')) { $Previous['catalogVersion'] })
        $catalogAfter = [string]$(if ($Run.Contains('catalogVersion')) { $Run['catalogVersion'] })
        $catalogChanged = [bool]($catalogBefore -and $catalogAfter -and $catalogBefore -ne $catalogAfter)
        $changedWhy = @{}; $catalogNotes = @()
        if ($catalogChanged) {
            $after = { param([string] $a, [string] $b) $x = $null; $y = $null; if ([version]::TryParse($a, [ref]$x) -and [version]::TryParse($b, [ref]$y)) { $x -gt $y } else { $a -ne $b } }
            foreach ($entry in @($(if ($Catalog.Contains('changes')) { $Catalog['changes'] }) | Where-Object { $_ -and (& $after ([string]$_['version']) $catalogBefore) })) {
                $catalogNotes += [string]$entry['summary']
                foreach ($k in $entry['checks'].get_Keys()) { $changedWhy[[string]$k] = [string]$entry['checks'][$k] }
            }
        }
        $newFailures = @(); $resolved = @(); $moved = @(); $logicChanged = @(); $lostAnswer = @()
        foreach ($r in $results) {
            $pr = $prevById[[string]$r.id]
            if (-not $pr) { if ($r.status -eq 'fail') { $newFailures += , [ordered]@{ id = $r.id; title = $r.title; severity = $r.severity; detail = 'new check, failing' } }; continue }
            $was = [string]$pr['status']
            $countMoved = $r.status -eq 'fail' -and $was -eq 'fail' -and [int]$r.affectedCount -ne [int]$pr['affectedCount']
            if ($r.status -eq $was -and -not $countMoved) { continue }
            if ($changedWhy.ContainsKey([string]$r.id)) {
                $say = { param([string] $status, $count) if ($status -eq 'fail') { "fail ($([int]$count) affected)" } else { $status } }
                $logicChanged += , [ordered]@{ id = $r.id; title = $r.title; severity = $r.severity; before = (& $say $was $pr['affectedCount']); after = (& $say ([string]$r.status) $r.affectedCount); detail = $changedWhy[[string]$r.id] }
            }
            # An answer that is gone is not a fix, and not a failure either.
            elseif ($r.status -eq 'notEvaluated' -and $was -in 'pass', 'fail') { $lostAnswer += , [ordered]@{ id = $r.id; title = $r.title; severity = $r.severity; was = $was; detail = [string]$r.reason } }
            elseif ($r.status -eq 'fail' -and $was -ne 'fail') { $newFailures += , [ordered]@{ id = $r.id; title = $r.title; severity = $r.severity; detail = "was $was" } }
            elseif ($r.status -ne 'fail' -and $was -eq 'fail') { $resolved += , [ordered]@{ id = $r.id; title = $r.title; severity = $r.severity; detail = "now $($r.status)" } }
            elseif ($countMoved) { $moved += , [ordered]@{ id = $r.id; title = $r.title; severity = $r.severity; before = [int]$pr['affectedCount']; after = [int]$r.affectedCount } }
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
            catalogBefore      = $catalogBefore
            catalogAfter       = $catalogAfter
            catalogChanged     = $catalogChanged
            catalogNotes       = @($catalogNotes)
            logicChanged       = @($logicChanged | Sort-Object { -$weight[[string]$_.severity] }, { $_.id })
            lostAnswer         = @($lostAnswer | Sort-Object { -$weight[[string]$_.severity] }, { $_.id })
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

    # Recommendations in the audit plan's buckets (section 5), a card each: within a bucket the quick fixes first
    # (effort S, M, L, then unrated), then the one that affects most. Passing checks are listed per domain.
    $bucketOf = @{ Critical = 'Stop the bleeding'; High = 'Foundations'; Medium = 'Program workstreams'; Low = 'Later' }
    $effortRank = @{ S = 1; M = 2; L = 3 }
    $recommendations = [ordered]@{}
    foreach ($b in 'Stop the bleeding', 'Foundations', 'Program workstreams', 'Later') { $recommendations[$b] = @() }
    $failed = @($results | Where-Object { $_.status -eq 'fail' } | Sort-Object { -$weight[[string]$_.severity] }, { $e = [string]$byId[$_.id]['effort']; if ($effortRank.ContainsKey($e)) { $effortRank[$e] } else { 4 } }, { - [int]$_.affectedCount }, { $_.id })
    foreach ($r in $failed) {
        $c = $byId[$r.id]
        $recommendations[$bucketOf[[string]$r.severity]] += , [ordered]@{
            id = $r.id; title = $r.title; severity = $r.severity; domain = $r.domain; affectedCount = $r.affectedCount
            # How many of them the run holds (and affected/<id>.csv with it): fewer than affectedCount when the check's own list is cut.
            affectedListed = $(if ($r.Contains('affectedListed')) { [int]$r.affectedListed } else { @($r.affected).Count })
            reason = [string]$r.reason; affected = @(@($r.affected) | Select-Object -First 25)
            observed = $(if ($r.Contains('observed') -and $r.observed) { $r.observed } else { [ordered]@{} }); thresholds = $r.thresholds
            why = [string]$c['narrative']
            userImpact = $(if ($c.Contains('userImpact')) { $c['userImpact'] } else { $null })
            steps = @($c['steps']); remediation = [string]$c['remediation']
            effort = $(if ($c.Contains('effort')) { [string]$c['effort'] } else { $null }); category = [string]$c['category']
            learn = [string]$c['learn']; deepLink = [string]$c['deepLink']; license = @($c['license'])
            frameworks = $(if ($c['frameworks']) { $c['frameworks'] } else { [ordered]@{} })
            attack = @(Get-PostureAttackTechnique -Catalog $Catalog -Check $c)
        }
    }
    # Do today: failing quick fixes (effort S) that users will not notice or will barely notice.
    $doToday = @($recommendations.Values | ForEach-Object { $_ } | Where-Object { $_.effort -eq 'S' -and $_.userImpact -and [string]$_.userImpact['level'] -in 'none', 'low' } | ForEach-Object { [ordered]@{ id = $_.id; title = $_.title; severity = $_.severity; userImpact = $_.userImpact } })
    $chains = @(Get-PostureControlChainResult -Chain @(Import-PostureControlChain -Catalog $Catalog) -Result @($results))
    $alreadyGood = [ordered]@{}
    foreach ($r in @($results | Where-Object { $_.status -eq 'pass' } | Sort-Object { $_.domain }, { $_.id })) {
        if (-not $alreadyGood.Contains([string]$r.domain)) { $alreadyGood[[string]$r.domain] = @() }
        $alreadyGood[[string]$r.domain] += , [ordered]@{ id = $r.id; title = $r.title }
    }

    # Who are your admins (spec 7.2): roles joined to registration and users.
    $active = & $load '04-role-assignments-active'
    $eligible = & $load '04-role-assignments-pim-eligible'
    # The administrators' rows: the collector's admin-only files, or for a run made before them the same rows read
    # out of the full lists a row at a time (Get-PostureAdminRow).
    $reg = Get-PostureAdminRow -Folder $Evidence -List Registration
    $users = Get-PostureAdminRow -Folder $Evidence -List Users
    $regByUpn = @{}; foreach ($r in @($reg | Where-Object { $_ })) { $regByUpn[[string]$r.UserPrincipalName] = $r }
    $userByUpn = @{}; foreach ($u in @($users | Where-Object { $_ })) { $userByUpn[[string]$u.UserPrincipalName] = $u }
    $strongest = {
        param([string] $methods)
        $m = @($methods -split ';' | Where-Object { $_ })
        # The same device-bound list AU-008 uses, so the table, the chart and the check agree.
        if ($m -contains 'windowsHelloForBusiness' -and @($m | Where-Object { $_ -in $script:PostureDeviceBoundMethods -and $_ -ne 'windowsHelloForBusiness' }).Count -eq 0) { return 'Windows Hello for Business' }
        if ($m | Where-Object { $_ -in $script:PostureDeviceBoundMethods }) { return 'Phishing-resistant' }
        if ($m -contains 'passKeySynced') { return 'Synced passkey' }
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
                lastSignIn = $(if ($u -and (& $v $u 'LastInteractiveSignIn')) { (ConvertTo-PostureUtcDateTime (& $v $u 'LastInteractiveSignIn')).ToString('yyyy-MM-dd') } else { $null })
                synced = [bool]($a.PrincipalSynced -eq $true)
                licenses = $(if ($u -and $null -ne (& $v $u 'LicenseCount')) { [int](& $v $u 'LicenseCount') } else { $null })
            }
        }
        $row = $adminRows[$key]
        $row.roles = @($row.roles + $a.Role | Select-Object -Unique)
        if ($a.AssignmentType -eq 'Eligible') { $row.eligible = @($row.eligible + $a.Role | Select-Object -Unique) } else { $row.permanent = @($row.permanent + $a.Role | Select-Object -Unique) }
    }
    # People who hold a role through a group get a row of their own beside the group's: the group's row says what
    # was assigned, theirs says who can use it. "Role (through Group)" keeps the two apart in the same columns.
    $roleHolders = Get-PostureRoleHolder -Folder $Evidence
    foreach ($person in $roleHolders.people.get_Values()) {
        foreach ($hr in @($person.roles | Where-Object { $_.held -in 'Group', 'EligibleGroup' })) {
            $key = "user|$($person.id)"
            if (-not $adminRows.ContainsKey($key)) {
                $u = $userByUpn[[string]$person.upn]; $rg = $regByUpn[[string]$person.upn]
                $adminRows[$key] = [ordered]@{
                    name = $person.name; upn = [string]$person.upn; type = 'user'; roles = @(); permanent = @(); eligible = @()
                    strongestMethod = $(if ($rg) { & $strongest ([string]$rg.MethodsRegistered) } else { 'Unknown' })
                    lastSignIn = $(if ($u -and (& $v $u 'LastInteractiveSignIn')) { (ConvertTo-PostureUtcDateTime (& $v $u 'LastInteractiveSignIn')).ToString('yyyy-MM-dd') } else { $null })
                    synced = [bool]($person.synced -eq $true)
                    licenses = $(if ($u -and $null -ne (& $v $u 'LicenseCount')) { [int](& $v $u 'LicenseCount') } else { $null })
                }
            }
            $row = $adminRows[$key]
            $label = "$($hr.role) (through $($hr.groupName))"
            $row.roles = @($row.roles + $hr.role | Select-Object -Unique)
            if ($hr.held -eq 'Group') { $row.permanent = @($row.permanent + $label | Select-Object -Unique) } else { $row.eligible = @($row.eligible + $label | Select-Object -Unique) }
        }
    }
    $adminsTable = @($adminRows.Values | Sort-Object { -(@($_.permanent | Where-Object { $_ -like 'Global Administrator*' }).Count -gt 0) }, { $_.name })

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

    # The story of the run: projected score if the top five fixes land, score history, quick wins (effort against
    # user impact), roadmap lanes, the attack path funnel and the accepted-risk ledger.
    $effortRank = @{ S = 1; M = 2; L = 3 }
    $topFive = @($recommendations.Values | ForEach-Object { $_ } | Select-Object -First 5)
    $projected = $(if ($possible -gt 0) { [Math]::Round(100.0 * ($earned + [double](@($topFive | ForEach-Object { $w = $weight[[string]$_.severity]; if ($w) { $w } else { 1 } }) + 0 | Measure-Object -Sum).Sum) / $possible) } else { $null })
    $earlierRuns = @($(try { Get-PostureScoreHistory -Run $Evidence } catch { @() }))
    $history = @(@($earlierRuns | ForEach-Object { [ordered]@{ label = $_.label; value = $_.value } }) + @($(if ($null -ne $score) { [ordered]@{ label = 'now'; value = $score } })))
    $outcomes = @(Get-PostureOutcomeResult -Catalog $Catalog -Result @($results) -History $earlierRuns)
    $impactOf = { param($x) if ($x.userImpact) { [string]$x.userImpact['level'] } else { 'unknown' } }
    $failingRecs = @($recommendations.Values | ForEach-Object { $_ })
    $quickWins = [ordered]@{}
    foreach ($imp in 'none', 'low', 'medium', 'high') { foreach ($ef in 'S', 'M', 'L') { $quickWins["$imp|$ef"] = @($failingRecs | Where-Object { [string]$_.effort -eq $ef -and (& $impactOf $_) -eq $imp } | ForEach-Object { [ordered]@{ id = $_.id; title = $_.title; severity = $_.severity } }) } }
    $laneOf = { param($x) $e = $(if ($effortRank.ContainsKey([string]$x.effort)) { $effortRank[[string]$x.effort] } else { 2 }); switch ([string]$x.severity) { 'Critical' { 'now' } 'High' { if ($e -eq 1) { 'now' } else { 'next' } } 'Medium' { if ($e -eq 1) { 'next' } else { 'later' } } default { 'later' } } }
    $roadmap = [ordered]@{ now = @(); next = @(); later = @() }
    foreach ($x in $failingRecs) { $roadmap[(& $laneOf $x)] += , [ordered]@{ id = $x.id; title = $x.title; severity = $x.severity; effort = $x.effort } }
    # Nested by construction: one per-user source and the device-bound list AU-008 uses, so every phishable
    # administrator is also counted among the phishable members.
    # Counted by the collector in its own pass over the registration report, or a row at a time for an older run:
    # the report has a row per user and is never loaded here (Get-PostureRegistrationTally).
    $regTally = Get-PostureRegistrationTally -Folder $Evidence
    $funnel = $null
    if ($null -ne $regTally) {
        $memberCount = $regTally.Users; $phishable = $regTally.Phishable; $adminPhishable = $regTally.PhishableAdmins
        $funnel = [ordered]@{ steps = @([ordered]@{ label = 'Members'; value = $memberCount }, [ordered]@{ label = 'Phishable members'; value = $phishable }, [ordered]@{ label = 'Phishable admins'; value = $adminPhishable }); takeaway = "$phishable of $memberCount members have no device-bound phishing-resistant method; $adminPhishable of them $(if ($adminPhishable -eq 1) { 'is an administrator' } else { 'are administrators' }), the shortest path from a stolen password to the tenant." }
    }
    $now = [datetime]::UtcNow
    $ledger = $null
    if (@($Exception).Count) {
        $bucket = [ordered]@{ 'Expired' = 0; 'Within 30 days' = 0; 'Within 90 days' = 0; 'Later' = 0; 'No expiry' = 0 }
        foreach ($e in @($Exception)) { $k = $(if (-not $e.expires) { 'No expiry' } elseif ($e.expired -or $e.expires -lt $now) { 'Expired' } elseif ($e.expires -lt $now.AddDays(30)) { 'Within 30 days' } elseif ($e.expires -lt $now.AddDays(90)) { 'Within 90 days' } else { 'Later' }); $bucket[$k]++ }
        $ledger = [ordered]@{ buckets = $bucket; total = @($Exception).Count }
    }
    $story = [ordered]@{ projected = $projected; history = $history; outcomes = $outcomes; quickWins = $quickWins; roadmap = $roadmap; funnel = $funnel; ledger = $ledger }

    $catalogText = [ordered]@{}
    foreach ($c in $Catalog.checks) { $catalogText[[string]$c['id']] = [ordered]@{ narrative = [string]$c['narrative']; remediation = [string]$c['remediation']; steps = @($c['steps']); effort = $(if ($c.Contains('effort')) { [string]$c['effort'] } else { $null }); category = [string]$c['category']; userImpact = $(if ($c.Contains('userImpact')) { $c['userImpact'] } else { $null }); learn = [string]$c['learn']; deepLink = [string]$c['deepLink']; license = @($c['license']); frameworks = $c['frameworks']; attack = @(Get-PostureAttackTechnique -Catalog $Catalog -Check $c); evidence = @($c['evidence']); input = $(if ($c.Contains('input')) { $c['input'] } else { $null }) } }

    $collection = & $load 'collection'
    $tenantId = $(if ($collection) { & $v $collection 'tenantId' } else { & $v (& $load 'metadata') 'tenantId' })
    $org = & $load '01-organization'
    $tenantName = $(if ($org) { [string](& $v @($org)[0] 'displayName') } else { $null })
    $clientName = $(if ($Brand.client.name) { [string]$Brand.client.name } elseif ($OrgProfile.clientName) { [string]$OrgProfile.clientName } elseif ($tenantName) { $tenantName } else { [string]$tenantId })

    # Licences the tenant holds, from the SKUs the Entra collector read: purchased, assigned, free.
    $skus = & $load '01-subscribed-skus'
    $licensing = $null
    if ($null -ne $skus) {
        $licensing = @(@($skus) | Where-Object { $_ } | ForEach-Object {
                $bought = [int](Get-PostureValue $_ 'prepaidUnits.enabled'); $used = [int](Get-PostureValue $_ 'consumedUnits')
                [ordered]@{ sku = [string]$_['skuPartNumber']; purchased = $bought; assigned = $used; available = [Math]::Max(0, $bought - $used); status = [string]$_['capabilityStatus'] }
            } | Sort-Object { - $_.purchased }, { $_.sku })
    }
    # The licensing advisor: features owned, partly assigned or missing, goals, and what to add for the profile's
    # goals; and the checks that could not be judged for lack of a licence, by what they need.
    $licenseAdvice = $null
    if ($null -ne $skus) {
        $planUse = & $load '06-users-license-plans'
        $byPlan = $(if ($planUse -and (& $v $planUse 'UsersByServicePlan')) { & $v $planUse 'UsersByServicePlan' } else { @{} })
        $licensedUsers = $(if ($planUse) { [int](& $v $planUse 'LicensedEnabledUsers') } else { 0 })
        $members = [int](& $v (& $load '06-users-summary') 'Members')
        $goalIds = @($(if ($OrgProfile -and $OrgProfile.Contains('goals')) { $OrgProfile['goals'] }) | Where-Object { $_ })
        $ownedFeatures = @(Get-PostureOwnedFeature -Sku @($skus | Where-Object { $_ }))
        $thirdPartyMap = $(if ($OrgProfile -and $OrgProfile.Contains('thirdParty') -and $OrgProfile['thirdParty']) { $OrgProfile['thirdParty'] } else { @{} })
        $seatCount = $(if ($licensedUsers) { $licensedUsers } else { $members })
        $licenseAdvice = Get-PostureLicenseAdvice -Owned $ownedFeatures -Goal $goalIds -Seats $seatCount -UsersByPlan $byPlan -LicensedUsers $licensedUsers -ThirdParty $thirdPartyMap -OwnedSku @($skus | Where-Object { $_ } | ForEach-Object { [string](Get-PostureValue $_ 'skuPartNumber') } | Where-Object { $_ })
        # What the page needs to run the same advisor again when goals or vendors change (templates/licensing.js).
        $licenseAdvice.page = Get-PostureLicensePageData -Owned $ownedFeatures -ThirdParty $thirdPartyMap -Seats $seatCount -Goal $goalIds -OwnedSku @($skus | Where-Object { $_ } | ForEach-Object { [string](Get-PostureValue $_ 'skuPartNumber') } | Where-Object { $_ })
        $licenseAdvice.notEvaluated = @($results | Where-Object { $_.status -eq 'notEvaluated' -and [string]$_.reason -match '^Requires (.+)\.$' } | Group-Object { [string]$_.reason } | Sort-Object Name | ForEach-Object { [ordered]@{ needs = ($_.Name -replace '^Requires |\.$', ''); checks = @($_.Group | ForEach-Object { [ordered]@{ id = $_.id; title = $_.title } }) } })
    }

    # Who ran it, with which roles, from run.json (Start-PostureRun records them after the sign-in).
    $runLayout = Get-PostureRunLayout -Folder $Evidence
    $planFile = Join-Path $runLayout.logs 'run.json'
    $plan = $(if (Test-Path -LiteralPath $planFile) { try { Get-Content -Raw -LiteralPath $planFile | ConvertFrom-Json -AsHashtable -Depth 10 } catch { $null } } else { $null })
    $runAs = $(if ($plan -and (Get-PostureValue $plan 'runAs')) { Get-PostureValue $plan 'runAs' } else { $null })

    # Run health: every failed step with its cause and what to grant, worst cause first (errors.jsonl, or errors.txt
    # for runs made before it existed).
    $causeOrder = @{ permission = 0; unavailable = 1; licence = 2; token = 3; module = 4; throttled = 5; network = 6; notProvisioned = 7; notReadable = 8; unknown = 9 }
    $causeLabel = @{ permission = 'Needs a role'; unavailable = 'Needs a role or licence'; licence = 'Needs a licence'; token = 'Sign-in ran out'; module = 'Module missing'; throttled = 'Throttled'; network = 'Network or service error'; notProvisioned = 'Not set up in this tenant'; notReadable = 'Not readable with this sign-in'; unknown = 'Not recognised' }
    $failures = @($(try { Read-PostureRunFailure -Folder $Evidence } catch { @() }))
    $fullTierForHealth = ($Entitlement['domains'] -is [string] -and $Entitlement['domains'] -eq '*')
    $runHealth = [ordered]@{
        failures = @($failures | Sort-Object { $causeOrder[[string]$_['cause']] }, { [string]$_['collector'] }, { [string]$_['step'] } | ForEach-Object {
                [ordered]@{ collector = [string]$_['collector']; step = [string]$_['step']; cause = [string]$_['cause']; causeLabel = $causeLabel[[string]$_['cause']]; advice = (Get-PostureFailureAdvice -Failure $_); roles = @($_['roles']); licence = [string]$_['licence']; message = [string]$_['message']
                    support = (Get-PostureSupportDetail -Failure $_ -RunName (Split-Path $runLayout.root -Leaf) -Build ([string]$buildState.detail) -Name @($tenantName, $clientName, $(if ($runAs) { [string](Get-PostureValue $runAs 'account') })))
                }
            })
        byCause  = [ordered]@{}
        resume   = "Resume-PostureRun -Path '$((Get-PostureRunLayout -Folder $Evidence).root -replace "'", "''")'"
        diagnostics = "Export-PostureDiagnostics -Run '$((Get-PostureRunLayout -Folder $Evidence).root -replace "'", "''")'"
        # Every request the run sent, counted (logs/calls.json), and anything that was not a read.
        calls    = $(try { Get-PostureCallSummary -Folder $Evidence } catch { $null })
        # Evidence brought in from another machine (Import-PostureEvidence): what, from where, and how it was checked.
        imports  = @($(try { $il = Join-Path $runLayout.logs 'imports.json'; if (Test-Path -LiteralPath $il) { @(Get-Content -Raw -LiteralPath $il | ConvertFrom-Json -AsHashtable -Depth 6) } } catch { @() }) | Where-Object { $_ } | ForEach-Object {
                [ordered]@{ kind = [string]$_['kind']; label = [string]$_['label']; collector = [string]$_['collector']; collectedUtc = [string]$_['collectedUtc']; importedUtc = [string]$_['importedUtc']; account = [string]$_['account']; checked = [string]$_['checked']; files = @($_['files']).Count; tenantCheck = [string]$(if ($_.Contains('tenantCheck')) { $_['tenantCheck'] }) }
            })
    }
    # What Microsoft had open for the tenant when the run was made (12-service-health): incidents first. It is not a
    # finding; it is here because an incident on the day explains a read that failed or a number that looks wrong.
    $serviceIssues = & $load '12-service-health'
    $runHealth.serviceHealth = $(if ($null -eq $serviceIssues -or -not $fullTierForHealth) { $null } else {
            @(@($serviceIssues) | Where-Object { $_ } | Sort-Object { $(if ([string](& $v $_ 'Classification') -eq 'incident') { 0 } else { 1 }) }, { [string](& $v $_ 'Service') } | ForEach-Object { [ordered]@{ id = [string](& $v $_ 'Id'); service = [string](& $v $_ 'Service'); title = [string](& $v $_ 'Title'); kind = [string](& $v $_ 'Classification'); status = [string](& $v $_ 'Status') } })
        })
    # The Active Directory read is made apart from the run, sometimes long before it: the hybrid scorecard says when.
    $adImport = @($runHealth.imports | Where-Object { $_.kind -eq 'ad' -and $_.collectedUtc } | Select-Object -Last 1)
    if ($adImport.Count -gt 0) {
        $adWhen = ConvertTo-PostureUtcDateTime $adImport[0].collectedUtc
        $runWhen = $(if ($collection -and (& $v $collection 'timestampUtc')) { ConvertTo-PostureUtcDateTime (& $v $collection 'timestampUtc') } else { $null })
        if ($adWhen) {
            $days = $(if ($runWhen) { [int][Math]::Floor(($runWhen - $adWhen).TotalDays) } else { $null })
            $note = "Active Directory was read on $($adWhen.ToString('yyyy-MM-dd'))$(if ($null -ne $days -and $days -ge 1) { ", $days day$(if ($days -ne 1) { 's' }) before the rest of this run" })."
            foreach ($d in @($domains)) { if ($d.key -eq 'hybrid') { $d.evidenceNote = $note } }
        }
    }
    # Checks that have an answer from part of the data (a sample, a capped list, some subscriptions): each with the
    # sentence that says how much was read.
    $runHealth.judgedOnPart = @($results | Where-Object { $_.status -in 'pass', 'fail' -and $_.Contains('judgedOnPart') -and $_.judgedOnPart } | ForEach-Object { [ordered]@{ id = [string]$_.id; title = [string]$_.title; status = [string]$_.status; note = [string]$_.judgedOnPart } })
    # Where a collection stopped. From the journal (logs/journal.jsonl; a run made before it has none): the steps
    # the collection started and never finished, and the files left from an earlier attempt, which are not read.
    # From the plan and the manifest: the collectors the run set out to collect that did not finish (the same
    # answer Resume-PostureRun gives). From the folder: writes that were cut short (.part files, never read).
    $journal = $(try { Get-PostureJournalState -Folder $Evidence } catch { @{ present = $false; steps = @{}; collectors = @{}; files = @{} } })
    $runHealth.stoppedIn = @($journal.steps.get_Values() | Where-Object { $_.state -eq 'started' } | Sort-Object { $_.started } | ForEach-Object { [ordered]@{ collector = [string]$_.collector; step = [string]$_.step } })
    $finished = @($(try { Get-PostureFinishedCollector -Folder $Evidence -Manifest @($(if ($collection) { & $v $collection 'collectors' })) } catch { @($(if ($collection) { & $v $collection 'collectors' })) }))
    # Steps that were not attempted because the sign-in they depend on had ended.
    $runHealth.notAttempted = @($journal.steps.get_Values() | Where-Object { $_.state -eq 'skipped' } | Sort-Object { [string]$_.collector }, { [string]$_.step } | ForEach-Object { [ordered]@{ collector = [string]$_.collector; step = [string]$_.step } })
    $expected = @(@($(if ($plan) { Get-PostureValue $plan 'planned' })) + @($journal.collectors.get_Keys()) | Where-Object { $_ } | Select-Object -Unique)
    $runHealth.notFinished = @($expected | Where-Object { $_ -notin $finished })
    $staleNames = @($(try { Get-PostureStaleEvidence -Folder $Evidence } catch { @() }))
    $runHealth.stale = @($staleNames | ForEach-Object { $n = $_; $rec = @($journal.files.get_Keys() | Where-Object { ($_ -replace '\.(json|csv)$', '') -eq $n } | ForEach-Object { $journal.files[$_] })[0]; [ordered]@{ file = $n; collector = [string]$(if ($rec) { $rec.collector }); step = [string]$(if ($rec) { $rec.step }) } })
    $runHealth.cutShort = @(Get-ChildItem -LiteralPath $runLayout.evidence -File -Filter '*.part' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name } | Sort-Object)
    foreach ($f in $runHealth.failures) { $runHealth.byCause[$f.causeLabel] = 1 + $(if ($runHealth.byCause.Contains($f.causeLabel)) { $runHealth.byCause[$f.causeLabel] } else { 0 }) }
    $runHealth.retryable = @($runHealth.failures | Where-Object { $_.cause -in 'permission', 'token', 'throttled', 'network', 'unknown', 'module' }).Count

    # The tiers (docs/licensing.md): without the full tier only the Conditional Access domain is assessed, so nothing
    # drawn straight from the evidence (charts, the inventory beyond CA, administrators, headline figures, Copilot,
    # licensing) appears either; the checks are limited the same way above.
    $fullTier = ($Entitlement['domains'] -is [string] -and $Entitlement['domains'] -eq '*')
    $allowedDomains = @($Entitlement['domains'])
    if (-not $fullTier) { foreach ($k in @($headline.Keys)) { $headline[$k] = $null } }
    # What the assessment still lacks, as rows someone can act on (the completion block of checks/catalog.json).
    # Only where every domain is assessed: in the Conditional Access tier the other domains are not waiting for evidence.
    $completion = @()
    if ($fullTier) {
        $completionArgs = @{ Catalog = $Catalog; Result = @($results); Evidence = $Evidence; Failure = @($failures) }
        if ($plan -is [System.Collections.IDictionary]) { $completionArgs.Plan = $plan }
        if ($collection -is [System.Collections.IDictionary]) { $completionArgs.Collection = $collection }
        $completion = @($(try { Get-PostureCompletion @completionArgs } catch { Write-Verbose "What the assessment lacks was not worked out: $($_.Exception.Message)"; @() }))
        # Every source with where this run stands, for Run Health: the list above is silent when nothing is missing,
        # and a reader cannot tell "not needed for this tenant" from "nobody told me".
        $runHealth['sources'] = @($(try { Get-PostureSourceStatus -Catalog $Catalog -Evidence $Evidence -Completion @($completion) -Failure @($failures) } catch { Write-Verbose "The sources were not listed: $($_.Exception.Message)"; @() }))
    }

    # The organisation's own logo and icon from its Entra company branding, for the top of the page and the browser
    # tab. In any paid tier. A redacted copy leaves it out (ConvertTo-PostureRedactedReport): a logo names the customer.
    $tenantLogo = $null
    if ($Entitlement['licensed']) {
        $logoDoc = $(try { Read-PostureEvidenceFile -Folder $Evidence -Name '01-company-branding-logos' } catch { $null })
        if ($logoDoc -is [System.Collections.IDictionary]) {
            $asUri = {
                param([string] $Name, [string[]] $Allowed)
                $x = $logoDoc[$Name]
                if (-not ($x -is [System.Collections.IDictionary])) { return $null }
                $type = [string]$x['ContentType']; $data = [string]$x['Base64']
                # The evidence is a file anyone could have edited: only the image kinds the collector keeps, only base64, and no more than it would have kept.
                if ($type -notin $Allowed -or $data.Length -eq 0 -or $data.Length -gt 720000 -or $data -notmatch '^[A-Za-z0-9+/]+={0,2}$') { return $null }
                "data:$type;base64,$data"
            }
            $picture = @('image/png', 'image/jpeg', 'image/gif')
            $banner = & $asUri 'BannerLogo' $picture; if (-not $banner) { $banner = & $asUri 'SquareLogo' $picture }
            $icon = & $asUri 'Favicon' ($picture + 'image/x-icon'); if (-not $icon) { $icon = & $asUri 'SquareLogo' $picture }
            if ($banner -or $icon) { $tenantLogo = [ordered]@{ banner = $banner; icon = $icon } }
        }
    }

    return [ordered]@{
        title        = "Microsoft Security Posture Report: $clientName"
        tenantLogo   = $tenantLogo
        clientName   = $clientName
        tenantId     = $tenantId
        tenantName   = $tenantName
        template     = $Template
        brand        = $Brand
        generatedUtc = $GeneratedUtc
        collectedUtc = $(if ($collection) { & $v $collection 'timestampUtc' } else { $null })
        collectors   = @($(if ($collection) { & $v $collection 'collectors' } else { @() }))
        licence      = $Run.entitlement
        attestations = $(if ($OrgProfile.attestations) { $OrgProfile.attestations } else { [ordered]@{} })
        exceptions   = @($Exception | ForEach-Object { [ordered]@{ check = $_.check; object = $_.object; justification = $_.justification; owner = $_.owner; approver = $_.approver; expires = $(if ($_.expires) { $_.expires.ToString('yyyy-MM-dd') } else { $null }) } })
        build        = [ordered]@{ state = [string]$buildState.state; detail = [string]$buildState.detail; version = [string]$buildState.version }
        score        = [ordered]@{ value = $score; grade = $grade; method = 'Weighted pass rate over evaluated checks: Critical 4, High 3, Medium 2, Low 1. Accepted risk counts as a pass and is marked. Not evaluated and not applicable checks are excluded.'; evaluated = $scored.Count; earned = $earned; possible = $possible }
        headline     = $headline
        counts       = $Run.counts
        topRisks     = $topRisks
        domains      = @($domains)
        domainsNotCollected = $domainsNotCollected
        recommendations = $recommendations
        alreadyGood     = $alreadyGood
        chains          = $chains
        layers          = @(Get-PostureLayerSetResult -LayerSet @(Import-PostureLayerSet -Catalog $Catalog) -Result @($results))
        journeys        = @(Get-PostureJourneyResult -Catalog $Catalog -Result @($results))
        doToday         = $doToday
        story           = $story
        inventory       = @(Get-PostureInventory -Evidence $Evidence | Where-Object { $fullTier -or [string]$_.domain -in $allowedDomains })
        charts          = $(if (-not $fullTier) { [ordered]@{} } else { Get-PostureChartData -Evidence $Evidence -Admin @($adminsTable) -DomainFacts $(if ($Run.Contains('domains')) { $f = [ordered]@{}; foreach ($k in $Run.domains.Keys) { $f[$k] = $Run.domains[$k].facts }; $f } else { @{} }) })
        admins       = @(if ($fullTier) { $adminsTable })
        ca           = $ca
        copilot      = $(if ($fullTier) { $copilot } else { $null })
        trend        = $trend
        crosswalk    = $crosswalk
        attack       = (Get-PostureAttackCoverage -Catalog $Catalog -Result @($results))
        results      = $results
        catalogText  = $catalogText
        labels       = $(if ($Catalog.Contains('labels') -and $Catalog['labels']) { $Catalog['labels'] } else { @{ facts = @{}; thresholds = @{} } })
        runHealth    = $runHealth
        completion   = $completion
        licensing    = $(if ($fullTier) { $licensing } else { $null })
        licenseAdvice = $(if ($fullTier) { $licenseAdvice } else { $null })
        runAs        = $runAs
        appendix     = [ordered]@{
            catalogVersion = $Run.catalogVersion; baseline = $Run.baseline; profile = $Run.profile; profilePresent = [bool]$OrgProfile.present
            profileAnswers = $(if ($OrgProfile.present) { [ordered]@{ licenses = @($OrgProfile.licenses); platforms = @($OrgProfile.platforms); identityModel = $OrgProfile.identityModel; byod = $OrgProfile.byod; externalCollaboration = $OrgProfile.externalCollaboration; copilot = $OrgProfile.copilot; azure = $OrgProfile.azure; thirdParty = $OrgProfile.thirdParty; frameworks = @($OrgProfile.frameworks); thresholds = $OrgProfile.thresholds; breakGlass = @($OrgProfile.breakGlass) } } else { $null })
            exceptions = @($Exception)
            evidence = $Evidence
            scopes = @($(if ($collection) { & $v $collection 'scopes' } else { @() }))
            graphApiVersions = @($(if ($collection) { & $v $collection 'graphApiVersions' } else { @() }))
            evidenceFiles = @(Get-ChildItem -LiteralPath $Evidence -File | Where-Object { $_.Extension -in '.json', '.csv' -and $_.Name -notin 'run.json', 'calls.json', 'imports.json' } | ForEach-Object { $_.Name } | Sort-Object)
            errors = @($(if ($collection) { & $v $collection 'errors' } else { @() }))
            notEvaluated = @($results | Where-Object { $_.status -in @('notEvaluated', 'notApplicable') } | ForEach-Object { [ordered]@{ id = $_.id; title = $_.title; status = $_.status; reason = $_.reason } })
            moduleVersion = $script:ModuleVersion
            build = [string]$buildState.detail
            licence = $(if ($Run.entitlement.licensed) { "$(if ($Run.entitlement.Contains('trial') -and $Run.entitlement.trial) { 'trial, ' })$($Run.entitlement.tier) tier, licence $($Run.entitlement.licenceId), $($Run.entitlement.customer), expires $($Run.entitlement.expiresUtc)" } else { "none: $($Run.entitlement.reason)" })
        }
    }
}
