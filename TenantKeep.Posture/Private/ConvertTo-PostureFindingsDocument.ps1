# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function ConvertTo-PostureFindingsDocument {
    <#
    .SYNOPSIS
        findings.json: the assessment as one document a tool or an AI model reads without parsing the report. A
        summary first, then every failing check ranked, each with why it matters, how to fix it, where, what it
        needs and a sample of what it affects; then accepted risks and what could not be evaluated.
    .DESCRIPTION
        The shape is stable (schemaVersion) and explained in the document itself (about), so a model given only this
        file knows how to read it. Ranking: severity (Critical, High, Medium, Low), then effort (quick fixes
        first), then the number of objects affected, then the check id: the order of the report's Recommendations. The full affected lists are in affected/<id>.csv beside the report.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Report,
        [int] $SampleSize = 25
    )

    $ErrorActionPreference = 'Stop'
    $weight = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }
    $priority = @{ Critical = 'Stop the bleeding: this week'; High = 'Foundations: this quarter'; Medium = 'Program workstreams: planned work'; Low = 'Later: when time allows' }
    $text = $Report.catalogText
    $nameOf = { param($a) if ($a -is [System.Collections.IDictionary]) { [string]$a['name'] } else { [string]$a } }
    $detailOf = { param($a) if ($a -is [System.Collections.IDictionary] -and $a.Contains('detail')) { [string]$a['detail'] } else { '' } }
    $labelOf = @{}; foreach ($d in @($Report.domains) + @($Report.domainsNotCollected)) { if ($d) { $labelOf[[string]$d.key] = [string]$d.label } }

    $effortRank = @{ S = 1; M = 2; L = 3 }
    $effortOf = { param($id) if ($text.Contains($id) -and $text[$id]['effort'] -and $effortRank.ContainsKey([string]$text[$id]['effort'])) { $effortRank[[string]$text[$id]['effort']] } else { 4 } }
    $failing = @($Report.results | Where-Object { $_.status -eq 'fail' } | Sort-Object { - $weight[[string]$_.severity] }, { & $effortOf $_.id }, { - [int]$_.affectedCount }, { $_.id })
    $factText = $(if ($Report.Contains('labels') -and $Report.labels -and $Report.labels.facts) { $Report.labels.facts } else { @{} })
    $rank = 0
    $findings = foreach ($r in $failing) {
        $rank++
        $c = $(if ($text.Contains($r.id)) { $text[$r.id] } else { @{} })
        [ordered]@{
            rank           = $rank
            id             = $r.id
            title          = $r.title
            domain         = $(if ($labelOf.ContainsKey([string]$r.domain)) { $labelOf[[string]$r.domain] } else { [string]$r.domain })
            severity       = $r.severity
            priority       = $priority[[string]$r.severity]
            category       = $(if ($c['category']) { [string]$c['category'] } else { 'fix' })
            effort         = $(if ($c['effort']) { [string]$c['effort'] } else { $null })
            finding        = [string]$r.reason
            observed       = $(if ($r.Contains('observed') -and $r.observed) { $r.observed } else { [ordered]@{} })
            thresholds     = $(if ($r.Contains('thresholds') -and $r.thresholds) { $r.thresholds } else { [ordered]@{} })
            found          = @(@($(if ($r.Contains('observed') -and $r.observed) { $r.observed.Keys | ForEach-Object { [ordered]@{ label = $(if ($factText.Contains($_)) { [string]$factText[$_] } else { $_ }); value = $r.observed[$_] } } })))
            affectedCount  = [int]$r.affectedCount
            affectedListed = $(if ($r.Contains('affectedListed')) { [int]$r.affectedListed } else { @($r.affected).Count })
            affectedSample = @(@($r.affected) | Select-Object -First $SampleSize | ForEach-Object { [ordered]@{ name = (& $nameOf $_); detail = (& $detailOf $_) } })
            affectedFile   = $(if ([int]$r.affectedCount -gt 0) { "affected/$($r.id).csv" } else { $null })
            whyItMatters   = [string]$c['narrative']
            userImpact     = $(if ($c['userImpact']) { [ordered]@{ level = [string]$c['userImpact']['level']; whatUsersNotice = [string]$c['userImpact']['text'] } } else { $null })
            howToFix       = [string]$c['remediation']
            steps          = @($c['steps'] | Where-Object { $_ })
            portal         = [string]$c['deepLink']
            learn          = [string]$c['learn']
            licenceNeeded  = @($c['license'] | Where-Object { $_ })
            frameworks     = $(if ($c['frameworks']) { $c['frameworks'] } else { [ordered]@{} })
            attack         = @(@($c['attack']) | Where-Object { $_ } | ForEach-Object { [ordered]@{ id = [string]$_.id; name = [string]$_.name; url = [string]$_.url } })
        }
    }
    $rh = $Report.runHealth
    # The remediation plan in brief: stages of projects, each with its failing checks and what it waits on.
    $plan = $null
    if ($Report.Contains('plan') -and $Report.plan) {
        $brief = { param($p) [ordered]@{ id = $p.id; name = $p.name; risk = $p.risk; toFix = $p.toFix; size = $p.size; checks = @($p.checks | ForEach-Object { $_.id }); waitsOn = @($p.waitsOn | ForEach-Object { [ordered]@{ id = $_.id; name = $_.name; kind = $_.kind; state = $_.state; why = $_.why } }) } }
        $plan = [ordered]@{
            about = 'Projects (groups of checks) with something to fix, in the order they can start. Projects in one stage do not wait on each other. waitsOn.kind is needs (finish that one first) or after (recommended order).'
            stages = @($Report.plan.columns | Where-Object { $_.key -ne 'inPlace' } | ForEach-Object { [ordered]@{ stage = $_.key; projects = @($_.projects | ForEach-Object { & $brief $_ }) } })
            alsoReady = @($Report.plan.whenever | ForEach-Object { & $brief $_ })
            counts = $Report.plan.counts
        }
    }
    return [ordered]@{
        about          = 'TenantKeep Posture findings. "findings" lists every failing check, most important first (rank 1 first): severity, then effort (S quick, M planned, L a project), then how many objects it affects. category is fix (a gap) or improve (hardening beyond the baseline). userImpact says what users notice when the fix lands (level none, low, medium, high); summary.doToday lists the quick fixes users will barely notice. Each has what was found (observed: the values judged, beside the thresholds), why it matters, how to fix it as steps with the admin portal and Microsoft Learn links, the licence it needs, the MITRE ATT&CK techniques it helps stop or detect (attack), and up to 25 affected objects; affectedFile names the CSV with all of them. "licensing" says what the licences held cover and the smallest addition for the chosen goals, with no prices. "chains" are controls that protect only together: status pass, broken (brokenAt names the first failing link, the one to fix first) or notEvaluated. "acceptedRisks" were failures the organisation accepted with a reason and an expiry; "notEvaluated" could not be judged from what was collected, with why; "summary.runHealth" lists what could not be read and what to grant. Nothing in this file was written to the tenant.'
        schemaVersion  = 1
        tenant         = [ordered]@{ id = $Report.tenantId; name = $Report.tenantName }
        generatedUtc   = [string]$Report.generatedUtc
        collectedUtc   = [string]$Report.collectedUtc
        moduleVersion  = $Report.appendix.moduleVersion
        baseline       = $Report.appendix.baseline
        summary        = [ordered]@{
            score               = $Report.score.value
            grade               = $Report.score.grade
            scoreMethod         = $Report.score.method
            counts              = $Report.counts
            domains             = @($Report.domains | ForEach-Object { [ordered]@{ domain = $_.label; score = $_.score; pass = $_.counts.pass; fail = $_.counts.fail; notEvaluated = $_.counts.notEvaluated } })
            domainsNotCollected = @($Report.domainsNotCollected | ForEach-Object { $_.label })
            doToday             = @($(if ($Report.Contains('doToday')) { $Report.doToday | ForEach-Object { $_.id } }))
            runHealth           = @($(if ($rh) { $rh.failures | ForEach-Object { [ordered]@{ domain = $_.collector; step = $_.step; why = $_.causeLabel; whatToDo = $_.advice } } }))
        }
        findings       = @($findings)
        licensing      = $(if ($Report.Contains('licenseAdvice') -and $Report.licenseAdvice) { $la = $Report.licenseAdvice; [ordered]@{ advice = $la.advice; featuresOwned = @($la.features | Where-Object { $_.status -ne 'missing' } | ForEach-Object { $_.name }); featuresPartlyAssigned = @($la.features | Where-Object { $_.status -eq 'partial' } | ForEach-Object { $_.name }); goalsNotCovered = @($la.goals | Where-Object { -not $_.met } | ForEach-Object { [ordered]@{ goal = $_.name; needs = $_.missing } }) } } else { $null })
        chains         = @($(if ($Report.Contains('chains')) { $Report.chains | ForEach-Object { [ordered]@{ id = $_.id; name = $_.name; status = $_.status; brokenAt = $_.brokenAt; whyItMatters = $_.why; links = @($_.links | ForEach-Object { [ordered]@{ id = $_.check; title = $_.title; status = $_.status; role = $_.role } }) } } }))
        plan           = $plan
        acceptedRisks  = @($Report.results | Where-Object { $_.status -eq 'acceptedRisk' } | ForEach-Object { [ordered]@{ id = $_.id; title = $_.title; severity = $_.severity; reason = $_.reason } })
        notEvaluated   = @($Report.results | Where-Object { $_.status -eq 'notEvaluated' } | ForEach-Object { [ordered]@{ id = $_.id; title = $_.title; reason = $_.reason } })
    }
}
