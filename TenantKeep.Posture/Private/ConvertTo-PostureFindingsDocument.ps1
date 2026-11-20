# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function ConvertTo-PostureFindingsDocument {
    <#
    .SYNOPSIS
        findings.json: the assessment as one document a tool or an AI model reads without parsing the report. A
        summary first, then every failing check ranked, each with why it matters, how to fix it, where, what it
        needs and a sample of what it affects; then accepted risks and what could not be evaluated.
    .DESCRIPTION
        The shape is stable (schemaVersion) and explained in the document itself (about), so a model given only this
        file knows how to read it. Ranking: severity (Critical, High, Medium, Low), then the number of objects
        affected, then the check id. The full affected lists are in affected/<id>.csv beside the report.
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

    $failing = @($Report.results | Where-Object { $_.status -eq 'fail' } | Sort-Object { - $weight[[string]$_.severity] }, { - [int]$_.affectedCount }, { $_.id })
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
            finding        = [string]$r.reason
            affectedCount  = [int]$r.affectedCount
            affectedSample = @(@($r.affected) | Select-Object -First $SampleSize | ForEach-Object { [ordered]@{ name = (& $nameOf $_); detail = (& $detailOf $_) } })
            affectedFile   = $(if ([int]$r.affectedCount -gt 0) { "affected/$($r.id).csv" } else { $null })
            whyItMatters   = [string]$c['narrative']
            howToFix       = [string]$c['remediation']
            portal         = [string]$c['deepLink']
            learn          = [string]$c['learn']
            licenceNeeded  = @($c['license'] | Where-Object { $_ })
            frameworks     = $(if ($c['frameworks']) { $c['frameworks'] } else { [ordered]@{} })
        }
    }
    $rh = $Report.runHealth
    return [ordered]@{
        about          = 'TenantKeep Posture findings. "findings" lists every failing check, most important first (rank 1 first): severity, then how many objects it affects. Each has what was found, why it matters, how to fix it with the admin portal and Microsoft Learn links, the licence it needs, and up to 25 affected objects; affectedFile names the CSV with all of them. "acceptedRisks" were failures the organisation accepted with a reason and an expiry; "notEvaluated" could not be judged from what was collected, with why; "summary.runHealth" lists what could not be read and what to grant. Nothing in this file was written to the tenant.'
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
            runHealth           = @($(if ($rh) { $rh.failures | ForEach-Object { [ordered]@{ domain = $_.collector; step = $_.step; why = $_.causeLabel; whatToDo = $_.advice } } }))
        }
        findings       = @($findings)
        acceptedRisks  = @($Report.results | Where-Object { $_.status -eq 'acceptedRisk' } | ForEach-Object { [ordered]@{ id = $_.id; title = $_.title; severity = $_.severity; reason = $_.reason } })
        notEvaluated   = @($Report.results | Where-Object { $_.status -eq 'notEvaluated' } | ForEach-Object { [ordered]@{ id = $_.id; title = $_.title; reason = $_.reason } })
    }
}
