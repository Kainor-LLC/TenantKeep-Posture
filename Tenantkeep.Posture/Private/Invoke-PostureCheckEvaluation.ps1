# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureCheckEvaluation {
    <#
    .SYNOPSIS
        The check engine: runs a catalog against evidence with a baseline, a profile and exceptions, one result per check in scope.
    .DESCRIPTION
        Facts come from one provider per domain, Get-Posture<Domain>Fact, called once per domain as
        -Evidence <folder> -OrgProfile <profile> -Thresholds <merged domain thresholds>. -FactProvider overrides providers by domain (tests).
        Statuses: pass, fail, notEvaluated (reason: license, data missing, provider failed), notApplicable (profile),
        acceptedRisk (exception), coveredBy (third-party control in the profile).
        Threshold precedence: catalog default, then profile.thresholds by key, then baseline.thresholds[check id].
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Catalog,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Baseline,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $OrgProfile,
        [AllowEmptyCollection()] [object[]] $Exception = @(),
        [Parameter(Mandatory)] [string] $Evidence,
        [string[]] $Domain,
        [hashtable] $FactProvider = @{},
        [datetime] $AsOf = [datetime]::UtcNow
    )

    $ErrorActionPreference = 'Stop'

    # 1. Scope from the baseline, then the optional domain filter.
    $all = @($Catalog.checks)
    $selected = if (@($Baseline.checks) -contains '*') { $all } else { @($all | Where-Object { $_['id'] -in @($Baseline.checks) }) }
    $selected = @($selected | Where-Object { $_['id'] -notin @($Baseline.exclude) })
    if ($Domain) { $selected = @($selected | Where-Object { [string]$_['domain'] -in $Domain }) }

    # 2. Effective thresholds per check, and merged per domain for the providers.
    $effective = @{}
    $domainThresholds = @{}
    foreach ($c in $selected) {
        $t = [ordered]@{}
        foreach ($k in @($c['thresholds'].Keys)) { $t[$k] = $c['thresholds'][$k] }
        foreach ($k in @($t.Keys)) { if ($OrgProfile.thresholds -and $OrgProfile.thresholds.Contains($k)) { $t[$k] = $OrgProfile.thresholds[$k] } }
        $override = $Baseline.thresholds[$c['id']]
        if ($override) { foreach ($k in @($override.Keys)) { $t[$k] = $override[$k] } }
        $effective[$c['id']] = $t
        $d = [string]$c['domain']
        if (-not $domainThresholds.ContainsKey($d)) { $domainThresholds[$d] = @{} }
        foreach ($k in @($t.Keys)) { $domainThresholds[$d][$k] = $t[$k] }
    }

    # 3. Facts per domain.
    $domainFacts = @{}
    foreach ($d in @($domainThresholds.Keys)) {
        $provider = $FactProvider[$d]
        if (-not $provider) {
            $name = "Get-Posture$($d.Substring(0, 1).ToUpperInvariant() + $d.Substring(1))Fact"
            $cmd = Get-Command -Name $name -ErrorAction SilentlyContinue
            if ($cmd) { $provider = $cmd }
        }
        if (-not $provider) { $domainFacts[$d] = @{ available = $false; reason = "No fact provider for domain '$d'." }; continue }
        try {
            $r = & $provider -Evidence $Evidence -OrgProfile $OrgProfile -Thresholds $domainThresholds[$d]
            if (-not $r.Contains('available')) { $r['available'] = $true }
            if (-not $r.Contains('affected')) { $r['affected'] = @{} }
            if (-not $r.Contains('evidence')) { $r['evidence'] = @() }
            $domainFacts[$d] = $r
        }
        catch { $domainFacts[$d] = @{ available = $false; reason = "Fact provider for '$d' failed: $($_.Exception.Message)" } }
    }

    # 4. Evaluate.
    $results = foreach ($c in $selected) {
        $id = [string]$c['id']; $d = [string]$c['domain']
        $thresholds = $effective[$id]
        $severity = if ($Baseline.severity -and $Baseline.severity[$id]) { [string]$Baseline.severity[$id] } else { [string]$c['severityDefault'] }
        $result = [ordered]@{
            id = $id; domain = $d; title = [string]$c['title']; status = $null; severity = $severity; reason = $null
            thresholds = $thresholds; affected = @(); affectedCount = 0; evidence = @($c['evidence']); exception = $null
            coveredBy = $null; custom = [bool]$c['custom']; checkedUtc = $AsOf.ToString('o')
        }

        # Applicability against the profile: a key the profile knows with no overlap means not applicable.
        $na = $null
        foreach ($k in @($c['applicableWhen'].Keys)) {
            $wanted = @($c['applicableWhen'][$k])
            if ($wanted.Count -eq 0 -or -not $OrgProfile.Contains($k)) { continue }
            $have = @(@($OrgProfile[$k]) | Where-Object { $null -ne $_ -and $_ -ne '' })
            if ($have.Count -eq 0) { continue }
            if (@($wanted | Where-Object { $_ -in $have }).Count -eq 0) { $na = "Profile: $k is $($have -join ', '), check applies to $($wanted -join ', ')."; break }
        }
        if ($na) { $result.status = 'notApplicable'; $result.reason = $na; $result; continue }

        # Third-party coverage.
        $covered = $null
        foreach ($cb in @($c['coveredBy'])) {
            $cat, $vendor = ([string]$cb).Split(':', 2)
            if ($OrgProfile.thirdParty -and $OrgProfile.thirdParty.Contains($cat)) {
                $have = [string]$OrgProfile.thirdParty[$cat]
                if ($have -and $have -ne 'none' -and ($vendor -eq '*' -or $vendor -eq $have)) { $covered = "$cat`:$have"; break }
            }
        }
        if ($covered) { $result.status = 'coveredBy'; $result.coveredBy = $covered; $result.reason = "Covered by $($covered.Split(':')[1]) per the profile; verify there."; $result; continue }

        # License gate, only when the profile states licenses.
        $needs = @($c['license'])
        if ($OrgProfile.present -and $needs.Count -gt 0 -and @($OrgProfile.licenses).Count -gt 0 -and @($needs | Where-Object { $_ -in @($OrgProfile.licenses) }).Count -eq 0) {
            $result.status = 'notEvaluated'; $result.reason = "Requires $($needs -join ' or ')."; $result; continue
        }

        # Facts.
        $df = $domainFacts[$d]
        if (-not $df -or -not $df['available']) { $result.status = 'notEvaluated'; $result.reason = $(if ($df) { [string]$df['reason'] } else { 'No facts for this domain.' }); $result; continue }
        $result.evidence = @(@($c['evidence']) + @($df['evidence']) | Select-Object -Unique)
        # A provider may rule a specific check out with a reason (for example: no naming pattern configured).
        if ($df.Contains('notEvaluated') -and $df['notEvaluated'] -and $df['notEvaluated'].Contains($id)) {
            $result.status = 'notEvaluated'; $result.reason = [string]$df['notEvaluated'][$id]; $result; continue
        }
        try {
            $passed = Invoke-PostureExpression -Expression ([string]$c['pass']) -Context @{ facts = $df['facts']; thresholds = $thresholds }
        }
        catch { $result.status = 'notEvaluated'; $result.reason = "Data missing: $($_.Exception.Message)"; $result; continue }

        if ($c.Contains('affected') -and $c['affected']) {
            $key = ([string]$c['affected']) -replace '^facts\.', ''
            if ($df['affected'].Contains($key)) { $result.affected = @($df['affected'][$key]) }
        }
        $result.status = if ($passed) { 'pass' } else { 'fail' }

        # Exceptions.
        $mine = @($Exception | Where-Object { $_.check -eq $id })
        $active = @($mine | Where-Object { -not $_.expired })
        $expiredOnes = @($mine | Where-Object { $_.expired })
        if ($result.status -eq 'fail' -and $active.Count -gt 0) {
            $checkLevel = @($active | Where-Object { -not $_.object })
            $objectLevel = @($active | Where-Object { $_.object })
            if ($checkLevel.Count -gt 0) {
                $e = $checkLevel[0]
                $result.status = 'acceptedRisk'; $result.exception = $e
                $result.reason = "Accepted risk: $($e.justification) (owner $($e.owner), approver $($e.approver), until $(if ($e.expires) { $e.expires.ToString('yyyy-MM-dd') } else { 'no expiry' }))."
            }
            elseif ($result.affected.Count -gt 0) {
                $names = @($objectLevel | ForEach-Object { $_.object })
                $label = { param($o) if ($o -is [System.Collections.IDictionary]) { [string]$o['name'] } elseif ($o.PSObject.Properties['name']) { [string]$o.name } else { [string]$o } }
                $remaining = @($result.affected | Where-Object { (& $label $_) -notin $names })
                $excepted = @($result.affected | Where-Object { (& $label $_) -in $names })
                if ($excepted.Count -gt 0) {
                    $result.affected = $remaining
                    if ($remaining.Count -eq 0) {
                        $result.status = 'acceptedRisk'; $result.exception = $objectLevel
                        $result.reason = "Accepted risk for $($excepted.Count) object(s): $(@($objectLevel | ForEach-Object { "$($_.object): $($_.justification)" }) -join '; ')."
                    }
                    else { $result.reason = "$($excepted.Count) object(s) accepted by exception; $($remaining.Count) remain." }
                }
            }
        }
        if ($expiredOnes.Count -gt 0 -and $result.status -ne 'acceptedRisk') {
            $result.reason = (@($result.reason, "$($expiredOnes.Count) expired exception(s) ignored.") | Where-Object { $_ }) -join ' '
        }
        $result.affectedCount = @($result.affected).Count
        $result
    }

    $counts = [ordered]@{}
    foreach ($s in 'pass', 'fail', 'notEvaluated', 'notApplicable', 'acceptedRisk', 'coveredBy') { $counts[$s] = @($results | Where-Object { $_.status -eq $s }).Count }

    return [ordered]@{
        catalogVersion = $Catalog.version
        baseline       = $Baseline.name
        profile        = $(if ($OrgProfile.present) { $OrgProfile.path } else { 'none (license gating off)' })
        evidence       = $Evidence
        evaluatedUtc   = $AsOf.ToString('o')
        counts         = $counts
        domains        = [ordered]@{}
        results        = @($results)
    }
}
