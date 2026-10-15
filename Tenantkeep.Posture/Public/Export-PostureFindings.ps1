# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Export-PostureFindings {
    <#
    .SYNOPSIS
        Writes findings.csv in the audit plan's Appendix E schema from a checks.json, one row per failed or accepted
        check, keeping the owners and statuses already recorded in an earlier findings.csv.
    .DESCRIPTION
        Columns: ID, Workstream, Finding, Evidence, Likelihood 1-5, Impact 1-5, Risk, Effort S/M/L/XL, Dependency,
        Quick win, Bucket, Owner, Status. Likelihood and impact follow the severity (Critical 5, High 4, Medium 3,
        Low 2) until the catalog carries its own; risk is their product; the bucket is the report's. Rows whose ID is
        in -Merge keep that file's Owner, Status, Effort and Dependency, so the register round-trips between runs: a
        check that no longer fails is written with status Resolved, a new one with Open.
    .PARAMETER Path
        checks.json, or a folder holding one (an evidence folder after Invoke-PostureChecks or New-PostureReport).
    .PARAMETER OutputPath
        Where to write findings.csv. Default: next to the checks.json.
    .PARAMETER Merge
        An earlier findings.csv whose Owner, Status, Effort and Dependency survive for the same IDs.
    .PARAMETER IncludePassed
        Also write the passing checks, status Resolved or Pass, so the register shows the whole catalog.
    .PARAMETER PassThru
        Return the rows instead of the file path.
    .EXAMPLE
        Export-PostureFindings -Path ~/tenantkeep/evidence/20261015-0952 -Merge ~/tenantkeep/clients/contoso/findings.csv -OutputPath ~/tenantkeep/clients/contoso/findings.csv
    .OUTPUTS
        System.String, the findings.csv path. With -PassThru, the rows.
    .LINK
        docs/m365-environment-audit-plan.md Appendix E
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'The spec names the cmdlet after the findings register (Appendix E).')]
    [OutputType([string], [object[]])]
    param(
        [Parameter(Mandatory, Position = 0)] [ValidateNotNullOrEmpty()] [string] $Path,
        [string] $OutputPath,
        [string] $Merge,
        [switch] $IncludePassed,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $checksPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if (Test-Path -LiteralPath $checksPath -PathType Container) { $checksPath = Join-Path $checksPath 'checks.json' }
    if (-not (Test-Path -LiteralPath $checksPath -PathType Leaf)) { throw "checks.json not found: $checksPath (run Invoke-PostureChecks or New-PostureReport first)" }
    $run = Get-Content -Raw -LiteralPath $checksPath | ConvertFrom-Json -AsHashtable -Depth 20
    $catalog = Import-PostureCheckCatalog
    $byId = @{}; foreach ($c in $catalog.checks) { $byId[[string]$c['id']] = $c }

    $labels = @{ identity = 'Identity and privileged access'; auth = 'Authentication methods'; ca = 'Conditional Access'; devices = 'Devices'; endpoint = 'Endpoint security'; email = 'Email security'; purview = 'Data protection'; collaboration = 'Collaboration and oversharing'; copilot = 'Copilot readiness'; governance = 'Governance and lifecycle'; operations = 'Operations and monitoring'; azure = 'Azure'; hybrid = 'Hybrid identity and on-premises AD' }
    $score = @{ Critical = 5; High = 4; Medium = 3; Low = 2 }
    $bucket = @{ Critical = 'Stop the bleeding'; High = 'Foundations'; Medium = 'Program workstreams'; Low = 'Later' }

    $previous = @{}
    if ($Merge) {
        $mergePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Merge)
        if (-not (Test-Path -LiteralPath $mergePath -PathType Leaf)) { throw "findings.csv to merge not found: $mergePath" }
        foreach ($row in @(Import-Csv -LiteralPath $mergePath)) { if ($row.ID) { $previous[[string]$row.ID] = $row } }
    }

    $rows = foreach ($r in @($run.results)) {
        $status = [string]$r.status
        if ($status -notin @('fail', 'acceptedRisk') -and -not $IncludePassed) { continue }
        if ($status -in @('notEvaluated', 'notApplicable')) { continue }
        $id = [string]$r.id; $sev = [string]$r.severity; $c = $byId[$id]
        $affected = @($r.affected | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [string]$_['name'] } else { [string]$_ } } | Where-Object { $_ })
        $finding = [string]$r.title
        if ($affected.Count -gt 0) { $finding += " ($($r.affectedCount) affected: $(@($affected | Select-Object -First 5) -join ', ')$(if ($affected.Count -gt 5) { ', ...' }))" }
        $l = $(if ($score.ContainsKey($sev)) { $score[$sev] } else { 3 })
        $old = $previous[$id]
        $newStatus = switch ($status) { 'fail' { $(if ($old -and $old.Status -and $old.Status -notin @('Resolved', 'Pass')) { $old.Status } else { 'Open' }) } 'acceptedRisk' { 'Accepted' } default { 'Resolved' } }
        [pscustomobject]@{
            'ID'             = $id
            'Workstream'     = $(if ($labels.ContainsKey([string]$r.domain)) { $labels[[string]$r.domain] } else { [string]$r.domain })
            'Finding'        = $finding
            'Evidence'       = (@($r.evidence) -join '; ')
            'Likelihood 1-5' = $l
            'Impact 1-5'     = $l
            'Risk'           = $l * $l
            'Effort S/M/L/XL' = $(if ($old -and $old.'Effort S/M/L/XL') { $old.'Effort S/M/L/XL' } else { '' })
            'Dependency'     = $(if ($old -and $old.Dependency) { $old.Dependency } else { '' })
            'Quick win'      = $(if ($status -eq 'fail' -and $r.affectedCount -le 5 -and $sev -in @('Low', 'Medium')) { 'Y' } else { '' })
            'Bucket'         = $(if ($bucket.ContainsKey($sev)) { $bucket[$sev] } else { 'Later' })
            'Owner'          = $(if ($old -and $old.Owner) { $old.Owner } else { '' })
            'Status'         = $newStatus
            'Remediation'    = $(if ($c) { [string]$c['remediation'] } else { '' })
            'Learn'          = $(if ($c) { [string]$c['learn'] } else { '' })
            'Checked'        = [string]$r.checkedUtc
        }
    }
    $rows = @($rows | Sort-Object { -[int]$_.Risk }, { $_.ID })

    $out = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($(if ($OutputPath) { $OutputPath } else { Join-Path (Split-Path $checksPath -Parent) 'findings.csv' }))
    if (Test-Path -LiteralPath $out -PathType Container) { $out = Join-Path $out 'findings.csv' }
    if ($PSCmdlet.ShouldProcess($out, 'Write findings.csv')) {
        $dir = Split-Path $out -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $rows | Export-Csv -LiteralPath $out -NoTypeInformation -Encoding utf8
    }
    if ($PassThru) { return $rows }
    return $out
}
