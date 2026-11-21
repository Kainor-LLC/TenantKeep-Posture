# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Export-PostureFindings {
    <#
    .SYNOPSIS
        Writes findings.csv from a checks.json: one row per failed or accepted check, most severe first, with what
        to do about it. Rebuilt from the run every time, so it is always the current list.
    .DESCRIPTION
        Columns: ID, Domain, Finding, Severity, Priority, Status, Affected, Remediation, Portal, Learn, Evidence,
        Checked, Licence. Priority is the report's bucket for the severity. The file is for whoever tracks
        remediation in their own tool; nothing here reads an earlier findings.csv. Accepted risks come from
        exceptions.json (Add-PostureException), which the run applies before this is written.
    .PARAMETER Path
        checks.json, or a folder holding one (an evidence folder after Invoke-PostureChecks or New-PostureReport).
    .PARAMETER OutputPath
        Where to write findings.csv. Default: next to the checks.json.
    .PARAMETER LicensePath
        TenantKeep licence file; the same lookup as New-PostureReport. Findings from unlicensed domains are left out and every row carries the licence id.
    .PARAMETER IncludePassed
        Also write the passing checks, status Pass, so the file shows the whole catalog.
    .PARAMETER PassThru
        Return the rows instead of the file path.
    .EXAMPLE
        Export-PostureFindings -Path ~/tenantkeep/evidence/20261015-0952
    .OUTPUTS
        System.String, the findings.csv path. With -PassThru, the rows.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'The file is the findings list; the noun names it.')]
    [OutputType([string], [object[]])]
    param(
        [Parameter(Mandatory, Position = 0)] [ValidateNotNullOrEmpty()] [string] $Path,
        [string] $OutputPath,
        [string] $LicensePath,
        [switch] $IncludePassed,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $checksPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $outDefault = $null
    if (Test-Path -LiteralPath $checksPath -PathType Container) { $layout = Get-PostureRunLayout -Folder $checksPath; $checksPath = Join-Path $layout.logs 'checks.json'; $outDefault = Join-Path $layout.root 'findings.csv' }
    if (-not (Test-Path -LiteralPath $checksPath -PathType Leaf)) { throw "checks.json not found: $checksPath (run Invoke-PostureChecks or New-PostureReport first)" }
    $run = Get-Content -Raw -LiteralPath $checksPath | ConvertFrom-Json -AsHashtable -Depth 20
    $catalog = Import-PostureCheckCatalog
    $byId = @{}; foreach ($c in $catalog.checks) { $byId[[string]$c['id']] = $c }
    # The licence is verified here too, not read back from checks.json (docs/licensing.md, Hardening).
    $entitlement = Confirm-PostureEntitlement -Entitlement (Get-PostureEntitlement -Evidence (Get-PostureRunLayout -Folder (Split-Path $checksPath -Parent)).evidence -LicensePath $LicensePath)
    $run.results = Limit-PostureResultsToEntitlement -Results @($run.results) -Entitlement $entitlement
    $licenceLabel = $(if ($entitlement.licensed -and $entitlement.licence) { [string]$entitlement.licence.licenceId } elseif ($entitlement.licensed) { [string]$entitlement.source } else { 'unlicensed' })

    $labels = @{}; foreach ($k in @($catalog.domains.Keys)) { $labels[$k] = $catalog.domains[$k] }
    $weight = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }
    $bucket = @{ Critical = 'Stop the bleeding'; High = 'Foundations'; Medium = 'Program workstreams'; Low = 'Later' }
    $statusText = @{ fail = 'Fail'; acceptedRisk = 'Accepted risk'; pass = 'Pass'; coveredBy = 'Covered by' }

    $rows = foreach ($r in @($run.results)) {
        $status = [string]$r.status
        if ($status -in @('notEvaluated', 'notApplicable')) { continue }
        if ($status -notin @('fail', 'acceptedRisk') -and -not $IncludePassed) { continue }
        $id = [string]$r.id; $sev = [string]$r.severity; $c = $byId[$id]
        $affected = @($r.affected | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [string]$_['name'] } else { [string]$_ } } | Where-Object { $_ })
        $finding = [string]$r.title
        if ($affected.Count -gt 0) { $finding += " ($($r.affectedCount) affected: $(@($affected | Select-Object -First 5) -join ', ')$(if ($affected.Count -gt 5) { ', ...' }))" }
        [pscustomobject]@{
            'ID'          = $id
            'Domain'      = $(if ($labels.ContainsKey([string]$r.domain)) { $labels[[string]$r.domain] } else { [string]$r.domain })
            'Finding'     = $finding
            'Severity'    = $sev
            'Priority'    = $(if ($bucket.ContainsKey($sev)) { $bucket[$sev] } else { 'Later' })
            'Status'      = $(if ($statusText.ContainsKey($status)) { $statusText[$status] } else { $status })
            'Affected'    = [int]$r.affectedCount
            'Remediation' = $(if ($c) { [string]$c['remediation'] } else { '' })
            'Portal'      = $(if ($c -and $c.Contains('deepLink')) { [string]$c['deepLink'] } else { '' })
            'Learn'       = $(if ($c) { [string]$c['learn'] } else { '' })
            'ATT&CK'      = $(if ($c -and $c.Contains('attack')) { @($c['attack']) -join '; ' } else { '' })
            'Evidence'    = (@($r.evidence) -join '; ')
            'Checked'     = [string]$r.checkedUtc
            'Licence'     = $licenceLabel
        }
    }
    # Failures first, then accepted, then passing; within each, most severe first.
    $order = @{ 'Fail' = 0; 'Accepted risk' = 1 }
    $rows = @($rows | Sort-Object { if ($order.ContainsKey($_.Status)) { $order[$_.Status] } else { 2 } }, { - $(if ($weight.ContainsKey($_.Severity)) { $weight[$_.Severity] } else { 0 }) }, { $_.ID })

    $out = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($(if ($OutputPath) { $OutputPath } elseif ($outDefault) { $outDefault } else { Join-Path (Split-Path $checksPath -Parent) 'findings.csv' }))
    if (Test-Path -LiteralPath $out -PathType Container) { $out = Join-Path $out 'findings.csv' }
    if ($PSCmdlet.ShouldProcess($out, 'Write findings.csv')) {
        $dir = Split-Path $out -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        # The file is for a spreadsheet or a ticketing system: no cell may start a formula. -PassThru returns the rows as they are.
        $rows | ConvertTo-PostureCsvSafeRow | Export-Csv -LiteralPath $out -NoTypeInformation -Encoding utf8
    }
    if ($PassThru) { return $rows }
    return $out
}
