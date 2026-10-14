# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Compare-PostureCaSnapshot {
    <#
    .SYNOPSIS
        Compares two Export-PostureCaSnapshot folders and writes an email-ready change report (spec 5.3).
    .DESCRIPTION
        Reports policies added, removed, renamed, state changed and modified with field-level before and after
        using resolved names; named location, authentication strength and authentication context changes; scope
        drift for every group a policy references (member-level when both snapshots were taken with
        -IncludeMembers); and, at the top, the risk-relevant changes: an exclusion added to an MFA or legacy-auth
        policy, a policy moved from enabled to report-only or disabled, a break-glass account removed from an
        exclusion, a trusted location added or widened, an authentication strength weakened, a device compliance
        requirement removed, a policy now referencing a deleted object, and an enabled policy deleted.

        Reads only the two folders. No Graph session is needed.

        For a scheduled runbook that must alert on risk, use -FailOnRiskRelevantChange: the report is written first,
        then the cmdlet throws, so `pwsh -Command` exits non-zero. Without it, inspect HasRiskRelevantChanges on the
        -PassThru object.
    .PARAMETER Before
        The older snapshot folder.
    .PARAMETER After
        The newer snapshot folder.
    .PARAMETER OutputPath
        Folder for ca-changes.md and ca-changes.html. Default: the After folder.
    .PARAMETER Format
        Markdown, Html, or both. Default: both.
    .PARAMETER Brand
        Path to brand.json (spec 7.5).
    .PARAMETER BreakGlass
        UPNs or display names of the break-glass accounts. Default: excluded users whose name or UPN contains
        break-glass or emergency.
    .PARAMETER FailOnRiskRelevantChange
        Throw after writing the report when any risk-relevant change exists.
    .PARAMETER PassThru
        Return an object with Files, Diff, RiskRelevantCount and HasRiskRelevantChanges instead of the file paths.
    .EXAMPLE
        Compare-PostureCaSnapshot -Before ~/audit/evidence/20261013-0905-ca -After ~/audit/evidence/20261014-0905-ca

        Writes ca-changes.md and ca-changes.html into the newer folder.
    .EXAMPLE
        pwsh -Command "Compare-PostureCaSnapshot -Before ./prev -After ./latest -FailOnRiskRelevantChange"

        Exit code 1 when a risk-relevant change is present, for a runbook or a GitHub Action step.
    .OUTPUTS
        System.String. Written file paths. With -PassThru, a summary object.
    .LINK
        docs/posture-spec.md section 5.3
    #>
    [CmdletBinding()]
    [OutputType([string], [pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)] [ValidateNotNullOrEmpty()] [string] $Before,
        [Parameter(Mandatory, Position = 1)] [ValidateNotNullOrEmpty()] [string] $After,
        [string] $OutputPath,
        [ValidateSet('Markdown', 'Html')] [string[]] $Format = @('Markdown', 'Html'),
        [string] $Brand,
        [string[]] $BreakGlass,
        [switch] $FailOnRiskRelevantChange,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $beforeSnap = Import-PostureCaSnapshot -Path $Before
    $afterSnap = Import-PostureCaSnapshot -Path $After
    $brandModel = Import-PostureBrand -Path $Brand

    $bTenant = Get-PostureValue $beforeSnap.Metadata 'tenantId'
    $aTenant = Get-PostureValue $afterSnap.Metadata 'tenantId'
    if ($bTenant -and $aTenant -and $bTenant -ne $aTenant) {
        Write-Warning "The snapshots come from different tenants ($bTenant and $aTenant). The comparison is still produced."
    }

    $diffParams = @{ Before = $beforeSnap; After = $afterSnap }
    if ($BreakGlass) { $diffParams.BreakGlass = $BreakGlass }
    $diff = Compare-PostureCaModel @diffParams

    $counts = [ordered]@{
        added        = @($diff.policies.added).Count
        removed      = @($diff.policies.removed).Count
        renamed      = @($diff.policies.changed | Where-Object { $_.renamed }).Count
        stateChanged = @($diff.policies.changed | Where-Object { $_.stateChanged }).Count
        modified     = @($diff.policies.changed | Where-Object { $_.modified }).Count
        locations    = @($diff.locations.added).Count + @($diff.locations.removed).Count + @($diff.locations.changed).Count
        strengths    = @($diff.strengths.added).Count + @($diff.strengths.removed).Count + @($diff.strengths.changed).Count
        contexts     = @($diff.contexts.added).Count + @($diff.contexts.removed).Count + @($diff.contexts.changed).Count
        scope        = @($diff.scope).Count
        risk         = @($diff.risk).Count
    }
    $noChanges = (($counts.Values | Measure-Object -Sum).Sum -eq 0)

    $clientName = if ($brandModel.client.name) { [string]$brandModel.client.name } else { [string]$aTenant }
    $report = [ordered]@{
        title         = "Conditional Access changes: $clientName"
        brand         = $brandModel
        generatedUtc  = [datetime]::UtcNow
        moduleVersion = $script:ModuleVersion
        breakGlass    = @($BreakGlass)
        counts        = $counts
        noChanges     = $noChanges
        diff          = $diff
    }

    $outFolder = if ($OutputPath) { $OutputPath } else { $afterSnap.Path }
    if (-not (Test-Path -LiteralPath $outFolder)) { New-Item -ItemType Directory -Path $outFolder -Force | Out-Null }
    $outFolder = (Resolve-Path -LiteralPath $outFolder).Path

    $written = [System.Collections.Generic.List[string]]::new()
    foreach ($f in @('Markdown', 'Html')) {
        if ($Format -notcontains $f) { continue }
        $ext, $content = switch ($f) {
            'Markdown' { 'md', (ConvertTo-PostureCaDiffMarkdown -Report $report) }
            'Html' { 'html', (ConvertTo-PostureCaDiffHtml -Report $report) }
        }
        $path = Join-Path $outFolder "ca-changes.$ext"
        [System.IO.File]::WriteAllText($path, $content, [System.Text.UTF8Encoding]::new($false))
        $written.Add($path)
    }

    $riskCount = @($diff.risk).Count
    if ($riskCount -gt 0) { Write-Warning "$riskCount risk-relevant change(s). See $($written -join ', ')" }

    $result = [pscustomobject]@{
        Files                  = $written.ToArray()
        Diff                   = $diff
        Counts                 = $counts
        RiskRelevantCount      = $riskCount
        HasRiskRelevantChanges = ($riskCount -gt 0)
    }
    if ($FailOnRiskRelevantChange -and $riskCount -gt 0) {
        throw "$riskCount risk-relevant Conditional Access change(s) between $($beforeSnap.Path) and $($afterSnap.Path): $(@($diff.risk | ForEach-Object { "$($_.rule) ($($_.subject))" }) -join '; '). Report: $($written -join ', ')"
    }
    if ($PassThru) { return $result }
    return $written.ToArray()
}
