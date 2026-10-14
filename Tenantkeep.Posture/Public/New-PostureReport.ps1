# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function New-PostureReport {
    <#
    .SYNOPSIS
        Renders the posture report (spec 3 and 7) from an evidence folder: runs the catalog, writes checks.json, and
        writes the report as Markdown and, in a later step, the self-contained HTML.
    .DESCRIPTION
        Reads only local files. The report carries the posture score with its method, the headline numbers, one
        scorecard per domain, the top risks, recommendations in the audit plan's four buckets, the administrators
        table, the Conditional Access matrix and policy summaries, and an appendix with the baseline, profile,
        exceptions, scopes, API versions and the evidence index. Domains whose evidence is not collected yet are
        listed as such.

        -Client points at a client folder (spec 10.5) holding brand.json, profile.json and exceptions.json; explicit
        -Brand, -Profile and -Exceptions override the folder's files.
    .PARAMETER Evidence
        A collection folder from Invoke-PostureCollection (a bare Export-PostureCaSnapshot folder works for the CA domain alone).
    .PARAMETER Client
        Client folder with brand.json, profile.json and exceptions.json.
    .PARAMETER Template
        Executive (cover, summary, scorecards, recommendations) or Full. Default Full.
    .PARAMETER Format
        Markdown for now. Default Markdown.
    .PARAMETER OutputPath
        Folder for report.<ext> and checks.json. Default: the evidence folder.
    .PARAMETER PassThru
        Return the report model and the written file paths.
    .EXAMPLE
        New-PostureReport -Evidence ~/audit/evidence/20261013-2350 -Client ./clients/contoso
    .EXAMPLE
        New-PostureReport -Evidence ./evidence/run -Profile ./profile.json -Template Executive -PassThru
    .OUTPUTS
        System.String, written file paths. With -PassThru, an object with Files and Report.
    .LINK
        docs/posture-spec.md sections 3 and 7
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string], [pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)] [ValidateNotNullOrEmpty()] [string] $Evidence,
        [string] $Client,
        [string] $Brand,
        [Alias('Profile')] [string] $ProfilePath,
        [string] $Exceptions,
        [string] $Baseline = 'standard',
        [string[]] $CustomChecks = @(),
        [ValidateSet('Executive', 'Full')] [string] $Template = 'Full',
        [ValidateSet('Markdown')] [string[]] $Format = @('Markdown'),
        [string] $OutputPath,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    if (-not (Test-Path -LiteralPath $Evidence -PathType Container)) { throw "Evidence folder not found: $Evidence" }
    $evidencePath = (Resolve-Path -LiteralPath $Evidence).Path

    if ($Client) {
        if (-not (Test-Path -LiteralPath $Client -PathType Container)) { throw "Client folder not found: $Client" }
        foreach ($pair in @(@('Brand', 'brand.json'), @('ProfilePath', 'profile.json'), @('Exceptions', 'exceptions.json'))) {
            $candidate = Join-Path $Client $pair[1]
            if (-not (Get-Variable -Name $pair[0] -ValueOnly) -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { Set-Variable -Name $pair[0] -Value $candidate }
        }
    }

    $catalog = Import-PostureCheckCatalog -CustomPath $CustomChecks
    $baselineModel = Import-PostureBaseline -Baseline $Baseline
    $profileModel = Import-PostureProfile -Path $ProfilePath
    $exceptionList = @(Import-PostureException -Path $Exceptions)
    $brandModel = Import-PostureBrand -Path $Brand

    $run = Invoke-PostureCheckEvaluation -Catalog $catalog -Baseline $baselineModel -OrgProfile $profileModel -Exception $exceptionList -Evidence $evidencePath
    $run.moduleVersion = $script:ModuleVersion
    $report = ConvertTo-PostureReportModel -Run $run -Catalog $catalog -Evidence $evidencePath -OrgProfile $profileModel -Brand $brandModel -Exception $exceptionList -Template $Template

    $outFolder = [System.IO.Path]::GetFullPath($(if ($OutputPath) { $OutputPath } else { $evidencePath }))

    $written = [System.Collections.Generic.List[string]]::new()
    $checksPath = Join-Path $outFolder 'checks.json'
    if ($PSCmdlet.ShouldProcess($checksPath, 'Write checks.json')) {
        if (-not (Test-Path -LiteralPath $outFolder)) { New-Item -ItemType Directory -Path $outFolder -Force -WhatIf:$false | Out-Null }
        [System.IO.File]::WriteAllText($checksPath, (ConvertTo-Json -InputObject $run -Depth 20), [System.Text.UTF8Encoding]::new($false))
        $written.Add($checksPath)
    }
    foreach ($f in $Format) {
        $ext, $content = switch ($f) {
            'Markdown' { 'md', (ConvertTo-PostureReportMarkdown -Report $report) }
        }
        $path = Join-Path $outFolder "report.$ext"
        if ($PSCmdlet.ShouldProcess($path, "Write $f report")) {
            [System.IO.File]::WriteAllText($path, $content, [System.Text.UTF8Encoding]::new($false))
            $written.Add($path)
        }
    }

    Write-Verbose "Score $($report.score.value) ($($report.score.grade)); $($run.counts.fail) failed check(s)"
    if ($PassThru) { return [pscustomobject]@{ Files = $written.ToArray(); Report = $report; Run = $run } }
    return $written.ToArray()
}
