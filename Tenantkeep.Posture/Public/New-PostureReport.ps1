# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function New-PostureReport {
    <#
    .SYNOPSIS
        Renders the posture report (spec 3 and 7) from an evidence folder: runs the catalog, writes checks.json, and
        writes the report as a self-contained interactive HTML file and as Markdown. PDF prints the HTML through a
        headless Edge or Chrome.
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
        One or more of Html, Markdown, Pdf. Default: Html and Markdown. Pdf always writes the HTML too.
    .PARAMETER Previous
        An earlier run's checks.json, or the folder holding one, for the Trend view: score and domain deltas, checks
        that started or stopped failing, affected counts that moved.
    .PARAMETER OutputPath
        Folder for report.<ext> and checks.json. Default: the evidence folder.
    .PARAMETER PassThru
        Return the report model and the written file paths.
    .EXAMPLE
        New-PostureReport -Evidence ~/tenantkeep/evidence/20261013-2350 -Client ~/tenantkeep/clients/contoso
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
        [ValidateSet('Html', 'Markdown', 'Pdf')] [string[]] $Format = @('Html', 'Markdown'),
        [string] $Previous,
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
    $previousRun = $null
    if ($Previous) {
        $prevPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Previous)
        if (Test-Path -LiteralPath $prevPath -PathType Container) { $prevPath = Join-Path $prevPath 'checks.json' }
        if (-not (Test-Path -LiteralPath $prevPath -PathType Leaf)) { throw "Previous checks.json not found: $prevPath" }
        $previousRun = Get-Content -Raw -LiteralPath $prevPath | ConvertFrom-Json -AsHashtable -Depth 20
    }
    $report = ConvertTo-PostureReportModel -Run $run -Catalog $catalog -Evidence $evidencePath -OrgProfile $profileModel -Brand $brandModel -Exception $exceptionList -Template $Template -Previous $previousRun -BaselineModel $baselineModel

    $outFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($(if ($OutputPath) { $OutputPath } else { $evidencePath }))   # expands ~ too

    $written = [System.Collections.Generic.List[string]]::new()
    $checksPath = Join-Path $outFolder 'checks.json'
    if ($PSCmdlet.ShouldProcess($checksPath, 'Write checks.json')) {
        if (-not (Test-Path -LiteralPath $outFolder)) { New-Item -ItemType Directory -Path $outFolder -Force -WhatIf:$false | Out-Null }
        [System.IO.File]::WriteAllText($checksPath, (ConvertTo-Json -InputObject $run -Depth 20), [System.Text.UTF8Encoding]::new($false))
        $written.Add($checksPath)
    }
    $formats = [System.Collections.Generic.List[string]]::new([string[]]$Format)
    if ($formats -contains 'Pdf' -and $formats -notcontains 'Html') { $formats.Insert(0, 'Html') }
    $htmlPath = $null
    foreach ($f in @('Html', 'Markdown')) {
        if ($formats -notcontains $f) { continue }
        $ext, $content = switch ($f) {
            'Html' { 'html', (ConvertTo-PostureReportHtml -Report $report) }
            'Markdown' { 'md', (ConvertTo-PostureReportMarkdown -Report $report) }
        }
        $path = Join-Path $outFolder "report.$ext"
        if ($PSCmdlet.ShouldProcess($path, "Write $f report")) {
            [System.IO.File]::WriteAllText($path, $content, [System.Text.UTF8Encoding]::new($false))
            $written.Add($path)
            if ($f -eq 'Html') { $htmlPath = $path }
        }
    }
    if ($formats -contains 'Pdf' -and $htmlPath) {
        $pdfPath = Join-Path $outFolder 'report.pdf'
        if ($PSCmdlet.ShouldProcess($pdfPath, 'Print HTML to PDF with a headless browser')) { $written.Add((Export-PostureHtmlToPdf -HtmlPath $htmlPath -PdfPath $pdfPath)) }
    }

    Write-Verbose "Score $($report.score.value) ($($report.score.grade)); $($run.counts.fail) failed check(s)"
    if ($PassThru) { return [pscustomobject]@{ Files = $written.ToArray(); Report = $report; Run = $run } }
    return $written.ToArray()
}
