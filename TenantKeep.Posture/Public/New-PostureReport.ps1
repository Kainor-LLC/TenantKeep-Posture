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
        Executive opens the page in Executive Mode: the Overview, Recommendations and the domain scorecards, without
        the technical detail. The button on the page switches either way. Full is the default.
    .PARAMETER Format
        One or more of Html, Markdown, Pdf. Default: Html and Markdown. Pdf always writes the HTML too.
    .PARAMETER LicensePath
        TenantKeep licence file. Default: TENANTKEEP_LICENSE, <Client>/tenantkeep.lic, then ~/tenantkeep/tenantkeep.lic. Without a valid Full licence only the Conditional Access domain is evaluated and the report says so (docs/licensing.md).
    .PARAMETER Previous
        An earlier run's checks.json, or the folder holding one, for the Trend view: score and domain deltas, checks
        that started or stopped failing, affected counts that moved.
    .PARAMETER OutputPath
        Folder for report.<ext>, checks.json and affected/. Default: for a run Start-PostureRun made, the reports
        at the top of the run folder, checks.json in logs/ and affected/ beside the reports; for a one-folder run,
        that folder.
    .PARAMETER Redact
        Also write share/report.html, share/report.md and share/findings.json with the tenant's people and places
        replaced by placeholders (user-001, site-014, ip-002), for a report that goes to an AI service or a third
        party. The key that maps them back is logs/redaction-key.csv: keep it private. Best effort: read it first.
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
        [string] $LicensePath,
        [switch] $Redact,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    if (-not (Test-Path -LiteralPath $Evidence -PathType Container)) { throw "Evidence folder not found: $Evidence" }
    # The run folder or its evidence/ folder; a one-folder run is both.
    $layout = Get-PostureRunLayout -Folder (Resolve-Path -LiteralPath $Evidence).Path
    $evidencePath = $layout.evidence

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

    $entitlement = Get-PostureEntitlement -Evidence $evidencePath -LicensePath $LicensePath -ClientFolder $Client
    $run = Invoke-PostureCheckEvaluation -Catalog $catalog -Baseline $baselineModel -OrgProfile $profileModel -Exception $exceptionList -Evidence $evidencePath -Entitlement $entitlement
    $run.entitlement = ConvertTo-PostureEntitlementRecord -Entitlement $entitlement
    $run.moduleVersion = $script:ModuleVersion
    $previousRun = $null
    if ($Previous) {
        $prevPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Previous)
        if (Test-Path -LiteralPath $prevPath -PathType Container) { $prevPath = Join-Path (Get-PostureRunLayout -Folder $prevPath).logs 'checks.json' }
        if (-not (Test-Path -LiteralPath $prevPath -PathType Leaf)) { throw "Previous checks.json not found: $prevPath" }
        $previousRun = Get-Content -Raw -LiteralPath $prevPath | ConvertFrom-Json -AsHashtable -Depth 20
    }
    $report = ConvertTo-PostureReportModel -Run $run -Catalog $catalog -Evidence $evidencePath -OrgProfile $profileModel -Brand $brandModel -Exception $exceptionList -Template $Template -Previous $previousRun -BaselineModel $baselineModel -Entitlement $entitlement
    # The ranked findings for tools and AI: findings.json, embedded in the HTML, and the top of the Markdown.
    $report.findings = ConvertTo-PostureFindingsDocument -Report $report

    if ($OutputPath) { $outFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath); $checksFolder = $outFolder; $affectedFolder = Join-Path $outFolder 'affected' }   # expands ~ too
    else { $outFolder = $layout.root; $checksFolder = $layout.logs; $affectedFolder = $layout.affected }

    $written = [System.Collections.Generic.List[string]]::new()
    $checksPath = Join-Path $checksFolder 'checks.json'
    if ($PSCmdlet.ShouldProcess($checksPath, 'Write checks.json')) {
        foreach ($d in $outFolder, $checksFolder) { if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force -WhatIf:$false | Out-Null } }
        Save-PostureJsonFile -Path $checksPath -InputObject $run -Confirm:$false
        $written.Add($checksPath)
    }
    # Every affected list in full as a CSV per check; the page carries the first 500 of each, so a check with tens
    # of thousands of objects does not make the report too heavy to open.
    $withAffected = @($run.results | Where-Object { $_.affectedCount -gt 0 })
    if ($withAffected.Count -gt 0 -and $PSCmdlet.ShouldProcess($affectedFolder, 'Write the affected objects per check')) {
        New-Item -ItemType Directory -Path $affectedFolder -Force | Out-Null
        Get-ChildItem -LiteralPath $affectedFolder -Filter '*.csv' -File | Remove-Item -Force
        foreach ($r in $withAffected) {
            # People open these in a spreadsheet, and the names come from the tenant (a guest picks their own): no cell may start a formula.
            @($r.affected | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [pscustomobject]@{ Name = (ConvertTo-PostureCsvSafeText ([string]$_['name'])); Detail = (ConvertTo-PostureCsvSafeText ([string]$_['detail'])) } } else { [pscustomobject]@{ Name = (ConvertTo-PostureCsvSafeText ([string]$_)); Detail = '' } } }) |
                Export-Csv -LiteralPath (Join-Path $affectedFolder "$($r.id).csv") -Encoding utf8
        }
    }
    $formats = [System.Collections.Generic.List[string]]::new([string[]]$Format)
    if ($formats -contains 'Pdf' -and $formats -notcontains 'Html') { $formats.Insert(0, 'Html') }
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $render = {
        param([System.Collections.IDictionary] $Model, [string] $Folder)
        $paths = @{}
        foreach ($f in @('Html', 'Markdown')) {
            if ($formats -notcontains $f) { continue }
            $ext, $content = switch ($f) {
                'Html' { 'html', (ConvertTo-PostureReportHtml -Report $Model) }
                'Markdown' { 'md', (ConvertTo-PostureReportMarkdown -Report $Model) }
            }
            $path = Join-Path $Folder "report.$ext"
            if ($PSCmdlet.ShouldProcess($path, "Write $f report")) { [System.IO.File]::WriteAllText($path, $content, $utf8); $written.Add($path); $paths[$f] = $path }
        }
        $fj = Join-Path $Folder 'findings.json'
        if ($PSCmdlet.ShouldProcess($fj, 'Write findings.json')) { [System.IO.File]::WriteAllText($fj, (ConvertTo-Json -InputObject $Model.findings -Depth 20), $utf8); $written.Add($fj) }
        $paths
    }
    $paths = & $render $report $outFolder
    $htmlPath = $(if ($paths.ContainsKey('Html')) { $paths['Html'] } else { $null })
    if ($Redact) {
        $redacted = ConvertTo-PostureRedactedReport -Report $report
        $shareFolder = Join-Path $outFolder 'share'
        if ($PSCmdlet.ShouldProcess($shareFolder, 'Write the redacted copies')) {
            New-Item -ItemType Directory -Path $shareFolder -Force | Out-Null
            $null = & $render $redacted.report $shareFolder
            $keyPath = Join-Path $checksFolder 'redaction-key.csv'
            $redacted.key | ConvertTo-PostureCsvSafeRow | Export-Csv -LiteralPath $keyPath -Encoding utf8
            $written.Add($keyPath)
        }
    }
    if ($formats -contains 'Pdf' -and $htmlPath) {
        $pdfPath = Join-Path $outFolder 'report.pdf'
        if ($PSCmdlet.ShouldProcess($pdfPath, 'Print HTML to PDF with a headless browser')) { $written.Add((Export-PostureHtmlToPdf -HtmlPath $htmlPath -PdfPath $pdfPath)) }
    }

    Write-Verbose "Score $($report.score.value) ($($report.score.grade)); $($run.counts.fail) failed check(s)"
    Clear-PostureEvidenceCache -Confirm:$false
    if ($PassThru) { return [pscustomobject]@{ Files = $written.ToArray(); Report = $report; Run = $run } }
    return $written.ToArray()
}
