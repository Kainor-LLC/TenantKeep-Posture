# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function New-PostureCaDocument {
    <#
    .SYNOPSIS
        Renders Conditional Access documentation from an Export-PostureCaSnapshot folder (spec 5.2).
    .DESCRIPTION
        Reads the snapshot, resolves every id to a name, and writes a document with one section per policy
        (plain-English summary, assignments, targets, conditions, grant and session controls, health flags) plus
        the tenant-level pages: health flag table, policy matrix, naming convention report, named locations,
        authentication strengths and contexts, and a snapshot appendix.

        Reads only the snapshot folder. Never touches the tenant and needs no Graph session.
    .PARAMETER Snapshot
        Path to a snapshot folder written by Export-PostureCaSnapshot.
    .PARAMETER OutputPath
        Folder for the output files. Default: the snapshot folder. Files are named ca-document.<ext>.
    .PARAMETER Format
        One or more of Markdown, Html, Pdf. Default: Markdown and Html. Pdf prints the HTML through a headless
        Microsoft Edge or Google Chrome (spec 6) and always writes the HTML file too.
    .PARAMETER NamePattern
        Regex the policy names must match for the naming report. Falls back to caNamePattern in brand.json.
    .PARAMETER Brand
        Path to brand.json (spec 7.5) for prepared-by, client name, confidentiality line and footer.
    .PARAMETER ExclusionGroupThreshold
        Excluded groups larger than this raise a health flag. Default 25.
    .PARAMETER ReportOnlyDays
        Policies in report-only longer than this raise a health flag. Default 90.
    .PARAMETER DisabledDays
        Policies disabled longer than this raise a health flag. Default 90.
    .PARAMETER ProposedNameFormat
        Template for proposed names in the naming report. Tokens: {seq}, {persona}, {action}, {name}.
    .PARAMETER MatrixColumn
        Subset of matrix columns: allUsers, adminRoles, guests, workloadIdentities, allApps, office365, adminPortals, registerSecurityInfo.
    .PARAMETER Baseline
        Baseline for the Coverage findings page (name under baselines/ or a path). Default: standard.
    .PARAMETER ProfilePath
        profile.json for the Coverage findings page (alias -Profile): licenses, platforms, break-glass accounts, thresholds.
    .PARAMETER Exceptions
        exceptions.json for the Coverage findings page: accepted risk per check or per object.
    .PARAMETER SkipChecks
        Leave the Coverage findings page out instead of running the Conditional Access checks on the snapshot.
    .PARAMETER PassThru
        Return the document model and the written file paths instead of the file paths alone.
    .EXAMPLE
        New-PostureCaDocument -Snapshot ~/audit/evidence/20261013-0905-ca

        Writes ca-document.md and ca-document.html into the snapshot folder and returns their paths.
    .EXAMPLE
        New-PostureCaDocument -Snapshot ./snap -OutputPath ./out -Brand ./clients/contoso/brand.json -NamePattern '^CA-\d{3}-'

        Branded document with a naming report, written to ./out.
    .OUTPUTS
        System.String. Written file paths. With -PassThru, an object with Files and Document.
    .LINK
        docs/posture-spec.md section 5.2
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string], [pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)] [ValidateNotNullOrEmpty()] [string] $Snapshot,
        [string] $OutputPath,
        [ValidateSet('Markdown', 'Html', 'Pdf')] [string[]] $Format = @('Markdown', 'Html'),
        [string] $NamePattern,
        [string] $Brand,
        [ValidateRange(0, 100000)] [int] $ExclusionGroupThreshold = 25,
        [ValidateRange(0, 3650)] [int] $ReportOnlyDays = 90,
        [ValidateRange(0, 3650)] [int] $DisabledDays = 90,
        [string] $ProposedNameFormat = 'CA-{seq}-{persona}-{action}',
        [string[]] $MatrixColumn,
        [string] $Baseline = 'standard',
        [Alias('Profile')] [string] $ProfilePath,
        [string] $Exceptions,
        [switch] $SkipChecks,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $snap = Import-PostureCaSnapshot -Path $Snapshot
    $brandModel = Import-PostureBrand -Path $Brand
    if (-not $NamePattern -and $brandModel.caNamePattern) { $NamePattern = [string]$brandModel.caNamePattern }

    $modelParams = @{
        Snapshot = $snap; ExclusionGroupThreshold = $ExclusionGroupThreshold
        ReportOnlyDays = $ReportOnlyDays; DisabledDays = $DisabledDays
    }
    if ($NamePattern) { $modelParams.NamePattern = $NamePattern }
    $policies = @(ConvertTo-PostureCaPolicyModel @modelParams)

    $matrixParams = @{ Policy = $policies }
    if ($MatrixColumn) { $matrixParams.Column = $MatrixColumn }
    $matrix = Get-PostureCaMatrix @matrixParams
    $naming = if ($NamePattern) { Get-PostureCaNamingReport -Policy $policies -NamePattern $NamePattern -ProposedNameFormat $ProposedNameFormat } else { $null }

    $allFlags = @($policies | ForEach-Object { @($_.healthFlags) })
    $stats = [ordered]@{
        total        = $policies.Count
        enabled      = @($policies | Where-Object state -eq 'enabled').Count
        reportOnly   = @($policies | Where-Object state -eq 'reportOnly').Count
        disabled     = @($policies | Where-Object state -eq 'disabled').Count
        flagsError   = @($allFlags | Where-Object severity -eq 'error').Count
        flagsWarning = @($allFlags | Where-Object severity -eq 'warning').Count
        flagsInfo    = @($allFlags | Where-Object severity -eq 'info').Count
    }

    $clientName = if ($brandModel.client.name) { [string]$brandModel.client.name } else { [string](Get-PostureValue $snap.Metadata 'tenantId') }
    $document = [ordered]@{
        title        = "Conditional Access documentation: $clientName"
        brand        = $brandModel
        generatedUtc = [datetime]::UtcNow
        snapshot     = [ordered]@{
            path             = $snap.Path
            tenantId         = Get-PostureValue $snap.Metadata 'tenantId'
            account          = Get-PostureValue $snap.Metadata 'account'
            timestampUtc     = Get-PostureValue $snap.Metadata 'timestampUtc'
            moduleVersion    = Get-PostureValue $snap.Metadata 'moduleVersion'
            scopes           = @(Get-PostureValue $snap.Metadata 'scopes')
            graphApiVersions = @(Get-PostureValue $snap.Metadata 'graphApiVersions')
            errors           = @($snap.Errors)
        }
        options      = [ordered]@{
            namePattern = $NamePattern; exclusionGroupThreshold = $ExclusionGroupThreshold
            reportOnlyDays = $ReportOnlyDays; disabledDays = $DisabledDays; matrixColumns = @($matrix.columns | ForEach-Object { $_.key })
        }
        stats          = $stats
        policies       = $policies
        matrix         = $matrix
        naming         = $naming
        namedLocations = @($snap.NamedLocations)
        authStrengths  = @($snap.AuthStrengths)
        authContexts   = @($snap.AuthContexts)
    }

    # Coverage findings: the spec 4.3 checks, evaluated by the engine with the same thresholds this document uses.
    $document.coverage = $null
    if (-not $SkipChecks) {
        $profileModel = Import-PostureProfile -Path $ProfilePath
        if (-not $profileModel.thresholds) { $profileModel.thresholds = @{} }
        foreach ($pair in @(@('maxExclusionGroupMembers', $ExclusionGroupThreshold), @('reportOnlyMaxDays', $ReportOnlyDays), @('disabledMaxDays', $DisabledDays))) {
            if (-not $profileModel.thresholds.Contains($pair[0])) { $profileModel.thresholds[$pair[0]] = $pair[1] }
        }
        if ($NamePattern -and -not $profileModel.thresholds.Contains('namePattern')) { $profileModel.thresholds['namePattern'] = $NamePattern }
        $catalog = Import-PostureCheckCatalog
        $run = Invoke-PostureCheckEvaluation -Catalog $catalog -Baseline (Import-PostureBaseline -Baseline $Baseline) -OrgProfile $profileModel -Exception @(Import-PostureException -Path $Exceptions) -Evidence $snap.Path -Domain @('ca')
        $text = @{}
        foreach ($c in $catalog.checks) { $text[[string]$c['id']] = @{ narrative = [string]$c['narrative']; remediation = [string]$c['remediation']; learn = [string]$c['learn'] } }
        $document.coverage = [ordered]@{ run = $run; text = $text }
    }

    $outFolder = if ($OutputPath) { $OutputPath } else { $snap.Path }
    if (-not (Test-Path -LiteralPath $outFolder)) { New-Item -ItemType Directory -Path $outFolder -Force | Out-Null }
    $outFolder = (Resolve-Path -LiteralPath $outFolder).Path

    $formats = [System.Collections.Generic.List[string]]::new([string[]]$Format)
    if ($formats -contains 'Pdf' -and $formats -notcontains 'Html') { $formats.Insert(0, 'Html') }

    $written = [System.Collections.Generic.List[string]]::new()
    $htmlPath = $null
    foreach ($f in @('Markdown', 'Html')) {
        if ($formats -notcontains $f) { continue }
        $ext, $content = switch ($f) {
            'Markdown' { 'md', (ConvertTo-PostureCaMarkdown -Document $document) }
            'Html' { 'html', (ConvertTo-PostureCaHtml -Document $document) }
        }
        $path = Join-Path $outFolder "ca-document.$ext"
        if ($PSCmdlet.ShouldProcess($path, "Write $f document")) {
            [System.IO.File]::WriteAllText($path, $content, [System.Text.UTF8Encoding]::new($false))
            $written.Add($path)
            if ($f -eq 'Html') { $htmlPath = $path }
        }
    }
    if ($formats -contains 'Pdf' -and $htmlPath) {
        $pdfPath = Join-Path $outFolder 'ca-document.pdf'
        if ($PSCmdlet.ShouldProcess($pdfPath, 'Print HTML to PDF with a headless browser')) {
            $written.Add((Export-PostureHtmlToPdf -HtmlPath $htmlPath -PdfPath $pdfPath))
        }
    }

    if ($PassThru) { return [pscustomobject]@{ Files = $written.ToArray(); Document = $document } }
    return $written.ToArray()
}
