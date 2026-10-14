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
        Markdown. Html and Pdf follow in a later step. Default: Markdown.
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
    .PARAMETER PassThru
        Return the document model and the written file paths instead of the file paths alone.
    .EXAMPLE
        New-PostureCaDocument -Snapshot ~/audit/evidence/20261013-0905-ca

        Writes ca-document.md into the snapshot folder and returns its path.
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
        [ValidateSet('Markdown')] [string[]] $Format = @('Markdown'),
        [string] $NamePattern,
        [string] $Brand,
        [ValidateRange(0, 100000)] [int] $ExclusionGroupThreshold = 25,
        [ValidateRange(0, 3650)] [int] $ReportOnlyDays = 90,
        [ValidateRange(0, 3650)] [int] $DisabledDays = 90,
        [string] $ProposedNameFormat = 'CA-{seq}-{persona}-{action}',
        [string[]] $MatrixColumn,
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

    $outFolder = if ($OutputPath) { $OutputPath } else { $snap.Path }
    if (-not (Test-Path -LiteralPath $outFolder)) { New-Item -ItemType Directory -Path $outFolder -Force | Out-Null }
    $outFolder = (Resolve-Path -LiteralPath $outFolder).Path

    $written = [System.Collections.Generic.List[string]]::new()
    foreach ($f in $Format) {
        $ext, $content = switch ($f) {
            'Markdown' { 'md', (ConvertTo-PostureCaMarkdown -Document $document) }
        }
        $path = Join-Path $outFolder "ca-document.$ext"
        if ($PSCmdlet.ShouldProcess($path, "Write $f document")) {
            [System.IO.File]::WriteAllText($path, $content, [System.Text.UTF8Encoding]::new($false))
            $written.Add($path)
        }
    }

    if ($PassThru) { return [pscustomobject]@{ Files = $written.ToArray(); Document = $document } }
    return $written.ToArray()
}
