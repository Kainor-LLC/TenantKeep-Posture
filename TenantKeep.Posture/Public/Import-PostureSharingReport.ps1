# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Import-PostureSharingReport {
    <#
    .SYNOPSIS
        Adds the SharePoint "Site permissions across your organization" report to the assessment: Anyone links,
        organization-wide links and Everyone grants per site. Files it in the client folder and rebuilds the
        newest report.
    .DESCRIPTION
        Microsoft offers no Graph, REST or PnP read for SharePoint Advanced Management's data access governance
        reports, and starting one is a job on Microsoft's side, so the module never runs it. An admin with the
        SharePoint Administrator or SharePoint Advanced Management Administrator role runs it once a month:

          SharePoint admin center > Reports > Data access governance > Site permissions across your organization >
          Run report (SharePoint, and again for OneDrive) > when it is ready, Download CSV.

        The first run of the report can take up to five days; later ones finish within a day. It needs SharePoint
        Advanced Management, which any Microsoft 365 Copilot licence in the tenant includes.

        This cmdlet checks that each file is that report and belongs to the tenant, copies it into
        imports/sam-dag/ in the client folder with its report date in the name (the Copilot readiness gates read
        that folder too), summarises it into the newest run as spo-dag-site-permissions.json and rebuilds that
        run's report. Every later run summarises the newest files again on its own. Nothing is sent anywhere and
        nothing is written to the tenant.
    .PARAMETER Path
        The downloaded CSV, or several (SharePoint and OneDrive).
    .PARAMETER TenantId
        The tenant id from the report header. Finds the client folder whose profile.json names it.
    .PARAMETER Client
        The client folder, instead of -TenantId.
    .PARAMETER OutRoot
        Where run folders are. Default: the profile's outputRoot, else ~/tenantkeep/evidence.
    .PARAMETER NoReport
        File the report without rebuilding the newest run's report.
    .EXAMPLE
        Import-PostureSharingReport -TenantId 00000000-0000-0000-0000-000000000000 -Path ~/Downloads/SitePermissions.csv
    .EXAMPLE
        Import-PostureSharingReport -Client ~/tenantkeep/clients/contoso -Path ./sharepoint.csv, ./onedrive.csv
    .OUTPUTS
        The summary: totals and the most exposed sites.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive: tells the admin what was filed and that the report was rebuilt.')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)] [string[]] $Path,
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')] [string] $TenantId,
        [string] $Client,
        [string] $OutRoot,
        [switch] $NoReport
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $folder = Resolve-PostureClientFolder -Client $Client -TenantId $TenantId
    $profilePath = Join-Path $folder 'profile.json'
    $tenant = $TenantId
    if (-not $tenant -and (Test-Path -LiteralPath $profilePath)) { $tenant = [string]((Get-Content -Raw -LiteralPath $profilePath | ConvertFrom-Json -AsHashtable)['tenantId']) }
    $imports = Join-Path $folder 'imports' 'sam-dag'
    $filed = @()
    foreach ($p in $Path) {
        $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p)
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "File not found: $full" }
        if ($PSCmdlet.ShouldProcess($full, 'File the site permissions report')) {
            $target = Add-PostureSharingReportFile -Client $folder -Path $full -TenantId $tenant -Strict -Confirm:$false
            if ($target) { $filed += $target }
        }
    }
    if ($filed.Count -eq 0) { return }
    Write-Host "Filed $($filed.Count) report(s) in $imports"

    $run = Find-PostureRunFolder -Client $folder -TenantId $tenant -OutRoot $OutRoot
    $summary = $null
    if ($run) {
        $summary = Write-PostureSharingSummary -Client $folder -Folder (Get-PostureRunLayout -Folder $run).evidence -Confirm:$false
        if (-not $NoReport) {
            $report = Update-PostureRunReport -Run $run -Client $folder -Confirm:$false
            Write-Host "Report rebuilt: $report (refresh the page)"
        }
    }
    else { Write-Host 'No run for this tenant yet; the next run reads the report.' }
    if ($summary) {
        $t = $summary.totals
        return [pscustomobject]@{ Sites = $t.sites; ExposedSites = $summary.exposedSites; AnyoneLinks = $t.anyoneLinks; OrganizationLinks = $t.orgLinks; EveryoneExceptExternalGrants = $t.eeeuGrants; EveryoneGrants = $t.everyoneGrants; ReportDate = $summary.reportDateUtc; Files = $filed }
    }
}
