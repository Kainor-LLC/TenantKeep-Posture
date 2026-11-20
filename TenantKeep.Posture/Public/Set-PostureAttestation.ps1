# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Set-PostureAttestation {
    <#
    .SYNOPSIS
        Records the date you reviewed a portal page that no API can read (DSPM for AI, Copilot settings, site access
        reviews), in the client folder's profile.json, then rebuilds the newest report.
    .DESCRIPTION
        The checks that ask for a review (their report panel says which key and copies this command) pass for 90
        days from the recorded date by default. The date is written under attestations in profile.json; nothing is
        written to the tenant.
    .PARAMETER TenantId
        The tenant id from the report header. Finds the client folder whose profile.json names it.
    .PARAMETER Client
        The client folder, instead of -TenantId.
    .PARAMETER Key
        The attestation key a check asks for, for example dspmReviewedUtc.
    .PARAMETER Date
        The review date. Default: today.
    .PARAMETER OutRoot
        Where run folders are. Default: the profile's outputRoot, else ~/tenantkeep/evidence.
    .PARAMETER NoReport
        Record the date without rebuilding the newest report.
    .EXAMPLE
        Set-PostureAttestation -TenantId 00000000-0000-0000-0000-000000000000 -Key dspmReviewedUtc
    .EXAMPLE
        Set-PostureAttestation -Client ~/tenantkeep/clients/contoso -Key copilotSettingsReviewedUtc -Date 2026-11-02
    .OUTPUTS
        The key and the date recorded.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive: tells the admin where it wrote and that the report was rebuilt.')]
    [OutputType([pscustomobject])]
    param(
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')] [string] $TenantId,
        [string] $Client,
        [Parameter(Mandatory)]
        [ArgumentCompleter({ param($c, $p, $word) foreach ($k in 'siteAccessReviewsStartedUtc', 'dspmReviewedUtc', 'copilotSettingsReviewedUtc') { if ($k -like "$word*") { $k } } })]
        [string] $Key,
        [datetime] $Date = [datetime]::UtcNow.Date,
        [string] $OutRoot,
        [switch] $NoReport
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $keys = @((Import-PostureCheckCatalog).checks | ForEach-Object { $i = Get-PostureValue $_ 'input'; if ($i -and [string](Get-PostureValue $i 'kind') -eq 'attestation') { [string](Get-PostureValue $i 'key') } } | Sort-Object -Unique)
    if ($Key -notin $keys) { throw "$Key is not an attestation any check asks for. Known keys: $($keys -join ', ')." }
    if ($Date.Date -gt [datetime]::UtcNow.Date) { throw "The review date $($Date.ToString('yyyy-MM-dd')) is in the future." }

    $folder = Resolve-PostureClientFolder -Client $Client -TenantId $TenantId
    $path = Join-Path $folder 'profile.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "No profile.json in $folder; run Start-PostureRun or New-PostureProfile first." }
    $doc = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json -AsHashtable -Depth 20
    if (-not ($doc.Contains('attestations') -and $doc['attestations'] -is [System.Collections.IDictionary])) { $doc['attestations'] = [ordered]@{} }
    $value = $Date.ToString('yyyy-MM-dd') + 'T00:00:00Z'
    $doc['attestations'][$Key] = $value
    $doc['updatedUtc'] = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    if (-not $PSCmdlet.ShouldProcess($path, "Record $Key as $($Date.ToString('yyyy-MM-dd'))")) { return }
    Save-PostureJsonFile -Path $path -InputObject $doc -Confirm:$false
    Write-Host "Recorded $Key = $($Date.ToString('yyyy-MM-dd')) in $path"
    $run = Find-PostureRunFolder -Client $folder -TenantId $TenantId -OutRoot $OutRoot
    if ($run -and -not $NoReport) {
        $report = Update-PostureRunReport -Run $run -Client $folder -Confirm:$false
        Write-Host "Report rebuilt: $report (refresh the page)"
    }
    [pscustomobject]@{ Key = $Key; Date = $Date.ToString('yyyy-MM-dd'); Profile = $path }
}
