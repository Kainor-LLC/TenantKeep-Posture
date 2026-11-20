# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Remove-PostureException {
    <#
    .SYNOPSIS
        Withdraws an accepted risk from a client folder's exceptions.json, then rebuilds the newest report so the
        check shows as failing again after a refresh.
    .DESCRIPTION
        -Check alone removes every exception for that check; with -Object, only that object's. -Expired removes
        every expired exception. The file is local to the client folder; nothing is written to the tenant.
    .PARAMETER TenantId
        The tenant id from the report header. Finds the client folder whose profile.json names it.
    .PARAMETER Client
        The client folder, instead of -TenantId.
    .PARAMETER Check
        The check whose exceptions to remove.
    .PARAMETER Object
        Only the exception for this object.
    .PARAMETER Expired
        Remove every expired exception instead.
    .PARAMETER OutRoot
        Where run folders are. Default: the profile's outputRoot, else ~/tenantkeep/evidence.
    .PARAMETER NoReport
        Change the file without rebuilding the newest report.
    .EXAMPLE
        Remove-PostureException -TenantId 00000000-0000-0000-0000-000000000000 -Check EM-016 -Object 'payroll@contoso.example'
    .EXAMPLE
        Remove-PostureException -Client ~/tenantkeep/clients/contoso -Expired
    .OUTPUTS
        The removed entries.
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Check')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive: tells the admin what changed and that the report was rebuilt.')]
    [OutputType([pscustomobject])]
    param(
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')] [string] $TenantId,
        [string] $Client,
        [Parameter(Mandatory, ParameterSetName = 'Check')] [string] $Check,
        [Parameter(ParameterSetName = 'Check')] [string] $Object,
        [Parameter(Mandatory, ParameterSetName = 'Expired')] [switch] $Expired,
        [string] $OutRoot,
        [switch] $NoReport
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $folder = Resolve-PostureClientFolder -Client $Client -TenantId $TenantId
    $path = Join-Path $folder 'exceptions.json'
    $today = [datetime]::UtcNow.Date
    $all = @(Read-PostureExceptionFile -Path $path)
    $anyObject = -not $PSBoundParameters.ContainsKey('Object')
    $match = {
        param($e)
        if ($Expired) { $x = ConvertTo-PostureUtcDateTime (Get-PostureValue $e 'expires'); return [bool]($x -and $x.Date -lt $today) }
        if ([string]$e['check'] -ne $Check) { return $false }
        return $anyObject -or [string]$e['object'] -eq $Object
    }
    $gone = @($all | Where-Object { & $match $_ })
    if ($gone.Count -eq 0) { Write-Host "Nothing to remove in $path."; return }
    $what = $(if ($Expired) { "$($gone.Count) expired exception(s)" } else { "$($gone.Count) exception(s) for $Check$(if ($Object) { " ($Object)" })" })
    if (-not $PSCmdlet.ShouldProcess($path, "Remove $what")) { return }
    Save-PostureJsonFile -Path $path -InputObject ([ordered]@{ exceptions = @($all | Where-Object { -not (& $match $_) }) }) -Confirm:$false
    Write-Host "Removed $what from $path"
    $run = Find-PostureRunFolder -Client $folder -TenantId $TenantId -OutRoot $OutRoot
    if ($run -and -not $NoReport) {
        $report = Update-PostureRunReport -Run $run -Client $folder -Confirm:$false
        Write-Host "Report rebuilt: $report (refresh the page)"
    }
    $gone | ForEach-Object { [pscustomobject]$_ }
}
