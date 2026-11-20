# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Add-PostureException {
    <#
    .SYNOPSIS
        Accepts a risk: records an exception for a check, or for one affected object, in the client folder's
        exceptions.json, then rebuilds the newest report so the page shows it after a refresh.
    .DESCRIPTION
        The report's "Accept this risk" button copies this command with the tenant id, check and object filled in;
        paste it into PowerShell and it asks for the justification, owner, approver and expiry. Run it with only
        -TenantId (or -Client) to pick the check from the newest run's failures. An entry for the same check and
        object is replaced. The file is local to the client folder; nothing is written to the tenant.

        The newest run for the tenant is rebuilt from its evidence (seconds, no sign-in), so there is nothing to save
        in the browser: refresh the page. -NoReport skips the rebuild; the next run applies the exception either way.
    .PARAMETER TenantId
        The tenant id from the report header. Finds the client folder whose profile.json names it.
    .PARAMETER Client
        The client folder, instead of -TenantId.
    .PARAMETER Check
        The check id, for example EM-016. Omit it to choose from the newest run's failing checks.
    .PARAMETER Object
        One affected object (as the report names it). Omit it for the whole check.
    .PARAMETER Justification
        Why the risk is accepted and what compensates for it. Asked for when omitted.
    .PARAMETER Owner
        Who owns the risk. Asked for when omitted.
    .PARAMETER Approver
        Who approved it. Asked for when omitted; may be left blank.
    .PARAMETER Expires
        When the acceptance lapses and the check fails again. Default: one year from today.
    .PARAMETER OutRoot
        Where run folders are. Default: the profile's outputRoot, else ~/tenantkeep/evidence.
    .PARAMETER NoReport
        Record the exception without rebuilding the newest report.
    .EXAMPLE
        Add-PostureException -TenantId 00000000-0000-0000-0000-000000000000 -Check EM-016 -Object 'payroll@contoso.example'
    .EXAMPLE
        Add-PostureException -Client ~/tenantkeep/clients/contoso -Check CA-006 -Justification 'Pilot ends in March' -Owner 'IT Director' -Approver CISO -Expires 2027-03-31
    .OUTPUTS
        The recorded exception.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive: tells the admin where it wrote and that the report was rebuilt.')]
    [OutputType([pscustomobject])]
    param(
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')] [string] $TenantId,
        [string] $Client,
        [ValidatePattern('^[A-Z]{2,4}-\d{3}$')] [string] $Check,
        [string] $Object,
        [string] $Justification,
        [string] $Owner,
        [string] $Approver,
        [datetime] $Expires,
        [string] $OutRoot,
        [switch] $NoReport
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $folder = Resolve-PostureClientFolder -Client $Client -TenantId $TenantId
    $run = Find-PostureRunFolder -Client $folder -TenantId $TenantId -OutRoot $OutRoot
    $results = @()
    if ($run) { $results = @((Get-Content -Raw -LiteralPath (Join-Path (Get-PostureRunLayout -Folder $run).logs 'checks.json') | ConvertFrom-Json -AsHashtable -Depth 20).results) }
    $nameOf = { param($a) if ($a -is [System.Collections.IDictionary]) { [string]$a['name'] } else { [string]$a } }

    if (-not $Check) {
        $failing = @($results | Where-Object { $_.status -eq 'fail' } | Sort-Object { $_.id })
        if ($failing.Count -eq 0) { throw "No failing checks in the newest run$(if ($run) { " ($run)" }); pass -Check." }
        $why = (@($failing | ForEach-Object { "$($_.id) $($_.title)" }) -join "`n  ")
        $Check = Read-PostureAnswer -Question 'Which check is the accepted risk?' -Why $why -Choices @($failing | ForEach-Object { [string]$_.id })
    }
    $catalog = Import-PostureCheckCatalog
    $entry = @($catalog.checks | Where-Object { $_['id'] -eq $Check })
    if ($entry.Count -eq 0) { throw "$Check is not a check in the catalog." }
    $result = @($results | Where-Object { $_.id -eq $Check }) | Select-Object -First 1

    $affected = @()
    if ($result) { $affected = @(@($result.affected) | ForEach-Object { & $nameOf $_ } | Where-Object { $_ }) }
    if (-not $PSBoundParameters.ContainsKey('Object') -and -not $PSBoundParameters.ContainsKey('Justification') -and $affected.Count -gt 0) {
        $list = (@($affected | Select-Object -First 15) -join "`n  ") + $(if ($affected.Count -gt 15) { "`n  and $($affected.Count - 15) more" })
        while ($true) {
            $Object = [string](Read-PostureAnswer -Question 'One affected object, or blank for the whole check?' -Why $list -Default '')
            if (-not $Object -or $Object -in $affected) { break }
            Write-Warning "$Object is not among the affected objects of $Check."
        }
    }
    elseif ($Object -and $affected.Count -gt 0 -and $Object -notin $affected) { Write-Warning "$Object is not among the affected objects of $Check in the newest run; recorded anyway." }

    while (-not $Justification) { $Justification = [string](Read-PostureAnswer -Question 'Why is this risk accepted, and what compensates for it?') }
    if (-not $PSBoundParameters.ContainsKey('Owner')) { $Owner = [string](Read-PostureAnswer -Question 'Who owns the risk?' -Default '') }
    if (-not $PSBoundParameters.ContainsKey('Approver')) { $Approver = [string](Read-PostureAnswer -Question 'Who approved it? (blank if nobody yet)' -Default '') }
    if (-not $PSBoundParameters.ContainsKey('Expires')) {
        $default = [datetime]::UtcNow.Date.AddYears(1).ToString('yyyy-MM-dd')
        while ($true) {
            $text = [string](Read-PostureAnswer -Question 'Accepted until (yyyy-MM-dd)?' -Why 'After this date the check fails again until someone decides again.' -Default $default)
            $parsed = [datetime]::MinValue
            if ([datetime]::TryParseExact($text, 'yyyy-MM-dd', [cultureinfo]::InvariantCulture, 'AssumeUniversal', [ref]$parsed)) { $Expires = $parsed; break }
            Write-Warning "$text is not a date in yyyy-MM-dd form."
        }
    }
    if ($Expires.Date -le [datetime]::UtcNow.Date) { throw "The expiry $($Expires.ToString('yyyy-MM-dd')) is not in the future." }

    $path = Join-Path $folder 'exceptions.json'
    $list = @(Read-PostureExceptionFile -Path $path | Where-Object { -not ($_['check'] -eq $Check -and [string]$_['object'] -eq [string]$Object) })
    $new = [ordered]@{ check = $Check; object = $(if ($Object) { $Object } else { $null }); justification = $Justification; owner = $Owner; approver = $Approver; expires = $Expires.ToString('yyyy-MM-dd'); recordedUtc = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }
    $list += $new
    if (-not $PSCmdlet.ShouldProcess($path, "Accept the risk of $Check$(if ($Object) { " for $Object" })")) { return }
    Save-PostureJsonFile -Path $path -InputObject ([ordered]@{ exceptions = @($list) }) -Confirm:$false
    Write-Host "Recorded in $path"
    if ($run -and -not $NoReport) {
        $report = Update-PostureRunReport -Run $run -Client $folder -Confirm:$false
        Write-Host "Report rebuilt: $report (refresh the page)"
    }
    elseif (-not $run) { Write-Host 'No run for this tenant yet; the next run applies it.' }
    return [pscustomobject]$new
}
