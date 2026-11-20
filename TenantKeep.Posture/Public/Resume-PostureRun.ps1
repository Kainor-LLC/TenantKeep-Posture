# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Resume-PostureRun {
    <#
    .SYNOPSIS
        Finishes a run that partly failed: collects again only the domains that had a failure a second attempt can
        fix, or never finished, into the same run folder, then rebuilds its report.
    .DESCRIPTION
        Reads the run's plan (run.json), what it collected (collection.json) and what failed (errors.jsonl). A
        collector is collected again when it was planned and never finished, or when one of its steps failed for a
        reason a second attempt can fix: a role granted since, a sign-in that ran out, throttling, the network, a
        module installed since. Failures that are facts about the tenant (not licensed, not set up) are left, since
        collecting again would only say the same. A collector is rerun whole, not step by step, because later steps
        use what earlier ones read; everything it wrote before is replaced, and every other file stays.

        The failures being retried move from errors.jsonl and errors.txt to errors-previous.jsonl, so the report
        shows only what is still wrong. Then it signs in once (the run's tenant is pinned), collects, refreshes the
        profile and rebuilds report.html and findings.csv in the same folder.
    .PARAMETER Path
        The run folder (the report's Run Health view and the end of Start-PostureRun print the exact command).
    .PARAMETER Collector
        Collect these again instead of working it out, for example a domain that was skipped because its module was
        not installed.
    .PARAMETER DeviceCode
        Sign in with a device code instead of a browser window.
    .PARAMETER NoBrowser
        Print the sign-in address instead of opening the browser, and do not open the report.
    .PARAMETER AllowSleep
        Let the machine sleep during the run.
    .PARAMETER PassThru
        Return the Start-PostureRun summary, with the collectors that were collected again.
    .EXAMPLE
        Resume-PostureRun -Path ~/tenantkeep/evidence/20261120-0930
    .EXAMPLE
        Resume-PostureRun -Path ~/tenantkeep/evidence/20261120-0930 -Collector SharePoint
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string], [pscustomobject])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Tells the admin what will be collected again and why.')]
    param(
        [Parameter(Mandatory, Position = 0)] [string] $Path,
        [ValidateSet('Entra', 'SignIns', 'Intune', 'Exchange', 'SharePoint', 'Teams', 'Defender', 'Purview', 'Azure')] [string[]] $Collector,
        [switch] $DeviceCode,
        [switch] $NoBrowser,
        [switch] $AllowSleep,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $folder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if (-not (Test-Path -LiteralPath $folder -PathType Container)) { throw "Run folder not found: $folder" }
    $read = { param([string] $Name) $f = Join-Path $folder $Name; if (Test-Path -LiteralPath $f) { try { Get-Content -Raw -LiteralPath $f | ConvertFrom-Json -AsHashtable -Depth 10 } catch { $null } } }
    $plan = & $read 'run.json'
    $manifest = & $read 'collection.json'
    $tenantId = [string]$(if ($plan -and $plan['tenantId']) { $plan['tenantId'] } elseif ($manifest -and $manifest['tenantId']) { $manifest['tenantId'] })
    if (-not $tenantId) { throw "$folder has neither run.json nor collection.json with a tenant id; it is not a run folder Start-PostureRun made." }
    $client = [string]$(if ($plan -and $plan['client'] -and (Test-Path -LiteralPath $plan['client'])) { $plan['client'] } else { Resolve-PostureClientFolder -TenantId $tenantId })

    $failures = @(Read-PostureRunFailure -Folder $folder)
    $retryable = @('permission', 'token', 'throttled', 'network', 'module', 'unknown')
    if ($Collector) { $again = @($Collector); $why = @{}; foreach ($c in $again) { $why[$c] = 'asked for' } }
    else {
        $planned = @($(if ($plan) { $plan['planned'] } else { $manifest['collectors'] }) | Where-Object { $_ })
        $done = @($(if ($manifest) { $manifest['collectors'] }) | Where-Object { $_ })
        $why = [ordered]@{}
        foreach ($c in $planned) { if ($c -notin $done) { $why[$c] = 'did not finish' } }
        foreach ($f in $failures) {
            $c = [string]$f['collector']
            if (-not $c -or $c -eq 'ConditionalAccess' -or [string]$f['cause'] -notin $retryable) { continue }
            if (-not $why.Contains($c)) { $why[$c] = "$([string]$f['step']) failed ($([string]$f['cause']))" }
        }
        $again = @($why.Keys)
    }
    $valid = @('Entra', 'SignIns', 'Intune', 'Exchange', 'SharePoint', 'Teams', 'Defender', 'Purview', 'Azure')
    $again = @($again | Where-Object { $_ -in $valid })
    if ($plan -and $plan['skipped'] -and @($plan['skipped'].Keys).Count -gt 0 -and -not $Collector) {
        foreach ($k in @($plan['skipped'].Keys)) { Write-Host "Skipped when the run started: $k ($($plan['skipped'][$k])). Add -Collector to try it now." -ForegroundColor DarkGray }
    }
    if ($again.Count -eq 0) {
        $left = @($failures | Where-Object { [string]$_['cause'] -notin $retryable })
        Write-Host "Nothing to collect again in $folder$(if ($left.Count) { ": the $($left.Count) remaining failure(s) are facts about the tenant (not licensed or not set up), which a second attempt would not change" })."
        return
    }
    foreach ($c in $again) { Write-Host "Collecting $c again: $($why[$c])" }
    if (-not $PSCmdlet.ShouldProcess($folder, "Collect $($again -join ', ') again and rebuild the report")) { return }

    # The failures being retried leave the live files, so the report shows only what is still wrong.
    Invoke-PostureFolderLock -Folder $folder -Script {
        $jsonl = Join-Path $folder 'errors.jsonl'; $txt = Join-Path $folder 'errors.txt'
        $retry = @($failures | Where-Object { [string]$_['collector'] -in $again })
        $keys = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($f in $retry) { $null = $keys.Add("$($f['step']) :: $($f['message'])") }
        if ($retry.Count -gt 0) { Add-Content -LiteralPath (Join-Path $folder 'errors-previous.jsonl') -Value @($retry | ForEach-Object { $_['retriedUtc'] = [datetime]::UtcNow.ToString('o'); $_ | ConvertTo-Json -Compress -Depth 5 }) }
        $keepJson = @($failures | Where-Object { [string]$_['collector'] -notin $again } | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 5 })
        if (Test-Path -LiteralPath $jsonl) { Set-Content -LiteralPath $jsonl -Value $keepJson }
        if (Test-Path -LiteralPath $txt) { Set-Content -LiteralPath $txt -Value @(Get-Content -LiteralPath $txt | Where-Object { $_.Trim() -and -not $keys.Contains($_.Trim()) }) }
    }

    $runArgs = @{ TenantId = $tenantId; Client = $client; Folder = $folder; Collector = $again; PassThru = $true; Confirm = $false }
    foreach ($s in 'DeviceCode', 'NoBrowser', 'AllowSleep') { if ($PSBoundParameters.ContainsKey($s)) { $runArgs[$s] = $PSBoundParameters[$s] } }
    $result = Start-PostureRun @runArgs
    if ($PassThru) { $result | Add-Member -NotePropertyName Recollected -NotePropertyValue $again -PassThru; return }
    return $result.Folder
}
