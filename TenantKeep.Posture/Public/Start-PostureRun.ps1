# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Start-PostureRun {
    <#
    .SYNOPSIS
        One sign-in, one command: collects every domain, builds the profile, writes the report and opens it.
    .DESCRIPTION
        Signs the admin in once (Connect-PostureSession), then runs the whole posture cycle from that sign-in:

          1. Graph-based collectors (Entra, Intune, Defender when the token carries ThreatHunting.Read.All) and Azure
             when the profile does not say azure: none and the Az modules are installed.
          2. SharePoint and Teams in this process, with tokens from the broker.
          3. Exchange and Purview in a fresh process, tokens handed over standard input (the Exchange and PnP modules
             do not share a process well on macOS). Purview is the one service with a sign-in of its own: Security &
             Compliance PowerShell issues no delegated token to a third-party app, so a second window opens for the
             same admin (a device code with -DeviceCode or -NoBrowser).
          4. Hybrid: the client folder's hybrid/ad-* files, from the Windows collector, are copied into the run.
          5. The profile: created from the evidence on the first run, discovered keys refreshed on later runs, every
             answer the wizard would ask left to the report's Settings view.
          6. The report, with the trend against the newest earlier run, and findings.csv merged with the register.
          7. The report opens in the browser. Without a Full licence for the tenant, the closing lines give the trial link
             with the tenant id filled in; the module sends nothing anywhere, the admin opens it or not.

        A collector whose module is not installed, or whose session fails, is skipped with a note and the report
        says what was not collected. A module older than the version the collectors were tested with gets a warning
        (Get-PostureRequirement lists them); the versions used are recorded in collection.json. The run folder keeps
        everything that was collected.

        Read-only throughout. Nothing leaves the machine: evidence under -OutRoot, client files under -Client.
    .PARAMETER TenantId
        Pin the run to one tenant: a sign-in to any other is refused before anything is read.
    .PARAMETER Client
        The client folder (profile.json, exceptions.json, findings.csv, tenantkeep.lic, imports/, hybrid/). Default:
        ~/tenantkeep/clients/<tenant display name, lower case, spaces to dashes>/, created on first run.
    .PARAMETER OutRoot
        Where run folders go. Default ~/tenantkeep/evidence.
    .PARAMETER Collector
        Which collectors to run. Default: all of them.
    .PARAMETER DeviceCode
        Sign in with a device code instead of a browser window.
    .PARAMETER NoBrowser
        Print the sign-in address instead of opening the browser, and do not open the report.
    .PARAMETER SkipReport
        Collect only.
    .PARAMETER PassThru
        Return a summary object: Folder, Client, Report, Skipped, Errors.
    .EXAMPLE
        Start-PostureRun
    .EXAMPLE
        Start-PostureRun -TenantId contoso.onmicrosoft.com -Collector Entra, Intune, Exchange
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string], [pscustomobject])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Progress lines for the admin at the console.')]
    param(
        [ValidatePattern('^([0-9a-fA-F-]{36}|[A-Za-z0-9.-]+\.[A-Za-z]{2,})$')] [string] $TenantId,
        [string] $Client,
        [ValidateNotNullOrEmpty()] [string] $OutRoot = (Join-Path $HOME 'tenantkeep' 'evidence'),
        [ValidateSet('Entra', 'Intune', 'Exchange', 'SharePoint', 'Teams', 'Defender', 'Purview', 'Azure')] [string[]] $Collector = @('Entra', 'Intune', 'Exchange', 'SharePoint', 'Teams', 'Defender', 'Purview', 'Azure'),
        [switch] $DeviceCode,
        [switch] $NoBrowser,
        [switch] $SkipReport,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    if (-not $PSCmdlet.ShouldProcess($(if ($TenantId) { $TenantId } else { 'the tenant you sign in to' }), 'Sign in, collect read-only evidence, write the report')) { return }
    $skipped = [ordered]@{}
    $step = { param([string] $Text) Write-Host "> $Text" -ForegroundColor Cyan }
    # Module versions against the tested ones (Get-PostureRequirement): missing skips the collector, older warns once.
    $warned = [System.Collections.Generic.HashSet[string]]::new()
    $usable = {
        param([string] $Module)
        $check = Test-PostureModuleRequirement -Name $Module
        if ($check.status -eq 'older' -and $warned.Add($Module)) { Write-Warning $check.message }
        $check
    }

    # 1. One sign-in.
    $connect = @{}
    if ($TenantId) { $connect.TenantId = $TenantId }
    if ($DeviceCode) { $connect.DeviceCode = $true } elseif ($NoBrowser) { $connect.NoBrowser = $true }
    $session = Connect-PostureSession @connect
    $context = Assert-PostureGraphScope -RequiredScope @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All')

    # 2. The client folder.
    if (-not $Client) {
        $slug = (([string]$session.tenantDisplayName).ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
        if (-not $slug) { $slug = [string]$session.tenantId }
        $Client = Join-Path $HOME 'tenantkeep' 'clients' $slug
    }
    $Client = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Client)
    New-Item -ItemType Directory -Path $Client, (Join-Path $Client 'imports'), (Join-Path $Client 'hybrid') -Force | Out-Null
    $OutRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutRoot)
    New-Item -ItemType Directory -Path $OutRoot -Force | Out-Null
    $profilePath = Join-Path $Client 'profile.json'
    $profileParam = @{}
    if (Test-Path -LiteralPath $profilePath) {
        $existing = Get-Content -Raw -LiteralPath $profilePath | ConvertFrom-Json -AsHashtable -Depth 10
        $expected = [string]$(if ($existing.Contains('tenantId')) { $existing['tenantId'] })
        if ($expected -and $expected -ne [string]$session.tenantId) { throw "$profilePath belongs to tenant $expected, but the sign-in is to $($session.tenantId). Pass -Client for this tenant's folder." }
        $profileParam.ProfilePath = $profilePath
        if ($existing.Contains('azure') -and [string]$existing['azure'] -eq 'none' -and 'Azure' -in $Collector) {
            $Collector = @($Collector | Where-Object { $_ -ne 'Azure' })
            $skipped['Azure'] = 'Profile says azure: none; the Azure domain is not applicable to this tenant.'
        }
    }
    Write-Host "Client folder: $Client"

    # 3. Graph-based collectors and Azure in this process.
    $main = @($Collector | Where-Object { $_ -in 'Entra', 'Intune' })
    if ('Defender' -in $Collector) {
        if ('ThreatHunting.Read.All' -in @($context.Scopes)) { $main += 'Defender' }
        else { $skipped['Defender'] = 'ThreatHunting.Read.All is not on the token; the tenant consented without it.' }
    }
    if ('Azure' -in $Collector) {
        $az = @('Az.Accounts', 'Az.ResourceGraph' | ForEach-Object { & $usable $_ })
        if (@($az | Where-Object { $_.status -eq 'missing' }).Count -eq 0) {
            try { Connect-PostureService -Name azure; $main += 'Azure' }
            catch { $skipped['Azure'] = "Azure sign-in failed: $($_.Exception.Message)" }
        }
        else { $skipped['Azure'] = 'Az.Accounts and Az.ResourceGraph are not installed; the Azure domain was not collected. Set azure: none in the profile if there is nothing in Azure.' }
    }
    if ($main.Count -eq 0) { $main = @('Entra') }
    & $step "Collecting $($main -join ', ')"
    $collection = Invoke-PostureCollection -OutRoot $OutRoot -Collector $main -PassThru @profileParam
    $folder = [string]$collection.Folder
    $errorCount = @($collection.Errors).Count

    # 4. SharePoint and Teams here, after every Graph read above (PnP.PowerShell loads an older Microsoft.Graph.Core).
    $local = [System.Collections.Generic.List[string]]::new()
    $need = @{ SharePoint = 'PnP.PowerShell'; Teams = 'MicrosoftTeams' }
    foreach ($name in 'SharePoint', 'Teams') {
        if ($name -notin $Collector) { continue }
        $check = & $usable $need[$name]
        if ($check.status -eq 'missing') { $skipped[$name] = $check.message; continue }
        try { Connect-PostureService -Name $name.ToLowerInvariant(); $local.Add($name) }
        catch { $skipped[$name] = "$name sign-in failed: $($_.Exception.Message)" }
    }
    if ($local.Count -gt 0) {
        & $step "Collecting $($local -join ', ')"
        try { Invoke-PostureCollection -Collector @($local) -SkipCaSnapshot -OutputFolder $folder @profileParam | Out-Null }
        catch { foreach ($n in $local) { $skipped[$n] = $_.Exception.Message } }
    }

    # 5. Exchange and Purview in their own process, tokens over standard input.
    $child = @($Collector | Where-Object { $_ -in 'Exchange', 'Purview' })
    if ($child.Count -gt 0) {
        $exo = & $usable 'ExchangeOnlineManagement'
        if ($exo.status -eq 'missing') { foreach ($n in $child) { $skipped[$n] = $exo.message } }
        else {
            & $step "Collecting $($child -join ', ') in a second process$(if ('Purview' -in $child) { ' (Purview opens a sign-in of its own)' })"
            $tokens = @{}
            foreach ($name in @('graph') + @($child | Where-Object { $_ -eq 'Exchange' } | ForEach-Object { 'exchange' })) {
                $null = Get-PostureToken -Resource $name -Force
                $tokens[$name] = @{ accessToken = $script:PostureSession['tokens'][$name]['accessToken']; expiresUtc = $script:PostureSession['tokens'][$name]['expiresUtc'].ToString('o') }
            }
            $request = @{ clientId = $session.clientId; tenantId = $session.tenantId; tenantName = $session.tenantName; account = $session.account; folder = $folder; profilePath = $(if ($profileParam.Count -gt 0) { $profilePath } else { '' }); collectors = $child; tokens = $tokens; purviewSignIn = $(if ($DeviceCode -or $NoBrowser) { 'device' } else { 'browser' }) }
            $exit = Start-PostureChildCollection -Request $request
            if ($exit -ne 0) { $skipped['Exchange or Purview'] = "The second process reported $exit failed collector(s); see errors.txt in the run folder." }
        }
    }

    # 6. Hybrid files from the Windows collector.
    $hybrid = Join-Path $Client 'hybrid'
    $adFiles = @(Get-ChildItem -LiteralPath $hybrid -Filter 'ad-*' -File -ErrorAction SilentlyContinue)
    if ($adFiles.Count -gt 0) { $adFiles | Copy-Item -Destination $folder -Force; Write-Host "Hybrid: $($adFiles.Count) ad-* files copied in" }

    # 7. Profile: discovered from the evidence, the rest left to the report's Settings view.
    & $step 'Profile'
    $profileArgs = @{ Path = $profilePath; Evidence = $folder; NonInteractive = $true; TenantId = $session.tenantId }
    if (-not (Test-Path -LiteralPath $profilePath)) { $profileArgs.ClientName = [string]$session.tenantDisplayName }
    $null = New-PostureProfile @profileArgs

    $reportFile = $null
    if (-not $SkipReport) {
        # 8. Report, with the trend against the newest earlier run that has checks.json.
        & $step 'Report'
        $previous = @(Get-ChildItem -LiteralPath $OutRoot -Directory | Where-Object { $_.Name -match '^\d{8}-\d{4}$' -and $_.FullName -ne $folder -and (Test-Path (Join-Path $_.FullName 'checks.json')) } | Sort-Object Name | Select-Object -Last 1)
        $reportArgs = @{ Evidence = $folder; Client = $Client; PassThru = $true }
        if ($previous.Count -gt 0) { $reportArgs.Previous = $previous[0].FullName }
        $report = New-PostureReport @reportArgs
        $reportFile = @($report.Files | Where-Object { $_ -like '*.html' })[0]
        $findingsArgs = @{ Path = $folder; OutputPath = (Join-Path $folder 'findings.csv') }
        if (Test-Path -LiteralPath (Join-Path $Client 'findings.csv')) { $findingsArgs.Merge = Join-Path $Client 'findings.csv' }
        $null = Export-PostureFindings @findingsArgs
        if ($reportFile -and -not $NoBrowser) { try { Start-Process $reportFile } catch { Write-Verbose "Report did not open: $($_.Exception.Message)" } }
    }

    # errors.txt is appended by every process that wrote into the folder, so it is the count to report.
    $errorsFile = Join-Path $folder 'errors.txt'
    if (Test-Path -LiteralPath $errorsFile) { $errorCount = @(Get-Content -LiteralPath $errorsFile | Where-Object { $_.Trim() }).Count }
    Write-Host ''
    Write-Host "Run folder: $folder"
    $versions = Get-PostureModuleVersionUsed
    Write-Host "PowerShell $($PSVersionTable.PSVersion); modules: $(@($versions.Keys | ForEach-Object { "$_ $(if ($versions[$_]) { $versions[$_] } else { 'not installed' })" }) -join ', ')"
    if ($reportFile) { Write-Host "Report: $reportFile" }
    if ($errorCount -gt 0) { Write-Host "$errorCount step(s) logged in errors.txt" -ForegroundColor Yellow }
    foreach ($k in $skipped.Keys) { Write-Host "Skipped $($k): $($skipped[$k])" -ForegroundColor Yellow }
    # No network call here or anywhere: the trial is requested in the browser, by the admin, if they choose to.
    $licPath = Join-Path $Client 'tenantkeep.lic'
    $licArgs = @{ TenantId = [string]$session.tenantId }
    if (Test-Path -LiteralPath $licPath) { $licArgs.Path = $licPath }
    $lic = $(try { Get-PostureLicense @licArgs } catch { $null })
    if (-not ($lic -and $lic.Valid -and $lic.Tier -eq 'full')) {
        Write-Host "Conditional Access only: no Full licence for this tenant. Every domain free for 30 days: https://tenantkeep.app/trial/?tenant=$($session.tenantId)" -ForegroundColor Cyan
    }

    if ($PassThru) { return [pscustomobject]@{ Folder = $folder; Client = $Client; Report = $reportFile; Skipped = $skipped; Errors = $errorCount } }
    return $folder
}
