# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Start-PostureRun {
    <#
    .SYNOPSIS
        One sign-in, one command: collects every domain, builds the profile, writes the report and opens it.
    .DESCRIPTION
        Signs the admin in once (Connect-PostureSession), then runs the whole posture cycle from that sign-in:

          1. Exchange and Purview start first, in a second process, tokens handed over standard input (the Exchange
             and PnP modules do not share a process well on macOS). Purview is the one service with a sign-in of its
             own: Security & Compliance PowerShell issues no delegated token to a third-party app, so a second window
             may open for the same admin (a device code with -DeviceCode or -NoBrowser). Starting it first puts that
             prompt in the first minute; after it the run needs nothing from anyone.
          2. At the same time, in this process: the Graph-based collectors (Entra, Intune, Defender when the token
             carries ThreatHunting.Read.All) and Azure when the profile does not say azure: none and the Az modules
             are installed, then SharePoint and Teams with tokens from the broker.
          3. Hybrid: the client folder's hybrid/ad-* files, from the Windows collector, are copied into the run.
          4. The profile: created from the evidence on the first run, discovered keys refreshed on later runs, every
             other answer kept as New-PostureProfile last wrote it.
          5. The report, with the trend against the newest earlier run, and findings.csv in the run folder.
          6. The report opens in the browser. Without a Full licence for the tenant, the closing lines give the trial link
             with the tenant id filled in; the module sends nothing anywhere, the admin opens it or not.

        A progress bar shows the domain and step under way, the time so far and an estimate of the time left (from
        this tenant's previous run, or rough figures on the first). The machine is kept from idle sleep until the
        run ends, unless -AllowSleep; a closed laptop lid still sleeps.

        A collector whose module is not installed, or whose session fails, is skipped with a note and the report
        says what was not collected. A module older than the version the collectors were tested with gets a warning
        (Get-PostureRequirement lists them); the versions used are recorded in collection.json. The run folder keeps
        everything that was collected.

        Read-only throughout. Nothing leaves the machine: evidence under -OutRoot, client files under -Client.
    .PARAMETER TenantId
        Pin the run to one tenant, by id or by a verified domain such as contoso.onmicrosoft.com: a sign-in to any
        other is refused before anything is read. Optional: without it you pick the account in the browser and the
        tenant comes from that sign-in.
    .PARAMETER Client
        The client folder (profile.json, exceptions.json, tenantkeep.lic, imports/, hybrid/). Default:
        ~/tenantkeep/clients/<tenant display name, lower case, spaces to dashes>/, created on first run.
    .PARAMETER OutRoot
        Where run folders go, for this run. Default: outputRoot in the client's profile.json (New-PostureProfile
        asks for it), else ~/tenantkeep/evidence. Each run is a dated folder inside it, with report.html.
    .PARAMETER Collector
        Which collectors to run. Default: all of them.
    .PARAMETER DeviceCode
        Sign in with a device code instead of a browser window.
    .PARAMETER NoBrowser
        Print the sign-in address instead of opening the browser, and do not open the report.
    .PARAMETER AllowSleep
        Let the machine sleep during the run. Default: it is kept awake until the run ends.
    .PARAMETER SkipReport
        Collect only.
    .PARAMETER PassThru
        Return a summary object: Folder, Client, Report, Skipped, Errors, Duration.
    .EXAMPLE
        Start-PostureRun
    .EXAMPLE
        Start-PostureRun -TenantId contoso.onmicrosoft.com -Collector Entra, Intune, Exchange
    .EXAMPLE
        Start-PostureRun -OutRoot ~/Clients/Contoso/Assessments
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string], [pscustomobject])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Progress lines for the admin at the console.')]
    param(
        [ValidatePattern('^([0-9a-fA-F-]{36}|[A-Za-z0-9.-]+\.[A-Za-z]{2,})$')] [string] $TenantId,
        [string] $Client,
        [string] $OutRoot,
        [ValidateSet('Entra', 'Intune', 'Exchange', 'SharePoint', 'Teams', 'Defender', 'Purview', 'Azure')] [string[]] $Collector = @('Entra', 'Intune', 'Exchange', 'SharePoint', 'Teams', 'Defender', 'Purview', 'Azure'),
        [switch] $DeviceCode,
        [switch] $NoBrowser,
        [switch] $AllowSleep,
        [switch] $SkipReport,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    if (-not $PSCmdlet.ShouldProcess($(if ($TenantId) { $TenantId } else { 'the tenant you sign in to' }), 'Sign in, collect read-only evidence, write the report')) { return }
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $skipped = [ordered]@{}
    # Module versions against the tested ones (Get-PostureRequirement): missing skips the collector, older warns once.
    $warned = [System.Collections.Generic.HashSet[string]]::new()
    $usable = {
        param([string] $Module)
        $check = Test-PostureModuleRequirement -Name $Module
        if ($check.status -eq 'older' -and $warned.Add($Module)) { Write-Warning $check.message }
        $check
    }

    # 1. One sign-in.
    Write-Host 'Sign in once with an admin account that has the read roles (Get-PostureRequirement lists them).'
    Write-Host 'Every service uses that one sign-in; Purview may ask once more, before collection starts.'
    $connect = @{}
    if ($TenantId) { $connect.TenantId = $TenantId }
    if ($DeviceCode) { $connect.DeviceCode = $true } elseif ($NoBrowser) { $connect.NoBrowser = $true }
    $session = Connect-PostureSession @connect
    $context = Assert-PostureGraphScope -RequiredScope @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All')

    # 2. The client folder and where runs go.
    if (-not $Client) {
        $slug = (([string]$session.tenantDisplayName).ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
        if (-not $slug) { $slug = [string]$session.tenantId }
        $Client = Join-Path $HOME 'tenantkeep' 'clients' $slug
    }
    $Client = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Client)
    New-Item -ItemType Directory -Path $Client, (Join-Path $Client 'imports'), (Join-Path $Client 'hybrid') -Force | Out-Null
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
    $OutRoot = Get-PostureOutputRoot -Client $Client -OutRoot $OutRoot
    New-Item -ItemType Directory -Path $OutRoot -Force | Out-Null
    Write-Host "Client folder: $Client"

    # What runs where: decided before anything is collected, so the progress bar knows the whole run.
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
    $need = @{ SharePoint = 'PnP.PowerShell'; Teams = 'MicrosoftTeams' }
    $localPlan = [System.Collections.Generic.List[string]]::new()
    foreach ($name in 'SharePoint', 'Teams') {
        if ($name -notin $Collector) { continue }
        $check = & $usable $need[$name]
        if ($check.status -eq 'missing') { $skipped[$name] = $check.message; continue }
        $localPlan.Add($name)
    }
    $child = @($Collector | Where-Object { $_ -in 'Exchange', 'Purview' })
    if ($child.Count -gt 0) {
        $exo = & $usable 'ExchangeOnlineManagement'
        if ($exo.status -eq 'missing') { foreach ($n in $child) { $skipped[$n] = $exo.message }; $child = @() }
    }

    $awake = $(if ($AllowSleep) { $null } else { Enable-PostureKeepAwake })
    if ($awake) { Write-Host "Keeping this computer awake until the run ends ($($awake['method'])); a closed lid still sleeps." }
    $folder = $null
    $reportFile = $null
    $adFiles = @()
    try {
        $folder = New-PostureEvidenceFolder -OutRoot $OutRoot
        Write-Host "Run folder:    $folder"
        $estimates = Get-PostureRunEstimate -OutRoot $OutRoot -TenantId ([string]$session.tenantId)
        $phases = @(@('ConditionalAccess') + $main + @($localPlan) + @($(if ($child.Count -gt 0) { 'Second' })) + @($(if (-not $SkipReport) { 'Report' })) | Where-Object { $_ })
        $childFile = $(if ($child.Count -gt 0) { Join-Path $folder '.progress-child.json' } else { $null })
        Start-PostureProgress -Phase $phases -Estimate $estimates -ChildFile $childFile -Activity "TenantKeep Posture: $(if ($session.tenantDisplayName) { $session.tenantDisplayName } else { $session.tenantId })" -Confirm:$false

        # 3. Exchange and Purview first, in their own process, tokens over standard input.
        $childProcess = $null
        if ($child.Count -gt 0) {
            $tokens = @{}
            foreach ($name in @('graph') + @($child | Where-Object { $_ -eq 'Exchange' } | ForEach-Object { 'exchange' })) {
                $null = Get-PostureToken -Resource $name -Force
                $tokens[$name] = @{ accessToken = $script:PostureSession['tokens'][$name]['accessToken']; expiresUtc = $script:PostureSession['tokens'][$name]['expiresUtc'].ToString('o') }
            }
            $childEstimates = @{}
            foreach ($n in $child) { if ($estimates.ContainsKey($n)) { $childEstimates[$n] = $estimates[$n] } }
            $request = @{
                clientId = $session.clientId; tenantId = $session.tenantId; tenantName = $session.tenantName; account = $session.account; folder = $folder
                profilePath = $(if ($profileParam.Count -gt 0) { $profilePath } else { '' }); collectors = $child; tokens = $tokens
                purviewSignIn = $(if ($DeviceCode -or $NoBrowser) { 'device' } else { 'browser' }); progressFile = $childFile; estimates = $childEstimates
            }
            $childProcess = Start-PostureChildCollection -Request $request -NoWait
            Write-Host "Started $($child -join ' and ') in a second process.$(if ('Purview' -in $child) { ' Purview may open one more sign-in now; after that the run needs nothing from you.' })"
        }

        # 4. Graph-based collectors and Azure in this process, then SharePoint and Teams (PnP.PowerShell loads an
        # older Microsoft.Graph.Core, so it comes after every Graph read).
        $null = Invoke-PostureCollection -OutputFolder $folder -Collector $main -PassThru @profileParam
        $local = [System.Collections.Generic.List[string]]::new()
        foreach ($name in $localPlan) {
            try { Connect-PostureService -Name $name.ToLowerInvariant(); $local.Add($name) }
            catch { $skipped[$name] = "$name sign-in failed: $($_.Exception.Message)" }
        }
        if ($local.Count -gt 0) {
            try { Invoke-PostureCollection -Collector @($local) -SkipCaSnapshot -OutputFolder $folder @profileParam | Out-Null }
            catch { foreach ($n in $local) { $skipped[$n] = $_.Exception.Message } }
        }
        if ($childProcess) {
            Set-PostureProgressPhase -Name 'Second' -Label 'waiting for the second process' -Confirm:$false
            $exit = Wait-PostureChildCollection -Process $childProcess
            if ($exit -ne 0) { $skipped['Exchange or Purview'] = "The second process reported $exit failed collector(s); see errors.txt in the run folder." }
        }

        # 5. Hybrid files from the Windows collector.
        $adFiles = @(Get-ChildItem -LiteralPath (Join-Path $Client 'hybrid') -Filter 'ad-*' -File -ErrorAction SilentlyContinue)
        if ($adFiles.Count -gt 0) { $adFiles | Copy-Item -Destination $folder -Force }
        # The newest SharePoint site permissions report filed with Import-PostureSharingReport, summarised into this run.
        $null = Write-PostureSharingSummary -Client $Client -Folder $folder -Confirm:$false

        # 6. Profile: discovered from the evidence; every other answer stays as the wizard or the cmdlets wrote it.
        Set-PostureProgressPhase -Name 'Report' -Label 'profile' -Confirm:$false
        $profileArgs = @{ Path = $profilePath; Evidence = $folder; NonInteractive = $true; TenantId = $session.tenantId }
        if (-not (Test-Path -LiteralPath $profilePath)) { $profileArgs.ClientName = [string]$session.tenantDisplayName }
        $null = New-PostureProfile @profileArgs

        if (-not $SkipReport) {
            # 7. Report, with the trend against the newest earlier run that has checks.json.
            Set-PostureProgressPhase -Name 'Report' -Label 'report' -Confirm:$false
            $previous = @(Get-ChildItem -LiteralPath $OutRoot -Directory | Where-Object { $_.Name -match '^\d{8}-\d{4}$' -and $_.FullName -ne $folder -and (Test-Path (Join-Path $_.FullName 'checks.json')) } | Sort-Object Name | Select-Object -Last 1)
            $reportArgs = @{ Evidence = $folder; Client = $Client; PassThru = $true }
            if ($previous.Count -gt 0) { $reportArgs.Previous = $previous[0].FullName }
            $report = New-PostureReport @reportArgs
            $reportFile = @($report.Files | Where-Object { $_ -like '*.html' })[0]
            $null = Export-PostureFindings -Path $folder -OutputPath (Join-Path $folder 'findings.csv')
        }
    }
    finally {
        Complete-PostureProgress -Confirm:$false
        Disable-PostureKeepAwake -Handle $awake
        try { Stop-Transcript | Out-Null } catch { Write-Verbose 'No transcript to stop.' }
    }
    if ($reportFile -and -not $NoBrowser) { try { Start-Process $reportFile } catch { Write-Verbose "Report did not open: $($_.Exception.Message)" } }

    # errors.txt is appended by every process that wrote into the folder, so it is the count to report.
    $errorCount = 0
    $errorsFile = Join-Path $folder 'errors.txt'
    if (Test-Path -LiteralPath $errorsFile) { $errorCount = @(Get-Content -LiteralPath $errorsFile | Where-Object { $_.Trim() }).Count }
    Write-Host ''
    Write-Host "Finished in $(Format-PostureDuration $clock.Elapsed.TotalSeconds)." -ForegroundColor Green
    if ($adFiles.Count -gt 0) { Write-Host "Hybrid: $($adFiles.Count) ad-* files copied in" }
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

    if ($PassThru) { return [pscustomobject]@{ Folder = $folder; Client = $Client; Report = $reportFile; Skipped = $skipped; Errors = $errorCount; Duration = $clock.Elapsed } }
    return $folder
}
