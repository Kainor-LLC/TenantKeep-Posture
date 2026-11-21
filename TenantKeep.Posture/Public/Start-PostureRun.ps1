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
          3. Hybrid: the client folder's hybrid/ad-* files, from the Windows collector, are brought into the run
             through Import-PostureEvidence's checks.
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
    .PARAMETER Name
        What to call this run's folder, for example "Contoso Q4 2026". Default: the date and time (2026-11-20-0957).
        Inside it, report.html, report.md, findings.csv and findings.json sit at the top and evidence/, affected/,
        errors/ and logs/ hold the rest.
    .PARAMETER Client
        The client folder (profile.json, exceptions.json, tenantkeep.lic, imports/, hybrid/). Default:
        ~/tenantkeep/clients/<tenant display name, lower case, spaces to dashes>/, created on first run.
    .PARAMETER OutRoot
        Where run folders go, for this run. Default: outputRoot in the client's profile.json (New-PostureProfile
        asks for it), else ~/tenantkeep/evidence. Each run is a dated folder inside it, with report.html.
    .PARAMETER Collector
        Which collectors to run. Default: all of them.
    .PARAMETER Folder
        Collect into this existing run folder instead of a new one, keeping what is already there. Resume-PostureRun
        uses it to collect only what failed; the Conditional Access snapshot is not taken again when the folder has one.
    .PARAMETER DeviceCode
        Sign in with a device code instead of a browser window.
    .PARAMETER NoBrowser
        Print the sign-in address instead of opening the browser, and do not open the report.
    .PARAMETER SignInDays
        Days of Entra sign-in log to read, 1 to 30. Default 7. On a large tenant this is the longest part of a run;
        it streams, saves a checkpoint, carries on by itself after a failure and resumes with Resume-PostureRun.
    .PARAMETER FullPerUserMfa
        Read every member's per-user MFA state. Default: all of them up to 5,000 members; above that a sample, every
        admin and 1,000 at random, and the check says it judged a sample.
    .PARAMETER Redact
        Also write share/ with the report, report.md and findings.json with the tenant's people and places replaced
        by placeholders, for a report that goes to an AI service or a third party (New-PostureReport -Redact).
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
    .EXAMPLE
        Start-PostureRun -Name "Contoso Q4 2026"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string], [pscustomobject])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Progress lines for the admin at the console.')]
    param(
        [ValidatePattern('^([0-9a-fA-F-]{36}|[A-Za-z0-9.-]+\.[A-Za-z]{2,})$')] [string] $TenantId,
        [string] $Name,
        [string] $Client,
        [string] $OutRoot,
        [ValidateSet('Entra', 'SignIns', 'Intune', 'Exchange', 'SharePoint', 'Teams', 'Defender', 'Purview', 'Azure')] [string[]] $Collector = @('Entra', 'SignIns', 'Intune', 'Exchange', 'SharePoint', 'Teams', 'Defender', 'Purview', 'Azure'),
        [string] $Folder,
        [switch] $DeviceCode,
        [switch] $NoBrowser,
        [switch] $AllowSleep,
        [ValidateRange(1, 30)] [int] $SignInDays = 7,
        [switch] $FullPerUserMfa,
        [switch] $Redact,
        [switch] $SkipReport,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest
    # PowerShell names are case-insensitive: -Folder and the run's $folder below would be one variable.
    $into = $Folder

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
    $null = Set-PostureFolderPrivate -Path $Client -Confirm:$false
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
    if ($into) {
        $into = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($into)
        if (-not (Test-Path -LiteralPath $into -PathType Container)) { throw "Run folder not found: $into" }
        $into = (Get-PostureRunLayout -Folder $into).root
        $OutRoot = Split-Path $into -Parent
    }
    else { $OutRoot = Get-PostureOutputRoot -Client $Client -OutRoot $OutRoot }
    New-Item -ItemType Directory -Path $OutRoot -Force | Out-Null
    Write-Host "Client folder: $Client"

    # What runs where: decided before anything is collected, so the progress bar knows the whole run.
    $main = @($Collector | Where-Object { $_ -in 'Entra', 'SignIns', 'Intune' })
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
    if ($main.Count -eq 0 -and -not $into) { $main = @('Entra') }
    # Into an existing run, the Conditional Access snapshot is kept when it is there.
    $caDone = [bool]($into -and @(Get-ChildItem -LiteralPath (Get-PostureRunLayout -Folder $into).evidence -Filter 'policies.json' -File -ErrorAction SilentlyContinue).Count -gt 0)
    $need = @{ SharePoint = 'PnP.PowerShell'; Teams = 'MicrosoftTeams' }
    $localPlan = [System.Collections.Generic.List[string]]::new()
    # $svc, never $name: PowerShell variables ignore case, so a loop over $name would overwrite -Name.
    foreach ($svc in 'SharePoint', 'Teams') {
        if ($svc -notin $Collector) { continue }
        $check = & $usable $need[$svc]
        if ($check.status -eq 'missing') { $skipped[$svc] = $check.message; continue }
        $localPlan.Add($svc)
    }
    # The SharePoint admin read has its own app, granted to named admins only. Graph says first whether this admin
    # holds it, so a tenant that never set it up sees no second browser window; the SharePoint checks then use what
    # Graph returns (the Entra collector reads it).
    if ($localPlan.Contains('SharePoint')) {
        $spClient = Get-PostureSharePointClientId -OrgProfile $(if ($profileParam.ContainsKey('ProfilePath')) { $existing } else { $null })
        $access = $(if ($spClient) { Test-PostureSharePointAccess -ClientId $spClient } else { @{ status = 'absent'; reason = 'This build carries no app id for TenantKeep Posture for SharePoint.' } })
        if ($access.status -in 'granted', 'unknown') {
            $spConnect = @{ SharePoint = $true; ClientId = $spClient }
            if ($DeviceCode) { $spConnect.DeviceCode = $true } elseif ($NoBrowser) { $spConnect.NoBrowser = $true }
            try { $null = Connect-PostureSession @spConnect }
            catch { $skipped['SharePoint'] = "SharePoint admin read not used: $($_.Exception.Message) The SharePoint checks use what Graph returns."; $null = $localPlan.Remove('SharePoint') }
        }
        else { $skipped['SharePoint'] = "SharePoint admin read not used: $($access.reason)"; $null = $localPlan.Remove('SharePoint') }
    }
    $child = @($Collector | Where-Object { $_ -in 'Exchange', 'Purview' })
    if ($child.Count -gt 0) {
        $exo = & $usable 'ExchangeOnlineManagement'
        if ($exo.status -eq 'missing') { foreach ($n in $child) { $skipped[$n] = $exo.message }; $child = @() }
    }

    # Roles before a long run: what will come back empty, and what to grant. The run goes on either way.
    $coverage = @(); $heldRoles = @()
    try { $heldRoles = @(Get-PostureSignedInRole); $coverage = @(Test-PostureRoleCoverage -Collector (@($main) + @($localPlan) + @($child)) -HeldRole $heldRoles) }
    catch { Write-Verbose "Role check skipped: $($_.Exception.Message)" }
    $short = @($coverage | Where-Object { $_.Status -eq 'missing' })
    foreach ($row in $coverage) {
        $colour = @{ ok = 'Green'; missing = 'Yellow'; unknown = 'DarkGray' }[$row.Status]
        Write-Host ('  {0,-11} {1}' -f $row.Collector, $row.Detail) -ForegroundColor $colour
    }
    if ($short.Count -gt 0) { Write-Host "  $($short.Count) domain(s) will come back incomplete. Grant the role and run again, or carry on and use Resume-PostureRun after. PIM roles count once activated." -ForegroundColor Yellow }

    $awake = $(if ($AllowSleep) { $null } else { Enable-PostureKeepAwake })
    if ($awake) { Write-Host "Keeping this computer awake until the run ends ($($awake['method'])); a closed lid still sleeps." }
    $folder = $null
    $runLayout = $null
    $tokenServer = $null
    $reportFile = $null; $report = $null
    $hybridImport = $null
    try {
        # $folder is where evidence goes (what the collectors and the report read); $runLayout has the rest.
        $runLayout = $(if ($into) { Get-PostureRunLayout -Folder $into } else { New-PostureRunFolder -OutRoot $OutRoot -Name $Name -Confirm:$false })
        $folder = $runLayout.evidence
        try { Start-Transcript -Path (Join-Path $runLayout.logs 'transcript.txt') -Append | Out-Null } catch { Write-Verbose "Transcript not started: $($_.Exception.Message)" }
        Write-Host "Run folder:    $($runLayout.root)"
        # How big the tenant is and what that means for this run, before anything long starts. Three small reads;
        # a count Graph will not give is said as unknown.
        if ($main.Count -gt 0) {
            $previewArgs = @{ Size = (Get-PostureTenantSize); Collector = @(@($main) + @($localPlan) + @($child)); FullPerUserMfa = [bool]$FullPerUserMfa }
            foreach ($line in @(Get-PostureRunPreview @previewArgs)) { Write-Host $line }
        }
        $runAs = [ordered]@{ account = [string]$session.account; roles = @($heldRoles); checkedUtc = [datetime]::UtcNow.ToString('o'); coverage = @($coverage | ForEach-Object { [ordered]@{ collector = $_.Collector; status = $_.Status; detail = $_.Detail } }) }
        Write-PostureRunPlan -Folder $runLayout.root -TenantId ([string]$session.tenantId) -Client $Client -Collector (@($main) + @($localPlan) + @($child)) -Skipped $skipped -RunAs $runAs -Resume:([bool]$into) -Confirm:$false
        $estimates = Get-PostureRunEstimate -OutRoot $OutRoot -TenantId ([string]$session.tenantId)
        $phases = @(@($(if (-not $caDone -and ($main.Count -gt 0 -or -not $into)) { 'ConditionalAccess' })) + $main + @($localPlan) + @($(if ($child.Count -gt 0) { 'Second' })) + @($(if (-not $SkipReport) { 'Report' })) | Where-Object { $_ })
        $childFile = $(if ($child.Count -gt 0) { Join-Path $runLayout.logs '.progress-child.json' } else { $null })
        Start-PostureProgress -Phase $phases -Estimate $estimates -ChildFile $childFile -Activity "TenantKeep Posture: $(if ($session.tenantDisplayName) { $session.tenantDisplayName } else { $session.tenantId })" -Confirm:$false

        # 3. Exchange and Purview first, in their own process, tokens over standard input.
        $childProcess = $null
        if ($child.Count -gt 0) {
            $tokens = @{}
            # Graph only: Exchange and Purview sign in through the Exchange module's own app in that process.
            foreach ($svc in @('graph')) {
                $null = Get-PostureToken -Resource $svc -Force
                $tokens[$svc] = @{ accessToken = $script:PostureSession['tokens'][$svc]['accessToken']; expiresUtc = $script:PostureSession['tokens'][$svc]['expiresUtc'].ToString('o') }
            }
            $childEstimates = @{}
            foreach ($n in $child) { if ($estimates.ContainsKey($n)) { $childEstimates[$n] = $estimates[$n] } }
            $request = @{
                clientId = $session.clientId; tenantId = $session.tenantId; tenantName = $session.tenantName; account = $session.account; folder = $folder
                profilePath = $(if ($profileParam.Count -gt 0) { $profilePath } else { '' }); collectors = $child; tokens = $tokens
                purviewSignIn = $(if ($DeviceCode -or $NoBrowser) { 'device' } else { 'browser' }); progressFile = $childFile; estimates = $childEstimates
            }
            # A fresh Graph token for the second process on request, so it never meets an expired one.
            $tokenServer = Start-PostureTokenServer -Resource @($tokens.Keys) -Confirm:$false
            if ($tokenServer) { $request.tokenPipe = $tokenServer.pipe; $request.tokenSecret = $tokenServer.secret }
            $childProcess = Start-PostureChildCollection -Request $request -NoWait
            Write-Host "Started $($child -join ' and ') in a second process.$(if ('Purview' -in $child) { ' Purview may open one more sign-in now; after that the run needs nothing from you.' })"
        }

        # 4. Graph-based collectors and Azure in this process, then SharePoint and Teams (PnP.PowerShell loads an
        # older Microsoft.Graph.Core, so it comes after every Graph read).
        if ($main.Count -gt 0) { $null = Invoke-PostureCollection -OutputFolder $folder -Collector $main -SkipCaSnapshot:$caDone -SignInDays $SignInDays -FullPerUserMfa:$FullPerUserMfa -PassThru @profileParam }
        $local = [System.Collections.Generic.List[string]]::new()
        foreach ($svc in $localPlan) {
            try { Connect-PostureService -Name $svc.ToLowerInvariant(); $local.Add($svc) }
            catch { $skipped[$svc] = "$svc sign-in failed: $($_.Exception.Message)" }
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

        # 5. The Active Directory read the client folder holds (hybrid/, from the Windows collector), through the same
        # checks as any evidence from another machine: every file against the collector's bundle.json, and the
        # forest's sign-in names against the tenant's domains. What an earlier attempt at this run brought in goes
        # first, so the client folder is the one source. A folder that fails a check is not used, and says why.
        $hybridFolder = Join-Path $Client 'hybrid'
        if (@(Get-ChildItem -LiteralPath $hybridFolder -Filter 'ad-*' -File -ErrorAction SilentlyContinue).Count -gt 0) {
            Get-ChildItem -LiteralPath $folder -File -Filter 'ad-*' | Where-Object { $_.Name -match '^ad-\d{2}-[a-z0-9-]+\.(json|csv)$' } | Remove-Item -Force
            try { $hybridImport = Import-PostureEvidence -Path $hybridFolder -Run $runLayout.root -NoReport -Confirm:$false }
            catch {
                $message = "The Active Directory evidence in $hybridFolder was not used: $((([string]$_.Exception.Message) -replace '\s*[\r\n]+\s*', ' ').Trim())"
                Write-Warning $message
                Invoke-PostureFolderLock -Folder $folder -Script { Add-Content -Path (Join-Path $runLayout.errors 'errors.txt') -Value "Active Directory evidence :: $message" }
                Write-PostureStepFailure -Folder $folder -Label 'Active Directory evidence' -Message $message -Collector 'Hybrid' -Confirm:$false
            }
        }
        # A site permissions report the admin saved straight into imports/ is filed first, with the same checks as
        # Import-PostureSharingReport (it is that report, it has sites, it is this tenant's); a file that is
        # anything else is left where it is and not read.
        foreach ($dropped in @(Get-ChildItem -LiteralPath (Join-Path $Client 'imports') -Filter '*.csv' -File -ErrorAction SilentlyContinue)) {
            try { $filedReport = Add-PostureSharingReportFile -Client $Client -Path $dropped.FullName -TenantId ([string]$session.tenantId) -Confirm:$false; if ($filedReport) { Write-Host "Site permissions report filed from imports/: $($dropped.Name)" } }
            catch { Write-Warning "imports/$($dropped.Name) was not used: $((([string]$_.Exception.Message) -replace '\s*[\r\n]+\s*', ' ').Trim())" }
        }
        # The newest SharePoint site permissions report filed with Import-PostureSharingReport, summarised into this run.
        $null = Write-PostureSharingSummary -Client $Client -Folder $folder -Confirm:$false
        # The calls made outside a collector (the role check, the SharePoint grant check) join the ledger.
        $null = Save-PostureCallLedger -Folder $folder -Confirm:$false

        # 6. Profile: discovered from the evidence; every other answer stays as the wizard or the cmdlets wrote it.
        Set-PostureProgressPhase -Name 'Report' -Label 'profile' -Confirm:$false
        $profileArgs = @{ Path = $profilePath; Evidence = $folder; NonInteractive = $true; TenantId = $session.tenantId }
        if (-not (Test-Path -LiteralPath $profilePath)) { $profileArgs.ClientName = [string]$session.tenantDisplayName }
        $null = New-PostureProfile @profileArgs

        if (-not $SkipReport) {
            # 7. Report, with the trend against the newest earlier run that has checks.json.
            Set-PostureProgressPhase -Name 'Report' -Label 'report' -Confirm:$false
            $previous = Get-PosturePreviousRun -Run $runLayout.root
            $reportArgs = @{ Evidence = $folder; Client = $Client; PassThru = $true; Redact = [bool]$Redact }
            if ($previous) { $reportArgs.Previous = $previous }
            $report = New-PostureReport @reportArgs
            $reportFile = @($report.Files | Where-Object { $_ -like '*.html' })[0]
            $null = Export-PostureFindings -Path $runLayout.root -OutputPath (Join-Path $runLayout.root 'findings.csv')
            Write-PostureRunReadme -Layout $runLayout -Confirm:$false
        }
    }
    finally {
        Stop-PostureTokenServer -Server $tokenServer -Confirm:$false
        Complete-PostureProgress -Confirm:$false
        Disable-PostureKeepAwake -Handle $awake
        try { Stop-Transcript | Out-Null } catch { Write-Verbose 'No transcript to stop.' }
    }
    if ($reportFile -and -not $NoBrowser) { try { Start-Process $reportFile } catch { Write-Verbose "Report did not open: $($_.Exception.Message)" } }

    # errors.txt is appended by every process that wrote into the folder, so it is the count to report.
    $errorCount = 0
    $errorsFile = Join-Path (Get-PostureRunLayout -Folder $folder).errors 'errors.txt'
    if (Test-Path -LiteralPath $errorsFile) { $errorCount = @(Get-Content -LiteralPath $errorsFile | Where-Object { $_.Trim() }).Count }
    Write-Host ''
    Write-Host "Finished in $(Format-PostureDuration $clock.Elapsed.TotalSeconds)." -ForegroundColor Green
    if ($hybridImport) { Write-Host "Hybrid: $(@($hybridImport.Files).Count + @($hybridImport.Unchanged).Count) Active Directory files brought in from the client folder ($($hybridImport.Checked); tenant $($hybridImport.TenantCheck))" }
    Write-Host "Run folder: $($runLayout.root)"
    $versions = Get-PostureModuleVersionUsed
    Write-Host "PowerShell $($PSVersionTable.PSVersion); modules: $(@($versions.Keys | ForEach-Object { "$_ $(if ($versions[$_]) { $versions[$_] } else { 'not installed' })" }) -join ', ')"
    if ($reportFile) { Write-Host "Report: $reportFile" }
    if ($errorCount -gt 0) {
        $failures = @($(try { Read-PostureRunFailure -Folder $folder } catch { @() }))
        Write-Host "$errorCount step(s) could not be read:" -ForegroundColor Yellow
        foreach ($group in @($failures | Group-Object { [string]$_['cause'] } | Sort-Object Count -Descending)) {
            $steps = @($group.Group | ForEach-Object { "$($_['collector']) $($_['step'])".Trim() } | Select-Object -Unique)
            Write-Host "  $($steps -join '; ')" -ForegroundColor Yellow
            foreach ($advice in @($group.Group | ForEach-Object { Get-PostureFailureAdvice -Failure $_ } | Select-Object -Unique)) { Write-Host "    $advice" }
        }
        $defaultClients = Join-Path $HOME 'tenantkeep' 'clients'
        $resume = $(if ((Split-Path $Client -Parent) -eq $defaultClients) { "Resume-PostureRun -Client $(Split-Path $Client -Leaf)" } else { "Resume-PostureRun -Path '$($runLayout.root -replace "'", "''")'" })
        Write-Host "  Then collect only what failed, into this run: $resume" -ForegroundColor Cyan
    }
    foreach ($k in $skipped.Keys) { Write-Host "Skipped $($k): $($skipped[$k])" -ForegroundColor Yellow }
    # What the assessment still lacks, the same rows the report's overview shows.
    $todo = @($(if ($report -and $report.Report -and $report.Report.Contains('completion')) { $report.Report.completion }))
    if ($todo.Count -gt 0) {
        Write-Host ''
        Write-Host 'To complete this assessment:' -ForegroundColor Cyan
        foreach ($t in $todo) {
            Write-Host "  $($t.title)$(if ($null -ne $t.checks -and $t.checks -gt 0) { ": $($t.checks) check$(if ($t.checks -ne 1) { 's' }) waiting" })$(if ($t.note) { " ($($t.note))" })"
            Write-Host "      Who: $($t.who). Where: $($t.where)." -ForegroundColor DarkGray
            Write-Host "      $($t.get)"
            if ($t.bring) { Write-Host "      Then: $($t.bring)" -ForegroundColor DarkGray }
        }
    }
    # No network call here or anywhere: the trial is requested in the browser, by the admin, if they choose to.
    $licPath = Join-Path $Client 'tenantkeep.lic'
    $licArgs = @{ TenantId = [string]$session.tenantId }
    if (Test-Path -LiteralPath $licPath) { $licArgs.Path = $licPath }
    $lic = $(try { Get-PostureLicense @licArgs } catch { $null })
    if (-not ($lic -and $lic.Valid -and $lic.Tier -eq 'full')) {
        Write-Host "Conditional Access only: no Full licence for this tenant. Every domain free for 30 days: https://tenantkeep.app/trial/?tenant=$($session.tenantId)" -ForegroundColor Cyan
    }

    if ($PassThru) { return [pscustomobject]@{ Folder = $runLayout.root; Evidence = $folder; Client = $Client; Report = $reportFile; Skipped = $skipped; Errors = $errorCount; Duration = $clock.Elapsed } }
    return $runLayout.root
}
