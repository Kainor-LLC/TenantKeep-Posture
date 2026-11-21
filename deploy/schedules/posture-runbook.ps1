#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Azure Automation runbook (PowerShell 7.6 runtime): the monthly full posture cycle with the account's managed identity.
.DESCRIPTION
    Deployed by deploy/automation/deploy.ps1 -IncludePosture. One job does what an admin does by hand over an afternoon:
      1. sign in as the managed identity: Graph and Azure first and every Graph call before PnP loads (its old
         Microsoft.Graph.Core breaks the Graph SDK), then Exchange, Purview (certificate app from the customer's Key
         Vault, when New-PosturePurviewApp.ps1 has run), then SharePoint and Teams
      2. download the client container: profile.json, brand.json, exceptions.json, tenantkeep.lic and any
         ad-* files a hybrid tenant's Windows collector produced
      3. Invoke-PostureCollection into a work folder (every collector whose session opened)
      4. New-PostureReport against the previous run for the trend, Export-PostureFindings into the run
      5. upload the run to the posture container, prune old runs
    A collector whose sign-in fails is skipped with the reason in the job output; the report says which domains were not
    collected. Nothing here writes to the tenant: sign-ins and reads only, storage in the customer's own subscription.

    A job that is stopped carries on. Azure Automation stops a sandbox job after three hours and starts it again from
    the top of this script, up to three times (verify the limit for the PowerShell 7 runtime). So the run is copied to
    the posture container as it goes: each evidence file when its step closes, with the run's journal and error files
    (Invoke-PostureCollection -StepCompleted). A job that starts and finds a run in the container that began less than
    a day ago and has a journal and no report downloads it and continues in it: domains that finished are left alone
    (-SkipFinished) and a long list that finished is kept, not read again. A list that was part way through is read
    again from its start. Above the size in docs/scheduling.md, run this runbook on a Hybrid Runbook Worker instead,
    which has neither the three hours nor the sandbox's memory and disk.

    Identity roles: Grant-ManagedIdentityGraphRole.ps1 -IncludePosture (Graph application roles, Exchange.ManageAsApp,
    the Teams tenant admin API role, Global Reader), plus Reader and Security Reader on the subscriptions. SharePoint:
    the tenant settings are read through Graph. The admin read (site list) is opt-in: it needs Sites.FullControl.All
    (Grant-ManagedIdentityGraphRole.ps1 -IncludeSharePointAdminRead) and TENANTKEEP_SHAREPOINT_ADMIN_URL.

    Variables: TENANTKEEP_POSTURE_CONTAINER_URL, TENANTKEEP_CLIENT_CONTAINER_URL, TENANTKEEP_POSTURE_KEEP_RUNS,
    TENANTKEEP_ORGANIZATION, TENANTKEEP_SHAREPOINT_ADMIN_URL, TENANTKEEP_PURVIEW_APP_ID, TENANTKEEP_PURVIEW_CERT (a Key
    Vault secret URL, never the certificate), TEAMS_WEBHOOK, EMAIL_TO, EMAIL_FROM.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

try {
    Write-Output "step: read variables (PowerShell $($PSVersionTable.PSVersion))"
    $getVar = { param([string] $Name) try { ([string](Get-AutomationVariable -Name $Name)).Trim('"') } catch { '' } }
    $postureUrl = & $getVar 'TENANTKEEP_POSTURE_CONTAINER_URL'
    $clientUrl = & $getVar 'TENANTKEEP_CLIENT_CONTAINER_URL'
    if (-not $postureUrl -or -not $clientUrl) { throw 'Automation variables TENANTKEEP_POSTURE_CONTAINER_URL and TENANTKEEP_CLIENT_CONTAINER_URL must be set (deploy with -IncludePosture).' }
    $keepRuns = [int]((& $getVar 'TENANTKEEP_POSTURE_KEEP_RUNS') -replace '[^0-9]', '0')
    $organization = & $getVar 'TENANTKEEP_ORGANIZATION'
    $spoAdmin = & $getVar 'TENANTKEEP_SHAREPOINT_ADMIN_URL'
    $purviewAppId = & $getVar 'TENANTKEEP_PURVIEW_APP_ID'
    $purviewCert = & $getVar 'TENANTKEEP_PURVIEW_CERT'
    $webhook = & $getVar 'TEAMS_WEBHOOK'
    $emailTo = @(((& $getVar 'EMAIL_TO')) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $emailFrom = & $getVar 'EMAIL_FROM'

    # The Purview variable is a Key Vault secret URL, and the identity's vault token goes to that address: only an
    # address in Azure Key Vault is accepted, so a changed variable cannot send the token anywhere else.
    if ($purviewCert -and $purviewCert -notmatch '^https://[A-Za-z0-9-]{3,24}\.vault\.azure\.net/secrets/[0-9A-Za-z-]{1,127}(/[0-9a-fA-F]{32})?/?$') {
        Write-Output 'TENANTKEEP_PURVIEW_CERT is not a Key Vault secret URL (https://<vault>.vault.azure.net/secrets/<name>); it is not used, and Purview is skipped.'
        $purviewCert = ''; $purviewCertRefused = $true
    }
    else { $purviewCertRefused = $false }

    $accountName = ([uri]$postureUrl).Host.Split('.')[0]
    $postureContainer = ([uri]$postureUrl).AbsolutePath.Trim('/')
    $clientContainer = ([uri]$clientUrl).AbsolutePath.Trim('/')
    $blobBase = "https://$accountName.blob.core.windows.net"

    # Blob storage over REST with the identity's token. Az.Storage is deliberately not used: it and ExchangeOnlineManagement
    # each ship a Microsoft.OData.Core, and whichever loads second fails, which costs either the mailbox reads or the upload.
    $blobToken = {
        $t = Get-AzAccessToken -ResourceUrl 'https://storage.azure.com/' -WarningAction SilentlyContinue
        if ($t.Token -is [securestring]) { ConvertFrom-SecureString -SecureString $t.Token -AsPlainText } else { [string]$t.Token }
    }
    $blobHeaders = { @{ Authorization = "Bearer $(& $blobToken)"; 'x-ms-version' = '2021-12-02'; 'x-ms-date' = [datetime]::UtcNow.ToString('R') } }
    $blobList = {
        param([string] $Container, [string] $Prefix = '')
        $names = [System.Collections.Generic.List[string]]::new(); $marker = ''
        do {
            $uri = "$blobBase/$Container`?restype=container&comp=list&prefix=$([uri]::EscapeDataString($Prefix))$(if ($marker) { "&marker=$([uri]::EscapeDataString($marker))" })"
            $text = [string](Invoke-WebRequest -Uri $uri -Headers (& $blobHeaders) -Method Get).Content
            $xml = [xml]$text.TrimStart([char]0xFEFF)   # the listing starts with a byte order mark the XML parser rejects
            foreach ($b in @($xml.SelectNodes('/EnumerationResults/Blobs/Blob'))) { if ($b -and $b.Name) { $names.Add([string]$b.Name) } }   # an empty container has a Blobs element with no children; strict mode has no .Blob on that
            $marker = [string]$xml.EnumerationResults.NextMarker
        } while ($marker)
        return $names.ToArray()   # callers wrap in @(); a leading comma here would hand them a nested array
    }
    $blobGet = { param([string] $Container, [string] $Name, [string] $Path) Invoke-WebRequest -Uri "$blobBase/$Container/$Name" -Headers (& $blobHeaders) -Method Get -OutFile $Path | Out-Null }
    $blobPut = { param([string] $Container, [string] $Name, [string] $Path) $h = & $blobHeaders; $h['x-ms-blob-type'] = 'BlockBlob'; Invoke-WebRequest -Uri "$blobBase/$Container/$Name" -Headers $h -Method Put -InFile $Path -ContentType 'application/octet-stream' | Out-Null }
    $blobDelete = { param([string] $Container, [string] $Name) Invoke-WebRequest -Uri "$blobBase/$Container/$Name" -Headers (& $blobHeaders) -Method Delete | Out-Null }

    # The run in the container as it goes. $uploaded remembers what is there (relative name, length and time), so a file
    # is sent once and sent again only when it has changed: the journal and the manifest grow, an evidence file does not.
    # Files still being written (.part), list cursors and lock files stay in the sandbox.
    $uploaded = @{}
    $uploadChanged = {
        param([string] $RunFolder, [string[]] $Path)
        $name = Split-Path $RunFolder -Leaf
        foreach ($p in @($Path)) {
            if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
            # FileInfo, not Get-Item: Get-Item does not find a dot file on Linux and macOS without -Force.
            $item = [System.IO.FileInfo]::new($p)
            if ($item.Name -like '*.part' -or $item.Name -like 'cursor-*.json' -or $item.Name -like '.*' -or $item.Name -like '*.tmp-*') { continue }
            $rel = [System.IO.Path]::GetRelativePath($RunFolder, $item.FullName) -replace '\\', '/'
            if ($rel.StartsWith('..')) { continue }
            $stamp = "$($item.Length)|$($item.LastWriteTimeUtc.Ticks)"
            if ($uploaded.ContainsKey($rel) -and $uploaded[$rel] -eq $stamp) { continue }
            & $blobPut $postureContainer "$name/$rel" $item.FullName
            $uploaded[$rel] = $stamp
        }
    }
    # Called by the module each time a step or a domain finishes, with the files it closed and the run's records.
    $onStep = { param($done) & $uploadChanged ([string]$done.folder) (@($done.files) + @($done.record)) }
    # The run to carry on in, from the container's listing: the newest run, when it has a journal and no report and
    # began less than a day ago. Anything else is a new run.
    $findUnfinished = {
        param([string[]] $Blobs, [datetime] $Now)
        $newest = @($Blobs | ForEach-Object { ($_ -split '/')[0] } | Where-Object { $_ -match '^\d{8}-\d{4}$' } | Sort-Object -Unique | Select-Object -Last 1)
        if ($newest.Count -eq 0) { return $null }
        $name = [string]$newest[0]
        if ($Blobs -notcontains "$name/journal.jsonl" -or $Blobs -contains "$name/report.html") { return $null }
        $began = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($name, 'yyyyMMdd-HHmm', [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$began)) { return $null }
        $age = $Now - $began
        if ($age.TotalHours -lt 0 -or $age.TotalHours -ge 24) { return $null }
        return $name
    }

    # ---- 1. Graph and Azure first. The session-bound modules are imported only after the last Graph call (see 4b).
    Write-Output 'step: sign in (Azure, Graph)'
    $null = Connect-AzAccount -Identity
    Connect-MgGraph -Identity -NoWelcome
    $ctx = Get-MgContext
    Write-Output "Graph tenant $($ctx.TenantId), roles: $(@($ctx.Scopes).Count)"
    if (-not $organization) {
        $org = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains' -OutputType HashTable
        $organization = [string](@($org.value[0].verifiedDomains | Where-Object { $_.isInitial })[0].name)
        Write-Output "Organization from Graph: $organization"
    }
    $skipped = [ordered]@{}
    # Purview: ExchangeOnlineManagement has no managed identity sign-in for Connect-IPPSSession, so the customer's setup
    # script (New-PosturePurviewApp.ps1) registers a certificate app with the certificate in the customer's Key Vault. The
    # identity reads it here, in memory, never to disk (the CLAUDE.md carve-out). Without the variables, Purview is skipped.
    $purviewOpen = $false
    if ($purviewAppId -and $purviewCert) {
        try {
            $vaultToken = Get-AzAccessToken -ResourceUrl 'https://vault.azure.net' -WarningAction SilentlyContinue
            $vt = $(if ($vaultToken.Token -is [securestring]) { ConvertFrom-SecureString -SecureString $vaultToken.Token -AsPlainText } else { [string]$vaultToken.Token })
            $secret = Invoke-RestMethod -Uri "$purviewCert`?api-version=7.4" -Headers @{ Authorization = "Bearer $vt" } -Method Get
            $pfx = [Convert]::FromBase64String([string]$secret.value)
            $purviewCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfx, [string]$null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
            Connect-IPPSSession -Certificate $purviewCertificate -AppId $purviewAppId -Organization $organization -ShowBanner:$false
            $purviewOpen = $true; Write-Output "Purview session open (certificate $($purviewCertificate.Thumbprint.Substring(0, 8))..., expires $($purviewCertificate.NotAfter.ToString('yyyy-MM-dd')))"
        }
        catch { $skipped['Purview'] = $_.Exception.Message; Write-Output "Purview sign-in failed; skipped: $($_.Exception.Message)" }
    }
    elseif ($purviewCertRefused) { $skipped['Purview'] = 'TENANTKEEP_PURVIEW_CERT is not a Key Vault secret URL (https://<vault>.vault.azure.net/secrets/<name>).' }
    else { $skipped['Purview'] = 'Purview app not configured: run deploy/setup/New-PosturePurviewApp.ps1 once to collect Purview in the scheduled run.' }
    # Exchange signs in now, before Az.Storage loads: both carry Microsoft.OData.Core, and the mailbox cmdlets need Exchange's newer copy to be the one in memory.
    $exchangeOpen = $false
    try {
        Connect-ExchangeOnline -ManagedIdentity -Organization $organization -ShowBanner:$false; $exchangeOpen = $true
        # One REST cmdlet now, so Exchange's Microsoft.OData.Core is the copy in memory before Az.Storage brings its older one.
        $null = Get-EXOMailbox -ResultSize 1 -ErrorAction SilentlyContinue
        Write-Output 'Exchange session open'
    }
    catch { $skipped['Exchange'] = $_.Exception.Message; Write-Output "Exchange sign-in failed; skipped: $($_.Exception.Message)" }

    Write-Output 'step: import module'
    Import-Module TenantKeep.Posture
    Write-Output "module $((Get-Module TenantKeep.Posture).Version) build: $(& (Get-Module TenantKeep.Posture) { $script:PostureBuildState.detail })"

    $work = Join-Path ([System.IO.Path]::GetTempPath()) 'TenantKeep-Posture'
    if (Test-Path $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    $evidenceRoot = Join-Path $work 'evidence'; $client = Join-Path $work 'client'
    New-Item -ItemType Directory -Path $evidenceRoot, $client -Force | Out-Null

    # ---- 2. Client files (profile, brand, exceptions, licence, register, hybrid ad-* files).
    Write-Output 'step: download client container'
    $clientBlobs = @(& $blobList $clientContainer)
    foreach ($name in $clientBlobs) {
        $dest = Join-Path $client ($name -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force | Out-Null
        & $blobGet $clientContainer $name $dest
    }
    Write-Output "client files: $($clientBlobs.Count)"
    $profilePath = Join-Path $client 'profile.json'
    if (-not (Test-Path $profilePath)) { Write-Output 'No profile.json in the client container; the report uses discovery defaults. Upload one from New-PostureProfile for thresholds and third-party answers.' }

    # ---- 3. The runs in the container: one to carry on in, if a job was stopped today, and the last finished one
    # for the trend.
    Write-Output 'step: list previous runs'
    $blobs = @(& $blobList $postureContainer)
    $runNames = @($blobs | ForEach-Object { ($_ -split '/')[0] } | Where-Object { $_ -match '^\d{8}-\d{4}$' } | Sort-Object -Unique)
    $continue = & $findUnfinished $blobs (Get-Date)
    $folder = $null
    if ($continue) {
        $folder = Join-Path $evidenceRoot $continue
        $mine = @($blobs | Where-Object { $_ -like "$continue/*" })
        foreach ($b in $mine) {
            $dest = Join-Path $folder ($b.Substring($continue.Length + 1) -replace '/', [System.IO.Path]::DirectorySeparatorChar)
            New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force | Out-Null
            & $blobGet $postureContainer $b $dest
            # What came from the container is not sent back unless it changes.
            $got = [System.IO.FileInfo]::new($dest)
            $uploaded[$b.Substring($continue.Length + 1)] = "$($got.Length)|$($got.LastWriteTimeUtc.Ticks)"
        }
        Write-Output "carrying on in run $continue, which an earlier job began ($($mine.Count) files brought back)"
    }
    $previous = $null
    $finishedRuns = @($runNames | Where-Object { $_ -ne $continue -and $blobs -contains "$_/checks.json" })
    if ($finishedRuns.Count -gt 0) {
        $latest = $finishedRuns[-1]; $previous = Join-Path $evidenceRoot $latest
        New-Item -ItemType Directory -Path $previous -Force | Out-Null
        & $blobGet $postureContainer "$latest/checks.json" (Join-Path $previous 'checks.json')
        Write-Output "previous run $latest"
    }

    # ---- 4. Collect: Graph-based collectors and Azure first.
    Write-Output 'step: collect (Entra, Intune, Defender, Azure)'
    # Only name collectors whose roles the token carries: a named collector without its role is an error, an unnamed one a warning.
    $mainCollectors = @('Entra', 'Intune')
    if ('ThreatHunting.Read.All' -in @($ctx.Scopes)) { $mainCollectors += 'Defender' } else { $skipped['Defender'] = 'ThreatHunting.Read.All is not on the Graph token yet (roles granted recently are cached for up to a day).' }
    $azureWanted = $true
    if (Test-Path $profilePath) { try { $pj = Get-Content -Raw -LiteralPath $profilePath | ConvertFrom-Json -AsHashtable; if ($pj -and $pj.Contains('azure') -and [string]$pj['azure'] -eq 'none') { $azureWanted = $false } } catch { Write-Verbose 'profile.json unreadable; Azure stays on.' } }
    if (-not $azureWanted) { $skipped['Azure'] = 'Profile says azure: none; the Azure domain is not applicable to this tenant.' }
    elseif ((Get-AzContext -ErrorAction SilentlyContinue) -and (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) { $mainCollectors += 'Azure' } else { $skipped['Azure'] = 'No Azure context or Az.ResourceGraph not loaded.' }
    $collectParams = @{ Collector = $mainCollectors; PassThru = $true; StepCompleted = $onStep }
    if ($folder) {
        # A run an earlier job began: its finished domains are left alone, and its Conditional Access snapshot kept.
        $collectParams.OutputFolder = $folder; $collectParams.SkipFinished = $true
        if (Test-Path -LiteralPath (Join-Path $folder 'policies.json')) { $collectParams.SkipCaSnapshot = $true }
    }
    else { $collectParams.OutRoot = $evidenceRoot }
    if (Test-Path $profilePath) { $collectParams.ProfilePath = $profilePath }
    $collection = Invoke-PostureCollection @collectParams
    $folder = [string]$collection.Folder
    Write-Output "evidence $folder, errors $(@($collection.Errors).Count)"

    # ---- 4b. Session-bound collectors, in this order and only now: the Graph SDK resolves Microsoft.Graph.Core to the
    # old copy PnP.PowerShell loads, so every Graph call happens above, before PnP is imported. The sandbox has no pwsh
    # executable (the host is a custom .NET app), so there is no child process to hide in. Each phase is its own try.
    $phase = {
        param([string] $Name, [scriptblock] $Connect, [string[]] $Collectors)
        try {
            & $Connect
            Invoke-PostureCollection -Collector $Collectors -SkipCaSnapshot -OutputFolder $folder -StepCompleted $onStep -SkipFinished:([bool]$continue) @profileParam | Out-Null
            Write-Output "$Name collected"
        }
        catch { $skipped[$Name] = $_.Exception.Message; Write-Output "$Name failed; skipped: $($_.Exception.Message)" }
    }
    $profileParam = @{}; if (Test-Path $profilePath) { $profileParam.ProfilePath = $profilePath }
    Write-Output 'step: collect (Exchange)'
    if ($exchangeOpen) { & $phase 'Exchange' { } @('Exchange') }
    Write-Output 'step: collect (Purview)'
    if ($purviewOpen) { & $phase 'Purview' { } @('Purview') }
    # The SharePoint tenant settings were read through Graph with the Entra collector (SharePointTenantSettings.Read.All).
    # The SharePoint admin read (the site list, restricted search) runs only when the deployment names the admin site,
    # which goes with the Sites.FullControl.All grant (Grant-ManagedIdentityGraphRole.ps1 -IncludeSharePointAdminRead).
    # It has a phase of its own, so a refusal there never costs the Teams read.
    Write-Output 'step: collect (SharePoint)'
    if ($spoAdmin) { & $phase 'SharePoint' { Connect-PnPOnline -Url $spoAdmin -ManagedIdentity } @('SharePoint') }
    else { Write-Output 'SharePoint admin read not set up (no TENANTKEEP_SHAREPOINT_ADMIN_URL): the tenant settings come from Graph, and the checks on the site list say not evaluated.' }
    Write-Output 'step: collect (Teams)'
    & $phase 'Teams' { Connect-MicrosoftTeams -Identity | Out-Null } @('Teams')
    $hybrid = Join-Path $client 'hybrid'
    if (Test-Path $hybrid) { Copy-Item -Path (Join-Path $hybrid 'ad-*') -Destination $folder -Force; Write-Output 'hybrid ad-* files copied in' }

    Write-Output 'step: report'
    $reportParams = @{ Evidence = $folder; Client = $client; PassThru = $true }
    if ($previous -and (Test-Path (Join-Path $previous 'checks.json'))) { $reportParams.Previous = $previous }
    $report = New-PostureReport @reportParams
    Write-Output "report written: $(@($report.Files) -join ', ')"
    $null = Export-PostureFindings -Path $folder -OutputPath (Join-Path $folder 'findings.csv')

    # ---- 5. Upload the rest of the run, prune. Everything under the run folder, with its subfolders: the report
    # points to affected/<check>.csv for the full lists. Evidence went up as it was collected; this sends what is
    # new or changed since (the report, the findings, the check results, the final manifest).
    Write-Output 'step: upload'
    $runName = Split-Path $folder -Leaf
    $before = $uploaded.Count
    & $uploadChanged $folder @(Get-ChildItem -Path $folder -File -Recurse | ForEach-Object { $_.FullName })
    Write-Output "uploaded run $runName ($($uploaded.Count) files in the container, $($uploaded.Count - $before) of them now)"
    if ($keepRuns -gt 0) {
        $all = @(@($runNames) + @($runName) | Sort-Object -Unique)
        foreach ($old in ($all | Select-Object -First ([Math]::Max(0, $all.Count - $keepRuns)))) {
            foreach ($b in ($blobs | Where-Object { $_ -like "$old/*" })) { & $blobDelete $postureContainer $b }
            Write-Output "pruned run $old"
        }
    }

    # ---- 6. Tell someone, through the same opt-in channels as the CA cycle.
    $summary = "TenantKeep Posture run $runName for ${organization}: score $($report.Report.score.value) ($($report.Report.score.grade)), $($report.Report.counts.fail) failing checks. Report: $postureContainer/$runName/report.html"
    if ($skipped.Count -gt 0) { $summary += ". Not collected: $(@($skipped.Keys) -join ', ')" }
    Write-Output $summary
    if ($webhook) {
        # A plain Adaptive Card to the customer's own Teams Workflows webhook (opt-in, same channel as the CA cycle).
        $card = @{ type = 'message'; attachments = @(@{ contentType = 'application/vnd.microsoft.card.adaptive'; content = @{ type = 'AdaptiveCard'; version = '1.4'; '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'; body = @(@{ type = 'TextBlock'; text = 'TenantKeep Posture monthly run'; weight = 'Bolder'; size = 'Medium' }, @{ type = 'TextBlock'; text = $summary; wrap = $true }) } }) } | ConvertTo-Json -Depth 8
        try { Invoke-RestMethod -Uri $webhook -Method Post -ContentType 'application/json' -Body $card | Out-Null; Write-Output 'posted to Teams' } catch { Write-Output "Teams post failed: $($_.Exception.Message)" }
    }
    $notify = Join-Path (Split-Path (Get-Module TenantKeep.Posture).Path) 'schedules' 'ca-notifications.ps1'
    if ($emailTo.Count -gt 0 -and $emailFrom -and (Test-Path $notify)) {
        . $notify
        # The report goes as an attachment up to 2 MB. A larger one would put the message over what Graph takes in one
        # request (verify the limit), and the mail would not be sent at all: the message then says where the report is.
        $reportFile = Join-Path $folder 'report.html'
        $mail = @{ To = $emailTo; From = $emailFrom; Subject = "TenantKeep Posture: $runName" }
        if ((Get-Item -LiteralPath $reportFile).Length -le 2MB) { $mail.HtmlBody = "<p>$([System.Net.WebUtility]::HtmlEncode($summary))</p>"; $mail.AttachmentPath = $reportFile }
        else { $mail.HtmlBody = "<p>$([System.Net.WebUtility]::HtmlEncode($summary))</p><p>The report is too large to attach. It is in the storage container: $([System.Net.WebUtility]::HtmlEncode("$postureUrl/$runName/report.html"))</p>" }
        try { $null = Send-CaChangeEmail @mail; Write-Output "emailed the $(if ($mail.ContainsKey('AttachmentPath')) { 'report' } else { 'summary with where the report is' })" } catch { Write-Output "Email failed: $($_.Exception.Message)" }
    }
    [pscustomobject]@{ Run = $runName; Score = $report.Report.score.value; Failing = $report.Report.counts.fail; Skipped = @($skipped.Keys); Container = $postureUrl }
}
catch {
    Write-Error "Runbook failed: $($_.Exception.Message)`nat $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())`n$($_.ScriptStackTrace)" -ErrorAction Continue
    throw
}
