#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Azure Automation runbook (PowerShell 7.4 runtime): the monthly full posture cycle with the account's managed identity.
.DESCRIPTION
    Deployed by deploy/automation/deploy.ps1 -IncludePosture. One job does what an admin does by hand over an afternoon:
      1. sign in as the managed identity: Graph and Azure first and every Graph call before PnP loads (its old
         Microsoft.Graph.Core breaks the Graph SDK), then Exchange, Purview (certificate app from the customer's Key
         Vault, when New-PosturePurviewApp.ps1 has run), then SharePoint and Teams
      2. download the client container: profile.json, brand.json, exceptions.json, tenantkeep.lic, findings.csv and any
         ad-* files a hybrid tenant's Windows collector produced
      3. Invoke-PostureCollection into a work folder (every collector whose session opened)
      4. New-PostureReport against the previous run for the trend, Export-PostureFindings merged with the register
      5. upload the run to the posture container, write findings.csv back to the client container, prune old runs
    A collector whose sign-in fails is skipped with the reason in the job output; the report says which domains were not
    collected. Nothing here writes to the tenant: sign-ins and reads only, storage in the customer's own subscription.

    Identity roles: Grant-ManagedIdentityGraphRole.ps1 -IncludePosture (Graph application roles, Exchange.ManageAsApp,
    SharePoint Sites.FullControl.All (verify: the least SharePoint application permission that lets Get-PnPTenant read),
    the Teams tenant admin API role, Global Reader), plus Reader and Security Reader on the subscriptions.

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
    Import-Module Tenantkeep.Posture
    Write-Output "module $((Get-Module Tenantkeep.Posture).Version) build: $(& (Get-Module Tenantkeep.Posture) { $script:PostureBuildState.detail })"

    $work = Join-Path ([System.IO.Path]::GetTempPath()) 'tenantkeep-posture'
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

    # ---- 3. Previous run, for the trend and the register merge.
    Write-Output 'step: list previous runs'
    $blobs = @(& $blobList $postureContainer)
    $runNames = @($blobs | ForEach-Object { ($_ -split '/')[0] } | Where-Object { $_ -match '^\d{8}-\d{4}$' } | Sort-Object -Unique)
    $previous = $null
    if ($runNames.Count -gt 0) {
        $latest = $runNames[-1]; $previous = Join-Path $evidenceRoot $latest
        New-Item -ItemType Directory -Path $previous -Force | Out-Null
        if ($blobs -contains "$latest/checks.json") { & $blobGet $postureContainer "$latest/checks.json" (Join-Path $previous 'checks.json') }
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
    $collectParams = @{ OutRoot = $evidenceRoot; Collector = $mainCollectors; PassThru = $true }
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
            Invoke-PostureCollection -Collector $Collectors -SkipCaSnapshot -OutputFolder $folder @profileParam | Out-Null
            Write-Output "$Name collected"
        }
        catch { $skipped[$Name] = $_.Exception.Message; Write-Output "$Name failed; skipped: $($_.Exception.Message)" }
    }
    $profileParam = @{}; if (Test-Path $profilePath) { $profileParam.ProfilePath = $profilePath }
    Write-Output 'step: collect (Exchange)'
    if ($exchangeOpen) { & $phase 'Exchange' { } @('Exchange') }
    Write-Output 'step: collect (Purview)'
    if ($purviewOpen) { & $phase 'Purview' { } @('Purview') }
    Write-Output 'step: collect (SharePoint, Teams)'
    if ($spoAdmin) {
        & $phase 'SharePoint and Teams' { Connect-PnPOnline -Url $spoAdmin -ManagedIdentity; Connect-MicrosoftTeams -Identity | Out-Null } @('SharePoint', 'Teams')
    }
    else {
        $skipped['SharePoint'] = 'TENANTKEEP_SHAREPOINT_ADMIN_URL not set.'
        & $phase 'Teams' { Connect-MicrosoftTeams -Identity | Out-Null } @('Teams')
    }
    $hybrid = Join-Path $client 'hybrid'
    if (Test-Path $hybrid) { Copy-Item -Path (Join-Path $hybrid 'ad-*') -Destination $folder -Force; Write-Output 'hybrid ad-* files copied in' }

    Write-Output 'step: report'
    $reportParams = @{ Evidence = $folder; Client = $client; PassThru = $true }
    if ($previous -and (Test-Path (Join-Path $previous 'checks.json'))) { $reportParams.Previous = $previous }
    $report = New-PostureReport @reportParams
    Write-Output "report written: $(@($report.Files) -join ', ')"
    $register = Join-Path $client 'findings.csv'
    $findingsParams = @{ Path = $folder; OutputPath = (Join-Path $folder 'findings.csv') }
    if (Test-Path $register) { $findingsParams.Merge = $register }
    $null = Export-PostureFindings @findingsParams

    # ---- 5. Upload the run, write the register back, prune.
    Write-Output 'step: upload'
    $runName = Split-Path $folder -Leaf
    foreach ($f in (Get-ChildItem -Path $folder -File)) { & $blobPut $postureContainer "$runName/$($f.Name)" $f.FullName }
    & $blobPut $clientContainer 'findings.csv' (Join-Path $folder 'findings.csv')
    Write-Output "uploaded run $runName ($((Get-ChildItem -Path $folder -File).Count) files)"
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
    $notify = Join-Path (Split-Path (Get-Module Tenantkeep.Posture).Path) 'schedules' 'ca-notifications.ps1'
    if ($emailTo.Count -gt 0 -and $emailFrom -and (Test-Path $notify)) {
        . $notify
        try { $null = Send-CaChangeEmail -To $emailTo -From $emailFrom -Subject "TenantKeep Posture: $runName" -HtmlBody "<p>$([System.Net.WebUtility]::HtmlEncode($summary))</p>" -AttachmentPath (Join-Path $folder 'report.html'); Write-Output 'emailed the report' } catch { Write-Output "Email failed: $($_.Exception.Message)" }
    }
    [pscustomobject]@{ Run = $runName; Score = $report.Report.score.value; Failing = $report.Report.counts.fail; Skipped = @($skipped.Keys); Container = $postureUrl }
}
catch {
    Write-Error "Runbook failed: $($_.Exception.Message)`nat $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())`n$($_.ScriptStackTrace)" -ErrorAction Continue
    throw
}
