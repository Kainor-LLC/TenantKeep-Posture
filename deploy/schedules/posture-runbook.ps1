#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Azure Automation runbook (PowerShell 7.4 runtime): the monthly full posture cycle with the account's managed identity.
.DESCRIPTION
    Deployed by deploy/automation/deploy.ps1 -IncludePosture. One job does what an admin does by hand over an afternoon:
      1. sign in everywhere as the managed identity (Graph, Azure, Exchange, Purview, SharePoint, Teams), read-only roles
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
    TENANTKEEP_ORGANIZATION, TENANTKEEP_SHAREPOINT_ADMIN_URL, TEAMS_WEBHOOK, EMAIL_TO, EMAIL_FROM.
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
    $webhook = & $getVar 'TEAMS_WEBHOOK'
    $emailTo = @(((& $getVar 'EMAIL_TO')) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $emailFrom = & $getVar 'EMAIL_FROM'

    $accountName = ([uri]$postureUrl).Host.Split('.')[0]
    $postureContainer = ([uri]$postureUrl).AbsolutePath.Trim('/')
    $clientContainer = ([uri]$clientUrl).AbsolutePath.Trim('/')

    # ---- 1. Sign in everywhere. Each optional service is its own try: a missing role skips that collector, not the run.
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
    $try = {
        param([string] $Name, [scriptblock] $Connect)
        try { & $Connect; Write-Output "$Name session open" }
        catch { $skipped[$Name] = $_.Exception.Message; Write-Output "$Name sign-in failed; that collector is skipped: $($_.Exception.Message)" }
    }
    & $try 'Exchange' { Connect-ExchangeOnline -ManagedIdentity -Organization $organization -ShowBanner:$false }
    & $try 'Purview' { Connect-IPPSSession -ManagedIdentity -Organization $organization -ShowBanner:$false }   # (verify) app-only Purview support in the installed ExchangeOnlineManagement
    if ($spoAdmin) { & $try 'SharePoint' { Connect-PnPOnline -Url $spoAdmin -ManagedIdentity } } else { $skipped['SharePoint'] = 'TENANTKEEP_SHAREPOINT_ADMIN_URL not set' }
    & $try 'Teams' { Connect-MicrosoftTeams -Identity | Out-Null }

    Write-Output 'step: import module'
    Import-Module Tenantkeep.Posture
    Write-Output "module $((Get-Module Tenantkeep.Posture).Version) build: $(& (Get-Module Tenantkeep.Posture) { $script:PostureBuildState.detail })"
    $storage = New-AzStorageContext -StorageAccountName $accountName -UseConnectedAccount

    $work = Join-Path ([System.IO.Path]::GetTempPath()) 'tenantkeep-posture'
    if (Test-Path $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    $evidenceRoot = Join-Path $work 'evidence'; $client = Join-Path $work 'client'
    New-Item -ItemType Directory -Path $evidenceRoot, $client -Force | Out-Null

    # ---- 2. Client files (profile, brand, exceptions, licence, register, hybrid ad-* files).
    Write-Output 'step: download client container'
    $clientBlobs = @(Get-AzStorageBlob -Container $clientContainer -Context $storage -ErrorAction SilentlyContinue)
    foreach ($b in $clientBlobs) {
        $dest = Join-Path $client ($b.Name -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force | Out-Null
        $null = Get-AzStorageBlobContent -Blob $b.Name -Container $clientContainer -Context $storage -Destination $dest -Force
    }
    Write-Output "client files: $($clientBlobs.Count)"
    $profilePath = Join-Path $client 'profile.json'
    if (-not (Test-Path $profilePath)) { Write-Output 'No profile.json in the client container; the report uses discovery defaults. Upload one from New-PostureProfile for thresholds and third-party answers.' }

    # ---- 3. Previous run, for the trend and the register merge.
    Write-Output 'step: list previous runs'
    $blobs = @(Get-AzStorageBlob -Container $postureContainer -Context $storage -ErrorAction SilentlyContinue)
    $runNames = @($blobs | ForEach-Object { ($_.Name -split '/')[0] } | Where-Object { $_ -match '^\d{8}-\d{4}$' } | Sort-Object -Unique)
    $previous = $null
    if ($runNames.Count -gt 0) {
        $latest = $runNames[-1]; $previous = Join-Path $evidenceRoot $latest
        New-Item -ItemType Directory -Path $previous -Force | Out-Null
        foreach ($b in ($blobs | Where-Object { $_.Name -eq "$latest/checks.json" })) { $null = Get-AzStorageBlobContent -Blob $b.Name -Container $postureContainer -Context $storage -Destination (Join-Path $previous 'checks.json') -Force }
        Write-Output "previous run $latest"
    }

    # ---- 4. Collect, evaluate, report.
    Write-Output 'step: collect'
    $collectParams = @{ OutRoot = $evidenceRoot; PassThru = $true }
    if (Test-Path $profilePath) { $collectParams.ProfilePath = $profilePath }
    $collection = Invoke-PostureCollection @collectParams
    $folder = [string]$collection.Folder
    Write-Output "evidence $folder, errors $(@($collection.Errors).Count)"
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
    foreach ($f in (Get-ChildItem -Path $folder -File)) { $null = Set-AzStorageBlobContent -File $f.FullName -Container $postureContainer -Blob "$runName/$($f.Name)" -Context $storage -Force }
    $null = Set-AzStorageBlobContent -File (Join-Path $folder 'findings.csv') -Container $clientContainer -Blob 'findings.csv' -Context $storage -Force
    Write-Output "uploaded run $runName ($((Get-ChildItem -Path $folder -File).Count) files)"
    if ($keepRuns -gt 0) {
        $all = @(@($runNames) + @($runName) | Sort-Object -Unique)
        foreach ($old in ($all | Select-Object -First ([Math]::Max(0, $all.Count - $keepRuns)))) {
            foreach ($b in ($blobs | Where-Object { $_.Name -like "$old/*" })) { Remove-AzStorageBlob -Blob $b.Name -Container $postureContainer -Context $storage -Force }
            Write-Output "pruned run $old"
        }
    }

    # ---- 6. Tell someone, through the same opt-in channels as the CA cycle.
    $summary = "Tenantkeep Posture run $runName for ${organization}: score $($report.Report.score.value) ($($report.Report.score.grade)), $($report.Report.counts.fail) failing checks. Report: $postureContainer/$runName/report.html"
    if ($skipped.Count -gt 0) { $summary += ". Not collected: $(@($skipped.Keys) -join ', ')" }
    Write-Output $summary
    if ($webhook) {
        # A plain Adaptive Card to the customer's own Teams Workflows webhook (opt-in, same channel as the CA cycle).
        $card = @{ type = 'message'; attachments = @(@{ contentType = 'application/vnd.microsoft.card.adaptive'; content = @{ type = 'AdaptiveCard'; version = '1.4'; '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'; body = @(@{ type = 'TextBlock'; text = 'Tenantkeep Posture monthly run'; weight = 'Bolder'; size = 'Medium' }, @{ type = 'TextBlock'; text = $summary; wrap = $true }) } }) } | ConvertTo-Json -Depth 8
        try { Invoke-RestMethod -Uri $webhook -Method Post -ContentType 'application/json' -Body $card | Out-Null; Write-Output 'posted to Teams' } catch { Write-Output "Teams post failed: $($_.Exception.Message)" }
    }
    $notify = Join-Path (Split-Path (Get-Module Tenantkeep.Posture).Path) 'schedules' 'ca-notifications.ps1'
    if ($emailTo.Count -gt 0 -and $emailFrom -and (Test-Path $notify)) {
        . $notify
        try { $null = Send-CaChangeEmail -To $emailTo -From $emailFrom -Subject "Tenantkeep Posture: $runName" -HtmlBody "<p>$([System.Net.WebUtility]::HtmlEncode($summary))</p>" -AttachmentPath (Join-Path $folder 'report.html'); Write-Output 'emailed the report' } catch { Write-Output "Email failed: $($_.Exception.Message)" }
    }
    [pscustomobject]@{ Run = $runName; Score = $report.Report.score.value; Failing = $report.Report.counts.fail; Skipped = @($skipped.Keys); Container = $postureUrl }
}
catch {
    Write-Error "Runbook failed: $($_.Exception.Message)`nat $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())`n$($_.ScriptStackTrace)" -ErrorAction Continue
    throw
}
