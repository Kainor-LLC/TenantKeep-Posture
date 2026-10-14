#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Azure Automation runbook (PowerShell 7.4 runtime): nightly Conditional Access snapshot and diff with a managed identity.
.DESCRIPTION
    Deployed by deploy/automation/deploy.ps1 (Bicep in deploy/automation/main.bicep). The sandbox disk is wiped
    between jobs, so runs live in a blob container: the previous run is downloaded, the cycle runs on local disk,
    the new run is uploaded, and runs beyond TENANTKEEP_KEEP_RUNS are deleted from the container.

    Identity: the account's system-assigned managed identity, with Storage Blob Data Contributor on the storage
    account (Bicep) and the Graph application roles from Grant-ManagedIdentityGraphRole.ps1.

    Variables: TENANTKEEP_CONTAINER_URL, TENANTKEEP_KEEP_RUNS, TEAMS_WEBHOOK (encrypted), EMAIL_TO, EMAIL_FROM, BREAK_GLASS.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$getVar = { param([string] $Name) try { [string](Get-AutomationVariable -Name $Name) } catch { '' } }
$containerUrl = (& $getVar 'TENANTKEEP_CONTAINER_URL').Trim('"')
if (-not $containerUrl) { throw 'Automation variable TENANTKEEP_CONTAINER_URL is not set.' }
$keepRuns = [int]((& $getVar 'TENANTKEEP_KEEP_RUNS') -replace '[^0-9]', '0')
$webhook = (& $getVar 'TEAMS_WEBHOOK').Trim('"')
$emailTo = @(((& $getVar 'EMAIL_TO').Trim('"')) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$emailFrom = (& $getVar 'EMAIL_FROM').Trim('"')
$breakGlass = @(((& $getVar 'BREAK_GLASS').Trim('"')) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

$uri = [uri]$containerUrl
$accountName = $uri.Host.Split('.')[0]
$containerName = $uri.AbsolutePath.Trim('/')

$null = Connect-AzAccount -Identity
Connect-MgGraph -Identity -NoWelcome
Import-Module Tenantkeep.Posture
$storage = New-AzStorageContext -StorageAccountName $accountName -UseConnectedAccount

$work = Join-Path ([System.IO.Path]::GetTempPath()) 'tenantkeep-ca'
if (Test-Path $work) { Remove-Item -LiteralPath $work -Recurse -Force }
New-Item -ItemType Directory -Path $work -Force | Out-Null

# Previous run: the newest '<stamp>-ca/' prefix in the container.
$blobs = @(Get-AzStorageBlob -Container $containerName -Context $storage)
$runNames = @($blobs | ForEach-Object { ($_.Name -split '/')[0] } | Where-Object { $_ -match '^\d{8}-\d{4}-ca$' } | Sort-Object -Unique)
if ($runNames.Count -gt 0) {
    $latest = $runNames[-1]
    $target = Join-Path $work $latest
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    foreach ($b in ($blobs | Where-Object { $_.Name -like "$latest/*" })) {
        $null = Get-AzStorageBlobContent -Blob $b.Name -Container $containerName -Context $storage -Destination (Join-Path $target (Split-Path $b.Name -Leaf)) -Force
    }
    Write-Output "Downloaded previous run $latest"
}

$cycle = Join-Path (Split-Path (Get-Module Tenantkeep.Posture).Path) 'schedules' 'ca-snapshot-cycle.ps1'
if (-not (Test-Path $cycle)) { $cycle = Join-Path $PSScriptRoot 'ca-snapshot-cycle.ps1' }

$params = @{ OutRoot = $work; KeepRuns = 0 }
if ($webhook) { $params.TeamsWebhookUrl = $webhook }
if ($breakGlass.Count -gt 0) { $params.BreakGlass = $breakGlass }
if ($emailTo.Count -gt 0 -and $emailFrom) { $params.EmailTo = $emailTo; $params.EmailFrom = $emailFrom }

$result = $null
$failure = $null
try { $result = & $cycle @params }
catch { $failure = $_ }

# Upload whatever the cycle produced, even on failure, so the evidence survives.
foreach ($folder in (Get-ChildItem -Path $work -Directory | Where-Object { $_.Name -match '^\d{8}-\d{4}-ca$' -and $_.Name -notin $runNames })) {
    foreach ($f in (Get-ChildItem -Path $folder.FullName -File)) {
        $null = Set-AzStorageBlobContent -File $f.FullName -Container $containerName -Blob "$($folder.Name)/$($f.Name)" -Context $storage -Force
    }
    Write-Output "Uploaded run $($folder.Name)"
}

if ($keepRuns -gt 0) {
    $all = @($runNames) + @(Get-ChildItem -Path $work -Directory | Where-Object { $_.Name -match '^\d{8}-\d{4}-ca$' } | ForEach-Object { $_.Name }) | Sort-Object -Unique
    foreach ($old in ($all | Select-Object -First ([Math]::Max(0, $all.Count - $keepRuns)))) {
        foreach ($b in ($blobs | Where-Object { $_.Name -like "$old/*" })) { Remove-AzStorageBlob -Blob $b.Name -Container $containerName -Context $storage -Force }
        Write-Output "Pruned run $old"
    }
}

if ($failure) { throw $failure }
if ($result -and $result.HasRiskRelevantChanges) {
    throw "$($result.RiskRelevantCount) risk-relevant Conditional Access change(s). Report uploaded to $containerName/$(Split-Path $result.Snapshot -Leaf)/ca-changes.html"
}
$result
