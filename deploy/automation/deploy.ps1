#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Deploys the customer-hosted Conditional Access monitor: Bicep infrastructure, module upload, runbook content.
.DESCRIPTION
    Needs an Azure CLI session (az login) with Owner or Contributor plus User Access Administrator on the resource
    group, and the az automation extension. Steps:
      1. Resource group and Bicep deployment (main.bicep).
      2. Stage the module (./build.ps1 -Task Build), zip it, upload to the modules container, import it into the
         account's PowerShell 7.6 runtime through a user-delegation SAS. Dev builds are unsigned; releases are signed.
      3. Import Microsoft.Graph.Authentication from the PowerShell Gallery into the same runtime (and, with
         -IncludePosture, the collectors' modules).
      4. Upload automation-runbook.ps1 as the runbook content and publish it.
      5. Link the schedules.
      6. Wait for every package import to finish, retrying one that fails on Automation's side, and say when a job
         can start. Stops with an error if an import still fails or is still running after -ImportWaitMinutes.
    Then, once, a Global Administrator runs Grant-ManagedIdentityGraphRole.ps1 with the printed principal id.
.EXAMPLE
    ./deploy.ps1 -ResourceGroup rg-tenantkeep-dev -Location centralus -WhatIf
.EXAMPLE
    ./deploy.ps1 -ResourceGroup rg-tenantkeep-dev -Location centralus -EmailTo secops@kainor.com -EmailFrom ca-monitor@kainor.com
#>
[CmdletBinding(SupportsShouldProcess)]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Deployment script output is for the console.')]
param(
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [string] $Location = 'centralus',
    [string] $BaseName = 'tenantkeep',
    [ValidateSet('dev', 'test', 'prod')] [string] $EnvName = 'dev',
    [string] $ScheduleTimeUtc = '02:15',
    [int] $KeepRuns = 90,
    [string] $TeamsWebhookUrl,
    [string[]] $EmailTo,
    [string] $EmailFrom,
    [string[]] $BreakGlass,
    [string] $GraphAuthenticationVersion = '2.39.0',
    [switch] $SkipModuleImport,

    # Monthly full posture cycle (second runbook). Needs the collectors' modules in the runtime environment and the
    # posture roles from Grant-ManagedIdentityGraphRole.ps1 -IncludePosture.
    [switch] $IncludePosture,
    [string] $Organization,
    [string] $SharePointAdminUrl,
    [ValidateRange(1, 28)] [int] $PostureDayOfMonth = 1,
    [string] $PostureTimeUtc = '03:00',
    [int] $PostureKeepRuns = 24,
    [string] $ClientFolder,
    # The versions the module is tested with (Get-PostureRequirement)
    [string] $ExchangeOnlineManagementVersion = '3.10.1',
    [string] $PnPPowerShellVersion = '3.2.0',
    [string] $MicrosoftTeamsVersion = '7.9.0',
    # How long to wait for Automation to finish the package imports before giving up.
    [ValidateRange(1, 120)] [int] $ImportWaitMinutes = 20,

    # Sign the staged module's integrity manifest through Key Vault so the report reads "Signed release" instead of "Development build".
    [string] $IntegrityVaultName,
    [string] $IntegrityKeyName = 'kainor-2026-10'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path

function Invoke-Az {
    # Plain function on purpose: an advanced function would bind az flags such as -o and -g as its own parameters.
    $out = & az @args 2>&1
    if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed: $out" }
    return $out
}

$account = Invoke-Az account show -o json | ConvertFrom-Json
Write-Host "Subscription $($account.name) ($($account.id)), tenant $($account.tenantId), user $($account.user.name)"

# 1. Infrastructure
if ($PSCmdlet.ShouldProcess($ResourceGroup, "Create resource group in $Location")) {
    $null = Invoke-Az group create -n $ResourceGroup -l $Location -o none
}
$paramArgs = @("baseName=$BaseName", "envName=$EnvName", "scheduleTimeUtc=$ScheduleTimeUtc", "keepRuns=$KeepRuns",
    "emailTo=$(($EmailTo | ForEach-Object { $_ }) -join ',')", "emailFrom=$EmailFrom", "breakGlass=$(($BreakGlass | ForEach-Object { $_ }) -join ',')",
    "teamsWebhookUrl=$TeamsWebhookUrl",
    "includePosture=$($IncludePosture.IsPresent.ToString().ToLowerInvariant())", "postureDayOfMonth=$PostureDayOfMonth", "postureTimeUtc=$PostureTimeUtc", "postureKeepRuns=$PostureKeepRuns",
    "organization=$Organization", "sharePointAdminUrl=$SharePointAdminUrl")
$bicep = Join-Path $PSScriptRoot 'main.bicep'
if (-not $PSCmdlet.ShouldProcess($ResourceGroup, 'Deploy main.bicep')) {
    Invoke-Az deployment group what-if -g $ResourceGroup -f $bicep -p @paramArgs | Write-Host
    return
}
$deployment = Invoke-Az deployment group create -g $ResourceGroup -f $bicep -p @paramArgs -o json | ConvertFrom-Json
$o = $deployment.properties.outputs
$automationAccount = $o.automationAccountName.value
$storageAccount = $o.storageAccountName.value
$runbookName = $o.runbookName.value
$runtimeEnv = $o.runtimeEnvironmentName.value
Write-Host "Automation account $automationAccount, identity $($o.automationPrincipalId.value), storage $storageAccount, first run $($o.firstRunUtc.value)"

$subId = $account.id
$aaPath = "/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.Automation/automationAccounts/$automationAccount"
$apiVersion = '2023-05-15-preview'

# Package imports run in the background: the PUT returns at once and the import finishes, or fails, minutes later.
# Every import sent is recorded so step 6 can wait for it and send it again if Automation fails it.
$imports = [System.Collections.Generic.List[object]]::new()
$sendImport = {
    param([string] $Name, [string] $Version, [string] $Uri)
    $body = @{ properties = @{ contentLink = @{ uri = $Uri } } } | ConvertTo-Json -Compress
    $null = Invoke-Az rest --method put --url "https://management.azure.com$aaPath/runtimeEnvironments/$runtimeEnv/packages/$($Name)?api-version=$apiVersion" --body $body -o none
}
$queueImport = {
    param([string] $Name, [string] $Version, [string] $Uri)
    & $sendImport $Name $Version $Uri
    $imports.Add([pscustomobject]@{ Name = $Name; Version = $Version; Uri = $Uri; State = 'Importing'; Attempts = 1; Error = $null })
    Write-Host "Import sent: $Name $Version"
}

# 2. Module
if (-not $SkipModuleImport) {
    if ($IntegrityVaultName) { & (Join-Path $repo 'build.ps1') -Task Build, Integrity -VaultName $IntegrityVaultName -KeyName $IntegrityKeyName | Out-Null }
    else { & (Join-Path $repo 'build.ps1') -Task Build | Out-Null }
    $version = (Import-PowerShellDataFile (Join-Path $repo 'TenantKeep.Posture' 'TenantKeep.Posture.psd1')).ModuleVersion
    $staged = Join-Path $repo 'out' 'TenantKeep.Posture' $version
    $zip = Join-Path $repo 'out' "TenantKeep.Posture-$version-unsigned.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    # Automation expects the module folder at the zip root (module.psd1 directly inside).
    Compress-Archive -Path (Join-Path $staged '*') -DestinationPath $zip
    $blobName = "TenantKeep.Posture-$version-$((Get-Date).ToString('yyyyMMddHHmm')).zip"
    # The deployer's blob role comes from the same deployment; RBAC can take a minute or two to propagate.
    $attempt = 0
    while ($true) {
        try { $null = Invoke-Az storage blob upload --account-name $storageAccount --container-name modules --name $blobName --file $zip --auth-mode login --overwrite true -o none; break }
        catch { if (++$attempt -ge 8) { throw }; Write-Host "Waiting for blob data access to propagate ($attempt)"; Start-Sleep -Seconds 20 }
    }
    $expiry = (Get-Date).ToUniversalTime().AddHours(2).ToString('yyyy-MM-ddTHH:mmZ')
    $sas = (Invoke-Az storage blob generate-sas --account-name $storageAccount --container-name modules --name $blobName --permissions r --expiry $expiry --auth-mode login --as-user --full-uri -o tsv) | Select-Object -Last 1
    $sas = [string]$sas
    $sas = $sas.Trim('"')
    & $queueImport 'TenantKeep.Posture' $version $sas

    # 3. Dependency from the Gallery
    & $queueImport 'Microsoft.Graph.Authentication' $GraphAuthenticationVersion "https://www.powershellgallery.com/api/v2/package/Microsoft.Graph.Authentication/$GraphAuthenticationVersion"
    if ($IncludePosture) {
        # The collectors' session modules. A job started before they finish runs without them and skips those domains.
        # Az.ResourceGraph comes with the runtime's Az rollup; a separately imported newer version needs a newer Az.Accounts and breaks the import.
        foreach ($pkg in @(@('ExchangeOnlineManagement', $ExchangeOnlineManagementVersion), @('PnP.PowerShell', $PnPPowerShellVersion), @('MicrosoftTeams', $MicrosoftTeamsVersion))) {
            & $queueImport $pkg[0] $pkg[1] "https://www.powershellgallery.com/api/v2/package/$($pkg[0])/$($pkg[1])"
        }
    }
}

# 4. Runbook content
$runbookFile = Join-Path $repo 'deploy' 'schedules' 'automation-runbook.ps1'
$null = Invoke-Az automation runbook replace-content -g $ResourceGroup --automation-account-name $automationAccount -n $runbookName --content "@$runbookFile" -o none
$null = Invoke-Az automation runbook publish -g $ResourceGroup --automation-account-name $automationAccount -n $runbookName -o none
Write-Host "Published runbook $runbookName"
if ($IncludePosture) {
    $postureRunbook = $o.postureRunbookName.value
    $postureFile = Join-Path $repo 'deploy' 'schedules' 'posture-runbook.ps1'
    $null = Invoke-Az automation runbook replace-content -g $ResourceGroup --automation-account-name $automationAccount -n $postureRunbook --content "@$postureFile" -o none
    $null = Invoke-Az automation runbook publish -g $ResourceGroup --automation-account-name $automationAccount -n $postureRunbook -o none
    Write-Host "Published runbook $postureRunbook"
    if ($ClientFolder) {
        # profile.json, brand.json, exceptions.json, tenantkeep.lic, findings.csv; hybrid/ad-* for hybrid tenants.
        foreach ($f in (Get-ChildItem -Path $ClientFolder -File -Recurse | Where-Object { $_.Name -in 'profile.json', 'brand.json', 'exceptions.json', 'tenantkeep.lic', 'findings.csv' -or $_.Name -like 'ad-*' })) {
            $rel = $f.FullName.Substring((Resolve-Path $ClientFolder).Path.Length).TrimStart('/', '\') -replace '\\', '/'
            if ($f.Name -like 'ad-*' -and $rel -notlike 'hybrid/*') { $rel = "hybrid/$($f.Name)" }
            $null = Invoke-Az storage blob upload --account-name $storageAccount --container-name client --name $rel --file $f.FullName --auth-mode login --overwrite true -o none
            Write-Host "Uploaded client/$rel"
        }
    }
}

# 5. Link the schedule (only once the runbook has a published version, which is why it is not in Bicep).
$scheduleName = $o.scheduleName.value
$links = (Invoke-Az rest --method get --url "https://management.azure.com$aaPath/jobSchedules?api-version=2023-11-01" -o json | ConvertFrom-Json).value
$linked = $links | Where-Object { $_.properties.runbook.name -eq $runbookName -and $_.properties.schedule.name -eq $scheduleName }
if (-not $linked) {
    $linkId = [guid]::NewGuid().ToString()
    $body = @{ properties = @{ runbook = @{ name = $runbookName }; schedule = @{ name = $scheduleName } } } | ConvertTo-Json -Compress
    $null = Invoke-Az rest --method put --url "https://management.azure.com$aaPath/jobSchedules/$linkId`?api-version=2023-11-01" --body $body -o none
    Write-Host "Linked schedule $scheduleName to $runbookName"
}
else { Write-Host "Schedule $scheduleName already linked" }
if ($IncludePosture) {
    $postureSchedule = $o.postureScheduleName.value
    $plinked = $links | Where-Object { $_.properties.runbook.name -eq $postureRunbook -and $_.properties.schedule.name -eq $postureSchedule }
    if (-not $plinked) {
        $body = @{ properties = @{ runbook = @{ name = $postureRunbook }; schedule = @{ name = $postureSchedule } } } | ConvertTo-Json -Compress
        $null = Invoke-Az rest --method put --url "https://management.azure.com$aaPath/jobSchedules/$([guid]::NewGuid())`?api-version=2023-11-01" --body $body -o none
        Write-Host "Linked schedule $postureSchedule to $postureRunbook"
    }
    else { Write-Host "Schedule $postureSchedule already linked" }
}

# 6. Wait for the imports. Automation has failed a good import on its side (a 500 or a timeout while storing the content)
# and passed the same import on the next try, so a failed import is sent again, twice at most.
if ($imports.Count -gt 0) {
    Write-Host "Waiting for $($imports.Count) package import(s) in $runtimeEnv (up to $ImportWaitMinutes minutes)"
    $deadline = (Get-Date).AddMinutes($ImportWaitMinutes)
    while (@($imports | Where-Object State -EQ 'Importing').Count -gt 0 -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 20
        foreach ($p in @($imports | Where-Object State -EQ 'Importing')) {
            $pkg = Invoke-Az rest --method get --url "https://management.azure.com$aaPath/runtimeEnvironments/$runtimeEnv/packages/$($p.Name)?api-version=$apiVersion" -o json | ConvertFrom-Json
            $state = [string]$pkg.properties.provisioningState
            if ($state -eq 'Succeeded') { $p.State = 'Succeeded'; Write-Host "  $($p.Name) $($p.Version): imported" }
            elseif ($state -eq 'Failed') {
                $reason = (([string]$pkg.properties.error.message) -split '\r?\n|   at ')[0]
                if ($p.Attempts -lt 3) {
                    Write-Host "  $($p.Name) $($p.Version): failed on Automation's side, sending it again ($($p.Attempts) of 2): $reason"
                    $p.Attempts++
                    & $sendImport $p.Name $p.Version $p.Uri
                }
                else { $p.State = 'Failed'; $p.Error = $reason }
            }
        }
    }
    foreach ($p in @($imports | Where-Object State -EQ 'Importing')) { $p.State = 'Still importing' }
    Write-Host ''
    foreach ($p in $imports) { Write-Host ('  {0,-32} {1,-10} {2}{3}' -f $p.Name, $p.Version, $p.State, $(if ($p.Error) { ": $($p.Error)" })) }
}
$notReady = @($imports | Where-Object State -NE 'Succeeded')

Write-Host ''
Write-Host 'Next, once, as a Global Administrator of the tenant:'
Write-Host "  Connect-MgGraph -TenantId $($account.tenantId) -Scopes AppRoleAssignment.ReadWrite.All, Application.Read.All"
Write-Host "  ./deploy/automation/Grant-ManagedIdentityGraphRole.ps1 -PrincipalId $($o.automationPrincipalId.value)$(if ($EmailTo) { ' -IncludeMailSend' })$(if ($IncludePosture) { ' -IncludePosture' })"
$after = $(if ($notReady) { ' (once the imports above show Succeeded)' } else { '' })
Write-Host "Then start a job$($after): az automation runbook start -g $ResourceGroup --automation-account-name $automationAccount -n $runbookName"
if ($IncludePosture) {
    Write-Host "Purview (once): ./deploy/setup/New-PosturePurviewApp.ps1 -ResourceGroup $ResourceGroup -AutomationAccount $automationAccount -VaultName $($o.purviewVaultName.value)"
    Write-Host "Posture run$($after): az automation runbook start -g $ResourceGroup --automation-account-name $automationAccount -n $postureRunbook   (after the Azure Reader roles)"
}
if ($notReady) {
    Write-Host ''
    Write-Host 'To send an import again:'
    foreach ($p in $notReady) {
        # The module's own link is a user-delegation SAS; it is not printed. Rerunning the script uploads and imports it again.
        if ($p.Name -eq 'TenantKeep.Posture') { Write-Host '  TenantKeep.Posture: run this script again with the same parameters'; continue }
        $body = (@{ properties = @{ contentLink = @{ uri = $p.Uri } } } | ConvertTo-Json -Compress) -replace "'", "''"
        Write-Host "  az rest --method put --url `"https://management.azure.com$aaPath/runtimeEnvironments/$runtimeEnv/packages/$($p.Name)?api-version=$apiVersion`" --body '$body' -o none"
    }
}

[pscustomobject]@{
    ResourceGroup     = $ResourceGroup
    AutomationAccount = $automationAccount
    PrincipalId       = $o.automationPrincipalId.value
    StorageAccount    = $storageAccount
    ContainerUrl      = $o.containerUrl.value
    Runbook           = $runbookName
    FirstRunUtc       = $o.firstRunUtc.value
}
if ($notReady) { throw "Package import not finished in ${runtimeEnv}: $(($notReady | ForEach-Object { "$($_.Name) ($($_.State))" }) -join ', '). Everything else is deployed." }
