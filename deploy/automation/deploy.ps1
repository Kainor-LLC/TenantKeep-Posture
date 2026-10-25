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
         account's PowerShell 7.4 runtime through a user-delegation SAS. Dev builds are unsigned; releases are signed.
      3. Import Microsoft.Graph.Authentication from the PowerShell Gallery into the same runtime.
      4. Upload automation-runbook.ps1 as the runbook content and publish it.
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
    # (verify) current Gallery versions at deployment time
    [string] $ExchangeOnlineManagementVersion = '3.9.0',
    [string] $PnPPowerShellVersion = '3.1.0',
    [string] $MicrosoftTeamsVersion = '7.3.1',

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
    $body = @{ properties = @{ contentLink = @{ uri = $sas } } } | ConvertTo-Json -Compress
    $null = Invoke-Az rest --method put --url "https://management.azure.com$aaPath/runtimeEnvironments/$runtimeEnv/packages/TenantKeep.Posture?api-version=$apiVersion" --body $body -o none
    Write-Host "Imported TenantKeep.Posture $version into runtime environment $runtimeEnv"

    # 3. Dependency from the Gallery
    $galleryUri = "https://www.powershellgallery.com/api/v2/package/Microsoft.Graph.Authentication/$GraphAuthenticationVersion"
    $body = @{ properties = @{ contentLink = @{ uri = $galleryUri } } } | ConvertTo-Json -Compress
    $null = Invoke-Az rest --method put --url "https://management.azure.com$aaPath/runtimeEnvironments/$runtimeEnv/packages/Microsoft.Graph.Authentication?api-version=$apiVersion" --body $body -o none
    Write-Host "Imported Microsoft.Graph.Authentication $GraphAuthenticationVersion"
    if ($IncludePosture) {
        # The collectors' session modules. Package imports run in the background; a job started before they finish fails to import them.
        # Az.ResourceGraph comes with the runtime's Az rollup; a separately imported newer version needs a newer Az.Accounts and breaks the import.
        foreach ($pkg in @(@('ExchangeOnlineManagement', $ExchangeOnlineManagementVersion), @('PnP.PowerShell', $PnPPowerShellVersion), @('MicrosoftTeams', $MicrosoftTeamsVersion))) {
            $body = @{ properties = @{ contentLink = @{ uri = "https://www.powershellgallery.com/api/v2/package/$($pkg[0])/$($pkg[1])" } } } | ConvertTo-Json -Compress
            $null = Invoke-Az rest --method put --url "https://management.azure.com$aaPath/runtimeEnvironments/$runtimeEnv/packages/$($pkg[0])?api-version=$apiVersion" --body $body -o none
            Write-Host "Imported $($pkg[0]) $($pkg[1])"
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

Write-Host ''
Write-Host 'Next, once, as a Global Administrator of the tenant:'
Write-Host "  Connect-MgGraph -TenantId $($account.tenantId) -Scopes AppRoleAssignment.ReadWrite.All, Application.Read.All"
Write-Host "  ./deploy/automation/Grant-ManagedIdentityGraphRole.ps1 -PrincipalId $($o.automationPrincipalId.value)$(if ($EmailTo) { ' -IncludeMailSend' })$(if ($IncludePosture) { ' -IncludePosture' })"
Write-Host "Then start a job: az automation runbook start -g $ResourceGroup --automation-account-name $automationAccount -n $runbookName"
if ($IncludePosture) {
    Write-Host "Purview (once): ./deploy/setup/New-PosturePurviewApp.ps1 -ResourceGroup $ResourceGroup -AutomationAccount $automationAccount -VaultName $($o.purviewVaultName.value)"
    Write-Host "Posture run: az automation runbook start -g $ResourceGroup --automation-account-name $automationAccount -n $postureRunbook   (after the Azure Reader roles and once the package imports show Available)"
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
