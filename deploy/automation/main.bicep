// Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
// Customer-hosted nightly Conditional Access monitoring (spec 5.4 / 11 option B) and, with includePosture, the monthly
// full posture cycle: every collector with the managed identity, the report, the findings register, the trend.
// Automation account with a system-assigned identity, a storage account for snapshots (RBAC only, no shared keys),
// the variables the runbook reads, the daily schedule, and the runbook shell. Runbook content and the module are
// uploaded by deploy.ps1 because ARM cannot carry inline runbook content.
targetScope = 'resourceGroup'

@description('Short name used in resource names. Lowercase letters and digits.')
@minLength(3)
@maxLength(12)
param baseName string = 'tenantkeep'

@description('Environment suffix: dev, test, prod.')
@allowed(['dev', 'test', 'prod'])
param envName string = 'dev'

param location string = resourceGroup().location

@description('Daily run time, UTC, HH:mm.')
param scheduleTimeUtc string = '02:15'

@description('Runs to keep in the container. 0 keeps everything.')
param keepRuns int = 90

@description('Teams Workflows webhook URL. Empty disables Teams.')
@secure()
param teamsWebhookUrl string = ''

@description('Comma-separated recipients. Empty disables email.')
param emailTo string = ''

@description('Sender mailbox for Graph sendMail. The identity needs Mail.Send restricted to this mailbox.')
param emailFrom string = ''

@description('Comma-separated break-glass UPNs. Empty uses the name heuristic.')
param breakGlass string = ''

@description('Also deploy the monthly full posture cycle (second runbook, schedule, containers, variables).')
param includePosture bool = false

@description('Day of month for the posture run, 1 to 28.')
@minValue(1)
@maxValue(28)
param postureDayOfMonth int = 1

@description('Posture run time, UTC, HH:mm.')
param postureTimeUtc string = '03:00'

@description('Posture runs to keep in the container. 0 keeps everything.')
param postureKeepRuns int = 24

@description('The tenant initial domain, for app-only Exchange and Purview sign-in: contoso.onmicrosoft.com.')
param organization string = ''

@description('SharePoint admin site URL, for app-only PnP sign-in: https://contoso-admin.sharepoint.com.')
param sharePointAdminUrl string = ''

param tags object = {
  product: 'Tenantkeep Posture'
  component: 'ca-monitor'
}

param now string = utcNow('yyyy-MM-dd')

@description('Object id of whoever runs the deployment; gets blob data access so deploy.ps1 can upload the module. Empty skips it.')
param deployerObjectId string = deployer().objectId

var suffix = toLower(uniqueString(resourceGroup().id, baseName, envName))
var storageName = toLower('st${take(baseName, 8)}${take(suffix, 10)}')
var automationName = 'aa-${baseName}-${envName}'
var containerName = 'ca-snapshots'
var blobEndpoint = 'https://${storageName}.blob.${environment().suffixes.storage}/'
var runbookName = 'Invoke-CaSnapshotCycle'
var runtimeEnvironmentName = 'tenantkeep-ps74'
var scheduleName = 'ca-snapshot-nightly'
var postureRunbookName = 'Invoke-PostureCycle'
var postureScheduleName = 'posture-monthly'
var postureContainerName = 'posture-runs'
var clientContainerName = 'client'
var postureDay = postureDayOfMonth < 10 ? '0${postureDayOfMonth}' : '${postureDayOfMonth}'
var postureFirstRun = dateTimeAdd('${take(now, 7)}-${postureDay}T${postureTimeUtc}:00Z', 'P1M')
var purviewVaultName = toLower('kv-${take(baseName, 6)}-${take(suffix, 8)}')
var keyVaultSecretsUser = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
var firstRun = dateTimeAdd('${now}T${scheduleTimeUtc}:00Z', 'P1D')
var blobDataContributor = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    supportsHttpsTrafficOnly: true
    accessTier: 'Hot'
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    deleteRetentionPolicy: { enabled: true, days: 30 }
  }
}

resource snapshots 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: containerName
  properties: { publicAccess: 'None' }
}

resource modules 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'modules'
  properties: { publicAccess: 'None' }
}

// Posture: one container for runs (evidence, report, findings), one the customer fills with profile.json, brand.json,
// exceptions.json, tenantkeep.lic and, for hybrid tenants, the ad-* files from the Windows collector.
resource postureRuns 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = if (includePosture) {
  parent: blobService
  name: postureContainerName
  properties: { publicAccess: 'None' }
}
resource clientFiles 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = if (includePosture) {
  parent: blobService
  name: clientContainerName
  properties: { publicAccess: 'None' }
}

resource automation 'Microsoft.Automation/automationAccounts@2023-11-01' = {
  name: automationName
  location: location
  tags: tags
  identity: { type: 'SystemAssigned' }
  properties: {
    sku: { name: 'Basic' }
    publicNetworkAccess: true
    disableLocalAuth: true
  }
}

resource blobRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, automation.id, blobDataContributor)
  scope: storage
  properties: {
    roleDefinitionId: blobDataContributor
    principalId: automation.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource deployerBlobRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(deployerObjectId)) {
  name: guid(storage.id, deployerObjectId, blobDataContributor)
  scope: storage
  properties: {
    roleDefinitionId: blobDataContributor
    principalId: deployerObjectId
  }
}

var variables = [
  { name: 'TENANTKEEP_CONTAINER_URL', value: '"${blobEndpoint}${containerName}"', encrypted: false }
  { name: 'TENANTKEEP_KEEP_RUNS', value: string(keepRuns), encrypted: false }
  { name: 'TEAMS_WEBHOOK', value: '"${teamsWebhookUrl}"', encrypted: true }
  { name: 'EMAIL_TO', value: '"${emailTo}"', encrypted: false }
  { name: 'EMAIL_FROM', value: '"${emailFrom}"', encrypted: false }
  { name: 'BREAK_GLASS', value: '"${breakGlass}"', encrypted: false }
  { name: 'TENANTKEEP_POSTURE_CONTAINER_URL', value: '"${blobEndpoint}${postureContainerName}"', encrypted: false }
  { name: 'TENANTKEEP_CLIENT_CONTAINER_URL', value: '"${blobEndpoint}${clientContainerName}"', encrypted: false }
  { name: 'TENANTKEEP_POSTURE_KEEP_RUNS', value: string(postureKeepRuns), encrypted: false }
  { name: 'TENANTKEEP_ORGANIZATION', value: '"${organization}"', encrypted: false }
  { name: 'TENANTKEEP_SHAREPOINT_ADMIN_URL', value: '"${sharePointAdminUrl}"', encrypted: false }
]

resource automationVariables 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = [for v in variables: {
  parent: automation
  name: v.name
  properties: {
    value: v.value
    isEncrypted: v.encrypted
  }
}]

// System runtime environments stop at PowerShell 7.2; the module needs 7.4, so the account gets its own.
resource runtimeEnvironment 'Microsoft.Automation/automationAccounts/runtimeEnvironments@2023-05-15-preview' = {
  parent: automation
  name: runtimeEnvironmentName
  location: location
  properties: {
    runtime: { language: 'PowerShell', version: '7.4' }
    defaultPackages: { az: '12.3.0' } // (verify) Az version offered for 7.4 runtimes
    description: 'PowerShell 7.4 with Az, for Tenantkeep Posture'
  }
}

resource runbook 'Microsoft.Automation/automationAccounts/runbooks@2023-05-15-preview' = {
  parent: automation
  name: runbookName
  location: location
  tags: tags
  properties: {
    runbookType: 'PowerShell'
    runtimeEnvironment: runtimeEnvironment.name
    logProgress: false
    logVerbose: false
    description: 'Nightly Conditional Access snapshot, document, diff and notify. Content uploaded by deploy.ps1.'
  }
}

resource schedule 'Microsoft.Automation/automationAccounts/schedules@2023-11-01' = {
  parent: automation
  name: scheduleName
  properties: {
    frequency: 'Day'
    interval: 1
    startTime: firstRun
    timeZone: 'Etc/UTC'
    description: 'Daily at ${scheduleTimeUtc} UTC'
  }
}

// Purview has no managed identity sign-in (CLAUDE.md carve-out, decided 2026-10-15): the customer's setup script
// (deploy/setup/New-PosturePurviewApp.ps1) puts a certificate in this vault and registers the app; the identity reads
// the certificate at run time. The vault is the customer's; nothing in it is ever in code, config or the repo.
resource purviewVault 'Microsoft.KeyVault/vaults@2023-07-01' = if (includePosture) {
  name: purviewVaultName
  location: location
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    publicNetworkAccess: 'Enabled'
  }
}
resource purviewVaultSecretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (includePosture) {
  name: guid(purviewVaultName, automation.id, keyVaultSecretsUser)
  scope: purviewVault
  properties: {
    roleDefinitionId: keyVaultSecretsUser
    principalId: automation.identity.principalId
    principalType: 'ServicePrincipal'
  }
}
// The deployer administers the certificate (create, renew) through the setup script.
resource purviewVaultDeployer 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (includePosture && !empty(deployerObjectId)) {
  name: guid(purviewVaultName, deployerObjectId, 'certificates-officer')
  scope: purviewVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'a4417e6f-fecd-4de8-b567-7b0420556985')
    principalId: deployerObjectId
  }
}

resource postureRunbook 'Microsoft.Automation/automationAccounts/runbooks@2023-05-15-preview' = if (includePosture) {
  parent: automation
  name: postureRunbookName
  location: location
  tags: tags
  properties: {
    runbookType: 'PowerShell'
    runtimeEnvironment: runtimeEnvironment.name
    logProgress: false
    logVerbose: false
    description: 'Monthly full posture cycle: every collector with the managed identity, report, findings register, trend. Content uploaded by deploy.ps1.'
  }
}

resource postureSchedule 'Microsoft.Automation/automationAccounts/schedules@2023-11-01' = if (includePosture) {
  parent: automation
  name: postureScheduleName
  properties: {
    frequency: 'Month'
    interval: 1
    startTime: postureFirstRun
    timeZone: 'Etc/UTC'
    description: 'Monthly on day ${postureDayOfMonth} at ${postureTimeUtc} UTC'
  }
}

// The schedules are linked to the runbooks by deploy.ps1 after the content is published; ARM refuses to link an
// unpublished runbook.

output automationAccountName string = automation.name
output automationPrincipalId string = automation.identity.principalId
output storageAccountName string = storage.name
output containerUrl string = '${blobEndpoint}${containerName}'
output modulesContainerUrl string = '${blobEndpoint}modules'
output runbookName string = runbook.name
output scheduleName string = schedule.name
output runtimeEnvironmentName string = runtimeEnvironment.name
output firstRunUtc string = firstRun
output includePosture bool = includePosture
output postureRunbookName string = includePosture ? postureRunbookName : ''
output postureScheduleName string = includePosture ? postureScheduleName : ''
output postureContainerUrl string = includePosture ? '${blobEndpoint}${postureContainerName}' : ''
output clientContainerUrl string = includePosture ? '${blobEndpoint}${clientContainerName}' : ''
output purviewVaultName string = includePosture ? purviewVaultName : ''
