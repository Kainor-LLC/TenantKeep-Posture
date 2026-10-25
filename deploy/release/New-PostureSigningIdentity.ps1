#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    One-time Kainor-side setup for release signing: the Entra app the sign-release workflow signs in as through
    OpenID Connect, its two role assignments, and the GitHub variables, secrets and environment the workflow reads.
.DESCRIPTION
    Releases are Authenticode-signed through Azure Artifact Signing (formerly Trusted Signing): Microsoft issues and
    holds the certificate, and the workflow gets a short-lived token for it. Nothing here produces a secret. The app
    registration has no credential at all; a federated credential trusts GitHub's token for this repository's
    "release" environment, and the environment requires a maintainer's approval before any run starts.

    Before running this: create the Artifact Signing account and its certificate profile in the Azure portal and
    complete identity validation for Kainor LLC (portal only, 1 to 20 business days). The licence signing key must
    already exist in its Key Vault. Then: az login to the Kainor tenant, gh auth login as a repository admin, and
    run this script. It is idempotent; run it again after rotating anything.

    Role assignments made, both least privilege: Artifact Signing Certificate Profile Signer on the signing account,
    and Key Vault Crypto User on the one licence key (sign and verify, never export).
.PARAMETER SigningAccount
    The Artifact Signing account name.
.PARAMETER SigningResourceGroup
    Its resource group.
.PARAMETER CertificateProfile
    The certificate profile name inside the account (Public Trust).
.PARAMETER Endpoint
    The regional signing endpoint, for example https://eus.codesigning.azure.net/ (the account's region).
.PARAMETER VaultName
    The Key Vault holding the licence signing key.
.PARAMETER KeyName
    The licence signing key (build.ps1 -LicenseKeyId).
.PARAMETER Repository
    The GitHub repository, owner/name.
.PARAMETER AppName
    Display name of the app registration.
.EXAMPLE
    az login --tenant <Kainor tenant id>
    ./deploy/release/New-PostureSigningIdentity.ps1 -SigningAccount as-kainor -SigningResourceGroup rg-tenantkeep-dev -CertificateProfile tenantkeep-public -Endpoint https://eus.codesigning.azure.net/ -VaultName <vault> -KeyName kainor-2026-10
#>
[CmdletBinding(SupportsShouldProcess)]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'One-time admin script output is for the console.')]
param(
    [Parameter(Mandatory)] [string] $SigningAccount,
    [Parameter(Mandatory)] [string] $SigningResourceGroup,
    [Parameter(Mandatory)] [string] $CertificateProfile,
    [Parameter(Mandatory)] [ValidatePattern('^https://[a-z]+\.codesigning\.azure\.net/?$')] [string] $Endpoint,
    [Parameter(Mandatory)] [string] $VaultName,
    [Parameter(Mandatory)] [string] $KeyName,
    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')] [string] $Repository = 'Kainor-LLC/tenantkeep-posture',
    [string] $Environment = 'release',
    [string] $AppName = 'TenantKeep Posture release signing'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Az {
    param([Parameter(Mandatory)] [string[]] $Arguments)
    $out = & az @Arguments --output json 2>&1
    if ($LASTEXITCODE -ne 0) { throw "az $($Arguments[0..1] -join ' ') failed: $out" }
    if ($out) { $out | ConvertFrom-Json -AsHashtable -Depth 20 } else { $null }
}

foreach ($tool in 'az', 'gh') { if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool is not installed." } }
$account = Invoke-Az @('account', 'show')
$tenantId = [string]$account['tenantId']; $subscriptionId = [string]$account['id']
Write-Host "Azure: tenant $tenantId, subscription $($account['name'])"

# 1. The signing account and the vault key, as scopes.
$signing = Invoke-Az @('resource', 'show', '--resource-group', $SigningResourceGroup, '--name', $SigningAccount, '--resource-type', 'Microsoft.CodeSigning/codeSigningAccounts')   # (verify) the provider type name
$signingId = [string]$signing['id']
$vault = Invoke-Az @('keyvault', 'show', '--name', $VaultName)
$keyScope = "$($vault['id'])/keys/$KeyName"
$null = Invoke-Az @('keyvault', 'key', 'show', '--vault-name', $VaultName, '--name', $KeyName)
Write-Host "Signing account: $signingId"
Write-Host "Licence key:     $keyScope"

# 2. The app registration: no credential, one federated credential for the release environment.
$apps = @(Invoke-Az @('ad', 'app', 'list', '--display-name', $AppName))
if ($apps.Count -gt 0) { $app = $apps[0]; Write-Host "App exists: $($app['appId'])" }
elseif ($PSCmdlet.ShouldProcess($AppName, 'Create the app registration')) { $app = Invoke-Az @('ad', 'app', 'create', '--display-name', $AppName, '--sign-in-audience', 'AzureADMyOrg'); Write-Host "App created: $($app['appId'])" }
else { return }
$appId = [string]$app['appId']; $appObjectId = [string]$app['id']
$sps = @(Invoke-Az @('ad', 'sp', 'list', '--filter', "appId eq '$appId'"))
$sp = $(if ($sps.Count -gt 0) { $sps[0] } else { Invoke-Az @('ad', 'sp', 'create', '--id', $appId) })
$spObjectId = [string]$sp['id']

$subject = "repo:$($Repository):environment:$Environment"
$creds = @(Invoke-Az @('ad', 'app', 'federated-credential', 'list', '--id', $appObjectId))
if (-not ($creds | Where-Object { $_['subject'] -eq $subject })) {
    $body = @{ name = 'github-release-environment'; issuer = 'https://token.actions.githubusercontent.com'; subject = $subject; audiences = @('api://AzureADTokenExchange'); description = "GitHub Actions, $Repository, environment $Environment" } | ConvertTo-Json -Compress
    $tmp = New-TemporaryFile
    try { Set-Content -LiteralPath $tmp -Value $body -NoNewline; $null = Invoke-Az @('ad', 'app', 'federated-credential', 'create', '--id', $appObjectId, '--parameters', "@$tmp") }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    Write-Host "Federated credential added for $subject"
}
else { Write-Host "Federated credential exists for $subject" }

# 3. Least-privilege roles.
foreach ($pair in @(@('Artifact Signing Certificate Profile Signer', $signingId), @('Key Vault Crypto User', $keyScope))) {
    $role, $scope = $pair
    $have = @(Invoke-Az @('role', 'assignment', 'list', '--assignee', $spObjectId, '--role', $role, '--scope', $scope))
    if ($have.Count -gt 0) { Write-Host "Role exists: $role"; continue }
    $null = Invoke-Az @('role', 'assignment', 'create', '--assignee-object-id', $spObjectId, '--assignee-principal-type', 'ServicePrincipal', '--role', $role, '--scope', $scope)
    Write-Host "Role assigned: $role"
}

# 4. GitHub: the environment with a required reviewer, the variables the workflow reads, the two masked names.
$me = gh api user --jq '.id' 2>&1
if ($LASTEXITCODE -ne 0) { throw "gh api user failed: $me" }
$envBody = @{ reviewers = @(@{ type = 'User'; id = [int]$me }); deployment_branch_policy = $null } | ConvertTo-Json -Compress -Depth 5
$envBody | gh api -X PUT "repos/$Repository/environments/$Environment" --input - --silent
if ($LASTEXITCODE -ne 0) { throw "Creating the $Environment environment failed." }
Write-Host "Environment $Environment requires your approval on every run"
$variables = [ordered]@{ AZURE_CLIENT_ID = $appId; AZURE_TENANT_ID = $tenantId; AZURE_SUBSCRIPTION_ID = $subscriptionId; SIGNING_ENDPOINT = $Endpoint; SIGNING_ACCOUNT = $SigningAccount; SIGNING_PROFILE = $CertificateProfile }
foreach ($name in $variables.Keys) { gh variable set $name --repo $Repository --body $variables[$name]; if ($LASTEXITCODE -ne 0) { throw "gh variable set $name failed." } }
# The vault and key names are not secrets, but a public repository's logs are public; secrets are masked there.
foreach ($pair in @(@('LICENCE_VAULT', $VaultName), @('LICENCE_KEY', $KeyName))) { gh secret set $pair[0] --repo $Repository --body $pair[1]; if ($LASTEXITCODE -ne 0) { throw "gh secret set $($pair[0]) failed." } }
Write-Host "GitHub variables and secrets set on $Repository"
Write-Host "`nNext: Actions > Sign release > Run workflow with the tag, approve the run, then publish the draft release."
