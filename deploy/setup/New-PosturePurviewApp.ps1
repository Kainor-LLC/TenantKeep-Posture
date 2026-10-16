#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    One-time customer-side setup for Purview in the scheduled posture run: a certificate in the customer's Key Vault,
    an app registration that trusts it, the Exchange.ManageAsApp consent, the Global Reader role, and the two Automation
    variables the runbook reads. Run once by a Global Administrator with Owner on the deployment's resource group.
.DESCRIPTION
    Why this exists: ExchangeOnlineManagement signs in to Purview (Connect-IPPSSession) app-only with a certificate
    only; there is no managed identity option. This is the one carve-out from "delegated or managed identity only"
    (CLAUDE.md, docs/architecture.md). The certificate is generated inside the Key Vault the deployment created, its
    public half goes on the app registration, and the Automation identity (Key Vault Secrets User) reads it at run
    time. It is never written to disk here, never in code or config, and the customer can revoke it by deleting the
    certificate or the app.

    Everything runs through the Azure CLI: az login to the customer's tenant and subscription first.
.PARAMETER ResourceGroup
    The Automation deployment's resource group.
.PARAMETER AutomationAccount
    The Automation account name (aa-<baseName>-<env>).
.PARAMETER VaultName
    The vault the deployment created (purviewVaultName output).
.PARAMETER ValidityMonths
    Certificate validity. Renew by running this script again before it expires; the runbook always reads the current version.
.EXAMPLE
    az login --tenant <tenant id>
    ./deploy/setup/New-PosturePurviewApp.ps1 -ResourceGroup rg-tenantkeep-dev -AutomationAccount aa-tenantkeep-dev -VaultName kv-tenant-abcd1234
#>
[CmdletBinding(SupportsShouldProcess)]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'One-time admin script output is for the console.')]
param(
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [Parameter(Mandatory)] [string] $AutomationAccount,
    [Parameter(Mandatory)] [string] $VaultName,
    [string] $AppName = 'Tenantkeep Posture (Purview)',
    [string] $CertificateName = 'tenantkeep-purview',
    [ValidateRange(3, 36)] [int] $ValidityMonths = 24
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Az { $out = & az @args 2>&1; if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed: $out" }; return $out }
$graph = 'https://graph.microsoft.com/v1.0'
function Get-G([string] $Url) { Invoke-Az rest --method get --url $Url -o json | ConvertFrom-Json }
function Send-GraphPost([string] $Url, $Body) { Invoke-Az rest --method post --url $Url --headers 'Content-Type=application/json' --body ($Body | ConvertTo-Json -Depth 8 -Compress) -o json | ConvertFrom-Json }
function Send-GraphPatch([string] $Url, $Body) { Invoke-Az rest --method patch --url $Url --headers 'Content-Type=application/json' --body ($Body | ConvertTo-Json -Depth 8 -Compress) -o none }

$account = Invoke-Az account show -o json | ConvertFrom-Json
Write-Host "Tenant $($account.tenantId), subscription $($account.name), user $($account.user.name)"

# 1. Certificate, generated inside the vault (the private key is born there and read only by the Automation identity).
$existingCert = $null
try { $existingCert = Invoke-Az keyvault certificate show --vault-name $VaultName -n $CertificateName -o json 2>$null | ConvertFrom-Json } catch { $existingCert = $null }
$renew = $existingCert -and ([datetime]$existingCert.attributes.expires) -lt (Get-Date).AddMonths(3)
if (-not $existingCert -or $renew) {
    if ($PSCmdlet.ShouldProcess($VaultName, "$(if ($renew) { 'Renew' } else { 'Create' }) certificate $CertificateName ($ValidityMonths months)")) {
        $policy = @{
            issuerParameters = @{ name = 'Self' }
            keyProperties = @{ exportable = $true; keySize = 2048; keyType = 'RSA'; reuseKey = $false }
            secretProperties = @{ contentType = 'application/x-pkcs12' }
            x509CertificateProperties = @{ subject = "CN=$CertificateName"; validityInMonths = $ValidityMonths; keyUsage = @('digitalSignature', 'keyEncipherment') }
            lifetimeActions = @(@{ trigger = @{ daysBeforeExpiry = 30 }; action = @{ actionType = 'AutoRenew' } })
        } | ConvertTo-Json -Depth 6 -Compress
        $null = Invoke-Az keyvault certificate create --vault-name $VaultName -n $CertificateName -p $policy -o none
        for ($i = 0; $i -lt 30; $i++) { Start-Sleep -Seconds 5; $existingCert = Invoke-Az keyvault certificate show --vault-name $VaultName -n $CertificateName -o json | ConvertFrom-Json; if ($existingCert.cer) { break } }
        Write-Host "Certificate $CertificateName ready, expires $($existingCert.attributes.expires)"
    }
}
else { Write-Host "Certificate $CertificateName exists, expires $($existingCert.attributes.expires)" }
$cerBase64 = [string]$existingCert.cer
$thumbprint = [string]$existingCert.x509ThumbprintHex

# 2. App registration that trusts the certificate; Exchange.ManageAsApp requested.
$exoSp = (Get-G "$graph/servicePrincipals?`$filter=appId eq '00000002-0000-0ff1-ce00-000000000000'&`$select=id,appRoles").value[0]
$manageAsApp = @($exoSp.appRoles | Where-Object { $_.value -eq 'Exchange.ManageAsApp' -and $_.allowedMemberTypes -contains 'Application' })[0]
if (-not $manageAsApp) { throw 'Office 365 Exchange Online exposes no Exchange.ManageAsApp application role in this tenant.' }
$apps = @((Get-G "$graph/applications?`$filter=displayName eq '$($AppName -replace "'", "''")'&`$select=id,appId,keyCredentials").value)
$keyCredential = @{ type = 'AsymmetricX509Cert'; usage = 'Verify'; key = $cerBase64; displayName = "$CertificateName $thumbprint" }
if ($apps.Count -eq 0) {
    if ($PSCmdlet.ShouldProcess($AppName, 'Create the app registration')) {
        $app = Post-G "$graph/applications" @{ displayName = $AppName; signInAudience = 'AzureADMyOrg'; keyCredentials = @($keyCredential); requiredResourceAccess = @(@{ resourceAppId = '00000002-0000-0ff1-ce00-000000000000'; resourceAccess = @(@{ id = $manageAsApp.id; type = 'Role' }) }); notes = 'Tenantkeep Posture: app-only Purview reads for the scheduled posture run. Certificate in Key Vault; read-only use. Safe to delete to revoke.' }
        Write-Host "App registration created: $($app.appId)"
    }
}
else {
    $app = $apps[0]
    $have = @($app.keyCredentials | Where-Object { [string]$_.customKeyIdentifier -and ([Convert]::ToHexString([Convert]::FromBase64String([string]$_.customKeyIdentifier)) -eq $thumbprint) })
    if ($have.Count -eq 0 -and $PSCmdlet.ShouldProcess($AppName, 'Add the current certificate to the app registration')) {
        Patch-G "$graph/applications/$($app.id)" @{ keyCredentials = @(@($app.keyCredentials | ForEach-Object { @{ type = $_.type; usage = $_.usage; key = $_.key; keyId = $_.keyId; displayName = $_.displayName } }) + @($keyCredential)) }
        Write-Host 'Certificate added to the app registration'
    }
    else { Write-Host "App registration exists: $($app.appId)" }
}
$sps = @((Get-G "$graph/servicePrincipals?`$filter=appId eq '$($app.appId)'&`$select=id").value)
$sp = $(if ($sps.Count -gt 0) { $sps[0] } elseif ($PSCmdlet.ShouldProcess($AppName, 'Create the service principal')) { Post-G "$graph/servicePrincipals" @{ appId = $app.appId } })

# 3. Consent: Exchange.ManageAsApp on the service principal.
$assigned = @((Get-G "$graph/servicePrincipals/$($sp.id)/appRoleAssignments").value | Where-Object { $_.appRoleId -eq $manageAsApp.id })
if ($assigned.Count -eq 0 -and $PSCmdlet.ShouldProcess($AppName, 'Grant Exchange.ManageAsApp')) {
    $null = Post-G "$graph/servicePrincipals/$($sp.id)/appRoleAssignments" @{ principalId = $sp.id; resourceId = $exoSp.id; appRoleId = $manageAsApp.id }
    Write-Host 'Exchange.ManageAsApp granted'
}
else { Write-Host 'Exchange.ManageAsApp already granted' }

# 4. Global Reader on the service principal: the directory role Purview app-only reads map to (verify: if Purview cmdlets
#    refuse reads with Global Reader, Compliance Administrator is the documented alternative and a write role; prefer not).
$readerTemplate = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451'
$defs = @((Get-G "$graph/roleManagement/directory/roleDefinitions?`$filter=templateId eq '$readerTemplate'&`$select=id").value)
$haveRole = @((Get-G "$graph/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($sp.id)'").value | Where-Object { $_.roleDefinitionId -eq $defs[0].id })
if ($haveRole.Count -eq 0 -and $PSCmdlet.ShouldProcess($AppName, 'Assign the Global Reader directory role')) {
    $null = Post-G "$graph/roleManagement/directory/roleAssignments" @{ principalId = $sp.id; roleDefinitionId = $defs[0].id; directoryScopeId = '/' }
    Write-Host 'Global Reader assigned'
}
else { Write-Host 'Global Reader already assigned' }

# 5. The two Automation variables the runbook reads. The certificate is referenced by its Key Vault secret URL, never copied.
$secretId = "https://$VaultName.vault.azure.net/secrets/$CertificateName"
foreach ($pair in @(@('TENANTKEEP_PURVIEW_APP_ID', [string]$app.appId), @('TENANTKEEP_PURVIEW_CERT', $secretId))) {
    if ($PSCmdlet.ShouldProcess($AutomationAccount, "Set variable $($pair[0])")) {
        $exists = $null; try { $exists = Invoke-Az automation variable show -g $ResourceGroup --automation-account-name $AutomationAccount -n $pair[0] -o json 2>$null } catch { $exists = $null }
        if ($exists) { $null = Invoke-Az automation variable update -g $ResourceGroup --automation-account-name $AutomationAccount -n $pair[0] --value "`"$($pair[1])`"" -o none }
        else { $null = Invoke-Az automation variable create -g $ResourceGroup --automation-account-name $AutomationAccount -n $pair[0] --value "`"$($pair[1])`"" -o none }
    }
}
Write-Host @"

Done. The scheduled posture run now signs in to Purview as '$AppName' with the certificate in $VaultName.
Renewal: the vault auto-renews the certificate 30 days before expiry; run this script again afterwards so the app
registration trusts the new one (it adds the current certificate, keeping the old until you remove it).
Revoke: delete the app registration or the certificate; the next run reports Purview as not collected.
"@
