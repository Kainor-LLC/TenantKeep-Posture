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

# 2. App registration that trusts the certificate; Exchange.ManageAsApp requested on both resources: Security & Compliance
#    PowerShell app-only is the role on "Microsoft Exchange Online Protection" (per Microsoft's app-only guide), Exchange's own is
#    "Office 365 Exchange Online". Both are granted so the same app works for either session.
$resources = [ordered]@{ '00000002-0000-0ff1-ce00-000000000000' = 'Office 365 Exchange Online'; '00000007-0000-0ff1-ce00-000000000000' = 'Microsoft Exchange Online Protection' }
$manageAsAppRoles = [ordered]@{}
foreach ($rid in $resources.Keys) {
    $found = @((Get-G "$graph/servicePrincipals?`$filter=appId eq '$rid'&`$select=id,appRoles").value)
    if ($found.Count -eq 0) { Write-Warning "No service principal for $($resources[$rid]) in this tenant; skipped."; continue }
    $role = @($found[0].appRoles | Where-Object { $_.value -eq 'Exchange.ManageAsApp' -and $_.allowedMemberTypes -contains 'Application' })[0]
    if ($role) { $manageAsAppRoles[$rid] = @{ sp = $found[0]; role = $role } } else { Write-Warning "$($resources[$rid]) exposes no Exchange.ManageAsApp application role." }
}
if ($manageAsAppRoles.Count -eq 0) { throw 'Neither Exchange resource exposes Exchange.ManageAsApp in this tenant.' }
$apps = @((Get-G "$graph/applications?`$filter=displayName eq '$($AppName -replace "'", "''")'&`$select=id,appId,keyCredentials").value)
$keyCredential = @{ type = 'AsymmetricX509Cert'; usage = 'Verify'; key = $cerBase64; displayName = "$CertificateName $thumbprint" }
if ($apps.Count -eq 0) {
    if ($PSCmdlet.ShouldProcess($AppName, 'Create the app registration')) {
        $app = Send-GraphPost "$graph/applications" @{ displayName = $AppName; signInAudience = 'AzureADMyOrg'; keyCredentials = @($keyCredential); requiredResourceAccess = @($manageAsAppRoles.Keys | ForEach-Object { @{ resourceAppId = $_; resourceAccess = @(@{ id = $manageAsAppRoles[$_].role.id; type = 'Role' }) } }); notes = 'Tenantkeep Posture: app-only Purview reads for the scheduled posture run. Certificate in Key Vault; read-only use. Safe to delete to revoke.' }
        Write-Host "App registration created: $($app.appId)"
    }
}
else {
    $app = $apps[0]
    # Graph lists existing credentials by keyId and display name; the thumbprint is in customKeyIdentifier when present and in our display name always.
    $have = @($app.keyCredentials | Where-Object { ([string]$_.displayName -like "*$thumbprint") -or ([string]$_.key -eq $cerBase64) -or ([string]$_.customKeyIdentifier -and ([Convert]::ToHexString([Convert]::FromBase64String([string]$_.customKeyIdentifier)) -eq $thumbprint)) })
    if ($have.Count -eq 0 -and $PSCmdlet.ShouldProcess($AppName, 'Add the current certificate to the app registration')) {
        # Existing credentials go back by keyId only (Graph refuses key material on an existing keyId); the new one carries the key.
        Send-GraphPatch "$graph/applications/$($app.id)" @{ keyCredentials = @(@($app.keyCredentials | ForEach-Object { @{ type = $_.type; usage = $_.usage; keyId = $_.keyId; displayName = $_.displayName } }) + @($keyCredential)) }
        Write-Host 'Certificate added to the app registration'
    }
    else { Write-Host "App registration exists: $($app.appId)" }
}
$sps = @((Get-G "$graph/servicePrincipals?`$filter=appId eq '$($app.appId)'&`$select=id").value)
$sp = $(if ($sps.Count -gt 0) { $sps[0] } elseif ($PSCmdlet.ShouldProcess($AppName, 'Create the service principal')) { Send-GraphPost "$graph/servicePrincipals" @{ appId = $app.appId } })

# 3. Consent: Exchange.ManageAsApp on the service principal, for each resource.
$assignments = @((Get-G "$graph/servicePrincipals/$($sp.id)/appRoleAssignments").value)
foreach ($rid in $manageAsAppRoles.Keys) {
    $r = $manageAsAppRoles[$rid]
    if ($assignments | Where-Object { $_.appRoleId -eq $r.role.id -and $_.resourceId -eq $r.sp.id }) { Write-Host "Exchange.ManageAsApp already granted on $($resources[$rid])"; continue }
    if ($PSCmdlet.ShouldProcess($AppName, "Grant Exchange.ManageAsApp on $($resources[$rid])")) {
        $null = Send-GraphPost "$graph/servicePrincipals/$($sp.id)/appRoleAssignments" @{ principalId = $sp.id; resourceId = $r.sp.id; appRoleId = $r.role.id }
        Write-Host "Exchange.ManageAsApp granted on $($resources[$rid])"
    }
}

# 4. Global Reader on the service principal: the directory role Purview app-only reads map to (verify: if Purview cmdlets
#    refuse reads with Global Reader, Compliance Administrator is the documented alternative and a write role; prefer not).
$readerTemplate = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451'
$defs = @((Get-G "$graph/roleManagement/directory/roleDefinitions?`$filter=templateId eq '$readerTemplate'&`$select=id").value)
$haveRole = @((Get-G "$graph/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($sp.id)'").value | Where-Object { $_.roleDefinitionId -eq $defs[0].id })
if ($haveRole.Count -eq 0 -and $PSCmdlet.ShouldProcess($AppName, 'Assign the Global Reader directory role')) {
    $null = Send-GraphPost "$graph/roleManagement/directory/roleAssignments" @{ principalId = $sp.id; roleDefinitionId = $defs[0].id; directoryScopeId = '/' }
    Write-Host 'Global Reader assigned'
}
else { Write-Host 'Global Reader already assigned' }

# 5. The two Automation variables the runbook reads. The certificate is referenced by its Key Vault secret URL, never copied.
$secretId = "https://$VaultName.vault.azure.net/secrets/$CertificateName"
# Through the ARM REST API: the CLI's automation extension has no variable commands in every version.
$aaPath = "/subscriptions/$($account.id)/resourceGroups/$ResourceGroup/providers/Microsoft.Automation/automationAccounts/$AutomationAccount"
foreach ($pair in @(@('TENANTKEEP_PURVIEW_APP_ID', [string]$app.appId), @('TENANTKEEP_PURVIEW_CERT', $secretId))) {
    if ($PSCmdlet.ShouldProcess($AutomationAccount, "Set variable $($pair[0])")) {
        $body = @{ name = $pair[0]; properties = @{ value = ('"' + $pair[1] + '"'); isEncrypted = $false; description = 'Set by New-PosturePurviewApp.ps1' } } | ConvertTo-Json -Compress
        $null = Invoke-Az rest --method put --url "https://management.azure.com$aaPath/variables/$($pair[0])?api-version=2023-11-01" --headers 'Content-Type=application/json' --body $body -o none
        Write-Host "Variable $($pair[0]) set"
    }
}
Write-Host @"

Done. The scheduled posture run now signs in to Purview as '$AppName' with the certificate in $VaultName.

Global Reader covers labels, label policies, DLP, retention and the audit configuration. Two more reads need a Purview
role group on the app's service principal (a Security & Compliance PowerShell session, interactive, as an admin):

  Connect-IPPSSession -UserPrincipalName <admin>
  New-ServicePrincipal -AppId $($app.appId) -ObjectId $($sp.id) -DisplayName '$AppName'
  New-RoleGroup -Name 'Tenantkeep Posture (view only)' -DisplayName 'Tenantkeep Posture (view only)' -Description 'Read-only roles for the Tenantkeep Posture scheduled run' -Roles 'View-Only Audit Logs', 'Insider Risk Management Audit', 'View-Only Retention Management', 'View-Only DLP Compliance Management', 'View-Only IB Compliance Management' -Members $($sp.id)
  # Role names as listed by Get-ManagementRole (2026-10-15). Proven in Kainor: this group opens Insider Risk policies.
  # Audit retention policies (Get-UnifiedAuditLogRetentionPolicy) stay hidden with View-Only Audit Logs; add the 'Audit Logs'
  # role to the group if you want that read in the scheduled run (verify it is the least role that works).

eDiscovery cases (Get-ComplianceCase) are not supported app-only by Microsoft; that check stays by hand.
Renewal: the vault auto-renews the certificate 30 days before expiry; run this script again afterwards so the app
registration trusts the new one (it adds the current certificate, keeping the old until you remove it).
Revoke: delete the app registration or the certificate; the next run reports Purview as not collected.
"@
