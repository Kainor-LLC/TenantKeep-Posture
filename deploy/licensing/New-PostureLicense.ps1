#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Issues a Tenantkeep licence file. Kainor-side only: it needs the private signing key, which lives in Kainor's Azure
    Key Vault (or, for development, a local PEM that never enters this repository). Customers never run this.
.DESCRIPTION
    Writes <tenantId>.tenantkeep.lic: the licence fields, the key id and an ECDSA P-256 signature (SHA-256, IEEE P1363
    r||s, base64) over the canonical text the module verifies (Tenantkeep.Posture/Private/Test-PostureLicense.ps1).
    Two signing modes:
      -PrivateKeyPath   a PEM file (development, or an emergency copy you then destroy)
      -VaultName/-KeyName   az keyvault key sign with ES256 against a Key Vault EC P-256 key; the key never leaves the
                        vault (verify: the az output field name and encoding on the installed CLI version)
    The licence automation (Stripe webhook to an Azure Function in the Kainor tenant) calls the same signing path.
.EXAMPLE
    ./New-PostureLicense.ps1 -TenantId 00000000-0000-0000-0000-000000000001 -Tier full -Customer 'Contoso Ltd' -PrivateKeyPath ~/tenantkeep/licensing/kainor-2026-10.private.pem -OutputPath ~/tenantkeep/clients/contoso/tenantkeep.lic
.EXAMPLE
    ./New-PostureLicense.ps1 -TenantId <guid> -Tier ca -Customer 'Contoso Ltd' -VaultName kv-tenantkeep-licensing -KeyName kainor-2026-10
#>
[CmdletBinding(DefaultParameterSetName = 'Pem')]
param(
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')] [string] $TenantId,
    [Parameter(Mandatory)] [ValidateSet('ca', 'full')] [string] $Tier,
    [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Customer,
    [ValidateRange(1, 120)] [int] $Months = 13,
    [datetime] $ExpiresUtc,
    [string] $KeyId = 'kainor-2026-10',
    [Parameter(Mandatory, ParameterSetName = 'Pem')] [string] $PrivateKeyPath,
    [Parameter(Mandatory, ParameterSetName = 'Vault')] [string] $VaultName,
    [Parameter(Mandatory, ParameterSetName = 'Vault')] [string] $KeyName,
    [string] $OutputPath,
    [switch] $PassThru
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$issued = [datetime]::UtcNow
$expires = $(if ($PSBoundParameters.ContainsKey('ExpiresUtc')) { $ExpiresUtc.ToUniversalTime() } else { $issued.AddMonths($Months) })
$licence = [ordered]@{
    licenceId  = [guid]::NewGuid().ToString()
    product    = 'tenantkeep'
    tenantId   = $TenantId.ToLowerInvariant()
    tier       = $Tier.ToLowerInvariant()
    customer   = $Customer.Trim()
    issuedUtc  = $issued.ToString('o')
    expiresUtc = $expires.ToString('o')
    keyId      = $KeyId
}
# Must match ConvertTo-PostureLicenceCanonical in the module: format tag then the fields, one per line, in this order; dates as UTC round-trip ('o') strings.
$canonical = [System.Text.Encoding]::UTF8.GetBytes((@('tenantkeep-licence/1', $licence.licenceId, $licence.product, $licence.tenantId, $licence.tier, $licence.customer, $licence.issuedUtc, $licence.expiresUtc, $licence.keyId) -join "`n"))

if ($PSCmdlet.ParameterSetName -eq 'Pem') {
    $pemPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PrivateKeyPath)
    if (-not (Test-Path -LiteralPath $pemPath -PathType Leaf)) { throw "Private key not found: $pemPath" }
    $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
    $ecdsa.ImportFromPem((Get-Content -Raw -LiteralPath $pemPath))
    $signature = $ecdsa.SignData($canonical, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
}
else {
    $digest = [System.Security.Cryptography.SHA256]::HashData($canonical)
    $raw = & az keyvault key sign --vault-name $VaultName --name $KeyName --algorithm ES256 --digest ([Convert]::ToBase64String($digest)) --output json 2>&1
    if ($LASTEXITCODE -ne 0) { throw "az keyvault key sign failed: $raw" }
    $sigText = [string](($raw | ConvertFrom-Json).signature)   # (verify) field name; base64url per the Key Vault REST contract
    $b64 = $sigText.Replace('-', '+').Replace('_', '/'); while ($b64.Length % 4) { $b64 += '=' }
    $signature = [Convert]::FromBase64String($b64)
}

$doc = [ordered]@{ format = 'tenantkeep-licence/1'; licence = $licence; algorithm = 'ES256'; signature = [Convert]::ToBase64String($signature) }
$out = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($(if ($OutputPath) { $OutputPath } else { "$($licence.tenantId).tenantkeep.lic" }))
$dir = Split-Path -Parent $out; if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
[System.IO.File]::WriteAllText($out, (ConvertTo-Json -InputObject $doc -Depth 5) + "`n", [System.Text.UTF8Encoding]::new($false))
Write-Verbose "Licence $($licence.licenceId) for tenant $($licence.tenantId), $Tier tier, expires $($expires.ToString('yyyy-MM-dd')): $out"
if ($PassThru) { [pscustomobject]@{ Path = $out; LicenceId = $licence.licenceId; TenantId = $licence.tenantId; Tier = $Tier; ExpiresUtc = $licence.expiresUtc } } else { $out }
