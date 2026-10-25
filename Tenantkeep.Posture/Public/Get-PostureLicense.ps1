# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureLicense {
    <#
    .SYNOPSIS
        Shows whether a TenantKeep licence file is valid, for which tenant and tier, and when it expires. Verification
        is offline: an ECDSA signature checked against the public keys built into the module. Nothing is sent anywhere.
    .DESCRIPTION
        Without -Path the file is looked for in TENANTKEEP_LICENSE, then ~/tenantkeep/tenantkeep.lic. With -Evidence
        the tenant id recorded in that folder is the one the licence must name; with -TenantId that id is used; with
        neither, the tenant binding is reported but not enforced.
    .PARAMETER Path
        The licence file (tenantkeep.lic).
    .PARAMETER TenantId
        Tenant the licence must name.
    .PARAMETER Evidence
        Evidence folder whose collection.json or metadata.json names the tenant.
    .EXAMPLE
        Get-PostureLicense -Path ~/tenantkeep/clients/contoso/tenantkeep.lic -Evidence ~/tenantkeep/evidence/20261015-0952
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string] $Path,
        [string] $TenantId,
        [string] $Evidence
    )
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    if ($Evidence -and -not $TenantId) {
        foreach ($name in 'collection.json', 'metadata.json') {
            $f = Join-Path $Evidence $name
            if (Test-Path -LiteralPath $f -PathType Leaf) { $m = Get-Content -Raw -LiteralPath $f | ConvertFrom-Json -AsHashtable -Depth 10; if ($m -and $m.Contains('tenantId') -and $m['tenantId']) { $TenantId = [string]$m['tenantId']; break } }
        }
        if (-not $TenantId) { throw "No tenant id recorded in $Evidence (collection.json or metadata.json)." }
    }
    $candidates = @($(if ($Path) { $Path }), $env:TENANTKEEP_LICENSE, (Join-Path $HOME 'tenantkeep' 'tenantkeep.lic')) | Where-Object { $_ }
    $found = $null
    foreach ($c in $candidates) { $p = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($c); if (Test-Path -LiteralPath $p -PathType Leaf) { $found = $p; break } }
    if (-not $found) {
        return [pscustomobject]@{ Valid = $false; Tier = 'none'; Customer = $null; TenantId = $TenantId; IssuedUtc = $null; ExpiresUtc = $null; KeyId = $null; Path = $null; Reason = "No licence file found (looked for $($candidates -join ', '))." }
    }
    $r = Test-PostureLicense -Path $found -TenantId $TenantId
    $lic = $r.licence
    [pscustomobject]@{
        Valid      = $r.valid
        Tier       = $r.tier
        Customer   = $(if ($lic) { $lic.customer })
        TenantId   = $(if ($lic) { $lic.tenantId } else { $TenantId })
        IssuedUtc  = $(if ($lic) { $lic.issuedUtc })
        ExpiresUtc = $(if ($lic) { $lic.expiresUtc })
        KeyId      = $(if ($lic) { $lic.keyId })
        Path       = $found
        Reason     = $(if ($r.valid) { 'Valid.' } else { $r.reason })
    }
}
