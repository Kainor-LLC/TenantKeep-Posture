# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.

# Public keys the module trusts for licence signatures, by key id. The matching private keys live in Kainor's Azure Key
# Vault and never in this repository. A second entry here is how a key rotation ships: both keys verify for one release
# cycle, then the old one is removed. docs/licensing.md describes the file format and what is checked.
$script:PostureLicenceKeys = @{
    'kainor-2026-10' = @'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+axLNQOUSb3Tt3hXVANqlEAbXC4E
BN/1sppIu50Y2ywXirjygzSVJKvyvzPq2p3h1C7+04vGIW5WuIFlXYy3yA==
-----END PUBLIC KEY-----
'@
}

function ConvertTo-PostureLicenceCanonical {
    <#
    .SYNOPSIS
        The exact bytes a licence signature covers: the format tag and the licence fields in a fixed order, one per
        line, tenant id and tier lower-cased. The issuing script in deploy/licensing builds the same string.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Licence)
    $ErrorActionPreference = 'Stop'
    $v = { param([string] $k) if ($Licence.Contains($k) -and $null -ne $Licence[$k]) { [string]$Licence[$k] } else { '' } }
    # Dates canonicalise as UTC round-trip strings whether the file holds a string or ConvertFrom-Json already parsed it.
    $d = { param([string] $k) if ($Licence.Contains($k) -and $null -ne $Licence[$k]) { $u = ConvertTo-PostureUtcDateTime $Licence[$k]; if ($u) { $u.ToString('o') } else { [string]$Licence[$k] } } else { '' } }
    $text = @('tenantkeep-licence/1', (& $v 'licenceId'), (& $v 'product'), (& $v 'tenantId').ToLowerInvariant(), (& $v 'tier').ToLowerInvariant(), (& $v 'customer'), (& $d 'issuedUtc'), (& $d 'expiresUtc'), (& $v 'keyId')) -join "`n"
    return [System.Text.Encoding]::UTF8.GetBytes($text)
}

function Test-PostureLicense {
    <#
    .SYNOPSIS
        Verifies a licence file offline: known key id, valid ECDSA P-256 signature over the canonical fields, product,
        tenant binding and expiry. Returns a hashtable with valid, reason, tier and the licence fields.
    .PARAMETER TenantId
        The tenant the licence must name. Comes from the evidence (collection.json or metadata.json) or the live session.
    .PARAMETER AsOfUtc
        The moment the licence must still be valid at. Callers pass the later of now and the collection time, so a
        rolled-back clock does not revive an expired file.
    .PARAMETER PublicKeys
        Replaces the built-in key table. Not reachable from any public cmdlet; the test suite signs with a throwaway
        key and verifies through this.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [string] $TenantId,
        [datetime] $AsOfUtc = [datetime]::UtcNow,
        [System.Collections.IDictionary] $PublicKeys
    )
    $ErrorActionPreference = 'Stop'
    $keys = $(if ($PublicKeys) { $PublicKeys } else { $script:PostureLicenceKeys })
    $fail = { param([string] $why) return @{ valid = $false; reason = $why; tier = 'none'; licence = $null; path = $Path } }

    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { return & $fail "Licence file not found: $full" }
    try { $doc = Get-Content -Raw -LiteralPath $full | ConvertFrom-Json -AsHashtable -Depth 5 }
    catch { return & $fail "Licence file is not valid JSON: $($_.Exception.Message)" }
    if (-not $doc -or -not $doc.Contains('licence') -or -not $doc.Contains('signature')) { return & $fail 'Licence file is missing the licence or signature field.' }
    if ([string]$doc['format'] -ne 'tenantkeep-licence/1') { return & $fail "Unknown licence format '$($doc['format'])'." }
    $lic = $doc['licence']
    $keyId = [string]$(if ($lic.Contains('keyId')) { $lic['keyId'] })
    if (-not $keys.Contains($keyId)) { return & $fail "Licence was signed with an unknown key '$keyId'; this module build does not trust it." }

    try {
        $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
        $ecdsa.ImportFromPem([string]$keys[$keyId])
        $sig = [Convert]::FromBase64String([string]$doc['signature'])
        $ok = $ecdsa.VerifyData((ConvertTo-PostureLicenceCanonical -Licence $lic), $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    }
    catch { return & $fail "Licence signature could not be checked: $($_.Exception.Message)" }
    if (-not $ok) { return & $fail 'Licence signature does not match its contents. The file was edited or is not from Kainor.' }

    if ([string]$lic['product'] -ne 'tenantkeep') { return & $fail "Licence is for product '$($lic['product'])', not Tenantkeep." }
    $tier = ([string]$lic['tier']).ToLowerInvariant()
    if ($tier -notin @('ca', 'full')) { return & $fail "Licence tier '$tier' is not one this module knows." }
    if ($TenantId -and ([string]$lic['tenantId']).ToLowerInvariant() -ne $TenantId.ToLowerInvariant()) { return & $fail "Licence is for tenant $($lic['tenantId']), not $TenantId." }
    $issued = ConvertTo-PostureUtcDateTime $lic['issuedUtc']; $expires = ConvertTo-PostureUtcDateTime $lic['expiresUtc']
    if (-not $issued -or -not $expires) { return & $fail 'Licence dates are not valid timestamps.' }
    if ($issued -gt $AsOfUtc.ToUniversalTime().AddDays(1)) { return & $fail "Licence is not valid yet (issued $($issued.ToString('yyyy-MM-dd')))." }
    if ($expires -lt $AsOfUtc.ToUniversalTime()) { return & $fail "Licence expired on $($expires.ToString('yyyy-MM-dd')). Renew it to keep the full report." }

    return @{ valid = $true; reason = $null; tier = $tier; path = $full; licence = @{ licenceId = [string]$lic['licenceId']; customer = [string]$lic['customer']; tenantId = [string]$lic['tenantId']; issuedUtc = $issued.ToString('o'); expiresUtc = $expires.ToString('o'); keyId = $keyId } }
}
