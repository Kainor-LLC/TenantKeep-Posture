# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.

# Build integrity (docs/licensing.md, Hardening). A signed release ships integrity.json: the SHA-256 of every file in the
# module folder, signed with the same ECDSA key family as licences. At import the module hashes itself and records one
# of three states: release (manifest present, trusted signature, every file matches), development (no manifest: a
# source checkout), modified (manifest present but a file differs, a file was added or removed, or the signature does
# not verify). The state is printed in every report header. It is a label, not a lock: anyone can edit it out, and the
# point is that the deliverable they produce says so until they do.

function Get-PostureIntegrityFileList {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $ModuleRoot)
    $ErrorActionPreference = 'Stop'
    $root = (Resolve-Path -LiteralPath $ModuleRoot).Path
    $files = @{}
    foreach ($f in Get-ChildItem -Path $root -Recurse -File) {
        $rel = $f.FullName.Substring($root.Length).TrimStart('/', '\') -replace '\\', '/'
        if ($rel -eq 'integrity.json' -or $rel -like '.*' -or $rel -like '*/.*') { continue }
        $files[$rel] = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    return $files
}

function ConvertTo-PostureIntegrityCanonical {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Manifest)
    $ErrorActionPreference = 'Stop'
    $files = $Manifest['files']
    # generatedUtc canonicalises as a UTC round-trip string: ConvertFrom-Json hands it back as a DateTime, not the string that was signed.
    $gen = ConvertTo-PostureUtcDateTime $Manifest['generatedUtc']
    $lines = @('tenantkeep-integrity/1', [string]$Manifest['version'], $(if ($gen) { $gen.ToString('o') } else { [string]$Manifest['generatedUtc'] }), [string]$Manifest['keyId'])
    foreach ($k in @($files.Keys | Sort-Object -Culture ([cultureinfo]::InvariantCulture))) { $lines += "$k $([string]$files[$k])" }
    return [System.Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))
}

function New-PostureIntegrityManifest {
    <#
    .SYNOPSIS
        Writes integrity.json into a staged module folder. Build-time only (build.ps1 -Task Integrity); needs the private
        key as a PEM path or a -Signer scriptblock that takes the canonical bytes and returns the signature bytes (Key Vault).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $ModuleRoot,
        [Parameter(Mandatory)] [string] $KeyId,
        [string] $PrivateKeyPath,
        [scriptblock] $Signer
    )
    $ErrorActionPreference = 'Stop'
    if (-not $PrivateKeyPath -and -not $Signer) { throw 'New-PostureIntegrityManifest needs -PrivateKeyPath or -Signer.' }
    $root = (Resolve-Path -LiteralPath $ModuleRoot).Path
    $version = [string](Import-PowerShellDataFile -Path (Join-Path $root 'TenantKeep.Posture.psd1')).ModuleVersion
    $manifest = [ordered]@{ format = 'tenantkeep-integrity/1'; version = $version; generatedUtc = [datetime]::UtcNow.ToString('o'); keyId = $KeyId; files = $null; algorithm = 'ES256'; signature = $null }
    $files = Get-PostureIntegrityFileList -ModuleRoot $root
    $ordered = [ordered]@{}; foreach ($k in @($files.Keys | Sort-Object -Culture ([cultureinfo]::InvariantCulture))) { $ordered[$k] = $files[$k] }
    $manifest.files = $ordered
    $bytes = ConvertTo-PostureIntegrityCanonical -Manifest $manifest
    if ($Signer) { $sig = [byte[]](& $Signer $bytes) }
    else {
        $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
        $ecdsa.ImportFromPem((Get-Content -Raw -LiteralPath $PrivateKeyPath))
        $sig = $ecdsa.SignData($bytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    }
    $manifest.signature = [Convert]::ToBase64String($sig)
    $path = Join-Path $root 'integrity.json'
    if ($PSCmdlet.ShouldProcess($path, 'Write integrity manifest')) { [System.IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $manifest -Depth 5) + "`n", [System.Text.UTF8Encoding]::new($false)) }
    return $path
}

function Test-PostureIntegrity {
    <#
    .SYNOPSIS
        Compares the module folder with its signed integrity.json. Returns state (release, development, modified),
        detail, version and the changed file list.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $ModuleRoot,
        [System.Collections.IDictionary] $PublicKeys
    )
    $ErrorActionPreference = 'Stop'
    $keys = $(if ($PublicKeys) { $PublicKeys } else { $script:PostureLicenceKeys })
    $root = (Resolve-Path -LiteralPath $ModuleRoot).Path
    $manifestPath = Join-Path $root 'integrity.json'
    $version = $(try { [string](Import-PowerShellDataFile -Path (Join-Path $root 'TenantKeep.Posture.psd1')).ModuleVersion } catch { '' })
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { return @{ state = 'development'; detail = 'Development build: no signed release manifest.'; version = $version; changed = @() } }
    $modified = { param([string] $why, [string[]] $changed = @()) @{ state = 'modified'; detail = "Modified build: $why"; version = $version; changed = @($changed) } }
    try { $m = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json -AsHashtable -Depth 5 } catch { return & $modified 'integrity.json is not valid JSON.' }
    if (-not $m -or [string]$m['format'] -ne 'tenantkeep-integrity/1' -or -not $m.Contains('files') -or -not $m.Contains('signature')) { return & $modified 'integrity.json is not a release manifest.' }
    $keyId = [string]$m['keyId']
    if (-not $keys.Contains($keyId)) { return & $modified "the release manifest is signed with a key this build does not trust ('$keyId')." }
    try {
        $ecdsa = [System.Security.Cryptography.ECDsa]::Create(); $ecdsa.ImportFromPem([string]$keys[$keyId])
        $ok = $ecdsa.VerifyData((ConvertTo-PostureIntegrityCanonical -Manifest $m), [Convert]::FromBase64String([string]$m['signature']), [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    }
    catch { return & $modified "the release manifest signature could not be checked ($($_.Exception.Message))." }
    if (-not $ok) { return & $modified 'the release manifest signature does not match its contents.' }
    $actual = Get-PostureIntegrityFileList -ModuleRoot $root
    $expected = $m['files']
    $changed = [System.Collections.Generic.List[string]]::new()
    foreach ($k in $expected.Keys) { if (-not $actual.ContainsKey($k)) { $changed.Add("$k (removed)") } elseif ($actual[$k] -ne ([string]$expected[$k]).ToLowerInvariant()) { $changed.Add("$k (changed)") } }
    foreach ($k in $actual.Keys) { if (-not $expected.Contains($k)) { $changed.Add("$k (added)") } }
    if ($changed.Count -gt 0) { return & $modified "$($changed.Count) file(s) differ from the signed release $([string]$m['version']): $(@($changed | Sort-Object | Select-Object -First 5) -join ', ')$(if ($changed.Count -gt 5) { ', ...' })." @($changed) }
    return @{ state = 'release'; detail = "Signed release $([string]$m['version'])."; version = [string]$m['version']; changed = @() }
}
