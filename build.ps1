#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
  Build script for TenantKeep.Posture.
.DESCRIPTION
  Tasks: Analyze, Test, Build, Sign, Verify, Integrity, Package, Catalog (the public catalog page for the website). Sign needs a local
  code-signing certificate and is the emergency path; releases are signed by the sign-release workflow through Azure Artifact Signing,
  after which Verify checks that every staged file carries a valid Authenticode signature. Integrity needs the licence signing key (PEM
  or Key Vault) and writes the signed integrity.json the module checks at import (docs/licensing.md, Hardening). Package refuses to run
  without integrity.json and without Sign or Verify in the same run. Sign and Verify are Windows-only; the rest runs everywhere.
.EXAMPLE
  ./build.ps1 -Task Analyze, Test
.EXAMPLE
  ./build.ps1 -Task Package -CertificatePath ./signing.pfx
  # password from TENANTKEEP_SIGNING_PASSWORD
.EXAMPLE
  ./build.ps1 -Task Package -CertificateThumbprint ABC123...
  # Windows cert store, or TENANTKEEP_SIGNING_THUMBPRINT
.NOTES
  checks/ and baselines/ are staged into the module at Build time once they exist (CLAUDE.md layout keeps them at the root). (verify) PowerShell Gallery layout for sibling data folders.
#>
[CmdletBinding()]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Build script output is for the console, not the pipeline.')]
param(
    [ValidateSet('Analyze', 'Test', 'Build', 'Sign', 'Verify', 'Integrity', 'Package', 'Clean', 'Catalog')]
    [string[]] $Task = @('Analyze', 'Test'),

    [string] $CertificateThumbprint = $env:TENANTKEEP_SIGNING_THUMBPRINT,
    [string] $CertificatePath       = $env:TENANTKEEP_SIGNING_PFX,
    [string] $TimestampServer       = 'http://timestamp.digicert.com',

    [switch] $SkipInstall,

    # Catalog task only: where catalog.md and catalog.html land. Default: out/.
    [string] $CatalogPath,

    # Integrity task: the licence signing key that signs integrity.json. A PEM path (TENANTKEEP_LICENCE_KEY) or a Key Vault key.
    [string] $LicenseKeyPath = $env:TENANTKEEP_LICENCE_KEY,
    [string] $LicenseKeyId   = 'kainor-2026-10',
    [string] $VaultName,
    [string] $KeyName
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root       = $PSScriptRoot
$ModuleName = 'TenantKeep.Posture'
$SrcPath    = Join-Path $Root $ModuleName
$OutRoot    = Join-Path $Root 'out'
$Manifest   = Join-Path $SrcPath "$ModuleName.psd1"

function Write-Task([string] $Name) { Write-Host "`n==> $Name" -ForegroundColor Cyan }

function Install-BuildDependency {
    param([string] $Name, [string] $MinimumVersion)
    $have = Get-Module -ListAvailable -Name $Name | Where-Object { $_.Version -ge [version]$MinimumVersion } | Select-Object -First 1
    if ($have) { return }
    if ($SkipInstall) { throw "$Name >= $MinimumVersion is required. Install it or drop -SkipInstall." }
    Write-Host "Installing $Name >= $MinimumVersion"
    if (Get-Command Install-PSResource -ErrorAction SilentlyContinue) {
        Install-PSResource -Name $Name -Version "[$MinimumVersion,)" -Scope CurrentUser -TrustRepository -Quiet
    }
    else {
        Install-Module -Name $Name -MinimumVersion $MinimumVersion -Scope CurrentUser -Force
    }
}

function Get-ModuleVersion {
    (Import-PowerShellDataFile -Path $Manifest).ModuleVersion
}

function Get-SigningCertificate {
    <#
      Resolves the code-signing certificate or throws. This is the gate: no cert, no Sign, no Package.
    #>
    $cert = $null

    if ($CertificatePath) {
        if (-not (Test-Path -LiteralPath $CertificatePath)) { throw "Signing certificate not found at '$CertificatePath'." }
        $password = $env:TENANTKEEP_SIGNING_PASSWORD
        if (-not $password) { throw 'TENANTKEEP_SIGNING_PASSWORD is not set; it must hold the PFX password.' }
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            (Resolve-Path -LiteralPath $CertificatePath).Path, $password,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
    }
    elseif ($CertificateThumbprint) {
        if (-not $IsWindows) { throw 'Certificate store lookup by thumbprint is Windows-only. Use -CertificatePath on this platform.' }
        $cert = Get-ChildItem -Path 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
            Where-Object Thumbprint -eq $CertificateThumbprint | Select-Object -First 1
        if (-not $cert) { throw "No certificate with thumbprint '$CertificateThumbprint' in CurrentUser\My or LocalMachine\My." }
    }
    else {
        throw 'No signing certificate. Pass -CertificatePath (PFX) or -CertificateThumbprint, or set TENANTKEEP_SIGNING_PFX / TENANTKEEP_SIGNING_THUMBPRINT. Releases must be Authenticode-signed (spec section 6).'
    }

    if (-not $cert.HasPrivateKey) { throw "Certificate '$($cert.Subject)' has no private key." }
    $codeSigningOid = '1.3.6.1.5.5.7.3.3'
    $eku = $cert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] }
    $hasCodeSigning = $eku -and ($eku.EnhancedKeyUsages | Where-Object Value -eq $codeSigningOid)
    if (-not $hasCodeSigning) { throw "Certificate '$($cert.Subject)' is not a code-signing certificate (missing EKU $codeSigningOid)." }
    if ($cert.NotAfter -lt (Get-Date)) { throw "Certificate '$($cert.Subject)' expired on $($cert.NotAfter.ToString('u'))." }

    Write-Host "Signing with: $($cert.Subject) (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))"
    return $cert
}

function Invoke-Catalog {
    # The public catalog page for the website (CLAUDE.md, Licensing): ids, titles, the narrative and the licence required.
    # No pass logic, no remediation, no framework mappings: those are the product.
    Write-Task 'Catalog'
    $target = $(if ($CatalogPath) { $CatalogPath } else { $OutRoot })
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    $labels = @{ identity = 'Identity and privileged access'; auth = 'Authentication methods'; ca = 'Conditional Access'; devices = 'Devices'; endpoint = 'Endpoint security'; email = 'Email security'; purview = 'Data protection'; collaboration = 'Collaboration and oversharing'; copilot = 'Copilot readiness'; governance = 'Governance and lifecycle'; operations = 'Operations and monitoring'; azure = 'Azure'; hybrid = 'Hybrid identity and on-premises AD' }
    $order = @('identity', 'auth', 'ca', 'devices', 'endpoint', 'email', 'purview', 'collaboration', 'copilot', 'governance', 'operations', 'azure', 'hybrid')
    $version = (Get-Content -Raw (Join-Path $Root 'checks' 'catalog.json') | ConvertFrom-Json).version
    $files = Get-ChildItem -Path (Join-Path $Root 'checks') -Filter '*.json' | Where-Object { $_.Name -ne 'catalog.json' }
    $byDomain = @{}
    foreach ($f in $files) { $d = Get-Content -Raw $f.FullName | ConvertFrom-Json; $byDomain[[string]$d.domain] = @($d.checks) }
    $md = [System.Collections.Generic.List[string]]::new()
    $md.Add("# TenantKeep Posture check catalog $version"); $md.Add('')
    $md.Add('Every check the product evaluates, by domain. The pass logic, remediation and framework mappings are part of the product; this page lists what is checked and the licence each check needs.'); $md.Add('')
    $total = 0
    $esc = { param([string] $x) $x -replace '\|', '\|' }
    foreach ($dom in $order) {
        if (-not $byDomain.ContainsKey($dom)) { continue }
        $checks = @($byDomain[$dom]); $total += $checks.Count
        $md.Add("## $($labels[$dom]) ($($checks.Count))"); $md.Add(''); $md.Add('| ID | Check | Severity | Licence | What it means |'); $md.Add('|---|---|---|---|---|')
        foreach ($c in $checks) { $md.Add("| $($c.id) | $(& $esc $c.title) | $($c.severityDefault) | $(if (@($c.license).Count -gt 0) { @($c.license) -join ', ' } else { 'none' }) | $(& $esc $c.narrative) |") }
        $md.Add('')
    }
    $md.Add("$total checks in $($order.Where({ $byDomain.ContainsKey($_) }).Count) domains. Generated by build.ps1 -Task Catalog from checks/; never edited by hand.")
    $mdPath = Join-Path $target 'catalog.md'
    [System.IO.File]::WriteAllText($mdPath, ($md -join "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
    $h = { param([string] $x) [System.Net.WebUtility]::HtmlEncode($x) }
    $html = [System.Collections.Generic.List[string]]::new()
    $html.Add('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>TenantKeep Posture check catalog</title><style>body{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#1b1b1b}table{border-collapse:collapse;width:100%;margin-bottom:2rem}th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top;font-size:.92rem}th{background:#f3f3f3}h2{margin-top:2rem}</style></head><body>')
    $html.Add("<h1>TenantKeep Posture check catalog $(& $h $version)</h1><p>Every check the product evaluates, by domain. The pass logic, remediation and framework mappings are part of the product; this page lists what is checked and the licence each check needs.</p>")
    foreach ($dom in $order) {
        if (-not $byDomain.ContainsKey($dom)) { continue }
        $checks = @($byDomain[$dom])
        $html.Add("<h2>$(& $h $labels[$dom]) ($($checks.Count))</h2><table><thead><tr><th>ID</th><th>Check</th><th>Severity</th><th>Licence</th><th>What it means</th></tr></thead><tbody>")
        foreach ($c in $checks) { $html.Add("<tr><td>$(& $h $c.id)</td><td>$(& $h $c.title)</td><td>$(& $h $c.severityDefault)</td><td>$(& $h $(if (@($c.license).Count -gt 0) { @($c.license) -join ', ' } else { 'none' }))</td><td>$(& $h $c.narrative)</td></tr>") }
        $html.Add('</tbody></table>')
    }
    $html.Add("<p>$total checks. Generated by build.ps1 -Task Catalog from checks/; never edited by hand.</p></body></html>")
    $htmlPath = Join-Path $target 'catalog.html'
    [System.IO.File]::WriteAllText($htmlPath, ($html -join "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
    Write-Host "Catalog: $total checks -> $mdPath, $htmlPath"
}

function Invoke-Clean {
    Write-Task 'Clean'
    if (Test-Path $OutRoot) { Remove-Item -LiteralPath $OutRoot -Recurse -Force }
}

function Invoke-Analyze {
    Write-Task 'Analyze'
    Install-BuildDependency -Name PSScriptAnalyzer -MinimumVersion 1.22.0
    Import-Module PSScriptAnalyzer
    $settings = Join-Path $Root 'PSScriptAnalyzerSettings.psd1'
    $paths = @($SrcPath, (Join-Path $Root 'tests'), (Join-Path $Root '.githooks'), (Join-Path $Root 'deploy'), (Join-Path $Root 'build.ps1'))

    # A file that does not parse is a hard failure; Invoke-ScriptAnalyzer does not reliably report that.
    $parseErrors = foreach ($file in (Get-ChildItem -Path $paths -Recurse -Include '*.ps1', '*.psm1', '*.psd1')) {
        $tokens = $null; $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
        foreach ($e in @($errors)) { "$($file.FullName):$($e.Extent.StartLineNumber):$($e.Extent.StartColumnNumber) $($e.Message)" }
    }
    if ($parseErrors) { $parseErrors | Write-Host; throw "$(@($parseErrors).Count) parse error(s)." }
    $results = foreach ($p in $paths) { Invoke-ScriptAnalyzer -Path $p -Recurse -Settings $settings }
    if ($results) {
        $results | Format-Table -AutoSize RuleName, Severity, ScriptName, Line, Message | Out-String -Width 200 | Write-Host
        throw "PSScriptAnalyzer reported $(@($results).Count) finding(s)."
    }
    Write-Host 'PSScriptAnalyzer: clean'
}

function Invoke-Test {
    Write-Task 'Test'
    Install-BuildDependency -Name Pester -MinimumVersion 5.5.0
    Import-Module Pester
    New-Item -ItemType Directory -Path $OutRoot -Force | Out-Null

    $config = New-PesterConfiguration
    $config.Run.Path = Join-Path $Root 'tests'
    $config.Run.Exit = $false
    $config.Run.PassThru = $true
    $config.Output.Verbosity = 'Detailed'
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputFormat = 'NUnitXml'
    $config.TestResult.OutputPath = Join-Path $OutRoot 'test-results.xml'

    $result = Invoke-Pester -Configuration $config
    if ($result.FailedCount -gt 0) { throw "$($result.FailedCount) test(s) failed." }
}

function Invoke-Build {
    Write-Task 'Build'
    $version = Get-ModuleVersion
    $stage = Join-Path $OutRoot $ModuleName $version
    if (Test-Path $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Copy-Item -Path (Join-Path $SrcPath '*') -Destination $stage -Recurse -Exclude '.gitkeep'
    foreach ($data in 'checks', 'baselines', 'templates') {
        $src = Join-Path $Root $data
        if (Test-Path $src) { Copy-Item -Path $src -Destination (Join-Path $stage $data) -Recurse -Exclude '.gitkeep' }
    }
    # The scheduling scripts ship inside the module so a runbook can find them next to the manifest.
    $schedules = Join-Path $Root 'deploy' 'schedules'
    if (Test-Path $schedules) {
        New-Item -ItemType Directory -Path (Join-Path $stage 'schedules') -Force | Out-Null
        Copy-Item -Path (Join-Path $schedules '*.ps1') -Destination (Join-Path $stage 'schedules')
    }

    # The export list is derived from Public/, so the manifest can never drift from the source tree.
    $publicFunctions = @(Get-ChildItem -Path (Join-Path $stage 'Public') -Filter '*.ps1' | Select-Object -ExpandProperty BaseName | Sort-Object)
    Update-ModuleManifest -Path (Join-Path $stage "$ModuleName.psd1") -FunctionsToExport $publicFunctions
    $null = Test-ModuleManifest -Path (Join-Path $stage "$ModuleName.psd1")

    Write-Host "Staged $ModuleName $version with $($publicFunctions.Count) exported function(s) at $stage"
    return $stage
}

function Invoke-Sign {
    param([string] $Stage)
    Write-Task 'Sign'
    $cert = Get-SigningCertificate
    if (-not $IsWindows) {
        throw 'Authenticode signing (Set-AuthenticodeSignature) is only available on Windows. Run Sign or Package on a Windows machine or runner.'
    }
    $files = Get-ChildItem -Path $Stage -Recurse -Include '*.ps1', '*.psm1', '*.psd1'
    foreach ($f in $files) {
        $sig = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampServer -IncludeChain All
        if ($sig.Status -ne 'Valid') { throw "Signing failed for $($f.FullName): $($sig.Status) $($sig.StatusMessage)" }
    }
    Write-Host "Signed $($files.Count) file(s)"
}

function Invoke-Verify {
    <#
      Every staged .ps1, .psm1 and .psd1 must carry a valid Authenticode signature. This is the gate for a stage signed outside this
      script (the sign-release workflow, Azure Artifact Signing): Package accepts Verify in place of Sign.
    #>
    param([string] $Stage)
    Write-Task 'Verify'
    if (-not $Stage) { $Stage = Join-Path $OutRoot $ModuleName (Get-ModuleVersion) }
    if (-not (Test-Path -LiteralPath (Join-Path $Stage "$ModuleName.psd1"))) { throw "No staged module at $Stage; run Build first." }
    if (-not $IsWindows) { throw 'Verify checks Authenticode signatures with Get-AuthenticodeSignature, which is Windows-only.' }
    $files = @(Get-ChildItem -Path $Stage -Recurse -Include '*.ps1', '*.psm1', '*.psd1')
    $bad = foreach ($f in $files) {
        $sig = Get-AuthenticodeSignature -FilePath $f.FullName
        if ($sig.Status -ne 'Valid') { "$($f.FullName): $($sig.Status) $($sig.StatusMessage)" }
    }
    if ($bad) { $bad | Write-Host; throw "$(@($bad).Count) file(s) without a valid Authenticode signature." }
    $signer = (Get-AuthenticodeSignature -FilePath $files[0].FullName).SignerCertificate
    Write-Host "Verified $($files.Count) signed file(s). Signer: $($signer.Subject) (expires $($signer.NotAfter.ToString('yyyy-MM-dd')))"
    $script:Verified = $true
}

function Invoke-Integrity {
    param([string] $Stage)
    Write-Task 'Integrity'
    if (-not $Stage) { $Stage = Join-Path $OutRoot $ModuleName (Get-ModuleVersion) }
    if (-not (Test-Path -LiteralPath (Join-Path $Stage "$ModuleName.psd1"))) { throw "No staged module at $Stage; run Build first." }
    Import-Module (Join-Path $SrcPath "$ModuleName.psd1") -Force
    $m = Get-Module $ModuleName
    if ($VaultName -and $KeyName) {
        $vault = $VaultName; $key = $KeyName
        $signer = {
            param([byte[]] $bytes)
            $digest = [System.Security.Cryptography.SHA256]::HashData($bytes)
            $raw = & az keyvault key sign --vault-name $vault --name $key --algorithm ES256 --digest ([Convert]::ToBase64String($digest)) --output json 2>&1
            if ($LASTEXITCODE -ne 0) { throw "az keyvault key sign failed: $raw" }
            $b64 = ([string](($raw | ConvertFrom-Json).signature)).Replace('-', '+').Replace('_', '/'); while ($b64.Length % 4) { $b64 += '=' }   # base64url, confirmed with azure-cli 2.90
            , [Convert]::FromBase64String($b64)
        }.GetNewClosure()
        $path = & $m { param($Root, $KeyId, $Signer) New-PostureIntegrityManifest -ModuleRoot $Root -KeyId $KeyId -Signer $Signer } $Stage $LicenseKeyId $signer
    }
    else {
        if (-not $LicenseKeyPath) { throw 'Integrity needs the licence signing key: -LicenseKeyPath (or TENANTKEEP_LICENCE_KEY), or -VaultName and -KeyName.' }
        if (-not (Test-Path -LiteralPath $LicenseKeyPath -PathType Leaf)) { throw "Licence signing key not found: $LicenseKeyPath" }
        $path = & $m { param($Root, $KeyId, $Pem) New-PostureIntegrityManifest -ModuleRoot $Root -KeyId $KeyId -PrivateKeyPath $Pem } $Stage $LicenseKeyId $LicenseKeyPath
    }
    $state = & $m { param($Root) Test-PostureIntegrity -ModuleRoot $Root } $Stage
    if ($state.state -ne 'release') { throw "Integrity manifest written but the staged module does not verify as a release: $($state.detail)" }
    Write-Host "Integrity manifest: $path ($($state.detail))"
}

function Invoke-Package {
    param([string] $Stage)
    Write-Task 'Package'
    $version = Get-ModuleVersion
    if (-not (Test-Path -LiteralPath (Join-Path $OutRoot $ModuleName $version 'integrity.json'))) { throw 'No integrity.json in the staged module; run Integrity before Package.' }
    if (-not $script:Verified -and $tasks -notcontains 'Sign') { throw 'Package needs Sign (local certificate) or Verify (a stage signed by the sign-release workflow) in the same run.' }
    $zip = Join-Path $OutRoot "$ModuleName-$version.zip"
    if (Test-Path $zip) { Remove-Item -LiteralPath $zip -Force }
    Compress-Archive -Path (Join-Path $OutRoot $ModuleName) -DestinationPath $zip
    $hash = (Get-FileHash -Path $zip -Algorithm SHA256).Hash
    Set-Content -Path "$zip.sha256" -Value "$hash  $(Split-Path $zip -Leaf)"
    Write-Host "Packaged $zip`nSHA256 $hash"
}

# Package implies Build and Sign. Sign implies Build. The cert check runs first so a missing cert fails fast.
$script:Verified = $false
$tasks = [System.Collections.Generic.List[string]]::new($Task)
if ($tasks -contains 'Package' -and $tasks -notcontains 'Sign' -and $tasks -notcontains 'Verify') { $tasks.Add('Sign') }
if ($tasks -contains 'Sign'    -and $tasks -notcontains 'Build') { $tasks.Add('Build') }
if ($tasks -contains 'Sign') { $null = Get-SigningCertificate }

$stage = $null
foreach ($t in @('Clean', 'Analyze', 'Test', 'Build', 'Sign', 'Verify', 'Integrity', 'Package', 'Catalog')) {
    if ($tasks -notcontains $t) { continue }
    switch ($t) {
        'Clean' { Invoke-Clean }
        'Analyze' { Invoke-Analyze }
        'Test' { Invoke-Test }
        'Build' { $stage = Invoke-Build }
        'Sign' { Invoke-Sign -Stage $stage }
        'Verify' { Invoke-Verify -Stage $stage }
        'Integrity' { Invoke-Integrity -Stage $stage }
        'Package' { Invoke-Package -Stage $stage }
        'Catalog' { Invoke-Catalog }
    }
}
Write-Host "`nDone: $($tasks -join ', ')" -ForegroundColor Green
