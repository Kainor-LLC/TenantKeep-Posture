#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
  Build script for Tenantkeep.Posture.
.DESCRIPTION
  Tasks: Analyze, Test, Build, Sign, Package. Sign and Package refuse to run without a code-signing certificate.
  Authenticode signing is Windows-only; Analyze, Test and Build run everywhere.
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
    [ValidateSet('Analyze', 'Test', 'Build', 'Sign', 'Package', 'Clean')]
    [string[]] $Task = @('Analyze', 'Test'),

    [string] $CertificateThumbprint = $env:TENANTKEEP_SIGNING_THUMBPRINT,
    [string] $CertificatePath       = $env:TENANTKEEP_SIGNING_PFX,
    [string] $TimestampServer       = 'http://timestamp.digicert.com',

    [switch] $SkipInstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root       = $PSScriptRoot
$ModuleName = 'Tenantkeep.Posture'
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

function Invoke-Clean {
    Write-Task 'Clean'
    if (Test-Path $OutRoot) { Remove-Item -LiteralPath $OutRoot -Recurse -Force }
}

function Invoke-Analyze {
    Write-Task 'Analyze'
    Install-BuildDependency -Name PSScriptAnalyzer -MinimumVersion 1.22.0
    Import-Module PSScriptAnalyzer
    $settings = Join-Path $Root 'PSScriptAnalyzerSettings.psd1'
    $paths = @($SrcPath, (Join-Path $Root 'tests'), (Join-Path $Root '.githooks'), (Join-Path $Root 'build.ps1'))
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
    foreach ($data in 'checks', 'baselines') {
        $src = Join-Path $Root $data
        if (Test-Path $src) { Copy-Item -Path $src -Destination (Join-Path $stage $data) -Recurse -Exclude '.gitkeep' }
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

function Invoke-Package {
    param([string] $Stage)
    Write-Task 'Package'
    $version = Get-ModuleVersion
    $zip = Join-Path $OutRoot "$ModuleName-$version.zip"
    if (Test-Path $zip) { Remove-Item -LiteralPath $zip -Force }
    Compress-Archive -Path (Join-Path $OutRoot $ModuleName) -DestinationPath $zip
    $hash = (Get-FileHash -Path $zip -Algorithm SHA256).Hash
    Set-Content -Path "$zip.sha256" -Value "$hash  $(Split-Path $zip -Leaf)"
    Write-Host "Packaged $zip`nSHA256 $hash"
}

# Package implies Build and Sign. Sign implies Build. The cert check runs first so a missing cert fails fast.
$tasks = [System.Collections.Generic.List[string]]::new($Task)
if ($tasks -contains 'Package' -and $tasks -notcontains 'Sign') { $tasks.Add('Sign') }
if ($tasks -contains 'Sign'    -and $tasks -notcontains 'Build') { $tasks.Add('Build') }
if ($tasks -contains 'Sign') { $null = Get-SigningCertificate }

$stage = $null
foreach ($t in @('Clean', 'Analyze', 'Test', 'Build', 'Sign', 'Package')) {
    if ($tasks -notcontains $t) { continue }
    switch ($t) {
        'Clean' { Invoke-Clean }
        'Analyze' { Invoke-Analyze }
        'Test' { Invoke-Test }
        'Build' { $stage = Invoke-Build }
        'Sign' { Invoke-Sign -Stage $stage }
        'Package' { Invoke-Package -Stage $stage }
    }
}
Write-Host "`nDone: $($tasks -join ', ')" -ForegroundColor Green
