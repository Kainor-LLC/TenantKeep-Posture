#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
Set-StrictMode -Version Latest

$script:ModuleRoot    = $PSScriptRoot
$script:ModuleVersion = (Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'TenantKeep.Posture.psd1')).ModuleVersion
# Graph API versions used by the current run, recorded into metadata.json (CLAUDE.md: pin every API version).
$script:GraphApiVersionsUsed = [System.Collections.Generic.HashSet[string]]::new()
# The one sign-in (Connect-PostureSession): refresh token and per-resource access tokens, in memory only.
$script:PostureSession = $null

$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue)
$public  = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in ($private + $public)) {
    try { . $file.FullName }
    catch { throw "Failed to load $($file.FullName): $($_.Exception.Message)" }
}

# Build integrity state, printed in every report header (Test-PostureIntegrity). A failure to compute it reads as modified.
try { $script:PostureBuildState = Test-PostureIntegrity -ModuleRoot $PSScriptRoot }
catch { $script:PostureBuildState = @{ state = 'modified'; detail = "Modified build: integrity could not be checked ($($_.Exception.Message))."; version = $script:ModuleVersion; changed = @() } }

Export-ModuleMember -Function @($public | ForEach-Object BaseName)
