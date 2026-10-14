#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
Set-StrictMode -Version Latest

$script:ModuleRoot    = $PSScriptRoot
$script:ModuleVersion = (Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'Tenantkeep.Posture.psd1')).ModuleVersion
# Graph API versions used by the current run, recorded into metadata.json (CLAUDE.md: pin every API version).
$script:GraphApiVersionsUsed = [System.Collections.Generic.HashSet[string]]::new()

$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue)
$public  = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in ($private + $public)) {
    try { . $file.FullName }
    catch { throw "Failed to load $($file.FullName): $($_.Exception.Message)" }
}

Export-ModuleMember -Function @($public | ForEach-Object BaseName)
