# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-integrity-$([guid]::NewGuid().ToString('n'))"
    $script:Copy = Join-Path $script:Root 'Tenantkeep.Posture'
    New-Item -ItemType Directory -Path $script:Root -Force | Out-Null
    Copy-Item -Path (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture') -Destination $script:Copy -Recurse
    $k = [System.Security.Cryptography.ECDsa]::Create(); $k.GenerateKey([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $script:Pem = Join-Path $script:Root 'k.pem'; [System.IO.File]::WriteAllText($script:Pem, $k.ExportECPrivateKeyPem())
    $script:Keys = @{ 'test-key' = $k.ExportSubjectPublicKeyInfoPem() }
}
AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Build integrity manifest' {
    It 'a source checkout is a development build' {
        InModuleScope Tenantkeep.Posture -Parameters @{ M = $script:Copy } { (Test-PostureIntegrity -ModuleRoot $M).state | Should -Be 'development' }
        InModuleScope Tenantkeep.Posture { $script:PostureBuildState.state | Should -BeIn @('development', 'release') }
    }
    It 'a signed manifest over an intact folder is a release; an edited, added or removed file is a modified build; an untrusted key is modified' {
        InModuleScope Tenantkeep.Posture -Parameters @{ M = $script:Copy; Pem = $script:Pem; K = $script:Keys } {
            $path = New-PostureIntegrityManifest -ModuleRoot $M -KeyId test-key -PrivateKeyPath $Pem
            $path | Should -Exist
            $r = Test-PostureIntegrity -ModuleRoot $M -PublicKeys $K
            $r.state | Should -Be 'release' -Because $r.detail
            (Test-PostureIntegrity -ModuleRoot $M).state | Should -Be 'modified' -Because 'the shipped key table does not trust the test key'
            $target = Join-Path $M 'Private' 'Test-PostureLicense.ps1'
            Add-Content -LiteralPath $target -Value '# edited'
            $r2 = Test-PostureIntegrity -ModuleRoot $M -PublicKeys $K
            $r2.state | Should -Be 'modified'; $r2.changed | Should -Contain 'Private/Test-PostureLicense.ps1 (changed)'
            Set-Content -LiteralPath (Join-Path $M 'extra.ps1') -Value '# added'
            (Test-PostureIntegrity -ModuleRoot $M -PublicKeys $K).changed | Should -Contain 'extra.ps1 (added)'
            Remove-Item -LiteralPath (Join-Path $M 'extra.ps1')
            Remove-Item -LiteralPath (Join-Path $M 'Public' 'Get-PostureLicense.ps1')
            (Test-PostureIntegrity -ModuleRoot $M -PublicKeys $K).changed | Should -Contain 'Public/Get-PostureLicense.ps1 (removed)'
            $doc = Get-Content -Raw $path | ConvertFrom-Json -AsHashtable; $doc.files['Public/Get-PostureLicense.ps1'] = 'deadbeef'
            $doc | ConvertTo-Json -Depth 5 | Set-Content $path
            (Test-PostureIntegrity -ModuleRoot $M -PublicKeys $K).detail | Should -Match 'signature does not match'
        }
    }
}
