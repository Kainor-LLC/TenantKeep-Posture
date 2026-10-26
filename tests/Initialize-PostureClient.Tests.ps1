# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-init-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root -Force | Out-Null
    $k = [System.Security.Cryptography.ECDsa]::Create(); $k.GenerateKey([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $script:PrivatePem = Join-Path $script:Root 'test.private.pem'
    [System.IO.File]::WriteAllText($script:PrivatePem, $k.ExportECPrivateKeyPem())
    $script:PublicPem = $k.ExportSubjectPublicKeyInfoPem()
    $script:Tenant = 'aaaaaaaa-1111-2222-3333-444444444444'
    $issuer = Join-Path $PSScriptRoot '..' 'deploy' 'licensing' 'New-PostureLicense.ps1'
    $script:Lic = & $issuer -TenantId $script:Tenant -Tier full -Customer 'Contoso Ltd' -KeyId test-key -PrivateKeyPath $script:PrivatePem -OutputPath (Join-Path $script:Root 'download' 'tenantkeep.lic')
    # The module trusts the throwaway key for the duration of this file only.
    InModuleScope TenantKeep.Posture -Parameters @{ Pem = $script:PublicPem } { $script:PostureLicenceKeys['test-key'] = $Pem }
}

AfterAll {
    InModuleScope TenantKeep.Posture { $script:PostureLicenceKeys.Remove('test-key') }
    Remove-Module TenantKeep.Posture -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Initialize-PostureClient' {
    It 'creates the folder, copies a valid licence in, seeds the profile from it and says what to run next' {
        $target = Join-Path $script:Root 'clients' 'contoso'
        $r = Initialize-PostureClient -Path $target -LicensePath $script:Lic -PassThru
        $r.Path | Should -Be $target
        $r.TenantId | Should -Be $script:Tenant
        $r.ClientName | Should -Be 'Contoso Ltd'
        $r.Licence.Valid | Should -BeTrue -Because $r.Licence.Reason
        $r.Licence.Tier | Should -Be 'full'
        $r.Next | Should -Be "Start-PostureRun -Client '$target' -TenantId $($script:Tenant)"
        Join-Path $target 'tenantkeep.lic' | Should -Exist
        Join-Path $target 'imports' | Should -Exist
        Join-Path $target 'hybrid' | Should -Exist
        $seed = Get-Content -Raw (Join-Path $target 'profile.json') | ConvertFrom-Json -AsHashtable
        $seed.tenantId | Should -Be $script:Tenant
        $seed.clientName | Should -Be 'Contoso Ltd'
    }

    It 'names the default folder after the licence customer under ~/tenantkeep/clients' {
        $saved = $HOME
        try {
            Set-Variable -Name HOME -Value (Join-Path $script:Root 'home') -Scope Global -Force
            $r = Initialize-PostureClient -LicensePath $script:Lic -PassThru
            $r.Path | Should -Be (Join-Path $script:Root 'home' 'tenantkeep' 'clients' 'contoso-ltd')
        }
        finally { Set-Variable -Name HOME -Value $saved -Scope Global -Force }
    }

    It 'refuses an unusable licence before writing anything, and needs a name when there is none' {
        $target = Join-Path $script:Root 'clients' 'wrong-tenant'
        { Initialize-PostureClient -Path $target -LicensePath $script:Lic -TenantId 'bbbbbbbb-1111-2222-3333-444444444444' } | Should -Throw '*not usable*'
        $target | Should -Not -Exist
        { Initialize-PostureClient } | Should -Throw '*-Path, or -ClientName*'
        { Initialize-PostureClient -LicensePath (Join-Path $script:Root 'missing.lic') } | Should -Throw '*No licence file*'
    }

    It 'works without a licence, reports the free tier, and keeps an existing profile unless it belongs to another tenant' {
        $target = Join-Path $script:Root 'clients' 'free'
        $r = Initialize-PostureClient -Path $target -ClientName 'Free Co' -TenantId $script:Tenant -PassThru
        $r.Licence.Valid | Should -BeFalse
        $r.Licence.Tier | Should -Be 'none'
        Join-Path $target 'tenantkeep.lic' | Should -Not -Exist
        (Get-Content -Raw (Join-Path $target 'profile.json') | ConvertFrom-Json -AsHashtable).clientName | Should -Be 'Free Co'
        Set-Content -LiteralPath (Join-Path $target 'profile.json') -Value (@{ tenantId = $script:Tenant; clientName = 'Edited' } | ConvertTo-Json)
        $null = Initialize-PostureClient -Path $target -ClientName 'Free Co' -TenantId $script:Tenant -PassThru
        (Get-Content -Raw (Join-Path $target 'profile.json') | ConvertFrom-Json -AsHashtable).clientName | Should -Be 'Edited' -Because 'an existing profile is left alone'
        { Initialize-PostureClient -Path $target -TenantId 'bbbbbbbb-1111-2222-3333-444444444444' } | Should -Throw '*already belongs to tenant*'
    }

    It 'supports -WhatIf without creating the folder' {
        $target = Join-Path $script:Root 'clients' 'whatif'
        Initialize-PostureClient -Path $target -ClientName 'X' -WhatIf
        $target | Should -Not -Exist
    }
}
