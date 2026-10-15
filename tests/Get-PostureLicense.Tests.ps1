# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force   # a fresh import: no entitlement override from earlier files
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-lic-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root -Force | Out-Null
    # A throwaway key pair: the module is told to trust it through the private -PublicKeys parameter only.
    $k = [System.Security.Cryptography.ECDsa]::Create(); $k.GenerateKey([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $script:PrivatePem = Join-Path $script:Root 'test.private.pem'
    [System.IO.File]::WriteAllText($script:PrivatePem, $k.ExportECPrivateKeyPem())
    $script:Keys = @{ 'test-key' = $k.ExportSubjectPublicKeyInfoPem() }
    $script:Issuer = Join-Path $PSScriptRoot '..' 'deploy' 'licensing' 'New-PostureLicense.ps1'
    $script:Tenant = 'aaaaaaaa-1111-2222-3333-444444444444'
    $script:Lic = & $script:Issuer -TenantId $script:Tenant -Tier full -Customer 'Contoso Ltd' -KeyId test-key -PrivateKeyPath $script:PrivatePem -OutputPath (Join-Path $script:Root 'tenantkeep.lic')
    $script:Ev = Join-Path $script:Root 'evidence'; New-Item -ItemType Directory -Path $script:Ev | Out-Null
    @{ tenantId = $script:Tenant; timestampUtc = [datetime]::UtcNow.ToString('o'); collectors = @('Entra') } | ConvertTo-Json | Set-Content (Join-Path $script:Ev 'collection.json')
}
AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Licence verification (offline, ECDSA P-256)' {
    It 'accepts a licence the issuer signed, for its tenant, before expiry' {
        InModuleScope Tenantkeep.Posture -Parameters @{ P = $script:Lic; T = $script:Tenant; K = $script:Keys } {
            $r = Test-PostureLicense -Path $P -TenantId $T -PublicKeys $K
            $r.valid | Should -BeTrue -Because $r.reason
            $r.tier | Should -Be 'full'
            $r.licence.customer | Should -Be 'Contoso Ltd'
        }
    }
    It 'rejects it for another tenant, after expiry, and when any field is edited' {
        InModuleScope Tenantkeep.Posture -Parameters @{ P = $script:Lic; T = $script:Tenant; K = $script:Keys; Root = $script:Root } {
            (Test-PostureLicense -Path $P -TenantId 'bbbbbbbb-1111-2222-3333-444444444444' -PublicKeys $K).reason | Should -Match 'not bbbbbbbb'
            (Test-PostureLicense -Path $P -TenantId $T -AsOfUtc ([datetime]::UtcNow.AddYears(2)) -PublicKeys $K).reason | Should -Match 'expired'
            $doc = Get-Content -Raw $P | ConvertFrom-Json -AsHashtable
            foreach ($edit in @(@{ tenantId = 'bbbbbbbb-1111-2222-3333-444444444444' }, @{ tier = 'full'; expiresUtc = [datetime]::UtcNow.AddYears(20).ToString('o') }, @{ customer = 'Someone else' })) {
                $copy = Get-Content -Raw $P | ConvertFrom-Json -AsHashtable
                foreach ($field in $edit.Keys) { $copy.licence[$field] = $edit[$field] }   # not $k: that is the key table (PowerShell variables are case-insensitive)
                $f = Join-Path $Root "edited-$([guid]::NewGuid().ToString('n')).lic"
                $copy | ConvertTo-Json -Depth 5 | Set-Content $f
                $tenant = [string]$copy.licence.tenantId
                $r = Test-PostureLicense -Path $f -TenantId $tenant -PublicKeys $K
                $r.valid | Should -BeFalse -Because "editing $($edit.Keys -join ',') must break the signature"
                $r.reason | Should -Match 'signature'
            }
            $doc.licence.keyId | Should -Be 'test-key'
        }
    }
    It 'rejects a licence signed by a key the module does not trust (the shipped table has no test key)' {
        InModuleScope Tenantkeep.Posture -Parameters @{ P = $script:Lic; T = $script:Tenant } {
            (Test-PostureLicense -Path $P -TenantId $T).reason | Should -Match 'unknown key'
        }
    }
    It 'the shipped public key table holds PEM public keys only' {
        InModuleScope Tenantkeep.Posture {
            $script:PostureLicenceKeys.Count | Should -BeGreaterThan 0
            foreach ($k in $script:PostureLicenceKeys.Keys) { $script:PostureLicenceKeys[$k] | Should -Match '^-----BEGIN PUBLIC KEY-----' ; $script:PostureLicenceKeys[$k] | Should -Not -Match 'PRIVATE' }
        }
    }
}

Describe 'Entitlement gate' {
    It 'without a licence only the Conditional Access domain is evaluated and the run records why' {
        $env:TENANTKEEP_LICENSE = $null
        $run = Invoke-PostureChecks -Evidence $script:Ev -Domain ca, identity -PassThru
        $run.entitlement.licensed | Should -BeFalse
        $run.entitlement.reason | Should -Match 'No licence file'
        @($run.results | Where-Object { $_.domain -eq 'identity' -and $_.status -ne 'notEvaluated' }).Count | Should -Be 0
        @($run.results | Where-Object { $_.domain -eq 'identity' })[0].reason | Should -Match 'Not licensed'
        @($run.results | Where-Object { $_.domain -eq 'ca' -and $_.reason -match 'Not licensed' }).Count | Should -Be 0 -Because 'the Conditional Access domain is free'
    }
    It 'with a trusted full licence every domain is evaluated' {
        InModuleScope Tenantkeep.Posture -Parameters @{ K = $script:Keys } { $script:PostureLicenceKeys['test-key'] = $K['test-key'] }   # trust the test key for this one test
        try {
            $run = Invoke-PostureChecks -Evidence $script:Ev -Domain ca, identity -LicensePath $script:Lic -PassThru
            $run.entitlement.licensed | Should -BeTrue -Because $run.entitlement.reason
            $run.entitlement.tier | Should -Be 'full'
            $run.entitlement.customer | Should -Be 'Contoso Ltd'
            @($run.results | Where-Object { $_.domain -eq 'identity' -and $_.reason -match 'Not licensed' }).Count | Should -Be 0
            (Get-PostureLicense -Path $script:Lic -Evidence $script:Ev).Valid | Should -BeTrue
        }
        finally { InModuleScope Tenantkeep.Posture { $script:PostureLicenceKeys.Remove('test-key') } }
    }
    It 'Get-PostureLicense reports a missing file and an untrusted key in plain words' {
        (Get-PostureLicense -Path (Join-Path $script:Root 'nope.lic') -TenantId $script:Tenant).Reason | Should -Match 'No licence file'
        (Get-PostureLicense -Path $script:Lic -TenantId $script:Tenant).Reason | Should -Match 'unknown key'
    }
}
