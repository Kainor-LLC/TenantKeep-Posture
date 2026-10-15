# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-profile-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $script:Skus = @(
        @{ skuPartNumber = 'SPB'; consumedUnits = 12; servicePlans = @(@{ servicePlanName = 'AAD_PREMIUM' }, @{ servicePlanName = 'INTUNE_A' }, @{ servicePlanName = 'ATP_ENTERPRISE' }, @{ servicePlanName = 'MDE_SMB' }, @{ servicePlanName = 'EXCHANGE_S_STANDARD' }) }
        @{ skuPartNumber = 'AAD_PREMIUM_P2'; consumedUnits = 2; servicePlans = @(@{ servicePlanName = 'AAD_PREMIUM_P2' }, @{ servicePlanName = 'AAD_PREMIUM' }) }
    )
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
}

Describe 'Get-PostureLicenseToken' {
    It 'expands bundles into the tokens the catalog gates on' {
        InModuleScope Tenantkeep.Posture -Parameters @{ S = $script:Skus } {
            Get-PostureLicenseToken -Sku $S | Should -Be @('BusinessPremium', 'Intune', 'MDEBusiness', 'MDO1', 'P1', 'P2')
        }
    }

    It 'reads the audit plan CSV-shaped rows too' {
        InModuleScope Tenantkeep.Posture {
            $rows = @(@{ SkuPartNumber = 'SPE_E5'; ServicePlans = 'AAD_PREMIUM;AAD_PREMIUM_P2;WINDEFATP;THREAT_INTELLIGENCE;INTUNE_A;MIP_S_CLP2' })
            Get-PostureLicenseToken -Sku $rows | Should -Be @('E5', 'Intune', 'MDE2', 'MDO2', 'P1', 'P2', 'Purview')
            Get-PostureLicenseToken -Sku @() | Should -BeNullOrEmpty
        }
    }
}

Describe 'New-PostureProfile' {
    Context 'non-interactive' {
        It 'writes defaults plus parameters and reads back through Import-PostureProfile' {
            $path = Join-Path $script:Root 'a' 'profile.json'
            $out = New-PostureProfile -Path $path -NonInteractive -Licenses P1, Intune -Platforms windows, macOS -BreakGlass 'bg01@contoso.example' -Thresholds @{ namePattern = '^CA\d{3} - '; maxExclusionGroupMembers = 10 } -ThirdParty @{ mfa = 'duo' } -Frameworks cisa-scuba -ClientName 'Contoso Ltd'
            $out | Should -Be $path
            $j = Get-Content -Raw $path | ConvertFrom-Json
            $j.version | Should -Be 1
            $j.clientName | Should -Be 'Contoso Ltd'
            $j.licenses | Should -Be @('P1', 'Intune')
            $j.platforms | Should -Be @('windows', 'macOS')
            $j.identityModel | Should -Be 'cloud-only'
            $j.thirdParty.mfa | Should -Be 'duo'
            $j.thirdParty.edr | Should -Be 'none'
            $j.frameworks | Should -Be @('cisa-scuba')
            $j.thresholds.namePattern | Should -Be '^CA\d{3} - '
            $j.thresholds.maxExclusionGroupMembers | Should -Be 10
            $j.thresholds.reportOnlyMaxDays | Should -Be 90
            $j.breakGlass | Should -Be @('bg01@contoso.example')
            $j.licensesSource | Should -Be 'manual'
            InModuleScope Tenantkeep.Posture -Parameters @{ P = $path } {
                $m = Import-PostureProfile -Path $P
                $m.present | Should -BeTrue
                $m.licenses | Should -Be @('P1', 'Intune')
                $m.thresholds.namePattern | Should -Be '^CA\d{3} - '
                $m.breakGlass | Should -Be @('bg01@contoso.example')
            }
        }

        It 'edits an existing file: unspecified answers survive, createdUtc is kept' {
            $path = Join-Path $script:Root 'a' 'profile.json'
            $before = (Get-Content -Raw $path | ConvertFrom-Json).createdUtc
            $null = New-PostureProfile -Path $path -NonInteractive -Copilot pilot
            $j = Get-Content -Raw $path | ConvertFrom-Json
            $j.copilot | Should -Be 'pilot'
            $j.licenses | Should -Be @('P1', 'Intune')
            $j.breakGlass | Should -Be @('bg01@contoso.example')
            $j.createdUtc | Should -Be $before
        }

        It 'expands a tilde in -Path, because the file writer does not' {
            $rel = "~/.tkp-test-$([guid]::NewGuid().ToString('n'))"
            $expected = Join-Path $HOME ($rel.Substring(2)) 'profile.json'
            try {
                $out = New-PostureProfile -Path "$rel/profile.json" -NonInteractive -ClientName 'Tilde' -SharePointClientId '89ebfc90-bbac-49ad-a8f3-b81a29737495' -TenantId '11111111-2222-3333-4444-555555555555'
                $out | Should -Be $expected
                $written = Get-Content -Raw $expected | ConvertFrom-Json
                $written.sharePointClientId | Should -Be '89ebfc90-bbac-49ad-a8f3-b81a29737495'
                $written.tenantId | Should -Be '11111111-2222-3333-4444-555555555555'
            }
            finally { Remove-Item -LiteralPath (Join-Path $HOME ($rel.Substring(2))) -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'discovers licenses, platforms, identity model, BYOD, collaboration, Copilot, tenant and name from an evidence folder, and asks only the rest' {
            $ev = Join-Path $script:Root 'discover'
            New-Item -ItemType Directory -Path $ev -Force | Out-Null
            $w = { param([string] $Name, $Data) ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $ev "$Name.json") }
            & $w 'collection' @{ tenantId = '11111111-2222-3333-4444-555555555555' }
            & $w '01-organization' @(@{ id = 't'; displayName = 'Contoso Ltd'; onPremisesSyncEnabled = $true })
            & $w '01-domains' @(@{ Id = 'contoso.example'; AuthenticationType = 'Federated'; IsVerified = $true }, @{ Id = 'contoso.onmicrosoft.com'; AuthenticationType = 'Managed'; IsVerified = $true })
            & $w '01-subscribed-skus' @(
                @{ skuPartNumber = 'SPE_E5'; consumedUnits = 400; servicePlans = @(@{ servicePlanName = 'AAD_PREMIUM_P2' }, @{ servicePlanName = 'INTUNE_A' }, @{ servicePlanName = 'THREAT_INTELLIGENCE' }, @{ servicePlanName = 'WINDEFATP' }) }
                @{ skuPartNumber = 'Microsoft_365_Copilot'; consumedUnits = 40; servicePlans = @(@{ servicePlanName = 'M365_COPILOT' }) }
            )
            & $w '09-intune-managed-devices' (@(1..60 | ForEach-Object { @{ OperatingSystem = 'Windows'; ManagedDeviceOwnerType = 'company' } }) + @(1..6 | ForEach-Object { @{ OperatingSystem = 'macOS'; ManagedDeviceOwnerType = 'company' } }) + @(@{ OperatingSystem = 'iOS'; ManagedDeviceOwnerType = 'personal' }))
            & $w '08-entra-devices' (@(1..30 | ForEach-Object { @{ OperatingSystem = 'IPhone' } }) + @(@{ OperatingSystem = 'Android' }, @{ OperatingSystem = 'Linux' }))
            & $w '09-intune-app-protection-policies' @(@{ Type = 'iosManagedAppProtection'; IsAssigned = $true })
            & $w '06-users-summary' @{ Total = 420; Members = 400; Guests = 20 }
            & $w 'spo-tenant-settings' @{ SharingCapability = 'ExternalUserSharingOnly'; ExternalUserExpirationRequired = $true; SharingDomainRestrictionMode = 'None' }
            $path = Join-Path $script:Root 'discovered-profile.json'
            $p = New-PostureProfile -Path $path -NonInteractive -Evidence $ev -Platforms windows, macOS, iOS, android -PassThru 6>$null
            @($p.licenses) | Should -Contain 'Copilot'
            @($p.licenses) | Should -Contain 'SAM' -Because 'Copilot includes SharePoint Advanced Management'
            @($p.platforms) | Should -Be @('windows', 'macOS', 'iOS', 'android') -Because 'the parameter wins over discovery'
            $p.identityModel | Should -Be 'hybrid-adfs'
            $p.byod | Should -Be 'mam'
            $p.externalCollaboration | Should -Be 'governed'
            $p.copilot | Should -Be 'pilot' -Because '40 seats for 400 members'
            $p.tenantId | Should -Be '11111111-2222-3333-4444-555555555555'
            $p.clientName | Should -Be 'Contoso Ltd'
            @($p.discovery.keys) | Should -Not -Contain 'platforms'
            @($p.discovery.keys) | Should -Contain 'identityModel'
            $p.discovery.sources.identityModel | Should -Match 'federated=1'
            InModuleScope Tenantkeep.Posture -Parameters @{ Ev = $ev } {
                $d = Get-PostureProfileDiscovery -Evidence $Ev
                @($d.facts.platforms) | Should -Be @('iOS', 'macOS', 'windows') -Because 'Android and Linux have one device each, under the floor'
            }
        }

        It 'detects licenses from an evidence folder' {
            $ev = Join-Path $script:Root 'evidence'
            New-Item -ItemType Directory -Path $ev | Out-Null
            ConvertTo-Json -InputObject @(@{ SkuPartNumber = 'SPE_E3'; ServicePlans = 'AAD_PREMIUM;INTUNE_A' }) -Depth 5 | Set-Content (Join-Path $ev '01-subscribed-skus.json')
            $p = New-PostureProfile -Path (Join-Path $script:Root 'b.json') -NonInteractive -Evidence $ev -PassThru
            $p.licenses | Should -Be @('E3', 'Intune', 'P1')
            $p.licensesSource | Should -Match '^evidence:'
        }

        It 'detects licenses from Graph with a read-only scope' {
            Mock -ModuleName Tenantkeep.Posture Get-MgContext { [pscustomobject]@{ TenantId = 't'; Account = 'a'; AuthType = 'Delegated'; Scopes = @('Organization.Read.All') } }
            Mock -ModuleName Tenantkeep.Posture Invoke-MgGraphRequest { @{ value = $script:Skus } }
            $p = New-PostureProfile -Path (Join-Path $script:Root 'c.json') -NonInteractive -FromGraph -PassThru
            $p.licenses | Should -Contain 'BusinessPremium'
            $p.licensesSource | Should -Match '^graph:\d{4}-\d{2}-\d{2}$'
            Should -Invoke -ModuleName Tenantkeep.Posture Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/subscribedSkus' }
        }

        It 'refuses -FromGraph without a suitable scope' {
            Mock -ModuleName Tenantkeep.Posture Get-MgContext { [pscustomobject]@{ TenantId = 't'; Account = 'a'; AuthType = 'Delegated'; Scopes = @('User.Read') } }
            { New-PostureProfile -Path (Join-Path $script:Root 'd.json') -NonInteractive -FromGraph } | Should -Throw '*needs one of: Organization.Read.All, Directory.Read.All*'
        }

        It 'honours -WhatIf' {
            $path = Join-Path $script:Root 'whatif.json'
            New-PostureProfile -Path $path -NonInteractive -WhatIf
            $path | Should -Not -Exist
        }
    }

    Context 'interactive' {
        It 'asks every question with defaults and writes the answers' {
            Mock -ModuleName Tenantkeep.Posture Read-PostureAnswer {
                switch -Wildcard ($Question) {
                    'Client or tenant*' { 'Fabrikam' }
                    'Licenses present*' { @('E5', 'P2') }
                    'Platforms in scope*' { @('windows', 'linux') }
                    'Identity model*' { 'hybrid-connect' }
                    'Third-party edr*' { 'sentinelone' }
                    'Regulated frameworks*' { @('hipaa', 'iso27001') }
                    'Threshold maxPermanentGlobalAdmins*' { '4' }
                    'Threshold namePattern*' { '^CA-' }
                    'Break-glass*' { @('bg@fabrikam.example') }
                    default { $Default }
                }
            }
            $p = New-PostureProfile -Path (Join-Path $script:Root 'i.json') -PassThru
            $p.clientName | Should -Be 'Fabrikam'
            $p.licenses | Should -Be @('E5', 'P2')
            $p.platforms | Should -Be @('windows', 'linux')
            $p.identityModel | Should -Be 'hybrid-connect'
            $p.byod | Should -Be 'mam'
            $p.thirdParty.edr | Should -Be 'sentinelone'
            $p.thirdParty.mfa | Should -Be 'none'
            $p.frameworks | Should -Be @('hipaa', 'iso27001')
            $p.thresholds.maxPermanentGlobalAdmins | Should -Be 4
            $p.thresholds.namePattern | Should -Be '^CA-'
            $p.thresholds.staleDeviceDays | Should -Be 90
            $p.breakGlass | Should -Be @('bg@fabrikam.example')
            Should -Invoke -ModuleName Tenantkeep.Posture Read-PostureAnswer -Times 26 -Exactly -Because 'client, licenses, platforms, identity, byod, external, copilot, azure, six third-party categories, frameworks, eight thresholds, break-glass, audience, cadence'
        }

        It 'asks before overwriting and respects no' {
            $path = Join-Path $script:Root 'i.json'
            Mock -ModuleName Tenantkeep.Posture Read-PostureAnswer { if ($Question -like 'Overwrite*') { 'no' } else { $Default } }
            $stamp = (Get-Item $path).LastWriteTimeUtc
            $out = New-PostureProfile -Path $path -WarningAction SilentlyContinue
            $out | Should -BeNullOrEmpty
            (Get-Item $path).LastWriteTimeUtc | Should -Be $stamp
        }
    }
}

Describe 'Read-PostureAnswer' {
    It 'validates choices, takes the default on empty input, splits lists' {
        InModuleScope Tenantkeep.Posture {
            Mock Read-Host { '' }
            Read-PostureAnswer -Question 'q' -Choices @('a', 'b') -Default 'b' | Should -Be 'b'
            Mock Read-Host { 'A' }
            Read-PostureAnswer -Question 'q' -Choices @('a', 'b') -Default 'b' | Should -Be 'a' -Because 'the canonical spelling comes back'
            Mock Read-Host { 'a, b ,b' }
            Read-PostureAnswer -Question 'q' -Choices @('a', 'b') -Default @() -Multi | Should -Be @('a', 'b', 'b')
            $script:Calls = 0
            Mock Read-Host { $script:Calls++; if ($script:Calls -eq 1) { 'zzz' } else { 'a' } }
            Read-PostureAnswer -Question 'q' -Choices @('a', 'b') -Default 'b' | Should -Be 'a' -Because 'an invalid answer re-asks'
        }
    }
}
