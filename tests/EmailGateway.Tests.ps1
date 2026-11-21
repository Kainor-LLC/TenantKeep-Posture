# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Write = { param([string] $Dir, [string] $Name, $Data) New-Item -ItemType Directory -Path $Dir -Force | Out-Null; ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }
    $script:Checks = {
        param([string] $Dir, [hashtable] $ThirdParty = @{})
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
        $pf = Join-Path $Dir 'profile.json'
        $tp = @{ email = 'none'; training = 'none' }; foreach ($k in $ThirdParty.Keys) { $tp[$k] = $ThirdParty[$k] }
        @{ version = 1; identityModel = 'cloud-only'; licenses = @('MDO2', 'E5'); thirdParty = $tp } | ConvertTo-Json -Depth 4 | Set-Content $pf
        $r = Invoke-PostureChecks -Evidence $Dir -Domain email -ProfilePath $pf -PassThru; $by = @{}; foreach ($x in $r.results) { $by[$x.id] = $x }; $by
    }
    $script:Base = {
        param([string] $Dir, [string] $Mx)
        & $script:Write $Dir 'exo-01-orgconfig' @{ Name = 'contoso' }
        & $script:Write $Dir 'dns-01-mail-records' @(@{ Domain = 'contoso.example'; MX = $Mx; SPF = 'v=spf1 -all'; DMARC = ''; MTASTS = ''; TLSRPT = '' })
        & $script:Write $Dir 'exo-05-mdo-safelinks' @(@{ Name = 'Built-in'; EnableSafeLinksForEmail = $true; EnableSafeLinksForTeams = $true; EnableSafeLinksForOffice = $false })
        & $script:Write $Dir 'exo-05-mdo-safeattachments' @(@{ Name = 'Built-in'; Enable = $true; Action = 'Block' })
        & $script:Write $Dir 'exo-05-mdo-global' @(@{ EnableATPForSPOTeamsODB = $true; EnableSafeDocs = $true })
    }
}

Describe 'A third-party email gateway in front of Microsoft 365' {
    It 'fails when MX points at a gateway and Exchange Online still takes mail from anyone, and passes once it is locked to the gateway' {
        $d = Join-Path $TestDrive 'open'
        & $script:Base $d '10 mx1.pphosted.example'
        & $script:Write $d 'exo-03-inbound-connectors' @()
        $by = & $script:Checks $d
        $by['EM-026'].status | Should -Be 'fail'
        @($by['EM-026'].affected)[0].detail | Should -Match 'nothing stops mail sent straight to Exchange Online'
        & $script:Write $d 'exo-03-inbound-connectors' @(@{ Name = 'From Proofpoint'; Enabled = $true; ConnectorType = 'Partner'; SenderDomains = 'smtp:*;1'; RestrictDomainsToIPAddresses = $true; RestrictDomainsToCertificate = $false })
        (& $script:Checks $d)['EM-026'].status | Should -Be 'pass'
    }

    It 'has nothing to judge when mail comes straight to Microsoft and no vendor is named, and judges a named vendor even with Microsoft MX' {
        $d = Join-Path $TestDrive 'direct'
        & $script:Base $d '0 contoso-example.mail.protection.outlook.com'
        & $script:Write $d 'exo-03-inbound-connectors' @()
        (& $script:Checks $d)['EM-026'].status | Should -Be 'pass'
        (& $script:Checks $d @{ email = 'Proofpoint' })['EM-026'].status | Should -Be 'fail'
    }

    It 'judges files and links in SharePoint, OneDrive, Teams and Office apart from mail, and lets a training vendor cover simulations' {
        $d = Join-Path $TestDrive 'files'
        & $script:Base $d '0 contoso-example.mail.protection.outlook.com'
        & $script:Write $d 'exo-03-inbound-connectors' @()
        $by = & $script:Checks $d @{ email = 'Proofpoint'; training = 'KnowBe4' }
        $by['EM-005'].status | Should -Be 'coveredBy' -Because 'the gateway covers mail'
        $by['EM-027'].status | Should -Be 'fail' -Because 'Safe Links for Office apps is off, and the gateway does not reach files or apps'
        $by['EM-020'].status | Should -Be 'coveredBy'
        $by['EM-020'].reason | Should -Match 'KnowBe4'
    }
}
