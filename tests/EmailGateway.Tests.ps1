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

Describe 'Mail DNS records whose lookup failed' {
    BeforeAll {
        $script:Dns = {
            param([string] $Dir, [object[]] $Rows)
            & $script:Write $Dir 'exo-01-orgconfig' @{ Name = 'contoso' }
            & $script:Write $Dir 'exo-03-inbound-connectors' @()
            & $script:Write $Dir 'dns-01-mail-records' $Rows
        }
        $script:Good = @{ MX = '0 contoso-example.mail.protection.outlook.com'; SPF = 'v=spf1 include:spf.protection.outlook.com -all'; DMARC = 'v=DMARC1; p=reject; rua=mailto:dmarc@contoso.example'; MTASTS = 'v=STSv1; id=1'; TLSRPT = 'v=TLSRPTv1; rua=mailto:tls@contoso.example' }
        $script:Row = { param([string] $Domain, [hashtable] $Change = @{}) $r = @{ Domain = $Domain; LookupFailed = '' }; foreach ($k in $script:Good.Keys) { $r[$k] = $script:Good[$k] }; foreach ($k in $Change.Keys) { $r[$k] = $Change[$k] }; $r }
    }

    It 'does not call a record missing when DNS did not answer: the check has no answer yet, and says for which domain' {
        $d = Join-Path $TestDrive 'dns-unknown'
        & $script:Dns $d @((& $script:Row 'contoso.example'), (& $script:Row 'fabrikam.example' @{ DMARC = ''; LookupFailed = 'DMARC' }))
        $by = & $script:Checks $d
        $by['EM-013'].status | Should -Be 'notEvaluated' -Because 'an empty DMARC from a lookup that timed out used to read as "no DMARC record"'
        $by['EM-013'].reason | Should -Match 'DNS lookup failed for 1 domain\(s\) \(fabrikam\.example\)'
        $by['EM-014'].status | Should -Be 'pass' -Because 'the SPF lookups all answered'
        $by['EM-015'].status | Should -Be 'pass'
    }

    It 'still fails on a gap it did see, whatever else did not answer' {
        $d = Join-Path $TestDrive 'dns-gap'
        & $script:Dns $d @((& $script:Row 'contoso.example' @{ DMARC = '' }), (& $script:Row 'fabrikam.example' @{ DMARC = ''; SPF = ''; LookupFailed = 'DMARC;SPF' }))
        $by = & $script:Checks $d
        $by['EM-013'].status | Should -Be 'fail'
        @($by['EM-013'].affected).name | Should -Be @('contoso.example') -Because 'only the domain that answered with no record is a finding'
        $by['EM-014'].status | Should -Be 'notEvaluated'
    }

    It 'cannot say there is no gateway when the MX lookup failed and the profile names no vendor' {
        $d = Join-Path $TestDrive 'dns-mx'
        & $script:Dns $d @((& $script:Row 'contoso.example' @{ MX = ''; LookupFailed = 'MX' }))
        (& $script:Checks $d)['EM-026'].status | Should -Be 'notEvaluated'
        (& $script:Checks $d @{ email = 'proofpoint' })['EM-026'].status | Should -Be 'fail' -Because 'a named vendor is a gateway in front whatever DNS says, and nothing locks Exchange Online to it'
    }

    It 'reads evidence from before the lookups were recorded as before' {
        $d = Join-Path $TestDrive 'dns-old'
        $old = & $script:Row 'contoso.example' @{ DMARC = '' }; $old.Remove('LookupFailed')
        & $script:Dns $d @($old)
        (& $script:Checks $d)['EM-013'].status | Should -Be 'fail'
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
