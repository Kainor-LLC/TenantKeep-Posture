# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
    InModuleScope Tenantkeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-email-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $script:Write = { param([string] $Dir, [string] $Name, $Data) New-Item -ItemType Directory -Path $Dir -Force | Out-Null; ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }
    $script:Facts = {
        param([string] $Dir, [hashtable] $Thresholds = @{}, [hashtable] $OrgProfile = @{})
        InModuleScope Tenantkeep.Posture -Parameters @{ D = $Dir; T = $Thresholds; P = $OrgProfile } { Get-PostureEmailFact -Evidence $D -OrgProfile $P -Thresholds $T -AsOf ([datetime]::new(2026, 10, 14, 0, 0, 0, [System.DateTimeKind]::Utc)) }
    }
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Get-PostureEmailFact' {
    It 'is unavailable with a reason when no exo file exists' {
        $d = Join-Path $script:Root 'empty'; New-Item -ItemType Directory -Path $d | Out-Null
        $r = & $script:Facts $d
        $r.available | Should -BeFalse
        $r.reason | Should -Match 'Connect-ExchangeOnline'
    }

    It 'grades DMARC against the threshold and SPF against hard fail and the lookup limit' {
        $d = Join-Path $script:Root 'dns'
        & $script:Write $d 'exo-02-accepted-domains' @(@{ DomainName = 'a.example'; DomainType = 'Authoritative' })
        & $script:Write $d 'dns-01-mail-records' @(
            @{ Domain = 'a.example'; MX = '0 x'; SPF = 'v=spf1 include:one.example ~all'; DMARC = 'v=DMARC1; p=quarantine; rua=mailto:d@a.example'; MTASTS = ''; TLSRPT = '' }
            @{ Domain = 'b.example'; MX = '0 x'; SPF = 'v=spf1 include:1 include:2 include:3 include:4 include:5 include:6 include:7 include:8 include:9 a mx -all'; DMARC = 'v=DMARC1; p=reject'; MTASTS = 'v=STSv1; id=1'; TLSRPT = 'v=TLSRPTv1; rua=mailto:t@b.example' }
            @{ Domain = 'c.example'; MX = ''; SPF = ''; DMARC = ''; MTASTS = ''; TLSRPT = '' }
        )
        $strict = (& $script:Facts $d)
        $strict.facts.dmarcGaps | Should -Be 3 -Because 'quarantine is below reject, reject without rua, and none'
        $strict.facts.spfGaps | Should -Be 3 -Because 'soft fail, 11 lookups, missing'
        $strict.facts.mtaStsGaps | Should -Be 2
        @($strict.affected.spfGaps | Where-Object { $_.name -eq 'b.example' })[0].detail | Should -Match '11 lookup'
        $lenient = (& $script:Facts $d @{ minDmarcPolicy = 'quarantine'; spfRequireHardFail = $false })
        $lenient.facts.dmarcGaps | Should -Be 2
        $lenient.facts.spfGaps | Should -Be 2
    }

    It 'joins shared mailboxes to 06-users for the sign-in state and marks EM-018 when users are missing' {
        $d = Join-Path $script:Root 'shared'
        & $script:Write $d 'exo-02-accepted-domains' @(@{ DomainName = 'a.example'; DomainType = 'Authoritative' })
        & $script:Write $d 'exo-09-mailboxes' @(
            @{ UserPrincipalName = 's1@a.example'; RecipientTypeDetails = 'SharedMailbox'; ExternalDirectoryObjectId = 'id1'; ForwardingSmtpAddress = $null; ForwardingAddress = $null }
            @{ UserPrincipalName = 's2@a.example'; RecipientTypeDetails = 'SharedMailbox'; ExternalDirectoryObjectId = 'id2'; ForwardingSmtpAddress = $null; ForwardingAddress = $null }
            @{ UserPrincipalName = 'u@a.example'; RecipientTypeDetails = 'UserMailbox'; ExternalDirectoryObjectId = 'id3'; ForwardingSmtpAddress = 'smtp:x@a.example'; ForwardingAddress = $null }
        )
        $without = & $script:Facts $d
        $without.notEvaluated['EM-018'] | Should -Match '06-users'
        $without.facts.mailboxesForwardingExternally | Should -Be 0 -Because 'the forward targets an accepted domain'
        & $script:Write $d '06-users' @(@{ Id = 'id1'; AccountEnabled = $true }, @{ Id = 'id2'; AccountEnabled = $false }, @{ Id = 'id3'; AccountEnabled = $true })
        $with = & $script:Facts $d
        $with.facts.sharedMailboxesSignInEnabled | Should -Be 1
        $with.affected.sharedMailboxesSignInEnabled[0].name | Should -Be 's1@a.example'
    }

    It 'expects Safe Documents only with E5 or Defender for Endpoint P2 in the profile' {
        $d = Join-Path $script:Root 'mdo'
        & $script:Write $d 'exo-02-accepted-domains' @()
        & $script:Write $d 'exo-05-mdo-safelinks' @(@{ Name = 'p'; EnableSafeLinksForEmail = $true; EnableSafeLinksForTeams = $true; EnableSafeLinksForOffice = $true })
        & $script:Write $d 'exo-05-mdo-safeattachments' @(@{ Name = 'p'; Enable = $true; Action = 'DynamicDelivery' })
        & $script:Write $d 'exo-05-mdo-global' @{ EnableATPForSPOTeamsODB = $true; EnableSafeDocs = $false }
        (& $script:Facts $d @{} @{ licenses = @('BusinessPremium', 'MDO1') }).facts.safeDocumentsExpected | Should -BeFalse
        (& $script:Facts $d @{} @{ licenses = @('E5') }).facts.safeDocumentsExpected | Should -BeTrue
        (& $script:Facts $d).facts.safeAttachmentsEnabled | Should -BeTrue
    }

    It 'counts attack simulations inside the window' {
        $d = Join-Path $script:Root 'sim'
        & $script:Write $d 'exo-02-accepted-domains' @()
        & $script:Write $d 'exo-11-attack-simulations' @(
            @{ DisplayName = 'old'; LaunchDateTime = '2026-01-01T00:00:00Z'; CompletionDateTime = '2026-01-10T00:00:00Z' }
            @{ DisplayName = 'recent'; LaunchDateTime = '2026-09-01T00:00:00Z'; CompletionDateTime = $null }
        )
        $f = (& $script:Facts $d).facts
        $f.attackSimulations | Should -Be 2
        $f.attackSimulationsInWindow | Should -Be 1
    }
}

Describe 'Email catalog' {
    It 'ships 21 email checks with coverage only on the delivery checks' {
        $cat = @(Get-PostureCheckCatalog -Domain email -Full)
        $cat.Count | Should -Be 21
        @($cat | Where-Object { $_.CoveredBy -contains 'email:*' } | ForEach-Object { $_.Id }) | Should -Be @('EM-001', 'EM-002', 'EM-003', 'EM-004', 'EM-005', 'EM-006', 'EM-007')
        @($cat | Where-Object { $_.License -contains 'MDO2' } | ForEach-Object { $_.Id }) | Should -Be @('EM-002', 'EM-004', 'EM-005', 'EM-020')
    }
}
