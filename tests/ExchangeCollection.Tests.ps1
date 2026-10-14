# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
    . (Join-Path $PSScriptRoot 'Fixtures' 'ExchangeFixture.ps1')
    . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-exo-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $env:TKP_EXO_FIXTURE = (Join-Path $PSScriptRoot 'Fixtures' 'ExchangeFixture.ps1')

    Mock -ModuleName Tenantkeep.Posture Get-MgContext { [pscustomobject]@{ TenantId = 'tenant-guid'; Account = 'reader@contoso.example'; AuthType = 'Delegated'; Scopes = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All') } }
    Mock -ModuleName Tenantkeep.Posture Start-Transcript { }
    Mock -ModuleName Tenantkeep.Posture Stop-Transcript { }
    Mock -ModuleName Tenantkeep.Posture Test-PostureExoSession { $env:TKP_EXO_CONNECTED -eq '1' }
    # Mock bodies run in the module scope, so the fixture is dot-sourced from the path in the environment.
    Mock -ModuleName Tenantkeep.Posture Invoke-PostureExoCommand { . $env:TKP_EXO_FIXTURE; if ($Name -eq 'Get-RoleGroup' -and $env:TKP_EXO_FAIL -eq '1') { throw 'Access denied: View-Only Organization Management required' }; @(Get-ExchangeFixtureObject -Name $Name) }
    Mock -ModuleName Tenantkeep.Posture Resolve-PostureDnsRecord { . $env:TKP_EXO_FIXTURE; @(Get-ExchangeFixtureDnsRecord -Name $Name -Type $Type) }
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
    Remove-Item Env:TKP_EXO_FIXTURE, Env:TKP_EXO_CONNECTED, Env:TKP_EXO_FAIL -ErrorAction SilentlyContinue
}

Describe 'Invoke-PostureCollection -Collector Exchange' {
    Context 'connected' {
        BeforeAll {
            $env:TKP_EXO_CONNECTED = '1'; $env:TKP_EXO_FAIL = '1'
            $script:Folder = Join-Path $script:Root 'run1'
            $script:Result = Invoke-PostureCollection -Collector Exchange -SkipCaSnapshot -OutputFolder $script:Folder -PassThru -WarningAction SilentlyContinue
            $script:Read = { param([string] $n) Get-Content -Raw (Join-Path $script:Folder "$n.json") | ConvertFrom-Json -AsHashtable }
        }

        It 'writes the A.2 files with the audit plan names' {
            foreach ($n in 'exo-01-orgconfig', 'exo-01-transport-config', 'exo-01-audit-config', 'exo-02-accepted-domains', 'exo-02-dkim', 'exo-03-inbound-connectors', 'exo-03-transport-rules', 'exo-04-eop-content-filter', 'exo-04-antiphish', 'exo-04-outbound-spam', 'exo-04-preset-rules-eop', 'exo-05-mdo-safelinks', 'exo-05-quarantine-policies', 'exo-09-mailboxes', 'exo-09-mailboxes-by-type', 'exo-09-mailboxes-with-forwarding', 'exo-10-cas-mailboxes', 'exo-10-cas-summary', 'dns-01-mail-records') {
                Join-Path $script:Folder "$n.json" | Should -Exist
            }
            Join-Path $script:Folder 'exo-09-mailboxes.csv' | Should -Exist
            Join-Path $script:Folder 'dns-01-mail-records.csv' | Should -Exist
            $script:Result.Collectors | Should -Be @('Exchange')
        }

        It 'flattens single objects to one dictionary and lists to arrays of scalars' {
            $org = & $script:Read 'exo-01-orgconfig'
            $org.AuditDisabled | Should -BeFalse
            $org.ContainsKey('Identity') | Should -BeFalse -Because 'the property list for org config does not include Identity'
            $conn = & $script:Read 'exo-03-inbound-connectors'
            $conn.Count | Should -Be 2
            @($conn[0].SenderIPAddresses) | Should -Be @('203.0.113.10')
        }

        It 'summarises mailboxes by type, forwarding and CAS protocols' {
            @(& $script:Read 'exo-09-mailboxes-by-type' | Where-Object { $_.Name -eq 'SharedMailbox' })[0].Count | Should -Be 2
            @(& $script:Read 'exo-09-mailboxes-with-forwarding').Count | Should -Be 3
            $cas = & $script:Read 'exo-10-cas-summary'
            $cas.Total | Should -Be 4
            $cas.ImapEnabled | Should -Be 1
            $cas.SmtpAuthExplicitlyEnabled | Should -Be 1
        }

        It 'resolves MX, SPF, DMARC, MTA-STS and TLS-RPT for the custom authoritative domains only' {
            $dns = @(& $script:Read 'dns-01-mail-records')
            @($dns | ForEach-Object { $_.Domain }) | Should -Be @('contoso.example', 'legacy.example')
            $dns[0].DMARC | Should -Match '^v=DMARC1; p=reject'
            $dns[0].MTASTS | Should -Match '^v=STSv1'
            $dns[1].TLSRPT | Should -BeNullOrEmpty
        }

        It 'skips attack simulations quietly without the scope, and logs a denied cmdlet without stopping' {
            Join-Path $script:Folder 'exo-11-attack-simulations.json' | Should -Not -Exist
            @($script:Result.Errors) | Should -HaveCount 1 -Because ($script:Result.Errors -join ' | ')
            $script:Result.Errors[0] | Should -Match 'Role groups.*Access denied'
            Join-Path $script:Folder 'exo-08-role-groups.json' | Should -Not -Exist
        }

        It 'feeds the email checks from the same folder' {
            Copy-Item -Path (Join-Path (Initialize-CollectionFixture -Root (Join-Path $script:Root 'a1')) '06-users.json') -Destination $script:Folder
            $run = Invoke-PostureChecks -Evidence $script:Folder -Domain email -OutputPath (Join-Path $script:Root 'checks.json') -PassThru
            $by = @{}; foreach ($r in $run.results) { $by[$r.id] = $r }
            $by['EM-001'].status | Should -Be 'pass'
            $by['EM-002'].status | Should -Be 'fail' -Because 'the MDO preset rule is scoped to a group'
            $by['EM-008'].status | Should -Be 'fail'
            $by['EM-016'].status | Should -Be 'fail'
            $by['EM-016'].affectedCount | Should -Be 2 -Because 'one external SMTP forward and one recipient forward; the internal one is fine'
            $by['EM-019'].status | Should -Be 'pass'
            $by['EM-020'].status | Should -Be 'notEvaluated'
        }
    }

    Context 'not connected' {
        BeforeAll { $env:TKP_EXO_CONNECTED = '0'; $env:TKP_EXO_FAIL = '0' }

        It 'refuses when Exchange was asked for by name' {
            { Invoke-PostureCollection -Collector Exchange -SkipCaSnapshot -OutputFolder (Join-Path $script:Root 'run2') } | Should -Throw '*Connect-ExchangeOnline*'
        }

        It 'never connects on its own' {
            Should -Invoke -ModuleName Tenantkeep.Posture Invoke-PostureExoCommand -Times 0 -Scope It
        }
    }
}

Describe 'Invoke-PostureExoCommand' {
    It 'accepts Get- names only' {
        InModuleScope Tenantkeep.Posture {
            { Invoke-PostureExoCommand -Name 'Set-Mailbox' } | Should -Throw
            { Invoke-PostureExoCommand -Name 'Remove-TransportRule' } | Should -Throw
        }
    }

    It 'projects rich objects to scalars and string lists' {
        InModuleScope Tenantkeep.Posture {
            $obj = [pscustomobject]@{ Name = 'x'; When = [datetime]'2026-01-01'; Tags = @('a', 'b'); Nested = [pscustomobject]@{ A = 1 }; Id = [guid]::Empty }
            $flat = $obj | ConvertTo-PostureFlatObject
            $flat.Name | Should -Be 'x'
            $flat.When | Should -BeOfType [datetime]
            @($flat.Tags) | Should -Be @('a', 'b')
            $flat.Nested | Should -BeOfType [string]
            $flat.Id | Should -Be '00000000-0000-0000-0000-000000000000'
            ($obj | ConvertTo-PostureFlatObject -Property Name, Missing).Keys | Should -Be @('Name', 'Missing')
        }
    }
}
