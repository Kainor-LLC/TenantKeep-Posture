# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    . (Join-Path $PSScriptRoot 'Fixtures' 'ExchangeFixture.ps1')
    . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-exo-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $env:TKP_EXO_FIXTURE = (Join-Path $PSScriptRoot 'Fixtures' 'ExchangeFixture.ps1')

    Mock -ModuleName TenantKeep.Posture Get-MgContext { [pscustomobject]@{ TenantId = 'tenant-guid'; Account = 'reader@contoso.example'; AuthType = 'Delegated'; Scopes = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All') } }
    Mock -ModuleName TenantKeep.Posture Start-Transcript { }
    Mock -ModuleName TenantKeep.Posture Stop-Transcript { }
    Mock -ModuleName TenantKeep.Posture Test-PostureExoSession { $env:TKP_EXO_CONNECTED -eq '1' }
    # Mock bodies run in the module scope, so the fixture is dot-sourced from the path in the environment.
    Mock -ModuleName TenantKeep.Posture Invoke-PostureExoCommand { . $env:TKP_EXO_FIXTURE; if ($Name -eq 'Get-RoleGroup' -and $env:TKP_EXO_FAIL -eq '1') { throw 'Access denied: View-Only Organization Management required' }; $items = @(Get-ExchangeFixtureObject -Name $Name); if ($PesterBoundParameters.ContainsKey('OnItem')) { foreach ($i in $items) { & $PesterBoundParameters['OnItem'] $i }; return }; $items }
    Mock -ModuleName TenantKeep.Posture Resolve-PostureDnsRecord { . $env:TKP_EXO_FIXTURE; @(Get-ExchangeFixtureDnsRecord -Name $Name -Type $Type) }
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
            @(& $script:Read 'exo-03-transport-rules')[0].Contains('SetHeaderName') | Should -BeTrue -Because 'EM-038 reads the header a rule sets, and a rule that sets none still says so'
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
            $ps = & $script:Read 'exo-12-remote-powershell-summary'
            $ps.RemotePowerShellEnabled | Should -Be 3 -Because 'every account with the setting on is counted'
            $ps.NonAdmin | Should -Be 2 -Because 'the shared mailbox does not sign in'
            $ps.Listed | Should -Be 2
            $ps.AdminsExcluded | Should -BeFalse -Because 'this folder has no role holders to tell administrators by'
            @(& $script:Read 'exo-12-remote-powershell-users' | ForEach-Object { $_.UserPrincipalName }) | Should -Be @('admin1@contoso.example', 'user1@contoso.example')
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

        It 'records a lookup that failed as failed, by record, and never as an empty record' {
            # One name does not answer (a timeout); every other lookup does.
            Mock -ModuleName TenantKeep.Posture Resolve-PostureDnsRecord {
                if ($Name -eq '_dmarc.legacy.example') { throw 'DNS lookup failed for TXT _dmarc.legacy.example: no answer (timed out, or no resolver reached)' }
                . $env:TKP_EXO_FIXTURE; @(Get-ExchangeFixtureDnsRecord -Name $Name -Type $Type)
            }
            $folder = Join-Path $script:Root 'run-dns'
            $null = Invoke-PostureCollection -Collector Exchange -SkipCaSnapshot -OutputFolder $folder -PassThru -WarningAction SilentlyContinue
            $rows = @(Get-Content -Raw (Join-Path $folder 'dns-01-mail-records.json') | ConvertFrom-Json -AsHashtable)
            $legacy = @($rows | Where-Object { $_['Domain'] -eq 'legacy.example' })[0]
            $legacy['LookupFailed'] | Should -Be 'DMARC'
            $legacy['DMARC'] | Should -Be ''
            $legacy['SPF'] | Should -Match '^v=spf1' -Because 'the lookups that answered are kept'
            @($rows | Where-Object { $_['Domain'] -eq 'contoso.example' })[0]['LookupFailed'] | Should -Be ''
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

    Context 'Exchange Online PowerShell access, with the Entra evidence in the folder' {
        It 'leaves the administrators out of the count and the list when it knows who they are' {
            $folder = Join-Path $script:Root 'ps-admins'; New-Item -ItemType Directory -Path $folder | Out-Null
            ConvertTo-Json -InputObject @(@{ Role = 'Exchange Administrator'; AssignmentType = 'Assigned'; PrincipalType = 'user'; PrincipalUpn = 'admin1@contoso.example'; PrincipalName = 'Admin One'; PrincipalId = 'u1' }) | Set-Content -LiteralPath (Join-Path $folder '04-role-assignments-active.json')
            $null = Invoke-PostureCollection -Collector Exchange -SkipCaSnapshot -OutputFolder $folder -PassThru -WarningAction SilentlyContinue
            $ps = Get-Content -Raw (Join-Path $folder 'exo-12-remote-powershell-summary.json') | ConvertFrom-Json
            $ps.RemotePowerShellEnabled | Should -Be 3
            $ps.NonAdmin | Should -Be 1
            $ps.AdminsExcluded | Should -BeTrue
            @(Import-Csv -LiteralPath (Join-Path $folder 'exo-12-remote-powershell-users.csv')).UserPrincipalName | Should -Be 'user1@contoso.example'
        }

        It 'does not read the setting at all when the Exchange Online PowerShell app is closed' {
            $folder = Join-Path $script:Root 'ps-closed'; New-Item -ItemType Directory -Path $folder | Out-Null
            ConvertTo-Json -InputObject @(@{ AppId = 'fb78d390-0c51-40cd-8e17-fdbfab77341b'; DisplayName = 'Microsoft Exchange REST API Based PowerShell'; AccountEnabled = $true; AppRoleAssignmentRequired = $true }) | Set-Content -LiteralPath (Join-Path $folder '10-service-principals.json')
            $null = Invoke-PostureCollection -Collector Exchange -SkipCaSnapshot -OutputFolder $folder -PassThru -WarningAction SilentlyContinue
            $ps = Get-Content -Raw (Join-Path $folder 'exo-12-remote-powershell-summary.json') | ConvertFrom-Json
            $ps.Skipped | Should -Match 'closed to everyone but the people assigned to it'
            $ps.RemotePowerShellEnabled | Should -BeNullOrEmpty
            Join-Path $folder 'exo-12-remote-powershell-users.json' | Should -Not -Exist
            Should -Invoke -ModuleName TenantKeep.Posture Invoke-PostureExoCommand -Times 0 -Exactly -Scope It -ParameterFilter { $Name -eq 'Get-User' }
            # The check passes on the app alone.
            $by = @{}; foreach ($x in (Invoke-PostureChecks -Evidence $folder -Domain email -PassThru).results) { $by[$x.id] = $x }
            $by['EM-025'].status | Should -Be 'pass'
        }
    }

    Context 'second process into the same folder' {
        It 'keeps the collectors and start time of the manifest already there' {
            $env:TKP_EXO_CONNECTED = '1'; $env:TKP_EXO_FAIL = '0'
            $folder = Join-Path $script:Root 'run-merge'
            $first = Invoke-PostureCollection -Collector Entra -SkipCaSnapshot -OutputFolder $folder -PassThru -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            $second = Invoke-PostureCollection -Collector Exchange -SkipCaSnapshot -OutputFolder $folder -PassThru -WarningAction SilentlyContinue
            $second.Collectors | Should -Be @('Entra', 'Exchange')
            $second.Manifest.timestampUtc | Should -Be $first.Manifest.timestampUtc
            (Get-Content -Raw (Join-Path $folder 'collection.json') | ConvertFrom-Json).collectors | Should -Be @('Entra', 'Exchange')
        }
    }

    Context 'not connected' {
        BeforeAll { $env:TKP_EXO_CONNECTED = '0'; $env:TKP_EXO_FAIL = '0' }

        It 'refuses when Exchange was asked for by name' {
            { Invoke-PostureCollection -Collector Exchange -SkipCaSnapshot -OutputFolder (Join-Path $script:Root 'run2') } | Should -Throw '*Connect-ExchangeOnline*'
        }

        It 'never connects on its own' {
            Should -Invoke -ModuleName TenantKeep.Posture Invoke-PostureExoCommand -Times 0 -Scope It
        }
    }
}

Describe 'Invoke-PostureExoCommand' {
    It 'reads dig: records for an answer, nothing for "no such record", an error when DNS did not answer' {
        InModuleScope TenantKeep.Posture {
            $header = ';; ->>HEADER<<- opcode: QUERY, status: {0}, id: 4242'
            $txt = @(($header -f 'NOERROR'), ';; flags: qr rd ra; QUERY: 1, ANSWER: 2', 'contoso.example.	300	IN	TXT	"v=spf1 include:spf.protection.outlook.com" " -all"', 'contoso.example.	300	IN	TXT	"MS=ms12345678"')
            ConvertFrom-PostureDigAnswer -Line $txt -Name 'contoso.example' -Type TXT | Should -Be @('v=spf1 include:spf.protection.outlook.com -all', 'MS=ms12345678')
            $mx = @(($header -f 'NOERROR'), 'contoso.example.	3600	IN	MX	0 contoso-example.mail.protection.outlook.com.', 'contoso.example.	3600	IN	MX	10 mx2.contoso.example.')
            ConvertFrom-PostureDigAnswer -Line $mx -Name 'contoso.example' -Type MX | Should -Be @('0 contoso-example.mail.protection.outlook.com', '10 mx2.contoso.example')
            # A CNAME on the way to the answer is not the answer.
            $cname = @(($header -f 'NOERROR'), '_dmarc.contoso.example.	300	IN	CNAME	dmarc.vendor.example.', 'dmarc.vendor.example.	300	IN	TXT	"v=DMARC1; p=reject"')
            ConvertFrom-PostureDigAnswer -Line $cname -Name '_dmarc.contoso.example' -Type TXT | Should -Be @('v=DMARC1; p=reject')
            @(ConvertFrom-PostureDigAnswer -Line @(($header -f 'NXDOMAIN')) -Name '_mta-sts.contoso.example' -Type TXT).Count | Should -Be 0 -Because 'the name does not exist is an answer'
            @(ConvertFrom-PostureDigAnswer -Line @(($header -f 'NOERROR')) -Name 'contoso.example' -Type MX).Count | Should -Be 0 -Because 'no record of that type is an answer'
            { ConvertFrom-PostureDigAnswer -Line @(($header -f 'SERVFAIL')) -Name 'contoso.example' -Type TXT } | Should -Throw '*DNS lookup failed for TXT contoso.example: the server answered SERVFAIL*'
            { ConvertFrom-PostureDigAnswer -Line @(';; connection timed out; no servers could be reached') -Name 'contoso.example' -Type MX } | Should -Throw '*no answer*'
            { ConvertFrom-PostureDigAnswer -Line @() -Name 'contoso.example' -Type MX } | Should -Throw '*no answer*'
        }
    }

    It 'accepts Get- names only' {
        InModuleScope TenantKeep.Posture {
            { Invoke-PostureExoCommand -Name 'Set-Mailbox' } | Should -Throw
            { Invoke-PostureExoCommand -Name 'Remove-TransportRule' } | Should -Throw
        }
    }

    It 'projects rich objects to scalars and string lists' {
        InModuleScope TenantKeep.Posture {
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
