# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-run-$([guid]::NewGuid().ToString('n'))"
    $script:OutRoot = Join-Path $script:Root 'evidence'
    $script:Client = Join-Path $script:Root 'clients' 'contoso'
    New-Item -ItemType Directory -Path $script:OutRoot | Out-Null
    $script:Tid = '33333333-3333-3333-3333-333333333333'
}

AfterAll {
    Remove-Module Tenantkeep.Posture -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Start-PostureRun' {
    BeforeAll {
        InModuleScope Tenantkeep.Posture -Parameters @{ outRoot = $script:OutRoot; tid = $script:Tid } {
            $script:TestOutRoot = $outRoot
            $script:TestTid = $tid
            $script:Calls = [System.Collections.Generic.List[string]]::new()
            Mock Connect-PostureSession { $script:Calls.Add('signin'); @{ tenantId = $script:TestTid; tenantName = 'contoso'; tenantDisplayName = 'Contoso Ltd'; account = 'admin@contoso.example'; clientId = 'aaaaaaaa-0000-0000-0000-000000000001'; scopes = @('Policy.Read.All'); expiresUtc = [datetime]::UtcNow.AddHours(1) } }
            Mock Assert-PostureGraphScope { @{ TenantId = $script:TestTid; Account = 'admin@contoso.example'; Scopes = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All', 'ThreatHunting.Read.All') } }
            Mock Connect-PostureService { $script:Calls.Add("connect:$Name") }
            Mock Get-Module { $true } -ParameterFilter { $ListAvailable }
            Mock Get-Module { @() } -ParameterFilter { -not $ListAvailable }   # nothing loaded: the run manifest records the installed version
            Mock Invoke-PostureCollection {
                $script:Calls.Add("collect:$($Collector -join '+')")
                $f = $(if ($OutputFolder) { $OutputFolder } else { Join-Path $script:TestOutRoot '20261022-1200' })
                New-Item -ItemType Directory -Path $f -Force | Out-Null
                # One error from this process; two more lines land in errors.txt from the later ones. The count reported is the file's.
                if (-not $OutputFolder) { Add-Content -LiteralPath (Join-Path $f 'errors.txt') -Value 'A :: one', 'B :: two', 'C :: three' }
                [pscustomobject]@{ Folder = $f; Errors = @('one'); Files = @() }
            }
            Mock Get-PostureToken { 'tok' }
            Mock Start-PostureChildCollection { $script:Calls.Add("child:$($Request['collectors'] -join '+')"); $script:ChildRequest = $Request; 0 }
            Mock New-PostureProfile { $script:Calls.Add('profile'); Set-Content -LiteralPath $Path -Value (@{ tenantId = $script:TestTid; clientName = $ClientName } | ConvertTo-Json) }
            Mock New-PostureReport {
                $script:Calls.Add("report:$(if ($Previous) { Split-Path $Previous -Leaf } else { 'none' })")
                $html = Join-Path $Evidence 'report.html'; Set-Content -LiteralPath $html -Value '<html>'
                Set-Content -LiteralPath (Join-Path $Evidence 'checks.json') -Value '[]'
                [pscustomobject]@{ Files = @($html); Report = @{} }
            }
            Mock Export-PostureFindings { $script:Calls.Add('findings') }
            Mock Start-Process { $script:Calls.Add("open:$(Split-Path $FilePath -Leaf)") }
            $script:PostureSession = @{ tokens = @{ graph = @{ accessToken = 'g'; expiresUtc = [datetime]::UtcNow.AddHours(1) }; exchange = @{ accessToken = 'e'; expiresUtc = [datetime]::UtcNow.AddHours(1) }; purview = @{ accessToken = 'p'; expiresUtc = [datetime]::UtcNow.AddHours(1) } } }
        }
    }
    AfterAll { InModuleScope Tenantkeep.Posture { $script:PostureSession = $null } }

    It 'runs the whole cycle in order from one sign-in and opens the report' {
        InModuleScope Tenantkeep.Posture -Parameters @{ client = $script:Client } {
            $script:Calls.Clear()
            $result = Start-PostureRun -Client $client -OutRoot $script:TestOutRoot -PassThru 6>$null
            $result.Folder | Should -Be (Join-Path $script:TestOutRoot '20261022-1200')
            $result.Client | Should -Be $client
            $result.Report | Should -Match 'report\.html$'
            $result.Errors | Should -Be 3
            @($script:Calls) | Should -Be @('signin', 'connect:azure', 'collect:Entra+Intune+Defender+Azure', 'connect:sharepoint', 'connect:teams', 'collect:SharePoint+Teams', 'child:Exchange+Purview', 'profile', 'report:none', 'findings', 'open:report.html')
            $script:ChildRequest['tokens'].Keys | Sort-Object | Should -Be @('exchange', 'graph')
            $script:ChildRequest['purviewSignIn'] | Should -Be 'browser'
            $script:ChildRequest['tokens']['graph']['accessToken'] | Should -Be 'g'
            $script:ChildRequest.Keys | Should -Not -Contain 'refreshToken'
            Test-Path (Join-Path $client 'profile.json') | Should -BeTrue
            Test-Path (Join-Path $client 'imports') | Should -BeTrue
            Should -Invoke New-PostureProfile -Times 1 -Exactly -ParameterFilter { $NonInteractive -and $ClientName -eq 'Contoso Ltd' -and $TenantId -eq $script:TestTid }
        }
    }

    It 'on the next run keeps the profile, finds the previous run for the trend, copies hybrid files and honours azure: none' {
        InModuleScope Tenantkeep.Posture -Parameters @{ client = $script:Client } {
            $script:Calls.Clear()
            $p = Join-Path $client 'profile.json'
            Set-Content -LiteralPath $p -Value (@{ tenantId = $script:TestTid; clientName = 'Contoso Ltd'; azure = 'none' } | ConvertTo-Json)
            Set-Content -LiteralPath (Join-Path $client 'hybrid' 'ad-01-forest.json') -Value '{}'
            Mock Invoke-PostureCollection {
                $script:Calls.Add("collect:$($Collector -join '+')")
                $f = $(if ($OutputFolder) { $OutputFolder } else { Join-Path $script:TestOutRoot '20261122-1200' })
                New-Item -ItemType Directory -Path $f -Force | Out-Null
                [pscustomobject]@{ Folder = $f; Errors = @(); Files = @() }
            }
            $result = Start-PostureRun -Client $client -OutRoot $script:TestOutRoot -Collector Entra, Azure, Exchange -NoBrowser -PassThru 6>$null
            @($script:Calls) | Should -Be @('signin', 'collect:Entra', 'child:Exchange', 'profile', 'report:20261022-1200', 'findings')
            $result.Skipped['Azure'] | Should -Match 'azure: none'
            Test-Path (Join-Path $result.Folder 'ad-01-forest.json') | Should -BeTrue
            Should -Invoke New-PostureProfile -Times 1 -Exactly -ParameterFilter { $ProfilePath -eq $null -and -not $PSBoundParameters.ContainsKey('ClientName') }
            Should -Invoke Start-Process -Times 0 -Exactly
        }
    }

    It 'refuses a client folder that belongs to another tenant before anything is read' {
        InModuleScope Tenantkeep.Posture -Parameters @{ root = $script:Root } {
            $other = Join-Path $root 'clients' 'other'
            New-Item -ItemType Directory -Path $other -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $other 'profile.json') -Value (@{ tenantId = '44444444-4444-4444-4444-444444444444' } | ConvertTo-Json)
            { Start-PostureRun -Client $other -OutRoot $script:TestOutRoot 6>$null } | Should -Throw '*belongs to tenant 44444444*'
            Should -Invoke Invoke-PostureCollection -Times 0 -Exactly -Scope It
        }
    }

    It 'skips what is not installed with a note that says how to install it, and names the default client folder after the tenant' {
        InModuleScope Tenantkeep.Posture -Parameters @{ root = $script:Root } {
            $script:Calls.Clear()
            Mock Get-Module { $false } -ParameterFilter { $ListAvailable }
            $saved = $HOME
            try {
                Set-Variable -Name HOME -Value (Join-Path $root 'home') -Scope Global -Force
                $result = Start-PostureRun -OutRoot $script:TestOutRoot -SkipReport -NoBrowser -PassThru 6>$null
            }
            finally { Set-Variable -Name HOME -Value $saved -Scope Global -Force }
            $result.Client | Should -Be (Join-Path $root 'home' 'tenantkeep' 'clients' 'contoso-ltd')
            $result.Skipped['Exchange'] | Should -Match 'Install-Module ExchangeOnlineManagement'
            $result.Skipped['SharePoint'] | Should -Match 'Install-Module PnP.PowerShell'
            $result.Skipped['Azure'] | Should -Match 'Az.Accounts'
            $result.Report | Should -BeNullOrEmpty
            @($script:Calls) | Should -Be @('signin', 'collect:Entra+Intune+Defender', 'profile')
        }
    }

    It 'warns once when a module is older than the tested version and still runs its collector' {
        InModuleScope Tenantkeep.Posture -Parameters @{ client = $script:Client } {
            $script:Calls.Clear()
            Mock Get-Module { [pscustomobject]@{ Name = $Name; Version = [version]'1.0.0' } } -ParameterFilter { $ListAvailable }
            $result = Start-PostureRun -Client $client -OutRoot $script:TestOutRoot -SkipReport -NoBrowser -PassThru -WarningVariable warn 6>$null
            $result.Skipped.Keys | Should -Not -Contain 'SharePoint'
            @($script:Calls) | Should -Contain 'collect:SharePoint+Teams'
            @($script:Calls) | Should -Contain 'child:Exchange+Purview'
            @($warn | Where-Object { "$_" -match '^PnP\.PowerShell 1\.0\.0 is older' }).Count | Should -Be 1
            @($warn | Where-Object { "$_" -match '^Az\.Accounts 1\.0\.0 is older' }).Count | Should -Be 1
            @($warn | Where-Object { "$_" -match '^ExchangeOnlineManagement 1\.0\.0 is older' }).Count | Should -Be 1
        }
    }
}

Describe 'The child process hand-off' {
    It 'passes the request over standard input to a fresh PowerShell and returns its exit code' {
        InModuleScope Tenantkeep.Posture -Parameters @{ root = $script:Root } {
            $echo = Join-Path $root 'stdin.json'
            $code = Start-PostureChildCollection -Request @{ collectors = @('Exchange'); tokens = @{ exchange = @{ accessToken = 'secret-token' } } } -Command "[Console]::In.ReadToEnd() | Set-Content -LiteralPath '$echo'; exit 3"
            $code | Should -Be 3
            $seen = Get-Content -Raw -LiteralPath $echo | ConvertFrom-Json -AsHashtable
            $seen['tokens']['exchange']['accessToken'] | Should -Be 'secret-token'
        }
    }

    It 'the child side opens Graph and each named service with the tokens it was given, never a refresh token, and counts failures' {
        InModuleScope Tenantkeep.Posture -Parameters @{ root = $script:Root } {
            $script:ChildCalls = [System.Collections.Generic.List[string]]::new()
            Mock Connect-PostureService { $script:ChildCalls.Add("connect:$Name"); if ($Name -eq 'purview') { throw 'no purview for you' } }
            Mock Invoke-PostureCollection { $script:ChildCalls.Add("collect:$($Collector -join '+'):$(Split-Path $OutputFolder -Leaf)") }
            $exp = [datetime]::UtcNow.AddMinutes(50).ToString('o')
            $json = @{ clientId = 'c'; tenantId = 't'; tenantName = 'contoso'; account = 'a@b'; folder = (Join-Path $root 'run1'); profilePath = ''; collectors = @('Exchange', 'Purview'); purviewSignIn = 'device'; tokens = @{ graph = @{ accessToken = 'g'; expiresUtc = $exp }; exchange = @{ accessToken = 'e'; expiresUtc = $exp } } } | ConvertTo-Json -Depth 10
            $failed = Invoke-PostureChildCollection -InputJson $json 6>$null
            $failed | Should -Be 1
            @($script:ChildCalls) | Should -Be @('connect:graph', 'connect:exchange', 'collect:Exchange:run1', 'connect:purview')
            $script:PostureSession['refreshToken'] | Should -Be ''
            $script:PostureSession['purviewSignIn'] | Should -Be 'device'
            (Get-PostureToken -Resource exchange) | Should -Be 'e'
            { Invoke-PostureChildCollection -InputJson ($json -replace [regex]::Escape($exp), [datetime]::UtcNow.AddMinutes(-1).ToString('o')) 6>$null } | Should -Throw '*already expired*'
            $script:PostureSession = $null
        }
    }
}
