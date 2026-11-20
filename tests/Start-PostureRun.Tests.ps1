# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-run-$([guid]::NewGuid().ToString('n'))"
    $script:OutRoot = Join-Path $script:Root 'evidence'
    $script:Client = Join-Path $script:Root 'clients' 'contoso'
    New-Item -ItemType Directory -Path $script:OutRoot | Out-Null
    $script:Tid = '33333333-3333-3333-3333-333333333333'
}

AfterAll {
    Remove-Module TenantKeep.Posture -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Start-PostureRun' {
    BeforeAll {
        InModuleScope TenantKeep.Posture -Parameters @{ outRoot = $script:OutRoot; tid = $script:Tid } {
            $script:TestOutRoot = $outRoot
            $script:TestTid = $tid
            $script:Calls = [System.Collections.Generic.List[string]]::new()
            Mock Connect-PostureSession { $script:Calls.Add('signin'); @{ tenantId = $script:TestTid; tenantName = 'contoso'; tenantDisplayName = 'Contoso Ltd'; account = 'admin@contoso.example'; clientId = 'aaaaaaaa-0000-0000-0000-000000000001'; scopes = @('Policy.Read.All'); expiresUtc = [datetime]::UtcNow.AddHours(1) } }
            Mock Assert-PostureGraphScope { @{ TenantId = $script:TestTid; Account = 'admin@contoso.example'; Scopes = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All', 'ThreatHunting.Read.All') } }
            Mock Connect-PostureService { $script:Calls.Add("connect:$Name") }
            Mock Get-Module { $true } -ParameterFilter { $ListAvailable }
            Mock Get-Module { @() } -ParameterFilter { -not $ListAvailable }   # nothing loaded: the run manifest records the installed version
            $script:NextStamp = '20261022-1200'
            Mock New-PostureEvidenceFolder { $f = Join-Path $script:TestOutRoot $script:NextStamp; New-Item -ItemType Directory -Path $f -Force | Out-Null; $f }
            Mock Invoke-PostureCollection {
                $script:Calls.Add("collect:$($Collector -join '+')")
                # Three lines in errors.txt from the processes that wrote into the folder. The count reported is the file's.
                if ($Collector -contains 'Entra' -and $script:NextStamp -eq '20261022-1200') { Add-Content -LiteralPath (Join-Path $OutputFolder 'errors.txt') -Value 'A :: one', 'B :: two', 'C :: three' }
                [pscustomobject]@{ Folder = $OutputFolder; Errors = @('one'); Files = @() }
            }
            Mock Get-PostureToken { 'tok' }
            Mock Start-PostureChildCollection { $script:Calls.Add("child:$($Request['collectors'] -join '+')"); $script:ChildRequest = $Request; $script:ChildNoWait = [bool]$NoWait; [System.Diagnostics.Process]::new() }
            Mock Wait-PostureChildCollection { $script:Calls.Add('wait'); 0 }
            Mock Enable-PostureKeepAwake { $script:Calls.Add('awake'); @{ method = 'test'; process = $null } }
            Mock Disable-PostureKeepAwake { $script:Calls.Add('sleep-ok') }
            Mock Write-Progress { }
            Mock Test-PostureRoleCoverage { @() }
            Mock New-PostureProfile { $script:Calls.Add('profile'); Set-Content -LiteralPath $Path -Value (@{ tenantId = $script:TestTid; clientName = $ClientName } | ConvertTo-Json) }
            Mock New-PostureReport {
                $script:Calls.Add("report:$(if ($Previous) { Split-Path $Previous -Leaf } else { 'none' })")
                $html = Join-Path $Evidence 'report.html'; Set-Content -LiteralPath $html -Value '<html>'
                Set-Content -LiteralPath (Join-Path $Evidence 'checks.json') -Value '[]'
                [pscustomobject]@{ Files = @($html); Report = @{} }
            }
            Mock Export-PostureFindings { $script:Calls.Add('findings') }
            Mock Start-Process { $script:Calls.Add("open:$(Split-Path $FilePath -Leaf)") }
            Mock Get-PostureLicense { [pscustomobject]@{ Valid = $false; Tier = 'none'; Reason = 'No licence file found.' } }
            $script:PostureSession = @{ tokens = @{ graph = @{ accessToken = 'g'; expiresUtc = [datetime]::UtcNow.AddHours(1) }; exchange = @{ accessToken = 'e'; expiresUtc = [datetime]::UtcNow.AddHours(1) }; purview = @{ accessToken = 'p'; expiresUtc = [datetime]::UtcNow.AddHours(1) } } }
        }
    }
    AfterAll { InModuleScope TenantKeep.Posture { $script:PostureSession = $null } }

    It 'runs the whole cycle in order from one sign-in and opens the report' {
        InModuleScope TenantKeep.Posture -Parameters @{ client = $script:Client } {
            $script:Calls.Clear()
            $result = Start-PostureRun -Client $client -OutRoot $script:TestOutRoot -PassThru 6>$null
            $result.Folder | Should -Be (Join-Path $script:TestOutRoot '20261022-1200')
            $result.Client | Should -Be $client
            $result.Report | Should -Match 'report\.html$'
            $result.Errors | Should -Be 3
            @($script:Calls) | Should -Be @('signin', 'connect:azure', 'awake', 'child:Exchange+Purview', 'collect:Entra+SignIns+Intune+Defender+Azure', 'connect:sharepoint', 'connect:teams', 'collect:SharePoint+Teams', 'wait', 'profile', 'report:none', 'findings', 'sleep-ok', 'open:report.html') -Because 'Exchange and Purview start first so the Purview sign-in comes in the first minute, and the machine is let sleep before the report opens'
            $script:ChildNoWait | Should -BeTrue
            $script:ChildRequest['progressFile'] | Should -Be (Join-Path $result.Folder '.progress-child.json')
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
        InModuleScope TenantKeep.Posture -Parameters @{ client = $script:Client } {
            $script:Calls.Clear()
            $p = Join-Path $client 'profile.json'
            Set-Content -LiteralPath $p -Value (@{ tenantId = $script:TestTid; clientName = 'Contoso Ltd'; azure = 'none' } | ConvertTo-Json)
            Set-Content -LiteralPath (Join-Path $client 'hybrid' 'ad-01-forest.json') -Value '{}'
            $script:NextStamp = '20261122-1200'
            $result = Start-PostureRun -Client $client -OutRoot $script:TestOutRoot -Collector Entra, Azure, Exchange -NoBrowser -AllowSleep -PassThru 6>$null
            @($script:Calls) | Should -Be @('signin', 'child:Exchange', 'collect:Entra', 'wait', 'profile', 'report:20261022-1200', 'findings', 'sleep-ok') -Because '-AllowSleep never asks the system to stay awake'
            $result.Skipped['Azure'] | Should -Match 'azure: none'
            Test-Path (Join-Path $result.Folder 'ad-01-forest.json') | Should -BeTrue
            Should -Invoke New-PostureProfile -Times 1 -Exactly -ParameterFilter { $ProfilePath -eq $null -and -not $PSBoundParameters.ContainsKey('ClientName') }
            Should -Invoke Start-Process -Times 0 -Exactly
        }
    }

    It 'collects into an existing run folder without a new Conditional Access snapshot, and records the resume in run.json' {
        InModuleScope TenantKeep.Posture -Parameters @{ client = $script:Client } {
            $script:Calls.Clear()
            $existing = Join-Path $script:TestOutRoot '20261022-1200'
            Set-Content -LiteralPath (Join-Path $existing 'policies.json') -Value '[]'
            $result = Start-PostureRun -Client $client -Folder $existing -Collector Entra -NoBrowser -AllowSleep -PassThru 6>$null
            $result.Folder | Should -Be $existing
            Should -Invoke New-PostureEvidenceFolder -Times 0 -Exactly -Scope It
            Should -Invoke Invoke-PostureCollection -Times 1 -Exactly -Scope It -ParameterFilter { $SkipCaSnapshot -and $OutputFolder -eq $existing }
            $plan = Get-Content -Raw (Join-Path $existing 'run.json') | ConvertFrom-Json -AsHashtable
            @($plan.resumes).Count | Should -BeGreaterOrEqual 1
            @($plan.resumes)[-1].collectors | Should -Be @('Entra')
        }
    }

    It 'refuses a client folder that belongs to another tenant before anything is read' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
            $other = Join-Path $root 'clients' 'other'
            New-Item -ItemType Directory -Path $other -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $other 'profile.json') -Value (@{ tenantId = '44444444-4444-4444-4444-444444444444' } | ConvertTo-Json)
            { Start-PostureRun -Client $other -OutRoot $script:TestOutRoot 6>$null } | Should -Throw '*belongs to tenant 44444444*'
            Should -Invoke Invoke-PostureCollection -Times 0 -Exactly -Scope It
        }
    }

    It 'skips what is not installed with a note that says how to install it, and names the default client folder after the tenant' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
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
            @($script:Calls) | Should -Be @('signin', 'awake', 'collect:Entra+SignIns+Intune+Defender', 'profile', 'sleep-ok')
        }
    }

    It 'warns once when a module is older than the tested version and still runs its collector' {
        InModuleScope TenantKeep.Posture -Parameters @{ client = $script:Client } {
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

Describe 'Start-PostureRun and the trial' {
    It 'prints the trial link with the tenant id when there is no Full licence, and stays quiet with one, without any web request' {
        InModuleScope TenantKeep.Posture -Parameters @{ client = (Join-Path $script:Client 'trial') ; outRoot = $script:OutRoot; tid = $script:Tid } {
            Mock Connect-PostureSession { @{ tenantId = $tid; tenantName = 'contoso'; tenantDisplayName = 'Contoso Ltd'; account = 'admin@contoso.example'; clientId = 'x' } }
            Mock Assert-PostureGraphScope { @{ TenantId = $tid; Scopes = @('Policy.Read.All') } }
            Mock Get-Module { $false } -ParameterFilter { $ListAvailable }
            Mock Get-Module { @() } -ParameterFilter { -not $ListAvailable }
            Mock New-PostureEvidenceFolder { $f = Join-Path $outRoot '20261027-0900'; New-Item -ItemType Directory -Path $f -Force | Out-Null; $f }
            Mock Invoke-PostureCollection { [pscustomobject]@{ Folder = $OutputFolder; Errors = @(); Files = @() } }
            Mock Enable-PostureKeepAwake { $null }
            Mock Write-Progress { }
            Mock New-PostureProfile { }
            Mock Invoke-WebRequest { throw 'no web requests' }
            Mock Invoke-RestMethod { throw 'no web requests' }
            Mock Get-PostureLicense { [pscustomobject]@{ Valid = $false; Tier = 'none'; Reason = 'No licence file found.' } }
            $out = Start-PostureRun -Client $client -OutRoot $outRoot -Collector Entra -SkipReport -NoBrowser 6>&1 | Out-String
            $out | Should -Match ([regex]::Escape("https://tenantkeep.app/trial/?tenant=$tid"))
            Mock Get-PostureLicense { [pscustomobject]@{ Valid = $true; Tier = 'full'; Reason = 'Valid.' } }
            $out = Start-PostureRun -Client $client -OutRoot $outRoot -Collector Entra -SkipReport -NoBrowser 6>&1 | Out-String
            $out | Should -Not -Match 'tenantkeep\.app/trial'
            Should -Invoke Invoke-WebRequest -Times 0 -Exactly -Scope It
            Should -Invoke Invoke-RestMethod -Times 0 -Exactly -Scope It
        }
    }
}

Describe 'The child process hand-off' {
    It 'passes the request over standard input to a fresh PowerShell and returns its exit code' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
            $echo = Join-Path $root 'stdin.json'
            $code = Start-PostureChildCollection -Request @{ collectors = @('Exchange'); tokens = @{ exchange = @{ accessToken = 'secret-token' } } } -Command "[Console]::In.ReadToEnd() | Set-Content -LiteralPath '$echo'; exit 3"
            $code | Should -Be 3
            $seen = Get-Content -Raw -LiteralPath $echo | ConvertFrom-Json -AsHashtable
            $seen['tokens']['exchange']['accessToken'] | Should -Be 'secret-token'
        }
    }

    It 'the child side opens Graph and each named service with the tokens it was given, never a refresh token, and counts failures' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
            $script:ChildCalls = [System.Collections.Generic.List[string]]::new()
            Mock Connect-PostureService { $script:ChildCalls.Add("connect:$Name"); if ($Name -eq 'purview') { throw 'no purview for you' } }
            Mock Invoke-PostureCollection { $script:ChildCalls.Add("collect:$($Collector -join '+'):$(Split-Path $OutputFolder -Leaf)") }
            $exp = [datetime]::UtcNow.AddMinutes(50).ToString('o')
            $json = @{ clientId = 'c'; tenantId = 't'; tenantName = 'contoso'; account = 'a@b'; folder = (Join-Path $root 'run1'); profilePath = ''; collectors = @('Exchange', 'Purview'); purviewSignIn = 'device'; tokens = @{ graph = @{ accessToken = 'g'; expiresUtc = $exp }; exchange = @{ accessToken = 'e'; expiresUtc = $exp } } } | ConvertTo-Json -Depth 10
            New-Item -ItemType Directory -Path (Join-Path $root 'run1') -Force | Out-Null
            $failed = Invoke-PostureChildCollection -InputJson $json 6>$null
            $failed | Should -Be 1
            @($script:ChildCalls) | Should -Be @('connect:graph', 'connect:purview', 'connect:exchange', 'collect:Exchange:run1') -Because 'Purview signs in first, while the admin is still at the screen'
            Get-Content -Raw (Join-Path $root 'run1' 'errors.txt') | Should -Match 'Purview collector :: no purview for you'
            $script:PostureSession['refreshToken'] | Should -Be ''
            $script:PostureSession['purviewSignIn'] | Should -Be 'device'
            (Get-PostureToken -Resource exchange) | Should -Be 'e'
            { Invoke-PostureChildCollection -InputJson ($json -replace [regex]::Escape($exp), [datetime]::UtcNow.AddMinutes(-1).ToString('o')) 6>$null } | Should -Throw '*already expired*'
            $script:PostureSession = $null
        }
    }
}

Describe 'Run conveniences' {
    It 'keeps a Mac awake with caffeinate tied to this process, and lets it go' {
        InModuleScope TenantKeep.Posture {
            Mock Get-Command { [pscustomobject]@{ Name = 'caffeinate' } } -ParameterFilter { $Name -eq 'caffeinate' }
            $fake = [pscustomobject]@{ HasExited = $true }
            Mock Start-Process { $fake }
            $h = Enable-PostureKeepAwake -Platform macOS
            $h.method | Should -Be 'caffeinate'
            Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter { $FilePath -eq 'caffeinate' -and ($ArgumentList -join ' ') -eq "-i -s -w $PID" }
            { Disable-PostureKeepAwake -Handle $h } | Should -Not -Throw
            Mock Get-Command { $null } -ParameterFilter { $Name -eq 'caffeinate' }
            Enable-PostureKeepAwake -Platform macOS | Should -BeNullOrEmpty -Because 'no keep-awake tool means none, not an error'
        }
    }

    It 'estimates the time left from the last run of the same tenant and from the pace of the phase under way' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
            $out = Join-Path $root 'estimate'
            $old = Join-Path $out '20261101-0900'; New-Item -ItemType Directory -Path $old -Force | Out-Null
            @{ tenantId = 't1'; timings = @{ Entra = @{ seconds = 600; steps = 20 }; Intune = @{ seconds = 300; steps = 10 } } } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $old 'collection.json')
            $e = Get-PostureRunEstimate -OutRoot $out -TenantId 't1'
            $e.Entra.seconds | Should -Be 600
            (Get-PostureRunEstimate -OutRoot $out -TenantId 'other').Count | Should -Be 0
            Mock Write-Progress { }
            Start-PostureProgress -Phase 'Entra', 'Intune' -Estimate $e -Confirm:$false
            Set-PostureProgressPhase -Name 'Entra' -Confirm:$false
            $s = Get-PostureProgressState
            $s.remaining | Should -BeGreaterThan 850 -Because 'all of Entra and Intune are still ahead'
            $s.phase | Should -Be 'Entra ID'
            Set-PostureProgressPhase -Name 'Intune' -Confirm:$false
            (Get-PostureProgressState).remaining | Should -BeLessOrEqual 300
            Complete-PostureProgress -Confirm:$false
            $script:PostureProgress | Should -BeNullOrEmpty
            { Step-PostureProgress -Label 'after the run' -Confirm:$false } | Should -Not -Throw -Because 'outside a run the hooks do nothing'
        }
    }

    It 'merges the manifest of two processes writing into one folder: collectors, API versions, scopes and timings' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
            $f = Join-Path $root 'merge'; New-Item -ItemType Directory -Path $f -Force | Out-Null
            @{ collectors = @('Purview'); graphApiVersions = @('beta'); scopes = @('X.Read'); timings = @{ Purview = @{ seconds = 12; steps = 1 } }; timestampUtc = '2026-11-20T10:00:00Z' } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $f 'collection.json')
            Mock Get-MgContext { [pscustomobject]@{ TenantId = 't'; Account = 'a'; AuthType = 'Delegated'; Scopes = @('Y.Read', 'Policy.Read.All', 'Directory.Read.All', 'Group.Read.All') } }
            Mock Invoke-PostureEntraCollection { $null = $script:GraphApiVersionsUsed.Add('v1.0'); @{ files = @() } }
            $r = Invoke-PostureCollection -Collector Entra -SkipCaSnapshot -OutputFolder $f -PassThru -WarningAction SilentlyContinue
            $m = Get-Content -Raw (Join-Path $f 'collection.json') | ConvertFrom-Json -AsHashtable
            @($m.collectors) | Should -Be @('Purview', 'Entra')
            @($m.graphApiVersions) | Should -Be @('beta', 'v1.0') -Because 'each process records the versions it used and neither overwrites the other'
            @($m.scopes) | Should -Contain 'X.Read'
            $m.timings.Purview.seconds | Should -Be 12
            $m.timings.Entra.steps | Should -BeGreaterOrEqual 1
            @($r.Collectors) | Should -Contain 'Entra'
        }
    }

    It 'serialises writers on the folder lock' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
            $f = Join-Path $root 'lock'; New-Item -ItemType Directory -Path $f -Force | Out-Null
            $held = [System.IO.File]::Open((Join-Path $f '.tenantkeep.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
            try { $clock = [System.Diagnostics.Stopwatch]::StartNew(); Invoke-PostureFolderLock -Folder $f -TimeoutSeconds 1 -Script { 'ran' } | Should -Be 'ran'; $clock.Elapsed.TotalSeconds | Should -BeGreaterOrEqual 0.9 -Because 'it waited for the holder, then wrote rather than lose the line' }
            finally { $held.Dispose() }
            Invoke-PostureFolderLock -Folder $f -Script { 'free' } | Should -Be 'free'
        }
    }
}
