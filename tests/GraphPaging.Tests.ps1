# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-paging-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    InModuleScope TenantKeep.Posture { $script:PostureGraphRetry = @{ maxAttempts = 4; maxWaitSeconds = 0; baseSeconds = 0; maxTokenRenewals = 2 } }
}

AfterAll {
    InModuleScope TenantKeep.Posture { $script:PostureGraphRetry = @{ maxAttempts = 8; maxWaitSeconds = 300; baseSeconds = 2; maxTokenRenewals = 5 }; $script:PostureSession = $null }
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
}

Describe 'The Graph wrapper at scale' {
    It 'waits out throttling and transient failures, then carries on with the same page' {
        InModuleScope TenantKeep.Posture {
            $script:Calls = 0
            Mock Invoke-MgGraphRequest {
                $script:Calls++
                if ($script:Calls -eq 1) { throw 'Response status code does not indicate success: TooManyRequests (Too Many Requests).' }
                if ($script:Calls -eq 2) { throw [System.Net.Http.HttpRequestException]::new('The SSL connection could not be established.') }
                @{ value = @(@{ id = 'a' }) }
            }
            Mock Start-Sleep { }
            @(Invoke-PostureGraphRequest -Uri 'users' -ApiVersion v1.0).Count | Should -Be 1
            $script:Calls | Should -Be 3
        }
    }

    It 'gives up after the attempts allowed, saying how many and where it stopped' {
        InModuleScope TenantKeep.Posture {
            Mock Invoke-MgGraphRequest { throw 'Response status code does not indicate success: ServiceUnavailable (Service Unavailable).' }
            Mock Start-Sleep { }
            { Invoke-PostureGraphRequest -Uri 'users' -ApiVersion v1.0 } | Should -Throw '*users] after 4 attempts*'
        }
    }

    It 'does not retry a refusal: 403 is thrown at once' {
        InModuleScope TenantKeep.Posture {
            $script:Calls = 0
            Mock Invoke-MgGraphRequest { $script:Calls++; throw 'Response status code does not indicate success: Forbidden (Forbidden).' }
            { Invoke-PostureGraphRequest -Uri 'users' -ApiVersion v1.0 } | Should -Throw '*Forbidden*'
            $script:Calls | Should -Be 1
        }
    }

    It 'renews an expired access token from the sign-in and asks for the same page again' {
        InModuleScope TenantKeep.Posture {
            $script:PostureSession = @{ refreshToken = 'r'; tokens = @{} }
            $script:Calls = 0
            Mock Invoke-MgGraphRequest { $script:Calls++; if ($script:Calls -eq 1) { throw 'Response status code does not indicate success: Unauthorized (Unauthorized).' }; @{ value = @(@{ id = 'a' }) } }
            Mock Get-PostureToken { 'new' }
            Mock Connect-PostureService { }
            @(Invoke-PostureGraphRequest -Uri 'users' -ApiVersion v1.0).Count | Should -Be 1
            Should -Invoke Get-PostureToken -Times 1 -Exactly -ParameterFilter { $Force }
            Should -Invoke Connect-PostureService -Times 1 -Exactly -ParameterFilter { $Name -eq 'graph' }
            $script:PostureSession = $null
        }
    }

    It 'hands pages over one at a time with -OnPage, returns the count, and starts from a saved link with -StartAt' {
        InModuleScope TenantKeep.Posture {
            Mock Invoke-MgGraphRequest {
                switch -Wildcard ($Uri) {
                    '*page=2*' { @{ value = @(@{ id = 3 }) } }
                    default { @{ value = @(@{ id = 1 }, @{ id = 2 }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users?page=2' } }
                }
            }
            $seen = [System.Collections.Generic.List[object]]::new()
            $n = Invoke-PostureGraphRequest -Uri 'users' -ApiVersion v1.0 -OnPage { param($page, $info) foreach ($p in $page) { $seen.Add($p.id) }; $info.number | Should -BeGreaterThan 0 }
            $n | Should -Be 3
            @($seen) | Should -Be @(1, 2, 3)
            @(Invoke-PostureGraphRequest -Uri 'users' -ApiVersion v1.0 -StartAt 'https://graph.microsoft.com/v1.0/users?page=2').id | Should -Be @(3)
        }
    }
}

Describe 'Sign-in log collector' {
    BeforeAll {
        InModuleScope TenantKeep.Posture {
            Mock Assert-PostureGraphScope { @{ Scopes = @('AuditLog.Read.All') } }
            Mock Write-Host { }
            Mock Start-Sleep { }
            # 2,500 made-up sign-ins over three pages, newest first; every tenth is IMAP4.
            $script:SignIns = @(for ($i = 0; $i -lt 2500; $i++) {
                    @{ id = "s$i"; createdDateTime = ([datetime]'2026-11-20T12:00:00Z').AddSeconds(-$i * 10).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); userPrincipalName = "user$($i % 50)@contoso.example"
                        clientAppUsed = $(if ($i % 10 -eq 0) { 'IMAP4' } else { 'Browser' }); isInteractive = $true; conditionalAccessStatus = $(if ($i % 2) { 'success' } else { 'notApplied' })
                        status = @{ errorCode = $(if ($i % 25 -eq 0) { 50126 } else { 0 }) }; authenticationRequirement = 'singleFactorAuthentication'; riskLevelDuringSignIn = 'none'; location = @{ countryOrRegion = 'US' }
                        ipAddress = $(if ($i % 25 -eq 0) { '203.0.113.7' } else { '198.51.100.1' })
                        appliedConditionalAccessPolicies = @(@{ id = 'p1'; displayName = 'Require MFA for everyone'; result = $(if ($i % 4 -eq 0) { 'reportOnlyInterrupted' } else { 'reportOnlySuccess' }) }, @{ id = 'p2'; displayName = 'Block legacy'; result = 'reportOnlyNotApplied' })
                    }
                })
            $script:Page = {
                param([int] $From)
                $slice = @($script:SignIns[$From..([Math]::Min($From + 999, $script:SignIns.Count - 1))])
                $r = @{ value = $slice }
                if ($From + 1000 -lt $script:SignIns.Count) { $r['@odata.nextLink'] = "https://graph.microsoft.com/v1.0/auditLogs/signIns?skip=$($From + 1000)" }
                $r
            }
        }
    }

    It 'streams every page into tallies: totals, legacy users, Conditional Access outcomes, failures, days and countries' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
            param($root)
            $f = Join-Path $root 'signins-full'; New-Item -ItemType Directory -Path $f | Out-Null
            @(@{ PrincipalUpn = 'user0@contoso.example'; Role = 'Global Administrator' }) | ConvertTo-Json -AsArray | Set-Content (Join-Path $f '04-role-assignments-active.json')
            Mock Invoke-MgGraphRequest { $m = [regex]::Match($Uri, 'skip=(\d+)'); & $script:Page $(if ($m.Success) { [int]$m.Groups[1].Value } else { 0 }) }
            $null = Invoke-PostureSignInCollection -Folder $f -Days 7 -AsOf ([datetime]'2026-11-20T12:00:00Z')
            $s = Get-Content -Raw (Join-Path $f '06-signins-summary.json') | ConvertFrom-Json -AsHashtable
            $s.SignIns | Should -Be 2500
            $s.LegacySignIns | Should -Be 250
            $s.LegacyUsers | Should -Be 5 -Because 'every tenth sign-in is IMAP4, which lands on five of the fifty users'
            $s.Failures | Should -Be 100
            $s.ByConditionalAccessStatus.notApplied | Should -Be 1250
            $s.ByCountry.US | Should -Be 2500
            $ro = @($s.ReportOnlyPolicies)
            $ro.Count | Should -Be 1 -Because 'a policy that did not apply is not an impact'
            $ro[0].Name | Should -Be 'Require MFA for everyone'
            $ro[0].WouldInterrupt | Should -Be 625
            $ro[0].UsersAffected | Should -Be 25 -Because 'every fourth sign-in, over fifty users, lands on each of the 25 even-numbered users'
            $admin = @($s.AdminSignIns)[0]
            $admin.UserPrincipalName | Should -Be 'user0@contoso.example'
            $admin.SignIns | Should -Be 50
            @($s.SprayAddresses).Count | Should -Be 0 -Because 'two accounts failing from one address is below the spray threshold of ten'
            $s.FailuresByErrorCode.'50126' | Should -Be 100
            @((Get-Content -Raw (Join-Path $f '06-signins-legacy-users.json') | ConvertFrom-Json)).Count | Should -Be 5
            Join-Path $f '.signins-checkpoint.json' | Should -Not -Exist -Because 'a finished read leaves no checkpoint'
            Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Uri -match 'top=1000' -and $Uri -match 'select=' -and $Uri -match 'createdDateTime ge' }
        }
    }

    It 'carries on by itself after a failure that outlasts the page retries, from where it stopped, counting nothing twice' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
            param($root)
            $f = Join-Path $root 'signins-retry'; New-Item -ItemType Directory -Path $f | Out-Null
            $script:Failed = $false
            Mock Invoke-MgGraphRequest {
                $m = [regex]::Match($Uri, 'skip=(\d+)')
                if ($m.Success -and $m.Groups[1].Value -eq '2000' -and -not $script:Failed) { $script:Failed = $true; throw 'Response status code does not indicate success: Forbidden (Forbidden). transient gateway' }
                & $script:Page $(if ($m.Success) { [int]$m.Groups[1].Value } else { 0 })
            }
            # A 403 is a refusal, not a blip: the step stops, keeps its checkpoint, and resuming finishes the count.
            { Invoke-PostureSignInCollection -Folder $f -Days 7 -AsOf ([datetime]'2026-11-20T12:00:00Z') -CheckpointPages 1 -SelfRetryWaitSeconds 0 -WarningAction SilentlyContinue } | Should -Throw '*Forbidden*'
            $cp = Get-Content -Raw (Join-Path $f '.signins-checkpoint.json') | ConvertFrom-Json -AsHashtable
            $cp.count | Should -Be 2000
            $cp.nextLink | Should -Match 'skip=2000'
            $null = Invoke-PostureSignInCollection -Folder $f -Days 7 -AsOf ([datetime]'2026-11-20T12:00:00Z') -CheckpointPages 1 -SelfRetryWaitSeconds 0
            (Get-Content -Raw (Join-Path $f '06-signins-summary.json') | ConvertFrom-Json).SignIns | Should -Be 2500

            # A transient failure that outlasts the page retries is waited out and resumed in the same call.
            $g = Join-Path $root 'signins-self'; New-Item -ItemType Directory -Path $g | Out-Null
            $script:Fails = 0
            Mock Invoke-MgGraphRequest {
                $m = [regex]::Match($Uri, 'skip=(\d+)')
                if ($m.Success -and $m.Groups[1].Value -eq '1000' -and $script:Fails -lt 5) { $script:Fails++; throw 'Response status code does not indicate success: ServiceUnavailable (Service Unavailable).' }
                & $script:Page $(if ($m.Success) { [int]$m.Groups[1].Value } else { 0 })
            }
            $null = Invoke-PostureSignInCollection -Folder $g -Days 7 -AsOf ([datetime]'2026-11-20T12:00:00Z') -CheckpointPages 1 -SelfRetryWaitSeconds 0 -WarningAction SilentlyContinue
            (Get-Content -Raw (Join-Path $g '06-signins-summary.json') | ConvertFrom-Json).SignIns | Should -Be 2500
        }
    }

    It 'replaces a page link Graph no longer accepts with a query from the oldest record counted, skipping that second''s records' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
            param($root)
            $f = Join-Path $root 'signins-expired'; New-Item -ItemType Directory -Path $f | Out-Null
            Mock Invoke-MgGraphRequest {
                if ($Uri -match 'skip=1000') { throw 'Response status code does not indicate success: BadRequest (Bad Request). The skip token has expired.' }
                $m = [regex]::Match([uri]::UnescapeDataString($Uri), 'createdDateTime le (\S+?)(&|$)')
                if ($m.Success -and $m.Groups[1].Value -ne '2026-11-20T12:00:00Z') {
                    # The restart: everything at or before the oldest counted, which repeats that second's record.
                    $from = [array]::FindIndex([object[]]$script:SignIns, [Predicate[object]] { param($x) $x.createdDateTime -le $m.Groups[1].Value })
                    $slice = @($script:SignIns[$from..($script:SignIns.Count - 1)])
                    return @{ value = $slice }
                }
                & $script:Page 0
            }
            $null = Invoke-PostureSignInCollection -Folder $f -Days 7 -AsOf ([datetime]'2026-11-20T12:00:00Z') -SelfRetryWaitSeconds 0 -WarningAction SilentlyContinue
            (Get-Content -Raw (Join-Path $f '06-signins-summary.json') | ConvertFrom-Json).SignIns | Should -Be 2500 -Because 'the record at the boundary second is counted once'
        }
    }
}

Describe 'Fresh tokens for the second process' {
    It 'answers the run''s secret with a token for an allowed resource, refuses anything else, and stops' {
        InModuleScope TenantKeep.Posture {
            $saved = $script:PostureSession
            try {
                $script:PostureSession = @{ clientId = 'c'; tenantId = 't'; tenantName = 'contoso'; account = 'a'; refreshToken = 'refresh-stays-here'; tokens = @{ exchange = @{ accessToken = 'exo-token'; expiresUtc = [datetime]::UtcNow.AddHours(1); scope = '' } } }
                $server = Start-PostureTokenServer -Resource exchange -Confirm:$false
                $server.pipe | Should -Match '^tenantkeep-[0-9a-f]{32}$'
                $ok = Request-PosturePipeMessage -Pipe $server.pipe -Message "$($server.secret) exchange" -TimeoutMs 20000
                $ok.accessToken | Should -Be 'exo-token'
                $ok.Keys | Should -Not -Contain 'refreshToken'
                (Request-PosturePipeMessage -Pipe $server.pipe -Message 'wrong-secret exchange').error | Should -Be 'refused'
                (Request-PosturePipeMessage -Pipe $server.pipe -Message "$($server.secret) graph").error | Should -Match 'not a resource'
                Stop-PostureTokenServer -Server $server -Confirm:$false
                $server.job.State | Should -BeIn @('Completed', 'Stopped')

                # The second process's side: no refresh token, so the broker asks the main process.
                $server = Start-PostureTokenServer -Resource exchange -Confirm:$false
                $script:PostureSession = @{ tenantId = 't'; tenantName = 'contoso'; refreshToken = ''; tokenPipe = $server.pipe; tokenSecret = $server.secret; tokens = @{} }
                Get-PostureToken -Resource exchange | Should -Be 'exo-token'
                $script:PostureSession = @{ refreshToken = 'refresh-stays-here'; tokens = @{} }
                Stop-PostureTokenServer -Server $server -Confirm:$false
            }
            finally { $script:PostureSession = $saved }
        }
    }

    It 'renews a broker-connected service before a call when its token is near expiry, and leaves a fresh one alone' {
        InModuleScope TenantKeep.Posture {
            $saved = $script:PostureSession; $savedConnected = $script:PostureConnected
            try {
                $script:PostureSession = @{ refreshToken = 'r'; tokens = @{ azure = @{ accessToken = 'old'; expiresUtc = [datetime]::UtcNow.AddMinutes(4) }; sharepoint = @{ accessToken = 'fresh'; expiresUtc = [datetime]::UtcNow.AddHours(1) } } }
                $script:PostureConnected = @{ azure = $true; sharepoint = $true }
                Mock Get-PostureToken { 'new' }
                Mock Connect-PostureService { }
                Update-PostureServiceSession -Name azure
                Update-PostureServiceSession -Name sharepoint
                Should -Invoke Connect-PostureService -Times 1 -Exactly -ParameterFilter { $Name -eq 'azure' }
                Should -Invoke Get-PostureToken -Times 1 -Exactly -ParameterFilter { $Resource -eq 'azure' -and $Force }
            }
            finally { $script:PostureSession = $saved; $script:PostureConnected = $savedConnected }
        }
    }
}

Describe 'Per-user MFA on a large tenant' {
    It 'reads a sample of 1,000 when nobody in it has per-user MFA, and everyone when somebody does' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
            param($root)
            Mock Write-Host { }
            Mock Assert-PostureGraphScope { @{ Scopes = @('Directory.Read.All') } }
            $script:FakeUsers = @(for ($i = 0; $i -lt 6000; $i++) { @{ id = "u$i"; userPrincipalName = "user$i@contoso.example"; userType = 'Member'; accountEnabled = $true } })
            $script:State = 'disabled'
            $script:Batches = 0
            Mock Invoke-PostureGraphRequest {
                if ($Uri -like 'users?*') { $null = & $OnPage $script:FakeUsers @{ number = 1; count = 6000; nextLink = $null }; return 6000 }
                if ($Uri -eq '$batch') { $script:Batches++; return @{ responses = @($Body.requests | ForEach-Object { @{ id = $_.id; status = 200; body = @{ perUserMfaState = $script:State } } }) } }
                if ($OnPage) { return 0 }
                return @()
            }
            $f = Join-Path $root 'mfa-sample'; New-Item -ItemType Directory -Path $f | Out-Null
            $null = Invoke-PostureEntraCollection -Folder $f -WarningAction SilentlyContinue
            $sum = Get-Content -Raw (Join-Path $f '05-per-user-mfa-summary.json') | ConvertFrom-Json
            $sum.Mode | Should -Be 'sample'
            $sum.SampleSize | Should -Be 1000
            $sum.Members | Should -Be 6000
            $script:Batches | Should -Be 50

            $script:State = 'enforced'; $script:Batches = 0
            $g = Join-Path $root 'mfa-full'; New-Item -ItemType Directory -Path $g | Out-Null
            $null = Invoke-PostureEntraCollection -Folder $g -WarningAction SilentlyContinue
            $full = Get-Content -Raw (Join-Path $g '05-per-user-mfa-summary.json') | ConvertFrom-Json
            $full.Mode | Should -Be 'full'
            $full.Users | Should -Be 6000 -Because 'someone in the sample had it, so everyone was read'
        }
    }
}

Describe 'Checks read large lists a row at a time' {
    It 'gives the device checks the same facts from the CSV as from the JSON of older runs' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
            param($root)
            Mock Write-Host { }
            $f = Join-Path $root 'devices-equal'; New-Item -ItemType Directory -Path $f | Out-Null
            $entra = @(for ($n = 0; $n -lt 300; $n++) { [ordered]@{ Id = "e$n"; DeviceId = "d$n"; DisplayName = "PC-$n"; OperatingSystem = $(if ($n % 3) { 'Windows' } else { 'macOS' }); AccountEnabled = ($n % 50 -ne 0); JoinType = @('EntraJoined', 'HybridJoined', 'Registered')[$n % 3]; Stale = ($n % 7 -eq 0); ApproximateLastSignInDateTime = '2026-01-01T00:00:00Z' } })
            $managed = @(for ($n = 0; $n -lt 300; $n++) { [ordered]@{ DeviceName = "PC-$n"; OperatingSystem = @('Windows', 'macOS', 'iOS')[$n % 3]; OSVersion = $(if ($n % 2) { '10.0.19045.1' } else { '10.0.26100.1' }); ComplianceState = @('compliant', 'noncompliant', 'unknown')[$n % 3]; AutopilotEnrolled = ($n % 4 -eq 0); IsEncrypted = ($n % 5 -ne 0); UserPrincipalName = "u$n@contoso.example" } })
            $null = Write-PostureEvidence -Folder $f -Name '08-entra-devices' -InputObject $entra -AsArray -Csv
            $null = Write-PostureEvidence -Folder $f -Name '09-intune-managed-devices' -InputObject $managed -AsArray -Csv
            $null = Write-PostureEvidence -Folder $f -Name '08-bitlocker-keys-by-device' -InputObject @(@{ DeviceId = 'd1'; Keys = 1 }) -AsArray
            $null = Write-PostureEvidence -Folder $f -Name '09-autopilot-devices' -InputObject @() -AsArray
            $fromCsv = Get-PostureDevicesFact -Evidence $f
            Clear-PostureEvidenceCache -Confirm:$false
            Remove-Item (Join-Path $f '*.csv')
            $fromJson = Get-PostureDevicesFact -Evidence $f
            ($fromCsv.facts | ConvertTo-Json -Depth 5 -Compress) | Should -Be ($fromJson.facts | ConvertTo-Json -Depth 5 -Compress)
            ($fromCsv.affected | ConvertTo-Json -Depth 5 -Compress) | Should -Be ($fromJson.affected | ConvertTo-Json -Depth 5 -Compress)
            $fromCsv.facts.staleEntraDevices | Should -BeGreaterThan 0
            $fromCsv.facts.windows10Devices | Should -BeGreaterThan 0
        }
    }

    It 'finds a handful of rows by id without loading the list, and says when the list was not collected' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
            param($root)
            Mock Write-Host { }
            $f = Join-Path $root 'find-rows'; New-Item -ItemType Directory -Path $f | Out-Null
            $null = Write-PostureEvidence -Folder $f -Name '06-users' -InputObject @(for ($n = 0; $n -lt 1000; $n++) { [ordered]@{ Id = "u$n"; UserPrincipalName = "u$n@contoso.example"; AccountEnabled = ($n % 2 -eq 0) } }) -AsArray -Csv
            $hit = Find-PostureEvidenceRow -Folder $f -Name '06-users' -Key Id -Value @('u2', 'u3', 'missing')
            @($hit.Keys | Sort-Object) | Should -Be @('u2', 'u3')
            Test-PostureTrue $hit['u2'].AccountEnabled | Should -BeTrue
            Test-PostureTrue $hit['u3'].AccountEnabled | Should -BeFalse
            Find-PostureEvidenceRow -Folder $f -Name 'not-collected' -Key Id -Value @('x') | Should -BeNullOrEmpty
        }
    }
}

Describe 'A failing sign-in read' {
    It 'is recorded and the other collectors still run (seen live 2026-11-20: it stopped Intune, Defender, SharePoint and Teams)' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
            param($root)
            Mock Write-Host { }
            Mock Get-MgContext { [pscustomobject]@{ TenantId = 't'; Account = 'a'; AuthType = 'Delegated'; Scopes = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All', 'AuditLog.Read.All') } }
            Mock Invoke-PostureSignInCollection { throw 'Response status code does not indicate success: BadRequest (Bad Request).' }
            Mock Invoke-PostureIntuneCollection { @{ files = @() } }
            $f = Join-Path $root 'signin-fails'
            $r = Invoke-PostureCollection -Collector SignIns, Intune -SkipCaSnapshot -OutputFolder $f -PassThru -WarningAction SilentlyContinue
            Should -Invoke Invoke-PostureIntuneCollection -Times 1 -Exactly
            @($r.Collectors) | Should -Contain 'Intune'
            Get-Content (Join-Path $f 'errors.txt') | Should -Match 'Sign-in log ::'
        }
    }

    It 'does not wait and retry a query Graph rejects outright' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
            param($root)
            Mock Assert-PostureGraphScope { @{ Scopes = @('AuditLog.Read.All') } }
            Mock Start-Sleep { }
            $script:Calls = 0
            Mock Invoke-MgGraphRequest { $script:Calls++; throw "Response status code does not indicate success: BadRequest (Bad Request). Could not find a property named 'x' on type 'microsoft.graph.signIn'." }
            $f = Join-Path $root 'signin-badrequest'; New-Item -ItemType Directory -Path $f | Out-Null
            { Invoke-PostureSignInCollection -Folder $f -Days 7 -SelfRetryWaitSeconds 60 -WarningAction SilentlyContinue } | Should -Throw '*BadRequest*'
            $script:Calls | Should -Be 1
            Should -Invoke Start-Sleep -Times 0 -Exactly
            Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Uri -like 'https://graph.microsoft.com/beta/auditLogs/signIns*' }
        }
    }
}

