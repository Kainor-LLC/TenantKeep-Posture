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
            Mock Invoke-MgGraphRequest { $m = [regex]::Match($Uri, 'skip=(\d+)'); & $script:Page $(if ($m.Success) { [int]$m.Groups[1].Value } else { 0 }) }
            $null = Invoke-PostureSignInCollection -Folder $f -Days 7 -AsOf ([datetime]'2026-11-20T12:00:00Z')
            $s = Get-Content -Raw (Join-Path $f '06-signins-summary.json') | ConvertFrom-Json -AsHashtable
            $s.SignIns | Should -Be 2500
            $s.LegacySignIns | Should -Be 250
            $s.LegacyUsers | Should -Be 5 -Because 'every tenth sign-in is IMAP4, which lands on five of the fifty users'
            $s.Failures | Should -Be 100
            $s.ByConditionalAccessStatus.notApplied | Should -Be 1250
            $s.ByCountry.US | Should -Be 2500
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
