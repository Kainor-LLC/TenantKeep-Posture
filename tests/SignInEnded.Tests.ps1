# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# A run that outlives its sign-in: the renewal that is refused, the admin asked to sign in again, the run that stops
# once when there is no one to ask, and what the run says beforehand.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-signin-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    function script:New-FakeJwt([hashtable] $Claims) {
        $b64 = { param($o) [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
        return "$(& $b64 @{ alg = 'none' }).$(& $b64 $Claims).sig"
    }
    $script:Tid = '33333333-3333-3333-3333-333333333333'
    $script:Refused = 'Sign-in failed (invalid_grant): AADSTS70043: The refresh token has expired or is invalid due to sign-in frequency checks by conditional access. The token was issued on 2026-11-21T09:00:00Z and the maximum allowed lifetime for this request is 14400.'
    Mock -ModuleName TenantKeep.Posture Write-Host { }
    Mock -ModuleName TenantKeep.Posture Step-PostureProgress { }

    # A session as Connect-PostureSession leaves it, with the Graph token already past its time.
    $script:NewSession = {
        param([bool] $Interactive = $true)
        InModuleScope TenantKeep.Posture -Parameters @{ Tid = $script:Tid; Interactive = $Interactive } {
            param($Tid, $Interactive)
            $script:PostureSessionEnded.Clear()
            $script:PostureTokenServer = $null
            $script:PostureSession = @{
                clientId = 'aaaaaaaa-0000-0000-0000-000000000001'; tenantId = $Tid; tenantName = 'contoso'; account = 'admin@contoso.example'
                refreshToken = 'refresh-1'; signedInUtc = [datetime]::UtcNow.AddHours(-4); interactive = $Interactive; signInMode = 'device'; signInsRenewed = 0
                tokens = @{ graph = @{ accessToken = 'old'; expiresUtc = [datetime]::UtcNow.AddMinutes(-1); scope = '' } }
            }
        }
    }
}

AfterAll {
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
    InModuleScope TenantKeep.Posture { $script:PostureSession = $null; $script:PostureSessionEnded.Clear(); $script:PostureTokenServer = $null; $script:PostureJournalFolder = $null; $script:PostureCurrentCollector = $null }
}

Describe 'A renewal the identity platform refuses' {
    It 'is an ended sign-in for <Text>' -ForEach @(
        @{ Text = 'Sign-in failed (invalid_grant): AADSTS70043: The refresh token has expired or is invalid due to sign-in frequency checks by conditional access.'; Ended = $true }
        @{ Text = 'Sign-in failed (invalid_grant): AADSTS700082: The refresh token has expired due to inactivity.'; Ended = $true }
        @{ Text = 'Sign-in failed (interaction_required): AADSTS50076: Due to a configuration change made by your administrator, you must use multi-factor authentication.'; Ended = $true }
        @{ Text = 'Sign-in failed (invalid_grant): AADSTS50173: The provided grant has expired due to it being revoked.'; Ended = $true }
        @{ Text = 'Sign-in failed (invalid_grant): AADSTS65001: The user or administrator has not consented to use the application.'; Ended = $false }
        @{ Text = 'Sign-in failed (access_denied): AADSTS53003: Access has been blocked by Conditional Access policies.'; Ended = $false }
        @{ Text = 'Sign-in failed (invalid_grant): AADSTS50105: The signed in user is not assigned to a role for the application.'; Ended = $false }
        @{ Text = 'The operation has timed out.'; Ended = $false }
    ) {
        InModuleScope TenantKeep.Posture -Parameters @{ Text = $Text } { param($Text) Test-PostureSignInEnded -Message $Text } | Should -Be $Ended
    }

    It 'stops the run once when there is no one to ask: the next renewal is not even sent' {
        & $script:NewSession $true
        InModuleScope TenantKeep.Posture -Parameters @{ Refused = $script:Refused } {
            param($Refused)
            Mock Test-PostureInteractive { $false }
            Mock Invoke-PostureSignIn { throw 'no one should be asked' }
            Mock Invoke-PostureTokenRequest { throw $Refused }
            { Get-PostureToken -Resource graph } | Should -Throw '*The sign-in ended at * UTC and could not be renewed: there is no one to ask in this run (AADSTS70043).*Resume-PostureRun*'
            $script:PostureSessionEnded.ContainsKey('main') | Should -BeTrue
            { Get-PostureToken -Resource powerbi } | Should -Throw '*The sign-in ended at *'
            Should -Invoke Invoke-PostureTokenRequest -Times 1 -Exactly -Because 'a sign-in known to have ended is not asked about again'
            Should -Invoke Invoke-PostureSignIn -Times 0 -Exactly
            Get-PostureFailureCause -Message "The sign-in ended at 14:02 UTC and could not be renewed: there is no one to ask in this run (AADSTS70043). Resume-PostureRun carries on after a new sign-in." | Should -Be 'token'
        }
    }

    It 'asks the same admin to sign in again, keeps the new refresh token, and gives the token that was asked for' {
        & $script:NewSession $true
        $jwt = New-FakeJwt @{ tid = $script:Tid; upn = 'Admin@Contoso.example' }
        InModuleScope TenantKeep.Posture -Parameters @{ Refused = $script:Refused; Jwt = $jwt } {
            param($Refused, $Jwt)
            Mock Test-PostureInteractive { $true }
            Mock Invoke-PostureSignIn { @{ access_token = $Jwt; refresh_token = 'refresh-2'; expires_in = 3600 } }
            Mock Invoke-PostureTokenRequest {
                if ($Form['refresh_token'] -eq 'refresh-1') { throw $Refused }
                @{ access_token = "token-for-$($Form['scope'])-with-$($Form['refresh_token'])"; expires_in = 3600 }
            }
            # The token service of the second process holds a copy of the session; it gets the new refresh token too.
            $script:PostureTokenServer = @{ pipe = 'p'; session = [hashtable]::Synchronized(@{ refreshToken = 'refresh-1' }) }
            Get-PostureToken -Resource powerbi | Should -Be "token-for-$(Get-PostureResourceScope -Resource powerbi)-with-refresh-2"
            Should -Invoke Invoke-PostureSignIn -Times 1 -Exactly -ParameterFilter { $LoginHint -eq 'admin@contoso.example' -and $DeviceCode -and $TenantId -eq '33333333-3333-3333-3333-333333333333' -and $Scope -match 'offline_access https://graph\.microsoft\.com/User\.Read$' } -Because 'the browser step asks only to sign in: the app is shared, and a request for everything it holds could offer more than this product asks for'
            $script:PostureSession['refreshToken'] | Should -Be 'refresh-2'
            $script:PostureSession['signInsRenewed'] | Should -Be 1
            $script:PostureSession['tokens']['graph']['accessToken'] | Should -Be 'token-for-https://graph.microsoft.com/.default-with-refresh-2' -Because 'what the organisation approved is fetched with the new refresh token, a request that shows no prompt'
            $script:PostureTokenServer['session']['refreshToken'] | Should -Be 'refresh-2'
            $script:PostureSessionEnded.get_Count() | Should -Be 0
        }
    }

    It 'stops the run when the new sign-in is <Why>' -ForEach @(
        @{ Why = 'someone else'; Claims = @{ tid = '33333333-3333-3333-3333-333333333333'; upn = 'other@contoso.example' }; Says = '*the new sign-in was as other@contoso.example*' }
        @{ Why = 'in another tenant'; Claims = @{ tid = '44444444-4444-4444-4444-444444444444'; upn = 'admin@contoso.example' }; Says = '*the new sign-in went to tenant 44444444*' }
    ) {
        & $script:NewSession $true
        $jwt = New-FakeJwt $Claims
        InModuleScope TenantKeep.Posture -Parameters @{ Refused = $script:Refused; Jwt = $jwt; Says = $Says } {
            param($Refused, $Jwt, $Says)
            Mock Test-PostureInteractive { $true }
            Mock Invoke-PostureSignIn { @{ access_token = $Jwt; refresh_token = 'refresh-x'; expires_in = 3600 } }
            Mock Invoke-PostureTokenRequest { throw $Refused }
            { Get-PostureToken -Resource graph } | Should -Throw $Says
            $script:PostureSession['refreshToken'] | Should -Be 'refresh-1' -Because 'everything read so far was read as the first account'
            $script:PostureSessionEnded.ContainsKey('main') | Should -BeTrue
        }
    }

    It 'stops the run when no one signs in, and after three new sign-ins in one run' {
        & $script:NewSession $true
        InModuleScope TenantKeep.Posture -Parameters @{ Refused = $script:Refused } {
            param($Refused)
            Mock Test-PostureInteractive { $true }
            Mock Invoke-PostureSignIn { throw 'The device code expired before the sign-in completed. Run the command again.' }
            Mock Invoke-PostureTokenRequest { throw $Refused }
            { Get-PostureToken -Resource graph } | Should -Throw '*the new sign-in did not complete (The device code expired*'
            $script:PostureSessionEnded.Clear()
            $script:PostureSession['signInsRenewed'] = 3
            { Get-PostureToken -Resource graph } | Should -Throw '*it was renewed 3 times in this run already*'
            Should -Invoke Invoke-PostureSignIn -Times 1 -Exactly
        }
    }

    It 'leaves any other refusal as it came, and never asks from the thread that renews for the second process' {
        & $script:NewSession $true
        InModuleScope TenantKeep.Posture -Parameters @{ Refused = $script:Refused } {
            param($Refused)
            Mock Test-PostureInteractive { $true }
            Mock Invoke-PostureSignIn { throw 'no one should be asked' }
            Mock Invoke-PostureTokenRequest { throw 'Sign-in failed (invalid_grant): AADSTS65001: The user or administrator has not consented to use the application.' }
            { Get-PostureToken -Resource graph } | Should -Throw '*AADSTS65001*'
            $script:PostureSessionEnded.get_Count() | Should -Be 0
            Mock Invoke-PostureTokenRequest { throw $Refused }
            $script:PostureSession['serviceThread'] = $true
            { Get-PostureToken -Resource graph } | Should -Throw '*the main window has to sign in again (AADSTS70043)*'
            $script:PostureSessionEnded.get_Count() | Should -Be 0 -Because 'once the main thread has signed in again, the next renewal from this thread works'
            Should -Invoke Invoke-PostureSignIn -Times 0 -Exactly
        }
    }
}

Describe 'A Graph page that meets an ended sign-in' {
    It 'is asked for again, the same page, once the admin has signed in again' {
        & $script:NewSession $true
        $jwt = New-FakeJwt @{ tid = $script:Tid; upn = 'admin@contoso.example' }
        InModuleScope TenantKeep.Posture -Parameters @{ Refused = $script:Refused; Jwt = $jwt } {
            param($Refused, $Jwt)
            Mock Test-PostureInteractive { $true }
            Mock Connect-PostureService { }
            Mock Add-PostureCallRecord { }
            Mock Invoke-PostureSignIn { @{ access_token = $Jwt; refresh_token = 'refresh-2'; expires_in = 3600 } }
            Mock Invoke-PostureTokenRequest { if ($Form['refresh_token'] -eq 'refresh-1') { throw $Refused }; @{ access_token = 'fresh'; expires_in = 3600 } }
            # Page 2 answers 401 until there is a new sign-in.
            $script:TestAsked = [System.Collections.Generic.List[string]]::new()
            Mock Invoke-MgGraphRequest {
                $script:TestAsked.Add([string]$Uri)
                if ($Uri -match 'skiptoken=2' -and $script:PostureSession['refreshToken'] -eq 'refresh-1') { throw 'Response status code does not indicate success: Unauthorized (Unauthorized).' }
                if ($Uri -match 'skiptoken=2') { return @{ value = @(@{ id = 'b' }) } }
                @{ value = @(@{ id = 'a' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users?$skiptoken=2' }
            }
            $rows = @(Invoke-PostureGraphRequest -Uri 'users' -ApiVersion 'v1.0')
            @($rows | ForEach-Object { $_['id'] }) | Should -Be @('a', 'b')
            @($script:TestAsked | Where-Object { $_ -match 'skiptoken=2' }).Count | Should -Be 2 -Because 'the page that was refused is the page asked for again'
            Should -Invoke Invoke-PostureSignIn -Times 1 -Exactly
            Should -Invoke Connect-PostureService -Times 1 -Exactly -ParameterFilter { $Name -eq 'graph' }
            Remove-Variable -Name TestAsked -Scope Script
        }
    }

    It 'fails the read with the ended sign-in, not with a bare 401, when there is no one to ask' {
        & $script:NewSession $true
        InModuleScope TenantKeep.Posture -Parameters @{ Refused = $script:Refused } {
            param($Refused)
            Mock Test-PostureInteractive { $false }
            Mock Connect-PostureService { }
            Mock Add-PostureCallRecord { }
            Mock Invoke-PostureTokenRequest { throw $Refused }
            Mock Invoke-MgGraphRequest { throw 'Response status code does not indicate success: Unauthorized (Unauthorized).' }
            { Invoke-PostureGraphRequest -Uri 'users' -ApiVersion 'v1.0' } | Should -Throw '*The sign-in ended at * UTC and could not be renewed*'
            $script:PostureSessionEnded.ContainsKey('main') | Should -BeTrue
        }
    }
}

Describe 'A step whose sign-in has ended' {
    BeforeEach {
        $script:Run = Join-Path $script:Root "run-$([guid]::NewGuid().ToString('n'))"; New-Item -ItemType Directory -Path $script:Run | Out-Null
        InModuleScope TenantKeep.Posture { $script:PostureSessionEnded.Clear(); $script:PostureSessionEnded['main'] = @{ utc = [datetime]::new(2026, 11, 21, 14, 2, 0, [System.DateTimeKind]::Utc); reason = 'there is no one to ask in this run (AADSTS70043).' } }
    }
    AfterEach { InModuleScope TenantKeep.Posture { $script:PostureSessionEnded.Clear(); $script:PostureJournalFolder = $null; $script:PostureCurrentCollector = $null } }

    It 'is not attempted for <Collector>: <Runs>' -ForEach @(
        @{ Collector = 'Entra'; Runs = $false }, @{ Collector = 'PowerBI'; Runs = $false }
        # Azure, Teams and Power Platform read through the second app's sign-in (Teams with two tokens of that app,
        # since the Teams module refuses a pair from two apps), SharePoint through its own, and Exchange and Purview
        # sign in through the Exchange module.
        @{ Collector = 'Azure'; Runs = $true }, @{ Collector = 'Teams'; Runs = $true }, @{ Collector = 'PowerPlatform'; Runs = $true }
        @{ Collector = 'SharePoint'; Runs = $true }, @{ Collector = 'Exchange'; Runs = $true }, @{ Collector = 'Purview'; Runs = $true }
    ) {
        InModuleScope TenantKeep.Posture -Parameters @{ F = $script:Run; Collector = $Collector; Runs = $Runs } {
            param($F, $Collector, $Runs)
            $script:PostureJournalFolder = $F; $script:PostureCurrentCollector = $Collector
            $seen = @{ ran = $false }
            $null = Invoke-PostureStep -Label 'Something' -Folder $F -Script { $seen.ran = $true }
            $seen.ran | Should -Be $Runs
            if (-not $Runs) {
                (Get-PostureJournalState -Folder $F).steps["$Collector|Something"].state | Should -Be 'skipped'
                Join-Path $F 'errors.txt' | Should -Not -Exist -Because 'the collection writes one line for the domain, not one for each step'
            }
        }
    }

    It 'stops Azure, Teams and Power Platform, and nothing else, when the second app''s sign-in is the one that ended' {
        InModuleScope TenantKeep.Posture {
            $ended = $script:PostureSessionEnded['main']; $script:PostureSessionEnded.Clear(); $script:PostureSessionEnded['services'] = $ended
            foreach ($collector in 'Azure', 'Teams', 'PowerPlatform') { (Get-PostureEndedSignIn -Collector $collector).holder | Should -Be 'services' -Because $collector }
            foreach ($collector in 'Entra', 'Intune', 'Defender', 'PowerBI', 'SharePoint', 'Exchange', 'Purview') { Get-PostureEndedSignIn -Collector $collector | Should -BeNullOrEmpty -Because $collector }
        }
    }

    It 'still keeps a long list that finished earlier in the run: that needs no sign-in' {
        InModuleScope TenantKeep.Posture -Parameters @{ F = $script:Run } {
            param($F)
            $script:PostureJournalFolder = $F; $script:PostureCurrentCollector = 'Entra'
            $ended = $script:PostureSessionEnded['main']; $script:PostureSessionEnded.Clear()
            $null = Invoke-PostureStep -Label 'Users' -Folder $F -KeepDone -Script { $null = Write-PostureEvidence -Folder $F -Name '06-users' -InputObject @(@{ Id = 'u1' }) -AsArray -Quiet }
            $script:PostureSessionEnded['main'] = $ended
            $seen = @{ ran = $false; kept = $false }
            $null = Invoke-PostureStep -Label 'Users' -Folder $F -KeepDone -WhenKept { $seen.kept = $true } -Script { $seen.ran = $true }
            $seen.kept | Should -BeTrue
            $seen.ran | Should -BeFalse
            (Get-PostureJournalState -Folder $F).steps['Entra|Users'].state | Should -Be 'done'
        }
    }
}

Describe 'A collection whose sign-in ends part way' {
    BeforeAll {
        $script:Run = Join-Path $script:Root 'collection'; New-Item -ItemType Directory -Path $script:Run | Out-Null
        # The mocks are made inside the module, where their bodies can call the step runner.
        $script:R = InModuleScope TenantKeep.Posture -Parameters @{ Run = $script:Run } {
            param($Run)
            Mock Get-MgContext { [pscustomobject]@{ TenantId = 'tenant-guid'; Account = 'admin@contoso.example'; AuthType = 'Delegated'; Scopes = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All') } }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }
            # Entra reads one thing and the sign-in ends in the next; Intune comes after and never gets a request.
            Mock Invoke-PostureEntraCollection {
                $null = Invoke-PostureStep -Label 'Organization' -Folder $Folder -Script { $null = Write-PostureEvidence -Folder $Folder -Name '01-organization' -InputObject @(@{ id = 't' }) -AsArray -Quiet }
                $null = Invoke-PostureStep -Label 'Users' -Folder $Folder -Script {
                    $script:PostureSessionEnded['main'] = @{ utc = [datetime]::new(2026, 11, 21, 14, 2, 0, [System.DateTimeKind]::Utc); reason = 'there is no one to ask in this run (AADSTS70043).' }
                    throw 'The sign-in ended at 14:02 UTC and could not be renewed: there is no one to ask in this run (AADSTS70043). Resume-PostureRun carries on after a new sign-in.'
                } -WarningAction SilentlyContinue
                foreach ($label in 'Groups', 'Entra devices', 'Risky users') { $null = Invoke-PostureStep -Label $label -Folder $Folder -Script { throw 'a step after the sign-in ended must not run' } }
                @{ files = @() }
            }
            Mock Invoke-PostureIntuneCollection {
                foreach ($label in 'Intune managed devices', 'Intune apps') { $null = Invoke-PostureStep -Label $label -Folder $Folder -Script { throw 'a step after the sign-in ended must not run' } }
                @{ files = @() }
            }
            $script:PostureSessionEnded.Clear(); $script:PostureSession = $null
            try { Invoke-PostureCollection -Collector Entra, Intune -SkipCaSnapshot -OutputFolder $Run -PassThru -WarningAction SilentlyContinue 6>$null }
            finally { $script:PostureSessionEnded.Clear() }
        }
    }

    It 'writes one line for each domain that did not finish, with how many steps were left, and no line per step' {
        $errors = @(Get-Content (Join-Path $script:Run 'errors.txt'))
        $errors.Count | Should -Be 3 -Because 'the step the sign-in ended in, and one line each for Entra and Intune'
        $errors[0] | Should -Match '^Users :: The sign-in ended at 14:02 UTC'
        $errors[1] | Should -Match '^Steps not attempted :: The sign-in ended at 14:02 UTC: there is no one to ask in this run \(AADSTS70043\)\. 3 step\(s\) of Entra were not attempted'
        $errors[2] | Should -Match '2 step\(s\) of Intune were not attempted'
        $failures = @(Get-Content (Join-Path $script:Run 'errors.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
        @($failures.cause | Sort-Object -Unique) | Should -Be @('token')
        @($failures.collector) | Should -Be @('Entra', 'Entra', 'Intune')
    }

    It 'does not record the domains as finished, so the run is resumed from them' {
        @($script:R.Collectors) | Should -BeNullOrEmpty
        InModuleScope TenantKeep.Posture -Parameters @{ F = $script:Run } {
            param($F)
            $state = Get-PostureJournalState -Folder $F
            $state.collectors['Entra'].state | Should -Be 'stopped'
            $state.collectors['Intune'].state | Should -Be 'stopped'
            @(Get-PostureFinishedCollector -Folder $F -Manifest @('ConditionalAccess', 'Entra', 'Intune')) | Should -Be @('ConditionalAccess') -Because 'an earlier attempt that finished them does not make this one finished'
            @($state.steps.get_Values() | Where-Object { $_.state -eq 'skipped' }).Count | Should -Be 5
        }
    }

    It 'says in Run Health which domains stopped and which steps were not attempted' {
        . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
        $ev = Initialize-CollectionFixture -Root (Join-Path $script:Root 'health')
        Copy-Item -LiteralPath (Join-Path $script:Run 'journal.jsonl') -Destination $ev
        Copy-Item -LiteralPath (Join-Path $script:Run 'errors.jsonl') -Destination $ev
        InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' }; Clear-PostureEvidenceCache -Confirm:$false }
        try { $r = New-PostureReport -Evidence $ev -PassThru } finally { InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null } }
        @($r.Report.runHealth.notFinished | Sort-Object) | Should -Be @('Entra', 'Intune')
        @($r.Report.runHealth.notAttempted).Count | Should -Be 5
        @($r.Report.runHealth.failures | ForEach-Object { $_.causeLabel } | Sort-Object -Unique) | Should -Be @('Sign-in ran out')
        $html = Get-Content -Raw (@($r.Files) -like '*.html')[0]
        $html | Should -Match '5 step\(s\) were not attempted, because the sign-in they depend on had ended'
        $html | Should -Match '<td>Intune</td><td>Intune managed devices</td>'
        Get-Content -Raw (@($r.Files) -like '*.md')[0] | Should -Match 'Not attempted, because the sign-in had ended: 5 step\(s\)\.'
    }
}

Describe 'Why a step failed, when the sign-in ended' {
    It 'classifies <Text> as <Cause>' -ForEach @(
        @{ Text = 'Response status code does not indicate success: Unauthorized (Unauthorized). [GET https://graph.microsoft.com/v1.0/users?$top=999]'; Cause = 'token' }
        @{ Text = 'The remote server returned an error: (401) Unauthorized.'; Cause = 'token' }
        @{ Text = 'Sign-in failed (invalid_grant): AADSTS70043: The refresh token has expired or is invalid due to sign-in frequency checks by conditional access.'; Cause = 'token' }
        @{ Text = 'The main process could not renew the graph token: The sign-in ended at 14:02 UTC and could not be renewed: the main window has to sign in again (AADSTS70043).'; Cause = 'token' }
        @{ Text = 'Sign-in failed (invalid_grant): AADSTS65001: The user or administrator has not consented to use the application.'; Cause = 'permission' }
        @{ Text = 'Attempted to perform an unauthorized operation.'; Cause = 'permission' }
        @{ Text = 'Response status code does not indicate success: Forbidden (Forbidden). 401 is not what this says: Insufficient privileges to complete the operation.'; Cause = 'permission' }
    ) {
        InModuleScope TenantKeep.Posture -Parameters @{ Text = $Text } { param($Text) Get-PostureFailureCause -Message $Text } | Should -Be $Cause
    }
}

Describe 'The sign-in frequency a run is told about beforehand' {
    BeforeAll {
        $script:Policies = {
            param([object[]] $Policy)
            $f = Join-Path $script:Root "ca-$([guid]::NewGuid().ToString('n'))"; New-Item -ItemType Directory -Path $f | Out-Null
            ConvertTo-Json -InputObject @($Policy) -Depth 20 | Set-Content (Join-Path $f 'policies.json')
            InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache -Confirm:$false }
            $f
        }
        $script:Policy = {
            param([string] $Name, [int] $Value, [string] $Type = 'hours', [hashtable] $Users = @{ includeUsers = @('All') }, [string[]] $Apps = @('All'), [string] $State = 'enabled', [string] $Interval = 'timeBased')
            @{ displayName = $Name; state = $State; conditions = @{ users = $Users; applications = @{ includeApplications = $Apps } }; sessionControls = @{ signInFrequency = @{ isEnabled = $true; type = $Type; value = $Value; frequencyInterval = $Interval } } }
        }
        $script:Notice = { param([string] $Folder, [hashtable] $More = @{}) InModuleScope TenantKeep.Posture -Parameters @{ F = $Folder; More = $More } { param($F, $More) Get-PostureSignInFrequencyNotice -Folder $F @More } }
        $script:GaRole = '62e90394-69f5-4237-9190-012177145e10'
    }

    It 'is the shortest one that applies to the account, by its roles' {
        $f = & $script:Policies @(
            (& $script:Policy 'Everyone, 30 days' 30 'days'),
            (& $script:Policy 'Admins, 4 hours' 4 'hours' @{ includeRoles = @($script:GaRole) }),
            (& $script:Policy 'Other role, 1 hour' 1 'hours' @{ includeRoles = @('f28a1f50-f6e7-4571-818b-6a12f2af6b6c') })
        )
        $n = & $script:Notice $f @{ ObjectId = 'oid-1'; RoleTemplateId = @($script:GaRole); Interactive = $true }
        $n.hours | Should -Be 4
        $n.certain | Should -BeTrue
        $n.text | Should -Be "Sign-in frequency: the Conditional Access policy 'Admins, 4 hours' asks this account to sign in again every 4 hours. When this run outlasts that, it pauses and asks for the sign-in again, then carries on."
    }

    It 'says what happens in a run with no one to ask' {
        $f = & $script:Policies @((& $script:Policy 'Everyone, 2 days' 2 'days'))
        (& $script:Notice $f @{ ObjectId = 'oid-1' }).text | Should -Be "Sign-in frequency: the Conditional Access policy 'Everyone, 2 days' asks this account to sign in again every 2 days. When this run outlasts that, it stops there, and Resume-PostureRun carries on after a new sign-in."
    }

    It 'leaves out a policy that <Why>' -ForEach @(
        @{ Why = 'excludes the account'; Users = @{ includeUsers = @('All'); excludeUsers = @('oid-1') }; Apps = @('All'); State = 'enabled'; Interval = 'timeBased' }
        @{ Why = 'excludes a role the account holds'; Users = @{ includeUsers = @('All'); excludeRoles = @('62e90394-69f5-4237-9190-012177145e10') }; Apps = @('All'); State = 'enabled'; Interval = 'timeBased' }
        @{ Why = 'is for one application that is not Microsoft Graph'; Users = @{ includeUsers = @('All') }; Apps = @('11111111-2222-3333-4444-555555555555'); State = 'enabled'; Interval = 'timeBased' }
        @{ Why = 'is report-only'; Users = @{ includeUsers = @('All') }; Apps = @('All'); State = 'enabledForReportingButNotEnforced'; Interval = 'timeBased' }
        @{ Why = 'asks every time, which is for particular actions'; Users = @{ includeUsers = @('All') }; Apps = @('All'); State = 'enabled'; Interval = 'everyTime' }
        @{ Why = 'names other people'; Users = @{ includeUsers = @('oid-2') }; Apps = @('All'); State = 'enabled'; Interval = 'timeBased' }
    ) {
        $f = & $script:Policies @((& $script:Policy 'P' 4 'hours' $Users $Apps $State $Interval))
        & $script:Notice $f @{ ObjectId = 'oid-1'; RoleTemplateId = @($script:GaRole) } | Should -BeNullOrEmpty
    }

    It 'says "may" when it depends on a group, or on roles that are not known' {
        $f = & $script:Policies @((& $script:Policy 'Group, 8 hours' 8 'hours' @{ includeGroups = @('g1') }))
        $n = & $script:Notice $f @{ ObjectId = 'oid-1'; RoleTemplateId = @($script:GaRole) }
        $n.certain | Should -BeFalse
        $n.text | Should -Match "'Group, 8 hours' may ask this account to sign in again every 8 hours"
        $f2 = & $script:Policies @((& $script:Policy 'Admins, 4 hours' 4 'hours' @{ includeRoles = @($script:GaRole) }))
        (& $script:Notice $f2).certain | Should -BeFalse -Because 'without a token the account''s roles are not known'
        (& $script:Notice $f2 @{ RoleTemplateId = @('f28a1f50-f6e7-4571-818b-6a12f2af6b6c') }) | Should -BeNullOrEmpty -Because 'the account holds another role'
    }

    It 'is said on the console and in the journal by a collection a person signed in to, and not in the second process' {
        $f = & $script:Policies @((& $script:Policy 'Everyone, 8 hours' 8))
        InModuleScope TenantKeep.Posture -Parameters @{ F = $f } {
            param($F)
            Mock Test-PostureInteractive { $true }
            $script:PostureJournalFolder = $F
            try {
                $script:PostureSession = @{ objectId = 'oid-1'; roleTemplateIds = @(); interactive = $true }
                Write-PostureSignInFrequencyNotice -Folder $F
                Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { [string]$Object -match "'Everyone, 8 hours' asks this account to sign in again every 8 hours\. When this run outlasts that, it pauses" }
                $entry = @(Read-PostureJournal -Folder $F | Where-Object { $_['state'] -eq 'signInFrequency' })
                $entry.Count | Should -Be 1
                $entry[0]['hours'] | Should -Be 8
                $script:PostureSession = @{ objectId = 'oid-1'; tokenPipe = 'pipe-name'; interactive = $false }
                Write-PostureSignInFrequencyNotice -Folder $F
                Should -Invoke Write-Host -Times 1 -Exactly -Because 'the second process says nothing: the main one has said it'
            }
            finally { $script:PostureJournalFolder = $null; $script:PostureSession = $null }
        }
    }

    It 'is nothing when no policy sets one, or the snapshot is not there' {
        $f = & $script:Policies @(@{ displayName = 'MFA for all'; state = 'enabled'; conditions = @{ users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('All') } }; grantControls = @{ builtInControls = @('mfa') } })
        & $script:Notice $f | Should -BeNullOrEmpty
        $empty = Join-Path $script:Root 'no-snapshot'; New-Item -ItemType Directory -Path $empty | Out-Null
        & $script:Notice $empty | Should -BeNullOrEmpty
    }
}
