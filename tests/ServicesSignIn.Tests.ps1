# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# The second sign-in: TenantKeep Posture for Azure, Teams and Power Platform (app-services.json). The three APIs with
# no read-only permission are read through it, so that the shared TenantKeep app holds read-only permissions only.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    Mock -ModuleName TenantKeep.Posture Write-Host { }
    InModuleScope TenantKeep.Posture {
        $script:TestTid = '33333333-3333-3333-3333-333333333333'
        $script:TestApp = 'cccccccc-0000-0000-0000-000000000003'
        $script:SvcJwt = {
            param([string] $Upn, [string] $Tid = '33333333-3333-3333-3333-333333333333')
            $b64 = { param($o) [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
            "$(& $b64 @{ alg = 'none' }).$(& $b64 @{ tid = $Tid; upn = $Upn; scp = 'User.Read' }).sig"
        }
        $script:NewSession = {
            $script:PostureSessionEnded.Clear()
            $script:PostureSession = @{
                clientId = 'main-app'; tenantId = $script:TestTid; tenantName = 'contoso'; account = 'admin@contoso.example'; refreshToken = 'main-refresh'
                interactive = $true; signInMode = 'browser'; signInsRenewed = 0
                tokens = @{ graph = @{ accessToken = 'main-graph'; expiresUtc = [datetime]::UtcNow.AddHours(1); scope = '' } }
            }
        }
        # The shipped manifests, the second app's with a client id whether or not the shipped one carries its own yet.
        $script:TestManifests = @{ main = (Get-PostureAppManifest); sharepoint = (Get-PostureAppManifest -Name sharepoint); services = (Get-PostureAppManifest -Name services) }
        $script:TestManifests.services['clientId'] = $script:TestApp
        $script:UseTestManifests = { Mock Get-PostureAppManifest { $script:TestManifests[$(if ($Name) { $Name } else { 'main' })] } }
    }
}

AfterAll { InModuleScope TenantKeep.Posture { $script:PostureSession = $null; $script:PostureSessionEnded.Clear() } }

Describe 'The second sign-in, for Azure, Teams and Power Platform' {
    It 'signs in as the run''s account, asks the browser only to sign in, and keeps its refresh token apart from the main one' {
        InModuleScope TenantKeep.Posture {
            & $script:NewSession
            $script:PostureSession['tokens']['azure'] = @{ accessToken = 'earlier'; expiresUtc = [datetime]::UtcNow.AddHours(1); scope = '' }
            Mock Invoke-PostureSignIn { @{ access_token = (& $script:SvcJwt 'Admin@Contoso.example'); refresh_token = 'svc-refresh-1'; expires_in = 3600 } }
            Mock Invoke-PostureTokenRequest { @{ access_token = "token-for-$($Form['scope'])-as-$($Form['client_id'])"; refresh_token = "$($Form['refresh_token'])+"; expires_in = 3600 } }
            $r = Connect-PostureSession -Services -ClientId $script:TestApp
            $r.account | Should -Be 'admin@contoso.example'
            Should -Invoke Invoke-PostureSignIn -Times 1 -Exactly -ParameterFilter {
                $ClientId -eq 'cccccccc-0000-0000-0000-000000000003' -and $LoginHint -eq 'admin@contoso.example' -and $TenantId -eq '33333333-3333-3333-3333-333333333333' -and
                $Scope -eq 'openid profile offline_access https://graph.microsoft.com/User.Read' -and $AppName -eq 'TenantKeep Posture for Azure, Teams and Power Platform'
            } -Because 'a browser request for an API the organisation did not approve would stop the sign-in for all three'
            $script:PostureSession['services']['refreshToken'] | Should -Be 'svc-refresh-1'
            $script:PostureSession['refreshToken'] | Should -Be 'main-refresh'
            $script:PostureSession['tokens'].ContainsKey('azure') | Should -BeFalse -Because 'a token cached before this sign-in is asked for again'
            $script:PostureSession['tokens']['graph']['accessToken'] | Should -Be 'main-graph' -Because 'Graph stays the main sign-in''s'

            Get-PostureToken -Resource azure | Should -Be 'token-for-https://management.core.windows.net//.default-as-cccccccc-0000-0000-0000-000000000003'
            Should -Invoke Invoke-PostureTokenRequest -Times 1 -Exactly -ParameterFilter { $Form['client_id'] -eq 'cccccccc-0000-0000-0000-000000000003' -and $Form['refresh_token'] -eq 'svc-refresh-1' }
            $script:PostureSession['services']['refreshToken'] | Should -Be 'svc-refresh-1+' -Because 'a new refresh token replaces the old one, in the same holder'
            Get-PostureToken -Resource teams | Should -Be 'token-for-48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default-as-cccccccc-0000-0000-0000-000000000003'
            Get-PostureToken -Resource powerplatform | Should -Be 'token-for-https://service.powerapps.com//.default-as-cccccccc-0000-0000-0000-000000000003'
            $script:PostureSession['refreshToken'] | Should -Be 'main-refresh' -Because 'the main refresh token is never sent for the second app'

            Get-PostureToken -Resource powerbi | Should -Be 'token-for-https://analysis.windows.net/powerbi/api/.default-as-main-app' -Because 'Power BI has a read-only permission and stays on the main app'
            Should -Invoke Invoke-PostureTokenRequest -Times 0 -Exactly -ParameterFilter { $Form['client_id'] -eq 'main-app' -and $Form['scope'] -match 'management\.core|48ac35b8|powerapps' }
            Should -Invoke Invoke-PostureTokenRequest -Times 0 -Exactly -ParameterFilter { $Form['client_id'] -eq 'cccccccc-0000-0000-0000-000000000003' -and $Form['scope'] -match 'graph\.microsoft\.com|powerbi' } -Because 'no Graph or Power BI read ever rides on the second app'
        }
    }

    It 'hands the Teams module two tokens of the second app, and keeps that app''s Graph token apart from the run''s' {
        # Seen live 2026-11-23: handed a Graph token of the main app and a Teams token of the second, the Teams
        # module answered "ApplicationIds must match in the provided token" and nothing in Teams was read.
        InModuleScope TenantKeep.Posture {
            & $script:NewSession
            . $script:UseTestManifests
            $script:PostureSession['services'] = @{ clientId = $script:TestApp; refreshToken = 'svc-refresh-1'; account = 'admin@contoso.example' }
            Mock Invoke-PostureTokenRequest { @{ access_token = "token-for-$($Form['scope'])-as-$($Form['client_id'])"; expires_in = 3600 } }
            $script:TeamsGot = $null
            Set-Item -Path Function:\Connect-MicrosoftTeams -Value { param($AccessTokens) $script:TeamsGot = @($AccessTokens) }
            try {
                Connect-PostureService -Name teams
                $script:TeamsGot | Should -Be @(
                    'token-for-https://graph.microsoft.com/.default-as-cccccccc-0000-0000-0000-000000000003'
                    'token-for-48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default-as-cccccccc-0000-0000-0000-000000000003'
                ) -Because 'the Teams module refuses a pair of tokens from two apps'
                $script:PostureSession['tokens']['graph']['accessToken'] | Should -Be 'main-graph' -Because 'the run''s own Graph token is the main sign-in''s, and the second app''s never replaces it'
                $script:PostureSession['tokens']['graph@services']['accessToken'] | Should -Match 'as-cccccccc-0000-0000-0000-000000000003$'
                Get-PostureToken -Resource graph | Should -Be 'main-graph' -Because 'no Graph read of the run goes through the second app'
                Should -Invoke Invoke-PostureTokenRequest -Times 1 -Exactly -ParameterFilter { $Form['client_id'] -eq 'cccccccc-0000-0000-0000-000000000003' -and $Form['scope'] -eq 'https://graph.microsoft.com/.default' -and $Form['refresh_token'] -eq 'svc-refresh-1' }
                Should -Invoke Invoke-PostureTokenRequest -Times 0 -Exactly -ParameterFilter { $Form['client_id'] -eq 'main-app' }

                # Near expiry, both of Teams's tokens are renewed from the second app and the module is connected again.
                foreach ($key in 'graph@services', 'teams') { $script:PostureSession['tokens'][$key]['expiresUtc'] = [datetime]::UtcNow.AddMinutes(2) }
                $script:TeamsGot = $null
                Update-PostureServiceSession -Name teams -Confirm:$false
                $script:TeamsGot.Count | Should -Be 2
                $script:PostureSession['tokens']['graph@services']['expiresUtc'] | Should -BeGreaterThan ([datetime]::UtcNow.AddMinutes(30))
                $script:PostureSession['tokens']['graph']['accessToken'] | Should -Be 'main-graph'

                # A new sign-in to the second app drops that app's Graph token with the others.
                Mock Invoke-PostureSignIn { @{ access_token = (& $script:SvcJwt 'admin@contoso.example'); refresh_token = 'svc-refresh-2'; expires_in = 3600 } }
                $null = Connect-PostureSession -Services -ClientId $script:TestApp
                $script:PostureSession['tokens'].ContainsKey('graph@services') | Should -BeFalse
                $script:PostureSession['tokens']['graph']['accessToken'] | Should -Be 'main-graph'
            }
            finally { Remove-Item Function:\Connect-MicrosoftTeams -ErrorAction SilentlyContinue; $script:PostureConnected.Remove('teams') }
        }
    }

    It 'refuses another account or tenant, and words the sign-in service''s refusals as what to do' {
        InModuleScope TenantKeep.Posture {
            & $script:NewSession
            Mock Invoke-PostureSignIn { @{ access_token = (& $script:SvcJwt 'someone.else@contoso.example'); refresh_token = 'x'; expires_in = 3600 } }
            { Connect-PostureSession -Services -ClientId $script:TestApp } | Should -Throw '*but the run is signed in as admin@contoso.example*'
            Mock Invoke-PostureSignIn { @{ access_token = (& $script:SvcJwt 'admin@contoso.example' '44444444-4444-4444-4444-444444444444'); refresh_token = 'x'; expires_in = 3600 } }
            { Connect-PostureSession -Services -ClientId $script:TestApp } | Should -Throw '*not the run''s tenant*'
            Mock Invoke-PostureSignIn { throw 'Sign-in failed (invalid_grant): AADSTS65001: The user or administrator has not consented to use the application.' }
            { Connect-PostureSession -Services -ClientId $script:TestApp } | Should -Throw '*has not approved TenantKeep Posture for Azure, Teams and Power Platform yet. An administrator approves it once, here: https://login.microsoftonline.com/33333333-3333-3333-3333-333333333333/v2.0/adminconsent?client_id=cccccccc-0000-0000-0000-000000000003*'
            Mock Invoke-PostureSignIn { throw 'Sign-in failed (access_denied): AADSTS53003: Access has been blocked by Conditional Access policies.' }
            { Connect-PostureSession -Services -ClientId $script:TestApp } | Should -Throw '*Conditional Access policy blocked the sign-in to TenantKeep Posture for Azure, Teams and Power Platform (app id cccccccc-0000-0000-0000-000000000003)*'
            Mock Invoke-PostureSignIn { throw 'Sign-in failed (invalid_client): AADSTS7000112: Application is disabled.' }
            { Connect-PostureSession -Services -ClientId $script:TestApp } | Should -Throw '*turned off in this organisation*'
            $script:PostureSession.ContainsKey('services') | Should -BeFalse
            { Connect-PostureSession -Services -SharePoint } | Should -Throw '*One at a time*'
            $script:PostureSession = $null
            { Connect-PostureSession -Services -ClientId $script:TestApp } | Should -Throw '*Sign in first*'
        }
    }

    It 'says so, and opens no browser, when the build carries no app id for the second app' {
        InModuleScope TenantKeep.Posture {
            & $script:NewSession
            $none = $script:TestManifests.services.Clone(); $none['clientId'] = ''
            Mock Get-PostureAppManifest { $(if ($Name -eq 'services') { $none } else { $script:TestManifests[$(if ($Name) { $Name } else { 'main' })] }) }
            Mock Invoke-PostureSignIn { throw 'no browser should open' }
            { Connect-PostureSession -Services } | Should -Throw '*carries no app id for TenantKeep Posture for Azure, Teams and Power Platform yet*'
            $access = Test-PostureServicesAccess -TenantId $script:TestTid
            $access.status | Should -Be 'absent'
            $access.reason | Should -Match 'carries no app id'
        }
    }

    It 'asks Graph first whether the organisation has the app at all' {
        InModuleScope TenantKeep.Posture {
            & $script:NewSession
            . $script:UseTestManifests
            $script:Answer = @{ value = @() }
            Mock Invoke-PostureGraphRequest { if ($script:Answer -is [string]) { throw $script:Answer }; $script:Answer }
            $absent = Test-PostureServicesAccess -TenantId $script:TestTid
            $absent.status | Should -Be 'absent'
            $absent.reason | Should -Match 'has not approved TenantKeep Posture for Azure, Teams and Power Platform, the app they are read through\. An administrator approves it once, here: https://login\.microsoftonline\.com/33333333-3333-3333-3333-333333333333/v2\.0/adminconsent\?client_id=cccccccc-0000-0000-0000-000000000003'
            Should -Invoke Invoke-PostureGraphRequest -Times 1 -Exactly -ParameterFilter { $ApiVersion -eq 'v1.0' -and $Uri -match "^servicePrincipals\?\`$filter=appId eq 'cccccccc-0000-0000-0000-000000000003'" }
            $script:Answer = @{ value = @(@{ id = 'sp-1'; accountEnabled = $false }) }
            (Test-PostureServicesAccess -TenantId $script:TestTid).status | Should -Be 'disabled'
            $script:Answer = @{ value = @(@{ id = 'sp-1'; accountEnabled = $true }) }
            (Test-PostureServicesAccess -TenantId $script:TestTid).status | Should -Be 'present'
            $script:Answer = 'Graph answered 403'
            (Test-PostureServicesAccess -TenantId $script:TestTid).status | Should -Be 'unknown' -Because 'a read that fails is not an answer; the sign-in may still be tried'
        }
    }

    It 'gives the link for one API when the organisation approved the app without it' {
        InModuleScope TenantKeep.Posture {
            . $script:UseTestManifests
            $azure = Get-PostureServicesSkipReason -Collector Azure -Message "Sign-in failed (invalid_grant): AADSTS65001: The user or administrator has not consented.`r`nTrace ID: x" -TenantId $script:TestTid
            $azure | Should -Match '^Azure not read: this organisation has not approved the Azure read\. An administrator approves it once, here: https://login\.microsoftonline\.com/33333333'
            [uri]::UnescapeDataString($azure) | Should -Match 'scope=openid profile offline_access https://graph\.microsoft\.com/User\.Read https://management\.core\.windows\.net//user_impersonation&'
            [uri]::UnescapeDataString((Get-PostureServicesSkipReason -Collector Teams -Message 'AADSTS65001' -TenantId $script:TestTid)) | Should -Match 'User\.Read 48ac35b8-9aa8-4d74-927d-1f4a14a0b239/user_impersonation&'
            Get-PostureServicesSkipReason -Collector Teams -Message "The module could not connect.`nTry again." | Should -Be 'Teams sign-in failed: The module could not connect. Try again.'
            $powerPlatform = Get-PosturePowerSkipReason -Collector PowerPlatform -Message 'AADSTS65001: not consented' -TenantId $script:TestTid
            $powerPlatform | Should -Match '^This tenant has not approved the Power Platform read\. It is optional: an administrator approves it once, here: https://login\.microsoftonline\.com/33333333-3333-3333-3333-333333333333/v2\.0/adminconsent\?client_id=cccccccc-0000-0000-0000-000000000003'
            [uri]::UnescapeDataString($powerPlatform) | Should -Match 'User\.Read https://service\.powerapps\.com//User&'
        }
    }
}

Describe 'The second sign-in when it ends during a run' {
    It 'asks the same admin to sign in to the second app again, and leaves the main sign-in and its Graph token alone' {
        InModuleScope TenantKeep.Posture {
            & $script:NewSession
            . $script:UseTestManifests
            $script:PostureSession['services'] = @{ clientId = $script:TestApp; refreshToken = 'svc-refresh-1'; account = 'admin@contoso.example' }
            $script:PostureSession['tokens']['teams'] = @{ accessToken = 'old-teams'; expiresUtc = [datetime]::UtcNow.AddHours(1); scope = '' }
            Mock Test-PostureInteractive { $true }
            Mock Invoke-PostureSignIn { @{ access_token = (& $script:SvcJwt 'admin@contoso.example'); refresh_token = 'svc-refresh-2'; expires_in = 3600 } }
            Mock Invoke-PostureTokenRequest {
                if ($Form['refresh_token'] -eq 'svc-refresh-1') { throw 'Sign-in failed (invalid_grant): AADSTS70043: The refresh token has expired or is invalid due to sign-in frequency checks by conditional access.' }
                @{ access_token = "token-for-$($Form['scope'])-with-$($Form['refresh_token'])"; expires_in = 3600 }
            }
            Get-PostureToken -Resource azure | Should -Be 'token-for-https://management.core.windows.net//.default-with-svc-refresh-2'
            Should -Invoke Invoke-PostureSignIn -Times 1 -Exactly -ParameterFilter { $ClientId -eq 'cccccccc-0000-0000-0000-000000000003' -and $LoginHint -eq 'admin@contoso.example' -and $Scope -eq 'openid profile offline_access https://graph.microsoft.com/User.Read' -and $AppName -eq 'TenantKeep Posture for Azure, Teams and Power Platform' }
            $script:PostureSession['services']['refreshToken'] | Should -Be 'svc-refresh-2'
            $script:PostureSession['refreshToken'] | Should -Be 'main-refresh'
            $script:PostureSession['tokens']['graph']['accessToken'] | Should -Be 'main-graph' -Because 'the browser token of the second app is never used as the run''s Graph token'
            $script:PostureSession['tokens'].ContainsKey('teams') | Should -BeFalse -Because 'the other two APIs get new tokens from the new refresh token when next asked'
            Should -Invoke Invoke-PostureTokenRequest -Times 0 -Exactly -ParameterFilter { $Form['scope'] -eq 'https://graph.microsoft.com/.default' } -Because 'no Graph token is redeemed from the second app'
            $script:PostureSessionEnded.get_Count() | Should -Be 0
        }
    }

    It 'records the second sign-in as ended, apart from the main one, when there is no one to ask' {
        InModuleScope TenantKeep.Posture {
            & $script:NewSession
            . $script:UseTestManifests
            $script:PostureSession['services'] = @{ clientId = $script:TestApp; refreshToken = 'svc-refresh-1'; account = 'admin@contoso.example' }
            Mock Test-PostureInteractive { $false }
            Mock Invoke-PostureSignIn { throw 'no one should be asked' }
            Mock Invoke-PostureTokenRequest {
                if ($Form['client_id'] -eq 'cccccccc-0000-0000-0000-000000000003') { throw 'Sign-in failed (invalid_grant): AADSTS70043: sign-in frequency.' }
                @{ access_token = 'main-token'; expires_in = 3600 }
            }
            { Get-PostureToken -Resource azure } | Should -Throw '*The sign-in ended at * UTC and could not be renewed*'
            $script:PostureSessionEnded.ContainsKey('services') | Should -BeTrue
            $script:PostureSessionEnded.ContainsKey('main') | Should -BeFalse
            Get-PostureToken -Resource powerbi | Should -Be 'main-token' -Because 'the main sign-in is its own and still works'
            (Get-PostureEndedSignIn -Collector Azure).holder | Should -Be 'services'
            Get-PostureEndedSignIn -Collector Entra | Should -BeNullOrEmpty
        }
    }
}
