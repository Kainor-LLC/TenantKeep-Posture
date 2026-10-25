# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    function script:New-FakeJwt([hashtable] $Claims) {
        $b64 = { param($o) [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
        return "$(& $b64 @{ alg = 'none' }).$(& $b64 $Claims).sig"
    }
    $script:Tid = '33333333-3333-3333-3333-333333333333'
    $script:GraphJwt = New-FakeJwt @{ tid = $script:Tid; upn = 'admin@contoso.example'; scp = 'Directory.Read.All Policy.Read.All Group.Read.All'; exp = 1 }
}

AfterAll { Remove-Module TenantKeep.Posture -Force -ErrorAction SilentlyContinue }

Describe 'ConvertFrom-PostureJwt' {
    It 'returns the payload claims of a token with base64url padding handled' {
        InModuleScope TenantKeep.Posture -Parameters @{ jwt = $script:GraphJwt } {
            $claims = ConvertFrom-PostureJwt -Token $jwt
            $claims['upn'] | Should -Be 'admin@contoso.example'
            $claims['scp'] | Should -Match 'Policy.Read.All'
        }
    }
}

Describe 'Connect-PostureSession in the browser flow' {
    BeforeAll {
        InModuleScope TenantKeep.Posture -Parameters @{ jwt = $script:GraphJwt; tid = $script:Tid } {
            $script:TestJwt = $jwt
            $script:TestTid = $tid
            Mock Start-Process { }
            Mock New-PostureLoopbackListener { @{ listener = $null; port = 43210; redirectUri = 'http://localhost:43210' } }
            Mock Wait-PostureAuthCode { 'the-code' }
            Mock Connect-PostureService { }
            Mock Assert-PostureGraphScope { @{ TenantId = $script:TestTid; Account = 'admin@contoso.example'; Scopes = @('Directory.Read.All') } }
            Mock Invoke-PostureGraphRequest { @{ id = $script:TestTid; displayName = 'Contoso'; verifiedDomains = @(@{ name = 'contoso.com'; isInitial = $false }, @{ name = 'contoso.onmicrosoft.com'; isInitial = $true }) } }
            Mock Invoke-PostureTokenRequest {
                param($Endpoint, $TenantId, $Form)
                if ($Form['grant_type'] -eq 'authorization_code') { return @{ access_token = $script:TestJwt; refresh_token = 'refresh-1'; expires_in = 3600; scope = 'Directory.Read.All' } }
                if ($Form['grant_type'] -eq 'refresh_token') { return @{ access_token = "token-for-$($Form['scope'])"; refresh_token = 'refresh-2'; expires_in = 3600 } }
                throw "unexpected grant $($Form['grant_type'])"
            }
        }
    }
    AfterAll { InModuleScope TenantKeep.Posture { $script:PostureSession = $null } }

    It 'signs in with PKCE on the loopback, opens Graph, reads the tenant name and keeps the refresh token in memory only' {
        InModuleScope TenantKeep.Posture {
            $result = Connect-PostureSession -ClientId 'aaaaaaaa-0000-0000-0000-000000000001' 6>$null
            $result.tenantId | Should -Be $script:TestTid
            $result.tenantName | Should -Be 'contoso'
            $result.tenantDisplayName | Should -Be 'Contoso'
            $result.account | Should -Be 'admin@contoso.example'
            $result.scopes | Should -Contain 'Policy.Read.All'
            Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter { $FilePath -match 'login\.microsoftonline\.com/organizations/oauth2/v2\.0/authorize' -and $FilePath -match 'code_challenge_method=S256' -and $FilePath -match 'redirect_uri=http%3A%2F%2Flocalhost%3A43210' -and $FilePath -match 'client_id=aaaaaaaa-0000-0000-0000-000000000001' }
            Should -Invoke Invoke-PostureTokenRequest -Times 1 -Exactly -ParameterFilter { $Form['grant_type'] -eq 'authorization_code' -and $Form['code'] -eq 'the-code' -and $Form['code_verifier'].Length -ge 43 -and $Form['redirect_uri'] -eq 'http://localhost:43210' }
            Should -Invoke Connect-PostureService -Times 1 -Exactly -ParameterFilter { $Name -eq 'graph' }
            $script:PostureSession['refreshToken'] | Should -Be 'refresh-1'
            $script:PostureSession['tokens']['graph']['accessToken'] | Should -Be $script:TestJwt
        }
    }

    It 'hands out a token per resource from the refresh token, caches it, and rotates the refresh token' {
        InModuleScope TenantKeep.Posture {
            $exo = Get-PostureToken -Resource exchange
            $exo | Should -Be 'token-for-https://outlook.office365.com/.default'
            $script:PostureSession['refreshToken'] | Should -Be 'refresh-2'
            Get-PostureToken -Resource exchange | Should -Be $exo
            Should -Invoke Invoke-PostureTokenRequest -Times 1 -Exactly -ParameterFilter { $Form['grant_type'] -eq 'refresh_token' -and $Form['scope'] -eq 'https://outlook.office365.com/.default' }
            Get-PostureToken -Resource sharepoint | Should -Be 'token-for-https://contoso-admin.sharepoint.com/.default'
            Get-PostureToken -Resource azure | Should -Be 'token-for-https://management.core.windows.net//.default'
            Get-PostureToken -Resource teams | Should -Be 'token-for-48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default'
            (Get-PostureToken -Resource graph -AsSecureString) | Should -BeOfType [securestring]
            { Get-PostureToken -Resource nothing } | Should -Throw '*names no resource*'
        }
    }

    It 'refuses a sign-in to another tenant when -TenantId was pinned' {
        InModuleScope TenantKeep.Posture {
            { Connect-PostureSession -ClientId 'aaaaaaaa-0000-0000-0000-000000000001' -TenantId '44444444-4444-4444-4444-444444444444' 6>$null } | Should -Throw '*Signed in to tenant 33333333*'
        }
    }

    It 'tells an unconsented tenant where the admin consents, with the app id' {
        InModuleScope TenantKeep.Posture {
            Mock Invoke-PostureTokenRequest { throw 'Sign-in failed (invalid_grant): AADSTS65001: The user or administrator has not consented to use the application' }
            { Connect-PostureSession -ClientId 'aaaaaaaa-0000-0000-0000-000000000001' 6>$null } | Should -Throw '*adminconsent?client_id=aaaaaaaa-0000-0000-0000-000000000001*'
        }
    }

    It 'reports a Conditional Access block with the app id and does not retry' {
        InModuleScope TenantKeep.Posture {
            Mock Invoke-PostureTokenRequest { throw 'Sign-in failed (access_denied): AADSTS53003: Access has been blocked by Conditional Access policies. The access policy does not allow token issuance.' }
            { Connect-PostureSession -ClientId 'aaaaaaaa-0000-0000-0000-000000000001' 6>$null } | Should -Throw '*Conditional Access policy*app id aaaaaaaa-0000-0000-0000-000000000001*'
            Should -Invoke Invoke-PostureTokenRequest -Times 1 -Exactly
        }
    }

    It 'Disconnect-PostureSession forgets the tokens' {
        InModuleScope TenantKeep.Posture {
            Mock Disconnect-PostureService { }
            $script:PostureSession = @{ refreshToken = 'r'; tokens = @{ graph = @{} } }
            Disconnect-PostureSession
            $script:PostureSession | Should -BeNullOrEmpty
            { Get-PostureToken -Resource graph } | Should -Throw '*No session*'
        }
    }
}

Describe 'Connect-PostureSession with a device code' {
    It 'polls through authorization_pending and slow_down until the token arrives' {
        InModuleScope TenantKeep.Posture -Parameters @{ jwt = $script:GraphJwt; tid = $script:Tid } {
            $script:Polls = 0
            $script:TestJwt = $jwt
            Mock Start-Sleep { }
            Mock Connect-PostureService { }
            Mock Assert-PostureGraphScope { @{ TenantId = $tid; Account = 'admin@contoso.example'; Scopes = @('Directory.Read.All') } }
            Mock Invoke-PostureGraphRequest { @{ displayName = 'Contoso'; verifiedDomains = @(@{ name = 'contoso.onmicrosoft.com'; isInitial = $true }) } }
            Mock Invoke-PostureTokenRequest {
                param($Endpoint, $TenantId, $Form)
                if ($Endpoint -eq 'devicecode') { return @{ device_code = 'dc'; user_code = 'ABCD-1234'; verification_uri = 'https://microsoft.com/devicelogin'; expires_in = 900; interval = 5; message = 'Go to https://microsoft.com/devicelogin and enter ABCD-1234' } }
                $script:Polls++
                if ($script:Polls -eq 1) { return @{ error = 'authorization_pending' } }
                if ($script:Polls -eq 2) { return @{ error = 'slow_down' } }
                return @{ access_token = $script:TestJwt; refresh_token = 'refresh-dc'; expires_in = 3600 }
            }
            $result = Connect-PostureSession -ClientId 'aaaaaaaa-0000-0000-0000-000000000001' -DeviceCode 6>$null
            $result.tenantName | Should -Be 'contoso'
            $script:Polls | Should -Be 3
            Should -Invoke Start-Sleep -Times 3 -Exactly
            Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 10 }
            $script:PostureSession = $null
        }
    }
}

Describe 'The loopback listener' {
    It 'takes a free port, answers the browser once and returns the code when the state matches' {
        InModuleScope TenantKeep.Posture {
            $loopback = New-PostureLoopbackListener
            $loopback.port | Should -BeGreaterThan 0
            $port = $loopback.port
            $job = Start-ThreadJob -ScriptBlock { Start-Sleep -Milliseconds 300; (Invoke-WebRequest -Uri "http://localhost:$using:port/?code=abc123&state=st-1" -UseBasicParsing).Content }
            $code = Wait-PostureAuthCode -Loopback $loopback -State 'st-1' -TimeoutSeconds 20
            $code | Should -Be 'abc123'
            (Receive-Job -Job $job -Wait -AutoRemoveJob) | Should -Match 'Signed in'
        }
    }

    It 'discards a code whose state does not match' {
        InModuleScope TenantKeep.Posture {
            $loopback = New-PostureLoopbackListener
            $port = $loopback.port
            $job = Start-ThreadJob -ScriptBlock { Start-Sleep -Milliseconds 300; try { Invoke-WebRequest -Uri "http://localhost:$using:port/?code=abc123&state=wrong" -UseBasicParsing | Out-Null } catch { Write-Verbose 'expected' } }
            { Wait-PostureAuthCode -Loopback $loopback -State 'st-1' -TimeoutSeconds 20 } | Should -Throw '*unexpected state*'
            Receive-Job -Job $job -Wait -AutoRemoveJob | Out-Null
        }
    }
}
