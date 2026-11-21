# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-spo-$([guid]::NewGuid().ToString('n'))"
    $script:Write = { param([string] $Dir, [string] $Name, $Data) New-Item -ItemType Directory -Path $Dir -Force | Out-Null; ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }
    $script:Checks = {
        param([string] $Dir, [string[]] $Domain)
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
        $r = Invoke-PostureChecks -Evidence $Dir -Domain $Domain -PassThru; $by = @{}; foreach ($x in $r.results) { $by[$x.id] = $x }; $by
    }
    # Graph's admin/sharepoint/settings as it answers, trimmed to what the checks read.
    $script:Graph = { param([string] $Capability) [ordered]@{ sharingCapability = $Capability; sharingDomainRestrictionMode = 'allowList'; sharingAllowedDomainList = @('partner.example'); sharingBlockedDomainList = @(); isLegacyAuthProtocolsEnabled = $false; isResharingByExternalUsersEnabled = $false; isRequireAcceptingUserToMatchInvitedUserEnabled = $true } }
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
    Remove-Item Function:\global:Get-MgContext, Function:\global:Invoke-MgGraphRequest -ErrorAction SilentlyContinue
    Remove-Item Env:TKP_SPGRANT_LOG -ErrorAction SilentlyContinue
}

Describe 'SharePoint settings without the SharePoint admin read' {
    It 'judges what Graph returns and says exactly what needs the admin read' {
        $d = Join-Path $script:Root 'graph-guests'
        & $script:Write $d 'spo-tenant-settings-graph' (& $script:Graph 'externalUserSharingOnly')
        $by = & $script:Checks $d 'collaboration', 'copilot'
        $by['CL-001'].status | Should -Be 'pass'
        $by['CL-004'].status | Should -Be 'pass' -Because 'the allow list comes from Graph'
        $by['CL-016'].status | Should -Be 'pass' -Because 'OneDrive cannot be more open than a tenant without Anyone links'
        $by['CL-002'].status | Should -Be 'pass'
        $by['CP-005'].status | Should -Be 'pass'
        foreach ($id in 'CL-003', 'CL-005', 'CL-006', 'CL-008', 'CP-004', 'CP-009') {
            $by[$id].status | Should -Be 'notEvaluated'
            $by[$id].reason | Should -Match 'Grant-PostureSharePointAccess\.ps1' -Because "$id names both ways to get the admin read"
            $by[$id].reason | Should -Match 'Get-SpoBaseline\.ps1'
        }
    }

    It 'leaves Anyone link expiry and OneDrive to the admin read when the tenant allows Anyone links' {
        $d = Join-Path $script:Root 'graph-anyone'
        & $script:Write $d 'spo-tenant-settings-graph' (& $script:Graph 'externalUserAndGuestSharing')
        $by = & $script:Checks $d 'collaboration', 'copilot'
        $by['CL-001'].status | Should -Be 'fail'
        foreach ($id in 'CL-002', 'CL-016', 'CP-005') { $by[$id].status | Should -Be 'notEvaluated' }
        $by['CL-016'].reason | Should -Match 'OneDrive sharing level'
    }

    It 'prefers the admin read when both files are in the folder' {
        $d = Join-Path $script:Root 'both'
        & $script:Write $d 'spo-tenant-settings-graph' (& $script:Graph 'externalUserSharingOnly')
        & $script:Write $d 'spo-tenant-settings' @{ SharingCapability = 'ExternalUserSharingOnly'; DefaultSharingLinkType = 'Direct'; DefaultLinkPermission = 'View'; OneDriveSharingCapability = 'ExternalUserSharingOnly'; SharingDomainRestrictionMode = 'None'; ExternalUserExpirationRequired = $true; ExternalUserExpireInDays = 30; ShowEveryoneClaim = $false; ShowEveryoneExceptExternalUsersClaim = $false; ShowAllUsersClaim = $false; EnableRestrictedAccessControl = $true }
        $by = & $script:Checks $d 'collaboration'
        $by['CL-003'].status | Should -Be 'pass'
        $by['CL-004'].status | Should -Be 'fail' -Because 'the admin read says no domain restriction, and it wins'
    }
}

Describe 'The two app manifests' {
    It 'keeps SharePoint full control out of the main app and alone in the SharePoint app, with no consent page' {
        $dir = Join-Path $PSScriptRoot '..' 'TenantKeep.Posture'
        $main = Get-Content -Raw (Join-Path $dir 'app.json') | ConvertFrom-Json -AsHashtable
        $sp = Get-Content -Raw (Join-Path $dir 'app-sharepoint.json') | ConvertFrom-Json -AsHashtable
        @($main.resources.name) | Should -Not -Contain 'sharepoint'
        @($main.resources | ForEach-Object { $_.scopes }) | Should -Not -Contain 'AllSites.FullControl'
        @($sp.resources.name) | Should -Be @('graph', 'sharepoint')
        @($sp.resources[0].scopes) | Should -Be @('openid', 'profile', 'offline_access', 'User.Read') -Because 'Graph only for the sign-in itself'
        @($sp.resources[1].scopes) | Should -Be @('AllSites.FullControl')
        $sp.consentRedirectUri | Should -BeNullOrEmpty -Because 'the SharePoint app is never consented for the whole organisation'
    }
}

Describe 'The SharePoint sign-in' {
    BeforeAll {
        InModuleScope TenantKeep.Posture {
            $script:SpJwt = {
                param([string] $Upn, [string] $Tid = '33333333-3333-3333-3333-333333333333')
                $b64 = { param($o) [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
                "$(& $b64 @{ alg = 'none' }).$(& $b64 @{ tid = $Tid; upn = $Upn; scp = 'AllSites.FullControl' }).sig"
            }
            $script:NewSession = { $script:PostureSession = @{ clientId = 'main-app'; tenantId = '33333333-3333-3333-3333-333333333333'; tenantName = 'contoso'; account = 'admin@contoso.example'; refreshToken = 'main-refresh'; tokens = @{} } }
        }
    }
    AfterAll { InModuleScope TenantKeep.Posture { $script:PostureSession = $null } }

    It 'signs in as the run''s account to the SharePoint app and keeps its refresh token apart from the main one' {
        InModuleScope TenantKeep.Posture {
            & $script:NewSession
            Mock Invoke-PostureSignIn { @{ access_token = (& $script:SpJwt 'Admin@Contoso.example'); refresh_token = 'sp-refresh-1'; expires_in = 3600 } }
            Mock Invoke-PostureTokenRequest { @{ access_token = 'sp-token-2'; refresh_token = 'sp-refresh-2'; expires_in = 3600 } }
            $r = Connect-PostureSession -SharePoint -ClientId 'bbbbbbbb-0000-0000-0000-000000000002' 6>$null
            $r.account | Should -Be 'admin@contoso.example'
            Should -Invoke Invoke-PostureSignIn -Times 1 -Exactly -ParameterFilter { $LoginHint -eq 'admin@contoso.example' -and $TenantId -eq '33333333-3333-3333-3333-333333333333' -and $Scope -eq 'openid profile offline_access https://contoso-admin.sharepoint.com/.default' }
            $script:PostureSession['sharepoint']['refreshToken'] | Should -Be 'sp-refresh-1'
            $script:PostureSession['refreshToken'] | Should -Be 'main-refresh'
            Get-PostureToken -Resource sharepoint -Force | Should -Be 'sp-token-2'
            Should -Invoke Invoke-PostureTokenRequest -Times 1 -Exactly -ParameterFilter { $Form['client_id'] -eq 'bbbbbbbb-0000-0000-0000-000000000002' -and $Form['refresh_token'] -eq 'sp-refresh-1' }
            $script:PostureSession['sharepoint']['refreshToken'] | Should -Be 'sp-refresh-2'
            $script:PostureSession['refreshToken'] | Should -Be 'main-refresh' -Because 'the main refresh token is never sent to the SharePoint app'
        }
    }

    It 'refuses another account or tenant, and words the Entra errors as what to do' {
        InModuleScope TenantKeep.Posture {
            & $script:NewSession
            Mock Invoke-PostureSignIn { @{ access_token = (& $script:SpJwt 'someone.else@contoso.example'); refresh_token = 'x'; expires_in = 3600 } }
            { Connect-PostureSession -SharePoint -ClientId 'bbbbbbbb-0000-0000-0000-000000000002' 6>$null } | Should -Throw '*but the run is signed in as admin@contoso.example*'
            Mock Invoke-PostureSignIn { @{ access_token = (& $script:SpJwt 'admin@contoso.example' '44444444-4444-4444-4444-444444444444'); refresh_token = 'x'; expires_in = 3600 } }
            { Connect-PostureSession -SharePoint -ClientId 'bbbbbbbb-0000-0000-0000-000000000002' 6>$null } | Should -Throw '*not the run''s tenant*'
            Mock Invoke-PostureSignIn { throw 'Sign-in failed (invalid_grant): AADSTS50105: The signed in user is not assigned to a role for the application.' }
            { Connect-PostureSession -SharePoint -ClientId 'bbbbbbbb-0000-0000-0000-000000000002' 6>$null } | Should -Throw '*not assigned to TenantKeep Posture for SharePoint*Grant-PostureSharePointAccess.ps1 -Admin admin@contoso.example*'
            Mock Invoke-PostureSignIn { throw 'Sign-in failed (invalid_client): AADSTS7000112: Application is disabled.' }
            { Connect-PostureSession -SharePoint -ClientId 'bbbbbbbb-0000-0000-0000-000000000002' 6>$null } | Should -Throw '*turned off*-Enable*'
            $script:PostureSession.ContainsKey('sharepoint') | Should -BeFalse
        }
    }

    It 'asks Graph first whether the app is there, turned on and granted to this admin' {
        InModuleScope TenantKeep.Posture {
            $script:Graph = @{ sp = @(@{ id = 'app-sp'; accountEnabled = $true }); grants = @() }
            Mock Invoke-PostureGraphRequest {
                switch -Regex ($Uri) {
                    "appId eq 'bbbb" { return @{ value = $script:Graph.sp } }
                    "appId eq '00000003-0000-0ff1" { return @{ value = @(@{ id = 'spo-sp' }) } }
                    '^me\?' { return @{ id = 'me-id' } }
                    'oauth2PermissionGrants' { return @{ value = $script:Graph.grants } }
                }
            }
            $id = 'bbbbbbbb-0000-0000-0000-000000000002'
            (Test-PostureSharePointAccess -ClientId $id).status | Should -Be 'notGranted'
            $script:Graph.grants = @(@{ consentType = 'Principal'; principalId = 'someone-else'; resourceId = 'spo-sp'; scope = 'AllSites.FullControl' })
            (Test-PostureSharePointAccess -ClientId $id).status | Should -Be 'notGranted'
            $script:Graph.grants += @{ consentType = 'Principal'; principalId = 'me-id'; resourceId = 'spo-sp'; scope = 'AllSites.FullControl' }
            (Test-PostureSharePointAccess -ClientId $id).status | Should -Be 'granted'
            $script:Graph.sp = @(@{ id = 'app-sp'; accountEnabled = $false })
            (Test-PostureSharePointAccess -ClientId $id).reason | Should -Match '-Enable'
            $script:Graph.sp = @()
            $absent = Test-PostureSharePointAccess -ClientId $id
            $absent.status | Should -Be 'absent'
            $absent.reason | Should -Match 'Get-SpoBaseline\.ps1'
            Mock Invoke-PostureGraphRequest { throw 'Forbidden' }
            (Test-PostureSharePointAccess -ClientId $id).status | Should -Be 'unknown'
        }
    }
}

Describe 'Grant-PostureSharePointAccess.ps1' {
    BeforeAll {
        $script:GrantScript = Join-Path $PSScriptRoot '..' 'deploy' 'setup' 'Grant-PostureSharePointAccess.ps1'
        $env:TKP_SPGRANT_LOG = Join-Path $script:Root 'grant-requests.jsonl'
        New-Item -ItemType Directory -Path $script:Root -Force | Out-Null
        $script:Requests = { @(Get-Content -LiteralPath $env:TKP_SPGRANT_LOG -ErrorAction SilentlyContinue | ForEach-Object { $_ | ConvertFrom-Json -Depth 10 }) }
        function global:Get-MgContext { [pscustomobject]@{ TenantId = '33333333-3333-3333-3333-333333333333'; Scopes = @('Application.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'User.Read.All') } }
        function global:Invoke-MgGraphRequest {
            param([string] $Method = 'GET', [string] $Uri, $Body, [string] $ContentType, [string] $OutputType)
            Add-Content -LiteralPath $env:TKP_SPGRANT_LOG -Value (ConvertTo-Json -InputObject @{ Method = $Method; Uri = [uri]::UnescapeDataString($Uri); Body = $(if ($Body) { $Body | ConvertFrom-Json } else { $null }) } -Depth 10 -Compress)
            $u = [uri]::UnescapeDataString($Uri)
            if ($Method -ne 'GET') { return @{ id = 'new-id'; displayName = 'TenantKeep Posture for SharePoint' } }
            switch -Regex ($u) {
                "appId eq 'bbbbbbbb" { return @{ value = @() } }
                "appId eq '00000003-0000-0ff1" { return @{ value = @(@{ id = 'spo-sp' }) } }
                "appId eq '00000003-0000-0000-c000" { return @{ value = @(@{ id = 'graph-sp' }) } }
                'users/spadmin@contoso\.example\?' { return @{ id = 'u-1'; userPrincipalName = 'spadmin@contoso.example' } }
                'users/u-1\?' { return @{ userPrincipalName = 'spadmin@contoso.example' } }
                "oauth2PermissionGrants\?.*principalId eq 'u-1'" { return @{ value = @() } }
                'oauth2PermissionGrants\?' { return @{ value = @(@{ id = 'g1'; consentType = 'Principal'; principalId = 'u-1'; resourceId = 'spo-sp'; scope = 'AllSites.FullControl' }) } }
                'appRoleAssignments\?' { return @{ value = @() } }
            }
            throw "Stub has no answer for $Method $u"
        }
    }

    It 'adds the app without consent, requires assignment, and grants one admin only, never the organisation' {
        Remove-Item -LiteralPath $env:TKP_SPGRANT_LOG -ErrorAction SilentlyContinue
        $out = & $script:GrantScript -TenantId '33333333-3333-3333-3333-333333333333' -ClientId 'bbbbbbbb-0000-0000-0000-000000000002' -Admin 'spadmin@contoso.example' 6>&1 | Out-String
        $writes = @(& $script:Requests | Where-Object Method -ne 'GET')
        @($writes | Where-Object { $_.Method -eq 'POST' -and $_.Uri -match 'servicePrincipals$' }).Count | Should -Be 1
        @($writes | Where-Object { $_.Method -eq 'PATCH' -and $_.Body.PSObject.Properties['appRoleAssignmentRequired'] -and $_.Body.appRoleAssignmentRequired -eq $true }).Count | Should -Be 1
        $grants = @($writes | Where-Object { $_.Uri -match 'oauth2PermissionGrants$' })
        $grants.Count | Should -Be 2
        foreach ($g in $grants) { $g.Body.consentType | Should -Be 'Principal'; $g.Body.principalId | Should -Be 'u-1' }
        @($grants | Where-Object { $_.Body.resourceId -eq 'spo-sp' })[0].Body.scope | Should -Be 'AllSites.FullControl'
        @($grants | Where-Object { $_.Body.resourceId -eq 'graph-sp' })[0].Body.scope | Should -Be 'openid profile offline_access User.Read'
        @($writes | Where-Object { $_.Uri -match 'users/u-1/appRoleAssignments$' }).Count | Should -Be 1
        @($writes | Where-Object { "$($_.Body)" -match 'AllPrincipals' }).Count | Should -Be 0
        $out | Should -Match 'granted to spadmin@contoso\.example'
    }

    It 'turns sign-in off between runs and refuses another tenant' {
        Remove-Item -LiteralPath $env:TKP_SPGRANT_LOG -ErrorAction SilentlyContinue
        $null = & $script:GrantScript -TenantId '33333333-3333-3333-3333-333333333333' -ClientId 'bbbbbbbb-0000-0000-0000-000000000002' -Disable 6>&1
        @(& $script:Requests | Where-Object { $_.Method -eq 'PATCH' -and $_.Body.PSObject.Properties['accountEnabled'] -and $_.Body.accountEnabled -eq $false }).Count | Should -Be 1
        { & $script:GrantScript -TenantId '44444444-4444-4444-4444-444444444444' -ClientId 'bbbbbbbb-0000-0000-0000-000000000002' -Disable 6>$null } | Should -Throw '*only runs in 4444*'
    }
}
