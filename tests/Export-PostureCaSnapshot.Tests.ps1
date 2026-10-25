# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force

    # Synthetic tenant. Every id below is made up.
    $script:Ids = @{
        BreakGlass   = '11111111-1111-1111-1111-111111111111'
        AdminsGroup  = '22222222-2222-2222-2222-222222222222'
        DeletedGroup = '33333333-3333-3333-3333-333333333333'
        GlobalAdmin  = '62e90394-69f5-4237-9190-012177145e10'
        Workload     = '44444444-4444-4444-4444-444444444444'
        HqLocation   = '55555555-5555-5555-5555-555555555555'
        GoneLocation = '66666666-6666-6666-6666-666666666666'
        PhishStrength = '00000000-0000-0000-0000-000000000004'
        CustomApp    = '77777777-7777-7777-7777-777777777777'
        Member1      = 'aaaaaaaa-0000-0000-0000-000000000001'
        Member2      = 'aaaaaaaa-0000-0000-0000-000000000002'
    }

    $script:Policies = @(
        @{
            id = 'p1'; displayName = 'CA001 Require phishing-resistant MFA for admins'; state = 'enabled'
            conditions = @{
                users = @{ includeUsers = @(); excludeUsers = @($script:Ids.BreakGlass); includeGroups = @(); excludeGroups = @($script:Ids.AdminsGroup); includeRoles = @($script:Ids.GlobalAdmin); excludeRoles = @() }
                applications = @{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @() }
                locations = @{ includeLocations = @('All'); excludeLocations = @($script:Ids.HqLocation) }
            }
            grantControls = @{ operator = 'OR'; builtInControls = @(); authenticationStrength = @{ id = $script:Ids.PhishStrength } }
        }
        @{
            id = 'p2'; displayName = 'CA002 Block legacy auth'; state = 'enabledForReportingButNotEnforced'
            conditions = @{
                users = @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @($script:Ids.DeletedGroup); excludeGroups = @() }
                applications = @{ includeApplications = @('Office365', $script:Ids.CustomApp); includeUserActions = @('urn:user:registersecurityinfo') }
                clientApplications = @{ includeServicePrincipals = @($script:Ids.Workload) }
                locations = @{ includeLocations = @($script:Ids.GoneLocation) }
            }
            grantControls = @{ operator = 'OR'; builtInControls = @('block') }
        }
    )

    Mock -ModuleName TenantKeep.Posture Get-MgContext {
        [pscustomobject]@{ TenantId = 'tenant-guid'; Account = 'reader@contoso.example'; AuthType = 'Delegated'; Scopes = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All', 'User.Read') }
    }
    Mock -ModuleName TenantKeep.Posture Start-Transcript { }
    Mock -ModuleName TenantKeep.Posture Stop-Transcript { }

    # Mock at the SDK boundary so the wrapper's paging and API version recording run for real.
    # Responses are shaped like the wire: { value = [...] } for collections, with @odata.nextLink for paging.
    Mock -ModuleName TenantKeep.Posture Invoke-MgGraphRequest {
        $u = [uri] $Uri
        $script:LastGraphUri = $Uri
        $path = [uri]::UnescapeDataString($u.PathAndQuery) -replace '^/(v1\.0|beta)/', ''
        switch -Regex ($path) {
            '^identity/conditionalAccess/policies$' { return @{ value = $script:Policies } }
            '^identity/conditionalAccess/namedLocations$' { return @{ value = @(@{ id = $script:Ids.HqLocation; displayName = 'HQ egress'; isTrusted = $true }) } }
            '^policies/authenticationStrengthPolicies$' { return @{ value = @(@{ id = $script:Ids.PhishStrength; displayName = 'Phishing-resistant MFA' }) } }
            '^identity/conditionalAccess/authenticationContextClassReferences$' { return @{ value = @() } }
            '^directoryObjects/getByIds$' {
                $requested = ($Body | ConvertFrom-Json -AsHashtable).ids
                $out = @()
                if ($requested -contains $script:Ids.BreakGlass) { $out += @{ '@odata.type' = '#microsoft.graph.user'; id = $script:Ids.BreakGlass; displayName = 'BreakGlass-01'; userPrincipalName = 'breakglass01@contoso.example' } }
                if ($requested -contains $script:Ids.AdminsGroup) { $out += @{ '@odata.type' = '#microsoft.graph.group'; id = $script:Ids.AdminsGroup; displayName = 'CA-Exclude-Admins' } }
                if ($requested -contains $script:Ids.Workload) { $out += @{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = $script:Ids.Workload; displayName = 'Backup Runner'; appId = 'app-workload' } }
                return @{ value = $out }
            }
            '^roleManagement/directory/roleDefinitions' { return @{ value = @(@{ id = $script:Ids.GlobalAdmin; displayName = 'Global Administrator'; isBuiltIn = $true; templateId = $script:Ids.GlobalAdmin }) } }
            '^servicePrincipals\?' { return @{ value = @(@{ id = 'sp-custom'; appId = $script:Ids.CustomApp; displayName = 'Payroll Portal'; servicePrincipalType = 'Application' }) } }
            "^groups/$($script:Ids.AdminsGroup)/transitiveMembers" {
                # Two pages, to exercise @odata.nextLink handling in the wrapper.
                if ($path -match 'skiptoken=page2') {
                    return @{ value = @(@{ '@odata.type' = '#microsoft.graph.user'; id = $script:Ids.Member1; displayName = 'Amy Admin'; userPrincipalName = 'amy@contoso.example' }) }
                }
                return @{
                    value = @(@{ '@odata.type' = '#microsoft.graph.user'; id = $script:Ids.Member2; displayName = 'Zed Admin'; userPrincipalName = 'zed@contoso.example' })
                    '@odata.nextLink' = "https://graph.microsoft.com/v1.0/groups/$($script:Ids.AdminsGroup)/transitiveMembers?`$skiptoken=page2"
                }
            }
            default { throw "Unexpected Graph call in test: $Uri" }
        }
    }

    $script:OutRoot = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-tests-$([guid]::NewGuid().ToString('n'))"
}

AfterAll {
    if ($script:OutRoot -and (Test-Path $script:OutRoot)) { Remove-Item -LiteralPath $script:OutRoot -Recurse -Force }
}

Describe 'Export-PostureCaSnapshot' {
    Context 'default run' {
        BeforeAll {
            $script:Folder = Export-PostureCaSnapshot -OutRoot $script:OutRoot
            $script:Read = { param($n) Get-Content -Raw -LiteralPath (Join-Path $script:Folder "$n.json") | ConvertFrom-Json -AsHashtable }
        }

        It 'creates a timestamped -ca folder under OutRoot' {
            $script:Folder | Should -Exist
            Split-Path $script:Folder -Leaf | Should -Match '^\d{8}-\d{4}-ca$'
            Split-Path $script:Folder -Parent | Should -Be $script:OutRoot
        }

        It 'writes all seven spec 5.1 files' -ForEach @('policies', 'named-locations', 'auth-strengths', 'auth-context', 'resolved-names', 'group-scope', 'metadata') {
            Join-Path $script:Folder "$_.json" | Should -Exist
        }

        It 'writes policies untouched as a JSON array' {
            $p = & $script:Read 'policies'
            $p.Count | Should -Be 2
            $p[0].conditions.users.excludeUsers | Should -Be @($script:Ids.BreakGlass)
            $p[1].state | Should -Be 'enabledForReportingButNotEnforced'
        }

        It 'writes an empty collection as [] not null' {
            (Get-Content -Raw -LiteralPath (Join-Path $script:Folder 'auth-context.json')).Trim() | Should -Be '[]'
        }

        It 'resolves users, groups, roles, apps, locations and strengths to names' {
            $r = & $script:Read 'resolved-names'
            $r[$script:Ids.BreakGlass].displayName | Should -Be 'BreakGlass-01'
            $r[$script:Ids.BreakGlass].type | Should -Be 'user'
            $r[$script:Ids.BreakGlass].userPrincipalName | Should -Be 'breakglass01@contoso.example'
            $r[$script:Ids.AdminsGroup].type | Should -Be 'group'
            $r[$script:Ids.GlobalAdmin].displayName | Should -Be 'Global Administrator'
            $r[$script:Ids.GlobalAdmin].type | Should -Be 'role'
            $r[$script:Ids.CustomApp].displayName | Should -Be 'Payroll Portal'
            $r[$script:Ids.CustomApp].type | Should -Be 'application'
            $r[$script:Ids.Workload].type | Should -Be 'servicePrincipal'
            $r[$script:Ids.HqLocation].displayName | Should -Be 'HQ egress'
            $r[$script:Ids.PhishStrength].displayName | Should -Be 'Phishing-resistant MFA'
        }

        It 'labels built-in values and user actions' {
            $r = & $script:Read 'resolved-names'
            $r['All'].type | Should -Be 'builtIn'
            $r['Office365'].displayName | Should -Match 'Office 365'
            $r['urn:user:registersecurityinfo'].displayName | Should -Be 'Register security information'
        }

        It 'flags deleted objects with their expected type' {
            $r = & $script:Read 'resolved-names'
            $r[$script:Ids.DeletedGroup].deleted | Should -BeTrue
            $r[$script:Ids.DeletedGroup].type | Should -Be 'group'
            $r[$script:Ids.GoneLocation].deleted | Should -BeTrue
            $r[$script:Ids.GoneLocation].type | Should -Be 'namedLocation'
            @($r.Values | Where-Object { -not $_.deleted }).Count | Should -BeGreaterThan 5
        }

        It 'writes member count and a sha256 of sorted member ids, no members' {
            $g = & $script:Read 'group-scope'
            $admins = $g | Where-Object groupId -eq $script:Ids.AdminsGroup
            $admins.memberCount | Should -Be 2
            $expected = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes("$($script:Ids.Member1)`n$($script:Ids.Member2)"))).ToLowerInvariant()
            $admins.memberHash | Should -Be $expected
            $admins.Keys | Should -Not -Contain 'members'
            (Get-Content -Raw -LiteralPath (Join-Path $script:Folder 'group-scope.json')) | Should -Not -Match 'contoso\.example'
        }

        It 'skips member lookup for a deleted group and records it' {
            $g = & $script:Read 'group-scope'
            $gone = $g | Where-Object groupId -eq $script:Ids.DeletedGroup
            $gone.deleted | Should -BeTrue
            Should -Invoke -ModuleName TenantKeep.Posture Invoke-MgGraphRequest -Times 0 -Scope Context -ParameterFilter { $Uri -like "*/groups/$($script:Ids.DeletedGroup)/*" }
        }

        It 'records tenant, account, scopes, api versions, module version and counts in metadata' {
            $m = & $script:Read 'metadata'
            $m.tenantId | Should -Be 'tenant-guid'
            $m.account | Should -Be 'reader@contoso.example'
            $m.scopes | Should -Contain 'Policy.Read.All'
            $m.graphApiVersions | Should -Be @('v1.0')
            $m.moduleVersion | Should -Be (Import-PowerShellDataFile (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1')).ModuleVersion
            $m.policyCount | Should -Be 2
            $m.groupCount | Should -Be 2
            $m.includeMembers | Should -BeFalse
            $m.errorCount | Should -Be 0
            [datetime]::Parse($m.timestampUtc) | Should -BeOfType [datetime]
        }

        It 'pins every Graph call to an API version and follows nextLink' {
            Should -Invoke -ModuleName TenantKeep.Posture Invoke-MgGraphRequest -Times 0 -Scope Context -ParameterFilter { $Uri -notmatch '^https://graph\.microsoft\.com/(v1\.0|beta)/' }
            Should -Invoke -ModuleName TenantKeep.Posture Invoke-MgGraphRequest -Times 1 -Exactly -Scope Context -ParameterFilter { $Uri -like '*skiptoken=page2' }
        }

        It 'writes no errors.txt on a clean run' {
            Join-Path $script:Folder 'errors.txt' | Should -Not -Exist
        }
    }

    Context '-IncludeMembers' {
        It 'stores member ids, display names and UPNs sorted by id' {
            $folder = Export-PostureCaSnapshot -OutRoot $script:OutRoot -IncludeMembers
            $g = Get-Content -Raw -LiteralPath (Join-Path $folder 'group-scope.json') | ConvertFrom-Json -AsHashtable
            $admins = $g | Where-Object groupId -eq $script:Ids.AdminsGroup
            $admins.members.Count | Should -Be 2
            $admins.members[0].id | Should -Be $script:Ids.Member1
            $admins.members[0].userPrincipalName | Should -Be 'amy@contoso.example'
            $admins.members[1].type | Should -Be 'user'
            (Get-Content -Raw -LiteralPath (Join-Path $folder 'metadata.json') | ConvertFrom-Json).includeMembers | Should -BeTrue
        }
    }

    Context '-PassThru and -ApiVersion' {
        It 'returns a summary object and uses beta when asked' {
            $r = Export-PostureCaSnapshot -OutRoot $script:OutRoot -ApiVersion beta -PassThru
            $r.Folder | Should -Exist
            $r.PolicyCount | Should -Be 2
            $r.Files.Count | Should -Be 7
            $r.Metadata.graphApiVersions | Should -Be @('beta', 'v1.0')
            Should -Invoke -ModuleName TenantKeep.Posture Invoke-MgGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies' }
        }
    }

    Context 'partial failure' {
        It 'logs a failing endpoint to errors.txt and still writes every file' {
            Mock -ModuleName TenantKeep.Posture Invoke-MgGraphRequest { throw 'Insufficient privileges to complete the operation.' } -ParameterFilter { $Uri -like '*/identity/conditionalAccess/namedLocations' }
            $r = Export-PostureCaSnapshot -OutRoot $script:OutRoot -PassThru -WarningAction SilentlyContinue
            $r.Errors | Should -Be 1
            Get-Content -LiteralPath (Join-Path $r.Folder 'errors.txt') | Should -Match '^Named locations :: Insufficient'
            (Get-Content -Raw -LiteralPath (Join-Path $r.Folder 'named-locations.json')).Trim() | Should -Be '[]'
            $names = Get-Content -Raw -LiteralPath (Join-Path $r.Folder 'resolved-names.json') | ConvertFrom-Json -AsHashtable
            $names[$script:Ids.HqLocation].deleted | Should -BeTrue -Because 'the location list was unavailable, so the reference cannot be confirmed'
        }
    }

    Context 'Graph error text' {
        It 'surfaces the Graph error message and the request in the thrown exception' {
            Mock -ModuleName TenantKeep.Posture Invoke-MgGraphRequest {
                $ex = [System.Exception]::new('Response status code does not indicate success: BadRequest (Bad Request).')
                $rec = [System.Management.Automation.ErrorRecord]::new($ex, 'x', 'InvalidOperation', $null)
                $rec.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('GET https://x HTTP/1.1 400 Bad Request' + "`n`n" + '{"error":{"code":"BadRequest","message":"Could not find a property named ''isPrivileged''"}}')
                throw $rec
            }
            InModuleScope TenantKeep.Posture {
                $message = try { Invoke-PostureGraphRequest -Uri 'roleManagement/directory/roleDefinitions?$select=isPrivileged' -ApiVersion v1.0; 'no throw' } catch { $_.Exception.Message }
                $message | Should -Match 'BadRequest'
                $message | Should -Match ([regex]::Escape('[GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=isPrivileged]'))
                $message | Should -Match "Could not find a property named 'isPrivileged'"
            }
        }
    }

    Context 'scope check' {
        It 'refuses to run without a Graph session' {
            Mock -ModuleName TenantKeep.Posture Get-MgContext { $null }
            { Export-PostureCaSnapshot -OutRoot $script:OutRoot } | Should -Throw '*No Microsoft Graph session*'
        }

        It 'refuses a session missing Policy.Read.All and names the gap' {
            Mock -ModuleName TenantKeep.Posture Get-MgContext { [pscustomobject]@{ TenantId = 't'; Account = 'a'; AuthType = 'Delegated'; Scopes = @('Directory.Read.All', 'Group.Read.All') } }
            { Export-PostureCaSnapshot -OutRoot $script:OutRoot } | Should -Throw '*missing scope(s): Policy.Read.All*'
            Should -Invoke -ModuleName TenantKeep.Posture Invoke-MgGraphRequest -Times 0 -Exactly -Scope It
        }
    }
}
