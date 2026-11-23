# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# AI agents (catalog 2026.11.3): the agent part of the Entra collection against a stand-in for Microsoft Graph, and
# the twelve checks judged from folders holding only the files they read. What is asked for, what is saved, what is
# left out, and what has no answer when a part could not be read.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-agents-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    function global:Get-MgContext { [pscustomobject]@{ TenantId = 'tenant-1'; Account = 'admin@contoso.example'; Scopes = @() } }

    # One collection into a new folder. -Mode says what the stand-in refuses.
    $script:Collect = {
        param([string] $Mode = 'all')
        $folder = Join-Path $script:Root ([guid]::NewGuid().ToString('n'))
        New-Item -ItemType Directory -Path $folder | Out-Null
        InModuleScope TenantKeep.Posture -Parameters @{ Folder = $folder; Mode = $Mode } {
            param($Folder, $Mode)
            $script:AgentMode = $Mode
            $script:AgentAsked = [System.Collections.Generic.List[hashtable]]::new()
            Mock Invoke-PostureGraphRequest {
                $script:AgentAsked.Add(@{ Uri = $Uri; ApiVersion = $ApiVersion })
                $refuse = { throw 'Response status code does not indicate success: BadRequest (Bad Request). Request_UnsupportedQuery' }
                switch -Regex -CaseSensitive ($Uri) {
                    '^servicePrincipals/microsoft\.graph\.agentIdentity\?\$select=id&\$expand=sponsors' {
                        if ($script:AgentMode -eq 'noSponsors') { & $refuse }
                        return @(@{ id = 'ag1'; sponsors = @(@{ id = 'person-1' }) }, @{ id = 'ag2'; sponsors = @() })
                    }
                    '^servicePrincipals/microsoft\.graph\.agentIdentity(\?|$)' {
                        if ($script:AgentMode -eq 'forbidden') { throw 'Response status code does not indicate success: Forbidden (Forbidden).' }
                        if ($script:AgentMode -eq 'noOwners' -and $Uri -match 'expand=owners') { & $refuse }
                        if ($script:AgentMode -eq 'plainOnly' -and $Uri -match '\?') { & $refuse }
                        return @(
                            @{ id = 'ag1'; appId = 'ag-app-1'; displayName = 'Invoice agent'; accountEnabled = $true; createdDateTime = '2026-06-01T08:00:00Z'; agentIdentityBlueprintId = 'bp-app-1'; createdByAppId = 'bp-app-1'; owners = @(@{ id = 'person-1' }) }
                            @{ id = 'ag2'; appId = 'ag-app-2'; displayName = 'Old agent'; accountEnabled = $false; createdDateTime = '2026-01-15T08:00:00Z'; agentIdentityBlueprintId = 'bp-app-1'; owners = @() }
                        )
                    }
                    '^servicePrincipals/microsoft\.graph\.agentIdentityBlueprintPrincipal\?\$select=id&\$expand=sponsors' { return @(@{ id = 'bpp1'; sponsors = @(@{ id = 'group-1' }, @{ id = 'person-1' }) }, @{ id = 'bpp2'; sponsors = @() }) }
                    '^servicePrincipals/microsoft\.graph\.agentIdentityBlueprintPrincipal\?' {
                        return @(
                            @{ id = 'bpp1'; appId = 'bp-app-1'; displayName = 'Invoice blueprint'; accountEnabled = $true; appOwnerOrganizationId = 'tenant-1'; appRoleAssignmentRequired = $false; appRoles = @(@{ isEnabled = $true; value = 'Invoices.Read' }, @{ isEnabled = $false; value = 'Old' }, $null); owners = @(@{ id = 'person-1' }) }
                            @{ id = 'bpp2'; appId = 'vendor-app'; displayName = 'Vendor agent'; accountEnabled = $true; appOwnerOrganizationId = 'tenant-of-the-vendor'; appRoleAssignmentRequired = $true; appRoles = @(); owners = @() }
                        )
                    }
                    '^applications/microsoft\.graph\.agentIdentityBlueprint\?\$select=id&\$expand=sponsors' { return @(@{ id = 'bp1'; sponsors = @() }, @{ id = 'bp2'; sponsors = @(@{ id = 'person-1' }) }) }
                    '^applications/microsoft\.graph\.agentIdentityBlueprint\?' {
                        return @(
                            @{
                                id = 'bp1'; appId = 'bp-app-1'; displayName = 'Invoice blueprint'; createdDateTime = '2025-12-01T08:00:00Z'; signInAudience = 'AzureADMyOrg'
                                passwordCredentials = @(@{ keyId = 'k-live'; hint = 'abc'; startDateTime = '2026-01-01T00:00:00Z'; endDateTime = '2029-06-01T00:00:00Z' }, @{ keyId = 'k-old'; startDateTime = '2024-01-01T00:00:00Z'; endDateTime = '2025-01-01T00:00:00Z' })
                                keyCredentials = @(@{ keyId = 'c-1'; customKeyIdentifier = 'THUMBPRINT-NOT-TO-BE-SAVED'; startDateTime = '2026-06-01T00:00:00Z'; endDateTime = '2026-12-01T00:00:00Z' })
                                web = @{ redirectUris = @('https://*.contoso.example/callback', 'http://agent.contoso.example/callback', 'http://localhost:8400/callback', 'https://agent.contoso.example/callback') }
                                owners = @(@{ id = 'person-1' })
                            }
                            @{ id = 'bp2'; appId = 'bp-app-2'; displayName = 'Quiet blueprint'; createdDateTime = '2026-09-01T08:00:00Z'; signInAudience = 'AzureADMyOrg'; passwordCredentials = @(); keyCredentials = @(); web = @{ redirectUris = @() }; owners = @(@{ id = 'person-1' }, @{ id = 'person-2' }) }
                        )
                    }
                    '^applications/bp1/microsoft\.graph\.agentIdentityBlueprint/inheritablePermissions' {
                        if ($script:AgentMode -eq 'noInherit') { throw 'Response status code does not indicate success: Forbidden (Forbidden).' }
                        return @(@{ resourceAppId = '00000003-0000-0000-c000-000000000000'; inheritableScopes = @{ kind = 'allAllowed' }; inheritableRoles = @{ kind = 'enumerated' } }, @{ resourceAppId = 'other-api'; inheritableScopes = @{ kind = 'enumerated' }; inheritableRoles = @{ kind = 'allAllowed' } })
                    }
                    '^applications/bp2/microsoft\.graph\.agentIdentityBlueprint/inheritablePermissions' { return @() }
                    '^applications/bp1/federatedIdentityCredentials' { return @(@{ id = 'fic-1' }) }
                    '^users/microsoft\.graph\.agentUser\?' {
                        if ($script:AgentMode -eq 'capital') { & $refuse }
                        return @(@{ id = 'au1'; displayName = 'Invoice agent'; userPrincipalName = 'invoice.agent@contoso.example'; accountEnabled = $true; identityParentId = 'ag1' })
                    }
                    '^users/microsoft\.graph\.AgentUser\?' { return @(@{ id = 'au1'; displayName = 'Invoice agent'; userPrincipalName = 'invoice.agent@contoso.example'; accountEnabled = $true; identityParentId = 'ag1' }) }
                    '^identity/conditionalAccess/policies$' {
                        return @(
                            @{ displayName = 'Agents: block all but approved'; state = 'enabled'; conditions = @{ clientApplications = @{ includeAgentIdServicePrincipals = @('All') } }; grantControls = @{ builtInControls = @('block') } }
                            @{ displayName = 'Agent users: block'; state = 'enabled'; conditions = @{ users = @{ includeUsers = @('AllAgentIdUsers') } }; grantControls = @{ builtInControls = @('block') } }
                            @{ displayName = 'Agents at risk'; state = 'enabledForReportingButNotEnforced'; conditions = @{ agentIdRiskLevels = 'medium,high'; clientApplications = @{ agentIdServicePrincipalFilter = @{ mode = 'include'; rule = 'CustomSecurityAttribute.Agents.Tier -eq "Pilot"' } } }; grantControls = @{ builtInControls = @('block') } }
                            @{ displayName = 'Everyone: multifactor'; state = 'enabled'; conditions = @{ users = @{ includeUsers = @('All') } }; grantControls = @{ builtInControls = @('mfa') } }
                        )
                    }
                    default { throw "The stand-in has no answer for $Uri" }
                }
            }
            $result = Invoke-PostureAgentIdentityCollection -Folder $Folder -AsOf ([datetime]::new(2026, 11, 23, 12, 0, 0, [System.DateTimeKind]::Utc)) -WarningAction SilentlyContinue 3>$null
            @{ files = @($result['files']); asked = $script:AgentAsked.ToArray() }
        } | ForEach-Object { $_['folder'] = $folder; $_ }
    }
    $script:Read = { param([string] $Folder, [string] $Name) Get-Content -Raw -LiteralPath (Join-Path $Folder "$Name.json") | ConvertFrom-Json -Depth 10 }

    # A folder of evidence judged by the engine: only the files named are there.
    $script:Judge = {
        param([string] $Domain, [System.Collections.IDictionary] $Files, [switch] $WithPolicies)
        $dir = Join-Path $script:Root ([guid]::NewGuid().ToString('n'))
        if ($WithPolicies) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot') -Destination $dir -Recurse } else { New-Item -ItemType Directory -Path $dir | Out-Null }
        foreach ($name in $Files.Keys) { ConvertTo-Json -InputObject $Files[$name] -Depth 8 | Set-Content (Join-Path $dir "$name.json") }
        '{ "version": 1, "licenses": ["E5", "P1", "P2"] }' | Set-Content (Join-Path $dir 'profile.json')
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
        $run = Invoke-PostureChecks -Evidence $dir -Domain $Domain -ProfilePath (Join-Path $dir 'profile.json') -PassThru
        $by = @{}; foreach ($r in $run.results) { $by[$r.id] = $r }
        $by
    }
    # Rows as the collector saves them.
    $script:Agent = { param([string] $Id, [string] $Name, [string] $Blueprint, $Owners = 1, $Sponsors = 1, [bool] $Enabled = $true) [ordered]@{ Id = $Id; AppId = "app-$Id"; DisplayName = $Name; AccountEnabled = $Enabled; CreatedDateTime = '2026-06-01T08:00:00Z'; BlueprintAppId = $Blueprint; CreatedByAppId = $Blueprint; DisabledByMicrosoft = $null; Owners = $Owners; Sponsors = $Sponsors } }
    $script:Principal = { param([string] $Id, [string] $Name, [string] $AppId, $HomeTenant = $true, $Owners = 1, $Sponsors = 1, [int] $Roles = 0, $Required = $true, [bool] $Enabled = $true) [ordered]@{ Id = $Id; AppId = $AppId; DisplayName = $Name; AccountEnabled = $Enabled; AppOwnerOrganizationId = 'tenant'; HomeTenant = $HomeTenant; AppRoleAssignmentRequired = $Required; EnabledAppRoles = $Roles; Owners = $Owners; Sponsors = $Sponsors } }
    $script:Blueprint = {
        param([string] $Id, [string] $Name, [string] $AppId, [hashtable] $Set = @{})
        $row = [ordered]@{ Id = $Id; AppId = $AppId; DisplayName = $Name; CreatedDateTime = '2026-05-01T08:00:00Z'; SignInAudience = 'AzureADMyOrg'; ActiveSecrets = 0; Certs = 0; ExpiredCredentials = 0; LongestCredentialDays = 0; FederatedCredentials = $null; WildcardRedirects = 0; HttpRedirects = 0; InheritAllScopes = 0; InheritAllRoles = 0; Owners = 1; Sponsors = 1 }
        foreach ($k in $Set.Keys) { $row[$k] = $Set[$k] }
        $row
    }
    $script:AgentUser = { param([string] $Id, [string] $Upn, [string] $Parent) [ordered]@{ Id = $Id; DisplayName = $Upn; UserPrincipalName = $Upn; AccountEnabled = $true; ParentId = $Parent } }
    $script:Role = { param([string] $PrincipalId, [string] $Type, [string] $Name, [string] $Role) [ordered]@{ Role = $Role; RoleDefinitionId = "def-$Role"; AssignmentType = 'Assigned'; MemberType = 'Direct'; DirectoryScopeId = '/'; StartDateTime = $null; EndDateTime = $null; PrincipalType = $Type; PrincipalName = $Name; PrincipalUpn = $null; PrincipalSynced = $null; PrincipalId = $PrincipalId } }
    # A tenant in good order: one agent, its blueprint, the blueprint's service principal and the agent's user account.
    $script:Tidy = {
        [ordered]@{
            '10-agent-identities'           = @((& $script:Agent 'ag1' 'Invoice agent' 'bp-app-1'))
            '10-agent-blueprints'           = @((& $script:Blueprint 'bp1' 'Invoice blueprint' 'bp-app-1'))
            '10-agent-blueprint-principals' = @((& $script:Principal 'bpp1' 'Invoice blueprint' 'bp-app-1' $true 1 1 1 $true))
            '10-agent-users'                = @((& $script:AgentUser 'au1' 'invoice.agent@contoso.example' 'ag1'))
            '04-role-assignments-active'    = @((& $script:Role 'person-1' 'user' 'Admin One' 'Global Administrator'))
            '10-graph-app-permissions'      = @(@{ PrincipalDisplayName = 'Invoice agent'; PrincipalId = 'ag1'; PrincipalType = 'ServicePrincipal'; Permission = 'User.Read.All'; CreatedDateTime = '2026-06-01T08:00:00Z' })
        }
    }
    $script:AgentChecks = 'ID-047', 'ID-048', 'ID-049', 'ID-050', 'ID-051', 'ID-052', 'ID-053', 'ID-054', 'ID-055', 'ID-056'
}

AfterAll {
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
    Remove-Item Function:\Get-MgContext -ErrorAction SilentlyContinue
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
}

Describe 'The agent part of the Entra collection' {
    BeforeAll { $script:Run = & $script:Collect 'all' }

    It 'asks Graph for the three typed lists, each with its owners and then its sponsors, and reads only' {
        $uris = @($script:Run.asked | ForEach-Object { $_.Uri })
        $uris | Should -Contain 'servicePrincipals/microsoft.graph.agentIdentity?$select=id,appId,displayName,accountEnabled,createdDateTime,agentIdentityBlueprintId,createdByAppId,disabledByMicrosoftStatus&$expand=owners($select=id)'
        $uris | Should -Contain 'servicePrincipals/microsoft.graph.agentIdentity?$select=id&$expand=sponsors($select=id)'
        $uris | Should -Contain 'servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal?$select=id&$expand=sponsors($select=id)'
        $uris | Should -Contain 'applications/microsoft.graph.agentIdentityBlueprint?$select=id&$expand=sponsors($select=id)'
        $uris | Should -Contain 'applications/bp1/federatedIdentityCredentials?$select=id'
        $uris | Should -Not -Contain 'applications/bp2/federatedIdentityCredentials?$select=id' -Because 'a blueprint with no working secret has nothing for a federated credential to stand beside'
        @($script:Run.asked | Where-Object { $_.ApiVersion -ne 'v1.0' } | ForEach-Object { $_.Uri }) | Should -Be @('identity/conditionalAccess/policies') -Because 'only the agent conditions of Conditional Access are beta'
        InModuleScope TenantKeep.Posture { Should -Invoke Invoke-PostureGraphRequest -Times 0 -Exactly -ParameterFilter { $PSBoundParameters.ContainsKey('Method') -and $Method -ne 'GET' } }
        @($script:Run.files | ForEach-Object { Split-Path $_ -Leaf } | Sort-Object) | Should -Be @('10-agent-blueprint-principals.json', '10-agent-blueprints.json', '10-agent-ca-policies.json', '10-agent-identities.json', '10-agent-summary.json', '10-agent-users.json')
    }

    It 'saves each agent identity with how many owners and sponsors it has, and not who they are' {
        $rows = @(& $script:Read $script:Run.folder '10-agent-identities')
        @($rows | ForEach-Object { "$($_.DisplayName): enabled $($_.AccountEnabled), blueprint $($_.BlueprintAppId), owners $($_.Owners), sponsors $($_.Sponsors)" }) | Should -Be @(
            'Invoice agent: enabled True, blueprint bp-app-1, owners 1, sponsors 1'
            'Old agent: enabled False, blueprint bp-app-1, owners 0, sponsors 0'
        )
        Get-Content -Raw -LiteralPath (Join-Path $script:Run.folder '10-agent-identities.json') | Should -Not -Match 'person-1'
        Join-Path $script:Run.folder '10-agent-identities.csv' | Should -Exist
    }

    It 'saves each blueprint service principal with whose blueprint it is and whether its roles are open to any caller' {
        $rows = @(& $script:Read $script:Run.folder '10-agent-blueprint-principals')
        @($rows | ForEach-Object { "$($_.DisplayName): home $($_.HomeTenant), roles $($_.EnabledAppRoles), assignment $($_.AppRoleAssignmentRequired), owners $($_.Owners), sponsors $($_.Sponsors)" }) | Should -Be @(
            'Invoice blueprint: home True, roles 1, assignment False, owners 1, sponsors 2'
            'Vendor agent: home False, roles 0, assignment True, owners 0, sponsors 0'
        ) -Because 'a role that is turned off, and an empty entry in the list, are not counted'
    }

    It 'saves what a blueprint''s credentials, redirect addresses and inheritable permissions look like, and no credential' {
        $rows = @(& $script:Read $script:Run.folder '10-agent-blueprints')
        $one = $rows | Where-Object Id -EQ 'bp1'
        $one.ActiveSecrets | Should -Be 1 -Because 'the other secret ended in 2025'
        $one.ExpiredCredentials | Should -Be 1
        $one.Certs | Should -Be 1
        $one.LongestCredentialDays | Should -Be 1247 -Because '1 January 2026 to 1 June 2029'
        $one.FederatedCredentials | Should -Be 1
        $one.WildcardRedirects | Should -Be 1
        $one.HttpRedirects | Should -Be 1 -Because 'plain http to this machine is how a developer signs in, and is not counted'
        $one.InheritAllScopes | Should -Be 1
        $one.InheritAllRoles | Should -Be 1
        $one.Owners | Should -Be 1
        $one.Sponsors | Should -Be 0
        $two = $rows | Where-Object Id -EQ 'bp2'
        "$($two.ActiveSecrets) $($two.ExpiredCredentials) $($two.LongestCredentialDays) $($two.InheritAllScopes) $($two.InheritAllRoles) $($two.Owners) $($two.Sponsors)" | Should -Be '0 0 0 0 0 2 1'
        $two.FederatedCredentials | Should -BeNullOrEmpty -Because 'it was not asked, which is not the same as none'
        Get-Content -Raw -LiteralPath (Join-Path $script:Run.folder '10-agent-blueprints.json') | Should -Not -Match 'THUMBPRINT|k-live|hint|redirectUris|contoso\.example/callback'
    }

    It 'saves the agent users, and of Conditional Access only the policies that name agents' {
        $users = @(& $script:Read $script:Run.folder '10-agent-users')
        "$($users[0].UserPrincipalName) $($users[0].ParentId)" | Should -Be 'invoice.agent@contoso.example ag1'
        $policies = @(& $script:Read $script:Run.folder '10-agent-ca-policies')
        @($policies | ForEach-Object { "$($_.Name): $($_.State), agents $($_.AgentIdentities), all $($_.AllAgentIdentities), users $($_.AgentUsers), risk '$($_.RiskLevels)', blocks $($_.Blocks)" }) | Should -Be @(
            "Agents: block all but approved: enabled, agents True, all True, users False, risk '', blocks True"
            "Agent users: block: enabled, agents False, all False, users True, risk '', blocks True"
            "Agents at risk: enabledForReportingButNotEnforced, agents True, all False, users False, risk 'medium,high', blocks True"
        ) -Because 'a policy for people is not saved here; policies.json has it'
        Get-Content -Raw -LiteralPath (Join-Path $script:Run.folder '10-agent-ca-policies.json') | Should -Not -Match 'CustomSecurityAttribute' -Because 'the rule that picks the agents is the organisation''s own classification'
        $summary = & $script:Read $script:Run.folder '10-agent-summary'
        "$($summary.AgentIdentities) $($summary.Blueprints) $($summary.BlueprintPrincipals) $($summary.AgentUsers) $($summary.PoliciesForAgents)" | Should -Be '2 2 2 1 3'
        @($summary.NotRead).Count | Should -Be 0
    }

    It 'reads a list without its owners when Graph refuses that form, and says the owners were not read' {
        $run = & $script:Collect 'noOwners'
        $rows = @(& $script:Read $run.folder '10-agent-identities')
        $rows.Count | Should -Be 2
        $rows[1].Owners | Should -BeNullOrEmpty -Because 'not read is not zero'
        $rows[0].Sponsors | Should -Be 1
        @((& $script:Read $run.folder '10-agent-summary').NotRead) | Should -Be @('owners of agent identities')
        # And without naming the properties, when Graph refuses that too.
        $plain = & $script:Collect 'plainOnly'
        @(& $script:Read $plain.folder '10-agent-identities').Count | Should -Be 2
        @($plain.asked | ForEach-Object { $_.Uri }) | Should -Contain 'servicePrincipals/microsoft.graph.agentIdentity'
    }

    It 'leaves the sponsors empty when the second pass is refused, and the inheritable permissions when that read is' {
        $run = & $script:Collect 'noSponsors'
        $rows = @(& $script:Read $run.folder '10-agent-identities')
        $rows[0].Sponsors | Should -BeNullOrEmpty
        $rows[0].Owners | Should -Be 1
        @((& $script:Read $run.folder '10-agent-summary').NotRead) | Should -Be @('sponsors of agent identities')
        $inherit = & $script:Collect 'noInherit'
        $blueprints = @(& $script:Read $inherit.folder '10-agent-blueprints')
        $blueprints[0].InheritAllScopes | Should -BeNullOrEmpty
        $blueprints[1].InheritAllScopes | Should -BeNullOrEmpty -Because 'after one refusal the others are not asked, and none is read as zero'
        $blueprints[0].ActiveSecrets | Should -Be 1 -Because 'the rest of the row is still read'
        @((& $script:Read $inherit.folder '10-agent-summary').NotRead) | Should -Be @('inheritable permissions of agent blueprints')
    }

    It 'carries on with the other lists when one permission is missing, and records the refusal' {
        $run = & $script:Collect 'forbidden'
        Join-Path $run.folder '10-agent-identities.json' | Should -Not -Exist
        Join-Path $run.folder '10-agent-blueprints.json' | Should -Exist
        $summary = & $script:Read $run.folder '10-agent-summary'
        $summary.AgentIdentities | Should -BeNullOrEmpty -Because 'a list that was refused has no count'
        $summary.Blueprints | Should -Be 2
        Get-Content -Raw -LiteralPath (Join-Path $run.folder 'errors.txt') | Should -Match 'Agent identities'
        InModuleScope TenantKeep.Posture {
            # Run Health names the one permission each list needs, and the role Microsoft documents for it.
            $need = Resolve-PostureStepRequirement -Collector Entra -Label 'Agent identities'
            @($need.scopes) | Should -Be @('AgentIdentity.Read.All')
            @($need.roles) | Should -Contain 'Agent ID Administrator'
            @((Resolve-PostureStepRequirement -Collector Entra -Label 'Agent identity blueprints').scopes) | Should -Be @('AgentIdentityBlueprint.Read.All')
            @((Resolve-PostureStepRequirement -Collector Entra -Label 'Agent identity blueprint principals').scopes) | Should -Be @('AgentIdentityBlueprintPrincipal.Read.All')
            @((Resolve-PostureStepRequirement -Collector Entra -Label 'Agent users').scopes) | Should -Not -Contain 'AgentIdentity.Read.All' -Because 'agent users list with the user read the run already holds'
        }
    }

    It 'asks for agent users under the other spelling of the type when Graph refuses the first' {
        $run = & $script:Collect 'capital'
        @(& $script:Read $run.folder '10-agent-users').Count | Should -Be 1
        @($run.asked | ForEach-Object { $_.Uri }) | Should -Contain 'users/microsoft.graph.AgentUser?$select=id,displayName,userPrincipalName,accountEnabled,identityParentId'
    }
}

Describe 'Checks on AI agents (catalog 2026.11.3)' {
    It 'passes every check in a tenant whose one agent is looked after, and in a tenant with no agents' {
        $tidy = & $script:Judge 'identity' (& $script:Tidy)
        foreach ($id in $script:AgentChecks) { $tidy[$id].status | Should -Be 'pass' -Because $id }
        $none = & $script:Judge 'identity' ([ordered]@{ '10-agent-identities' = @(); '10-agent-blueprints' = @(); '10-agent-blueprint-principals' = @(); '10-agent-users' = @(); '04-role-assignments-active' = @(); '10-graph-app-permissions' = @() })
        foreach ($id in $script:AgentChecks) { $none[$id].status | Should -Be 'pass' -Because "${id}: nothing to find" }
    }

    It 'ID-047 and ID-048 list what has no owner and what has no sponsor, by kind' {
        $files = & $script:Tidy
        $files['10-agent-identities'] = @((& $script:Agent 'ag1' 'Invoice agent' 'bp-app-1'), (& $script:Agent 'ag2' 'Lost agent' 'bp-app-1' 0 0))
        $files['10-agent-blueprints'] = @((& $script:Blueprint 'bp1' 'Invoice blueprint' 'bp-app-1' @{ Sponsors = 0 }))
        $files['10-agent-blueprint-principals'] = @((& $script:Principal 'bpp1' 'Invoice blueprint' 'bp-app-1' $true 0 1 1 $true))
        $by = & $script:Judge 'identity' $files
        $by['ID-047'].status | Should -Be 'fail'
        @($by['ID-047'].affected | ForEach-Object { "$($_.name): $($_.detail)" }) | Should -Be @('Lost agent: agent identity with no owner', 'Invoice blueprint: agent blueprint principal with no owner')
        $by['ID-048'].status | Should -Be 'fail'
        @($by['ID-048'].affected | ForEach-Object { "$($_.name): $($_.detail)" }) | Should -Be @('Lost agent: agent identity with no sponsor', 'Invoice blueprint: agent blueprint with no sponsor')
    }

    It 'ID-047 and ID-048 have no answer when the owners or the sponsors of a list could not be read' {
        $files = & $script:Tidy
        $files['10-agent-identities'] = @((& $script:Agent 'ag1' 'Invoice agent' 'bp-app-1' $null 1), (& $script:Agent 'ag2' 'Second agent' 'bp-app-1' $null 1))
        $files['10-agent-blueprints'] = @((& $script:Blueprint 'bp1' 'Invoice blueprint' 'bp-app-1' @{ Sponsors = $null }))
        $by = & $script:Judge 'identity' $files
        $by['ID-047'].status | Should -Be 'notEvaluated' -Because 'owners that were not read are not owners that are missing'
        $by['ID-047'].reason | Should -Match '^The owners of the agent identities could not be read' -Because 'the reason names the list'
        $by['ID-048'].status | Should -Be 'notEvaluated'
        $by['ID-048'].reason | Should -Match 'sponsors of the agent blueprints could not be read'
        # A list that was not collected at all is named by the engine.
        $files.Remove('10-agent-blueprint-principals')
        $missing = & $script:Judge 'identity' $files
        $missing['ID-047'].status | Should -Be 'notEvaluated'
        $missing['ID-047'].reason | Should -Match '10-agent-blueprint-principals'
    }

    It 'ID-049 lists a disabled agent and a disabled blueprint service principal' {
        $files = & $script:Tidy
        $files['10-agent-identities'] = @((& $script:Agent 'ag1' 'Invoice agent' 'bp-app-1'), (& $script:Agent 'ag2' 'Trial agent' 'bp-app-1' 1 1 $false))
        $files['10-agent-blueprint-principals'] = @((& $script:Principal 'bpp1' 'Invoice blueprint' 'bp-app-1' $true 1 1 1 $true), (& $script:Principal 'bpp2' 'Stopped blueprint' 'vendor-app' $false 1 1 0 $true $false))
        $by = & $script:Judge 'identity' $files
        $by['ID-049'].status | Should -Be 'fail'
        @($by['ID-049'].affected | ForEach-Object { "$($_.name): $($_.detail)" }) | Should -Be @('Trial agent: agent identity, disabled', 'Stopped blueprint: agent blueprint principal, disabled')
    }

    It 'ID-050 lists what has lost its parent, and leaves alone a blueprint another organisation publishes' {
        $files = & $script:Tidy
        $files['10-agent-identities'] = @((& $script:Agent 'ag1' 'Invoice agent' 'bp-app-1'), (& $script:Agent 'ag2' 'Stray agent' 'bp-app-gone'), (& $script:Agent 'ag3' 'Vendor helper' 'vendor-app'))
        $files['10-agent-blueprint-principals'] = @(
            (& $script:Principal 'bpp1' 'Invoice blueprint' 'bp-app-1' $true 1 1 1 $true)
            (& $script:Principal 'bpp2' 'Deleted blueprint' 'bp-app-deleted' $true)
            (& $script:Principal 'bpp3' 'Vendor agent' 'vendor-app' $false)
            (& $script:Principal 'bpp4' 'Unknown home' 'other-app' $null)
        )
        $files['10-agent-users'] = @((& $script:AgentUser 'au1' 'invoice.agent@contoso.example' 'ag1'), (& $script:AgentUser 'au2' 'ghost.agent@contoso.example' 'ag-gone'))
        $by = & $script:Judge 'identity' $files
        $by['ID-050'].status | Should -Be 'fail'
        @($by['ID-050'].affected | ForEach-Object { "$($_.name): $($_.detail)" }) | Should -Be @(
            'Stray agent: agent identity whose blueprint is not in this tenant'
            'Deleted blueprint: agent blueprint principal whose blueprint has been deleted'
            'ghost.agent@contoso.example: agent user whose agent identity is gone'
        ) -Because 'a vendor''s blueprint was never in this tenant, and a principal whose home is unknown is not judged'
        $files.Remove('10-agent-users')
        (& $script:Judge 'identity' $files)['ID-050'].status | Should -Be 'notEvaluated'
    }

    It 'ID-051 finds a privileged role on an agent however it is held, and only on an agent' {
        $files = & $script:Tidy
        $files['10-agent-blueprint-principals'] = @((& $script:Principal 'bpp1' 'Invoice blueprint' 'bp-app-1' $true 1 1 1 $true), (& $script:Principal 'bpp3' 'Vendor agent' 'vendor-app' $false))
        $files['04-role-assignments-active'] = @(
            (& $script:Role 'person-1' 'user' 'Admin One' 'Global Administrator')
            (& $script:Role 'ag1' 'servicePrincipal' 'Invoice agent' 'Global Administrator')
            (& $script:Role 'ag1' 'servicePrincipal' 'Invoice agent' 'Directory Readers')
            (& $script:Role 'not-in-the-lists' 'agentIdentity' 'Ghost agent' 'Security Administrator')
            (& $script:Role 'bpp3' 'servicePrincipal' 'Vendor agent' 'Exchange Administrator')
            (& $script:Role 'sp-other' 'servicePrincipal' 'Backup tool' 'Global Administrator')
        )
        $files['04-role-assignments-pim-eligible'] = @((& $script:Role 'au1' 'agentUser' 'Invoice agent' 'User Administrator'))
        $files['04-role-holders'] = @(
            @{ UserId = 'au1'; UserPrincipalName = 'invoice.agent@contoso.example'; Role = 'Helpdesk Administrator'; Held = 'Group'; GroupName = 'Tier 1 support' }
            @{ UserId = 'person-1'; UserPrincipalName = 'admin1@contoso.example'; Role = 'Helpdesk Administrator'; Held = 'Group'; GroupName = 'Tier 1 support' }
        )
        $by = & $script:Judge 'identity' $files
        $by['ID-051'].status | Should -Be 'fail'
        @($by['ID-051'].affected | ForEach-Object { "$($_.name) ($($_.detail))" }) | Should -Be @(
            'Invoice agent: Global Administrator (agent identity, assigned)'
            'Ghost agent: Security Administrator (agent identity, assigned)'
            'Vendor agent: Exchange Administrator (agent blueprint principal published by another organisation, assigned)'
            'invoice.agent@contoso.example: User Administrator (agent user, eligible)'
            'invoice.agent@contoso.example: Helpdesk Administrator (agent user, through the group Tier 1 support)'
        ) -Because 'a role that is not privileged, and a privileged one on a person or another application, are other checks'' business'
        # Judged on the assignments alone when the eligible assignments and the role holders were not collected.
        $files.Remove('04-role-assignments-pim-eligible'); $files.Remove('04-role-holders')
        (& $script:Judge 'identity' $files)['ID-051'].observed.agentsWithPrivilegedRoles | Should -Be 3
        $files.Remove('04-role-assignments-active')
        (& $script:Judge 'identity' $files)['ID-051'].status | Should -Be 'notEvaluated'
    }

    It 'ID-052 finds a high-privilege Graph permission on an agent or on a blueprint''s service principal' {
        $files = & $script:Tidy
        $files['10-graph-app-permissions'] = @(
            @{ PrincipalDisplayName = 'Invoice agent'; PrincipalId = 'ag1'; PrincipalType = 'ServicePrincipal'; Permission = 'RoleManagement.ReadWrite.Directory'; CreatedDateTime = '2026-06-01T08:00:00Z' }
            @{ PrincipalDisplayName = 'Invoice agent'; PrincipalId = 'ag1'; PrincipalType = 'ServicePrincipal'; Permission = 'User.Read.All'; CreatedDateTime = '2026-06-01T08:00:00Z' }
            @{ PrincipalDisplayName = 'Invoice blueprint'; PrincipalId = 'bpp1'; PrincipalType = 'ServicePrincipal'; Permission = 'RoleEligibilitySchedule.ReadWrite.Directory'; CreatedDateTime = '2026-06-01T08:00:00Z' }
            @{ PrincipalDisplayName = 'Backup tool'; PrincipalId = 'sp-other'; PrincipalType = 'ServicePrincipal'; Permission = 'Directory.ReadWrite.All'; CreatedDateTime = '2026-06-01T08:00:00Z' }
        )
        $by = & $script:Judge 'identity' $files
        $by['ID-052'].status | Should -Be 'fail'
        @($by['ID-052'].affected | ForEach-Object { "$($_.name) ($($_.detail))" }) | Should -Be @(
            'Invoice agent: RoleManagement.ReadWrite.Directory (agent identity, application permission)'
            'Invoice blueprint: RoleEligibilitySchedule.ReadWrite.Directory (agent blueprint principal, application permission)'
        ) -Because 'a permission that leads to a role by one more step counts for an agent, and another application''s is ID-011''s'
    }

    It 'ID-053 to ID-056 judge the blueprints: what they pass on, who may call them, where they redirect, and their credentials' {
        $files = & $script:Tidy
        $files['10-agent-blueprints'] = @(
            (& $script:Blueprint 'bp1' 'Invoice blueprint' 'bp-app-1' @{ InheritAllScopes = 1; InheritAllRoles = 2; WildcardRedirects = 1; HttpRedirects = 2; ExpiredCredentials = 1; LongestCredentialDays = 1247; ActiveSecrets = 3; FederatedCredentials = 1 })
            (& $script:Blueprint 'bp2' 'Quiet blueprint' 'bp-app-2' @{ ActiveSecrets = 2; LongestCredentialDays = 730; FederatedCredentials = 0 })
        )
        $files['10-agent-blueprint-principals'] = @((& $script:Principal 'bpp1' 'Invoice blueprint' 'bp-app-1' $true 1 1 2 $false), (& $script:Principal 'bpp2' 'Quiet blueprint' 'bp-app-2' $true 1 1 0 $false))
        $by = & $script:Judge 'identity' $files
        @($by['ID-053'].affected | ForEach-Object { "$($_.name): $($_.detail)" }) | Should -Be @('Invoice blueprint: passes on everything it holds on 1 API(s) as delegated permissions and on 2 as application permissions')
        @($by['ID-054'].affected | ForEach-Object { "$($_.name): $($_.detail)" }) | Should -Be @('Invoice blueprint: exposes 2 application role(s) and does not require assignment') -Because 'a blueprint with no roles has nothing to hand out'
        @($by['ID-055'].affected | ForEach-Object { "$($_.name): $($_.detail)" }) | Should -Be @('Invoice blueprint: 1 redirect address(es) with a wildcard, 2 over plain http')
        @($by['ID-056'].affected | ForEach-Object { "$($_.name): $($_.detail)" }) | Should -Be @('Invoice blueprint: 1 expired credential(s); a credential valid for 1247 days; 3 working secrets; a secret kept beside a federated credential') -Because 'two working secrets valid for 730 days are at the limit, not past it'
        foreach ($id in 'ID-053', 'ID-054', 'ID-055', 'ID-056') { $by[$id].status | Should -Be 'fail' -Because $id }
    }

    It 'ID-053 and ID-056 have no answer for what the collector could not read' {
        $files = & $script:Tidy
        $files['10-agent-blueprints'] = @((& $script:Blueprint 'bp1' 'Invoice blueprint' 'bp-app-1' @{ InheritAllScopes = $null; InheritAllRoles = $null; ActiveSecrets = 1; LongestCredentialDays = 365; FederatedCredentials = $null }))
        $by = & $script:Judge 'identity' $files
        $by['ID-053'].status | Should -Be 'notEvaluated'
        $by['ID-053'].reason | Should -Match 'could not be read \(inheritable permissions'
        $by['ID-056'].status | Should -Be 'notEvaluated' -Because 'the secret may stand beside a federated credential that was not read'
        $by['ID-056'].reason | Should -Match 'Whether 1 agent blueprint\(s\) with a working secret also have a federated credential could not be read'
        # Something else wrong with a credential is a fail whatever was not read.
        $files['10-agent-blueprints'][0]['ExpiredCredentials'] = 2
        (& $script:Judge 'identity' $files)['ID-056'].status | Should -Be 'fail'
    }

    It 'CA-030 and CA-031 ask for policies only of a tenant that has agents, and have no answer when the count was not read' {
        $policy = { param([string] $Name, [bool] $Agents, [bool] $Users, [string] $Risk = '', [string] $State = 'enabled', [bool] $Blocks = $true) [ordered]@{ Name = $Name; State = $State; AgentIdentities = $Agents; AllAgentIdentities = $Agents; AgentUsers = $Users; RiskLevels = $Risk; Blocks = $Blocks } }
        $summary = { param($Agents, $Users) [ordered]@{ AgentIdentities = $Agents; Blueprints = 1; BlueprintPrincipals = 1; AgentUsers = $Users; PoliciesForAgents = 0; NotRead = @() } }
        # No agents: nothing to cover.
        $none = & $script:Judge 'ca' ([ordered]@{ '10-agent-ca-policies' = @(); '10-agent-summary' = (& $summary 0 0) }) -WithPolicies
        foreach ($id in 'CA-030', 'CA-031') { $none[$id].status | Should -Be 'pass' -Because "${id}: a tenant with no agents needs no policy for them" }
        # Agents and no policy.
        $bare = & $script:Judge 'ca' ([ordered]@{ '10-agent-ca-policies' = @(); '10-agent-summary' = (& $summary 3 1) }) -WithPolicies
        foreach ($id in 'CA-030', 'CA-031') { $bare[$id].status | Should -Be 'fail' -Because $id }
        # A block for agent identities is half of CA-030 when the tenant also has agent users.
        $half = & $script:Judge 'ca' ([ordered]@{ '10-agent-ca-policies' = @((& $policy 'Agents: block' $true $false)); '10-agent-summary' = (& $summary 3 1) }) -WithPolicies
        $half['CA-030'].status | Should -Be 'fail'
        (& $script:Judge 'ca' ([ordered]@{ '10-agent-ca-policies' = @((& $policy 'Agents: block' $true $false)); '10-agent-summary' = (& $summary 3 0) }) -WithPolicies)['CA-030'].status | Should -Be 'pass' -Because 'there are no agent users to cover'
        $full = & $script:Judge 'ca' ([ordered]@{ '10-agent-ca-policies' = @((& $policy 'Agents: block' $true $false), (& $policy 'Agent users: block' $false $true), (& $policy 'Agents at risk' $true $false 'medium,high')); '10-agent-summary' = (& $summary 3 1) }) -WithPolicies
        $full['CA-030'].status | Should -Be 'pass'
        $full['CA-031'].status | Should -Be 'pass'
        # Report-only, a policy that does not block, and a risk level short of high do not count.
        $weak = & $script:Judge 'ca' ([ordered]@{ '10-agent-ca-policies' = @((& $policy 'Report only' $true $true 'high' 'enabledForReportingButNotEnforced'), (& $policy 'Asks, does not block' $true $true 'high' 'enabled' $false), (& $policy 'Medium only' $true $false 'medium')); '10-agent-summary' = (& $summary 3 1) }) -WithPolicies
        $weak['CA-030'].status | Should -Be 'fail' -Because 'the only enabled policy that blocks names agent identities, and the tenant has agent users too'
        $weak['CA-031'].status | Should -Be 'fail'
        # The agent list was refused: with no policy the answer is unknown, with one it is yes.
        $unknown = & $script:Judge 'ca' ([ordered]@{ '10-agent-ca-policies' = @(); '10-agent-summary' = (& $summary $null 0) }) -WithPolicies
        foreach ($id in 'CA-030', 'CA-031') { $unknown[$id].status | Should -Be 'notEvaluated' -Because "${id}: whether the tenant has agents was not read" }
        $unknown['CA-031'].reason | Should -Match 'agentIdentities'
        $covered = & $script:Judge 'ca' ([ordered]@{ '10-agent-ca-policies' = @((& $policy 'Agents at risk' $true $false 'high')); '10-agent-summary' = (& $summary $null 0) }) -WithPolicies
        $covered['CA-031'].status | Should -Be 'pass'
        # Without the file of policies that name agents there is nothing to judge.
        $absent = & $script:Judge 'ca' ([ordered]@{ '10-agent-summary' = (& $summary 3 1) }) -WithPolicies
        foreach ($id in 'CA-030', 'CA-031') { $absent[$id].status | Should -Be 'notEvaluated' -Because $id }
    }
}
