# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Power BI and Power Platform: the two collectors, the request entry points that keep them to reads, and the fifteen
# checks of the domain. No request leaves the test: the one function that sends is replaced.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-power-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $script:NewFolder = { $dir = Join-Path $script:Root ([guid]::NewGuid().ToString('n')); New-Item -ItemType Directory -Path $dir | Out-Null; $dir }
    $script:Judge = {
        param([System.Collections.IDictionary] $Files)
        $dir = & $script:NewFolder
        foreach ($name in $Files.Keys) { ConvertTo-Json -InputObject $Files[$name] -Depth 8 | Set-Content (Join-Path $dir "$name.json") }
        '{ "version": 1, "licenses": ["E5"] }' | Set-Content (Join-Path $dir 'profile.json')
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
        $run = Invoke-PostureChecks -Evidence $dir -Domain powerplatform -ProfilePath (Join-Path $dir 'profile.json') -PassThru
        $by = @{}; foreach ($r in $run.results) { $by[$r.id] = $r }
        $by
    }
    # Power BI settings as the collector saves them. $On: names that are on; $Groups: names held to a security group.
    $script:BiNames = 'PublishToWeb', 'AllowGuestUserToAccessSharedContent', 'ExternalSharingV2', 'ServicePrincipalAccessPermissionAPIs', 'AllowServicePrincipalsCreateAndUseProfiles', 'BlockResourceKeyAuthentication', 'RScriptVisual', 'EimInformationProtectionEdit'
    $script:Bi = { param([string[]] $On = @(), [string[]] $Groups = @(), [string[]] $Absent = @()) @{ 'pbi-01-tenant-settings' = @($script:BiNames | Where-Object { $_ -notin $Absent } | ForEach-Object { @{ SettingName = $_; Title = $_; Group = 'x'; Enabled = ($_ -in $On); CanSpecifySecurityGroups = $true; EnabledSecurityGroups = @($(if ($_ -in $Groups) { 'SG-Named' })); ExcludedSecurityGroups = @() } }) } }
    $script:Tenant = { param([bool] $Locked) @{ disableEnvironmentCreationByNonAdminUsers = $Locked; disableTrialEnvironmentCreationByNonAdminUsers = $Locked; disablePortalsCreationByNonAdminUsers = $Locked; powerPlatform = @{ powerApps = @{ disableShareWithEveryone = $Locked } } } }
    $script:Environments = @(@{ Name = 'Default-1'; DisplayName = 'Contoso (default)'; IsDefault = $true; Sku = 'Default' }, @{ Name = 'env-prod'; DisplayName = 'Field apps'; IsDefault = $false; Sku = 'Production' }, @{ Name = 'env-dev'; DisplayName = 'Dev'; IsDefault = $false; Sku = 'Sandbox' })
}

AfterAll {
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
}

Describe 'Power BI checks' {
    It 'passes a tenant set the way the baseline asks, and fails the opposite' {
        $good = & $script:Judge (& $script:Bi -On 'BlockResourceKeyAuthentication', 'EimInformationProtectionEdit')
        foreach ($id in 'BI-001', 'BI-002', 'BI-003', 'BI-004', 'BI-005', 'BI-006', 'BI-007', 'BI-008') { $good[$id].status | Should -Be 'pass' -Because $id }
        $bad = & $script:Judge (& $script:Bi -On 'PublishToWeb', 'AllowGuestUserToAccessSharedContent', 'ExternalSharingV2', 'ServicePrincipalAccessPermissionAPIs', 'AllowServicePrincipalsCreateAndUseProfiles', 'RScriptVisual')
        foreach ($id in 'BI-001', 'BI-002', 'BI-003', 'BI-004', 'BI-005', 'BI-006', 'BI-007', 'BI-008') { $bad[$id].status | Should -Be 'fail' -Because $id }
    }

    It 'counts a setting held to named security groups as restricted, except Publish to web' {
        $on = 'PublishToWeb', 'AllowGuestUserToAccessSharedContent', 'ExternalSharingV2', 'ServicePrincipalAccessPermissionAPIs', 'AllowServicePrincipalsCreateAndUseProfiles'
        $r = & $script:Judge (& $script:Bi -On $on -Groups $on)
        foreach ($id in 'BI-002', 'BI-003', 'BI-004', 'BI-005') { $r[$id].status | Should -Be 'pass' -Because "${id}: on for a named group is what the baseline allows" }
        $r['BI-001'].status | Should -Be 'fail' -Because 'a public link is public whichever group made it'
    }

    It 'has no answer for a setting Power BI did not return, and none at all without the file' {
        $r = & $script:Judge (& $script:Bi -Absent 'PublishToWeb')
        $r['BI-001'].status | Should -Be 'notEvaluated'
        $r['BI-001'].reason | Should -Match 'did not return the tenant setting PublishToWeb'
        $r['BI-002'].status | Should -Be 'pass' -Because 'one missing setting takes one answer away'
        $none = & $script:Judge @{ 'pp-01-tenant-settings' = (& $script:Tenant $true) }
        $none['BI-001'].status | Should -Be 'notEvaluated'
        $none['BI-001'].reason | Should -Match 'pbi-01-tenant-settings'
        $none['PP-001'].status | Should -Be 'pass' -Because 'the Power Platform half does not wait for the Power BI half'
    }
}

Describe 'Power Platform checks' {
    It 'reads the four tenant switches, and has no answer for one that is not there' {
        $locked = & $script:Judge @{ 'pp-01-tenant-settings' = (& $script:Tenant $true) }
        foreach ($id in 'PP-001', 'PP-002', 'PP-006', 'PP-007') { $locked[$id].status | Should -Be 'pass' -Because $id }
        $open = & $script:Judge @{ 'pp-01-tenant-settings' = (& $script:Tenant $false) }
        foreach ($id in 'PP-001', 'PP-002', 'PP-006', 'PP-007') { $open[$id].status | Should -Be 'fail' -Because $id }
        $thin = & $script:Judge @{ 'pp-01-tenant-settings' = @{ disableEnvironmentCreationByNonAdminUsers = $true } }
        $thin['PP-001'].status | Should -Be 'pass'
        $thin['PP-007'].status | Should -Be 'notEvaluated' -Because 'a switch the settings did not carry is not a pass'
    }

    It 'works out which environments a DLP policy reaches: all, only the named, or all but the named' {
        $with = { param($Policies) & $script:Judge @{ 'pp-02-environments' = $script:Environments; 'pp-03-dlp-policies' = @($Policies) } }
        $all = & $with @(@{ Name = 'p1'; DisplayName = 'Everything'; EnvironmentType = 'AllEnvironments'; Environments = @() })
        $all['PP-003'].status | Should -Be 'pass'
        $all['PP-004'].status | Should -Be 'pass'
        $only = & $with @(@{ Name = 'p1'; DisplayName = 'Default only'; EnvironmentType = 'OnlyEnvironments'; Environments = @('Default-1') })
        $only['PP-003'].status | Should -Be 'pass'
        $only['PP-004'].status | Should -Be 'fail'
        @($only['PP-004'].affected.name) | Should -Be @('Field apps', 'Dev')
        $except = & $with @(@{ Name = 'p1'; DisplayName = 'All but default and dev'; EnvironmentType = 'ExceptEnvironments'; Environments = @('Default-1', 'env-dev') })
        $except['PP-003'].status | Should -Be 'fail' -Because 'the default environment is one of the exceptions'
        @($except['PP-004'].affected.name) | Should -Be @('Dev')
        $none = & $with @()
        $none['PP-003'].status | Should -Be 'fail' -Because 'no policy at all was read, and that is an answer'
        (& $script:Judge @{ 'pp-02-environments' = $script:Environments })['PP-003'].status | Should -Be 'notEvaluated' -Because 'the policies were not read'
    }

    It 'reads tenant isolation, and has no answer when the policy does not say' {
        (& $script:Judge @{ 'pp-04-tenant-isolation' = @{ IsDisabled = $false; AllowedTenants = 2 } })['PP-005'].status | Should -Be 'pass'
        (& $script:Judge @{ 'pp-04-tenant-isolation' = @{ IsDisabled = $true; AllowedTenants = 0 } })['PP-005'].status | Should -Be 'fail'
        (& $script:Judge @{ 'pp-04-tenant-isolation' = @{ IsDisabled = $null; AllowedTenants = 0 } })['PP-005'].status | Should -Be 'notEvaluated'
    }
}

Describe 'The Power BI and Power Platform collectors' {
    BeforeAll {
        # What the two services answer, keyed by a part of the address. Every request the collectors send is recorded.
        $script:Sent = [System.Collections.Generic.List[object]]::new()
        Mock -ModuleName TenantKeep.Posture Invoke-PosturePowerRest {
            $script:Sent.Add([pscustomobject]@{ Service = $Service; Method = $Method; Uri = $Uri })
            if ($env:TKP_TEST_POWERBI -eq 'unlicensed' -and $Service -eq 'powerbi') { throw 'Power BI answered 401 to GET v1/admin/tenantsettings: UserNotLicensed: User is not licensed' }
            switch -Regex ($Uri) {
                'continuationToken=page2' { return @{ value = @(@{ settingName = 'RScriptVisual'; title = 'R and Python'; enabled = $true; canSpecifySecurityGroups = $false; tenantSettingGroup = 'R and Python visuals settings' }) } }
                '/v1/admin/tenantsettings$' { return @{ value = @(@{ settingName = 'PublishToWeb'; title = 'Publish to web'; enabled = $true; canSpecifySecurityGroups = $true; tenantSettingGroup = 'Export and sharing settings'; enabledSecurityGroups = @(@{ graphId = '1'; name = 'SG-Publishers' }) }); continuationUri = 'https://api.fabric.microsoft.com/v1/admin/tenantsettings?continuationToken=page2' } }
                'listTenantSettings' { return @{ disableEnvironmentCreationByNonAdminUsers = $true; powerPlatform = @{ powerApps = @{ disableShareWithEveryone = $false } } } }
                'scopes/admin/environments' { return @{ value = @(@{ name = 'Default-1'; location = 'unitedstates'; properties = @{ displayName = 'Contoso (default)'; isDefault = $true; environmentSku = 'Default'; createdTime = '2024-01-02T03:04:05Z' } }) } }
                'scopes/admin/apiPolicies' { return @{ value = @(@{ name = 'p-all'; properties = @{ displayName = 'Everything'; definition = @{ constraints = @{} } } }, @{ name = 'p-only'; properties = @{ displayName = 'Named'; definition = @{ constraints = @{ environmentFilter1 = @{ parameters = @{ filterType = 'include'; environments = @(@{ name = 'Default-1' }) } } } } } }) } }
                'tenantIsolationPolicy' { return @{ properties = @{ tenantId = 't'; isDisabled = $false; allowedTenants = @(@{ tenantId = 'other-1' }, @{ tenantId = 'other-2' }) } } }
                default { throw "No answer in the test for $Uri" }
            }
        }
        $script:Read = { param([string] $Folder, [string] $Name) Get-Content -Raw (Join-Path $Folder "$Name.json") | ConvertFrom-Json -AsHashtable }
    }
    AfterAll { $env:TKP_TEST_POWERBI = $null }

    It 'reads every page of the Power BI tenant settings and saves each setting with its groups' {
        $folder = & $script:NewFolder
        $result = InModuleScope TenantKeep.Posture -Parameters @{ Folder = $folder } { Invoke-PosturePowerBICollection -Folder $Folder }
        @($result.errors).Count | Should -Be 0
        $rows = @(& $script:Read $folder 'pbi-01-tenant-settings')
        @($rows.SettingName) | Should -Be @('PublishToWeb', 'RScriptVisual') -Because 'the second page is followed'
        $rows[0].EnabledSecurityGroups | Should -Be @('SG-Publishers')
        $rows[0].Enabled | Should -BeTrue
    }

    It 'says in plain words that the account needs a Power BI or Fabric licence' {
        $env:TKP_TEST_POWERBI = 'unlicensed'
        try {
            $folder = & $script:NewFolder
            $result = InModuleScope TenantKeep.Posture -Parameters @{ Folder = $folder } { Invoke-PosturePowerBICollection -Folder $Folder -WarningAction SilentlyContinue }
            Join-Path $folder 'pbi-01-tenant-settings.json' | Should -Not -Exist
            ($result.errors -join "`n") | Should -Match 'has no Power BI or Fabric licence' -Because 'seen on a live tenant, 2026-11-23'
            ($result.errors -join "`n") | Should -Match 'free Microsoft Fabric licence'
        }
        finally { $env:TKP_TEST_POWERBI = $null }
    }

    It 'treats the missing licence as something to fix on the account, with the role and the licence named' {
        InModuleScope TenantKeep.Posture {
            $said = 'Power BI refused the account that signed in because it has no Power BI or Fabric licence. Power BI answered 401 to GET v1/admin/tenantsettings: UserNotLicensed: User is not licensed'
            Get-PostureFailureCause -Message $said | Should -Be 'permission' -Because 'a free licence on the account fixes it; the tenant is not what is unlicensed'
            $need = Resolve-PostureStepRequirement -Collector PowerBI -Label 'Power BI tenant settings'
            $advice = Get-PostureFailureAdvice -Failure @{ cause = 'permission'; roles = @($need.roles); scopes = @(); licence = [string]$need.licence }
            $advice | Should -Match 'Fabric Administrator'
            $advice | Should -Match 'It also needs a Power BI or Fabric licence on the account that signs in'
        }
    }

    It 'collects the four Power Platform files, counting the allowed tenants and not saving them' {
        $script:Sent.Clear()
        $folder = & $script:NewFolder
        $result = InModuleScope TenantKeep.Posture -Parameters @{ Folder = $folder } { Invoke-PosturePowerPlatformCollection -Folder $Folder -TenantId '33333333-3333-3333-3333-333333333333' }
        @($result.errors).Count | Should -Be 0
        (& $script:Read $folder 'pp-01-tenant-settings').powerPlatform.powerApps.disableShareWithEveryone | Should -BeFalse
        @(& $script:Read $folder 'pp-02-environments')[0].IsDefault | Should -BeTrue
        $policies = @(& $script:Read $folder 'pp-03-dlp-policies')
        @($policies.EnvironmentType) | Should -Be @('AllEnvironments', 'OnlyEnvironments') -Because 'a policy with no filter applies to every environment'
        $policies[1].Environments | Should -Be @('Default-1')
        $isolation = & $script:Read $folder 'pp-04-tenant-isolation'
        $isolation.IsDisabled | Should -BeFalse
        $isolation.AllowedTenants | Should -Be 2
        Get-Content -Raw (Join-Path $folder 'pp-04-tenant-isolation.json') | Should -Not -Match 'other-1' -Because 'the other tenants are counted, not saved'
    }

    It 'sends three GETs and one POST to Power Platform, the POST to the listing of tenant settings and nowhere else' {
        $power = @($script:Sent | Where-Object Service -eq 'powerplatform')
        @($power | Where-Object Method -eq 'GET').Count | Should -Be 3
        $posts = @($power | Where-Object Method -ne 'GET')
        $posts.Count | Should -Be 1
        $posts[0].Uri | Should -Be 'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/listTenantSettings?api-version=2023-06-01'
        @($power | Where-Object { $_.Uri -notmatch '^https://api\.bap\.microsoft\.com/providers/(Microsoft\.BusinessAppPlatform|PowerPlatform\.Governance)/.+\?api-version=\d{4}-\d{2}-\d{2}$' }).Count | Should -Be 0 -Because 'every address is on the admin API with its version pinned'
        ($power | Where-Object { $_.Uri -match 'tenantIsolationPolicy' }).Uri | Should -Match '/tenants/33333333-3333-3333-3333-333333333333/tenantIsolationPolicy'
    }
}

Describe 'A tenant that has not approved the optional reads' {
    It 'is told so with the second consent link, and the reason names nothing else' {
        InModuleScope TenantKeep.Posture {
            $reason = Get-PosturePowerSkipReason -Collector PowerBI -Message 'AADSTS65001: The user or administrator has not consented to use the application.' -TenantId '33333333-3333-3333-3333-333333333333'
            $reason | Should -Match '^This tenant has not approved the Power BI read\. It is optional'
            $reason | Should -Match 'https://login\.microsoftonline\.com/33333333-3333-3333-3333-333333333333/v2\.0/adminconsent\?client_id='
            [uri]::UnescapeDataString($reason) | Should -Match 'powerbi/api/Tenant\.Read\.All https://service\.powerapps\.com//User'
            [uri]::UnescapeDataString($reason) | Should -Not -Match 'graph\.microsoft\.com' -Because 'what was approved before is not asked for again'
            Get-PosturePowerSkipReason -Collector PowerPlatform -Message 'something else went wrong' | Should -Be 'The Power Platform sign-in failed: something else went wrong'
        }
    }

    It 'leaves the two collectors out of a plain collection unless they are named' {
        $command = Get-Command Invoke-PostureCollection
        $default = $command.ScriptBlock.Ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Collector' } | ForEach-Object { $_.DefaultValue.Extent.Text }
        $default | Should -Not -Match 'PowerBI|PowerPlatform' -Because 'they need the run''s own sign-in, which Start-PostureRun opens'
        (Get-Command Start-PostureRun).ScriptBlock.Ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Collector' } | ForEach-Object { $_.DefaultValue.Extent.Text } | Should -Match "'PowerBI', 'PowerPlatform'"
    }
}
