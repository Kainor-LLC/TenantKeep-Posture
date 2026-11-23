# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    $script:Script = Join-Path $PSScriptRoot '..' 'deploy' 'setup' 'New-PostureClientApp.ps1'
    $script:ShippedManifest = Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'app.json'
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-clientapp-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $script:AppJson = Join-Path $script:Root 'app.json'
    Copy-Item -LiteralPath $script:ShippedManifest -Destination $script:AppJson
    $env:TKP_CLIENTAPP_LOG = Join-Path $script:Root 'requests.jsonl'
    $env:TKP_CLIENTAPP_JSON = $script:AppJson
    $script:ReadRequests = { @(Get-Content -LiteralPath $env:TKP_CLIENTAPP_LOG -ErrorAction SilentlyContinue | ForEach-Object { $_ | ConvertFrom-Json -Depth 10 }) }
    function global:Start-Sleep { param($Seconds) $env:TKP_CLIENTAPP_SLEPT = [int]$env:TKP_CLIENTAPP_SLEPT + [int]$Seconds }
    function global:Get-MgContext { [pscustomobject]@{ TenantId = '11111111-1111-1111-1111-111111111111'; Account = 'admin@kainor.example'; Scopes = @('Application.ReadWrite.All') } }
    function global:Invoke-MgGraphRequest {
        param([string] $Method = 'GET', [string] $Uri, $Body, [string] $ContentType, [string] $OutputType)
        Add-Content -WhatIf:$false -LiteralPath $env:TKP_CLIENTAPP_LOG -Value (ConvertTo-Json -InputObject @{ Method = $Method; Uri = $Uri; Body = $(if ($Body) { $Body | ConvertFrom-Json -AsHashtable -Depth 10 }) } -Depth 10 -Compress)
        $u = [uri]::UnescapeDataString($Uri)
        if ($u -match "servicePrincipals\?\`$filter=appId eq '([0-9a-f-]+)'") {
            $appId = $Matches[1]
            # Every resource exposes every scope the manifest asks for, except one deliberately missing value, so the test sees the warning path.
            $manifest = Get-Content -LiteralPath $env:TKP_CLIENTAPP_JSON -Raw | ConvertFrom-Json -AsHashtable
            # The product's own scopes and the ones a product sharing the app asks for.
            $all = @($manifest['resources']) + @($(if ($manifest.ContainsKey('sharedWith')) { $manifest['sharedWith'] | ForEach-Object { $_['resources'] } }))
            $resource = @($all | Where-Object { $_['appId'] -eq $appId })[0]
            $scopes = @($all | Where-Object { $_['appId'] -eq $appId } | ForEach-Object { $_['scopes'] } | Select-Object -Unique | Where-Object { $_ -ne 'NetworkAccess.Read.All' } | ForEach-Object { @{ id = "id-$_"; value = $_ } })
            return @{ value = @(@{ id = "sp-$appId"; displayName = $resource['label']; oauth2PermissionScopes = $scopes }) }
        }
        if ($u -match "applications\?\`$filter=appId eq '([0-9a-f-]+)'") {
            # Found by its client id only in the tenant that owns it.
            if ($env:TKP_CLIENTAPP_OWNS -eq $Matches[1]) { return @{ value = @(@{ id = 'obj-1'; appId = $Matches[1]; publisherDomain = 'kainor.com'; verifiedPublisher = @{ verifiedPublisherId = $null } }) } }
            return @{ value = @() }
        }
        if ($u -match "applications\?\`$filter=displayName eq 'TenantKeep Posture for Azure, Teams and Power Platform'") { return @{ value = @() } }
        if ($u -match "applications\?\`$filter=displayName eq 'TenantKeep'") {
            if ($env:TKP_CLIENTAPP_EXISTS -eq '1') { return @{ value = @(@{ id = 'obj-1'; appId = 'aaaaaaaa-0000-0000-0000-000000000001'; publisherDomain = 'kainor.example'; verifiedPublisher = @{ verifiedPublisherId = $null } }) } }
            return @{ value = @() }
        }
        if ($u -match 'applications$' -and $Method -eq 'POST') {
            if ($Body -match 'publisherDomain') { throw "POST https://graph.microsoft.com/v1.0/applications HTTP/1.1 400 Bad Request: Property 'publisherDomain' is read-only and cannot be set." }
            return @{ id = 'obj-1'; appId = 'aaaaaaaa-0000-0000-0000-000000000001'; publisherDomain = 'kainor.onmicrosoft.com' }
        }
        if ($u -match 'applications/obj-1$' -and $Method -eq 'PATCH') { return $null }
        if ($u -match 'setVerifiedPublisher$' -and $Method -eq 'POST') {
            if ([int]$env:TKP_CLIENTAPP_VERIFY_404 -gt 0) { $env:TKP_CLIENTAPP_VERIFY_404 = [int]$env:TKP_CLIENTAPP_VERIFY_404 - 1; throw "POST $u HTTP/1.1 404 Not Found: The target application (obj-1) cannot be found." }
            return $null
        }
        throw "Stub has no answer for $Method $u"
    }
}

AfterAll {
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Function:\Get-MgContext, Function:\Invoke-MgGraphRequest, Function:\Start-Sleep -ErrorAction SilentlyContinue
    Remove-Item Env:TKP_CLIENTAPP_LOG, Env:TKP_CLIENTAPP_EXISTS, Env:TKP_CLIENTAPP_OWNS, Env:TKP_CLIENTAPP_JSON, Env:TKP_CLIENTAPP_VERIFY_404, Env:TKP_CLIENTAPP_SLEPT -ErrorAction SilentlyContinue
}

Describe 'TenantKeep.Posture/app.json' {
    BeforeAll { $script:Manifest = Get-Content -LiteralPath $script:ShippedManifest -Raw | ConvertFrom-Json -AsHashtable }

    It 'names the app, the loopback redirect and the consent page' {
        $script:Manifest['displayName'] | Should -Be 'TenantKeep' -Because 'the registration is shared with TenantKeep On-Call, so it carries the family name'
        $script:Manifest['redirectUri'] | Should -Be 'http://localhost'
        $script:Manifest['consentRedirectUri'] | Should -Match '^https://tenantkeep\.app/'
    }

    It 'asks Graph for exactly the scopes the collection warns about, plus sign-in, refresh and the roles the grant script lists' {
        $graphScopes = @(@($script:Manifest['resources'] | Where-Object { $_['name'] -eq 'graph' })[0]['scopes'])
        $collection = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'Public' 'Invoke-PostureCollection.ps1') -Raw
        foreach ($scope in @([regex]::Matches($collection, "^\s+'([A-Za-z.]+\.Read[A-Za-z.]*)'\s+= '", 'Multiline') | ForEach-Object { $_.Groups[1].Value })) {
            $graphScopes | Should -Contain $scope
        }
        foreach ($scope in 'openid', 'profile', 'offline_access', 'User.Read', 'Policy.Read.All', 'Directory.Read.All', 'Group.Read.All', 'Organization.Read.All', 'Application.Read.All') {
            $graphScopes | Should -Contain $scope
        }
    }

    It 'carries no Graph scope that no collector or step uses, and names no scope the consent does not carry' {
        # requirements.json says which step needs which scope (Run Health quotes it). A scope on the consent screen
        # that nothing there names is a permission asked for and never used; a scope named there that the consent
        # does not carry is advice nobody can follow.
        $graphScopes = @(@($script:Manifest['resources'] | Where-Object { $_['name'] -eq 'graph' })[0]['scopes'])
        $requirements = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'requirements.json') | ConvertFrom-Json -AsHashtable -Depth 10
        $used = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in @($requirements['collectors'].Values) + @($requirements['steps'])) {
            if ($entry.Contains('scopes') -and $entry['scopes']) { foreach ($scope in @($entry['scopes'])) { $null = $used.Add([string]$scope) } }
        }
        foreach ($scope in @($graphScopes | Where-Object { $_ -notin 'openid', 'profile', 'offline_access', 'User.Read' })) {
            $used.Contains($scope) | Should -BeTrue -Because "$scope is on the consent screen, so a collector or a step in requirements.json must need it"
        }
        foreach ($scope in $used) { $graphScopes | Should -Contain $scope -Because "requirements.json tells admins the app needs $scope" }
        $graphScopes | Should -Not -Contain 'Sites.Read.All' -Because 'no collector reads site content'
        $graphScopes | Should -Not -Contain 'Reports.Read.All' -Because 'no collector reads a usage report'
    }

    It 'holds read permissions only, on every API, in what Posture asks for and in what a product sharing the app asks for' {
        # The shared read app cannot write: every scope is a sign-in basic or reads, by its name, with no exception
        # for any API. A refresh token for a registration can be redeemed for any API a tenant granted it, so one
        # broader permission anywhere would make "read permissions only" untrue in every tenant that approved it.
        # The three APIs that offer no read-only scope (Azure Service Management, the Teams admin API, the PowerApps
        # Service) are on the second app, app-services.json, and must never come back here (decided 2026-11-23).
        $basics = 'openid', 'profile', 'offline_access', 'User.Read'
        $reads = '^[A-Za-z-]+\.(Read|ReadBasic)\.(All|Directory|AzureADGroup)$'
        # The pattern above is what makes a scope a read. This second list is the words Microsoft uses for the rest,
        # looked for after the first dot so that a resource named RoleManagement or PrivilegedEligibilitySchedule passes.
        $writes = '\.(.*)(Write|Manage|FullControl|PrivilegedOperations|Send|Create|Delete|Remove|Revoke|EnableDisable|Register|AsApp)|application_access|user_impersonation'
        $shared = @($script:Manifest['sharedWith'])
        $shared.Count | Should -Be 1
        $shared[0]['product'] | Should -Be 'TenantKeep On-Call'
        @($script:Manifest['resources'].name) | Should -Be @('graph', 'powerbi') -Because 'Microsoft Graph and Power BI are the APIs Posture reads that have read-only permissions'
        @($script:Manifest['resources'].appId) | Should -Not -Contain '797f4846-ba00-4fd7-ba43-dac1f8f63013' -Because 'Azure Service Management has no read-only permission'
        @($script:Manifest['resources'].appId) | Should -Not -Contain '48ac35b8-9aa8-4d74-927d-1f4a14a0b239' -Because 'the Teams admin API has no read-only permission'
        @($script:Manifest['resources'].appId) | Should -Not -Contain '475226c6-020e-4fb2-8a90-7a972cbfc1d4' -Because 'the PowerApps Service has no read-only permission'
        foreach ($resource in @($script:Manifest['resources'])) {
            foreach ($scope in @($resource['scopes'])) {
                if ($scope -in $basics) { $resource['name'] | Should -Be 'graph'; continue }
                $scope | Should -Match $reads -Because "$scope on $($resource['label']) is on the read app"
                $scope | Should -Not -Match $writes
            }
        }
        @(@($script:Manifest['resources'] | Where-Object { $_['name'] -eq 'powerbi' })[0]['scopes']) | Should -Be @('Tenant.Read.All')
        foreach ($product in $shared) {
            foreach ($resource in @($product['resources'])) {
                $resource['appId'] | Should -Be '00000003-0000-0000-c000-000000000000' -Because "$($product['product']) reads through Microsoft Graph only"
                foreach ($scope in @($resource['scopes'])) {
                    if ($scope -in $basics) { continue }
                    $scope | Should -Match $reads -Because "$scope is on the read app for $($product['product'])"
                    $scope | Should -Not -Match $writes
                }
            }
            foreach ($uri in @($product['redirectUris'])) { $uri | Should -Match '^msauth\.com\.kainor\.[a-z.]+://auth$' }
        }
        $script:Manifest.ContainsKey('api') | Should -BeFalse -Because 'the read app exposes no permission of its own'
    }

    It 'gives customers a consent link that names what Posture reads and nothing of the product sharing the app' {
        Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
        InModuleScope TenantKeep.Posture {
            $link = Get-PostureConsentLink -TenantId '33333333-3333-3333-3333-333333333333'
            $link | Should -Match '^https://login\.microsoftonline\.com/33333333-3333-3333-3333-333333333333/v2\.0/adminconsent\?client_id=e5b148e7-9689-40b2-9b09-9d0bef133049&scope='
            $scopes = [uri]::UnescapeDataString(([regex]::Match($link, 'scope=([^&]+)')).Groups[1].Value) -split ' '
            $scopes | Should -Contain 'https://graph.microsoft.com/Policy.Read.All'
            $scopes | Should -Contain 'openid'
            @($scopes | Where-Object { $_ -notmatch '^(openid|profile|offline_access|https://graph\.microsoft\.com/[A-Za-z.-]+)$' }).Count | Should -Be 0 -Because 'the first link names Microsoft Graph reads and nothing else'
            @($scopes | Where-Object { $_ -match 'user_impersonation' }).Count | Should -Be 0 -Because 'Azure and Teams are approved on the second app'
            $scopes | Should -Not -Contain 'https://graph.microsoft.com/DeviceLocalCredential.Read.All' -Because 'a customer who wants a report is not asked to approve a LAPS password read'
            $scopes | Should -Not -Contain 'https://graph.microsoft.com/BitLockerKey.Read.All'
            @($scopes | Where-Object { $_ -match '\.default$' }).Count | Should -Be 0 -Because '.default would ask for everything registered on the shared app'
            $link | Should -Match 'redirect_uri=https%3A%2F%2Ftenantkeep\.app%2Fconsent%2F&state=posture$'
            Get-PostureConsentLink | Should -Match 'microsoftonline\.com/organizations/v2\.0/adminconsent'
            { Get-PostureConsentLink -Resource teams } | Should -Throw "*app.json names no permission for 'teams'*"
            # Power BI is approved from a link of its own, by a customer who wants those checks.
            @($scopes | Where-Object { $_ -match 'powerbi|powerapps' }).Count | Should -Be 0 -Because 'a tenant that approved the first link is not asked again'
            $second = Get-PostureConsentLink -TenantId '33333333-3333-3333-3333-333333333333' -Optional
            $second | Should -Match '^https://login\.microsoftonline\.com/33333333-3333-3333-3333-333333333333/v2\.0/adminconsent\?client_id=e5b148e7-9689-40b2-9b09-9d0bef133049&scope='
            ([uri]::UnescapeDataString(([regex]::Match($second, 'scope=([^&]+)')).Groups[1].Value) -split ' ') | Should -Be @('https://analysis.windows.net/powerbi/api/Tenant.Read.All') -Because 'the optional link of the read app names Power BI and nothing else'
        }
    }
}

Describe 'TenantKeep.Posture/app-services.json' {
    BeforeAll {
        $script:ServicesManifest = Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'app-services.json'
        $script:Services = Get-Content -LiteralPath $script:ServicesManifest -Raw | ConvertFrom-Json -AsHashtable
    }

    It 'is the one place the three APIs without a read-only permission are named, and holds nothing else' {
        $script:Services['displayName'] | Should -Be 'TenantKeep Posture for Azure, Teams and Power Platform'
        $script:Services['redirectUri'] | Should -Be 'http://localhost'
        $script:Services['consentRedirectUri'] | Should -Match '^https://tenantkeep\.app/'
        $script:Services['clientId'] | Should -Match '^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})?$' -Because 'empty until the registration is created, then its id'
        $script:Services['clientId'] | Should -Not -Be 'e5b148e7-9689-40b2-9b09-9d0bef133049' -Because 'it is a registration of its own'
        $script:Services.ContainsKey('sharedWith') | Should -BeFalse -Because 'only Posture signs in to it; TenantKeep On-Call never does'
        $script:Services.ContainsKey('api') | Should -BeFalse
        $by = @{}; foreach ($resource in @($script:Services['resources'])) { $by[[string]$resource['name']] = $resource }
        @($script:Services['resources'].name) | Should -Be @('graph', 'teams', 'azure', 'powerplatform')
        @($by['graph']['scopes']) | Should -Be @('openid', 'profile', 'offline_access', 'User.Read') -Because 'Graph only for the sign-in itself: every Graph read stays on the read app'
        $by['graph']['signIn'] | Should -BeTrue
        $by['teams']['appId'] | Should -Be '48ac35b8-9aa8-4d74-927d-1f4a14a0b239'
        @($by['teams']['scopes']) | Should -Be @('user_impersonation')
        $by['azure']['appId'] | Should -Be '797f4846-ba00-4fd7-ba43-dac1f8f63013'
        $by['azure']['audience'] | Should -Be 'https://management.core.windows.net/'
        @($by['azure']['scopes']) | Should -Be @('user_impersonation')
        $by['powerplatform']['appId'] | Should -Be '475226c6-020e-4fb2-8a90-7a972cbfc1d4'
        @($by['powerplatform']['scopes']) | Should -Be @('User')
        $by['powerplatform']['optional'] | Should -BeTrue -Because 'a customer approves the Power Platform read separately, knowing what it is'
        $by['teams'].ContainsKey('optional') | Should -BeFalse
        $by['azure'].ContainsKey('optional') | Should -BeFalse
    }

    It 'shares no API with the read app but the sign-in, and the module knows which sign-in each token comes from' {
        $main = Get-Content -LiteralPath $script:ShippedManifest -Raw | ConvertFrom-Json -AsHashtable
        $both = @($script:Services['resources'].appId | Where-Object { $_ -in @($main['resources'].appId) })
        $both | Should -Be @('00000003-0000-0000-c000-000000000000')
        Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
        InModuleScope TenantKeep.Posture {
            Get-PostureResourceApp -Resource graph | Should -Be 'main' -Because 'the second app names Graph only so that a person can sign in to it'
            Get-PostureResourceApp -Resource powerbi | Should -Be 'main'
            foreach ($api in 'azure', 'teams', 'powerplatform') { Get-PostureResourceApp -Resource $api | Should -Be 'services' }
            Get-PostureResourceApp -Resource sharepoint | Should -Be 'sharepoint'
            Get-PostureResourceScope -Resource azure | Should -Be 'https://management.core.windows.net//.default'
            Get-PostureResourceScope -Resource teams | Should -Be '48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default'
            Get-PostureResourceScope -Resource powerplatform | Should -Be 'https://service.powerapps.com//.default'
            Get-PostureResourceScope -Resource powerbi | Should -Be 'https://analysis.windows.net/powerbi/api/.default'
        }
    }

    It 'gives customers links that each name what signing in needs and the APIs chosen, and no Graph read' {
        Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
        InModuleScope TenantKeep.Posture {
            $id = 'cccccccc-0000-0000-0000-000000000003'
            $scopeOf = { param($link) [uri]::UnescapeDataString(([regex]::Match($link, 'scope=([^&]+)')).Groups[1].Value) -split ' ' }
            $link = Get-PostureConsentLink -App services -ClientId $id -TenantId '33333333-3333-3333-3333-333333333333'
            $link | Should -Match '^https://login\.microsoftonline\.com/33333333-3333-3333-3333-333333333333/v2\.0/adminconsent\?client_id=cccccccc-0000-0000-0000-000000000003&scope='
            $link | Should -Match 'redirect_uri=https%3A%2F%2Ftenantkeep\.app%2Fconsent%2F&state=posture$'
            & $scopeOf $link | Should -Be @('openid', 'profile', 'offline_access', 'https://graph.microsoft.com/User.Read', '48ac35b8-9aa8-4d74-927d-1f4a14a0b239/user_impersonation', 'https://management.core.windows.net//user_impersonation') -Because 'Azure writes its address with the slash, and Power Platform is approved separately'
            & $scopeOf (Get-PostureConsentLink -App services -ClientId $id -Optional) | Should -Be @('openid', 'profile', 'offline_access', 'https://graph.microsoft.com/User.Read', 'https://service.powerapps.com//User') -Because 'the link is enough alone for a customer who wants Power Platform and neither of the others'
            & $scopeOf (Get-PostureConsentLink -App services -ClientId $id -Resource azure) | Should -Be @('openid', 'profile', 'offline_access', 'https://graph.microsoft.com/User.Read', 'https://management.core.windows.net//user_impersonation')
            { Get-PostureConsentLink -App services -ClientId $id -Resource powerbi } | Should -Throw "*app-services.json names no permission for 'powerbi'*"
            $empty = Get-PostureAppManifest -Name services; $empty['clientId'] = ''
            { Get-PostureConsentLink -Manifest $empty } | Should -Throw '*app-services.json carries no client id yet*' -Because 'a link with no app in it would look real and approve nothing'
        }
    }
}

Describe 'New-PostureClientApp.ps1' {
    BeforeEach {
        Remove-Item -LiteralPath $env:TKP_CLIENTAPP_LOG -ErrorAction SilentlyContinue
        Copy-Item -LiteralPath $script:ShippedManifest -Destination $script:AppJson -Force
        # The shipped manifest carries the real client id; the tests start from an unregistered one.
        (Get-Content -LiteralPath $script:AppJson -Raw) -replace '"clientId":\s*"[^"]*"', '"clientId": ""' | Set-Content -LiteralPath $script:AppJson -NoNewline
        $env:TKP_CLIENTAPP_VERIFY_404 = '0'; $env:TKP_CLIENTAPP_SLEPT = '0'
    }

    It 'creates a multi-tenant public client with delegated scopes only, verifies the publisher and writes the client id back' {
        $env:TKP_CLIENTAPP_EXISTS = '0'
        $out = & $script:Script -AppJsonPath $script:AppJson -TenantId '11111111-1111-1111-1111-111111111111' -PartnerId 1234567 -WarningVariable warnings -WarningAction SilentlyContinue 6>&1
        $requests = & $script:ReadRequests
        $create = @($requests | Where-Object { $_.Method -eq 'POST' -and $_.Uri -match 'applications$' })
        $create.Count | Should -Be 1
        $create[0].Body.signInAudience | Should -Be 'AzureADMultipleOrgs'
        $create[0].Body.isFallbackPublicClient | Should -BeTrue
        $create[0].Body.publicClient.redirectUris | Should -Be @('http://localhost', 'msauth.com.kainor.lapslock://auth', 'msauth.com.kainor.tenantkeep.menubar://auth') -Because 'the phone and Mac app sign in to the same registration'
        $create[0].Body.PSObject.Properties.Name | Should -Not -Contain 'publisherDomain'
        $domain = @($requests | Where-Object { $_.Method -eq 'PATCH' -and $_.Uri -match 'applications/obj-1$' -and $_.Body.PSObject.Properties.Name -contains 'publisherDomain' })
        $domain.Count | Should -Be 1
        $domain[0].Body.publisherDomain | Should -Be 'kainor.com'
        $create[0].Body.PSObject.Properties.Name | Should -Not -Contain 'passwordCredentials'
        $create[0].Body.PSObject.Properties.Name | Should -Not -Contain 'keyCredentials'
        @($create[0].Body.requiredResourceAccess).resourceAppId | Should -Be @('00000003-0000-0000-c000-000000000000', '00000009-0000-0000-c000-000000000000') -Because 'Graph, and Power BI so that a customer can approve it; Azure, Teams and Power Platform are on the second app, Exchange signs in through its own module, and SharePoint full control lives only in the separate SharePoint app'
        @($create[0].Body.requiredResourceAccess).resourceAppId | Should -Not -Contain '00000007-0000-0ff1-ce00-000000000000'
        foreach ($r in @($create[0].Body.requiredResourceAccess)) { foreach ($a in @($r.resourceAccess)) { $a.type | Should -Be 'Scope' } }
        $graphAccess = @($create[0].Body.requiredResourceAccess | Where-Object { $_.resourceAppId -eq '00000003-0000-0000-c000-000000000000' })[0]
        @($graphAccess.resourceAccess).id | Should -Contain 'id-Policy.Read.All'
        @($graphAccess.resourceAccess).id | Should -Contain 'id-DeviceLocalCredential.Read.All' -Because 'what On-Call asks for is registered too, so an administrator can approve it for the organisation'
        @(@($graphAccess.resourceAccess).id | Group-Object | Where-Object Count -gt 1).Count | Should -Be 0 -Because 'a scope both products ask for is registered once'
        @($graphAccess.resourceAccess).id | Should -Not -Contain 'id-NetworkAccess.Read.All'
        @($warnings | Where-Object { $_ -match "no delegated scope 'NetworkAccess.Read.All'.*it exposes: .*Policy\.Read\.All" }).Count | Should -Be 1
        $verify = @($requests | Where-Object { $_.Uri -match 'setVerifiedPublisher$' })
        $verify.Count | Should -Be 1
        $verify[0].Body.verifiedPublisherId | Should -Be '1234567'
        (Get-Content -LiteralPath $script:AppJson -Raw | ConvertFrom-Json).clientId | Should -Be 'aaaaaaaa-0000-0000-0000-000000000001'
        $text = $out -join "`n"
        $text | Should -Match 'v2\.0/adminconsent\?client_id=aaaaaaaa-0000-0000-0000-000000000001&scope='
        $printed = [uri]::UnescapeDataString(([regex]::Match($text, 'scope=([^&\s]+)')).Groups[1].Value)
        $printed | Should -Match 'https://graph\.microsoft\.com/Policy\.Read\.All'
        $printed | Should -Not -Match 'DeviceLocalCredential|\.default' -Because 'the link names what Posture asks for, not everything registered'
        $text | Should -Match 'also carries what TenantKeep On-Call asks for'
    }

    It 'registers the second app from app-services.json: the three APIs, no credentials, and links that carry the sign-in' {
        $env:TKP_CLIENTAPP_EXISTS = '0'
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'app-services.json') -Destination $script:AppJson -Force
        (Get-Content -LiteralPath $script:AppJson -Raw) -replace '"clientId":\s*"[^"]*"', '"clientId": ""' | Set-Content -LiteralPath $script:AppJson -NoNewline
        $out = & $script:Script -AppJsonPath $script:AppJson -TenantId '11111111-1111-1111-1111-111111111111' -WarningAction SilentlyContinue 6>&1
        $requests = & $script:ReadRequests
        $create = @($requests | Where-Object { $_.Method -eq 'POST' -and $_.Uri -match 'applications$' })
        $create.Count | Should -Be 1
        $create[0].Body.displayName | Should -Be 'TenantKeep Posture for Azure, Teams and Power Platform'
        $create[0].Body.signInAudience | Should -Be 'AzureADMultipleOrgs'
        $create[0].Body.isFallbackPublicClient | Should -BeTrue
        $create[0].Body.publicClient.redirectUris | Should -Be @('http://localhost') -Because 'no phone or Mac app signs in to this one'
        $create[0].Body.PSObject.Properties.Name | Should -Not -Contain 'passwordCredentials'
        $create[0].Body.PSObject.Properties.Name | Should -Not -Contain 'keyCredentials'
        @($create[0].Body.requiredResourceAccess).resourceAppId | Should -Be @('00000003-0000-0000-c000-000000000000', '48ac35b8-9aa8-4d74-927d-1f4a14a0b239', '797f4846-ba00-4fd7-ba43-dac1f8f63013', '475226c6-020e-4fb2-8a90-7a972cbfc1d4')
        foreach ($r in @($create[0].Body.requiredResourceAccess)) { foreach ($a in @($r.resourceAccess)) { $a.type | Should -Be 'Scope' } }
        $graphAccess = @($create[0].Body.requiredResourceAccess | Where-Object { $_.resourceAppId -eq '00000003-0000-0000-c000-000000000000' })[0]
        @($graphAccess.resourceAccess).id | Should -Be @('id-openid', 'id-profile', 'id-offline_access', 'id-User.Read') -Because 'no Graph read is registered on the second app'
        (Get-Content -LiteralPath $script:AppJson -Raw | ConvertFrom-Json).clientId | Should -Be 'aaaaaaaa-0000-0000-0000-000000000001'
        $text = $out -join "`n"
        $links = @([regex]::Matches($text, 'scope=([^&\s]+)') | ForEach-Object { [uri]::UnescapeDataString($_.Groups[1].Value) })
        $links.Count | Should -Be 2
        $links[0] | Should -Be 'openid profile offline_access https://graph.microsoft.com/User.Read 48ac35b8-9aa8-4d74-927d-1f4a14a0b239/user_impersonation https://management.core.windows.net//user_impersonation'
        $links[1] | Should -Be 'openid profile offline_access https://graph.microsoft.com/User.Read https://service.powerapps.com//User'
        $text | Should -Match 'Customers approve TenantKeep Posture for Azure, Teams and Power Platform \(Skype and Teams Tenant Admin API, Azure Service Management\) once'
        $text | Should -Not -Match 'also carries what'
    }

    It 'writes the client id before verifying, and waits for a new registration to replicate before setVerifiedPublisher' {
        $env:TKP_CLIENTAPP_EXISTS = '0'; $env:TKP_CLIENTAPP_VERIFY_404 = '2'
        $null = & $script:Script -AppJsonPath $script:AppJson -TenantId '11111111-1111-1111-1111-111111111111' -PartnerId 1234567 -WarningAction SilentlyContinue 6>&1
        $requests = & $script:ReadRequests
        @($requests | Where-Object { $_.Uri -match 'setVerifiedPublisher$' }).Count | Should -Be 3
        [int]$env:TKP_CLIENTAPP_SLEPT | Should -Be 20
        (Get-Content -LiteralPath $script:AppJson -Raw | ConvertFrom-Json).clientId | Should -Be 'aaaaaaaa-0000-0000-0000-000000000001'
    }

    It 'keeps the client id and warns when verification keeps failing' {
        $env:TKP_CLIENTAPP_EXISTS = '0'; $env:TKP_CLIENTAPP_VERIFY_404 = '9'
        $null = & $script:Script -AppJsonPath $script:AppJson -TenantId '11111111-1111-1111-1111-111111111111' -PartnerId 1234567 -WarningVariable warnings -WarningAction SilentlyContinue 6>&1
        @($warnings | Where-Object { $_ -match 'Publisher verification failed' }).Count | Should -Be 1
        (Get-Content -LiteralPath $script:AppJson -Raw | ConvertFrom-Json).clientId | Should -Be 'aaaaaaaa-0000-0000-0000-000000000001'
    }

    It 'updates an existing registration in place instead of creating a second one' {
        $env:TKP_CLIENTAPP_EXISTS = '1'
        $null = & $script:Script -AppJsonPath $script:AppJson -TenantId '11111111-1111-1111-1111-111111111111' -WarningAction SilentlyContinue 6>&1
        $requests = & $script:ReadRequests
        @($requests | Where-Object { $_.Method -eq 'POST' -and $_.Uri -match 'applications$' }).Count | Should -Be 0
        @($requests | Where-Object { $_.Method -eq 'PATCH' -and $_.Uri -match 'applications/obj-1$' -and $_.Body.PSObject.Properties.Name -contains 'displayName' }).Count | Should -Be 1
        @($requests | Where-Object { $_.Method -eq 'PATCH' -and $_.Uri -match 'applications/obj-1$' -and $_.Body.PSObject.Properties.Name -contains 'publisherDomain' }).Count | Should -Be 1
        @($requests | Where-Object { $_.Uri -match 'setVerifiedPublisher$' }).Count | Should -Be 0
    }

    It 'finds the registration by the client id app.json records, so a new name renames it' {
        $env:TKP_CLIENTAPP_EXISTS = '0'; $env:TKP_CLIENTAPP_OWNS = 'e5b148e7-9689-40b2-9b09-9d0bef133049'
        try {
            Copy-Item -LiteralPath $script:ShippedManifest -Destination $script:AppJson -Force
            $null = & $script:Script -AppJsonPath $script:AppJson -TenantId '11111111-1111-1111-1111-111111111111' -WarningAction SilentlyContinue 6>&1
            $requests = & $script:ReadRequests
            @($requests | Where-Object { $_.Method -eq 'POST' -and $_.Uri -match 'applications$' }).Count | Should -Be 0 -Because 'the name in the tenant is still the old one, and a second registration would split every customer''s consent'
            $patch = @($requests | Where-Object { $_.Method -eq 'PATCH' -and $_.Uri -match 'applications/obj-1$' -and $_.Body.PSObject.Properties.Name -contains 'displayName' })
            $patch.Count | Should -Be 1
            $patch[0].Body.displayName | Should -Be 'TenantKeep'
            (Get-Content -LiteralPath $script:AppJson -Raw | ConvertFrom-Json).clientId | Should -Be 'e5b148e7-9689-40b2-9b09-9d0bef133049'
        }
        finally { Remove-Item Env:TKP_CLIENTAPP_OWNS -ErrorAction SilentlyContinue }
    }

    It 'refuses a session in another tenant and writes nothing under -WhatIf' {
        $env:TKP_CLIENTAPP_EXISTS = '0'
        { & $script:Script -AppJsonPath $script:AppJson -TenantId '22222222-2222-2222-2222-222222222222' } | Should -Throw '*only runs in 22222222*'
        $null = & $script:Script -AppJsonPath $script:AppJson -TenantId '11111111-1111-1111-1111-111111111111' -PartnerId 1234567 -WhatIf -WarningAction SilentlyContinue 6>&1
        $requests = & $script:ReadRequests
        @($requests | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
        (Get-Content -LiteralPath $script:AppJson -Raw | ConvertFrom-Json).clientId | Should -Be ''
    }
}
