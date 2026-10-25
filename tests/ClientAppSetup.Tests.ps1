# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    $script:Script = Join-Path $PSScriptRoot '..' 'deploy' 'setup' 'New-PostureClientApp.ps1'
    $script:ShippedManifest = Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'app.json'
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
            $resource = @($manifest['resources'] | Where-Object { $_['appId'] -eq $appId })[0]
            $scopes = @($resource['scopes'] | Where-Object { $_ -ne 'Reports.Read.All' } | ForEach-Object { @{ id = "id-$_"; value = $_ } })
            return @{ value = @(@{ id = "sp-$appId"; displayName = $resource['label']; oauth2PermissionScopes = $scopes }) }
        }
        if ($u -match "applications\?\`$filter=displayName eq 'TenantKeep Posture'") {
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
    Remove-Item Function:\global:Get-MgContext, Function:\global:Invoke-MgGraphRequest, Function:\global:Start-Sleep -ErrorAction SilentlyContinue
    Remove-Item Env:TKP_CLIENTAPP_LOG, Env:TKP_CLIENTAPP_EXISTS, Env:TKP_CLIENTAPP_JSON, Env:TKP_CLIENTAPP_VERIFY_404, Env:TKP_CLIENTAPP_SLEPT -ErrorAction SilentlyContinue
}

Describe 'Tenantkeep.Posture/app.json' {
    BeforeAll { $script:Manifest = Get-Content -LiteralPath $script:ShippedManifest -Raw | ConvertFrom-Json -AsHashtable }

    It 'names the app, the loopback redirect and the consent page' {
        $script:Manifest['displayName'] | Should -Be 'TenantKeep Posture'
        $script:Manifest['redirectUri'] | Should -Be 'http://localhost'
        $script:Manifest['consentRedirectUri'] | Should -Match '^https://tenantkeep\.app/'
    }

    It 'asks Graph for exactly the scopes the collection warns about, plus sign-in, refresh and the roles the grant script lists' {
        $graphScopes = @(@($script:Manifest['resources'] | Where-Object { $_['name'] -eq 'graph' })[0]['scopes'])
        $collection = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Public' 'Invoke-PostureCollection.ps1') -Raw
        foreach ($scope in @([regex]::Matches($collection, "^\s+'([A-Za-z.]+\.Read[A-Za-z.]*)'\s+= '", 'Multiline') | ForEach-Object { $_.Groups[1].Value })) {
            $graphScopes | Should -Contain $scope
        }
        foreach ($scope in 'openid', 'profile', 'offline_access', 'User.Read', 'Policy.Read.All', 'Directory.Read.All', 'Group.Read.All', 'Sites.Read.All', 'Organization.Read.All', 'Application.Read.All', 'Reports.Read.All') {
            $graphScopes | Should -Contain $scope
        }
    }

    It 'asks every resource for read-only delegated scopes and nothing that writes' {
        foreach ($resource in @($script:Manifest['resources'])) {
            foreach ($scope in @($resource['scopes'])) {
                $scope | Should -Not -Match 'ReadWrite|\.Write|Mail\.Send|AsApp|application_access'
            }
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
        $create[0].Body.publicClient.redirectUris | Should -Be @('http://localhost')
        $create[0].Body.PSObject.Properties.Name | Should -Not -Contain 'publisherDomain'
        $domain = @($requests | Where-Object { $_.Method -eq 'PATCH' -and $_.Uri -match 'applications/obj-1$' -and $_.Body.PSObject.Properties.Name -contains 'publisherDomain' })
        $domain.Count | Should -Be 1
        $domain[0].Body.publisherDomain | Should -Be 'kainor.com'
        $create[0].Body.PSObject.Properties.Name | Should -Not -Contain 'passwordCredentials'
        $create[0].Body.PSObject.Properties.Name | Should -Not -Contain 'keyCredentials'
        @($create[0].Body.requiredResourceAccess).Count | Should -Be 5
        @($create[0].Body.requiredResourceAccess).resourceAppId | Should -Not -Contain '00000007-0000-0ff1-ce00-000000000000'
        foreach ($r in @($create[0].Body.requiredResourceAccess)) { foreach ($a in @($r.resourceAccess)) { $a.type | Should -Be 'Scope' } }
        $graphAccess = @($create[0].Body.requiredResourceAccess | Where-Object { $_.resourceAppId -eq '00000003-0000-0000-c000-000000000000' })[0]
        @($graphAccess.resourceAccess).id | Should -Contain 'id-Policy.Read.All'
        @($graphAccess.resourceAccess).id | Should -Not -Contain 'id-Reports.Read.All'
        @($warnings | Where-Object { $_ -match "no delegated scope 'Reports.Read.All'.*it exposes: .*Policy\.Read\.All" }).Count | Should -Be 1
        $verify = @($requests | Where-Object { $_.Uri -match 'setVerifiedPublisher$' })
        $verify.Count | Should -Be 1
        $verify[0].Body.verifiedPublisherId | Should -Be '1234567'
        (Get-Content -LiteralPath $script:AppJson -Raw | ConvertFrom-Json).clientId | Should -Be 'aaaaaaaa-0000-0000-0000-000000000001'
        ($out -join "`n") | Should -Match 'adminconsent\?client_id=aaaaaaaa-0000-0000-0000-000000000001'
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

    It 'refuses a session in another tenant and writes nothing under -WhatIf' {
        $env:TKP_CLIENTAPP_EXISTS = '0'
        { & $script:Script -AppJsonPath $script:AppJson -TenantId '22222222-2222-2222-2222-222222222222' } | Should -Throw '*only runs in 22222222*'
        $null = & $script:Script -AppJsonPath $script:AppJson -TenantId '11111111-1111-1111-1111-111111111111' -PartnerId 1234567 -WhatIf -WarningAction SilentlyContinue 6>&1
        $requests = & $script:ReadRequests
        @($requests | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
        (Get-Content -LiteralPath $script:AppJson -Raw | ConvertFrom-Json).clientId | Should -Be ''
    }
}
