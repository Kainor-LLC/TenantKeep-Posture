# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# deploy/setup/Remove-PostureStaleGrant.ps1: in a tenant that approved the TenantKeep app when its manifest named
# more than it does now, the grants the manifest no longer names are taken away. Graph is a stub; nothing is called.
BeforeAll {
    $script:Script = Join-Path $PSScriptRoot '..' 'deploy' 'setup' 'Remove-PostureStaleGrant.ps1'
    $script:AppJson = Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'app.json'
    $script:Tid = '11111111-1111-1111-1111-111111111111'
    $script:App = 'e5b148e7-9689-40b2-9b09-9d0bef133049'
    $script:GraphReads = @(@((Get-Content -LiteralPath $script:AppJson -Raw | ConvertFrom-Json -AsHashtable)['resources'] | Where-Object { $_['name'] -eq 'graph' })[0]['scopes'])
    # A tenant that approved the app before 2026-11-23: Azure, Teams and Power Platform are still granted, one Graph
    # grant holds a permission no manifest names, and one account consented for itself. The stub keeps the tenant in
    # a file, so nothing is held in a global variable.
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-stalegrant-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $env:TKP_GRANT_STATE = Join-Path $script:Root 'tenant.json'
    $env:TKP_GRANT_LOG = Join-Path $script:Root 'requests.jsonl'
    $script:ReadState = { Get-Content -LiteralPath $env:TKP_GRANT_STATE -Raw | ConvertFrom-Json -AsHashtable -Depth 10 }
    $script:WriteState = { param($State) Set-Content -LiteralPath $env:TKP_GRANT_STATE -Value (ConvertTo-Json -InputObject $State -Depth 10) }
    $script:ReadRequests = { @(Get-Content -LiteralPath $env:TKP_GRANT_LOG -ErrorAction SilentlyContinue | ForEach-Object { $_ | ConvertFrom-Json -AsHashtable -Depth 10 }) }
    $script:Writes = { @(& $script:ReadRequests | Where-Object { $_['Method'] -ne 'GET' }) }
    $script:NewTenant = {
        Remove-Item -LiteralPath $env:TKP_GRANT_LOG -ErrorAction SilentlyContinue
        & $script:WriteState @{
            scopes       = @('DelegatedPermissionGrant.ReadWrite.All', 'Application.Read.All')
            hasApp       = $true
            registration = @()
            grants       = @(
                @{ id = 'g-graph'; consentType = 'AllPrincipals'; principalId = $null; resourceId = 'api-graph'; scope = " $($script:GraphReads -join ' ') DeviceLocalCredential.Read.All Mail.Send email" }
                @{ id = 'g-azure'; consentType = 'AllPrincipals'; principalId = $null; resourceId = 'api-azure'; scope = 'user_impersonation' }
                @{ id = 'g-teams'; consentType = 'AllPrincipals'; principalId = $null; resourceId = 'api-teams'; scope = 'user_impersonation' }
                @{ id = 'g-power'; consentType = 'AllPrincipals'; principalId = $null; resourceId = 'api-power'; scope = 'User' }
                @{ id = 'g-pbi'; consentType = 'AllPrincipals'; principalId = $null; resourceId = 'api-pbi'; scope = 'Tenant.Read.All' }
                @{ id = 'g-user'; consentType = 'Principal'; principalId = 'user-1'; resourceId = 'api-azure'; scope = 'user_impersonation' }
            )
        }
    }
    $script:Change = { param([scriptblock] $Edit) $state = & $script:ReadState; & $Edit $state; & $script:WriteState $state }
    function global:Get-MgContext { [pscustomobject]@{ TenantId = '11111111-1111-1111-1111-111111111111'; Account = 'admin@contoso.example'; Scopes = @((Get-Content -LiteralPath $env:TKP_GRANT_STATE -Raw | ConvertFrom-Json -AsHashtable -Depth 10)['scopes']) } }
    function global:Invoke-MgGraphRequest {
        param([string] $Method = 'GET', [string] $Uri, $Body, [string] $ContentType, [string] $OutputType)
        Add-Content -WhatIf:$false -LiteralPath $env:TKP_GRANT_LOG -Value (ConvertTo-Json -InputObject @{ Method = $Method; Uri = $Uri; Body = $(if ($Body) { $Body | ConvertFrom-Json -AsHashtable }) } -Depth 10 -Compress)
        $state = Get-Content -LiteralPath $env:TKP_GRANT_STATE -Raw | ConvertFrom-Json -AsHashtable -Depth 10
        $apis = @{
            'api-graph' = @{ appId = '00000003-0000-0000-c000-000000000000'; displayName = 'Microsoft Graph' }
            'api-azure' = @{ appId = '797f4846-ba00-4fd7-ba43-dac1f8f63013'; displayName = 'Windows Azure Service Management API' }
            'api-teams' = @{ appId = '48ac35b8-9aa8-4d74-927d-1f4a14a0b239'; displayName = 'Skype and Teams Tenant Admin API' }
            'api-power' = @{ appId = '475226c6-020e-4fb2-8a90-7a972cbfc1d4'; displayName = 'PowerApps Service' }
            'api-pbi'   = @{ appId = '00000009-0000-0000-c000-000000000000'; displayName = 'Power BI Service' }
        }
        $save = { Set-Content -WhatIf:$false -LiteralPath $env:TKP_GRANT_STATE -Value (ConvertTo-Json -InputObject $state -Depth 10) }
        $u = [uri]::UnescapeDataString($Uri)
        if ($Method -eq 'GET' -and $u -match "/servicePrincipals\?\`$filter=appId eq '") { return @{ value = @($(if ($state['hasApp']) { @{ id = 'sp-app'; displayName = 'TenantKeep' } })) } }
        if ($Method -eq 'GET' -and $u -match '/servicePrincipals/([a-z-]+)\?') { return $apis[$Matches[1]] }
        # Two pages, so the script is seen to follow the next link.
        if ($Method -eq 'GET' -and $u -match "/oauth2PermissionGrants\?\`$filter=clientId eq 'sp-app'$") { return @{ value = @(@($state['grants']) | Select-Object -First 3); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?page=2' } }
        if ($Method -eq 'GET' -and $u -match '/oauth2PermissionGrants\?page=2$') { return @{ value = @(@($state['grants']) | Select-Object -Skip 3) } }
        if ($Method -eq 'GET' -and $u -match "/applications\?\`$filter=appId eq '") { return @{ value = @($state['registration']) } }
        if ($Method -eq 'DELETE' -and $u -match '/oauth2PermissionGrants/(g-[a-z]+)$') { $id = $Matches[1]; $state['grants'] = @(@($state['grants']) | Where-Object { $_['id'] -ne $id }); & $save; return $null }
        if ($Method -eq 'PATCH' -and $u -match '/oauth2PermissionGrants/(g-[a-z]+)$') { $id = $Matches[1]; @(@($state['grants']) | Where-Object { $_['id'] -eq $id })[0]['scope'] = [string]($Body | ConvertFrom-Json).scope; & $save; return $null }
        throw "Stub has no answer for $Method $u"
    }
}

AfterAll {
    Remove-Item Function:\Get-MgContext, Function:\Invoke-MgGraphRequest -ErrorAction SilentlyContinue
    Remove-Item Env:TKP_GRANT_STATE, Env:TKP_GRANT_LOG -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Remove-PostureStaleGrant.ps1' {
    BeforeEach { & $script:NewTenant }

    It 'removes every grant the manifest no longer names, keeps every read it does name, and says the tenant is clean' {
        $out = (& $script:Script -TenantId $script:Tid -AppJsonPath $script:AppJson 6>&1) -join "`n"
        $writes = & $script:Writes
        @($writes | Where-Object { $_['Method'] -eq 'DELETE' } | ForEach-Object { ($_['Uri'] -split '/')[-1] }) | Should -Be @('g-azure', 'g-teams', 'g-power', 'g-user') -Because 'Azure, Teams and Power Platform have no read-only permission, for the organisation or for one account'
        $patch = @($writes | Where-Object { $_['Method'] -eq 'PATCH' })
        $patch.Count | Should -Be 1
        $patch[0]['Uri'] | Should -Match '/oauth2PermissionGrants/g-graph$'
        $kept = @($patch[0]['Body']['scope'] -split ' ')
        $kept | Should -Not -Contain 'Mail.Send' -Because 'no manifest names it'
        foreach ($scope in $script:GraphReads) { $kept | Should -Contain $scope }
        $kept | Should -Contain 'DeviceLocalCredential.Read.All' -Because 'what the product sharing the app asks for is named by the manifest too, and is kept'
        $kept | Should -Contain 'email' -Because 'a sign-in basic carries no access to data'
        @($writes | Where-Object { $_['Method'] -notin 'DELETE', 'PATCH' }).Count | Should -Be 0 -Because 'the script only removes; it never grants'
        @($writes | Where-Object { $_['Uri'] -match 'g-pbi' }).Count | Should -Be 0 -Because 'Tenant.Read.All is read-only by name and stays'
        $out | Should -Match 'Removed from Windows Azure Service Management API, granted for the organisation: user_impersonation'
        $out | Should -Match 'Removed from Windows Azure Service Management API, granted for one account \(object id user-1\): user_impersonation'
        $out | Should -Match 'Removed from Microsoft Graph, granted for the organisation: Mail\.Send'
        $out | Should -Match 'Power BI Service: Tenant\.Read\.All'
        $out | Should -Match "Clean: in tenant 11111111-1111-1111-1111-111111111111, TenantKeep holds only what app\.json names \(5 permission\(s\) removed\)\."
        @((& $script:ReadState)['grants'] | ForEach-Object { $_['id'] }) | Should -Be @('g-graph', 'g-pbi')
    }

    It 'finds nothing to do on a second run' {
        $null = & $script:Script -TenantId $script:Tid -AppJsonPath $script:AppJson 6>&1
        Remove-Item -LiteralPath $env:TKP_GRANT_LOG
        $out = (& $script:Script -TenantId $script:Tid -AppJsonPath $script:AppJson 6>&1) -join "`n"
        @(& $script:Writes).Count | Should -Be 0
        $out | Should -Match 'Clean: in tenant .+ TenantKeep holds only what app\.json names\.$'
    }

    It 'changes nothing under -WhatIf and says the tenant is not clean yet' {
        $out = (& $script:Script -TenantId $script:Tid -AppJsonPath $script:AppJson -WhatIf 6>&1) -join "`n"
        @(& $script:Writes).Count | Should -Be 0
        @((& $script:ReadState)['grants']).Count | Should -Be 6
        $out | Should -Match 'Not clean yet: 5 permission\(s\) the manifest does not name are still granted\. Run again without -WhatIf'
        $out | Should -Not -Match 'Clean: in tenant'
    }

    It 'says when the registration itself still lists an API the manifest does not, where the registration lives in this tenant' {
        & $script:Change { param($state) $state['registration'] = @(@{ id = 'obj-1'; requiredResourceAccess = @(@{ resourceAppId = '00000003-0000-0000-c000-000000000000' }, @{ resourceAppId = '797f4846-ba00-4fd7-ba43-dac1f8f63013' }) }) }
        $out = (& $script:Script -TenantId $script:Tid -AppJsonPath $script:AppJson -WarningVariable warnings -WarningAction SilentlyContinue 6>&1) -join "`n"
        @($warnings | Where-Object { "$_" -match 'still lists 1 API\(s\) app\.json does not name \(797f4846-ba00-4fd7-ba43-dac1f8f63013\)\. Run deploy/setup/New-PostureClientApp\.ps1' }).Count | Should -Be 1
        $out | Should -Match 'The grants in this tenant are clean \(5 permission\(s\) removed\); the registration is not yet\.'
        $out | Should -Not -Match 'Clean: in tenant'
    }

    It 'refuses a session in another tenant or without the permission to remove a grant, and does nothing where the app is not' {
        { & $script:Script -TenantId '22222222-2222-2222-2222-222222222222' -AppJsonPath $script:AppJson } | Should -Throw '*only runs in 22222222*'
        & $script:Change { param($state) $state['scopes'] = @('Application.Read.All') }
        { & $script:Script -TenantId $script:Tid -AppJsonPath $script:AppJson } | Should -Throw '*needs DelegatedPermissionGrant.ReadWrite.All*'
        & $script:Change { param($state) $state['scopes'] = @('DelegatedPermissionGrant.ReadWrite.All') }
        { & $script:Script -TenantId $script:Tid -AppJsonPath $script:AppJson } | Should -Throw '*needs Application.Read.All*'
        @(& $script:ReadRequests).Count | Should -Be 0 -Because 'the refusals come before any request'
        # The session the registration script asks for reads applications too, and is enough here.
        & $script:Change { param($state) $state['scopes'] = @('DelegatedPermissionGrant.ReadWrite.All', 'Application.ReadWrite.All'); $state['hasApp'] = $false }
        $out = (& $script:Script -TenantId $script:Tid -AppJsonPath $script:AppJson 6>&1) -join "`n"
        $out | Should -Match 'is not in this tenant: there is nothing to remove'
        @(& $script:Writes).Count | Should -Be 0
    }
}
