# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    $script:PnPAvailable = [bool](Get-Module -ListAvailable PnP.PowerShell | Where-Object { $_.Version.Major -ge 3 })
    $script:Script = Join-Path $PSScriptRoot '..' 'deploy' 'setup' 'New-PostureSharePointApp.ps1'
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-spoapp-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $env:TKP_SPOAPP_LOG = Join-Path $script:Root 'requests.jsonl'
    $script:ReadRequests = { @(Get-Content -LiteralPath $env:TKP_SPOAPP_LOG -ErrorAction SilentlyContinue | ForEach-Object { $_ | ConvertFrom-Json -Depth 10 }) }
    # Stubs for the Graph SDK: the script only needs these two commands. Shapes mirror -OutputType HashTable.
    function global:Get-MgContext { [pscustomobject]@{ TenantId = 'tenant-guid'; Account = 'admin@contoso.example'; Scopes = @('Application.ReadWrite.All', 'Application.Read.All', 'DelegatedPermissionGrant.ReadWrite.All') } }
    function global:Invoke-MgGraphRequest {
        param([string] $Method = 'GET', [string] $Uri, $Body, [string] $ContentType, [string] $OutputType)
        Add-Content -LiteralPath $env:TKP_SPOAPP_LOG -Value (ConvertTo-Json -InputObject @{ Method = $Method; Uri = $Uri; Body = $Body } -Depth 10 -Compress)
        $u = [uri]::UnescapeDataString($Uri)
        switch -Regex ($u) {
            "applications\?\`$filter=appId eq 'aaaaaaaa-0000-0000-0000-000000000001'" { return @{ value = @(@{ id = 'obj-1'; requiredResourceAccess = @(@{ resourceAppId = '00000003-0000-0000-c000-000000000000'; resourceAccess = @(@{ id = 'g1'; type = 'Scope' }) }) }) } }
            "servicePrincipals\?\`$filter=appId eq '00000003-0000-0ff1-ce00-000000000000'" { return @{ value = @(@{ id = 'spo-sp'; displayName = 'Office 365 SharePoint Online'; oauth2PermissionScopes = @(@{ id = 'fc'; value = 'AllSites.FullControl' }, @{ id = 'rd'; value = 'AllSites.Read' }) }) } }
            "servicePrincipals\?\`$filter=appId eq '00000003-0000-0000-c000-000000000000'" { return @{ value = @(@{ id = 'graph-sp'; displayName = 'Microsoft Graph'; oauth2PermissionScopes = @() }) } }
            "servicePrincipals\?\`$filter=appId eq 'aaaaaaaa-0000-0000-0000-000000000001'" { if ($env:TKP_SPOAPP_SP -eq 'missing') { return @{ value = @() } } else { return @{ value = @(@{ id = 'app-sp' }) } } }
            'servicePrincipals$' { if ($Method -eq 'POST') { $env:TKP_SPOAPP_SP = 'present'; throw 'POST https://graph.microsoft.com/v1.0/servicePrincipals HTTP/1.1 409 Conflict' } }
            "oauth2PermissionGrants\?\`$filter=clientId eq 'app-sp' and resourceId eq 'spo-sp'" { return @{ value = @(@{ id = 'grant-spo'; consentType = 'AllPrincipals'; scope = 'AllSites.Read' }) } }
            "oauth2PermissionGrants\?\`$filter=clientId eq 'app-sp' and resourceId eq 'graph-sp'" { return @{ value = @(@{ id = 'grant-graph'; consentType = 'AllPrincipals'; scope = 'User.Read Sites.Read.All Group.Read.All' }) } }
            'applications/obj-1$' { return $null }
            'oauth2PermissionGrants/grant-spo$' { return $null }
        }
        throw "Stub has no answer for $Method $u"
    }
}

AfterAll {
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Function:\global:Get-MgContext, Function:\global:Invoke-MgGraphRequest -ErrorAction SilentlyContinue
    Remove-Item Env:TKP_SPOAPP_SP -ErrorAction SilentlyContinue
    Remove-Item Env:TKP_SPOAPP_LOG -ErrorAction SilentlyContinue
}

Describe 'New-PostureSharePointApp.ps1 with an existing registration' {
    It 'adds AllSites.FullControl to the registration, extends the consent grant through Graph, records the id and prints no consent page step' {
        if (-not $script:PnPAvailable) { Set-ItResult -Skipped -Because 'PnP.PowerShell 3.x is not installed on this machine'; return }
        $env:TKP_SPOAPP_SP = 'present'
        $profilePath = Join-Path $script:Root 'profile.json'
        $out = & $script:Script -Tenant contoso.onmicrosoft.com -ClientId 'aaaaaaaa-0000-0000-0000-000000000001' -ProfilePath $profilePath 6>&1
        $text = ($out | Out-String)
        $text | Should -Match 'Added AllSites.FullControl'
        $text | Should -Match 'Admin consent granted for AllSites.Read AllSites.FullControl on Office 365 SharePoint Online'
        $text | Should -Match 'Consent already covers User.Read, Sites.Read.All, Group.Read.All on Microsoft Graph'
        $text | Should -Match 'Granted through Graph; nothing to do'
        (Get-Content -Raw $profilePath | ConvertFrom-Json).sharePointClientId | Should -Be 'aaaaaaaa-0000-0000-0000-000000000001'
        $requests = & $script:ReadRequests
        $patch = @($requests | Where-Object { $_.Method -eq 'PATCH' -and $_.Uri -like '*applications/obj-1' })
        $patch.Count | Should -Be 1
        @($patch[0].Body.requiredResourceAccess | Where-Object { $_.resourceAppId -eq '00000003-0000-0ff1-ce00-000000000000' })[0].resourceAccess.id | Should -Contain 'fc'
        $grantPatch = @($requests | Where-Object { $_.Method -eq 'PATCH' -and $_.Uri -like '*oauth2PermissionGrants/grant-spo' })
        $grantPatch[0].Body.scope | Should -Be 'AllSites.Read AllSites.FullControl'
    }

    It 'treats a 409 on the service principal as present and looks again' {
        if (-not $script:PnPAvailable) { Set-ItResult -Skipped -Because 'PnP.PowerShell 3.x is not installed on this machine'; return }
        Remove-Item -LiteralPath $env:TKP_SPOAPP_LOG -ErrorAction SilentlyContinue
        $env:TKP_SPOAPP_SP = 'missing'
        $text = (& $script:Script -Tenant contoso.onmicrosoft.com -ClientId 'aaaaaaaa-0000-0000-0000-000000000001' 6>&1 | Out-String)
        $text | Should -Match 'Admin consent granted for AllSites.Read AllSites.FullControl'
        @((& $script:ReadRequests) | Where-Object { $_.Method -eq 'POST' -and $_.Uri -like '*servicePrincipals' }).Count | Should -Be 1
    }

    It 'skips the consent under WhatIf when the service principal is not there yet' {
        if (-not $script:PnPAvailable) { Set-ItResult -Skipped -Because 'PnP.PowerShell 3.x is not installed on this machine'; return }
        $env:TKP_SPOAPP_SP = 'missing'
        $text = (& $script:Script -Tenant contoso.onmicrosoft.com -ClientId 'aaaaaaaa-0000-0000-0000-000000000001' -WhatIf 6>&1 | Out-String)
        $text | Should -Match 'consent skipped'
    }
}
