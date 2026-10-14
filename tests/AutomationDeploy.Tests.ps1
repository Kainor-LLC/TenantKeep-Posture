# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeDiscovery {
    $script:HasAz = [bool](Get-Command az -ErrorAction SilentlyContinue)
}

Describe 'deploy/automation/main.bicep' -Skip:(-not $script:HasAz) {
    BeforeAll {
        $bicep = Join-Path $PSScriptRoot '..' 'deploy' 'automation' 'main.bicep'
        $raw = & az bicep build --file $bicep --stdout 2>$null
        $script:Template = ($raw -join "`n") | ConvertFrom-Json
    }

    It 'compiles' {
        $script:Template | Should -Not -BeNullOrEmpty
        $script:Template.resources.Count | Should -BeGreaterOrEqual 9
    }

    It 'declares the account, identity, storage, container, role, variables, schedule, runtime and runbook' {
        $types = @($script:Template.resources | ForEach-Object { $_.type })
        foreach ($t in 'Microsoft.Automation/automationAccounts', 'Microsoft.Storage/storageAccounts', 'Microsoft.Storage/storageAccounts/blobServices/containers',
            'Microsoft.Authorization/roleAssignments', 'Microsoft.Automation/automationAccounts/variables', 'Microsoft.Automation/automationAccounts/schedules',
            'Microsoft.Automation/automationAccounts/runbooks', 'Microsoft.Automation/automationAccounts/runtimeEnvironments') {
            $types | Should -Contain $t
        }
        ($script:Template.resources | Where-Object type -eq 'Microsoft.Automation/automationAccounts').identity.type | Should -Be 'SystemAssigned'
    }

    It 'locks the storage account down: no shared key, no public blobs, TLS 1.2' {
        $st = $script:Template.resources | Where-Object type -eq 'Microsoft.Storage/storageAccounts'
        $st.properties.allowSharedKeyAccess | Should -BeFalse
        $st.properties.allowBlobPublicAccess | Should -BeFalse
        $st.properties.minimumTlsVersion | Should -Be 'TLS1_2'
    }

    It 'disables local auth on the Automation account and marks the webhook variable encrypted' {
        ($script:Template.resources | Where-Object type -eq 'Microsoft.Automation/automationAccounts').properties.disableLocalAuth | Should -BeTrue
        $vars = $script:Template.variables.variables
        ($vars | Where-Object name -eq 'TEAMS_WEBHOOK').encrypted | Should -BeTrue
        ($vars | Where-Object name -eq 'TENANTKEEP_CONTAINER_URL').encrypted | Should -BeFalse
    }

    It 'exposes the outputs deploy.ps1 reads' {
        foreach ($o in 'automationAccountName', 'automationPrincipalId', 'storageAccountName', 'containerUrl', 'runbookName', 'scheduleName', 'runtimeEnvironmentName', 'firstRunUtc') {
            $script:Template.outputs.PSObject.Properties.Name | Should -Contain $o
        }
    }
}

Describe 'deploy scripts' {
    It 'the runbook looks for the cycle script inside the staged module' {
        Get-Content -Raw (Join-Path $PSScriptRoot '..' 'deploy' 'schedules' 'automation-runbook.ps1') | Should -Match "'schedules' 'ca-snapshot-cycle.ps1'"
    }

    It 'the SharePoint app setup script asks for delegated read permissions only, supports WhatIf and prints the manual steps' {
        $path = Join-Path $PSScriptRoot '..' 'deploy' 'setup' 'New-PostureSharePointApp.ps1'
        $src = Get-Content -Raw $path
        $tokens = $null; $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null
        @($errors).Count | Should -Be 0
        $src | Should -Match 'SupportsShouldProcess'
        $src | Should -Match 'AllSites\.FullControl'
        $src | Should -Match 'ReadOnlyPermission'
        $src | Should -Not -Match 'ApplicationPermissions' -Because 'delegated only; application permissions would outlive the signed-in user'
        $src | Should -Match 'GraphDelegatePermissions = \$graphPermissions'
        $src | Should -Match '\$graphPermissions = @\(''User\.Read'', ''Sites\.Read\.All'', ''Group\.Read\.All''\)' -Because 'the Graph permissions the app requests are reads; Application.ReadWrite.All is the admin session scope for updating the registration, not an app permission'
        $src | Should -Match 'adminconsent\?client_id='
        $src | Should -Match 'SharePoint Administrator'
        $src | Should -Match 'sharePointClientId'
        $src | Should -Match 'DelegatedPermissionGrant\.ReadWrite\.All' -Because 'consent is granted through Graph when the admin session allows it; the adminconsent URL fails for a localhost-only public client'
        $src | Should -Match 'oauth2PermissionGrants'
    }

    It 'the grant script refuses without the admin scopes' {
        Mock Get-MgContext { [pscustomobject]@{ Scopes = @('Policy.Read.All') } }
        { & (Join-Path $PSScriptRoot '..' 'deploy' 'automation' 'Grant-ManagedIdentityGraphRole.ps1') -PrincipalId '00000000-0000-0000-0000-000000000001' } | Should -Throw '*missing AppRoleAssignment.ReadWrite.All*'
    }
}
