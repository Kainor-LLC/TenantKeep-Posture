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

    It 'the Catalog task writes the public catalog page without pass logic, remediation or framework mappings' {
        $out = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-catalog-$([guid]::NewGuid().ToString('n'))"
        try {
            & pwsh -NoProfile -File (Join-Path $PSScriptRoot '..' 'build.ps1') -Task Catalog -CatalogPath $out 2>&1 | Out-Null
            $md = Get-Content -Raw (Join-Path $out 'catalog.md')
            $md | Should -Match '## Conditional Access \(15\)'
            $md | Should -Match '\| CA-001 \|'
            $md | Should -Not -Match 'facts\.[a-zA-Z]' -Because 'no pass logic on the public page'
            $md | Should -Not -Match 'nist-csf-2'
            (Get-Content -Raw (Join-Path $out 'catalog.html')) | Should -Match '<h2>Identity and privileged access'
        }
        finally { Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'with includePosture the template adds the posture runbook, monthly schedule, two containers and the variables' {
        $src = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'deploy' 'automation' 'main.bicep')
        foreach ($needle in "param includePosture bool", "name: postureRunbookName", "frequency: 'Month'", "name: postureContainerName", "name: clientContainerName", 'TENANTKEEP_POSTURE_CONTAINER_URL', 'TENANTKEEP_CLIENT_CONTAINER_URL', 'TENANTKEEP_ORGANIZATION', 'TENANTKEEP_SHAREPOINT_ADMIN_URL', 'output postureRunbookName') { $src | Should -Match ([regex]::Escape($needle)) }
    }

    It 'the posture runbook parses, signs in as the identity only, and never calls a tenant write' {
        $path = Join-Path $PSScriptRoot '..' 'deploy' 'schedules' 'posture-runbook.ps1'
        $tokens = $null; $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null
        @($errors).Count | Should -Be 0
        $src = Get-Content -Raw $path
        $src | Should -Match 'Connect-MgGraph -Identity'
        $src | Should -Match 'Connect-ExchangeOnline -ManagedIdentity'
        $src | Should -Match 'Connect-PnPOnline -Url \$spoAdmin -ManagedIdentity'
        $src | Should -Not -Match '-Scopes|-Credential|ClientSecret|CertificateThumbprint' -Because 'the runbook has no secrets and no delegated sign-in'
        $src | Should -Not -Match '(^|[;{|(&\s])(Set|New|Remove|Update)-(Mg|EXO|Pnp|Cs|Az(?!Storage))' -Because 'reads only, storage aside'
        foreach ($cmd in 'Invoke-PostureCollection', 'New-PostureReport', 'Export-PostureFindings') { $src | Should -Match $cmd }
    }

    It 'the grant script lists every Graph role the collection warns about, plus the Exchange, SharePoint and Teams app roles' {
        $grant = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'deploy' 'automation' 'Grant-ManagedIdentityGraphRole.ps1')
        $collection = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Public' 'Invoke-PostureCollection.ps1')
        $warned = [regex]::Matches($collection, "'([A-Za-z]+\.[A-Za-z.]+)'\s+= '") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
        $warned.Count | Should -BeGreaterThan 15
        foreach ($scope in $warned) { $grant | Should -Match ([regex]::Escape("'$scope'")) -Because "$scope is a collector scope" }
        foreach ($needle in 'Exchange.ManageAsApp', 'Sites.FullControl.All', 'application_access', 'f2ef992c-3afb-46b9-b7cf-a126ee74c451') { $grant | Should -Match ([regex]::Escape($needle)) }
    }

    It 'the grant script refuses without the admin scopes' {
        Mock Get-MgContext { [pscustomobject]@{ Scopes = @('Policy.Read.All') } }
        { & (Join-Path $PSScriptRoot '..' 'deploy' 'automation' 'Grant-ManagedIdentityGraphRole.ps1') -PrincipalId '00000000-0000-0000-0000-000000000001' } | Should -Throw '*missing AppRoleAssignment.ReadWrite.All*'
    }
}
