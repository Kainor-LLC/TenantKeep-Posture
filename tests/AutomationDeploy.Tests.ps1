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

Describe 'deploy.ps1 package imports' {
    BeforeAll {
        # Runs the script's own wait-and-retry block (step 6) against a fake az: no Azure, no sleep.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..' 'deploy' 'automation' 'deploy.ps1'), [ref]$null, [ref]$null)
        $script:WaitBlock = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -eq '$imports.Count -gt 0' }, $true).Extent.Text
        $script:SendBlock = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$sendImport' }, $true).Extent.Text
    }
    It 'waits for every import, sends a failed one again, and reports one still running' {
        $result = & {
            # The variables the block reads from deploy.ps1's scope.
            foreach ($pair in @(@('aaPath', '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Automation/automationAccounts/aa'), @('runtimeEnv', 'tenantkeep-ps76'), @('apiVersion', 'v'), @('ImportWaitMinutes', 1))) { Set-Variable -Name $pair[0] -Value $pair[1] }
            $script:puts = [System.Collections.Generic.List[string]]::new(); $script:gets = @{}
            Mock Start-Sleep { }
            Mock Write-Host { }
            function Invoke-Az {
                $url = $args[$args.IndexOf('--url') + 1]; $name = ($url -split '/packages/')[1] -replace '\?.*$'
                if ($args[2] -eq 'put') { $script:puts.Add($name); return }
                $script:gets[$name] = 1 + [int]$script:gets[$name]
                $state = switch ($name) {
                    'MicrosoftTeams' { if ($script:puts.Where({ $_ -eq 'MicrosoftTeams' }).Count -lt 1) { 'Failed' } else { 'Succeeded' } }
                    'Microsoft.Graph.Authentication' { 'Creating' }
                    default { 'Succeeded' }
                }
                @{ properties = @{ provisioningState = $state; error = @{ message = "An internal error occurred.`r`n   at Somewhere" } } } | ConvertTo-Json -Depth 4
            }
            . ([scriptblock]::Create($script:SendBlock))
            $imports = [System.Collections.Generic.List[object]]::new()
            foreach ($n in 'TenantKeep.Posture', 'Microsoft.Graph.Authentication', 'MicrosoftTeams') { $imports.Add([pscustomobject]@{ Name = $n; Version = '1'; Uri = "https://example/$n"; State = 'Importing'; Attempts = 1; Error = $null }) }
            $script:start = Get-Date
            # The clock passes the deadline once Graph has been asked about five times.
            Mock Get-Date { if ($script:gets['Microsoft.Graph.Authentication'] -ge 5) { $script:start.AddMinutes(5) } else { $script:start } }
            . ([scriptblock]::Create($script:WaitBlock))
            [pscustomobject]@{ Imports = $imports; Puts = @($script:puts) }
        }
        ($result.Imports | Where-Object Name -EQ 'TenantKeep.Posture').State | Should -Be 'Succeeded'
        ($result.Imports | Where-Object Name -EQ 'MicrosoftTeams').State | Should -Be 'Succeeded'
        ($result.Imports | Where-Object Name -EQ 'MicrosoftTeams').Attempts | Should -Be 2
        ($result.Imports | Where-Object Name -EQ 'Microsoft.Graph.Authentication').State | Should -Be 'Still importing'
        @($result.Puts | Where-Object { $_ -eq 'MicrosoftTeams' }).Count | Should -Be 1
    }
    It 'gives up on an import after two retries and stops the script with an error' {
        $text = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'deploy' 'automation' 'deploy.ps1')
        $text | Should -Match '\$p\.Attempts -lt 3'
        $text | Should -Match 'throw "Package import not finished'
        $text | Should -Not -Match 'Write-Host .*\$sas'
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
            $md | Should -Match '## Conditional Access \(27\)'
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
        $collection = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'Public' 'Invoke-PostureCollection.ps1')
        $warned = [regex]::Matches($collection, "'([A-Za-z]+\.[A-Za-z.]+)'\s+= '") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
        $warned.Count | Should -BeGreaterThan 15
        foreach ($scope in $warned) { $grant | Should -Match ([regex]::Escape("'$scope'")) -Because "$scope is a collector scope" }
        foreach ($needle in 'Exchange.ManageAsApp', 'application_access', 'f2ef992c-3afb-46b9-b7cf-a126ee74c451') { $grant | Should -Match ([regex]::Escape($needle)) }
        $warned | Should -Contain 'SharePointTenantSettings.Read.All' -Because 'the scheduled run reads the SharePoint tenant settings through Graph'
        # Graph application roles nothing reads with: site content and usage reports.
        foreach ($unused in 'Sites.Read.All', 'Reports.Read.All') { $grant | Should -Not -Match ([regex]::Escape("'$unused'")) -Because "no collector uses $unused" }
    }

    It 'with includePosture the template adds the Purview certificate vault with Secrets User for the identity, and the runbook signs in to Purview with the certificate from it' {
        $src = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'deploy' 'automation' 'main.bicep')
        foreach ($needle in "resource purviewVault 'Microsoft.KeyVault/vaults", '4633458b-17de-408a-b874-0445c86b69e6', 'enableRbacAuthorization: true', 'output purviewVaultName') { $src | Should -Match ([regex]::Escape($needle)) }
        $rb = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'deploy' 'schedules' 'posture-runbook.ps1')
        $rb | Should -Match 'Connect-IPPSSession -Certificate \$purviewCertificate -AppId \$purviewAppId'
        $rb | Should -Match 'EphemeralKeySet' -Because 'the certificate stays in memory'
        $rb | Should -Not -Match 'Export-PfxCertificate|Set-Content.*pfx|\.pfx' -Because 'the certificate is never written to disk'
    }

    It 'the Purview setup script parses, supports WhatIf, grants Exchange.ManageAsApp and Global Reader only, and references the certificate by its vault URL' {
        $path = Join-Path $PSScriptRoot '..' 'deploy' 'setup' 'New-PosturePurviewApp.ps1'
        $tokens = $null; $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null
        @($errors).Count | Should -Be 0
        $src = Get-Content -Raw $path
        $src | Should -Match 'SupportsShouldProcess'
        $src | Should -Match 'Exchange\.ManageAsApp'
        $src | Should -Match 'f2ef992c-3afb-46b9-b7cf-a126ee74c451' -Because 'Global Reader is the role, not Compliance Administrator'
        $src | Should -Not -Match 'Compliance Administrator'' *\)' -Because 'no write role is assigned'
        $src | Should -Match 'vault\.azure\.net/secrets/'
        $src | Should -Not -Match 'passwordCredential|addPassword|--password' -Because 'no client secret, ever'
    }

    It 'the grant script refuses without the admin scopes' {
        Mock Get-MgContext { [pscustomobject]@{ Scopes = @('Policy.Read.All') } }
        { & (Join-Path $PSScriptRoot '..' 'deploy' 'automation' 'Grant-ManagedIdentityGraphRole.ps1') -PrincipalId '00000000-0000-0000-0000-000000000001' } | Should -Throw '*missing AppRoleAssignment.ReadWrite.All*'
    }
}

Describe 'posture-runbook.ps1 carries on in a run an earlier job began' {
    BeforeAll {
        # The runbook's own blocks, taken from its source and run against a fake container: no Azure.
        $script:RunbookPath = Join-Path $PSScriptRoot '..' 'deploy' 'schedules' 'posture-runbook.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:RunbookPath, [ref]$null, [ref]$null)
        $block = { param([string] $Name) $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq $Name }.GetNewClosure(), $true).Right.Extent.Text }
        $script:FindUnfinished = [scriptblock]::Create("& { $(& $block '$findUnfinished') }").Invoke()[0]
        $script:UploadChangedText = & $block '$uploadChanged'
        $script:Source = Get-Content -Raw $script:RunbookPath
        $script:Now = [datetime]::new(2026, 11, 21, 15, 0, 0)
    }

    It 'picks the newest run when it has a journal, no report, and began less than a day ago' {
        & $script:FindUnfinished @('20261101-0300/report.html', '20261101-0300/journal.jsonl', '20261121-0300/journal.jsonl', '20261121-0300/06-users.json') $script:Now | Should -Be '20261121-0300'
    }

    It 'starts a new run when <Why>' -ForEach @(
        @{ Why = 'the newest run has its report'; Blobs = @('20261121-0300/journal.jsonl', '20261121-0300/report.html') }
        @{ Why = 'the newest run began more than a day ago'; Blobs = @('20261120-0300/journal.jsonl') }
        @{ Why = 'the newest run has no journal (made before the journal, or by hand)'; Blobs = @('20261121-0300/06-users.json') }
        @{ Why = 'an older run is unfinished and a newer one is done'; Blobs = @('20261121-0100/journal.jsonl', '20261121-0300/journal.jsonl', '20261121-0300/report.html') }
        @{ Why = 'the newest run is dated after now'; Blobs = @('20261122-0300/journal.jsonl') }
        @{ Why = 'the container is empty'; Blobs = @() }
        @{ Why = 'nothing in the container is a run'; Blobs = @('notes/journal.jsonl', 'readme.txt') }
    ) {
        & $script:FindUnfinished ([string[]]$Blobs) $script:Now | Should -BeNullOrEmpty
    }

    It 'sends a file once, again only when it has changed, with its folder in the name, and never a file still being written' {
        $run = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-runbook-$([guid]::NewGuid().ToString('n'))" '20261121-0300'
        New-Item -ItemType Directory -Path (Join-Path $run 'affected') -Force | Out-Null
        try {
            foreach ($n in '06-users.json', '06-users.csv', 'journal.jsonl', '07-groups.json.part', 'cursor-07-groups.json', '.tenantkeep.lock', 'affected/ID-012.csv') { Set-Content -LiteralPath (Join-Path $run $n) -Value 'x' }
            $outside = Join-Path (Split-Path $run -Parent) 'profile.json'; Set-Content -LiteralPath $outside -Value '{}'
            # The variables the block reads from the runbook's scope (Set-Variable: nothing in this file reads them by name).
            $sent = [System.Collections.Generic.List[string]]::new()
            Set-Variable -Name uploaded -Value @{}
            Set-Variable -Name postureContainer -Value 'posture'
            Set-Variable -Name blobPut -Value { param([string] $Container, [string] $Name, [string] $Path) $sent.Add("$Container/$Name") }
            $uploadChanged = [scriptblock]::Create($script:UploadChangedText.Trim().TrimStart('{').TrimEnd('}'))
            $all = @(Get-ChildItem -LiteralPath $run -File -Recurse -Force | ForEach-Object { $_.FullName }) + @($outside, (Join-Path $run 'not-there.json'))
            & $uploadChanged $run $all
            @($sent | Sort-Object) | Should -Be @('posture/20261121-0300/06-users.csv', 'posture/20261121-0300/06-users.json', 'posture/20261121-0300/affected/ID-012.csv', 'posture/20261121-0300/journal.jsonl')
            $sent.Clear()
            & $uploadChanged $run $all
            $sent.Count | Should -Be 0 -Because 'nothing changed'
            Add-Content -LiteralPath (Join-Path $run 'journal.jsonl') -Value 'another line'
            & $uploadChanged $run $all
            @($sent) | Should -Be @('posture/20261121-0300/journal.jsonl') -Because 'the journal grew and the evidence did not'
        }
        finally { Remove-Item -LiteralPath (Split-Path $run -Parent) -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'copies the run to the container as it goes, continues in it, and uploads the subfolders' {
        $script:Source | Should -Match 'StepCompleted = \$onStep'
        $script:Source | Should -Match '-StepCompleted \$onStep -SkipFinished:\(\[bool\]\$continue\)'
        $script:Source | Should -Match '\$collectParams\.OutputFolder = \$folder; \$collectParams\.SkipFinished = \$true'
        $script:Source | Should -Match 'Get-ChildItem -Path \$folder -File -Recurse' -Because 'the report points to affected/<check>.csv'
        $script:Source | Should -Not -Match 'Remove-Item[^\n]*\$postureContainer' -Because 'a run in the container is only ever pruned by the keep-runs rule'
    }

    It 'sends the vault token only to an Azure Key Vault secret address' {
        $pattern = [regex]::Match($script:Source, "\`$purviewCert -notmatch '([^']+)'").Groups[1].Value
        $pattern | Should -Not -BeNullOrEmpty
        'https://kv-contoso-posture.vault.azure.net/secrets/purview-cert' | Should -Match $pattern
        'https://kv-contoso-posture.vault.azure.net/secrets/purview-cert/0123456789abcdef0123456789abcdef' | Should -Match $pattern
        foreach ($bad in 'https://attacker.example/secrets/x', 'https://kv.vault.azure.net.attacker.example/secrets/x', 'http://kv-contoso.vault.azure.net/secrets/x', 'https://kv-contoso.vault.azure.net/keys/x', 'https://kv-contoso.vault.azure.net/secrets/x?redirect=https://attacker.example', 'https://kv-contoso.vault.azure.net@attacker.example/secrets/x') {
            $bad | Should -Not -Match $pattern -Because "$bad is not a Key Vault secret"
        }
        # The check comes before the token is asked for.
        $script:Source.IndexOf('$purviewCert -notmatch') | Should -BeLessThan $script:Source.IndexOf("Get-AzAccessToken -ResourceUrl 'https://vault.azure.net'")
    }

    It 'attaches the report only up to 2 MB, and says where it is otherwise' {
        $script:Source | Should -Match '\(Get-Item -LiteralPath \$reportFile\)\.Length -le 2MB'
        $script:Source | Should -Match 'The report is too large to attach'
    }
}

Describe 'SharePoint in the scheduled run' {
    BeforeAll {
        $script:GrantPath = Join-Path $PSScriptRoot '..' 'deploy' 'automation' 'Grant-ManagedIdentityGraphRole.ps1'
        # The grant script against a fake Graph: every request is noted, nothing leaves the test.
        $script:RunGrant = {
            param([hashtable] $With)
            # A plain variable, not $script: one: the mock runs inside the grant script, whose script scope is its own.
            $graphSent = [System.Collections.Generic.List[object]]::new()
            Mock Get-MgContext { [pscustomobject]@{ Scopes = @('AppRoleAssignment.ReadWrite.All', 'Application.Read.All', 'RoleManagement.ReadWrite.Directory') } }
            Mock Write-Host { }
            Mock Invoke-MgGraphRequest {
                $graphSent.Add([pscustomobject]@{ Method = [string]$Method; Uri = [string]$Uri; Body = $Body })
                if ($Method -ne 'GET') { return @{} }
                if ($Uri -match 'appRoleAssignments$') { return @{ value = @() } }
                if ($Uri -match "servicePrincipals\?\`$filter=appId eq '([^']+)'") {
                    $app = $Matches[1]
                    # Every resource exposes every role asked of it, named by the role, so a grant can be read back.
                    $names = 'Policy.Read.All', 'Directory.Read.All', 'Group.Read.All', 'Mail.Send', 'User.Read.All', 'OnPremDirectorySynchronization.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All', 'RoleManagement.Read.Directory', 'IdentityRiskyUser.Read.All', 'IdentityRiskEvent.Read.All', 'DeviceManagementManagedDevices.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementServiceConfig.Read.All', 'DeviceManagementApps.Read.All', 'BitLockerKey.ReadBasic.All', 'AttackSimulation.Read.All', 'AccessReview.Read.All', 'EntitlementManagement.Read.All', 'LifecycleWorkflows.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'AdministrativeUnit.Read.All', 'NetworkAccess.Read.All', 'BackupRestore-Configuration.Read.All', 'ThreatHunting.Read.All', 'SecurityIncident.Read.All', 'SecurityEvents.Read.All', 'Organization.Read.All', 'Application.Read.All', 'SharePointTenantSettings.Read.All', 'DeviceManagementRBAC.Read.All', 'SecurityIdentitiesHealth.Read.All', 'ServiceHealth.Read.All', 'ServiceMessage.Read.All', 'Domain-InternalFederation.Read.All', 'Exchange.ManageAsApp', 'Sites.FullControl.All', 'application_access'
                    return @{ value = @(@{ id = "sp-$app"; appRoles = @($names | ForEach-Object { @{ id = "role:$_"; value = $_; allowedMemberTypes = @('Application') } }) }) }
                }
                if ($Uri -match 'roleDefinitions') { return @{ value = @(@{ id = 'def-global-reader'; displayName = 'Global Reader' }) } }
                if ($Uri -match 'roleAssignments\?') { return @{ value = @() } }
                throw "unexpected request $Uri"
            }
            $null = & $script:GrantPath -PrincipalId '00000000-0000-0000-0000-000000000001' @With -WarningVariable w -WarningAction SilentlyContinue
            $script:GrantWarnings = @($w)
            @($graphSent | Where-Object { $_.Method -eq 'POST' -and $_.Uri -match 'appRoleAssignments$' } | ForEach-Object { "$($_.Body.resourceId) $($_.Body.appRoleId -replace '^role:', '')" })
        }
    }

    It 'grants the Graph read of the tenant settings with -IncludePosture, and no SharePoint role at all' {
        $granted = & $script:RunGrant @{ IncludePosture = $true }
        $granted | Should -Contain 'sp-00000003-0000-0000-c000-000000000000 SharePointTenantSettings.Read.All'
        @($granted | Where-Object { $_ -match 'Sites\.' }) | Should -BeNullOrEmpty -Because 'full control of every site is not something a scheduled read gets by default'
        @($granted | Where-Object { $_ -match '^sp-00000003-0000-0ff1-ce00-000000000000 ' }) | Should -BeNullOrEmpty -Because 'nothing is granted on SharePoint Online itself'
        $granted | Should -Contain 'sp-00000002-0000-0ff1-ce00-000000000000 Exchange.ManageAsApp'
        $granted | Should -Contain 'sp-48ac35b8-9aa8-4d74-927d-1f4a14a0b239 application_access'
        @($script:GrantWarnings | Where-Object { [string]$_ -match 'FullControl' }) | Should -BeNullOrEmpty
        foreach ($role in 'DeviceManagementRBAC.Read.All', 'SecurityIdentitiesHealth.Read.All', 'ServiceHealth.Read.All', 'ServiceMessage.Read.All', 'Domain-InternalFederation.Read.All') { $granted | Should -Contain "sp-00000003-0000-0000-c000-000000000000 $role" }
        @($granted | Where-Object { $_ -match '^sp-00000003-0000-0000-c000-000000000000 ' -and ($_ -notmatch '\.Read' -or $_ -match 'ReadWrite') }) | Should -BeNullOrEmpty -Because 'every role the scheduled run holds on Graph is a read'
    }

    It 'grants Sites.FullControl.All only when asked, and says what it is' {
        $granted = & $script:RunGrant @{ IncludePosture = $true; IncludeSharePointAdminRead = $true }
        $granted | Should -Contain 'sp-00000003-0000-0ff1-ce00-000000000000 Sites.FullControl.All'
        @($script:GrantWarnings | Where-Object { [string]$_ -match 'standing permission to read and change every file in every site' }).Count | Should -Be 1
    }

    It 'refuses the SharePoint switch on its own' {
        Mock Get-MgContext { [pscustomobject]@{ Scopes = @('AppRoleAssignment.ReadWrite.All', 'Application.Read.All') } }
        Mock Invoke-MgGraphRequest { throw 'nothing should be sent' }
        { & $script:GrantPath -PrincipalId '00000000-0000-0000-0000-000000000001' -IncludeSharePointAdminRead } | Should -Throw '*goes with -IncludePosture*'
    }

    It 'keeps the Teams read when the SharePoint admin read is refused or not set up' {
        $rb = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'deploy' 'schedules' 'posture-runbook.ps1')
        $rb | Should -Match "& \`$phase 'SharePoint' \{ Connect-PnPOnline -Url \`$spoAdmin -ManagedIdentity \} @\('SharePoint'\)"
        $rb | Should -Match "& \`$phase 'Teams' \{ Connect-MicrosoftTeams -Identity \| Out-Null \} @\('Teams'\)"
        $rb | Should -Not -Match "@\('SharePoint', 'Teams'\)" -Because 'one sign-in that fails must not cost the other read'
    }

    It 'tells an identity without the Graph settings role how to get it' {
        $src = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'Private' 'Invoke-PostureEntraCollection.ps1')
        $src | Should -Match 'Run deploy/automation/Grant-ManagedIdentityGraphRole\.ps1 -IncludePosture again'
    }
}

Describe 'The posture runbook on a Hybrid Runbook Worker' {
    BeforeAll {
        $script:DeployPath = Join-Path $PSScriptRoot '..' 'deploy' 'automation' 'deploy.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:DeployPath, [ref]$null, [ref]$null)
        # The script's own block that links the posture schedule, run against a fake az.
        $script:LinkBlock = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -eq '$IncludePosture' -and $n.Extent.Text -match 'hybridRunbookWorkerGroups' }, $true).Extent.Text
        $script:Link = {
            param([string] $HybridWorkerGroup, [object[]] $Existing = @(), [switch] $GroupMissing)
            $calls = [System.Collections.Generic.List[string]]::new()
            function Invoke-Az {
                $line = $args -join ' '
                $calls.Add($line)
                if ($line -match 'hybridRunbookWorkerGroups' -and $GroupMissing) { throw 'az rest failed: ResourceNotFound' }
            }
            Mock Write-Host { }
            # The variables the block reads from deploy.ps1's scope.
            foreach ($pair in @(
                    @('IncludePosture', $true), @('postureRunbook', 'Invoke-PostureCycle'), @('automationAccount', 'aa-tenantkeep-dev'),
                    @('aaPath', '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Automation/automationAccounts/aa-tenantkeep-dev'),
                    @('o', [pscustomobject]@{ postureScheduleName = [pscustomobject]@{ value = 'posture-monthly' } })
                )) { Set-Variable -Name $pair[0] -Value $pair[1] }
            Set-Variable -Name links -Value @($Existing)
            . ([scriptblock]::Create($script:LinkBlock)) 3>$null
            , @($calls)
        }
        $script:Linked = { param([string] $RunOn) [pscustomobject]@{ id = '/x/jobSchedules/11111111-1111-1111-1111-111111111111'; properties = [pscustomobject]@{ runbook = [pscustomobject]@{ name = 'Invoke-PostureCycle' }; schedule = [pscustomobject]@{ name = 'posture-monthly' }; runOn = $RunOn } } }
    }

    It 'links the schedule to the sandbox when no worker group is named' {
        $calls = & $script:Link ''
        @($calls | Where-Object { $_ -match '--method put' }).Count | Should -Be 1
        ($calls -join "`n") | Should -Not -Match 'runOn'
        ($calls -join "`n") | Should -Not -Match 'hybridRunbookWorkerGroups'
    }

    It 'links the schedule to the worker group, after checking the group is there' {
        $calls = & $script:Link 'posture-workers'
        $calls[0] | Should -Match '--method get .*hybridRunbookWorkerGroups/posture-workers'
        @($calls | Where-Object { $_ -match '--method put' -and $_ -match '"runOn":"posture-workers"' }).Count | Should -Be 1
    }

    It 'moves a schedule from the sandbox to the worker group, and back' {
        $calls = & $script:Link 'posture-workers' @(& $script:Linked '')
        @($calls | Where-Object { $_ -match '--method delete .*jobSchedules/11111111-1111-1111-1111-111111111111' }).Count | Should -Be 1
        @($calls | Where-Object { $_ -match '--method put' -and $_ -match '"runOn":"posture-workers"' }).Count | Should -Be 1
        $back = & $script:Link '' @(& $script:Linked 'posture-workers')
        @($back | Where-Object { $_ -match '--method delete' }).Count | Should -Be 1
        @($back | Where-Object { $_ -match '--method put' -and $_ -notmatch 'runOn' }).Count | Should -Be 1
    }

    It 'leaves a schedule alone that already runs where it should, and one whose worker group is not there' {
        $same = & $script:Link 'posture-workers' @(& $script:Linked 'posture-workers')
        @($same | Where-Object { $_ -match '--method (put|delete)' }) | Should -BeNullOrEmpty
        $missing = & $script:Link 'posture-workers' @(& $script:Linked '') -GroupMissing
        @($missing | Where-Object { $_ -match '--method (put|delete)' }) | Should -BeNullOrEmpty -Because 'a schedule pointed at a group with no worker would start nothing'
    }

    It 'gives the worker identity the storage and vault roles in the template, and only when one is named' {
        $bicep = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'deploy' 'automation' 'main.bicep')
        $bicep | Should -Match "param workerPrincipalId string = ''"
        $bicep | Should -Match "resource workerBlobRole 'Microsoft\.Authorization/roleAssignments@[0-9-]+' = if \(!empty\(workerPrincipalId\)\)"
        $bicep | Should -Match "resource purviewVaultWorker 'Microsoft\.Authorization/roleAssignments@[0-9-]+' = if \(includePosture && !empty\(workerPrincipalId\)\)"
        $deploy = Get-Content -Raw $script:DeployPath
        $deploy | Should -Match '"workerPrincipalId=\$HybridWorkerPrincipalId"'
        $deploy | Should -Match '--run-on \$HybridWorkerGroup'
    }
}

Describe 'az warnings stay out of what the scripts parse' {
    BeforeAll {
        # A stand-in az that writes a notice to the error stream before its JSON, as the real one does when a new Bicep
        # release is out. A deployment stopped on exactly that: the notice reached ConvertFrom-Json. No Azure here.
        $script:FakeAz = Join-Path $TestDrive 'fake-az'
        New-Item -ItemType Directory -Path $script:FakeAz -Force | Out-Null
        if ($IsWindows) {
            $lines = @(
                '@echo off'
                '>&2 echo WARNING: A new Bicep release is available: v0.49.2. Upgrade now by running "az bicep upgrade".'
                'if "%1"=="fail" goto fail'
                'if "%1"=="keyvault" goto sign'
                'echo {"properties":{"outputs":{"runbookName":{"value":"rb"}}}}'
                'exit /b 0'
                ':sign'
                'echo {"signature":"AAEC"}'
                'exit /b 0'
                ':fail'
                '>&2 echo ERROR: the deployment failed'
                'exit /b 3'
            )
            [System.IO.File]::WriteAllText((Join-Path $script:FakeAz 'az.cmd'), ($lines -join "`r`n") + "`r`n")
        }
        else {
            $lines = @(
                '#!/bin/sh'
                'echo ''WARNING: A new Bicep release is available: v0.49.2. Upgrade now by running "az bicep upgrade".'' >&2'
                'case "$1" in'
                '  fail) echo ''ERROR: the deployment failed'' >&2; exit 3 ;;'
                '  keyvault) echo ''{"signature":"AAEC"}'' ;;'
                '  *) echo ''{"properties":{"outputs":{"runbookName":{"value":"rb"}}}}'' ;;'
                'esac'
            )
            $file = Join-Path $script:FakeAz 'az'
            [System.IO.File]::WriteAllText($file, ($lines -join "`n") + "`n")
            & chmod +x $file
        }
        $script:PathBefore = $env:PATH
        $env:PATH = $script:FakeAz + [System.IO.Path]::PathSeparator + $env:PATH
        $script:WrapperOf = {
            param([string] $RelativePath)
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..' $RelativePath), [ref]$null, [ref]$null)
            $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-Az' }, $true).Extent.Text
        }
    }
    AfterAll { $env:PATH = $script:PathBefore }

    It 'the stand-in is the az these tests call' {
        (Get-Command az -CommandType Application | Select-Object -First 1).Source | Should -BeLike (Join-Path $script:FakeAz '*')
    }

    It 'returns the output alone, shows the notice and names it when az fails: <Script>' -ForEach @(
        @{ Script = 'deploy/automation/deploy.ps1' }
        @{ Script = 'deploy/setup/New-PosturePurviewApp.ps1' }
    ) {
        Mock Write-Host { }
        . ([scriptblock]::Create((& $script:WrapperOf $Script)))
        $doc = Invoke-Az deployment group create -g rg -o json | ConvertFrom-Json
        $doc.properties.outputs.runbookName.value | Should -Be 'rb'
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match 'A new Bicep release is available' }
        { Invoke-Az fail -o json } | Should -Throw '*ERROR: the deployment failed*'
    }

    It 'the release setup script reads az the same way' {
        Mock Write-Host { }
        . ([scriptblock]::Create((& $script:WrapperOf 'deploy/release/New-PostureSigningIdentity.ps1')))
        $doc = Invoke-Az -Arguments @('deployment', 'group', 'create')
        $doc['properties']['outputs']['runbookName']['value'] | Should -Be 'rb'
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match 'A new Bicep release is available' }
        { Invoke-Az -Arguments @('fail', 'now') } | Should -Throw '*ERROR: the deployment failed*'
    }

    It 'a licence signed through the vault takes the signature and not the notice' {
        $out = Join-Path $TestDrive 'vault.lic'
        $null = & (Join-Path $PSScriptRoot '..' 'deploy' 'licensing' 'New-PostureLicense.ps1') -TenantId 'aaaaaaaa-1111-2222-3333-444444444444' -Tier full -Customer 'Contoso Ltd' -KeyId test-key -VaultName v -KeyName k -OutputPath $out
        (Get-Content -Raw -LiteralPath $out | ConvertFrom-Json).signature | Should -Be 'AAEC'
    }

    It 'no script hands az output to a JSON parser with the error stream still in it' {
        # The two places that sign through the vault take the output apart inline; every other az call goes through a wrapper above.
        foreach ($relative in 'build.ps1', 'deploy/licensing/New-PostureLicense.ps1') {
            $text = Get-Content -Raw (Join-Path $PSScriptRoot '..' $relative)
            $text | Should -Match '\$all = & az keyvault key sign' -Because "$relative keeps what az wrote apart from its notices"
            $text | Should -Match '\$raw = @\(\$all \| Where-Object \{ \$_ -isnot \[System\.Management\.Automation\.ErrorRecord\] \}\)'
            $text | Should -Not -Match '\$raw = & az[^\r\n]*2>&1'
        }
    }
}

Describe 'What the deployment tells the admin to run next' {
    It 'names every scope the grant script will ask for, the Global Reader one with -IncludePosture' {
        $deploy = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'deploy' 'automation' 'deploy.ps1')
        $deploy | Should -Match ([regex]::Escape('-Scopes AppRoleAssignment.ReadWrite.All, Application.Read.All$(if ($IncludePosture) { '', RoleManagement.ReadWrite.Directory'' })')) -Because 'the grant script refuses -IncludePosture without it, and the printed line is what a first deployment follows'
        $grant = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'deploy' 'automation' 'Grant-ManagedIdentityGraphRole.ps1')
        $grant | Should -Match ([regex]::Escape("@('AppRoleAssignment.ReadWrite.All', 'Application.Read.All') + @(`$(if (`$IncludePosture) { 'RoleManagement.ReadWrite.Directory' }))"))
    }

    It 'says a new role can take a day to reach a job, as the scheduling guide does' {
        (Get-Content -Raw (Join-Path $PSScriptRoot '..' 'deploy' 'automation' 'Grant-ManagedIdentityGraphRole.ps1')) | Should -Match 'for up to a day'
        (Get-Content -Raw (Join-Path $PSScriptRoot '..' 'docs' 'scheduling.md')) | Should -Match 'after up to a day'
    }
}

Describe 'Power BI in the scheduled run' {
    BeforeAll {
        $script:Automation = Join-Path $PSScriptRoot '..' 'deploy' 'automation'
        $script:Runbook = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'deploy' 'schedules' 'posture-runbook.ps1')
    }

    It 'is opt-in: a deployment switch sets one variable, and the runbook reads Power BI only where it is true' {
        $bicep = Get-Content -Raw (Join-Path $script:Automation 'main.bicep')
        $bicep | Should -Match 'param includePowerBi bool = false'
        $bicep | Should -Match ([regex]::Escape('{ name: ''TENANTKEEP_POWERBI'', value: includePowerBi ? ''"true"'' : ''""'', encrypted: false }'))
        $deploy = Get-Content -Raw (Join-Path $script:Automation 'deploy.ps1')
        $deploy | Should -Match '\[switch\] \$IncludePowerBI'
        $deploy | Should -Match 'includePowerBi=\$\(\(\$IncludePosture -and \$IncludePowerBI\)'
        $script:Runbook | Should -Match "\`$powerBi = & \`$getVar 'TENANTKEEP_POWERBI'"
        $script:Runbook | Should -Match "if \(\`$powerBi -match '\^\(\?i\)\(true\|1\|yes\)\`$'\) \{ & \`$phase 'PowerBI' \{ \} @\('PowerBI'\) \}"
    }

    It 'never collects Power Platform on a schedule' {
        $script:Runbook | Should -Not -Match "@\('PowerPlatform'\)|-Collector [^\r\n]*PowerPlatform" -Because 'an unattended identity would need full Power Platform administration'
        $script:Runbook | Should -Match 'Power Platform is read only by a signed-in run'
    }

    It 'puts the identity in a security group and grants nothing on Power BI' {
        # A plain variable, not a script one: the mock runs inside the grant script, whose script scope is its own.
        $graphSent = [System.Collections.Generic.List[object]]::new()
        Mock Get-MgContext { [pscustomobject]@{ Scopes = @('AppRoleAssignment.ReadWrite.All', 'Application.Read.All', 'Group.ReadWrite.All') } }
        Mock Write-Host { }
        Mock Invoke-MgGraphRequest {
            $graphSent.Add([pscustomobject]@{ Method = [string]$Method; Uri = [string]$Uri; Body = $Body })
            if ($Method -eq 'POST' -and $Uri -match '/groups$') { return @{ id = 'group-1'; displayName = $Body.displayName } }
            if ($Method -ne 'GET') { return @{} }
            if ($Uri -match 'appRoleAssignments$') { return @{ value = @() } }
            if ($Uri -match "servicePrincipals\?\`$filter=appId eq '([^']+)'") {
                return @{ value = @(@{ id = "sp-$($Matches[1])"; appRoles = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All' | ForEach-Object { @{ id = "role:$_"; value = $_; allowedMemberTypes = @('Application') } }) }) }
            }
            if ($Uri -match '/groups\?') { return @{ value = @() } }
            if ($Uri -match '/groups/group-1/members\?') { return @{ value = @() } }
            throw "unexpected request $Uri"
        }
        $null = & (Join-Path $script:Automation 'Grant-ManagedIdentityGraphRole.ps1') -PrincipalId '00000000-0000-0000-0000-000000000001' -IncludePowerBI -WarningAction SilentlyContinue
        $created = @($graphSent | Where-Object { $_.Method -eq 'POST' -and $_.Uri -match '/groups$' })
        $created.Count | Should -Be 1
        $created[0].Body.displayName | Should -Be 'TenantKeep Posture (Power BI read)'
        $created[0].Body.securityEnabled | Should -BeTrue
        $created[0].Body.mailEnabled | Should -BeFalse
        $added = @($graphSent | Where-Object { $_.Method -eq 'POST' -and $_.Uri -match '/groups/group-1/members/\$ref$' })
        $added.Count | Should -Be 1
        $added[0].Body['@odata.id'] | Should -Be 'https://graph.microsoft.com/v1.0/directoryObjects/00000000-0000-0000-0000-000000000001'
        @($graphSent | Where-Object { $_.Uri -match '00000009-0000-0000-c000-000000000000' }).Count | Should -Be 0 -Because 'the identity must hold no Power BI permission, or the read-only admin API refuses it'
        @($graphSent | Where-Object { $_.Method -eq 'POST' -and $_.Uri -match 'appRoleAssignments$' } | ForEach-Object { [string]$_.Body.appRoleId }) | Should -Be @('role:Policy.Read.All', 'role:Directory.Read.All', 'role:Group.Read.All') -Because 'the switch adds a group membership and no role'
    }

    It 'refuses without the Graph permission that lets it make the group' {
        Mock Get-MgContext { [pscustomobject]@{ Scopes = @('AppRoleAssignment.ReadWrite.All', 'Application.Read.All') } }
        { & (Join-Path $script:Automation 'Grant-ManagedIdentityGraphRole.ps1') -PrincipalId '00000000-0000-0000-0000-000000000001' -IncludePowerBI } | Should -Throw '*missing Group.ReadWrite.All*'
    }
}
