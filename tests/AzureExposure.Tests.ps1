# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Write = { param([string] $Dir, [string] $Name, $Data) New-Item -ItemType Directory -Path $Dir -Force | Out-Null; ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }
    $script:Sub = '0b1c2d3e-0000-4000-8000-000000000001'
    $script:Base = {
        param([string] $Dir)
        & $script:Write $Dir 'az-01-subscriptions' @(@{ SubscriptionId = $script:Sub; Name = 'Production'; State = 'Enabled'; ManagementGroupChain = 'root / prod'; ManagementGroupNames = 'Tenant Root / Production'; AtTenantRoot = $false })
        & $script:Write $Dir 'az-12-open-management-ports' @(@{ Nsg = 'web-nsg'; SubscriptionId = $script:Sub; ResourceGroup = 'rg-web'; Rule = 'allow-rdp'; Ports = '3389' })
        & $script:Write $Dir 'az-13-budgets' @(@{ SubscriptionId = $script:Sub; Budgets = 0 })
        & $script:Write $Dir 'az-14-backup-vaults' @(@{ Name = 'rsv-prod'; Type = 'microsoft.recoveryservices/vaults'; SubscriptionId = $script:Sub; SoftDelete = 'Enabled'; Immutability = 'Disabled' }, @{ Name = 'bv-ok'; Type = 'microsoft.dataprotection/backupvaults'; SubscriptionId = $script:Sub; SoftDelete = 'AlwaysON'; Immutability = 'Locked' })
        & $script:Write $Dir 'az-15-sentinel' @(@{ Workspace = 'law-sec'; SubscriptionId = $script:Sub; Connectors = 'AzureActiveDirectory, Office365' })
        & $script:Write $Dir 'az-16-entra-domain-services' @(@{ Name = 'aadds.contoso.example'; SubscriptionId = $script:Sub; NtlmV1 = 'Enabled'; TlsV1 = 'Disabled'; SyncNtlmPasswords = 'Enabled'; KerberosRc4Encryption = 'Disabled' })
        & $script:Write $Dir 'az-02-secure-scores' @(@{ SubscriptionId = $script:Sub; Name = 'ascScore'; Current = 21; Max = 42; Percentage = 0.5 })
        & $script:Write $Dir 'az-02-assessments-summary' @(@{ SubscriptionId = $script:Sub; Status = 'Unhealthy'; Severity = 'High'; Count = 3 }, @{ SubscriptionId = $script:Sub; Status = 'Unhealthy'; Severity = 'Low'; Count = 5 }, @{ SubscriptionId = $script:Sub; Status = 'Healthy'; Severity = 'High'; Count = 9 })
        & $script:Write $Dir 'az-02-assessments-top' @(@{ Recommendation = 'Machines should have vulnerability findings resolved'; Severity = 'High'; Affected = 4 })
        & $script:Write $Dir 'def-06-secure-score-controls' @(
            @{ Id = 'MFARegistrationV2'; Title = 'Ensure all users can complete MFA'; Category = 'Identity'; Service = 'AzureAD'; MaxScore = 9; Score = 3; State = 'Default'; ImplementationCost = 'Moderate'; UserImpact = 'Moderate'; ActionUrl = 'https://security.microsoft.com/securescore?actionId=MFARegistrationV2' }
            @{ Id = 'aad_admin_consent_workflow'; Title = 'Ensure the admin consent workflow is enabled'; Category = 'Identity'; Service = 'AzureAD'; MaxScore = 4; Score = 0; State = 'Default'; ImplementationCost = 'Low'; UserImpact = 'Low'; ActionUrl = '' }
            @{ Id = 'mcas_made_up_action'; Title = 'Connect an app'; Category = 'Apps'; Service = 'MCAS'; MaxScore = 5; Score = 0; State = 'Default'; ImplementationCost = 'Low'; UserImpact = 'Low'; ActionUrl = '' }
            @{ Id = 'older_evidence_action'; Title = 'An action saved before the product was'; Category = 'Device'; MaxScore = 2; Score = 1; State = 'Default'; ImplementationCost = 'Low'; UserImpact = 'Low'; ActionUrl = '' }
            @{ Id = 'BlockLegacyAuthentication'; Title = 'Block legacy authentication'; Category = 'Identity'; MaxScore = 8; Score = 8; State = 'Default'; ImplementationCost = 'Moderate'; UserImpact = 'Moderate'; ActionUrl = 'https://security.microsoft.com/securescore?actionId=BlockLegacyAuthentication' }
            @{ Id = 'mdo_safeattachments'; Title = 'Turn on Safe Attachments'; Category = 'Data'; MaxScore = 8; Score = 0; State = 'ThirdParty'; ImplementationCost = 'Low'; UserImpact = 'Low'; ActionUrl = '' }
        )
    }
}

Describe 'Azure exposure, cost, backups, Sentinel and Entra Domain Services' {
    BeforeAll {
        $script:Dir = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-azexp-$([guid]::NewGuid().ToString('n'))"
        & $script:Base $script:Dir
        $pf = Join-Path $script:Dir 'profile.json'
        @{ version = 1; azure = 'workloads' } | ConvertTo-Json | Set-Content $pf
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
        $script:Run = Invoke-PostureChecks -Evidence $script:Dir -Domain azure -ProfilePath $pf -PassThru
        $script:By = @{}; foreach ($x in $script:Run.results) { $script:By[$x.id] = $x }
    }
    AfterAll { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue }

    It 'gives <Id> status <Status>' -ForEach @(
        @{ Id = 'AZ-024'; Status = 'fail' }
        @{ Id = 'AZ-025'; Status = 'fail' }
        @{ Id = 'AZ-026'; Status = 'fail' }
        @{ Id = 'AZ-027'; Status = 'fail' }
        @{ Id = 'AZ-028'; Status = 'fail' }
    ) { $script:By[$Id].status | Should -Be $Status -Because ($script:By[$Id].reason) }

    It 'names what to fix' {
        @($script:By['AZ-024'].affected)[0].detail | Should -Be 'ports 3389 open to the internet, Production (0b1c2d3e-0000-4000-8000-000000000001)'
        @($script:By['AZ-026'].affected.name) | Should -Be @('rsv-prod')
        @($script:By['AZ-027'].affected)[0].detail | Should -Be 'missing MicrosoftThreatProtection'
        @($script:By['AZ-028'].affected)[0].detail | Should -Be 'NTLMv1, NTLM password sync on'
    }

    It 'charts the Secure Score actions with Microsoft''s links and the Defender for Cloud picture' {
        InModuleScope TenantKeep.Posture -Parameters @{ D = $script:Dir } {
            $c = Get-PostureChartData -Evidence $D -DomainFacts @{}
            @($c.secureScoreActions.rows.title) | Should -Be @('Ensure all users can complete MFA', 'Connect an app', 'Ensure the admin consent workflow is enabled', 'An action saved before the product was') -Because 'a control already earned or covered by a third party is not an action, and the most points come first'
            @($c.secureScoreActions.all.id) | Should -Be @('MFARegistrationV2', 'mcas_made_up_action', 'aad_admin_consent_workflow', 'older_evidence_action') -Because 'the full list has every open action'
            @($c.secureScoreActions.all.product) | Should -Be @('Microsoft Entra ID', 'Defender for Cloud Apps', 'Microsoft Entra ID', 'Device') -Because 'the product is Microsoft''s, by name, and the category stands in for evidence saved without it'
            $c.secureScoreActions.rows[0].points | Should -Be 6
            ($c.secureScoreCategories.rows | Where-Object label -eq 'Identity').available | Should -Be 10
            $c.azureSecureScore.item[0].value | Should -Be 50
            @($c.azureRecommendations.segment | ForEach-Object { $_.value }) | Should -Be @(3, 0, 5)
        }
        $rep = New-PostureReport -Evidence $script:Dir -OutputPath (Join-Path $script:Dir 'out') -PassThru 6>$null
        $html = Get-Content -Raw ($rep.Files | Where-Object { $_ -like '*report.html' })
        foreach ($t in 'Top Secure Score Improvements', 'Secure Score by Category', 'Defender for Cloud Secure Score', 'Top Defender for Cloud Recommendations') { $html | Should -Match $t }
        $html | Should -Match 'href="https://security\.microsoft\.com/securescore\?actionId=MFARegistrationV2"'
        # Every open action under its product, with the check here that judges the same setting.
        $html | Should -Match 'All 4 open Secure Score actions, by product'
        $html | Should -Match '2 of 4 are also judged by a check in this report'
        $html | Should -Match '<tr class="group"><th colspan="4">Microsoft Entra ID <span class="tech">2 actions, 10 points</span>'
        $html | Should -Match 'data-check="ID-009" title="[^"]+"><code>ID-009</code></a> <span class="status notEvaluated">Not evaluated</span>'
        $html | Should -Match 'data-check="AU-006"'
        $html | Should -Match 'Connect an app</td><td>5</td><td>Low</td><td><span class="tech">Microsoft''s only</span>'
        [regex]::Matches($html, '<tr class="group">').Count | Should -Be 3 -Because 'three products have an open action'
        $html.IndexOf('Microsoft Entra ID <span class="tech">2 actions') | Should -BeLessThan $html.IndexOf('Defender for Cloud Apps <span class="tech">1 action,') -Because 'the product with the most points to earn comes first'
        # The remediation plan sits beside the roadmap lanes, in the page, the findings file and the Markdown.
        $html | Should -Match '<h4>Remediation Plan</h4>'
        $html | Should -Match '<h4>Roadmap</h4>' -Because 'the lanes stay: they say what matters most, the plan says what comes first'
        $html | Should -Match 'href="#plan-PJ-038"' -Because 'the failing Azure workload checks make that project part of the plan'
        $findings = Get-Content -Raw ($rep.Files | Where-Object { $_ -like '*findings.json' }) | ConvertFrom-Json
        @($findings.plan.stages)[0].stage | Should -Be 'start'
        @(@($findings.plan.stages)[0].projects.id) | Should -Contain 'PJ-036' -Because 'Azure foundations has a failing check and waits on nothing'
        $workloads = @(@($findings.plan.stages | Where-Object stage -eq 'then')[0].projects | Where-Object id -eq 'PJ-038')[0]
        $workloads.checks | Should -Contain 'AZ-024'
        @($workloads.waitsOn)[0].id | Should -Be 'PJ-036' -Because 'the workloads project is better after the foundations, which are also in the plan'
        @($workloads.waitsOn)[0].kind | Should -Be 'after'
        Get-Content -Raw ($rep.Files | Where-Object { $_ -like '*report.md' }) | Should -Match '(?s)### Remediation plan.*\*\*Start now\*\*.*\*\*Then\*\*.*Azure workloads and Defender for Cloud.*better after Azure foundations'
    }

    It 'does not pass AZ-026, AZ-027 or AZ-028 on a tenant without backup vaults, Sentinel or Entra Domain Services' {
        $empty = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-azempty-$([guid]::NewGuid().ToString('n'))"
        try {
            & $script:Base $empty
            foreach ($n in 'az-14-backup-vaults', 'az-15-sentinel', 'az-16-entra-domain-services') { & $script:Write $empty $n @() }
            $pf = Join-Path $empty 'profile.json'
            @{ version = 1; azure = 'workloads' } | ConvertTo-Json | Set-Content $pf
            InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
            $r = Invoke-PostureChecks -Evidence $empty -Domain azure -ProfilePath $pf -PassThru
            foreach ($id in 'AZ-026', 'AZ-027', 'AZ-028') { @($r.results | Where-Object id -eq $id)[0].status | Should -Be 'notEvaluated' -Because "$id has nothing to judge" }
        }
        finally { Remove-Item -LiteralPath $empty -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
