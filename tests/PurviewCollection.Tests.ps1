# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-purview-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $env:TKP_PV_FIXTURE = (Join-Path $PSScriptRoot 'Fixtures' 'PurviewFixture.ps1')

    Mock -ModuleName TenantKeep.Posture Get-MgContext { [pscustomobject]@{ TenantId = 'tenant-guid'; Account = 'reader@contoso.example'; AuthType = 'Delegated'; Scopes = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All') } }
    Mock -ModuleName TenantKeep.Posture Start-Transcript { }
    Mock -ModuleName TenantKeep.Posture Stop-Transcript { }
    Mock -ModuleName TenantKeep.Posture Test-PosturePurviewSession { $env:TKP_PV_CONNECTED -eq '1' }
    Mock -ModuleName TenantKeep.Posture Invoke-PostureExoCommand { . $env:TKP_PV_FIXTURE; @(Get-PurviewFixtureObject -Name $Name) }
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
    Remove-Item Env:TKP_PV_FIXTURE, Env:TKP_PV_CONNECTED -ErrorAction SilentlyContinue
}

Describe 'Invoke-PostureCollection -Collector Purview' {
    Context 'connected' {
        BeforeAll {
            $env:TKP_PV_CONNECTED = '1'
            $script:Folder = Join-Path $script:Root 'run1'
            $script:Result = Invoke-PostureCollection -Collector Purview -SkipCaSnapshot -OutputFolder $script:Folder -PassThru -WarningAction SilentlyContinue
            $script:Read = { param([string] $n) Get-Content -Raw (Join-Path $script:Folder "$n.json") | ConvertFrom-Json -AsHashtable }
            '{ "UnifiedAuditLogIngestionEnabled": true }' | Set-Content -LiteralPath (Join-Path $script:Folder 'exo-01-audit-config.json')
            '{ "Total": 10, "Labeled": 0 }' | Set-Content -LiteralPath (Join-Path $script:Folder 'spo-sites-summary.json')
        }

        It 'writes the A.2 pv-* files' {
            foreach ($n in 'pv-01-sensitivity-labels', 'pv-01-label-policies', 'pv-01-autolabel-policies', 'pv-02-dlp-policies', 'pv-02-dlp-rules', 'pv-03-retention-policies', 'pv-03-retention-rules', 'pv-03-retention-labels', 'pv-04-insider-risk-policies', 'pv-05-audit-retention-policies', 'pv-06-ediscovery-cases', 'pv-07-alert-policies', 'pv-08-role-groups') {
                Join-Path $script:Folder "$n.json" | Should -Exist
            }
            Join-Path $script:Folder 'pv-02-dlp-policies.csv' | Should -Exist
            $script:Result.Collectors | Should -Be @('Purview')
            $script:Result.Errors.Count | Should -Be 0
            @(& $script:Read 'pv-01-label-policies')[0].ExchangeLocation | Should -Be @('All')
            @(& $script:Read 'pv-01-label-policies')[0].Settings | Should -Contain '[attachmentaction, Automatic]' -Because 'a label policy''s settings are where PV-009 finds its answer'
            @(& $script:Read 'pv-07-alert-policies')[0].NotifyUser | Should -Be @('TenantAdmins') -Because 'PV-013 reads who an alert is sent to'
        }

        It 'feeds the purview checks' {
            $profilePath = Join-Path $script:Root 'profile.json'
            '{ "version": 1, "licenses": ["E5"] }' | Set-Content -LiteralPath $profilePath
            $run = Invoke-PostureChecks -Evidence $script:Folder -Domain purview -ProfilePath $profilePath -PassThru
            $by = @{}; foreach ($r in $run.results) { $by[$r.id] = $r }
            $by['PV-001'].status | Should -Be 'pass' -Because $by['PV-001'].reason
            $by['PV-002'].status | Should -Be 'pass'
            $by['PV-003'].status | Should -Be 'fail' -Because 'the auto-labeling policy is in simulation'
            $by['PV-004'].status | Should -Be 'fail' -Because 'container labels exist but no site is labeled'
            $by['PV-005'].status | Should -Be 'fail'
            @($by['PV-005'].affected | ForEach-Object { $_.name }) | Should -Be @('Teams', 'EndpointDevices') -Because 'the Teams policy is in test mode and E5 expects Endpoint DLP'
            $by['PV-006'].status | Should -Be 'fail' -Because 'retention covers Exchange only'
            $by['PV-007'].status | Should -Be 'fail'
            $by['PV-008'].status | Should -Be 'fail' -Because 'six distinct members across the two admin groups'
            $by['PV-008'].affectedCount | Should -Be 6
            $by['PV-009'].status | Should -Be 'pass' -Because 'the label policy gives an email the label of its attachment'
        }

        It 'does not fail audit retention it could not read' {
            $partial = Join-Path $script:Root 'run-partial'
            Copy-Item -LiteralPath $script:Folder -Destination $partial -Recurse
            Remove-Item -LiteralPath (Join-Path $partial 'pv-05-audit-retention-policies.json')
            $run = Invoke-PostureChecks -Evidence $partial -Domain purview -ProfilePath (Join-Path $script:Root 'profile.json') -PassThru
            $pv1 = $run.results | Where-Object id -EQ 'PV-001'
            $pv1.status | Should -Be 'notEvaluated' -Because 'on E5 an unread list is not proof of no policies'
            $pv1.reason | Should -Match 'pv-05-audit-retention-policies'
        }
    }

    Context 'not connected' {
        It 'refuses when Purview was asked for by name' {
            $env:TKP_PV_CONNECTED = '0'
            { Invoke-PostureCollection -Collector Purview -SkipCaSnapshot -OutputFolder (Join-Path $script:Root 'run2') } | Should -Throw '*Connect-IPPSSession*'
        }
    }
}

Describe 'PV-009: an email takes the sensitivity label of its attachment' {
    BeforeAll {
        $script:Judge = {
            param([object[]] $Policies)
            $dir = Join-Path $script:Root ([guid]::NewGuid().ToString('n'))
            New-Item -ItemType Directory -Path $dir | Out-Null
            ConvertTo-Json -InputObject @(@{ DisplayName = 'General'; Name = 'l1'; Guid = 'g1'; Priority = 0; ContentType = 'File, Email'; ParentId = $null; Disabled = $false; EncryptionEnabled = $false; SiteAndGroupProtectionEnabled = $false; Settings = @() }) -Depth 5 | Set-Content (Join-Path $dir 'pv-01-sensitivity-labels.json')
            # A collection saves every property it selects, empty when the tenant has none; Settings is the one a case may leave out.
            $saved = @($Policies | ForEach-Object { $row = [ordered]@{ Name = $_.Name; Enabled = $_.Enabled; Mode = 'Enforce'; Labels = @('l1'); ExchangeLocation = @('All'); ModernGroupLocation = @() }; if ($_.ContainsKey('Settings')) { $row['Settings'] = $_.Settings }; $row })
            ConvertTo-Json -InputObject $saved -Depth 5 | Set-Content (Join-Path $dir 'pv-01-label-policies.json')
            '{ "version": 1, "licenses": ["E5"] }' | Set-Content (Join-Path $dir 'profile.json')
            InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
            $run = Invoke-PostureChecks -Evidence $dir -Domain purview -ProfilePath (Join-Path $dir 'profile.json') -PassThru
            @($run.results | Where-Object id -EQ 'PV-009')[0]
        }
    }

    It 'passes when a label policy applies the attachment''s label, automatically or as a recommendation' {
        (& $script:Judge @(@{ Name = 'Everyone'; Enabled = $true; ExchangeLocation = @('All'); Settings = @('[mandatory, true]', '[AttachmentAction, Recommended]') })).status | Should -Be 'pass'
        (& $script:Judge @(@{ Name = 'Pilot'; Enabled = $true; Settings = @() }, @{ Name = 'Everyone'; Enabled = $true; Settings = @('[attachmentaction, automatic]') })).status | Should -Be 'pass' -Because 'one policy with it is what Microsoft''s own assessment asks for'
    }

    It 'fails and names the policies when none does' {
        $r = & $script:Judge @(@{ Name = 'Everyone'; Enabled = $true; ExchangeLocation = @('All'); Settings = @('[mandatory, true]') }, @{ Name = 'Off'; Enabled = $false; Settings = @('[attachmentaction, Automatic]') })
        $r.status | Should -Be 'fail' -Because 'the only policy with the setting is disabled'
        @($r.affected.name) | Should -Be @('Everyone')
        (& $script:Judge @(@{ Name = 'Everyone'; Enabled = $true; Settings = $null })).status | Should -Be 'fail' -Because 'settings saved as empty are an answer: the policy has no such setting'
    }

    It 'has no answer for evidence collected before label policy settings were saved' {
        $r = & $script:Judge @(@{ Name = 'Everyone'; Enabled = $true; ExchangeLocation = @('All') })
        $r.status | Should -Be 'notEvaluated'
        $r.reason | Should -Match 'collected before label policy settings were saved'
    }
}

