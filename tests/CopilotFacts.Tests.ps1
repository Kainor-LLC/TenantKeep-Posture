# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
    InModuleScope Tenantkeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-copilot-$([guid]::NewGuid().ToString('n'))"
    $script:Ev = Join-Path $script:Root 'evidence'
    New-Item -ItemType Directory -Path $script:Ev -Force | Out-Null
    $w = { param([string] $Name, $Data) ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $script:Ev "$Name.json") }
    & $w 'exo-01-audit-config' @{ UnifiedAuditLogIngestionEnabled = $true }
    & $w 'spo-tenant-settings' @{ DefaultSharingLinkType = 'Direct'; SharingCapability = 'ExternalUserAndGuestSharing'; RequireAnonymousLinksExpireInDays = -1 }
    & $w 'spo-restricted-search' @{ Mode = 'Enabled'; AllowedSites = 0 }
    & $w 'pv-01-sensitivity-labels' @(@{ DisplayName = 'Highly Confidential'; Guid = 'hc'; Priority = 3; EncryptionEnabled = $true; SiteAndGroupProtectionEnabled = $true; Disabled = $false }, @{ DisplayName = 'General'; Guid = 'g'; Priority = 1; EncryptionEnabled = $false; SiteAndGroupProtectionEnabled = $false; Disabled = $false })
    & $w 'pv-01-label-policies' @(@{ Name = 'Global'; Enabled = $true })
    & $w 'spo-sites' @(@{ Url = 'https://contoso.sharepoint.example/sites/Board'; SensitivityLabel = 'hc'; RestrictedAccessControl = $false; IsOneDrive = $false }, @{ Url = 'https://contoso.sharepoint.example/sites/Legal'; SensitivityLabel = 'hc'; RestrictedAccessControl = $true; IsOneDrive = $false }, @{ Url = 'https://contoso.sharepoint.example/sites/Social'; SensitivityLabel = 'g'; RestrictedAccessControl = $false; IsOneDrive = $false })
    & $w 'spo-sites-summary' @{ Ownerless = 2 }
    & $w 'gov-01-access-reviews' @(@{ Recurring = $true; Status = 'InProgress'; ScopeQuery = "/users?`$filter=(userType eq 'Guest')" })
    & $w 'gov-02-access-packages-summary' @{ Packages = 0 }
    & $w 'pv-02-dlp-policies' @(@{ Name = 'Copilot sensitive'; Enabled = $true; Mode = 'Enable'; Workload = 'Applications'; ApplicationLocation = 'Microsoft 365 Copilot' })
    $script:ProfilePath = Join-Path $script:Root 'profile.json'
    '{ "version": 1, "licenses": ["E5", "Copilot", "SAM", "P2"], "copilot": "deployed", "operations": { "copilotLabelInheritanceTestedUtc": "2026-10-01T00:00:00Z" } }' | Set-Content -LiteralPath $script:ProfilePath
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Copilot readiness gates' {
    BeforeAll {
        $script:Run = Invoke-PostureChecks -Evidence $script:Ev -ProfilePath $script:ProfilePath -Domain copilot -PassThru
        $script:By = @{}; foreach ($r in $script:Run.results) { $script:By[$r.id] = $r }
    }

    It 'evaluates 18 gates' { $script:Run.results.Count | Should -Be 18 }

    It 'gives <Id> status <Status>' -ForEach @(
        @{ Id = 'CP-001'; Status = 'pass' }
        @{ Id = 'CP-002'; Status = 'pass' }
        @{ Id = 'CP-003'; Status = 'notEvaluated' }
        @{ Id = 'CP-004'; Status = 'pass' }
        @{ Id = 'CP-005'; Status = 'fail' }
        @{ Id = 'CP-006'; Status = 'pass' }
        @{ Id = 'CP-007'; Status = 'fail' }
        @{ Id = 'CP-009'; Status = 'fail' }
        @{ Id = 'CP-011'; Status = 'fail' }
        @{ Id = 'CP-012'; Status = 'fail' }
        @{ Id = 'CP-013'; Status = 'pass' }
        @{ Id = 'CP-014'; Status = 'notEvaluated' }
        @{ Id = 'CP-016'; Status = 'pass' }
        @{ Id = 'CP-017'; Status = 'notEvaluated' }
        @{ Id = 'CP-018'; Status = 'fail' }
    ) { $script:By[$Id].status | Should -Be $Status -Because ($script:By[$Id].reason) }

    It 'names the top-tier site without restricted access control' {
        $script:By['CP-007'].affectedCount | Should -Be 1
        $script:By['CP-007'].affected[0].name | Should -Match 'Board'
    }

    It 'carries the gate codes and hard flags in the catalog' {
        $cat = @(Get-PostureCheckCatalog -Domain copilot -Full)
        @($cat | Where-Object { $_.Gate.hard }).Id | Should -Be @('CP-001', 'CP-002', 'CP-003', 'CP-004', 'CP-006')
    }
}

Describe 'Copilot readiness page' {
    It 'leads with Blocked while a hard gate is not evaluated, lists the gates and the stopgap narrative' {
        $r = New-PostureReport -Evidence $script:Ev -ProfilePath $script:ProfilePath -Format Html, Markdown -OutputPath (Join-Path $script:Root 'out') -PassThru
        $r.Report.copilot.present | Should -BeTrue
        $r.Report.copilot.blocked | Should -BeTrue -Because 'C3 is not evaluated'
        @($r.Report.copilot.blockedBy | ForEach-Object { $_.code }) | Should -Be @('C3')
        $r.Report.copilot.readinessPct | Should -Be 50 -Because 'six of twelve evaluated gates pass'
        $r.Report.headline.copilotBlocked | Should -BeTrue
        $md = Get-Content -Raw (Join-Path $script:Root 'out' 'report.md')
        $md | Should -Match '### Copilot readiness'
        $md | Should -Match '\*\*Blocked\.\*\*'
        $md | Should -Match 'stopgaps'
        $html = Get-Content -Raw (Join-Path $script:Root 'out' 'report.html')
        $html | Should -Match '<section class="view" id="copilot"><h2>Copilot readiness</h2>'
        $html | Should -Match 'banner blocked'
        $html | Should -Not -Match 'na-panel">The 18 gates'
    }
}

Describe 'Reports and reviews the admin provides' {
    It 'dates the oversharing baseline from the newest data access governance export beside profile.json, and reads attestation dates' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-cp-input-$([guid]::NewGuid().ToString('n'))"
        $client = Join-Path $root 'client'; $imports = Join-Path $client 'imports' 'sam-dag'
        New-Item -ItemType Directory -Path $imports -Force | Out-Null
        Copy-Item -Path (Join-Path $script:Ev '*') -Destination $root -Recurse -Force
        Set-Content -LiteralPath (Join-Path $imports 'Sharing links_2020-01-05.csv') -Value 'SiteUrl,Links'
        Set-Content -LiteralPath (Join-Path $imports "potentially-oversharing-sites_$([datetime]::UtcNow.ToString('yyyy-MM-dd')).csv") -Value 'SiteUrl,Score'
        $today = [datetime]::UtcNow.ToString('yyyy-MM-dd')
        @{ version = 1; licenses = @('E5', 'SAM', 'Copilot'); copilot = 'deployed'; attestations = @{ dspmReviewedUtc = "$($today)T00:00:00Z"; copilotSettingsReviewedUtc = '2020-01-01T00:00:00Z' } } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $client 'profile.json')
        $run = Invoke-PostureChecks -Evidence $root -ProfilePath (Join-Path $client 'profile.json') -Domain copilot -PassThru
        $by = @{}; foreach ($r in $run.results) { $by[$r.id] = $r }
        $by['CP-003'].status | Should -Be 'pass' -Because 'the newest export is dated today'
        $by['CP-017'].status | Should -Be 'pass'
        $by['CP-014'].status | Should -Be 'pass'
        $by['CP-015'].status | Should -Be 'fail' -Because 'the review is years old'
        $by['CP-010'].status | Should -Be 'notEvaluated'
        $by['CP-010'].reason | Should -Match 'Record the date'
        Remove-Item -LiteralPath $root -Recurse -Force
    }
    It 'says where the report goes when none is on file' {
        $r = @($script:Run.results | Where-Object { $_.id -eq 'CP-003' })[0]
        $r.status | Should -Be 'notEvaluated'
        $r.reason | Should -Match 'imports'
        $r.reason | Should -Match 'SharePoint admin center'
    }
}

