# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-cause-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Why a step failed' {
    # The texts below are the ones live runs logged (tenant details removed).
    It 'classifies <Text> as <Cause>' -ForEach @(
        @{ Text = 'Response status code does not indicate success: Forbidden (Forbidden). [GET https://graph.microsoft.com/v1.0/directory/onPremisesSynchronization] Insufficient privileges to complete the operation.'; Cause = 'permission' }
        @{ Text = 'Attempted to perform an unauthorized operation.'; Cause = 'permission' }
        @{ Text = 'Get-InformationBarrierPolicy is not available; import ExchangeOnlineManagement and connect first.'; Cause = 'permission' }
        @{ Text = "Get-AutoSensitivityLabelPolicy is not in this session: the signed-in roles or the tenant's licences do not expose it."; Cause = 'unavailable' }
        @{ Text = 'You do not have the required license to perform this operation.'; Cause = 'licence' }
        @{ Text = 'Response status code does not indicate success: Forbidden (Forbidden). AadPremiumLicenseRequired'; Cause = 'licence' }
        @{ Text = 'Response status code does not indicate success: NotFound (Not Found). [GET https://graph.microsoft.com/v1.0/deviceManagement/applePushNotificationCertificate]'; Cause = 'notProvisioned' }
        @{ Text = 'GET /subscriptions/x/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01 returned 404: { "error": { "code": "x" } }'; Cause = 'notProvisioned' }
        @{ Text = 'GroupPolicy module not available; GPO inventory skipped.'; Cause = 'module' }
        @{ Text = 'Response status code does not indicate success: TooManyRequests (Too Many Requests).'; Cause = 'throttled' }
        @{ Text = 'The operation has timed out.'; Cause = 'network' }
        @{ Text = 'InvalidAuthenticationToken: Lifetime validation failed, the token is expired.'; Cause = 'token' }
        @{ Text = 'One or more properties are invalid. Parameter name: msLAPS-PasswordExpirationTime'; Cause = 'unknown' }
        @{ Text = 'Not readable with this sign-in: the Teams module reads Get-AllM365TeamsApps with a Microsoft 365 token (substrate.office.com) that a session opened with access tokens does not carry.'; Cause = 'notReadable' }
    ) {
        InModuleScope TenantKeep.Posture -Parameters @{ Text = $Text } { param($Text) Get-PostureFailureCause -Message $Text } | Should -Be $Cause
    }

    It 'names the step''s own role, scopes and licence, and falls back to the collector''s' {
        InModuleScope TenantKeep.Posture {
            $r = Resolve-PostureStepRequirement -Collector Entra -Label 'Risky users'
            $r.roles | Should -Contain 'Security Reader'
            $r.scopes | Should -Contain 'IdentityRiskyUser.Read.All'
            $r.licence | Should -Match 'P2'
            $d = Resolve-PostureStepRequirement -Collector Purview -Label 'DLP policies'
            $d.roles[0] | Should -Match 'View-Only DLP Compliance Management'
            $f = Resolve-PostureStepRequirement -Collector Entra -Label 'Domains'
            $f.roles | Should -Be @('Global Reader')
            (Resolve-PostureStepRequirement -Collector Exchange -Label 'Org config').roles | Should -Not -Contain 'Exchange Administrator' -Because 'the run never asks for a write role in Exchange'
        }
    }

    It 'has a requirement for every collector, and every step pattern is a valid regex for a known collector' {
        InModuleScope TenantKeep.Posture {
            $map = Get-PostureRequirementMap
            foreach ($c in 'Entra', 'Intune', 'Defender', 'Exchange', 'Purview', 'SharePoint', 'Teams', 'Azure') { $map.collectors.Keys | Should -Contain $c }
            foreach ($s in $map.steps) { $map.collectors.Keys | Should -Contain $s.collector; { [regex]::new($s.match) } | Should -Not -Throw }
        }
    }

    It 'checks the account''s roles before the run: ok, missing with what to grant, unknown for role groups' {
        InModuleScope TenantKeep.Posture {
            Mock Assert-PostureGraphScope { @{ Scopes = @('Directory.Read.All') } }
            Mock Invoke-PostureGraphRequest { @(@{ displayName = 'Security Reader' }) }
            $rows = @(Test-PostureRoleCoverage -Collector Entra, Defender, Exchange, Azure)
            ($rows | Where-Object Collector -eq 'Defender').Status | Should -Be 'ok'
            $entra = $rows | Where-Object Collector -eq 'Entra'
            $entra.Status | Should -Be 'missing'
            $entra.Detail | Should -Match 'needs Global Reader; you have Security Reader'
            ($rows | Where-Object Collector -eq 'Exchange').Status | Should -Be 'unknown' -Because 'View-Only Organization Management is an Exchange role group Graph cannot see'
            ($rows | Where-Object Collector -eq 'Azure').Status | Should -Be 'unknown'
            Mock Invoke-PostureGraphRequest { @(@{ displayName = 'Exchange Administrator' }) }
            $exo = @(Test-PostureRoleCoverage -Collector Exchange)[0]
            $exo.Status | Should -Be 'ok'
            $exo.Detail | Should -Match 'more than this run needs' -Because 'Exchange Administrator works, and says it is more than needed'
            Mock Invoke-PostureGraphRequest { @(@{ displayName = 'Global Administrator' }) }
            @(Test-PostureRoleCoverage -Collector Entra, Intune | Where-Object Status -ne 'ok').Count | Should -Be 0
        }
    }

    It 'writes the failure to errors.jsonl with its cause and role, and reads old errors.txt lines too' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
            param($root)
            $f = Join-Path $root 'run'; New-Item -ItemType Directory -Path $f | Out-Null
            $script:PostureCurrentCollector = 'Entra'
            $null = Invoke-PostureStep -Label 'Risky users' -Folder $f -Script { throw 'Response status code does not indicate success: Forbidden (Forbidden).' } -WarningAction SilentlyContinue
            $script:PostureCurrentCollector = $null
            Add-Content -LiteralPath (Join-Path $f 'errors.txt') -Value 'Purview collector :: Get-DlpCompliancePolicy is not available; import ExchangeOnlineManagement and connect first.'
            $all = @(Read-PostureRunFailure -Folder $f)
            $all.Count | Should -Be 2
            $all[0].collector | Should -Be 'Entra'
            $all[0].cause | Should -Be 'permission'
            $all[0].roles | Should -Contain 'Security Reader'
            $all[1].collector | Should -Be 'Purview'
            $all[1].cause | Should -Be 'permission'
        }
    }

    It 'shows the failures in the report: a banner on the overview, and Run Health with the role to grant and the resume command' {
        InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
        . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
        $ev = Initialize-CollectionFixture -Root (Join-Path $script:Root 'report-run')
        InModuleScope TenantKeep.Posture -Parameters @{ ev = $ev } {
            param($ev)
            $script:PostureCurrentCollector = 'Entra'
            $null = Invoke-PostureStep -Label 'Risky users' -Folder $ev -Script { throw 'Response status code does not indicate success: Forbidden (Forbidden).' } -WarningAction SilentlyContinue
            $script:PostureCurrentCollector = $null
        }
        $r = New-PostureReport -Evidence $ev -PassThru
        $html = Get-Content -Raw (@($r.Files) -like '*.html')[0]
        $html | Should -Match '1 step\(s\) could not be read'
        $html | Should -Match '<section class="view" id="health">'
        $html | Should -Match 'Give the account that runs the assessment one of: Security Reader, Global Reader'
        $html | Should -Match ([regex]::Escape([System.Net.WebUtility]::HtmlEncode("Resume-PostureRun -Path '$ev'")))
        Get-Content -Raw (@($r.Files) -like '*.md')[0] | Should -Match '### Run health'
        InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
    }
}
