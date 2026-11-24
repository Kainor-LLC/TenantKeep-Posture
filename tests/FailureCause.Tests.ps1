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

    Context 'A refusal that does not say whether a permission or a role was missing' {
        # Microsoft answers 403 for both. The run records which of the step's permissions the sign-in did not carry.
        BeforeAll {
            $script:Refused = 'Response status code does not indicate success: Forbidden (Forbidden). [GET https://graph.microsoft.com/v1.0/informationProtection/bitlocker/recoveryKeys?$select=id,deviceId,createdDateTime,volumeType]'
            $script:Fail = {
                param([string] $Folder, [string] $Message, $Context, $Session)
                InModuleScope TenantKeep.Posture -Parameters @{ Folder = $Folder; Message = $Message; Context = $Context; Session = $Session } {
                    param($Folder, $Message, $Context, $Session)
                    New-Item -ItemType Directory -Path $Folder -Force | Out-Null
                    Mock Get-MgContext { $Context }
                    $script:PostureSession = $Session
                    $script:PostureCurrentCollector = 'Intune'
                    try { $null = Invoke-PostureStep -Label 'BitLocker recovery keys' -Folder $Folder -Script { throw $Message } -WarningAction SilentlyContinue }
                    finally { $script:PostureCurrentCollector = $null; $script:PostureSession = $null }
                    @(Read-PostureRunFailure -Folder $Folder)[0]
                }
            }
        }

        It 'records the permission the sign-in did not carry, and says to approve the app again, not to grant a role' {
            $context = [pscustomobject]@{ TenantId = '11111111-2222-3333-4444-555555555555'; Scopes = @('Directory.Read.All', 'Policy.Read.All'); AuthType = 'UserProvidedAccessToken' }
            $f = & $script:Fail (Join-Path $script:Root 'lacks') $script:Refused $context @{ account = 'admin@contoso.example'; tokens = @{} }
            $f['cause'] | Should -Be 'permission'
            $f['signIn'] | Should -Be 'app'
            @($f['scopesMissing']) | Should -Be @('BitlockerKey.ReadBasic.All')
            $advice = InModuleScope TenantKeep.Posture -Parameters @{ f = $f } { param($f) Get-PostureFailureAdvice -Failure $f }
            $advice | Should -Match "^The tenant's approval of the TenantKeep app does not include the permission BitlockerKey\.ReadBasic\.All, and Microsoft refuses this read without it, whatever role the account holds\."
            $advice | Should -Match 'A Global Administrator approves the app again'
            $advice | Should -Not -Match 'Give the account'
        }

        It 'says a permission is not what is missing when the sign-in carries it, whatever its spelling' {
            $context = [pscustomobject]@{ TenantId = '11111111-2222-3333-4444-555555555555'; Scopes = @('Directory.Read.All', 'BitLockerKey.ReadBasic.All'); AuthType = 'Delegated' }
            $f = & $script:Fail (Join-Path $script:Root 'carries') $script:Refused $context $null
            $f['signIn'] | Should -Be 'graph'
            @($f['scopesMissing']).Count | Should -Be 0
            $advice = InModuleScope TenantKeep.Posture -Parameters @{ f = $f } { param($f) Get-PostureFailureAdvice -Failure $f }
            $advice | Should -Match '^The sign-in carries the permission this step reads with \(BitlockerKey\.ReadBasic\.All\), so a permission is not what is missing\. Give the account that runs the assessment one of: Global Reader'
            $advice | Should -Match 'It also needs Intune\.$'
        }

        It 'records nothing about permissions when the sign-in''s own list is not known, or the refusal is about a licence' {
            $unknown = & $script:Fail (Join-Path $script:Root 'unknown') $script:Refused $null $null
            $unknown.Contains('scopesMissing') | Should -BeFalse -Because 'not known must not read as nothing missing'
            $advice = InModuleScope TenantKeep.Posture -Parameters @{ f = $unknown } { param($f) Get-PostureFailureAdvice -Failure $f }
            $advice | Should -Match '^Give the account that runs the assessment one of: Global Reader.*The TenantKeep app needs the delegated permission BitlockerKey\.ReadBasic\.All too'
            $empty = [pscustomobject]@{ TenantId = '11111111-2222-3333-4444-555555555555'; Scopes = @(); AuthType = 'Delegated' }
            (& $script:Fail (Join-Path $script:Root 'empty') $script:Refused $empty $null).Contains('scopesMissing') | Should -BeFalse
            $context = [pscustomobject]@{ TenantId = '11111111-2222-3333-4444-555555555555'; Scopes = @('Directory.Read.All'); AuthType = 'Delegated' }
            $licence = & $script:Fail (Join-Path $script:Root 'licence') 'Response status code does not indicate success: Forbidden (Forbidden). AadPremiumLicenseRequired' $context $null
            $licence['cause'] | Should -Be 'licence'
            $licence.Contains('scopesMissing') | Should -BeFalse
        }

        It 'words the fix for <Kind>' -ForEach @(
            @{ Kind = 'application'; Expect = '^The identity the run signs in as has not been granted the permission X\.Read\.All, and Microsoft refuses this read without it, whatever role the account holds\. Grant it \(deploy/automation/Grant-ManagedIdentityGraphRole\.ps1 -IncludePosture\), and the next run reads this step\.$' }
            @{ Kind = 'graph'; Expect = '^The Graph session does not carry the permission X\.Read\.All, and Microsoft refuses this read without it, whatever role the account holds\. Connect again with it in -Scopes, then collect this step again\.$' }
            @{ Kind = 'app'; Expect = 'from the link the run prints when collecting starts, then Resume-PostureRun collects this step\.$' }
        ) {
            InModuleScope TenantKeep.Posture -Parameters @{ Kind = $Kind } {
                param($Kind)
                Get-PostureFailureAdvice -Failure @{ cause = 'permission'; roles = @('Global Reader'); scopes = @('X.Read.All'); licence = ''; message = 'Forbidden'; signIn = $Kind; scopesMissing = @('X.Read.All') }
            } | Should -Match $Expect
        }

        It 'still names the role when only some of a step''s permissions are missing, since the step may not read with them' {
            $advice = InModuleScope TenantKeep.Posture {
                Get-PostureFailureAdvice -Failure @{ cause = 'permission'; roles = @('Security Reader', 'Global Reader'); scopes = @('IdentityRiskyUser.Read.All', 'IdentityRiskEvent.Read.All'); licence = ''; message = 'Forbidden'; signIn = 'app'; scopesMissing = @('IdentityRiskEvent.Read.All') }
            }
            $advice | Should -Match 'does not include the permission IdentityRiskEvent\.Read\.All, which this step can need\.'
            $advice | Should -Match 'If the step is refused again after that, give the account one of: Security Reader, Global Reader\.$'
            $advice | Should -Not -Match 'whatever role'
        }

        It 'shows it in the report as a permission to approve, with the address to approve the app at' {
            InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
            . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
            $ev = Initialize-CollectionFixture -Root (Join-Path $script:Root 'approve-run')
            @{ tenantId = '11111111-2222-3333-4444-555555555555' } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ev 'metadata.json')
            $context = [pscustomobject]@{ TenantId = '11111111-2222-3333-4444-555555555555'; Scopes = @('Directory.Read.All'); AuthType = 'UserProvidedAccessToken' }
            $null = & $script:Fail $ev $script:Refused $context @{ account = 'admin@contoso.example'; tokens = @{} }
            $r = New-PostureReport -Evidence $ev -PassThru
            $html = Get-Content -Raw (@($r.Files) -like '*.html')[0]
            $html | Should -Match '<span class="status fail">Needs a permission</span>'
            $html | Should -Match 'approves the app again, from the link the run prints when collecting starts, then Resume-PostureRun collects this step\. <a href="https://login\.microsoftonline\.com/11111111-2222-3333-4444-555555555555/v2\.0/adminconsent\?[^"]*BitLockerKey\.ReadBasic\.All[^"]*" target="_blank" rel="noopener">Approve the app again</a>'
            $html | Should -Not -Match 'Give the account that runs the assessment one of: Global Reader, Security Reader, Cloud Device Administrator'
            Get-Content -Raw (@($r.Files) -like '*.md')[0] | Should -Match 'A Global Administrator approves the TenantKeep app again here: https://login\.microsoftonline\.com/11111111-2222-3333-4444-555555555555/'
            InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
        }
    }

    Context 'A read the run was not asked to make' {
        BeforeAll {
            $script:NotAsked = 'Not readable with this sign-in: the Teams module reads Get-AllM365TeamsApps with a Microsoft 365 token (substrate.office.com) that a session opened with access tokens does not carry. Start-PostureRun -TeamsAppSignIn reads it: Teams then asks for a sign-in of its own.'
        }

        It 'says how to read the two Teams app settings, and keeps "nothing to do" for a read nothing changes' {
            InModuleScope TenantKeep.Posture -Parameters @{ NotAsked = $script:NotAsked } {
                param($NotAsked)
                $offer = @{ cause = 'notReadable'; roles = @(); scopes = @(); licence = ''; message = $NotAsked }
                Test-PostureTeamsSignInOffer -Failure $offer | Should -BeTrue
                Get-PostureFailureAdvice -Failure $offer | Should -Match "^Read only through the Teams module's own sign-in, which this run was not asked to make\. To read it, collect Teams again with: Resume-PostureRun -Collector Teams -TeamsAppSignIn\."
                # A run that asked and was refused by the tenant's own policy, and a read Microsoft keeps for other applications.
                foreach ($message in @(
                        "Not readable with this sign-in: Conditional Access in this tenant refused the Teams module's own sign-in, which outside Windows can only be made with a device code. That is the tenant's policy working, and nothing in the run changes it. On Windows the Teams module signs in through the browser instead, so these two reads can be collected there with -TeamsAppSignIn."
                        'Not readable with this sign-in: Microsoft 365 Backup refused the read of its protection policies although the sign-in carries BackupRestore-Configuration.Read.All.'
                    )) {
                    $other = @{ cause = 'notReadable'; roles = @(); scopes = @(); licence = ''; message = $message }
                    Test-PostureTeamsSignInOffer -Failure $other | Should -BeFalse
                    Get-PostureFailureAdvice -Failure $other | Should -Match 'Nothing to grant, and collecting again says the same'
                }
            }
        }

        It 'shows it in the report as needing the Teams sign-in, and does not say that nothing is fixed by collecting again' {
            InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
            . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
            $ev = Initialize-CollectionFixture -Root (Join-Path $script:Root 'teams-offer-run')
            InModuleScope TenantKeep.Posture -Parameters @{ ev = $ev; NotAsked = $script:NotAsked } {
                param($ev, $NotAsked)
                $script:PostureCurrentCollector = 'Teams'
                $null = Invoke-PostureStep -Label 'Teams app availability' -Folder $ev -Script { throw $NotAsked } -WarningAction SilentlyContinue
                $script:PostureCurrentCollector = $null
            }
            $r = New-PostureReport -Evidence $ev -PassThru
            $html = Get-Content -Raw (@($r.Files) -like '*.html')[0]
            $html | Should -Match '<span class="status fail">Needs the Teams sign-in</span>'
            $html | Should -Match 'collect Teams again with: Resume-PostureRun -Collector Teams -TeamsAppSignIn\.'
            $html | Should -Match 'None of them is fixed by collecting again the same way: .* A row that can be read another way says how\.'
            $html | Should -Match 'none of them is fixed by collecting again the same way, and a row that can be read another way says how'
            $html | Should -Not -Match 'None of them is fixed by collecting again: '
            Get-Content -Raw (@($r.Files) -like '*.md')[0] | Should -Match 'None of them is fixed by collecting again the same way'
            InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
        }
    }
}
