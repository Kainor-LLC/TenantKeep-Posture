# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
}

Describe 'Secure Score actions and the checks that judge the same setting' {
    It 'maps a control id to the checks that name it, with this run''s answer, ignoring case' {
        InModuleScope TenantKeep.Posture {
            $checks = @(
                [ordered]@{ id = 'CA-001'; title = 'Legacy authentication blocked'; references = @{ secureScore = @('BlockLegacyAuthentication') } }
                [ordered]@{ id = 'CA-004'; title = 'Risk-based policies'; references = @{ secureScore = @('SigninRiskPolicy', 'UserRiskPolicy') } }
                [ordered]@{ id = 'ID-016'; title = 'No legacy sign-ins'; references = @{ secureScore = @('BlockLegacyAuthentication') } }
                [ordered]@{ id = 'ID-001'; title = 'No references at all' }
                [ordered]@{ id = 'ZZ-001'; title = 'Not in this run'; references = @{ secureScore = @('OneAdmin') } }
            )
            $catalog = @{ checks = $checks }
            $results = @(@{ id = 'CA-001'; status = 'pass' }, @{ id = 'CA-004'; status = 'fail' }, @{ id = 'ID-016'; status = 'notEvaluated' }, @{ id = 'ID-001'; status = 'pass' })
            $map = Get-PostureSecureScoreCheck -Catalog $catalog -Result $results
            @($map['blocklegacyauthentication'].id) | Should -Be @('CA-001', 'ID-016')
            @($map['BlockLegacyAuthentication'].status) | Should -Be @('pass', 'notEvaluated')
            @($map['UserRiskPolicy'])[0].title | Should -Be 'Risk-based policies'
            $map.ContainsKey('OneAdmin') | Should -BeFalse -Because 'a check with no result in this run has nothing to open'
            @($map.get_Keys()).Count | Should -Be 3
            @((Get-PostureSecureScoreCheck -Catalog @{ checks = @() }).get_Keys()).Count | Should -Be 0
        }
    }

    It 'names the product, keeps a code it does not know, and falls back to the category' {
        InModuleScope TenantKeep.Posture {
            Get-PostureSecureScoreProduct -Service 'AzureAD' -Category 'Identity' | Should -Be 'Microsoft Entra ID'
            Get-PostureSecureScoreProduct -Service 'mdo' -Category 'Apps' | Should -Be 'Defender for Office 365'
            Get-PostureSecureScoreProduct -Service 'Okta' -Category 'Apps' | Should -Be 'Okta'
            Get-PostureSecureScoreProduct -Service '' -Category 'Device' | Should -Be 'Device'
            Get-PostureSecureScoreProduct -Service $null -Category $null | Should -Be 'Other'
        }
    }

    It 'refuses a check whose references are not lists of ids under a known kind' {
        InModuleScope TenantKeep.Posture {
            $dir = Join-Path $TestDrive 'bad-references'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $check = [ordered]@{ id = 'XX-001'; domain = 'identity'; title = 't'; severityDefault = 'Low'; license = @(); applicableWhen = @{}; coveredBy = @(); thresholds = @{}; evidence = @(); pass = 'true'; remediation = 'Do the thing properly.'; learn = 'https://learn.microsoft.com/x'; deepLink = 'https://entra.microsoft.com/x'; narrative = 'n'; frameworks = @{}; effort = 'S'; category = 'fix'; userImpact = @{ level = 'none'; text = 'Nothing changes for users.' } }
            $save = { @{ domain = 'identity'; checks = @($check) } | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $dir 'identity.json') }
            $check.references = @{ secureScore = @('BlockLegacyAuthentication', 'aad_admin_consent_workflow') }
            & $save
            @((Import-PostureCheckCatalog -Path $dir).checks)[0].references.secureScore | Should -Be @('BlockLegacyAuthentication', 'aad_admin_consent_workflow')
            $check.references = 'BlockLegacyAuthentication'
            & $save
            { Import-PostureCheckCatalog -Path $dir } | Should -Throw '*references must be an object*'
            $check.references = @{ someOtherTool = @('x-1') }
            & $save
            { Import-PostureCheckCatalog -Path $dir } | Should -Throw "*references names 'someOtherTool'*"
            $check.references = @{ secureScore = @('Block legacy authentication') }
            & $save
            { Import-PostureCheckCatalog -Path $dir } | Should -Throw '*references.secureScore must be a list of ids*'
            $check.references = @{ secureScore = @() }
            & $save
            { Import-PostureCheckCatalog -Path $dir } | Should -Throw '*references.secureScore must be a list of ids*'
        }
    }

    It 'names each Secure Score control once per check in the shipped catalog, and only on checks that exist' {
        InModuleScope TenantKeep.Posture {
            $catalog = Import-PostureCheckCatalog
            $with = @($catalog.checks | Where-Object { $_.Contains('references') -and $_.references.Contains('secureScore') })
            $with.Count | Should -BeGreaterThan 20
            foreach ($check in $with) {
                $ids = @($check.references.secureScore)
                @($ids | Sort-Object -Unique).Count | Should -Be $ids.Count -Because "$($check.id) names a control twice"
            }
        }
    }
}
