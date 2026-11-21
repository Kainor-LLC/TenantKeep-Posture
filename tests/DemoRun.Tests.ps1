# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# The made-up tenant behind the sample report and the website's screenshots. It doubles as an end-to-end test: every
# fact provider reads it, so a provider that stops on a missing field, or a check the demo no longer reaches, shows here.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Made = & (Join-Path $PSScriptRoot '..' 'samples' 'demo' 'New-PostureDemoRun.ps1') -Path (Join-Path $TestDrive 'fernquill')
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'demo tenant, made-up data' } }
    $script:Checks = Invoke-PostureChecks -Evidence $script:Made.Evidence -ProfilePath (Join-Path $script:Made.Client 'profile.json') -Exceptions (Join-Path $script:Made.Client 'exceptions.json') -OutputPath (Join-Path $script:Made.Path 'logs') -PassThru
    $script:Results = @($script:Checks.results)
}

AfterAll {
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
}

Describe 'Demo tenant' {
    It 'writes a run folder with a client folder beside it' {
        $script:Made.Files | Should -BeGreaterThan 140
        Test-Path (Join-Path $script:Made.Path 'logs' 'run.json') | Should -BeTrue
        Test-Path (Join-Path $script:Made.Client 'profile.json') | Should -BeTrue
    }

    It 'runs every fact provider without stopping' {
        $crashed = @($script:Results | Where-Object { [string]$_['reason'] -match 'Fact provider for' })
        $crashed | ForEach-Object { "$($_['id']): $($_['reason'])" } | Should -BeNullOrEmpty
    }

    It 'leaves unevaluated only what the demo leaves out on purpose' {
        # Azure and Active Directory are not part of it, Global Secure Access is unlicensed, and a few Copilot gates
        # wait on an attestation or a report nobody can collect.
        $expected = 'AZ-*', 'HY-*', 'NET-*', 'CP-*', 'GV-005', 'ID-014', 'OP-007'
        $left = @($script:Results | Where-Object { $r = $_; $r['status'] -eq 'notEvaluated' -and -not @($expected | Where-Object { $r['id'] -like $_ }).Count })
        $left | ForEach-Object { "$($_['id']): $($_['reason'])" } | Should -BeNullOrEmpty
    }

    It 'shows a believable mix: mostly passing, real gaps, an accepted risk' {
        @($script:Results | Where-Object { $_['status'] -eq 'pass' }).Count | Should -BeGreaterThan 100
        @($script:Results | Where-Object { $_['status'] -eq 'fail' }).Count | Should -BeGreaterThan 20
        @($script:Results | Where-Object { $_['status'] -eq 'acceptedRisk' }).Count | Should -Be 1
    }

    It 'names only the made-up organisation' {
        $text = (Get-ChildItem -LiteralPath $script:Made.Evidence -Filter '*.json' | ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName }) -join "`n"
        $domains = @([regex]::Matches($text, '[A-Za-z0-9._%+#-]+@([A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})') | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() } | Sort-Object -Unique)
        $domains | Should -Not -BeNullOrEmpty
        foreach ($d in $domains) { $d | Should -Match '(\.example|^fernquilldemo\.onmicrosoft\.com)$' -Because 'the demo tenant uses reserved example domains only' }
    }
}
