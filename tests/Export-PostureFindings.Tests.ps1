# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-findings-$([guid]::NewGuid().ToString('n'))"
    $script:Ev = Initialize-CollectionFixture -Root (Join-Path $script:Root 'evidence')
    $null = Invoke-PostureChecks -Evidence $script:Ev -Domain identity, auth -OutputPath $script:Ev
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Export-PostureFindings' {
    It 'writes one row per failed check, most severe first, with the affected names in the finding' {
        $path = Export-PostureFindings -Path $script:Ev
        $path | Should -Be (Join-Path $script:Ev 'findings.csv')
        $rows = @(Import-Csv -LiteralPath $path)
        $rows.Count | Should -BeGreaterThan 3
        @($rows[0].PSObject.Properties.Name) | Should -Be @('ID', 'Domain', 'Finding', 'Severity', 'Priority', 'Status', 'Affected', 'Remediation', 'Portal', 'Learn', 'Evidence', 'Checked', 'Licence')
        $weight = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }
        @($rows | ForEach-Object { $weight[$_.Severity] }) | Should -Be @($rows | ForEach-Object { $weight[$_.Severity] } | Sort-Object -Descending)
        @($rows | Where-Object { $_.Status -ne 'Fail' }).Count | Should -Be 0
        @($rows | Where-Object { $_.Finding -match '\d+ affected: ' }).Count | Should -BeGreaterThan 0
        @($rows | Where-Object { $_.Domain -eq 'Identity and privileged access' }).Count | Should -BeGreaterThan 0
        @($rows | Where-Object { $_.Portal -like 'https://*' }).Count | Should -BeGreaterThan 0
    }

    It 'has no merge: an earlier file in the output place is replaced, not read' {
        $out = Join-Path $script:Root 'replace.csv'
        Set-Content -LiteralPath $out -Value "ID,Owner`nID-001,J. Smith"
        $rows = @(Export-PostureFindings -Path $script:Ev -OutputPath $out -PassThru)
        @($rows[0].PSObject.Properties.Name) | Should -Not -Contain 'Owner'
        (Get-Command Export-PostureFindings).Parameters.Keys | Should -Not -Contain 'Merge'
        Get-Content -LiteralPath $out -Raw | Should -Not -Match 'J\. Smith'
    }

    It 'writes passing checks as Pass only with -IncludePassed, after the failures' {
        $all = @(Export-PostureFindings -Path $script:Ev -IncludePassed -PassThru)
        @($all | Where-Object { $_.Status -eq 'Pass' }).Count | Should -BeGreaterThan 0
        @($all | Where-Object { $_.Status -eq 'Fail' }).Count | Should -Be @(Export-PostureFindings -Path $script:Ev -PassThru).Count
        $firstPass = [array]::IndexOf(@($all.Status), 'Pass')
        @($all | Select-Object -Skip $firstPass | Where-Object { $_.Status -eq 'Fail' }).Count | Should -Be 0
    }

    It 'refuses a folder without checks.json' {
        { Export-PostureFindings -Path $script:Root } | Should -Throw '*checks.json not found*'
    }
}
