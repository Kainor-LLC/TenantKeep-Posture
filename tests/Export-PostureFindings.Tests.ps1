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
    It 'writes one Appendix E row per failed check, risk-ordered, with the affected names in the finding' {
        $path = Export-PostureFindings -Path $script:Ev
        $path | Should -Be (Join-Path $script:Ev 'findings.csv')
        $rows = @(Import-Csv -LiteralPath $path)
        $rows.Count | Should -BeGreaterThan 3
        @($rows[0].PSObject.Properties.Name)[0..12] | Should -Be @('ID', 'Workstream', 'Finding', 'Evidence', 'Likelihood 1-5', 'Impact 1-5', 'Risk', 'Effort S/M/L/XL', 'Dependency', 'Quick win', 'Bucket', 'Owner', 'Status')
        @($rows | ForEach-Object { [int]$_.Risk }) | Should -Be @($rows | ForEach-Object { [int]$_.Risk } | Sort-Object -Descending)
        @($rows | Where-Object { $_.Status -ne 'Open' }).Count | Should -Be 0
        @($rows | Where-Object { $_.Finding -match '\d+ affected: ' }).Count | Should -BeGreaterThan 0
        @($rows | Where-Object { $_.Workstream -eq 'Identity and privileged access' }).Count | Should -BeGreaterThan 0
    }

    It 'keeps owner, status, effort and dependency from an earlier register for the same IDs' {
        $earlier = Join-Path $script:Root 'earlier.csv'
        $first = @(Export-PostureFindings -Path $script:Ev -PassThru)
        $first[0].Owner = 'J. Smith'; $first[0].Status = 'In progress'; $first[0].'Effort S/M/L/XL' = 'L'; $first[0].Dependency = 'HR feed'
        $first | Export-Csv -LiteralPath $earlier -NoTypeInformation
        $merged = @(Export-PostureFindings -Path $script:Ev -Merge $earlier -OutputPath (Join-Path $script:Root 'merged.csv') -PassThru)
        $hit = $merged | Where-Object { $_.ID -eq $first[0].ID }
        $hit.Owner | Should -Be 'J. Smith'
        $hit.Status | Should -Be 'In progress'
        $hit.'Effort S/M/L/XL' | Should -Be 'L'
        $hit.Dependency | Should -Be 'HR feed'
        Join-Path $script:Root 'merged.csv' | Should -Exist
    }

    It 'writes passing checks as Resolved only with -IncludePassed' {
        $all = @(Export-PostureFindings -Path $script:Ev -IncludePassed -PassThru)
        @($all | Where-Object { $_.Status -eq 'Resolved' }).Count | Should -BeGreaterThan 0
        @($all | Where-Object { $_.Status -eq 'Open' }).Count | Should -Be @(Export-PostureFindings -Path $script:Ev -PassThru).Count
    }

    It 'refuses a folder without checks.json' {
        { Export-PostureFindings -Path $script:Root } | Should -Throw '*checks.json not found*'
    }
}
