# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

Describe 'Upkeep task' {
    It 'reports a licensing file past its review date and says what -Offline skipped' {
        $root = Join-Path $TestDrive 'build'
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        Copy-Item (Join-Path $PSScriptRoot '..' 'build.ps1') $root
        Copy-Item (Join-Path $PSScriptRoot '..' 'licensing') $root -Recurse
        $file = Join-Path $root 'licensing' 'bundle-list.json'
        $doc = Get-Content -Raw $file | ConvertFrom-Json -AsHashtable -Depth 20
        $doc['reviewed'] = '2020-01-01'
        $doc | ConvertTo-Json -Depth 20 | Set-Content $file

        $report = Join-Path $TestDrive 'upkeep.md'
        & pwsh -NoProfile -File (Join-Path $root 'build.ps1') -Task Upkeep -Offline -UpkeepReport $report *> $null
        $LASTEXITCODE | Should -Be 0
        $md = Get-Content -Raw $report
        $md | Should -Match '^# Weekly upkeep, \d{4}-\d{2}-\d{2}'
        $md | Should -Match '- \[ \] licensing/bundle-list\.json was last reviewed on 2020-01-01'
        $md | Should -Match 'Offline: the licensing list, ATT&CK, module versions and Learn links were not checked\.'
        $md | Should -Not -Match ([char]0x2014)
    }

    It 'files the report from a workflow that only reads the repository and writes issues' {
        $yml = Get-Content -Raw (Join-Path $PSScriptRoot '..' '.github' 'workflows' 'upkeep.yml')
        $yml | Should -Match '(?m)^\s+contents: read$'
        $yml | Should -Match '(?m)^\s+issues: write$'
        $yml | Should -Not -Match 'secrets\.'
        $yml | Should -Match 'build\.ps1 -Task Upkeep'
    }
}
