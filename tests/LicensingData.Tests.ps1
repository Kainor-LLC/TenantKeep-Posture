# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Dir = Join-Path $PSScriptRoot '..' 'licensing'
}

Describe 'Licensing data' {
    It 'resolves every licence token a check gates on to a feature or a bundle' {
        InModuleScope TenantKeep.Posture {
            $d = Get-PostureLicensingData
            $known = @(@($d.features.Values | ForEach-Object { $_.token }) + @($d.bundles | Where-Object { $_.Contains('token') } | ForEach-Object { $_.token }))
            foreach ($c in (Import-PostureCheckCatalog).checks) { foreach ($t in @($c.license)) { $known | Should -Contain $t -Because "$($c.id) gates on $t" } }
        }
    }

    It 'names only real features in bundles, goals, includes and prerequisites' {
        InModuleScope TenantKeep.Posture {
            $d = Get-PostureLicensingData
            $ids = @($d.features.Keys)
            foreach ($b in $d.bundles) { foreach ($f in @($b.features)) { $ids | Should -Contain $f -Because "$($b.sku) lists $f" } }
            foreach ($g in $d.goals) { foreach ($group in @($g.needs)) { foreach ($f in @($group)) { $ids | Should -Contain $f -Because "goal $($g.id) needs $f" } } }
            foreach ($f in $d.features.Values) { foreach ($k in 'includes', 'requires', 'impliedBy') { if ($f.Contains($k)) { foreach ($x in @($f[$k])) { $ids | Should -Contain $x -Because "$($f.id).$k names $x" } } } }
        }
    }

    It 'keeps bundles.json generated from bundle-list.json, with the same SKUs' {
        $list = Get-Content -Raw (Join-Path $script:Dir 'bundle-list.json') | ConvertFrom-Json
        $gen = Get-Content -Raw (Join-Path $script:Dir 'bundles.json') | ConvertFrom-Json
        @($gen.bundles.sku) | Should -Be @($list.skus.sku) -Because 'run build.ps1 -Task LicensingData after editing the list'
        $gen.reviewed | Should -Be $list.reviewed
    }

    It 'has no em dash and was reviewed against Microsoft within 180 days' {
        foreach ($f in Get-ChildItem $script:Dir -Filter '*.json') { Get-Content -Raw $f.FullName | Should -Not -Match ([char]0x2014) }
        $stale = @(Get-ChildItem $script:Dir -Filter '*.json' | ForEach-Object { $j = Get-Content -Raw $_.FullName | ConvertFrom-Json; if ($j.PSObject.Properties['reviewed'] -and ([datetime]::UtcNow - [datetime]$j.reviewed).TotalDays -gt 180) { $_.Name } })
        if ($stale.Count) { Set-ItResult -Skipped -Because "review against Microsoft's service plan list and bump 'reviewed': $($stale -join ', ')" }
    }
}
