# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-ai-$([guid]::NewGuid().ToString('n'))"
    $script:Ev = Initialize-CollectionFixture -Root (Join-Path $script:Root 'run')
    $script:R = New-PostureReport -Evidence $script:Ev -Redact -PassThru 6>$null
    $script:Doc = Get-Content -Raw (Join-Path $script:Ev 'findings.json') | ConvertFrom-Json -AsHashtable
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Output for tools and AI' {
    It 'writes findings.json: explained, summarised, every failing check ranked by severity then reach' {
        $script:Doc.about | Should -Match 'most important first'
        $script:Doc.schemaVersion | Should -Be 1
        $f = @($script:Doc.findings)
        $f.Count | Should -Be @($script:R.Run.results | Where-Object { $_.status -eq 'fail' }).Count
        @($f | ForEach-Object { $_.rank }) | Should -Be @(1..$f.Count)
        $w = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }
        @($f | ForEach-Object { $w[$_.severity] }) | Should -Be @($f | ForEach-Object { $w[$_.severity] } | Sort-Object -Descending)
        $first = $f[0]
        foreach ($k in 'id', 'title', 'whyItMatters', 'howToFix', 'learn', 'priority') { $first[$k] | Should -Not -BeNullOrEmpty -Because "$k is what a reader acts on" }
        @($f | Where-Object { $_.affectedCount -gt 0 })[0].affectedFile | Should -Match '^affected/[A-Z]+-\d{3}\.csv$'
        $script:Doc.summary.counts.fail | Should -Be $f.Count
    }

    It 'puts the quick fix first within a severity, and carries steps, effort, category and what was found' {
        InModuleScope TenantKeep.Posture {
            $report = @{
                results     = @(
                    [ordered]@{ id = 'XX-001'; title = 'Project'; domain = 'x'; severity = 'High'; status = 'fail'; reason = $null; affected = @(); affectedCount = 10; observed = [ordered]@{ coveragePct = 40 }; thresholds = @{ minPct = 90 } }
                    [ordered]@{ id = 'XX-002'; title = 'Quick'; domain = 'x'; severity = 'High'; status = 'fail'; reason = $null; affected = @(); affectedCount = 1; observed = [ordered]@{ enabled = $false }; thresholds = @{} }
                    [ordered]@{ id = 'XX-003'; title = 'Worse'; domain = 'x'; severity = 'Critical'; status = 'fail'; reason = $null; affected = @(); affectedCount = 0 }
                )
                catalogText = @{
                    'XX-001' = @{ effort = 'L'; category = 'fix'; steps = @('Buy it.', 'Roll it out.'); remediation = 'Buy it. Roll it out.'; narrative = 'n' }
                    'XX-002' = @{ effort = 'S'; category = 'improve'; steps = @('Turn it on.'); remediation = 'Turn it on.'; narrative = 'n'; userImpact = @{ level = 'none'; text = 'Nothing users see.' } }
                    'XX-003' = @{ category = 'fix'; steps = @('Fix.'); remediation = 'Fix.'; narrative = 'n' }
                }
                domains = @(); domainsNotCollected = @(); score = @{ value = 50; grade = 'C'; method = 'm' }; appendix = @{ moduleVersion = '0'; baseline = 'standard' }; counts = @{}; runHealth = $null; tenantId = 't'; tenantName = 'T'; generatedUtc = ''; collectedUtc = ''
            }
            $f = @((ConvertTo-PostureFindingsDocument -Report $report).findings)
            @($f | ForEach-Object { $_.id }) | Should -Be @('XX-003', 'XX-002', 'XX-001') -Because 'severity first, then the quick fix before the project, whatever it affects'
            $f[1].category | Should -Be 'improve'
            $f[1].userImpact.level | Should -Be 'none'
            $f[1].userImpact.whatUsersNotice | Should -Be 'Nothing users see.'
            $f[1].observed.enabled | Should -BeFalse
            $f[2].steps | Should -Be @('Buy it.', 'Roll it out.')
            $f[2].thresholds.minPct | Should -Be 90
        }
    }

    It 'embeds the same findings in report.html and leads report.md with the ranked list' {
        $html = Get-Content -Raw (Join-Path $script:Ev 'report.html')
        $html | Should -Match '<script type="application/json" id="tenantkeep-findings">'
        $html | Should -Match 'For tools and AI'
        $md = Get-Content -Raw (Join-Path $script:Ev 'report.md')
        $md.IndexOf('## What to fix first') | Should -BeLessThan $md.IndexOf('## Executive summary')
        $md | Should -Match ([regex]::Escape("1. **$($script:Doc.findings[0].id)"))
    }

    It 'with -Redact, writes share/ copies with no address, sign-in name or affected name left, and a key to map them back' {
        $share = Join-Path $script:Ev 'share'
        foreach ($f in 'report.html', 'report.md', 'findings.json') { Join-Path $share $f | Should -Exist }
        $key = @(Import-Csv (Join-Path $script:Ev 'redaction-key.csv'))
        $key.Count | Should -BeGreaterThan 3
        @($key | Where-Object Kind -eq 'user').Count | Should -BeGreaterThan 0
        $all = (Get-Content -Raw (Join-Path $share 'report.md')) + (Get-Content -Raw (Join-Path $share 'findings.json')) + (Get-Content -Raw (Join-Path $share 'report.html'))
        $all | Should -Not -Match '@contoso\.example' -Because 'every sign-in name is replaced'
        foreach ($k in $key | Where-Object { $_.Kind -in 'user', 'object' }) { $all.Contains($k.Value) | Should -BeFalse -Because "$($k.Value) is in the key" }
        $all | Should -Match 'user-001'
        (Get-Content -Raw (Join-Path $script:Ev 'findings.json')) | Should -Match '@contoso\.example' -Because 'the private copy is untouched'
    }
}
