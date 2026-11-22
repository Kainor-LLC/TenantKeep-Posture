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

Describe 'The page a reader opens' {
    # How the charts are placed. Cards used to be pinned to the top of rows as tall as their tallest card, so a short
    # card beside a tall one left a hole under it, and the ring cards stood twice as tall as their neighbours.
    BeforeAll {
        $report = New-PostureReport -Evidence $script:Made.Evidence -Client $script:Made.Client -Format Html -OutputPath (Join-Path $TestDrive 'page') -PassThru 6>$null
        $script:Page = Get-Content -Raw (@($report.Files) -like '*.html')[0]
        $script:Css = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'templates' 'report.css')
    }

    It 'gives the cards of a row one height, and keeps a donut''s legend beside it' {
        $rule = [regex]::Match($script:Css, '(?m)^\.charts \{[^}]*\}').Value
        $rule | Should -Match 'align-items: stretch' -Because 'a row then has one bottom edge, and "View the checks" sits on it'
        $rule | Should -Not -Match 'align-items: start'
        [regex]::Match($script:Css, '(?m)^\.donut-wrap \{[^}]*\}').Value | Should -Not -Match 'flex-wrap: wrap' -Because 'a long label wraps its own words; it does not push the legend under the donut'
        [regex]::Match($script:Css, '(?m)^\.rings-wrap \{[^}]*\}').Value | Should -Match 'flex-direction: column' -Because 'the list under the rings has the card''s whole width'
    }

    It 'lets the opening cards fill their rows and gives the layered rings a row of their own' {
        $script:Page | Should -Match '<div class="charts story"><figure class="chart-card'
        $depth = [regex]::Match($script:Page, '<h3>Defence in Depth</h3><div class="charts">(.*?)</div>\s*<h3>', 'Singleline').Groups[1].Value
        $depth | Should -Not -BeNullOrEmpty
        [regex]::Matches($depth, '<figure class="chart-card').Count | Should -Be ([regex]::Matches($depth, 'class="rings-wrap"').Count) -Because 'every card in that row is a ring card'
        [regex]::Matches($depth, 'class="rings-wrap"').Count | Should -BeGreaterThan 1
        [regex]::Matches($script:Page, 'class="rings-wrap"').Count | Should -Be ([regex]::Matches($depth, 'class="rings-wrap"').Count) -Because 'no ring card is left among the shorter ones'
    }

    It 'opens the Domains tab on the scorecards and folds the charts of each domain under them' {
        $domains = [regex]::Match($script:Page, '<section class="view" id="domains">(.*?)</section>', 'Singleline').Groups[1].Value
        $domains.IndexOf('<div class="cards">') | Should -BeLessThan $domains.IndexOf('<h3>Charts by Domain</h3>') -Because 'the scores come first'
        $domains | Should -Match '<button type="button" class="fold-toggle" data-fold="details\.area" aria-expanded="false">Open all</button>'
        $areas = [regex]::Matches($domains, '<details class="area"><summary><span class="area-name">([^<]+)</span><span class="hint">(\d+) charts?</span></summary><div class="charts">')
        $areas.Count | Should -BeGreaterThan 4
        $domains | Should -Not -Match '<details class="area" open' -Because 'a section opens when it is asked for'
        foreach ($a in $areas) { [int]$a.Groups[2].Value | Should -BeGreaterThan 0 }
        $script:Page | Should -Match 'beforeprint' -Because 'a printed report has every section open'
    }

    It 'keeps three views in Executive Mode and sends a link to any other to the Overview' {
        # It used to hide two tabs and the technical detail, and looked the same as the full report.
        $script:Css | Should -Match 'body\.executive nav\.views a:not\(\[href="#overview"\]\):not\(\[href="#recommendations"\]\):not\(\[href="#domains"\]\) \{ display: none !important; \}'
        $script:Css | Should -Match 'body\.executive section\.view:not\(#overview\):not\(#recommendations\):not\(#domains\) \{ display: none !important; \}'
        $script:Css | Should -Match 'body\.executive #domains > h3, body\.executive #domains > table, body\.executive #domains \.area-head, body\.executive #domains details\.area \{ display: none !important; \}' -Because 'the scorecards stay; the charts and the tables of checks are detail'
        $script:Page | Should -Match "var execViews = \['overview', 'recommendations', 'domains'\];"
        $script:Page | Should -Match "classList\.contains\('executive'\) && execViews\.indexOf\(view\.id\) < 0\) \{ show\('overview'\); return; \}"
        foreach ($view in 'overview', 'recommendations', 'domains') { $script:Page | Should -Match "<section class=`"view[^`"]*`" id=`"$view`"" }
    }

    It 'folds each ATT&CK tactic into a section with its standing, and opens one from the bars above it' {
        # A column for each tactic left the short tactics standing beside the long ones with holes under them.
        $attack = [regex]::Match($script:Page, '<section class="view" id="attack">(.*?)</section>', 'Singleline').Groups[1].Value
        $attack | Should -Match '<button type="button" class="fold-toggle" data-fold="details\.attack-tactic" aria-expanded="false">Open all</button>'
        $tactics = [regex]::Matches($attack, '<details class="attack-tactic" id="attack-([a-z-]+)"><summary><span class="area-name">[^<]+</span><span class="muted tech">TA\d{4}</span><span class="hint">(\d+) of (\d+) covered[^<]*</span></summary><ul>')
        $tactics.Count | Should -BeGreaterThan 8
        foreach ($t in $tactics) { $attack | Should -Match ('<a class="pillar" href="#attack-' + $t.Groups[1].Value + '">') -Because 'each bar leads to its section' }
        $attack | Should -Not -Match '<details class="attack-tactic"[^>]* open'
        $script:Page | Should -Match "el\.tagName === 'DETAILS'" -Because 'a link to a folded section opens it'
    }
}
