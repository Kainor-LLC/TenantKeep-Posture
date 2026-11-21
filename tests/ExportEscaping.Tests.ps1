# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Names in a report come from the tenant, and some from outside it: a guest chooses their own display name. These
# tests put hostile names through every export a person opens: the affected lists, findings.csv, the page's own CSV
# export and the JSON the page embeds.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-escape-$([guid]::NewGuid().ToString('n'))"
    $script:Ev = Initialize-CollectionFixture -Root (Join-Path $script:Root 'evidence')
    @{ tenantId = 'tenant-guid'; account = 'reader@contoso.example'; collectors = @('Entra'); timestampUtc = '2026-10-14T01:00:00Z' } | ConvertTo-Json | Set-Content (Join-Path $script:Ev 'collection.json')

    # Two Global Administrators with names chosen to attack a spreadsheet and the page.
    $script:Formula = '=HYPERLINK("http://attacker.example/x","Open")'
    $script:Markup = '<!--<script>alert(1)</script> & "quoted"'
    $path = Join-Path $script:Ev '04-role-assignments-active.json'
    $rows = @(Get-Content -Raw -LiteralPath $path | ConvertFrom-Json -AsHashtable)
    $admins = @($rows | Where-Object { $_['Role'] -eq 'Global Administrator' -and $_['PrincipalName'] -ne 'BreakGlass-01' })
    $admins[0]['PrincipalName'] = $script:Formula
    $admins[1]['PrincipalName'] = $script:Markup
    ConvertTo-Json -InputObject $rows -Depth 10 | Set-Content -LiteralPath $path

    $script:Out = Join-Path $script:Root 'out'
    $script:R = New-PostureReport -Evidence $script:Ev -OutputPath $script:Out -PassThru
}

AfterAll {
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
}

Describe 'ConvertTo-PostureCsvSafeText' {
    It 'puts an apostrophe before <Why>' -ForEach @(
        @{ Why = 'an equals sign'; Text = '=1+1' }
        @{ Why = 'a plus'; Text = '+1+1' }
        @{ Why = 'a minus'; Text = '-2+3' }
        @{ Why = 'an at sign'; Text = '@SUM(A1:A9)' }
        @{ Why = 'a tab'; Text = "`t=1+1" }
        @{ Why = 'a carriage return'; Text = "`r=1+1" }
    ) {
        InModuleScope TenantKeep.Posture -Parameters @{ Text = $Text } { ConvertTo-PostureCsvSafeText $Text | Should -Be ("'" + $Text) }
    }

    It 'leaves <Text> alone' -ForEach @(
        @{ Text = 'megan@contoso.example' }
        @{ Text = 'DESKTOP-01, Windows 10.0.19045' }
        @{ Text = 'a = b' }
        @{ Text = '' }
    ) {
        InModuleScope TenantKeep.Posture -Parameters @{ Text = $Text } { ConvertTo-PostureCsvSafeText $Text | Should -Be $Text }
    }

    It 'keeps numbers and dates as they are in a row, and only changes text' {
        InModuleScope TenantKeep.Posture {
            $row = [pscustomobject]@{ Name = '=cmd'; Affected = 12; When = [datetime]'2026-11-21' } | ConvertTo-PostureCsvSafeRow
            $row.Name | Should -Be "'=cmd"
            $row.Affected | Should -Be 12
            $row.When | Should -BeOfType ([datetime])
        }
    }
}

Describe 'Exports a person opens in a spreadsheet' {
    It 'writes the affected list with no cell that starts a formula' {
        $csv = Join-Path $script:Out 'affected' 'ID-001.csv'
        Test-Path -LiteralPath $csv | Should -BeTrue
        $names = @(Import-Csv -LiteralPath $csv | ForEach-Object { $_.Name })
        $names | Should -Contain ("'" + $script:Formula)
        foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:Out 'affected') -Filter '*.csv') {
            foreach ($row in Import-Csv -LiteralPath $f.FullName) {
                foreach ($cell in $row.PSObject.Properties.Value) { [string]$cell | Should -Not -Match '^[=+\-@\t\r]' -Because "$($f.Name) is opened in a spreadsheet" }
            }
        }
    }

    It 'writes findings.csv the same way, and hands -PassThru the rows unchanged' {
        # A custom check may carry any title; make one start a formula.
        $checks = Join-Path $script:Out 'checks.json'
        $run = Get-Content -Raw -LiteralPath $checks | ConvertFrom-Json -AsHashtable -Depth 20
        $failing = @($run['results'] | Where-Object { $_['status'] -eq 'fail' })[0]
        $failing['title'] = '=1+1 custom check'
        ConvertTo-Json -InputObject $run -Depth 20 | Set-Content -LiteralPath $checks
        $out = Join-Path $script:Root 'findings.csv'
        $rows = @(Export-PostureFindings -Path $checks -OutputPath $out -PassThru)
        @($rows | Where-Object { $_.Finding -like '=1+1 custom check*' }).Count | Should -Be 1
        $written = @(Import-Csv -LiteralPath $out)
        @($written | Where-Object { $_.Finding -like "'=1+1 custom check*" }).Count | Should -Be 1
        foreach ($row in $written) { foreach ($cell in $row.PSObject.Properties.Value) { [string]$cell | Should -Not -Match '^[=+\-@\t\r]' } }
    }

    It 'guards the page''s own CSV export' {
        $js = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '..' 'templates' 'report.js')
        $fn = [regex]::Match($js, '(?m)^\s*function toCsv\(headers, list\) \{.*\}\s*$').Value.Trim()
        $fn | Should -Not -BeNullOrEmpty
        $fn | Should -Match ([regex]::Escape('/^[=+\-@\t\r]/')) -Because 'a name exported from the page must not start a formula either'
        $node = Get-Command node -ErrorAction SilentlyContinue
        if (-not $node) { return }
        $script = Join-Path $script:Root 'tocsv.js'
        Set-Content -LiteralPath $script -Value ($fn + "`nprocess.stdout.write(toCsv(['Name', 'Detail'], [['=1+1', 'ok'], ['plain', '-5'], [null, 'say `"hi`"']]));")
        $text = (& $node.Source $script) -join "`n"
        $text | Should -Match ([regex]::Escape('"''=1+1","ok"'))
        $text | Should -Match ([regex]::Escape('"plain","''-5"'))
        $text | Should -Match ([regex]::Escape('"","say ""hi"""'))
    }
}

Describe 'The JSON the page embeds' {
    BeforeAll { $script:Html = Get-Content -Raw -LiteralPath (@($script:R.Files | Where-Object { $_ -like '*report.html' })[0]) }

    It 'never carries a raw angle bracket or ampersand from the data, so no name can open a comment or close the block' {
        $blocks = @([regex]::Matches($script:Html, '(?s)<script type="application/json" id="([^"]+)">(.*?)</script>'))
        $blocks.Count | Should -BeGreaterThan 2
        foreach ($b in $blocks) { $b.Groups[2].Value | Should -Not -Match '[<>&]' -Because "block $($b.Groups[1].Value) is inside a script element" }
    }

    It 'still hands the page the names exactly as they are' {
        $block = [regex]::Match($script:Html, '(?s)<script type="application/json" id="data-results">(.*?)</script>').Groups[1].Value
        $results = $block | ConvertFrom-Json -AsHashtable -Depth 20
        $names = @(@($results | Where-Object { $_['id'] -eq 'ID-001' })[0]['affected'] | ForEach-Object { $_['name'] })
        $names | Should -Contain $script:Markup
        $names | Should -Contain $script:Formula
    }

    It 'shows the hostile name as text in the rendered views' {
        $script:Html | Should -Not -Match ([regex]::Escape('<!--<script>alert(1)'))
        $script:Html | Should -Match ([regex]::Escape('&lt;!--&lt;script&gt;alert(1)'))
    }
}
