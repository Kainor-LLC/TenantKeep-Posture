# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
}

Describe 'Report charts' {
    It 'draws a donut: one arc per part above zero, the total in the centre, every part in the legend and the table' {
        InModuleScope TenantKeep.Posture {
            $svg = ConvertTo-PostureDonutChart -Name 'Device compliance' -CenterLabel 'devices' -Segment @(@{ label = 'Compliant'; value = 1284; tone = 'ok' }, @{ label = 'Noncompliant'; value = 16; tone = 'err' }, @{ label = 'Unknown'; value = 0; tone = 'na' })
            ([regex]::Matches($svg, '<circle class="t-')).Count | Should -Be 2 -Because 'a part at zero draws nothing'
            $svg | Should -Match 'class="center-value">1,300<'
            $svg | Should -Match '<title>Compliant: 1,284 \(99%\)</title>'
            $svg | Should -Match 'Unknown <strong>0</strong>' -Because 'the legend keeps the empty part'
            $svg | Should -Match '<details class="chart-table">'
            $svg | Should -Match 'aria-label="Device compliance\. Compliant 1284, Noncompliant 16, Unknown 0\. Total 1300\."'
        }
    }

    It 'lays out a sankey: node heights follow their values, bands per flow, labels outside the nodes' {
        InModuleScope TenantKeep.Posture {
            $svg = ConvertTo-PostureSankeyChart -Name 'Users by method' -Height 200 -Column @(
                , @(@{ id = 'all'; label = 'All users'; tone = 'c1' })
                @(@{ id = 'pr'; label = 'Phishing-resistant'; tone = 'ok' }, @{ id = 'ph'; label = 'Phishable'; tone = 'warn' }, @{ id = 'no'; label = 'No MFA'; tone = 'err' })
            ) -Flow @(@{ from = 'all'; to = 'pr'; value = 30 }, @{ from = 'all'; to = 'ph'; value = 60 }, @{ from = 'all'; to = 'no'; value = 10 }, @{ from = 'all'; to = 'x'; value = 0 })
            ([regex]::Matches($svg, '<path class="band')).Count | Should -Be 3 -Because 'a flow at zero draws nothing'
            $h = @{}; foreach ($m in [regex]::Matches($svg, '<rect class="node t-\w+" x="[\d.]+" y="[\d.]+" width="10" height="([\d.]+)" rx="2"><title>([^:]+):')) { $h[$m.Groups[2].Value] = [double]$m.Groups[1].Value }
            [Math]::Round($h['Phishable'] / $h['Phishing-resistant'], 1) | Should -Be 2.0
            $h['All users'] | Should -BeGreaterThan $h['Phishable']
            $svg | Should -Match 'text-anchor="end" class="node-label">All users <tspan class="node-value">100</tspan>'
            $svg | Should -Match 'text-anchor="start" class="node-label">No MFA'
        }
    }

    It 'draws layered rings with the layers listed in words, so the colour is never the only signal' {
        InModuleScope TenantKeep.Posture {
            $svg = ConvertTo-PostureRingChart -Name 'Email protection' -Layer @(@{ label = 'Sender authentication'; passed = 3; total = 3; status = 'pass' }, @{ label = 'Filtering'; passed = 1; total = 4; status = 'partial' }, @{ label = 'Post-delivery'; passed = 0; total = 2; status = 'fail' })
            ([regex]::Matches($svg, 'class="track"')).Count | Should -Be 3
            ([regex]::Matches($svg, 'stroke-linecap="round"')).Count | Should -Be 2 -Because 'a layer with nothing passing shows only its track'
            $svg | Should -Match 'Partly, 1 of 4'
            $svg | Should -Match 'Missing, 0 of 2'
        }
    }

    It 'labels a bar block only where the label fits, and encodes every label' {
        InModuleScope TenantKeep.Posture {
            $svg = ConvertTo-PostureBarChart -Segment @(@{ label = 'Pass <b>'; value = 95; tone = 'ok' }, @{ label = 'Fail'; value = 5; tone = 'err' })
            $svg | Should -Match '>95</span>'
            $svg | Should -Not -Match '>5</span>' -Because 'a block under 8% has no room for its number'
            $svg | Should -Not -Match '<b>'
            $svg | Should -Match 'Pass &lt;b&gt;'
            ConvertTo-PostureBarChart -Thin -Segment @(@{ label = 'a'; value = 1; tone = 'ok' }) | Should -Not -Match 'chart-table'
        }
    }

    It 'frames a chart with its takeaway and a link into the checks behind it' {
        InModuleScope TenantKeep.Posture {
            $card = ConvertTo-PostureChartCard -Title 'Devices' -Takeaway '99% of devices are compliant.' -Body '<svg></svg>' -ViewAllDomain 'devices'
            $card | Should -Match '<p class="takeaway">99% of devices are compliant\.</p>'
            $card | Should -Match 'data-filter-domain="devices"'
            Format-PostureChartNumber 12900 | Should -Be '12.9K'
            Format-PostureChartNumber 1284 | Should -Be '1,284'
        }
    }
}
