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


    It 'draws the device flows in the same order every time: the largest first, equal ones by name' {
        # The tallies are plain hashtables, whose own order changes between PowerShell processes.
        $ev = Join-Path $TestDrive 'flow-order'
        New-Item -ItemType Directory -Path $ev | Out-Null
        $device = { param([string] $Os, [string] $Join, [string] $State, [int] $Count) 1..$Count | ForEach-Object { @{ OperatingSystem = $Os; JoinType = $Join; ComplianceState = $State; ManagedDeviceOwnerType = 'company' } } }
        $rows = @(& $device 'macOS' '' 'compliant' 2) + @(& $device 'Android' '' 'noncompliant' 1) + @(& $device 'Windows' 'azureADJoined' 'compliant' 3) + @(& $device 'iOS' '' 'compliant' 2)
        ConvertTo-Json -InputObject $rows -Depth 4 | Set-Content (Join-Path $ev '09-intune-managed-devices.json')
        $d = InModuleScope TenantKeep.Posture -Parameters @{ Ev = $ev } { param($Ev) Clear-PostureEvidenceCache; Get-PostureChartData -Evidence $Ev -Admin @() }
        @($d.devices.flow | ForEach-Object { "$($_.from) > $($_.to): $($_.value)" }) | Should -Be @(
            'p-Windows > j-Entra joined: 3'
            'p-iOS > j-Join type not reported: 2'
            'p-macOS > j-Join type not reported: 2'
            'p-Android > j-Join type not reported: 1'
            'j-Join type not reported > c-Compliant: 4'
            'j-Entra joined > c-Compliant: 3'
            'j-Join type not reported > c-Not compliant: 1'
        )
    }
    It 'builds the chart numbers from summaries, with takeaways in words, and leaves out what was not collected' {
        $ev = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-chartdata-$([guid]::NewGuid().ToString('n'))"
        New-Item -ItemType Directory -Path $ev | Out-Null
        try {
            '{ "Members": 1000, "Guests": 40 }' | Set-Content (Join-Path $ev '06-users-summary.json')
            '{ "StrongestMethod": { "PhishingResistant": 320, "Passwordless": 10, "Authenticator": 470, "PhoneOnly": 130, "None": 70 } }' | Set-Content (Join-Path $ev '05-auth-registration-summary.json')
            '{ "SignIns": 1000, "Days": 30, "ByDay": { "11/15/2026": 9, "2026-11-18": 4 }, "ByCountry": { "US": 900, "GB": 100 }, "CaByMfa": { "caApplied|mfa": 700, "caApplied|singleFactor": 100, "noCa|singleFactor": 200 }, "DeviceTrust": { "managedCompliant": 600, "unmanaged": 400 } }' | Set-Content (Join-Path $ev '06-signins-summary.json')
            '[ { "OperatingSystem": "Windows", "JoinType": "azureADJoined", "ComplianceState": "compliant", "ManagedDeviceOwnerType": "company" }, { "OperatingSystem": "Windows", "JoinType": "hybridAzureADJoined", "ComplianceState": "noncompliant", "ManagedDeviceOwnerType": "company" }, { "OperatingSystem": "iOS", "JoinType": "unknown", "ComplianceState": "compliant", "ManagedDeviceOwnerType": "personal" } ]' | Set-Content (Join-Path $ev '09-intune-managed-devices.json')
            $d = InModuleScope TenantKeep.Posture -Parameters @{ Ev = $ev } {
                param($Ev)
                Clear-PostureEvidenceCache
                Get-PostureChartData -Evidence $Ev -Admin @(@{ type = 'user'; strongestMethod = 'Phishing-resistant' }, @{ type = 'user'; strongestMethod = 'Windows Hello for Business' }, @{ type = 'user'; strongestMethod = 'Phone' }, @{ type = 'servicePrincipal'; strongestMethod = 'n/a' })
            }
            $d.authUsers.takeaway | Should -Be '32% of the 1,000 members in the registration report have a phishing-resistant method; 7% have no MFA method at all.'
            ($d.authUsers.flow | Where-Object { $_.from -eq 'all' -and $_.to -eq 'ph' }).value | Should -Be 610
            $d.authAdmins.takeaway | Should -Be '2 of 3 administrators have a device-bound phishing-resistant method.' -Because 'Windows Hello counts, and a service principal is not a person'
            $d.signInCa.takeaway | Should -Be 'Over the last 30 days, 70% of successful sign-ins went through Conditional Access with MFA; 20% had neither.'
            $d.signInDevice.takeaway | Should -Match '^60% of successful sign-ins came from a managed, compliant device; 40%'
            $d.devices.takeaway | Should -Be '67% of 3 managed devices are compliant.'
            ($d.devices.column[0] | Where-Object { $_.label -eq 'iOS' }).tone | Should -Be 'c3' -Because 'a platform keeps its slot whatever its rank'
            @($d.devices.column[1]).label | Should -Contain 'Join type not reported'
            $d.ownership.takeaway | Should -Be '33% of managed devices are personally owned.'
            @($d.tiles).label | Should -Be @('Members', 'Managed devices', 'Sign-ins read')
            @($d.signInsByDay.point.label) | Should -Be @('11-15', '11-16', '11-17', '11-18') -Because 'quiet days are zero, and both date shapes read'
            @($d.signInsByDay.point.value) | Should -Be @(9, 0, 0, 4)
            $d.signInCountries.item[0].label | Should -Be 'US'
            $d.Contains('compliance') | Should -BeFalse -Because 'the compliance summary was not collected'
            $d.Contains('antivirus') | Should -BeFalse
        }
        finally { Remove-Item -LiteralPath $ev -Recurse -Force }
    }

    It 'draws ranked bars largest first unless told to keep the order, with the value at each tip' {
        InModuleScope TenantKeep.Posture {
            $svg = ConvertTo-PostureRankedBarChart -Name 'Countries' -Item @(@{ label = 'US'; value = 10 }, @{ label = 'GB'; value = 40 }, @{ label = 'DE'; value = 20 })
            ([regex]::Matches($svg, 'class="rbar-label">(\w+)<') | ForEach-Object { $_.Groups[1].Value }) | Should -Be @('GB', 'DE', 'US')
            $svg | Should -Match 'style="width:100%"' -Because 'the largest bar spans the track'
            $kept = ConvertTo-PostureRankedBarChart -KeepOrder -Item @(@{ label = 'Critical'; value = 1 }, @{ label = 'High'; value = 5 })
            ([regex]::Matches($kept, 'class="rbar-label">(\w+)<') | ForEach-Object { $_.Groups[1].Value }) | Should -Be @('Critical', 'High')
        }
    }

    It 'draws a line over time with the last value labelled, and no line for a single point' {
        InModuleScope TenantKeep.Posture {
            $svg = ConvertTo-PostureLineChart -Percent -Point @(@{ label = '2026-10-01'; value = 50 }, @{ label = '2026-11-01'; value = 62 }, @{ label = 'now'; value = 70 })
            $svg | Should -Match '<path class="line" d="M'
            ([regex]::Matches($svg, '<circle class="dot"')).Count | Should -Be 3
            $svg | Should -Match 'class="end-label"[^>]*>70<'
            ConvertTo-PostureLineChart -Point @(@{ label = 'now'; value = 5 }) | Should -Not -Match 'class="line"'
        }
    }

    It 'draws the score ring with the change, the target and the projected score' {
        InModuleScope TenantKeep.Posture {
            $svg = ConvertTo-PostureScoreRing -Value 62 -Delta 4 -Projected 67 -Target 80 -Grade 'D'
            $svg | Should -Match 'class="ring-value">62<'
            $svg | Should -Match '\+4 since the last run'
            $svg | Should -Match '67 with the top five fixes'
            $svg | Should -Match '<line class="target"'
            ConvertTo-PostureScoreRing -Value 62 -Delta $null | Should -Match 'first run'
        }
    }

    It 'scores earlier runs of the same tenant for the trend, oldest first, and ignores other tenants' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-history-$([guid]::NewGuid().ToString('n'))"
        try {
            InModuleScope TenantKeep.Posture -Parameters @{ Root = $root } {
                param($Root)
                $mk = {
                    param([string] $Name, [string] $Started, [string] $Tenant, [string[]] $Status)
                    $l = New-PostureRunFolder -OutRoot $Root -Name $Name -Confirm:$false
                    @{ tenantId = $Tenant; startedUtc = $Started } | ConvertTo-Json | Set-Content (Join-Path $l.logs 'run.json')
                    @{ results = @($Status | ForEach-Object { @{ status = $_; severity = 'High' } }) } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $l.logs 'checks.json')
                    $l
                }
                $null = & $mk 'a' '2026-09-01T00:00:00Z' 't1' @('pass', 'fail')
                $null = & $mk 'b' '2026-10-01T00:00:00Z' 't2' @('fail', 'fail')
                $null = & $mk 'c' '2026-11-01T00:00:00Z' 't1' @('pass', 'pass', 'pass', 'fail')
                $now = & $mk 'd' '2026-11-20T00:00:00Z' 't1' @('pass')
                $h = @(Get-PostureScoreHistory -Run $now.root)
                @($h.value) | Should -Be @(50, 75)
                @($h.label) | Should -Be @('2026-09-01', '2026-11-01')
            }
        }
        finally { if (Test-Path $root) { Remove-Item -LiteralPath $root -Recurse -Force } }
    }

    It 'draws a heatmap with every count printed and the darkest cell for the largest, and a sparkline only with two points' {
        InModuleScope TenantKeep.Posture {
            $hm = ConvertTo-PostureHeatmap -Row 'Confidential', 'No label' -Column 'Org', 'Anyone' -Cell @{ 'Confidential|Anyone' = 2; 'No label|Org' = 10 }
            ([regex]::Matches($hm, '<td class="hm')).Count | Should -Be 4 -Because 'a cell with nothing still shows 0'
            $hm | Should -Match 'class="hm dark" style="--hm:90%"[^>]*>10<'
            $hm | Should -Match 'title="Confidential, Anyone: 2">2<'
            ConvertTo-PostureSparkline -Value 50, 62, 70 | Should -Match '<path d="M'
            ConvertTo-PostureSparkline -Value 50 | Should -BeNullOrEmpty
        }
    }

    It 'builds the sensitivity heatmap from the site list and the most exposed sites from an imported report' {
        $ev = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-exposure-$([guid]::NewGuid().ToString('n'))"
        New-Item -ItemType Directory -Path $ev | Out-Null
        try {
            '[ { "Title": "Board", "SensitivityLabel": "g1", "SharingCapability": "ExternalUserAndGuestSharing" }, { "Title": "Team", "SensitivityLabel": "", "SharingCapability": "Disabled" }, { "Title": "OD", "IsOneDrive": true, "SensitivityLabel": "", "SharingCapability": "ExternalUserAndGuestSharing" } ]' | Set-Content (Join-Path $ev 'spo-sites.json')
            '[ { "Guid": "g1", "DisplayName": "Highly Confidential" } ]' | Set-Content (Join-Path $ev 'pv-01-sensitivity-labels.json')
            '{ "exposedSites": 2, "top": [ { "url": "https://contoso.sharepoint.com/sites/board", "name": "Board Papers", "anyone": 3, "org": 1, "eeeu": 0, "everyone": 0 }, { "url": "https://contoso.sharepoint.com/sites/x", "name": "", "anyone": 0, "org": 0, "eeeu": 2, "everyone": 0 } ] }' | Set-Content (Join-Path $ev 'spo-dag-site-permissions.json')
            $d = InModuleScope TenantKeep.Posture -Parameters @{ Ev = $ev } { param($Ev) Clear-PostureEvidenceCache; Get-PostureChartData -Evidence $Ev }
            @($d.sensitivityExposure.rows) | Should -Be @('Highly Confidential', 'No label')
            $d.sensitivityExposure.cells['Highly Confidential|Anyone'] | Should -Be 1
            $d.sensitivityExposure.takeaway | Should -Be '1 labelled site(s) allow Anyone links; 1 site(s) carry no label.' -Because 'OneDrive is left out'
            $d.topExposed.sites[0].name | Should -Be 'Board Papers'
            $d.topExposed.sites[1].name | Should -Be 'https://contoso.sharepoint.com/sites/x' -Because 'a site without a name shows its address'
            $red = InModuleScope TenantKeep.Posture -Parameters @{ D = $d } { param($D) (ConvertTo-PostureRedactedReport -Report @{ charts = $D; results = @(); catalogText = @{}; admins = @(); tenantId = $null; tenantName = $null; clientName = $null }).report }
            ($red | ConvertTo-Json -Depth 20) | Should -Not -Match 'Board Papers' -Because 'site names are the tenant''s own'
        }
        finally { Remove-Item -LiteralPath $ev -Recurse -Force }
    }
}

