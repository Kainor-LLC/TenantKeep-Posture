# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
    InModuleScope Tenantkeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-report-$([guid]::NewGuid().ToString('n'))"
    $script:Ev = Initialize-CollectionFixture -Root (Join-Path $script:Root 'evidence')
    # The CA snapshot sits in the same folder, as Invoke-PostureCollection writes it.
    Copy-Item -Path (Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot' '*.json') -Destination $script:Ev
    @{ tenantId = 'tenant-guid'; account = 'reader@contoso.example'; collectors = @('ConditionalAccess', 'Entra'); timestampUtc = '2026-10-14T01:00:00Z'; scopes = @('Directory.Read.All'); graphApiVersions = @('v1.0'); errors = @('Hybrid sync features :: Forbidden') } | ConvertTo-Json | Set-Content (Join-Path $script:Ev 'collection.json')
    @(@{ id = 'tenant-guid'; displayName = 'Contoso' }) | ConvertTo-Json | Set-Content (Join-Path $script:Ev '01-organization.json')
    $script:Client = Join-Path $script:Root 'client'
    New-Item -ItemType Directory -Path $script:Client | Out-Null
    @{ preparedBy = @{ name = 'Example MSP' }; client = @{ name = 'Contoso Ltd' }; footer = 'Prepared by Example MSP' } | ConvertTo-Json | Set-Content (Join-Path $script:Client 'brand.json')
    $null = New-PostureProfile -Path (Join-Path $script:Client 'profile.json') -NonInteractive -Licenses P1, P2 -Platforms windows, macOS -BreakGlass 'breakglass01@contoso.example' -Thresholds @{ namePattern = '^CA-\d{3}-' }
    @(@{ check = 'ID-013'; justification = 'Open collaboration by policy'; owner = 'CISO'; approver = 'CISO'; expires = '2027-12-31' }) | ConvertTo-Json | Set-Content (Join-Path $script:Client 'exceptions.json')
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
}

Describe 'New-PostureReport' {
    Context 'full template with a client folder' {
        BeforeAll {
            $script:R = New-PostureReport -Evidence $script:Ev -Client $script:Client -OutputPath (Join-Path $script:Root 'out') -PassThru
            $script:Md = Get-Content -Raw -LiteralPath ($script:R.Files | Where-Object { $_ -like '*report.md' })
            $script:Rep = $script:R.Report
        }

        It 'writes checks.json, report.html and report.md' {
            @($script:R.Files | ForEach-Object { Split-Path $_ -Leaf } | Sort-Object) | Should -Be @('checks.json', 'report.html', 'report.md')
            (Get-Content -Raw (Join-Path $script:Root 'out' 'checks.json') | ConvertFrom-Json).results.Count | Should -Be 204
        }

        It 'scores with the stated method and grades it' {
            $s = $script:Rep.score
            $s.possible | Should -BeGreaterThan 0
            $s.value | Should -Be ([Math]::Round(100.0 * $s.earned / $s.possible))
            $s.grade | Should -BeIn @('A', 'B', 'C', 'D', 'F')
            $s.method | Should -Match 'Critical 4, High 3, Medium 2, Low 1'
            $script:Md | Should -Match "\*\*Posture score $($s.value) \($($s.grade)\)\.\*\*"
        }

        It 'computes headline numbers from the same run and marks the rest not collected' {
            $h = $script:Rep.headline
            $h.mfaRegisteredPct | Should -Be 75
            $h.adminsPhishingResistantPct | Should -Be 40
            $h.permanentGlobalAdmins | Should -Be 4
            $h.intuneCompliancePct | Should -BeNullOrEmpty
            $script:Md | Should -Match '\| 75% \| 40% \| 4 \| not collected yet \| not collected yet \| not collected yet \|'
        }

        It 'has one scorecard per collected domain and names the rest' {
            @($script:Rep.domains | ForEach-Object { $_.key }) | Should -Be @('identity', 'auth', 'ca', 'governance', 'operations') -Because 'governance and operations evaluate partly from the identity evidence'
            ($script:Rep.domains | Where-Object key -eq 'ca').checks[0].status | Should -Be 'fail' -Because 'failures sort first'
            $script:Rep.domainsNotCollected.label | Should -Contain 'Devices'
            $script:Md | Should -Match '### Identity and privileged access'
            $script:Md | Should -Match 'Not collected yet: Devices, Endpoint security'
        }

        It 'lists top risks by severity and buckets recommendations' {
            $script:Rep.topRisks.Count | Should -Be 5
            $script:Rep.topRisks[0].severity | Should -Be 'Critical'
            $script:Rep.recommendations['Stop the bleeding'].id | Should -Contain 'CA-002'
            $script:Rep.recommendations['Later'].id | Should -Contain 'CA-014'
            $script:Md | Should -Match '### Stop the bleeding'
            $script:Md | Should -Match '\*\*CA-002 MFA required for all users\*\* \(Critical, ca, needs P1\)'
        }

        It 'applies the client folder: brand, profile and exceptions' {
            $script:Rep.title | Should -Be 'Microsoft security posture report: Contoso Ltd'
            $script:Md | Should -Match 'Prepared by Example MSP for Contoso Ltd\.'
            ($script:Rep.results | Where-Object id -eq 'ID-013').status | Should -Be 'acceptedRisk'
            ($script:Rep.results | Where-Object id -eq 'CA-015').status | Should -Be 'fail' -Because 'the profile name pattern reached the CA facts'
            $script:Rep.appendix.profileAnswers.licenses | Should -Be @('P1', 'P2')
            $script:Md | Should -Match '\| ID-013 \|  \| Open collaboration by policy \| CISO \| CISO \| 2027-12-31 \| no \|'
        }

        It 'builds the admins table from roles, registration and users' {
            $a = $script:Rep.admins
            $a.Count | Should -Be 6
            $ga = $a | Where-Object upn -eq 'admin2@contoso.example'
            $ga.permanent | Should -Be @('Global Administrator')
            $ga.strongestMethod | Should -Be 'Phishing-resistant'
            $ga.synced | Should -BeTrue
            ($a | Where-Object upn -eq 'admin3@contoso.example').eligible | Should -Be @('Security Administrator')
            ($a | Where-Object type -eq 'servicePrincipal').strongestMethod | Should -Be 'n/a'
            $script:Md | Should -Match '\| Admin Two \| user \| Global Administrator \|  \| Phishing-resistant \| 2026-10-01 \| yes \| 0 \|'
        }

        It 'includes the CA matrix and the appendix with evidence index and errors' {
            $script:Rep.ca.policies.Count | Should -Be 8
            $script:Md | Should -Match '\| Policy \| All users \| Admin roles \|'
            $script:Md | Should -Match '### Evidence index'
            $script:Md | Should -Match '`04-role-assignments-active.json`'
            $script:Md | Should -Match '- Hybrid sync features :: Forbidden'
            $script:Rep.appendix.notEvaluated.id | Should -Contain 'ID-014'
        }
    }

    Context 'Html' {
        BeforeAll { $script:Html = Get-Content -Raw -LiteralPath ($script:R.Files | Where-Object { $_ -like '*report.html' }) }

        It 'is one self-contained file: inline CSS and JS, no remote resources, data embedded as JSON' {
            $script:Html | Should -Match '^<!DOCTYPE html>'
            $script:Html | Should -Match '<style>'
            $script:Html | Should -Match '<script>'
            $script:Html | Should -Not -Match '(src|<link[^>]*href)="https?://'
            $script:Html | Should -Not -Match '<script[^>]*src='
            $script:Html | Should -Match "default-src 'none'"
            $results = [regex]::Match($script:Html, '<script type="application/json" id="data-results">(.*?)</script>').Groups[1].Value | ConvertFrom-Json
            $results.Count | Should -Be 204
            $catalog = [regex]::Match($script:Html, '<script type="application/json" id="data-catalog">(.*?)</script>').Groups[1].Value | ConvertFrom-Json
            $catalog.'CA-002'.remediation | Should -Not -BeNullOrEmpty
        }

        It 'renders every view server-side with the navigation' {
            foreach ($id in 'overview', 'domains', 'checks', 'admins', 'exposure', 'copilot', 'ca', 'recommendations', 'trend', 'licensing', 'appendix') {
                $script:Html | Should -Match "<section class=`"view( active)?`" id=`"$id`""
                $script:Html | Should -Match "<a href=`"#$id`""
            }
            $script:Html | Should -Match '<section class="view active" id="overview">'
            $script:Html | Should -Match 'Not collected yet\.'
            ([regex]::Matches($script:Html, '<tr data-check="')).Count | Should -BeGreaterThan 39 -Because 'rows appear in the scorecards and the explorer'
            $script:Html | Should -Match '<button type="button" id="toggle-exec"'
            $script:Html | Should -Match 'class="tech"'
            $script:Html | Should -Match '@media print'
            $script:Html | Should -Match '<aside id="drawer"'
        }

        It 'encodes brand text and keeps the executive template flag on the body' {
            $script:Html | Should -Match '<body data-template="Full">'
            $script:Html | Should -Match 'Prepared by Example MSP for Contoso Ltd\.'
            $script:Html | Should -Match '<footer class="doc">Prepared by Example MSP</footer>'
            $script:Html | Should -Match '<td class="on">Phishing-resistant MFA</td>'
        }
    }

    Context 'Pdf' {
        It 'prints the HTML through a headless browser' {
            Mock -ModuleName Tenantkeep.Posture Find-PostureHeadlessBrowser { '/fake/msedge' }
            Mock -ModuleName Tenantkeep.Posture Start-Process {
                $pdf = ($ArgumentList | Where-Object { $_ -like '--print-to-pdf=*' }) -replace '^--print-to-pdf=', ''
                Set-Content -LiteralPath $pdf -Value '%PDF-1.7 fake'
                [pscustomobject]@{ ExitCode = 0 }
            }
            $r = New-PostureReport -Evidence $script:Ev -Format Pdf -OutputPath (Join-Path $script:Root 'pdf') -PassThru
            @($r.Files | ForEach-Object { [System.IO.Path]::GetExtension($_) } | Sort-Object) | Should -Be @('.html', '.json', '.pdf')
        }
    }

    Context 'executive template and edge cases' {
        It 'hides technical columns in the executive template' {
            $r = New-PostureReport -Evidence $script:Ev -Template Executive -OutputPath (Join-Path $script:Root 'exec') -PassThru
            $md = Get-Content -Raw -LiteralPath ($r.Files | Where-Object { $_ -like '*report.md' })
            (Get-Content -Raw -LiteralPath ($r.Files | Where-Object { $_ -like '*report.html' })) | Should -Match '<body data-template="Executive">'
            $md | Should -Match '\| Check \| Title \| Status \| Severity \|\n'
            $md | Should -Not -Match '\| Check \| Title \| Status \| Severity \| License \| Detail \|'
            $md | Should -Match 'Executive template'
            $r.Report.clientName | Should -Be 'Contoso' -Because 'without a brand or profile the organization display name is used'
        }

        It 'works on a bare CA snapshot folder' {
            $snap = Join-Path $script:Root 'snap'
            Copy-Item -Path (Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot') -Destination $snap -Recurse
            $r = New-PostureReport -Evidence $snap -PassThru
            @($r.Report.domains | ForEach-Object { $_.key }) | Should -Be @('ca')
            $r.Report.headline.mfaRegisteredPct | Should -BeNullOrEmpty
            $r.Report.admins.Count | Should -Be 0
            Get-Content -Raw -LiteralPath ($r.Files | Where-Object { $_ -like '*report.md' }) | Should -Match 'Role assignments were not collected'
        }

        It 'honours -WhatIf and rejects a missing folder' {
            New-PostureReport -Evidence $script:Ev -OutputPath (Join-Path $script:Root 'whatif') -WhatIf
            Join-Path $script:Root 'whatif' 'report.md' | Should -Not -Exist
            { New-PostureReport -Evidence (Join-Path $script:Root 'nope') } | Should -Throw '*Evidence folder not found*'
        }
    }
}

Describe 'Trend since a previous run' {
    It 'computes score deltas, new failures, resolved checks and moved affected counts from an earlier checks.json' {
        $prevPath = Join-Path $script:Root 'previous-checks.json'
        $current = Get-Content -Raw (Join-Path $script:Root 'out' 'checks.json') | ConvertFrom-Json -AsHashtable -Depth 20
        # Rewrite history: one failing check used to pass, one passing check used to fail, one failing check had fewer affected.
        $prev = $current
        $failing = @($prev.results | Where-Object { $_.status -eq 'fail' })
        $passing = @($prev.results | Where-Object { $_.status -eq 'pass' })
        $failing[0].status = 'pass'; $failing[0].affectedCount = 0
        $passing[0].status = 'fail'
        $failing[1].affectedCount = [int]$failing[1].affectedCount + 3
        $prev.checkedUtc = '2026-09-01T00:00:00Z'
        ConvertTo-Json -InputObject $prev -Depth 20 | Set-Content -LiteralPath $prevPath
        $r = New-PostureReport -Evidence $script:Ev -Previous $prevPath -Format Markdown, Html -OutputPath (Join-Path $script:Root 'trend') -PassThru
        $tr = $r.Report.trend
        $tr | Should -Not -BeNullOrEmpty
        @($tr.newFailures | ForEach-Object { $_.id }) | Should -Contain $failing[0].id
        @($tr.resolved | ForEach-Object { $_.id }) | Should -Contain $passing[0].id
        @($tr.affectedMoved | ForEach-Object { $_.id }) | Should -Contain $failing[1].id
        @($tr.domains).Count | Should -Be @($r.Report.domains).Count
        $tr.scoreBefore | Should -Not -BeNullOrEmpty
        $md = Get-Content -Raw (Join-Path $script:Root 'trend' 'report.md')
        $md | Should -Match '## Trend since 2026-09-01'
        $md | Should -Match 'Started failing'
        $html = Get-Content -Raw (Join-Path $script:Root 'trend' 'report.html')
        $html | Should -Match '<section class="view" id="trend"><h2>Trend since'
        $html | Should -Not -Match 'na-panel">Trend'
    }

    It 'refuses a missing previous run' {
        { New-PostureReport -Evidence $script:Ev -Previous (Join-Path $script:Root 'nope') -OutputPath (Join-Path $script:Root 'trend2') } | Should -Throw '*Previous checks.json not found*'
    }
}

Describe 'Framework baselines and the crosswalk' {
    It 'selects by framework reference and renders the crosswalk grouped by CSF function' {
        $r = New-PostureReport -Evidence $script:Ev -Baseline nist-csf-2 -Format Markdown, Html -OutputPath (Join-Path $script:Root 'csf') -PassThru
        $r.Report.crosswalk.framework | Should -Be 'nist-csf-2'
        @($r.Report.crosswalk.entries | ForEach-Object { $_.name }) | Should -Contain 'PR Protect'
        @($r.Report.crosswalk.entries | Where-Object { $_.name -eq 'PR Protect' })[0].checks.Count | Should -BeGreaterThan 5
        $md = Get-Content -Raw (Join-Path $script:Root 'csf' 'report.md')
        $md | Should -Match '## Framework crosswalk: nist-csf-2'
        $html = Get-Content -Raw (Join-Path $script:Root 'csf' 'report.html')
        $html | Should -Match '<section class="view" id="crosswalk">'
    }

    It 'maps the HIPAA safeguards through the CSF references' {
        $r = New-PostureReport -Evidence $script:Ev -Baseline hipaa -Format Markdown -OutputPath (Join-Path $script:Root 'hipaa') -PassThru
        $entry = @($r.Report.crosswalk.entries | Where-Object { $_.name -like '164.312(a)*' })
        $entry.Count | Should -Be 1
        $entry[0].checks.Count | Should -BeGreaterThan 0
        @($entry[0].checks | ForEach-Object { $_.reference } | Sort-Object -Unique) | Should -BeIn @('PR.AA-01', 'PR.AA-03', 'PR.AA-05')
    }

    It 'narrows the catalog to the Copilot gates and their feeders' {
        $run = Invoke-PostureChecks -Evidence $script:Ev -Baseline copilot-readiness -PassThru
        @($run.results | ForEach-Object { $_.domain } | Sort-Object -Unique) | Should -Contain 'copilot'
        @($run.results | Where-Object { $_.id -eq 'EM-001' }).Count | Should -Be 0
        $run.results.Count | Should -BeLessThan 60
    }
}

