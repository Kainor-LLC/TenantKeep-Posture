# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
    InModuleScope Tenantkeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Sample = Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot'
    $script:Out = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-doc-$([guid]::NewGuid().ToString('n'))"
    $script:Pattern = '^CA-\d{3}-(Admins|Users|Guests|WorkloadIDs)-.+$'
}

AfterAll {
    if (Test-Path $script:Out) { Remove-Item -LiteralPath $script:Out -Recurse -Force }
}

Describe 'New-PostureCaDocument' {
    Context 'default Markdown run with a name pattern' {
        BeforeAll {
            $script:Result = New-PostureCaDocument -Snapshot $script:Sample -OutputPath $script:Out -NamePattern $script:Pattern -PassThru
            $script:Md = Get-Content -Raw -LiteralPath $script:Result.Files[0]
        }

        It 'writes ca-document.md and ca-document.html into OutputPath by default' {
            $script:Result.Files.Count | Should -Be 2
            $script:Result.Files[0] | Should -Be (Join-Path $script:Out 'ca-document.md')
            $script:Result.Files[1] | Should -Be (Join-Path $script:Out 'ca-document.html')
            $script:Result.Files | Should -Exist
        }

        It 'renders the Coverage findings page from the engine with statuses and remediation' {
            $cov = $script:Result.Document.coverage
            $cov.run.results.Count | Should -Be 15
            ($cov.run.results | Where-Object id -eq 'CA-007').status | Should -Be 'fail'
            $script:Md | Should -Match '\| CA-007 \| Exclusion groups under the size threshold \| Fail \| High \| CA-Exclude-MFA-Legacy \|'
            $script:Md | Should -Match '\| CA-001 \| Legacy authentication blocked \| Pass \| Critical \|'
            $script:Md | Should -Match '### What to fix'
            $script:Md | Should -Match '\*\*CA-002 MFA required for all users\*\* \(Critical\)'
            $script:Md | Should -Match 'Remediation: .*\[Learn\]\(https://learn\.microsoft\.com/'
            ($cov.run.results | Where-Object id -eq 'CA-015').status | Should -Be 'fail' -Because 'the document name pattern flows into the checks and two sample policies break it'
            ($cov.run.results | Where-Object id -eq 'CA-015').affectedCount | Should -Be 2
        }

        It 'leaves the page out with -SkipChecks' {
            $r = New-PostureCaDocument -Snapshot $script:Sample -OutputPath (Join-Path $script:Out 'skip') -Format Markdown -SkipChecks -PassThru
            $r.Document.coverage | Should -BeNullOrEmpty
            Get-Content -Raw -LiteralPath $r.Files[0] | Should -Match 'Checks were skipped'
        }

        It 'passes exceptions through to the coverage page' {
            $ex = Join-Path $script:Out 'doc-exceptions.json'
            @(@{ check = 'CA-007'; object = 'CA-Exclude-MFA-Legacy'; justification = 'Legacy app'; owner = 'J. Smith'; approver = 'CISO'; expires = '2027-03-31' }) | ConvertTo-Json | Set-Content $ex
            $r = New-PostureCaDocument -Snapshot $script:Sample -OutputPath (Join-Path $script:Out 'exc') -Format Markdown -Exceptions $ex -PassThru
            ($r.Document.coverage.run.results | Where-Object id -eq 'CA-007').status | Should -Be 'acceptedRisk'
            Get-Content -Raw -LiteralPath $r.Files[0] | Should -Match '\| CA-007 \| .* \| Accepted risk \| High \| Accepted risk for 1 object'
        }

        It 'has every tenant-level section and one section per policy' -ForEach @(
            '## Summary', '## Health flags', '## Policy matrix', '## Naming convention', '## Coverage findings', '## Policies',
            '## Named locations', '## Authentication strengths', '## Authentication context', '## Appendix: snapshot',
            '### CA-001-Admins-Require phishing-resistant MFA', '### Block legacy authentication', '### Sign-in risk: require MFA (report-only pilot)'
        ) {
            $script:Md | Should -Match ([regex]::Escape($_))
        }

        It 'puts the plain-English summary under each policy' {
            $script:Md | Should -Match ([regex]::Escape('**Require Phishing-resistant MFA for users in Global Administrator and 2 other roles, all cloud apps, any platform. Excludes BreakGlass-01, BreakGlass-02.**'))
        }

        It 'renders names, never raw ids, in assignments' {
            $script:Md | Should -Match 'Exclude groups: CA-Exclude-ServiceAccounts \(12 members\), CA-Exclude-MFA-Legacy \(341 members\)'
            $script:Md | Should -Match 'Include roles: Global Administrator, Security Administrator, Exchange Administrator'
            $script:Md | Should -Match 'Allowed methods: fido2; windowsHelloForBusiness; x509CertificateMultiFactor'
        }

        It 'fills the matrix with the control applied per column' {
            $m = $script:Result.Document.matrix
            $m.columns.Count | Should -Be 8
            $row = $m.rows | Where-Object id -eq 'p-001'
            $row.cells.adminRoles | Should -Be 'Phishing-resistant MFA'
            $row.cells.allUsers | Should -Be ''
            $row.cells.guests | Should -Be ''
            $row.cells.allApps | Should -Be 'Phishing-resistant MFA'
            $row.cells.office365 | Should -Be 'Phishing-resistant MFA'
            $legacy = $m.rows | Where-Object id -eq 'p-003'
            $legacy.cells.allUsers | Should -Be 'Block'
            $legacy.cells.guests | Should -Be 'Block'
            $guests = $m.rows | Where-Object id -eq 'p-004'
            $guests.cells.guests | Should -Be 'MFA (report-only)'
            $guests.cells.allUsers | Should -Be ''
            $guests.cells.allApps | Should -Be ''
            $guests.cells.office365 | Should -Be 'MFA (report-only)'
            $wl = $m.rows | Where-Object id -eq 'p-006'
            $wl.cells.workloadIdentities | Should -Be 'Block (disabled)'
            $reg = $m.rows | Where-Object id -eq 'p-007'
            $reg.cells.registerSecurityInfo | Should -Be 'Block'
            $reg.cells.allApps | Should -Be ''
            $script:Md | Should -Match '\| Policy \| All users \| Admin roles \| Guests \| Workload identities \| All apps \| Office 365 \| Admin portals \| Register security info \|'
        }

        It 'lists non-conforming names with a proposed name' {
            $n = $script:Result.Document.naming
            $n.conforming.Count | Should -Be 6
            $n.nonConforming.Count | Should -Be 2
            ($n.nonConforming | Where-Object id -eq 'p-003').proposedName | Should -Be 'CA-008-Users-Block'
            ($n.nonConforming | Where-Object id -eq 'p-008').proposedName | Should -Be 'CA-009-Users-MFA'
            ($n.nonConforming | Where-Object id -eq 'p-008').matchesAfterRename | Should -BeTrue
            $script:Md | Should -Match '\| Block legacy authentication \| CA-008-Users-Block \|'
        }

        It 'reports health flag counts in the summary and the flag table' {
            $s = $script:Result.Document.stats
            $s.total | Should -Be 8
            $s.enabled | Should -Be 5
            $s.reportOnly | Should -Be 2
            $s.disabled | Should -Be 1
            $s.flagsError | Should -Be 2
            $script:Md | Should -Match '\| CA-005-Users-Require compliant device for Windows and macOS \| deletedReference \| error \|'
        }

        It 'uses the free-tier branding by default' {
            $script:Md | Should -Match '^# Conditional Access documentation: 00000000-aaaa-bbbb-cccc-000000000000'
            $script:Md | Should -Match 'Prepared by TenantKeep Posture\.'
            $script:Md | Should -Match 'Prepared with TenantKeep Posture'
        }

        It 'renders the device filter rule' {
            $script:Md | Should -Match 'Device filter \(exclude\): `device\.deviceOwnership -eq "Company" -and device\.trustType -eq "AzureAD"`'
        }

        It 'escapes pipes inside table cells' {
            $copy = Join-Path $script:Out 'piped-snapshot'
            Copy-Item -Path $script:Sample -Destination $copy -Recurse
            $policiesPath = Join-Path $copy 'policies.json'
            (Get-Content -Raw -LiteralPath $policiesPath).Replace('Block legacy authentication', 'Block | legacy authentication') | Set-Content -LiteralPath $policiesPath
            $r = New-PostureCaDocument -Snapshot $copy -OutputPath (Join-Path $script:Out 'piped') -NamePattern $script:Pattern -PassThru
            $md = Get-Content -Raw -LiteralPath $r.Files[0]
            $md | Should -Match '\| Block \\\| legacy authentication \| CA-008-Users-Block \|'
            $md | Should -Match '### Block \\\| legacy authentication'
            $matrixSection = ($md -split '## Policy matrix')[1].Split('## Naming convention')[0]
            $matrixRow = ($matrixSection -split "`n") | Where-Object { $_ -like '| Block \| legacy*' } | Select-Object -First 1
            ($matrixRow -split '(?<!\\)\|').Count | Should -Be 11 -Because 'one policy column plus eight matrix columns, with leading and trailing separators'
        }
    }

    Context 'brand.json' {
        It 'takes client name, confidentiality, footer and the name pattern from brand.json' {
            $brandPath = Join-Path $script:Out 'brand.json'
            New-Item -ItemType Directory -Path $script:Out -Force | Out-Null
            @{
                preparedBy = @{ name = 'Example MSP'; contact = 'security@example-msp.com' }
                client = @{ name = 'Contoso Ltd' }
                confidentiality = 'Confidential. Prepared for Contoso Ltd.'
                footer = 'Prepared by Example MSP'
                caNamePattern = $script:Pattern
            } | ConvertTo-Json | Set-Content -LiteralPath $brandPath
            $r = New-PostureCaDocument -Snapshot $script:Sample -OutputPath (Join-Path $script:Out 'branded') -Brand $brandPath -PassThru
            $md = Get-Content -Raw -LiteralPath $r.Files[0]
            $md | Should -Match '^# Conditional Access documentation: Contoso Ltd'
            $md | Should -Match 'Prepared by Example MSP for Contoso Ltd\.'
            $md | Should -Match '\*Confidential\. Prepared for Contoso Ltd\.\*'
            $md | Should -Match 'Prepared by Example MSP\s*$'
            $r.Document.naming.pattern | Should -Be $script:Pattern
            $md | Should -Not -Match 'Prepared with TenantKeep Posture'
        }
    }

    Context 'options' {
        It 'skips the naming report without a pattern' {
            $r = New-PostureCaDocument -Snapshot $script:Sample -OutputPath (Join-Path $script:Out 'nopattern') -PassThru
            $r.Document.naming | Should -BeNullOrEmpty
            Get-Content -Raw -LiteralPath $r.Files[0] | Should -Match 'No naming pattern configured'
        }

        It 'limits the matrix to the requested columns' {
            $r = New-PostureCaDocument -Snapshot $script:Sample -OutputPath (Join-Path $script:Out 'cols') -MatrixColumn allUsers, adminRoles -PassThru
            @($r.Document.matrix.columns | ForEach-Object { $_.key }) | Should -Be @('allUsers', 'adminRoles')
        }

        It 'rejects an unknown matrix column' {
            { New-PostureCaDocument -Snapshot $script:Sample -OutputPath (Join-Path $script:Out 'bad') -MatrixColumn nope } | Should -Throw '*Unknown matrix column*'
        }

        It 'passes thresholds through to the health flags' {
            $r = New-PostureCaDocument -Snapshot $script:Sample -OutputPath (Join-Path $script:Out 'thr') -ExclusionGroupThreshold 1000 -ReportOnlyDays 3650 -DisabledDays 3650 -PassThru
            $r.Document.stats.flagsWarning | Should -Be 0
        }

        It 'defaults OutputPath to the snapshot folder and honours -WhatIf' {
            New-PostureCaDocument -Snapshot $script:Sample -Format Markdown, Html, Pdf -WhatIf
            Join-Path $script:Sample 'ca-document.md' | Should -Not -Exist
            Join-Path $script:Sample 'ca-document.html' | Should -Not -Exist
            Join-Path $script:Sample 'ca-document.pdf' | Should -Not -Exist
        }

        It 'rejects a folder that is not a snapshot' {
            { New-PostureCaDocument -Snapshot $script:Out } | Should -Throw '*Not a CA snapshot folder*'
        }
    }
}

Describe 'New-PostureCaDocument HTML and PDF' {
    Context 'Html' {
        BeforeAll {
            $script:HtmlResult = New-PostureCaDocument -Snapshot $script:Sample -OutputPath (Join-Path $script:Out 'html') -Format Markdown, Html -NamePattern $script:Pattern -PassThru
            $script:Html = Get-Content -Raw -LiteralPath ($script:HtmlResult.Files | Where-Object { $_ -like '*.html' })
        }

        It 'writes both files' {
            $script:HtmlResult.Files.Count | Should -Be 2
            @($script:HtmlResult.Files | ForEach-Object { [System.IO.Path]::GetExtension($_) } | Sort-Object) | Should -Be @('.html', '.md')
        }

        It 'is self-contained: inline CSS, no scripts, no remote resources' {
            $script:Html | Should -Match '^<!DOCTYPE html>'
            $script:Html | Should -Match '<style>'
            $script:Html | Should -Not -Match '<script'
            $script:Html | Should -Not -Match '(src|<link[^>]*href)="https?://'
            $script:Html | Should -Not -Match '@import'
            $script:Html | Should -Match "default-src 'none'"
        }

        It 'carries light and dark themes and a print stylesheet' {
            $script:Html | Should -Match 'prefers-color-scheme: dark'
            $script:Html | Should -Match '@media print'
        }

        It 'has every section, one article per policy, and the coverage table' {
            foreach ($id in 'summary', 'health', 'matrix', 'naming', 'coverage', 'policies', 'locations', 'strengths', 'contexts', 'appendix') {
                $script:Html | Should -Match "<section id=`"$id`""
            }
            ([regex]::Matches($script:Html, '<article class="policy" id=')).Count | Should -Be 8
            $script:Html | Should -Match '<td><code>CA-007</code></td><td>Exclusion groups under the size threshold</td><td><span class="status fail">Fail</span></td>'
            $script:Html | Should -Match '<h3>What to fix</h3>'
        }

        It 'encodes names and marks deleted references' {
            $script:Html | Should -Match '<span class="deleted">&lt;deleted group 22222222-2222-2222-2222-222222222299&gt;</span>'
            $script:Html | Should -Match 'device\.deviceOwnership -eq &quot;Company&quot;'
            $script:Html | Should -Not -Match '<deleted group'
        }

        It 'fills matrix cells and links them to the policy' {
            $script:Html | Should -Match '<td class="on">Phishing-resistant MFA</td>'
            $script:Html | Should -Match '<a href="#p-ca-001-admins-require-phishing-resistant-mfa">'
            $script:Html | Should -Match '<article class="policy" id="p-ca-001-admins-require-phishing-resistant-mfa">'
        }

        It 'applies brand colors, font and an inlined logo' {
            $dir = Join-Path $script:Out 'html-brand'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $logo = Join-Path $dir 'logo.svg'
            Set-Content -LiteralPath $logo -Value '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10"/></svg>'
            $brand = Join-Path $dir 'brand.json'
            @{ preparedBy = @{ name = 'Example MSP'; logo = $logo }; client = @{ name = 'Contoso Ltd' }; colors = @{ primary = '#123456'; accent = '#abcdef' }; font = 'Georgia, serif' } | ConvertTo-Json | Set-Content -LiteralPath $brand
            $r = New-PostureCaDocument -Snapshot $script:Sample -OutputPath $dir -Format Html -Brand $brand -PassThru
            $html = Get-Content -Raw -LiteralPath $r.Files[0]
            $html | Should -Match '--primary: #123456; --accent: #abcdef; --font: Georgia, serif;'
            $html | Should -Match '<img class="logo" alt="logo" src="data:image/svg\+xml;base64,'
            $html | Should -Match '<title>Conditional Access documentation: Contoso Ltd</title>'
            $html | Should -Not -Match '(src|<link[^>]*href)="https?://'
        }

        It 'rejects an unsafe brand color instead of injecting it' {
            $dir = Join-Path $script:Out 'html-badcolor'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $brand = Join-Path $dir 'brand.json'
            @{ colors = @{ primary = 'red; } </style><script>alert(1)</script>' } } | ConvertTo-Json | Set-Content -LiteralPath $brand
            $r = New-PostureCaDocument -Snapshot $script:Sample -OutputPath $dir -Format Html -Brand $brand -PassThru
            $html = Get-Content -Raw -LiteralPath $r.Files[0]
            $html | Should -Not -Match '<script'
            $html | Should -Match '--primary: #1F3A5F;'
        }
    }

    Context 'Pdf' {
        It 'prints the HTML through a headless browser and returns all three files' {
            Mock -ModuleName Tenantkeep.Posture Find-PostureHeadlessBrowser { '/fake/msedge' }
            Mock -ModuleName Tenantkeep.Posture Start-Process {
                $pdf = ($ArgumentList | Where-Object { $_ -like '--print-to-pdf=*' }) -replace '^--print-to-pdf=', ''
                Set-Content -LiteralPath $pdf -Value '%PDF-1.7 fake'
                [pscustomobject]@{ ExitCode = 0 }
            }
            $r = New-PostureCaDocument -Snapshot $script:Sample -OutputPath (Join-Path $script:Out 'pdf') -Format Markdown, Pdf -PassThru
            @($r.Files | ForEach-Object { [System.IO.Path]::GetExtension($_) } | Sort-Object) | Should -Be @('.html', '.md', '.pdf')
            Should -Invoke -ModuleName Tenantkeep.Posture Start-Process -Times 1 -Exactly -ParameterFilter {
                $FilePath -eq '/fake/msedge' -and $ArgumentList -contains '--headless=new' -and $ArgumentList -contains '--no-pdf-header-footer' -and ($ArgumentList -join ' ') -match 'file:///.*ca-document\.html'
            }
        }

        It 'fails plainly when no browser is installed, after writing the HTML' {
            Mock -ModuleName Tenantkeep.Posture Find-PostureHeadlessBrowser { $null }
            $dir = Join-Path $script:Out 'pdf-nobrowser'
            { New-PostureCaDocument -Snapshot $script:Sample -OutputPath $dir -Format Pdf } | Should -Throw '*No headless browser found*'
            Join-Path $dir 'ca-document.html' | Should -Exist
        }

        It 'surfaces a non-zero browser exit code' {
            Mock -ModuleName Tenantkeep.Posture Find-PostureHeadlessBrowser { '/fake/chrome' }
            Mock -ModuleName Tenantkeep.Posture Start-Process { [pscustomobject]@{ ExitCode = 21 } }
            { New-PostureCaDocument -Snapshot $script:Sample -OutputPath (Join-Path $script:Out 'pdf-fail') -Format Pdf } | Should -Throw '*exited with code 21*'
        }
    }
}
