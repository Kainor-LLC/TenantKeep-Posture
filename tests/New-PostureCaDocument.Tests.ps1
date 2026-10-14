# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
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

        It 'writes ca-document.md into OutputPath and returns it' {
            $script:Result.Files.Count | Should -Be 1
            $script:Result.Files[0] | Should -Be (Join-Path $script:Out 'ca-document.md')
            $script:Result.Files[0] | Should -Exist
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
            $script:Md | Should -Match 'Prepared by Tenantkeep Posture\.'
            $script:Md | Should -Match 'Prepared with Tenantkeep Posture'
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
            $md | Should -Not -Match 'Prepared with Tenantkeep Posture'
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
            New-PostureCaDocument -Snapshot $script:Sample -WhatIf
            Join-Path $script:Sample 'ca-document.md' | Should -Not -Exist
        }

        It 'rejects a folder that is not a snapshot' {
            { New-PostureCaDocument -Snapshot $script:Out } | Should -Throw '*Not a CA snapshot folder*'
        }
    }
}
