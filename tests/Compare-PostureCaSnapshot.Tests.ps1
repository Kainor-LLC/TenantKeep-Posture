# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    . (Join-Path $PSScriptRoot 'Fixtures' 'CaDiffFixture.ps1')
    $script:Sample = Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot'
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-cmp-$([guid]::NewGuid().ToString('n'))"
    $script:Fx = Initialize-CaDiffFixture -Root $script:Root -Sample $script:Sample
    $script:Out = Join-Path $script:Root 'out'
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
}

Describe 'Compare-PostureCaSnapshot' {
    Context 'default run' {
        BeforeAll {
            $script:R = Compare-PostureCaSnapshot -Before $script:Fx.Before -After $script:Fx.After -OutputPath $script:Out -PassThru -WarningAction SilentlyContinue
            $script:Md = Get-Content -Raw -LiteralPath ($script:R.Files | Where-Object { $_ -like '*.md' })
            $script:Html = Get-Content -Raw -LiteralPath ($script:R.Files | Where-Object { $_ -like '*.html' })
        }

        It 'writes ca-changes.md and ca-changes.html' {
            @($script:R.Files | ForEach-Object { Split-Path $_ -Leaf } | Sort-Object) | Should -Be @('ca-changes.html', 'ca-changes.md')
            $script:R.Files | Should -Exist
        }

        It 'counts and flags risk' {
            $script:R.RiskRelevantCount | Should -Be 9
            $script:R.HasRiskRelevantChanges | Should -BeTrue
            $script:R.Counts.added | Should -Be 1
            $script:R.Counts.removed | Should -Be 1
            $script:R.Counts.renamed | Should -Be 1
            $script:R.Counts.stateChanged | Should -Be 1
            $script:R.Counts.modified | Should -Be 3
            $script:R.Counts.scope | Should -Be 2
        }

        It 'puts risk-relevant changes first in Markdown' {
            $script:Md.IndexOf('## Risk-relevant changes') | Should -BeLessThan $script:Md.IndexOf('## Summary')
            $script:Md | Should -Match '\*\*9 change\(s\) need a look\.\*\*'
            $script:Md | Should -Match '\| breakGlassExclusionRemoved \| CA-001-Admins-Require phishing-resistant MFA \|'
            $script:Md | Should -Match '\| stateWeakened \| CA-002-Users-Require MFA for all cloud apps \| Moved from enabled to disabled'
        }

        It 'renders field-level before and after with names' {
            $script:Md | Should -Match '\| assignments\.excludeUsers \| BreakGlass-01; BreakGlass-02 \| BreakGlass-01 \|'
            $script:Md | Should -Match '\| grant\.authenticationStrength \| Phishing-resistant MFA \| Multifactor authentication \|'
            $script:Md | Should -Match '- Renamed from \*\*Block legacy authentication\*\*'
            $script:Md | Should -Match '- State: \*\*Enabled\*\* to \*\*Disabled\*\*'
            $script:Md | Should -Not -Match '22222222-2222-2222-2222-222222222203'
        }

        It 'lists added and removed policies with their summaries' {
            $script:Md | Should -Match '\| CA-009-Users-Require MFA for admin portals \| Enabled \| Require MFA for all users, members of <deleted group [0-9-]+>, Microsoft admin portals'
            $script:Md | Should -Match '\| Sign-in risk: require MFA \(report-only pilot\) \| Report-only \| Report-only: Require MFA'
        }

        It 'reports scope drift with member detail where available' {
            $script:Md | Should -Match '\| CA-Exclude-ServiceAccounts \| 2 \| 2 \| 0 \| three@contoso\.example \| one@contoso\.example \|'
            $script:Md | Should -Match '\| CA-Exclude-MFA-Legacy \| 341 \| 350 \| \+9 \| n/a \(no -IncludeMembers\) \| n/a \(no -IncludeMembers\) \|'
        }

        It 'shows location and strength changes' {
            $script:Md | Should -Match 'Added: Branch VPN'
            $script:Md | Should -Match '### HQ egress'
            $script:Md | Should -Match '\| ipRanges \| .*203\.0\.113\.0/24.* \| .*198\.51\.100\.0/24.* \|'
            $script:Md | Should -Match '\| allowedCombinations \| fido2; windowsHelloForBusiness; x509CertificateMultiFactor \| fido2; password,sms; windowsHelloForBusiness; x509CertificateMultiFactor \|'
        }

        It 'produces self-contained HTML with the risk table first' {
            $script:Html | Should -Match '^<!DOCTYPE html>'
            $script:Html | Should -Not -Match '<script'
            $script:Html | Should -Not -Match '(src|href)="https?://'
            $script:Html.IndexOf('<section id="risk">') | Should -BeLessThan $script:Html.IndexOf('<section id="summary">')
            ([regex]::Matches($script:Html, '<table class="risk">')).Count | Should -Be 1
            $script:Html | Should -Match '<td class="before">BreakGlass-01; BreakGlass-02</td><td class="after">BreakGlass-01</td>'
            $script:Html | Should -Match '<td class="before">compliantDevice</td><td class="after">mfa</td>'
        }
    }

    Context 'exit behaviour' {
        It 'throws after writing the report with -FailOnRiskRelevantChange' {
            $dir = Join-Path $script:Root 'fail'
            { Compare-PostureCaSnapshot -Before $script:Fx.Before -After $script:Fx.After -OutputPath $dir -FailOnRiskRelevantChange -WarningAction SilentlyContinue } | Should -Throw '*9 risk-relevant Conditional Access change(s)*'
            Join-Path $dir 'ca-changes.md' | Should -Exist
            Join-Path $dir 'ca-changes.html' | Should -Exist
        }

        It 'gives a non-zero exit code to a pwsh -Command caller' {
            $module = Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1'
            $dir = Join-Path $script:Root 'exit'
            $cmd = "Import-Module '$module'; Compare-PostureCaSnapshot -Before '$($script:Fx.Before)' -After '$($script:Fx.After)' -OutputPath '$dir' -FailOnRiskRelevantChange -WarningAction SilentlyContinue"
            $null = & pwsh -NoProfile -NonInteractive -Command $cmd 2>&1
            $LASTEXITCODE | Should -Be 1
        }

        It 'does not throw when nothing is risk-relevant' {
            $dir = Join-Path $script:Root 'same'
            $r = Compare-PostureCaSnapshot -Before $script:Fx.Before -After $script:Fx.Before -OutputPath $dir -FailOnRiskRelevantChange -PassThru
            $r.HasRiskRelevantChanges | Should -BeFalse
            $r.RiskRelevantCount | Should -Be 0
            Get-Content -Raw -LiteralPath (Join-Path $dir 'ca-changes.md') | Should -Match 'No differences between the two snapshots\.'
        }
    }

    Context 'options' {
        It 'honours -BreakGlass and -Brand and records them in the appendix' {
            $dir = Join-Path $script:Root 'opts'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $brand = Join-Path $dir 'brand.json'
            @{ preparedBy = @{ name = 'Example MSP' }; client = @{ name = 'Contoso Ltd' }; footer = 'Prepared by Example MSP' } | ConvertTo-Json | Set-Content -LiteralPath $brand
            $r = Compare-PostureCaSnapshot -Before $script:Fx.Before -After $script:Fx.After -OutputPath $dir -Brand $brand -BreakGlass 'nobody@contoso.example' -Format Markdown -PassThru -WarningAction SilentlyContinue
            $r.RiskRelevantCount | Should -Be 8
            $md = Get-Content -Raw -LiteralPath $r.Files[0]
            $md | Should -Match '^# Conditional Access changes: Contoso Ltd'
            $md | Should -Match 'Prepared by Example MSP for Contoso Ltd\.'
            $md | Should -Match '\| Break-glass accounts \| nobody@contoso\.example \|'
            $r.Files.Count | Should -Be 1
        }

        It 'warns when the tenants differ' {
            $dir = Join-Path $script:Root 'tenants'
            $other = Join-Path $script:Root 'other-tenant'
            Copy-Item -Path $script:Fx.Before -Destination $other -Recurse
            $metaPath = Join-Path $other 'metadata.json'
            (Get-Content -Raw -LiteralPath $metaPath).Replace('00000000-aaaa-bbbb-cccc-000000000000', '99999999-aaaa-bbbb-cccc-000000000000') | Set-Content -LiteralPath $metaPath
            Compare-PostureCaSnapshot -Before $script:Fx.Before -After $other -OutputPath $dir -WarningVariable w -WarningAction SilentlyContinue | Out-Null
            @($w | Where-Object { $_ -like '*different tenants*' }).Count | Should -Be 1
        }

        It 'rejects a folder that is not a snapshot' {
            { Compare-PostureCaSnapshot -Before $script:Fx.Before -After $script:Root } | Should -Throw '*Not a CA snapshot folder*'
        }
    }
}
