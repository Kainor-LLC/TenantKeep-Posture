# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    . (Join-Path $PSScriptRoot 'Fixtures' 'ClientRunFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-sharing-$([guid]::NewGuid().ToString('n'))"
    $script:F = Initialize-ClientRunFixture -Root $script:Root
    # The collaboration domain needs its tenant settings to evaluate at all.
    @{ SharingCapability = 'ExternalUserSharingOnly' } | ConvertTo-Json | Set-Content (Join-Path $script:F.Run 'spo-tenant-settings.json')
    Mock Write-Host {} -ModuleName TenantKeep.Posture
    # A made-up export in the documented column layout.
    $header = 'TenantID,Site ID,Site Name,Site URL,Site Template,Primary admin,Primary admin email,ExternalSharing,Site Privacy,Site Sensitivity,Number of users having access,Guest user permissions,External participant permissions,Microsoft Entra group permission count,File count,Items with unique permissions count,People In Your Org link count,Anyone link count,EEEU permission count,Everyone permission count,Report Date'
    $script:Csv = Join-Path $script:Root 'SitePermissions.csv'
    $rows = @(
        "$($script:F.TenantId),s1,Finance,https://contoso.sharepoint.com/sites/finance,STS#3,Fin Owner,fin@contoso.example,Disabled,Private,Confidential,40,0,0,1,900,12,3,0,1,0,2026-11-18"
        "$($script:F.TenantId),s2,All Company,https://contoso.sharepoint.com/sites/allcompany,STS#3,IT,it@contoso.example,ExternalUserSharingOnly,Public,,900,2,0,1,300,4,10,5,0,1,2026-11-18"
        "$($script:F.TenantId),s3,Quiet,https://contoso.sharepoint.com/sites/quiet,STS#3,IT,it@contoso.example,Disabled,Private,General,5,0,0,1,10,0,0,0,0,0,2026-11-18"
    )
    Set-Content -LiteralPath $script:Csv -Value (@($header) + $rows)
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Import-PostureSharingReport' {
    It 'files the report with its date, summarises it into the newest run and rebuilds the report' {
        $r = Import-PostureSharingReport -Client $script:F.Client -OutRoot $script:F.OutRoot -Path $script:Csv
        Join-Path $script:F.Client 'imports' 'sam-dag' 'site-permissions-sharepoint-2026-11-18.csv' | Should -Exist
        $r.Sites | Should -Be 3
        $r.ExposedSites | Should -Be 2
        $r.AnyoneLinks | Should -Be 5
        $r.OrganizationLinks | Should -Be 13
        $s = Get-Content -Raw (Join-Path $script:F.Run 'spo-dag-site-permissions.json') | ConvertFrom-Json -AsHashtable
        $s.top[0].url | Should -Be 'https://contoso.sharepoint.com/sites/allcompany' -Because 'the most exposed site comes first'
        Join-Path $script:F.Run 'report.html' | Should -Exist
    }

    It 'feeds CL-015: failing with the exposed sites listed, each with what exposes it' {
        $null = Invoke-PostureChecks -Evidence $script:F.Run -Domain collaboration -OutputPath $script:F.Run
        $res = @((Get-Content -Raw (Join-Path $script:F.Run 'checks.json') | ConvertFrom-Json -AsHashtable -Depth 20).results | Where-Object { $_.id -eq 'CL-015' })[0]
        $res.status | Should -Be 'fail'
        $res.affectedCount | Should -Be 2
        @($res.affected | Where-Object { $_.name -like '*allcompany' })[0].detail | Should -Match '5 Anyone links.*10 organization-wide links.*1 Everyone grants; no sensitivity label'
    }

    It 'reads CL-015 as not provided, never zero, when no report is there' {
        $bare = Join-Path $script:Root 'bare'; New-Item -ItemType Directory -Path $bare | Out-Null
        @{ SharingCapability = 'ExternalUserSharingOnly' } | ConvertTo-Json | Set-Content (Join-Path $bare 'spo-tenant-settings.json')
        $null = Invoke-PostureChecks -Evidence $bare -Domain collaboration -OutputPath $bare
        $res = @((Get-Content -Raw (Join-Path $bare 'checks.json') | ConvertFrom-Json -AsHashtable -Depth 20).results | Where-Object { $_.id -eq 'CL-015' })[0]
        $res.status | Should -BeIn @('notEvaluated', 'notApplicable')
        if ($res.status -eq 'notEvaluated') { $res.reason | Should -Match 'Import-PostureSharingReport' }
    }

    It 'refuses a file that is not the site permissions report, and one from another tenant' {
        $wrong = Join-Path $script:Root 'wrong.csv'; Set-Content $wrong -Value "Site URL,Something`nhttps://x,1"
        { Import-PostureSharingReport -Client $script:F.Client -Path $wrong -NoReport } | Should -Throw "*Anyone link count*"
        $other = Join-Path $script:Root 'other.csv'
        (Get-Content $script:Csv) -replace [regex]::Escape($script:F.TenantId), '99999999-0000-0000-0000-000000000000' | Set-Content $other
        { Import-PostureSharingReport -Client $script:F.Client -Path $other -NoReport } | Should -Throw '*is for tenant 99999999*'
    }

    It 'keeps the newest row for a site that is in more than one report' {
        InModuleScope TenantKeep.Posture -Parameters @{ F = $script:F; csv = $script:Csv } {
            param($F, $csv)
            $older = Join-Path $F.Client 'imports' 'sam-dag' 'site-permissions-sharepoint-2026-10-01.csv'
            (Get-Content $csv) -replace '2026-11-18', '2026-10-01' -replace ',3,0,1,0,2026-10-01', ',30,0,1,0,2026-10-01' | Set-Content $older
            $s = Write-PostureSharingSummary -Client $F.Client -Folder $F.Run -Confirm:$false -WhatIf
            $s.totals.sites | Should -Be 3
            $s.totals.orgLinks | Should -Be 13 -Because 'the November report wins for every site it has'
        }
    }
}
