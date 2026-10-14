# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
    . (Join-Path $PSScriptRoot 'Fixtures' 'CaDiffFixture.ps1')
    $script:Cycle = Join-Path $PSScriptRoot '..' 'deploy' 'schedules' 'ca-snapshot-cycle.ps1'
    $script:Sample = Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot'
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-cycle-$([guid]::NewGuid().ToString('n'))"
    $script:Fx = Initialize-CaDiffFixture -Root $script:Root -Sample $script:Sample

    # Export is the only Graph-touching step; it is replaced by a copy of the fixture's "after" snapshot.
    # Mock bodies run in the cycle script's scope, so values cross over through environment variables.
    $env:TKP_TEST_AFTER = $script:Fx.After
    $env:TKP_TEST_POSTED = Join-Path $script:Root 'posted.json'
    Mock Export-PostureCaSnapshot {
        $stamp = (Get-Date).ToString('yyyyMMdd-HHmm')
        $folder = Join-Path $OutRoot "$stamp-ca"
        if (Test-Path $folder) { Remove-Item -LiteralPath $folder -Recurse -Force }
        Copy-Item -Path $env:TKP_TEST_AFTER -Destination $folder -Recurse
        [pscustomobject]@{ Folder = $folder; PolicyCount = 8; Errors = 0 }
    }
    Mock Invoke-RestMethod { Set-Content -LiteralPath $env:TKP_TEST_POSTED -Value $Body; $null }
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
    Remove-Item Env:TKP_TEST_AFTER, Env:TKP_TEST_POSTED -ErrorAction SilentlyContinue
}

Describe 'ca-snapshot-cycle.ps1' {
    It 'takes a first snapshot with nothing to compare' {
        $out = Join-Path $script:Root 'first'
        $r = & $script:Cycle -OutRoot $out -InformationAction SilentlyContinue
        $r.Snapshot | Should -Exist
        $r.Previous | Should -BeNullOrEmpty
        $r.HasRiskRelevantChanges | Should -BeFalse
        @($r.Documents).Count | Should -Be 2
        @($r.ChangeReports).Count | Should -Be 0
    }

    It 'compares with the previous run, posts to Teams and fails the job on risk' {
        $out = Join-Path $script:Root 'second'
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        Copy-Item -Path $script:Fx.Before -Destination (Join-Path $out '20260101-0000-ca') -Recurse
        Remove-Item -LiteralPath $env:TKP_TEST_POSTED -ErrorAction SilentlyContinue
        { & $script:Cycle -OutRoot $out -TeamsWebhookUrl 'https://example.invalid/webhook' -FailOnRiskRelevantChange -InformationAction SilentlyContinue -WarningAction SilentlyContinue } |
            Should -Throw '*9 risk-relevant Conditional Access change(s)*'
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://example.invalid/webhook' -and $Method -eq 'Post' }
        $card = Get-Content -Raw -LiteralPath $env:TKP_TEST_POSTED | ConvertFrom-Json
        $card.attachments[0].content.body[0].text | Should -Match '9 risk-relevant change'
        $card.attachments[0].content.body[2].facts.title | Should -Contain 'breakGlassExclusionRemoved'
        Get-ChildItem -Path $out -Directory | Where-Object Name -ne '20260101-0000-ca' | ForEach-Object { Join-Path $_.FullName 'ca-changes.html' } | Should -Exist
    }

    It 'returns normally on risk without -FailOnRiskRelevantChange and skips Teams without a webhook' {
        $out = Join-Path $script:Root 'third'
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        Copy-Item -Path $script:Fx.Before -Destination (Join-Path $out '20260101-0000-ca') -Recurse
        $r = & $script:Cycle -OutRoot $out -InformationAction SilentlyContinue -WarningAction SilentlyContinue
        $r.HasRiskRelevantChanges | Should -BeTrue
        $r.RiskRelevantCount | Should -Be 9
        $r.Previous | Should -Be (Join-Path $out '20260101-0000-ca')
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly -Scope It
    }

    It 'prunes the oldest runs beyond KeepRuns' {
        $out = Join-Path $script:Root 'prune'
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        foreach ($stamp in '20250101-0000', '20250102-0000', '20250103-0000') { Copy-Item -Path $script:Fx.Before -Destination (Join-Path $out "$stamp-ca") -Recurse }
        $r = & $script:Cycle -OutRoot $out -KeepRuns 2 -InformationAction SilentlyContinue -WarningAction SilentlyContinue
        $r.Pruned | Should -Be @('20250101-0000-ca', '20250102-0000-ca')
        (Get-ChildItem -Path $out -Directory).Count | Should -Be 2
        Join-Path $out '20250103-0000-ca' | Should -Exist
    }
}
