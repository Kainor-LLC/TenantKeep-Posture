# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    . (Join-Path $PSScriptRoot 'Fixtures' 'ClientRunFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-addex-$([guid]::NewGuid().ToString('n'))"
    $script:F = Initialize-ClientRunFixture -Root $script:Root
    $script:Results = @((Get-Content -Raw (Join-Path $script:F.Run 'checks.json') | ConvertFrom-Json -AsHashtable -Depth 20).results)
    $script:Failing = @($script:Results | Where-Object { $_.status -eq 'fail' -and $_.affectedCount -gt 1 })[0]
    $script:ExPath = Join-Path $script:F.Client 'exceptions.json'
    Mock Write-Host {} -ModuleName TenantKeep.Posture
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Add-PostureException' {
    BeforeEach { if (Test-Path $script:ExPath) { Remove-Item -LiteralPath $script:ExPath } }

    It 'records a whole-check exception without prompting when every value is given, and rebuilds the report' {
        $id = $script:Failing.id
        $r = Add-PostureException -Client $script:F.Client -OutRoot $script:F.OutRoot -Check $id -Justification 'Compensated by the SIEM rule' -Owner 'IT' -Approver 'CISO' -Expires ([datetime]::UtcNow.AddDays(30))
        $r.check | Should -Be $id
        $doc = Get-Content -Raw $script:ExPath | ConvertFrom-Json -AsHashtable
        @($doc.exceptions).Count | Should -Be 1
        $doc.exceptions[0].object | Should -BeNullOrEmpty
        $doc.exceptions[0].expires | Should -Match '^\d{4}-\d{2}-\d{2}$'
        $checks = Get-Content -Raw (Join-Path $script:F.Run 'checks.json') | ConvertFrom-Json -AsHashtable -Depth 20
        @($checks.results | Where-Object { $_.id -eq $id })[0].status | Should -Be 'acceptedRisk' -Because 'the newest run was evaluated again with the new file'
        Join-Path $script:F.Run 'report.html' | Should -Exist
        Join-Path $script:F.Run 'findings.csv' | Should -Exist
    }

    It 'asks for the check, the object, the reason, owner, approver and expiry when only the client is given' {
        $object = [string]$script:Failing.affected[0].name
        $answers = [System.Collections.Generic.Queue[object]]::new([object[]]@($script:Failing.id, $object, 'Vendor mailbox', 'Ops', '', ([datetime]::UtcNow.AddDays(60).ToString('yyyy-MM-dd'))))
        Mock Read-PostureAnswer { $answers.Dequeue() } -ModuleName TenantKeep.Posture
        $r = Add-PostureException -Client $script:F.Client -OutRoot $script:F.OutRoot -NoReport
        $r.object | Should -Be $object
        $r.justification | Should -Be 'Vendor mailbox'
        $answers.Count | Should -Be 0
    }

    It 'replaces an entry for the same check and object instead of adding a second' {
        $id = $script:Failing.id
        foreach ($why in 'First', 'Second') { $null = Add-PostureException -Client $script:F.Client -OutRoot $script:F.OutRoot -Check $id -Object 'x' -Justification $why -Owner 'o' -Approver 'a' -Expires ([datetime]::UtcNow.AddDays(10)) -NoReport }
        $doc = Get-Content -Raw $script:ExPath | ConvertFrom-Json -AsHashtable
        @($doc.exceptions).Count | Should -Be 1
        $doc.exceptions[0].justification | Should -Be 'Second'
    }

    It 'keeps the other entries and their fields' {
        @{ exceptions = @(@{ check = 'ID-001'; object = $null; justification = 'Kept'; owner = 'o'; approver = 'a'; expires = '2099-01-01'; ticket = 'CHG-1' }) } | ConvertTo-Json -Depth 5 | Set-Content $script:ExPath
        $null = Add-PostureException -Client $script:F.Client -OutRoot $script:F.OutRoot -Check $script:Failing.id -Justification 'New' -Owner 'o' -Approver 'a' -Expires ([datetime]::UtcNow.AddDays(10)) -NoReport
        $doc = Get-Content -Raw $script:ExPath | ConvertFrom-Json -AsHashtable
        @($doc.exceptions).Count | Should -Be 2
        @($doc.exceptions | Where-Object { $_.check -eq 'ID-001' })[0].ticket | Should -Be 'CHG-1'
    }

    It 'refuses an unknown check, a past expiry and a broken file' {
        { Add-PostureException -Client $script:F.Client -OutRoot $script:F.OutRoot -Check 'ZZ-999' -Justification 'j' -Owner 'o' -Approver 'a' -Expires ([datetime]::UtcNow.AddDays(1)) } | Should -Throw '*not a check in the catalog*'
        { Add-PostureException -Client $script:F.Client -OutRoot $script:F.OutRoot -Check $script:Failing.id -Justification 'j' -Owner 'o' -Approver 'a' -Expires ([datetime]::UtcNow.AddDays(-1)) } | Should -Throw '*not in the future*'
        Set-Content $script:ExPath -Value '{ not json'
        { Add-PostureException -Client $script:F.Client -OutRoot $script:F.OutRoot -Check $script:Failing.id -Justification 'j' -Owner 'o' -Approver 'a' -Expires ([datetime]::UtcNow.AddDays(1)) } | Should -Throw '*not valid JSON*'
        Get-Content -Raw $script:ExPath | Should -Match 'not json' -Because 'a broken file is left for the admin to fix, never overwritten'
    }

    It 'finds the client folder and the run from the tenant id alone' {
        InModuleScope TenantKeep.Posture -Parameters @{ F = $script:F } {
            param($F)
            Resolve-PostureClientFolder -TenantId $F.TenantId -ClientsRoot $F.ClientsRoot | Should -Be $F.Client
            Find-PostureRunFolder -Client $F.Client -TenantId $F.TenantId -OutRoot $F.OutRoot | Should -Be $F.Run
            Find-PostureRunFolder -Client $F.Client -TenantId '99999999-2222-3333-4444-555555555555' -OutRoot $F.OutRoot | Should -BeNullOrEmpty
            { Resolve-PostureClientFolder -TenantId '99999999-2222-3333-4444-555555555555' -ClientsRoot $F.ClientsRoot } | Should -Throw '*No client folder*'
        }
    }

    It 'reads outputRoot from the profile when no -OutRoot is given' {
        InModuleScope TenantKeep.Posture -Parameters @{ F = $script:F } {
            param($F)
            $p = Join-Path $F.Client 'profile.json'; $saved = Get-Content -Raw $p
            try {
                $doc = $saved | ConvertFrom-Json -AsHashtable; $doc.outputRoot = $F.OutRoot; $doc | ConvertTo-Json | Set-Content $p
                Get-PostureOutputRoot -Client $F.Client | Should -Be $F.OutRoot
                $other = Join-Path ([System.IO.Path]::GetTempPath()) 'tkp-elsewhere'
                Get-PostureOutputRoot -Client $F.Client -OutRoot $other | Should -Be $other
            }
            finally { Set-Content -LiteralPath $p -Value $saved }
        }
    }
}
