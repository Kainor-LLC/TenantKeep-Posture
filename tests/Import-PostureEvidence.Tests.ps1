# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Tid = '33333333-3333-3333-3333-333333333333'
    $script:NewRun = {
        param([string] $Root, [string] $Tenant = $script:Tid)
        foreach ($p in 'evidence', 'errors', 'logs') { New-Item -ItemType Directory -Path (Join-Path $Root $p) -Force | Out-Null }
        @{ tenantId = $Tenant; planned = @('Entra') } | ConvertTo-Json | Set-Content (Join-Path $Root 'logs' 'run.json')
        $Root
    }
    # A folder as Get-SpoBaseline.ps1 writes it, with bundle.json hashes over what is there.
    $script:NewSpoBundle = {
        param([string] $Dir, [string] $Tenant = $script:Tid)
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        @{ SharingCapability = 'ExternalUserSharingOnly'; DefaultSharingLinkType = 'Direct'; DefaultLinkPermission = 'View'; OneDriveSharingCapability = 'ExternalUserSharingOnly'; SharingDomainRestrictionMode = 'AllowList'; ExternalUserExpirationRequired = $true; ExternalUserExpireInDays = 30; ShowEveryoneClaim = $false; ShowEveryoneExceptExternalUsersClaim = $false; ShowAllUsersClaim = $false; EnableRestrictedAccessControl = $true } | ConvertTo-Json | Set-Content (Join-Path $Dir 'spo-tenant-settings.json')
        @{ Mode = 'Disabled'; AllowedSites = 0 } | ConvertTo-Json | Set-Content (Join-Path $Dir 'spo-restricted-search.json')
        'SharePoint (Windows collector) Sites :: The operation has timed out' | Set-Content (Join-Path $Dir 'errors.txt')
        'transcript' | Set-Content (Join-Path $Dir 'transcript.txt')
        $files = @('spo-tenant-settings.json', 'spo-restricted-search.json' | ForEach-Object { @{ name = $_; sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $Dir $_)).Hash.ToLowerInvariant() } })
        @{ kind = 'sharepoint'; collector = 'Get-SpoBaseline.ps1'; schema = 1; tenantId = $Tenant; collectedUtc = '2026-11-20T15:00:00Z'; account = 'spadmin'; files = $files } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $Dir 'bundle.json')
        $Dir
    }
}

Describe 'Import-PostureEvidence' {
    It 'checks the bundle and the tenant, copies only the evidence files, carries the errors over and records the import' {
        $run = & $script:NewRun (Join-Path $TestDrive 'run1')
        $src = & $script:NewSpoBundle (Join-Path $TestDrive 'spo1')
        $r = Import-PostureEvidence -Path $src -Run $run
        $r.Kind | Should -Be 'sharepoint'
        $r.Checked | Should -Be 'sha256'
        @($r.Files | Sort-Object) | Should -Be @('spo-restricted-search.json', 'spo-tenant-settings.json')
        Join-Path $run 'evidence' 'transcript.txt' | Should -Not -Exist
        Join-Path $run 'evidence' 'bundle.json' | Should -Not -Exist
        Get-Content (Join-Path $run 'errors' 'errors.txt') | Should -Contain 'SharePoint (Windows collector) Sites :: The operation has timed out'
        $log = Get-Content -Raw (Join-Path $run 'logs' 'imports.json') | ConvertFrom-Json
        @($log)[0].collector | Should -Be 'Get-SpoBaseline.ps1'
        $checks = Invoke-PostureChecks -Evidence (Join-Path $run 'evidence') -Domain collaboration -PassThru
        @($checks.results | Where-Object id -eq 'CL-003')[0].status | Should -Be 'pass' -Because 'the admin read is now in the run'
        $rep = New-PostureReport -Evidence (Join-Path $run 'evidence') -OutputPath (Join-Path $TestDrive 'out1') -PassThru 6>$null
        @($rep.Report.runHealth.imports).Count | Should -Be 1
        Get-Content -Raw ($rep.Files | Where-Object { $_ -like '*report.html' }) | Should -Match 'Evidence Brought In From Another Machine'
    }

    It 'refuses a changed file, another tenant, and a file the bundle should not list, copying nothing' {
        $run = & $script:NewRun (Join-Path $TestDrive 'run2')
        $src = & $script:NewSpoBundle (Join-Path $TestDrive 'spo2')
        Add-Content (Join-Path $src 'spo-tenant-settings.json') ' '
        { Import-PostureEvidence -Path $src -Run $run } | Should -Throw '*changed after collection*'
        @(Get-ChildItem (Join-Path $run 'evidence')).Count | Should -Be 0
        $other = & $script:NewSpoBundle (Join-Path $TestDrive 'spo3') '44444444-4444-4444-4444-444444444444'
        { Import-PostureEvidence -Path $other -Run $run } | Should -Throw '*from tenant 4444*the run is tenant 3333*'
        $evil = & $script:NewSpoBundle (Join-Path $TestDrive 'spo4')
        'Write-Host pwned' | Set-Content (Join-Path $evil 'payload.ps1')
        $b = Get-Content -Raw (Join-Path $evil 'bundle.json') | ConvertFrom-Json -AsHashtable
        $b.files += @{ name = 'payload.ps1'; sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $evil 'payload.ps1')).Hash.ToLowerInvariant() }
        $b | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $evil 'bundle.json')
        { Import-PostureEvidence -Path $evil -Run $run } | Should -Throw '*payload.ps1, which is not a sharepoint evidence file*'
        @(Get-ChildItem (Join-Path $run 'evidence')).Count | Should -Be 0
    }

    It 'keeps a different file already in the run unless -Force, and takes a zip' {
        $run = & $script:NewRun (Join-Path $TestDrive 'run3')
        '{"SharingCapability":"Disabled"}' | Set-Content (Join-Path $run 'evidence' 'spo-tenant-settings.json')
        $src = & $script:NewSpoBundle (Join-Path $TestDrive 'spo5')
        { Import-PostureEvidence -Path $src -Run $run } | Should -Throw '*already in the run and differs*'
        $zip = Join-Path $TestDrive 'spo5.zip'
        Compress-Archive -Path (Join-Path $src '*') -DestinationPath $zip
        $r = Import-PostureEvidence -Path $zip -Run $run -Force
        $r.Files | Should -Contain 'spo-tenant-settings.json'
        (Get-Content -Raw (Join-Path $run 'evidence' 'spo-tenant-settings.json')) | Should -Match 'ExternalUserSharingOnly'
    }

    It 'takes an AD folder from before bundle.json, by name only, with a warning' {
        $run = & $script:NewRun (Join-Path $TestDrive 'run4')
        $ad = Join-Path $TestDrive 'ad-old'
        New-Item -ItemType Directory -Path $ad | Out-Null
        '{"ForestFunctionalLevel":"Windows2016Forest"}' | Set-Content (Join-Path $ad 'ad-01-forest-domain.json')
        'x' | Set-Content (Join-Path $ad 'notes.json')
        $r = Import-PostureEvidence -Path $ad -Run $run -WarningVariable warn 3>$null
        $r.Kind | Should -Be 'ad'
        $r.Checked | Should -Be 'names only'
        $r.Files | Should -Be @('ad-01-forest-domain.json')
        "$warn" | Should -Match 'no bundle\.json'
        Join-Path $run 'evidence' 'notes.json' | Should -Not -Exist
    }

    It 'takes the SharePoint files of a run made on another machine, checking that run''s tenant' {
        $run = & $script:NewRun (Join-Path $TestDrive 'run5')
        $other = & $script:NewRun (Join-Path $TestDrive 'cloudpc-run')
        Copy-Item (Join-Path (& $script:NewSpoBundle (Join-Path $TestDrive 'spo6')) 'spo-tenant-settings.json') (Join-Path $other 'evidence')
        $r = Import-PostureEvidence -Path $other -Run $run
        $r.Files | Should -Be @('spo-tenant-settings.json')
        $wrong = & $script:NewRun (Join-Path $TestDrive 'wrong-run') '44444444-4444-4444-4444-444444444444'
        Copy-Item (Join-Path $other 'evidence' 'spo-tenant-settings.json') (Join-Path $wrong 'evidence')
        { Import-PostureEvidence -Path $wrong -Run (& $script:NewRun (Join-Path $TestDrive 'run6')) } | Should -Throw '*from tenant 4444*'
    }

    It 'honours -WhatIf' {
        $run = & $script:NewRun (Join-Path $TestDrive 'run7')
        $src = & $script:NewSpoBundle (Join-Path $TestDrive 'spo7')
        $null = Import-PostureEvidence -Path $src -Run $run -WhatIf
        @(Get-ChildItem (Join-Path $run 'evidence')).Count | Should -Be 0
        Join-Path $run 'logs' 'imports.json' | Should -Not -Exist
    }
}
