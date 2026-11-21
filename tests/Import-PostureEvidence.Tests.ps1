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

Describe 'Import-PostureEvidence, Active Directory evidence and the tenant' {
    BeforeAll {
        # A folder as Get-ADBaseline.ps1 writes it: the forest's UPN suffixes in bundle.json, hashes over the files.
        $script:NewAdBundle = {
            param([string] $Dir, [string[]] $Suffix = @('contoso.example', 'corp.contoso.local'), [switch] $NoSuffix, [string] $Level = 'Windows2016Forest')
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null
            "{`"ForestFunctionalLevel`":`"$Level`"}" | Set-Content (Join-Path $Dir 'ad-01-forest-domain.json')
            'SamAccountName' | Set-Content (Join-Path $Dir 'ad-07-stale-users.csv')
            'Group Policy inventory :: GroupPolicy module not available' | Set-Content (Join-Path $Dir 'errors.txt')
            $files = @('ad-01-forest-domain.json', 'ad-07-stale-users.csv' | ForEach-Object { @{ name = $_; sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $Dir $_)).Hash.ToLowerInvariant() } })
            $bundle = @{ kind = 'ad'; collector = 'Get-ADBaseline.ps1'; schema = 1; domain = 'corp.contoso.local'; forest = 'corp.contoso.local'; collectedUtc = '2026-10-15T15:00:00Z'; files = $files }
            if (-not $NoSuffix) { $bundle.upnSuffixes = $Suffix; $bundle.forestDomains = @('corp.contoso.local') }
            $bundle | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $Dir 'bundle.json')
            $Dir
        }
        # A run whose tenant has verified these domains.
        $script:NewRunWithDomains = {
            param([string] $Root, [string[]] $Domain = @('contoso.example', 'contoso.onmicrosoft.com'))
            $run = & $script:NewRun $Root
            ConvertTo-Json -InputObject @($Domain | ForEach-Object { @{ Id = $_; IsVerified = $true; IsDefault = $false } }) | Set-Content (Join-Path $run 'evidence' '01-domains.json')
            $run
        }
    }

    It 'takes a forest whose people sign in with a domain the tenant has verified, and records the match' {
        $run = & $script:NewRunWithDomains (Join-Path $TestDrive 'ad-run1')
        $r = Import-PostureEvidence -Path (& $script:NewAdBundle (Join-Path $TestDrive 'ad1')) -Run $run
        $r.Kind | Should -Be 'ad'
        $r.Checked | Should -Be 'sha256'
        $r.TenantCheck | Should -Be 'matched: contoso.example is a verified domain of the tenant'
        @($r.Files | Sort-Object) | Should -Be @('ad-01-forest-domain.json', 'ad-07-stale-users.csv')
        (Get-Content -Raw (Join-Path $run 'logs' 'imports.json') | ConvertFrom-Json)[0].tenantCheck | Should -Match '^matched'
    }

    It 'takes a forest named under a verified domain, or over one' {
        $run = & $script:NewRunWithDomains (Join-Path $TestDrive 'ad-run2')
        (Import-PostureEvidence -Path (& $script:NewAdBundle (Join-Path $TestDrive 'ad2') -Suffix 'emea.contoso.example') -Run $run).TenantCheck | Should -Match '^matched: emea\.contoso\.example'
        $run3 = & $script:NewRunWithDomains (Join-Path $TestDrive 'ad-run3') @('mail.fabrikam.example')
        (Import-PostureEvidence -Path (& $script:NewAdBundle (Join-Path $TestDrive 'ad3') -Suffix 'fabrikam.example') -Run $run3).TenantCheck | Should -Match '^matched: fabrikam\.example'
    }

    It 'refuses another organisation''s forest, copying nothing, and says how to bring it in when it is this one''s after all' {
        $run = & $script:NewRunWithDomains (Join-Path $TestDrive 'ad-run4')
        $other = & $script:NewAdBundle (Join-Path $TestDrive 'ad4') -Suffix 'fabrikam.example', 'corp.fabrikam.local'
        { Import-PostureEvidence -Path $other -Run $run } | Should -Throw "*whose people sign in as corp.contoso.local, corp.fabrikam.local, fabrikam.example. None of those is a domain this run's tenant has verified (contoso.example, contoso.onmicrosoft.com)*Nothing was copied*pass -Force*"
        @(Get-ChildItem (Join-Path $run 'evidence') -Filter 'ad-*').Count | Should -Be 0
        Join-Path $run 'logs' 'imports.json' | Should -Not -Exist
        $forced = Import-PostureEvidence -Path $other -Run $run -Force
        $forced.TenantCheck | Should -Be 'forced: no UPN suffix of the forest is a verified domain of the tenant'
        @($forced.Files).Count | Should -Be 2
    }

    It 'says so, and still takes it, when the folder or the run cannot be checked against the tenant' {
        $run = & $script:NewRunWithDomains (Join-Path $TestDrive 'ad-run5')
        $r = Import-PostureEvidence -Path (& $script:NewAdBundle (Join-Path $TestDrive 'ad5') -NoSuffix) -Run $run -WarningVariable warn 3>$null
        $r.TenantCheck | Should -Match '^not checked: the collector folder does not record'
        "$warn" | Should -Match 'cannot be checked against the run''s tenant'
        $bare = & $script:NewRun (Join-Path $TestDrive 'ad-run6')
        $r2 = Import-PostureEvidence -Path (& $script:NewAdBundle (Join-Path $TestDrive 'ad6')) -Run $bare -WarningVariable warn2 3>$null
        $r2.TenantCheck | Should -Match '^not checked: the run has no list'
        "$warn2" | Should -Match '01-domains\.json comes with the Entra collector'
    }

    It 'files the read in the client folder for later runs with -Client, replacing what was there' {
        $run = & $script:NewRunWithDomains (Join-Path $TestDrive 'ad-run7')
        $client = Join-Path $TestDrive 'client7'; New-Item -ItemType Directory -Path (Join-Path $client 'hybrid') -Force | Out-Null
        'old' | Set-Content (Join-Path $client 'hybrid' 'ad-09-adcs.json')
        'mine' | Set-Content (Join-Path $client 'hybrid' 'notes.txt')
        $r = Import-PostureEvidence -Path (& $script:NewAdBundle (Join-Path $TestDrive 'ad7')) -Run $run -Client $client
        $r.Filed | Should -Be (Join-Path $client 'hybrid')
        @(Get-ChildItem (Join-Path $client 'hybrid') -Name | Sort-Object) | Should -Be @('ad-01-forest-domain.json', 'ad-07-stale-users.csv', 'bundle.json', 'errors.txt', 'notes.txt') -Because 'the earlier collection''s files go, so two collections never mix; a file of the admin''s own stays'
        # The filed folder passes the same checks when a later run brings it in.
        $next = & $script:NewRunWithDomains (Join-Path $TestDrive 'ad-run8')
        (Import-PostureEvidence -Path (Join-Path $client 'hybrid') -Run $next).Checked | Should -Be 'sha256'
    }

    It 'does not file SharePoint evidence: that is for one run' {
        $run = & $script:NewRun (Join-Path $TestDrive 'spo-run9')
        $client = Join-Path $TestDrive 'client9'; New-Item -ItemType Directory -Path $client | Out-Null
        { Import-PostureEvidence -Path (& $script:NewSpoBundle (Join-Path $TestDrive 'spo9')) -Run $run -Client $client } | Should -Throw '*SharePoint evidence is for one run*'
        @(Get-ChildItem (Join-Path $run 'evidence')).Count | Should -Be 0
    }

    It 'rebuilds the report of a run that has one, with the run''s own client folder, and leaves it with -NoReport' {
        InModuleScope TenantKeep.Posture -Parameters @{ NewRun = $script:NewRunWithDomains; NewAd = $script:NewAdBundle; Drive = "$TestDrive" } {
            param($NewRun, $NewAd, $Drive)
            Mock Update-PostureRunReport { Join-Path $Run 'report.html' }
            $client = Join-Path $Drive 'client10'; New-Item -ItemType Directory -Path $client | Out-Null
            $run = & $NewRun (Join-Path $Drive 'ad-run10')
            @{ tenantId = '33333333-3333-3333-3333-333333333333'; client = $client; planned = @('Entra') } | ConvertTo-Json | Set-Content (Join-Path $run 'logs' 'run.json')
            # No report yet: nothing to rebuild.
            (Import-PostureEvidence -Path (& $NewAd (Join-Path $Drive 'ad10')) -Run $run).Report | Should -BeNullOrEmpty
            Should -Invoke Update-PostureRunReport -Times 0 -Exactly
            'report' | Set-Content (Join-Path $run 'report.html')
            (Import-PostureEvidence -Path (& $NewAd (Join-Path $Drive 'ad10b') -Level 'Windows2025Forest') -Run $run -Force -NoReport).Report | Should -BeNullOrEmpty
            Should -Invoke Update-PostureRunReport -Times 0 -Exactly
            (Import-PostureEvidence -Path (& $NewAd (Join-Path $Drive 'ad10c') -Level 'Windows2019Forest') -Run $run -Force).Report | Should -Be (Join-Path $run 'report.html')
            Should -Invoke Update-PostureRunReport -Times 1 -Exactly -ParameterFilter { $Run -eq $run -and $Client -eq $client }
        }
    }

    It 'takes a run kept in one folder, and refuses a folder that is not a run' {
        $flat = Join-Path $TestDrive 'flat-run'; New-Item -ItemType Directory -Path $flat | Out-Null
        @{ tenantId = $script:Tid; collectors = @('Entra') } | ConvertTo-Json | Set-Content (Join-Path $flat 'collection.json')
        ConvertTo-Json -InputObject @(@{ Id = 'contoso.example'; IsVerified = $true }) | Set-Content (Join-Path $flat '01-domains.json')
        $r = Import-PostureEvidence -Path (& $script:NewAdBundle (Join-Path $TestDrive 'ad11')) -Run $flat
        Join-Path $flat 'ad-01-forest-domain.json' | Should -Exist
        $r.TenantCheck | Should -Match '^matched'
        $loose = Join-Path $TestDrive 'not-a-run'; New-Item -ItemType Directory -Path $loose | Out-Null
        { Import-PostureEvidence -Path (& $script:NewAdBundle (Join-Path $TestDrive 'ad12')) -Run $loose } | Should -Throw '*is not a run folder*'
    }
}

