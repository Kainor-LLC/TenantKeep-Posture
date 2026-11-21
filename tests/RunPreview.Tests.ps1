# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Before a run collects: the tenant's size and what it means for the run; and the folders a run and a client live
# in, which are the owner's alone.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-preview-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
}

AfterAll { Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'The size of the tenant, asked before collecting' {
    It 'asks Graph three times, each for one object and the count, and reads no list' {
        InModuleScope TenantKeep.Posture {
            $script:TestAsked = [System.Collections.Generic.List[string]]::new()
            Mock Invoke-PostureGraphRequest {
                $script:TestAsked.Add("$Uri | $($Headers['ConsistencyLevel']) | $([bool]$Single)")
                @{ '@odata.count' = @{ users = 312400; devices = 48200; groups = 51000 }[($Uri -split '\?')[0]]; value = @(@{ id = 'x' }) }
            }
            $size = Get-PostureTenantSize
            $size.users | Should -Be 312400
            $size.devices | Should -Be 48200
            $size.groups | Should -Be 51000
            @($script:TestAsked) | Should -Be @('users?$count=true&$select=id&$top=1 | eventual | True', 'devices?$count=true&$select=id&$top=1 | eventual | True', 'groups?$count=true&$select=id&$top=1 | eventual | True')
            Remove-Variable -Name TestAsked -Scope Script
        }
    }

    It 'says unknown for a count Graph will not give, and never stops the run' {
        InModuleScope TenantKeep.Posture {
            Mock Invoke-PostureGraphRequest { if ($Uri -match '^devices') { throw 'Authorization_RequestDenied: Insufficient privileges' }; @{ '@odata.count' = 7; value = @() } }
            $size = Get-PostureTenantSize
            $size.users | Should -Be 7
            $size.devices | Should -BeNullOrEmpty
            @(Get-PostureRunPreview -Size $size -Collector Entra)[0] | Should -Be 'Tenant size:   7 users, an unknown number of devices, 7 groups.'
        }
    }
}

Describe 'What a run says before it collects' {
    It 'is one line for a small tenant' {
        InModuleScope TenantKeep.Posture {
            $lines = @(Get-PostureRunPreview -Size @{ users = 310; devices = 280; groups = 95 } -Collector Entra, SharePoint, Exchange)
            $lines | Should -Be @('Tenant size:   310 users, 280 devices, 95 groups.')
        }
    }

    It 'says how many requests the long lists are, what is sampled and what is left out, for a large one' {
        InModuleScope TenantKeep.Posture {
            $lines = @(Get-PostureRunPreview -Size @{ users = 300000; devices = 50000; groups = 50000 } -Collector Entra, SharePoint)
            $lines[0] | Should -Be 'Tenant size:   300,000 users, 50,000 devices, 50,000 groups.'
            $lines[1] | Should -Match '^  The user list is about 2,500 requests and the registration report about 301\.'
            $lines[2] | Should -Be '  Per-user MFA is read for a sample: every administrator and 1,000 other members. -FullPerUserMfa reads everyone.'
            $lines[3] | Should -Match '^  OneDrive sites are not listed'
            $lines[4] | Should -Match '^  At this size the run takes hours'
            $lines.Count | Should -Be 5
            foreach ($l in $lines) { $l | Should -Not -Match ([string][char]0x2014) }
        }
    }

    It 'follows what was asked for: everyone''s per-user MFA, the OneDrives, or no Entra at all' {
        InModuleScope TenantKeep.Posture {
            $size = @{ users = 30000; devices = 1; groups = 1 }
            @(Get-PostureRunPreview -Size $size -Collector Entra -FullPerUserMfa)[2] | Should -Be '  Per-user MFA is read for every member, a request for each twenty: about 1,500 requests.'
            @(Get-PostureRunPreview -Size $size -Collector SharePoint -IncludeOneDriveSites | Where-Object { $_ -match 'OneDrive' }) | Should -BeNullOrEmpty
            @(Get-PostureRunPreview -Size $size -Collector Azure | Where-Object { $_ -match 'user list|Per-user MFA' }) | Should -BeNullOrEmpty
        }
    }
}

Describe 'The folders a run and a client live in' {
    It 'are the owner''s alone where the platform has file modes' -Skip:$IsWindows {
        InModuleScope TenantKeep.Posture -Parameters @{ Root = $script:Root } {
            param($Root)
            $open = Join-Path $Root 'open'; New-Item -ItemType Directory -Path $open | Out-Null
            [System.IO.File]::SetUnixFileMode($open, [System.IO.UnixFileMode]'UserRead, UserWrite, UserExecute, GroupRead, GroupExecute, OtherRead, OtherExecute')
            Set-PostureFolderPrivate -Path $open -Confirm:$false | Should -Be 'set'
            [System.IO.File]::GetUnixFileMode($open) | Should -Be ([System.IO.UnixFileMode]'UserRead, UserWrite, UserExecute')
            Set-PostureFolderPrivate -Path $open -Confirm:$false | Should -Be 'already'
            # A file written inside afterwards is still the owner's to read and write.
            Set-Content -LiteralPath (Join-Path $open 'x.json') -Value '{}'
            Get-Content -Raw -LiteralPath (Join-Path $open 'x.json') | Should -Match '\{\}'
        }
    }

    It 'are made that way when a run folder, a collection folder or a client folder is created' -Skip:$IsWindows {
        $mine = [System.IO.UnixFileMode]'UserRead, UserWrite, UserExecute'
        InModuleScope TenantKeep.Posture -Parameters @{ Root = $script:Root; Mine = $mine } {
            param($Root, $Mine)
            $run = New-PostureRunFolder -OutRoot (Join-Path $Root 'runs') -Name 'a run' -Confirm:$false
            [System.IO.File]::GetUnixFileMode($run.root) | Should -Be $Mine
            $flat = New-PostureEvidenceFolder -OutRoot (Join-Path $Root 'flat') -NoTranscript -Confirm:$false
            [System.IO.File]::GetUnixFileMode($flat) | Should -Be $Mine
        }
        $client = Join-Path $script:Root 'client'
        $null = Initialize-PostureClient -Path $client -TenantId '33333333-3333-3333-3333-333333333333' 6>$null
        [System.IO.File]::GetUnixFileMode($client) | Should -Be $mine
    }

    It 'never stops a run when the mode cannot be set, and changes nothing on Windows' {
        InModuleScope TenantKeep.Posture -Parameters @{ Root = $script:Root } {
            param($Root)
            Set-PostureFolderPrivate -Path (Join-Path $Root 'not-there') -Confirm:$false | Should -BeIn @('failed', 'windows')
            $kept = Join-Path $Root 'whatif'; New-Item -ItemType Directory -Path $kept | Out-Null
            { Set-PostureFolderPrivate -Path $kept -WhatIf } | Should -Not -Throw
        }
    }
}
