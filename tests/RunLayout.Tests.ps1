# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-layout-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Run folders' {
    It 'names a run as asked, safe for every file system, and never reuses a name' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
            param($root)
            $a = New-PostureRunFolder -OutRoot $root -Name 'Contoso: Q4/2026' -Confirm:$false
            Split-Path $a.root -Leaf | Should -Be 'Contoso- Q4-2026'
            foreach ($p in 'evidence', 'errors', 'logs') { Join-Path $a.root $p | Should -Exist }
            $b = New-PostureRunFolder -OutRoot $root -Name 'Contoso: Q4/2026' -Confirm:$false
            Split-Path $b.root -Leaf | Should -Be 'Contoso- Q4-2026-2'
            $c = New-PostureRunFolder -OutRoot $root -Timestamp ([datetime]'2026-11-20T09:57:00') -Confirm:$false
            Split-Path $c.root -Leaf | Should -Be '2026-11-20-0957'
            { New-PostureRunFolder -OutRoot $root -Name ' . . ' -Confirm:$false } | Should -Throw '*nothing left*'
        }
    }

    It 'answers the same layout from the run folder or its evidence folder, and one folder for older runs' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } {
            param($root)
            $l = New-PostureRunFolder -OutRoot $root -Name 'layout' -Confirm:$false
            (Get-PostureRunLayout -Folder $l.evidence).root | Should -Be $l.root
            (Get-PostureRunLayout -Folder $l.root).errors | Should -Be (Join-Path $l.root 'errors')
            $flat = Join-Path $root '20261001-0800'; New-Item -ItemType Directory -Path $flat | Out-Null
            $f = Get-PostureRunLayout -Folder $flat
            $f.layout | Should -Be 'flat'
            $f.errors | Should -Be $flat
            $f.logs | Should -Be $flat
        }
    }

    It 'orders runs by when they started, whatever they are called, and finds the previous run of the same tenant' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = (Join-Path $script:Root 'ordered') } {
            param($root)
            $mk = {
                param([string] $Name, [string] $Started, [string] $Tenant)
                $l = New-PostureRunFolder -OutRoot $root -Name $Name -Confirm:$false
                @{ tenantId = $Tenant; startedUtc = $Started; planned = @('Entra') } | ConvertTo-Json | Set-Content (Join-Path $l.logs 'run.json')
                Set-Content (Join-Path $l.logs 'checks.json') -Value '{}'
                $l
            }
            $old = & $mk 'Zebra baseline' '2026-10-01T09:00:00Z' 't1'
            $other = & $mk 'Another tenant' '2026-11-01T09:00:00Z' 't2'
            $new = & $mk 'Alpha follow-up' '2026-11-20T09:00:00Z' 't1'
            @(Get-PostureRunInfo -Root $root).path | Should -Be @($new.root, $other.root, $old.root) -Because 'the names sort the other way; the start time decides'
            Get-PosturePreviousRun -Run $new.root | Should -Be (Join-Path $old.logs 'checks.json') -Because 'the newer run of another tenant is not a trend'
            Get-PosturePreviousRun -Run $old.root | Should -BeNullOrEmpty
        }
    }

    It 'puts the report at the top, checks.json in logs, affected lists beside the report, and README.txt' {
        $l = InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root } { param($root) New-PostureRunFolder -OutRoot $root -Name 'report layout' -Confirm:$false }
        $null = Initialize-CollectionFixture -Root $l.evidence
        $null = New-PostureReport -Evidence $l.evidence 6>$null
        Join-Path $l.root 'report.html' | Should -Exist
        Join-Path $l.logs 'checks.json' | Should -Exist
        Join-Path $l.evidence 'checks.json' | Should -Not -Exist
        @(Get-ChildItem (Join-Path $l.root 'affected') -Filter '*.csv').Count | Should -BeGreaterThan 0
        Export-PostureFindings -Path $l.root | Should -Be (Join-Path $l.root 'findings.csv')
        InModuleScope TenantKeep.Posture -Parameters @{ l = $l } { param($l) Write-PostureRunReadme -Layout $l -Confirm:$false }
        Get-Content -Raw (Join-Path $l.root 'README.txt') | Should -Match 'report\.html\s+Open this'
    }
}

Describe 'What -Client means on Start-PostureRun' {
    # "-Client contoso" was a path and nothing else: a live run started a second client folder in the directory the
    # admin was in, with no licence in it, while Resume-PostureRun read the same words as the client's name.
    BeforeAll {
        $script:ClientRoot = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-clientpath-$([guid]::NewGuid().ToString('n'))"
        $script:Clients = Join-Path $script:ClientRoot 'clients'
        $script:Here = Join-Path $script:ClientRoot 'somewhere'
        New-Item -ItemType Directory -Path (Join-Path $script:Clients 'contoso'), (Join-Path $script:Here 'local-folder') -Force | Out-Null
    }
    AfterAll { if (Test-Path $script:ClientRoot) { Remove-Item -LiteralPath $script:ClientRoot -Recurse -Force } }

    It 'takes a bare name as the client of that name, whether or not it exists yet' {
        InModuleScope TenantKeep.Posture -Parameters @{ clients = $script:Clients; here = $script:Here } {
            param($clients, $here)
            Push-Location $here
            try {
                Resolve-PostureClientPath -Client 'contoso' -ClientsRoot $clients | Should -Be (Join-Path $clients 'contoso')
                Resolve-PostureClientPath -Client 'fabrikam' -ClientsRoot $clients | Should -Be (Join-Path $clients 'fabrikam') -Because 'a new client starts under the clients folder, not where the admin happens to be'
                Join-Path $here 'contoso' | Should -Not -Exist
            }
            finally { Pop-Location }
        }
    }

    It 'takes a folder that exists where you are, and anything written as a path, as that folder' {
        InModuleScope TenantKeep.Posture -Parameters @{ clients = $script:Clients; here = $script:Here } {
            param($clients, $here)
            Push-Location $here
            try {
                Resolve-PostureClientPath -Client 'local-folder' -ClientsRoot $clients | Should -Be (Join-Path $here 'local-folder')
                Resolve-PostureClientPath -Client (Join-Path '.' 'new-here') -ClientsRoot $clients | Should -Be (Join-Path $here 'new-here')
                $absolute = Join-Path $here 'elsewhere'
                Resolve-PostureClientPath -Client $absolute -ClientsRoot $clients | Should -Be $absolute
            }
            finally { Pop-Location }
        }
    }
}
