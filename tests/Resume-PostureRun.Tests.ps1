# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-resume-$([guid]::NewGuid().ToString('n'))"
    $script:Client = Join-Path $script:Root 'clients' 'contoso'
    New-Item -ItemType Directory -Path $script:Client -Force | Out-Null
    $script:Tid = '55555555-5555-5555-5555-555555555555'
    @{ tenantId = $script:Tid } | ConvertTo-Json | Set-Content (Join-Path $script:Client 'profile.json')
    $script:NewRun = {
        param([string] $Name)
        $f = Join-Path $script:Root 'evidence' $Name
        New-Item -ItemType Directory -Path $f -Force | Out-Null
        @{ tenantId = $script:Tid; client = $script:Client; planned = @('Entra', 'Intune', 'Exchange', 'Purview'); skipped = @{ Azure = 'Az.Accounts and Az.ResourceGraph are not installed.' }; resumes = @() } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $f 'run.json')
        @{ tenantId = $script:Tid; collectors = @('ConditionalAccess', 'Entra', 'Intune', 'Purview') } | ConvertTo-Json | Set-Content (Join-Path $f 'collection.json')
        $lines = @(
            (@{ collector = 'Purview'; step = 'DLP policies'; cause = 'permission'; roles = @('View-Only DLP Compliance Management (role)'); scopes = @(); licence = ''; note = ''; message = 'Get-DlpCompliancePolicy is not available; import ExchangeOnlineManagement and connect first.' } | ConvertTo-Json -Compress)
            (@{ collector = 'Intune'; step = 'Apple VPP tokens'; cause = 'licence'; roles = @(); scopes = @(); licence = 'Intune'; note = ''; message = 'You do not have the required license to perform this operation.' } | ConvertTo-Json -Compress)
        )
        Set-Content -LiteralPath (Join-Path $f 'errors.jsonl') -Value $lines
        Set-Content -LiteralPath (Join-Path $f 'errors.txt') -Value 'DLP policies :: Get-DlpCompliancePolicy is not available; import ExchangeOnlineManagement and connect first.', 'Apple VPP tokens :: You do not have the required license to perform this operation.'
        $f
    }
    Mock Write-Host {} -ModuleName TenantKeep.Posture
    Mock Start-PostureRun -ModuleName TenantKeep.Posture { $script:RunArgs = $PSBoundParameters; [pscustomobject]@{ Folder = $Folder; Report = (Join-Path $Folder 'report.html') } }
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Resume-PostureRun' {
    It 'collects again what never finished and what failed for a reason a retry fixes, and leaves facts about the tenant alone' {
        $f = & $script:NewRun '20261120-0930'
        $r = Resume-PostureRun -Path $f -PassThru -Confirm:$false
        @($r.Recollected | Sort-Object) | Should -Be @('Exchange', 'Purview') -Because 'Exchange never finished and Purview was refused a role; Intune is not licensed, which a retry would not change'
        Should -Invoke Start-PostureRun -ModuleName TenantKeep.Posture -Times 1 -Exactly -ParameterFilter { $Folder -eq $f -and $TenantId -eq $script:Tid -and $Client -eq $script:Client }
    }

    It 'moves the retried failures out of the live files and keeps the rest' {
        $f = & $script:NewRun '20261120-1000'
        $null = Resume-PostureRun -Path $f -Confirm:$false
        $live = @(Get-Content (Join-Path $f 'errors.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
        $live.collector | Should -Be @('Intune')
        @(Get-Content (Join-Path $f 'errors.txt')) | Should -Be @('Apple VPP tokens :: You do not have the required license to perform this operation.')
        (Get-Content (Join-Path $f 'errors-previous.jsonl') | ConvertFrom-Json).step | Should -Be 'DLP policies'
    }

    It 'takes -Collector as given, and stops with a note when nothing a retry can fix is left' {
        $f = & $script:NewRun '20261120-1030'
        $r = Resume-PostureRun -Path $f -Collector Azure -PassThru -Confirm:$false
        $r.Recollected | Should -Be @('Azure')
        $done = Join-Path $script:Root 'evidence' '20261120-1100'; New-Item -ItemType Directory -Path $done | Out-Null
        @{ tenantId = $script:Tid; client = $script:Client; planned = @('Entra'); skipped = @{} } | ConvertTo-Json | Set-Content (Join-Path $done 'run.json')
        @{ tenantId = $script:Tid; collectors = @('Entra') } | ConvertTo-Json | Set-Content (Join-Path $done 'collection.json')
        Resume-PostureRun -Path $done -Confirm:$false | Should -BeNullOrEmpty
        Should -Invoke Start-PostureRun -ModuleName TenantKeep.Posture -Times 0 -Exactly -ParameterFilter { $Folder -eq $done }
    }

    It 'leaves a domain whose only failures are not available to the account or licence, however an older version recorded them' {
        $f = Join-Path $script:Root 'evidence' '20261120-1200'; New-Item -ItemType Directory -Path $f | Out-Null
        @{ tenantId = $script:Tid; client = $script:Client; planned = @('Purview'); skipped = @{} } | ConvertTo-Json | Set-Content (Join-Path $f 'run.json')
        @{ tenantId = $script:Tid; collectors = @('Purview') } | ConvertTo-Json | Set-Content (Join-Path $f 'collection.json')
        Set-Content (Join-Path $f 'errors.jsonl') -Value (@{ collector = 'Purview'; step = 'Auto-labeling policies'; cause = 'unknown'; message = "Get-AutoSensitivityLabelPolicy is not in this session: the signed-in roles or the tenant's licences do not expose it." } | ConvertTo-Json -Compress)
        Resume-PostureRun -Path $f -Confirm:$false | Should -BeNullOrEmpty
        Should -Invoke Start-PostureRun -ModuleName TenantKeep.Posture -Times 0 -Exactly -ParameterFilter { $Folder -eq $f }
    }

    It 'finds the newest run without a path, for every client or for one by name' {
        InModuleScope TenantKeep.Posture -Parameters @{ root = $script:Root; client = $script:Client } {
            param($root, $client)
            $clients = Split-Path $client -Parent
            $other = Join-Path $clients 'fabrikam'; New-Item -ItemType Directory -Path $other -Force | Out-Null
            $otherRoot = Join-Path $root 'fabrikam-runs'
            @{ tenantId = '66666666-6666-6666-6666-666666666666'; outputRoot = $otherRoot } | ConvertTo-Json | Set-Content (Join-Path $other 'profile.json')
            $p = Join-Path $client 'profile.json'; $d = Get-Content -Raw $p | ConvertFrom-Json -AsHashtable; $d.outputRoot = (Join-Path $root 'evidence'); $d | ConvertTo-Json | Set-Content $p
            $newest = Join-Path $otherRoot '20261121-0800'; New-Item -ItemType Directory -Path $newest -Force | Out-Null
            @{ tenantId = '66666666-6666-6666-6666-666666666666'; client = $other; planned = @('Entra') } | ConvertTo-Json | Set-Content (Join-Path $newest 'run.json')
            Find-PostureLatestRun -ClientsRoot $clients | Should -Be $newest -Because 'the newest run of any client'
            Find-PostureLatestRun -Client 'contoso' -ClientsRoot $clients | Should -Be (Join-Path $root 'evidence' '20261120-1200') -Because 'the newest of that client, found by name'
            { Find-PostureLatestRun -Client 'nobody' -ClientsRoot $clients } | Should -Throw '*No client folder named nobody*'
        }
    }

    It 'refuses a folder that is not a run' {
        $empty = Join-Path $script:Root 'not-a-run'; New-Item -ItemType Directory -Path $empty | Out-Null
        { Resume-PostureRun -Path $empty -Confirm:$false } | Should -Throw '*not a run folder*'
    }
}
