# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    # A run as Start-PostureRun leaves it, with one failed step recorded the way Invoke-PostureStep records it.
    $script:NewRun = {
        param([string] $Root)
        foreach ($p in 'evidence', 'errors', 'logs') { New-Item -ItemType Directory -Path (Join-Path $Root $p) -Force | Out-Null }
        @{ tenantId = '0b1c2d3e-0000-4000-8000-000000000001'; client = (Join-Path $HOME 'tenantkeep' 'clients' 'contoso-ltd'); planned = @('Entra', 'Intune'); skipped = @{ SharePoint = 'not granted' }; runAs = @{ account = 'jane.admin@contoso.example'; roles = @('Global Reader'); checkedUtc = '2026-11-20T14:00:00Z'; coverage = @() } } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $Root 'logs' 'run.json')
        @(@{ displayName = 'Contoso Ltd' }) | ConvertTo-Json | Set-Content (Join-Path $Root 'evidence' '01-organization.json')
        @{ users = 'a list of users' } | ConvertTo-Json | Set-Content (Join-Path $Root 'evidence' 'evidence-sample.json')
        "Transcript: signed in as jane.admin@contoso.example to Contoso Ltd (0b1c2d3e-0000-4000-8000-000000000001), files in $HOME/tenantkeep" | Set-Content (Join-Path $Root 'logs' 'transcript.txt')
        '{"results":[]}' | Set-Content (Join-Path $Root 'logs' 'checks.json')
        $Root
    }
}

Describe 'Export-PostureDiagnostics' {
    It 'records where a failed step stopped and the request it was making' {
        $run = & $script:NewRun (Join-Path $TestDrive 'run1')
        InModuleScope TenantKeep.Posture -Parameters @{ Run = $run } {
            $null = Invoke-PostureStep -Label 'Group Policy analytics' -Folder $Run -Script {
                Add-PostureCallRecord -Service graph -Method GET -Target 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyMigrationReports?$top=999'
                throw 'Forbidden: Application is not authorized to perform this operation for user jane.admin@contoso.example in tenant contoso.onmicrosoft.com.'
            } 3>$null
        }
        $f = Get-Content (Join-Path $run 'errors' 'errors.jsonl') | ConvertFrom-Json
        $f.request | Should -Be 'graph GET beta/deviceManagement/groupPolicyMigrationReports'
        @($f.where).Count | Should -BeGreaterThan 0
        $f.powershell | Should -Not -BeNullOrEmpty
    }

    It 'zips the logs with the tenant''s names taken out, and none of the evidence, the report or checks.json' {
        $run = & $script:NewRun (Join-Path $TestDrive 'run2')
        InModuleScope TenantKeep.Posture -Parameters @{ Run = $run } {
            $null = Invoke-PostureStep -Label 'Autopilot profiles' -Folder $Run -Script { Add-PostureCallRecord -Service graph -Method GET -Target 'https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles'; throw 'Forbidden for jane.admin@contoso.example (request-id 11111111-2222-3333-4444-555555555555) from 203.0.113.9' } 3>$null
            $null = Save-PostureCallLedger -Folder $Run -Confirm:$false
        }
        $r = Export-PostureDiagnostics -Run $run
        $r.Path | Should -Match 'share[\\/]diagnostics-\d{8}-\d{4}\.zip$'
        $r.Failures | Should -Be 1
        $out = Join-Path $TestDrive 'unzipped'
        Expand-Archive -LiteralPath $r.Path -DestinationPath $out
        @(Get-ChildItem $out -Name | Sort-Object) | Should -Be @('calls.json', 'errors.jsonl', 'errors.txt', 'run.json', 'summary.txt', 'transcript.txt')
        $all = (Get-ChildItem $out -File | ForEach-Object { Get-Content -Raw $_.FullName }) -join "`n"
        foreach ($leak in 'jane.admin@contoso.example', 'Contoso Ltd', 'contoso-ltd', '0b1c2d3e-0000-4000-8000-000000000001', '11111111-2222-3333-4444-555555555555', '203.0.113.9', $HOME) { $all | Should -Not -Match ([regex]::Escape($leak)) -Because "$leak names the tenant or the machine" }
        $summary = Get-Content -Raw (Join-Path $out 'summary.txt')
        $summary | Should -Match 'Step: Autopilot profiles'
        $summary | Should -Match 'Request: graph GET beta/deviceManagement/windowsAutopilotDeploymentProfiles'
        $summary | Should -Match 'Skipped SharePoint: not granted'
        $summary | Should -Match 'Where:'
    }

    It 'puts a Copy for Support block per failure in Run Health' {
        $run = & $script:NewRun (Join-Path $TestDrive 'run3')
        Copy-Item -Path (Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot' '*.json') -Destination (Join-Path $run 'evidence')
        InModuleScope TenantKeep.Posture -Parameters @{ Run = $run } {
            $null = Invoke-PostureStep -Label 'Directory settings' -Folder $Run -Script { throw 'Forbidden' } 3>$null
        }
        $rep = New-PostureReport -Evidence (Join-Path $run 'evidence') -OutputPath (Join-Path $TestDrive 'out3') -PassThru 6>$null
        $html = Get-Content -Raw ($rep.Files | Where-Object { $_ -like '*report.html' })
        $html | Should -Match 'Send a Failure for Support'
        $html | Should -Match 'data-copy="support-1"'
        $html | Should -Match 'Export-PostureDiagnostics -Run'
        $html | Should -Not -Match 'jane\.admin@contoso\.example(?![^<]*</td>)' -Because 'the support blocks carry no account names'
    }

    It 'honours -WhatIf and refuses a folder that is not a run' {
        $run = & $script:NewRun (Join-Path $TestDrive 'run4')
        $null = Export-PostureDiagnostics -Run $run -WhatIf
        Join-Path $run 'share' | Should -Not -Exist
        { Export-PostureDiagnostics -Run $TestDrive } | Should -Throw '*not a run folder*'
    }
}
