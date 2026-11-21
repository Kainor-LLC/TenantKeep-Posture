# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# The run's journal (logs/journal.jsonl): steps, files and finished collectors as they happen. Resume reads it to
# know what finished, and the evidence readers read it so a file left from an earlier attempt is never taken for
# this attempt's evidence.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-journal-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    Mock -ModuleName TenantKeep.Posture Write-Host { }
    Mock -ModuleName TenantKeep.Posture Step-PostureProgress { }
}

AfterAll {
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null; $script:PostureJournalFolder = $null; $script:PostureCurrentStep = $null }
}

Describe 'The journal of a collection' {
    It 'records a step that finished and one that failed, the files each wrote, and nothing when no collection opened it' {
        InModuleScope TenantKeep.Posture -Parameters @{ Root = $script:Root } {
            param($Root)
            $f = Join-Path $Root 'run1'; New-Item -ItemType Directory -Path $f | Out-Null
            # Outside a collection: nothing is written.
            $null = Invoke-PostureStep -Label 'Quiet' -Folder $f -Script { $null = Write-PostureEvidence -Folder $f -Name 'q' -InputObject @{ a = 1 } -Quiet }
            Join-Path $f 'journal.jsonl' | Should -Not -Exist

            $script:PostureJournalFolder = $f; $script:PostureCurrentCollector = 'Entra'
            try {
                $null = Invoke-PostureStep -Label 'Users' -Folder $f -Script {
                    $null = Write-PostureEvidence -Folder $f -Name '06-users-summary' -InputObject @{ Total = 3 } -Quiet
                    $s = Open-PostureEvidenceStream -Folder $f -Name '06-users' -Csv -Confirm:$false
                    foreach ($i in 1..3) { Add-PostureEvidenceRow -Stream $s -Row ([ordered]@{ Id = $i }) }
                    $null = Close-PostureEvidenceStream -Stream $s -Quiet
                }
                $null = Invoke-PostureStep -Label 'Risky users' -Folder $f -Script { throw 'Authorization_RequestDenied: Insufficient privileges' } -WarningAction SilentlyContinue
            }
            finally { $script:PostureJournalFolder = $null; $script:PostureCurrentCollector = $null }

            $entries = @(Read-PostureJournal -Folder $f)
            @($entries | ForEach-Object { "$($_['kind'])/$($_['state'])/$($_['step'])$($_['name'])" }) | Should -Be @('step/started/Users', 'file//Users06-users-summary', 'file//Users06-users', 'step/done/Users', 'step/started/Risky users', 'step/failed/Risky users')
            $file = @($entries | Where-Object { $_['name'] -eq '06-users' })[0]
            $file['rows'] | Should -Be 3
            $file['bytes'] | Should -BeGreaterThan 0
            $file['collector'] | Should -Be 'Entra'
            @($entries | Where-Object { $_['state'] -eq 'failed' })[0]['cause'] | Should -Be 'permission'
            $state = Get-PostureJournalState -Folder $f
            $state.present | Should -BeTrue
            $state.steps['Entra|Users'].state | Should -Be 'done'
            $state.steps['Entra|Risky users'].state | Should -Be 'failed'
        }
    }

    It 'gives a step inside another its own label, and the outer step its label back' {
        InModuleScope TenantKeep.Posture -Parameters @{ Root = $script:Root } {
            param($Root)
            $f = Join-Path $Root 'nested'; New-Item -ItemType Directory -Path $f | Out-Null
            $script:PostureJournalFolder = $f; $script:PostureCurrentCollector = 'SignIns'
            try {
                $null = Invoke-PostureStep -Label 'Outer' -Folder $f -Script {
                    $null = Invoke-PostureStep -Label 'Inner' -Folder $f -Script { $null = Write-PostureEvidence -Folder $f -Name 'inner' -InputObject @{ a = 1 } -Quiet }
                    $null = Write-PostureEvidence -Folder $f -Name 'outer' -InputObject @{ a = 1 } -Quiet
                }
            }
            finally { $script:PostureJournalFolder = $null; $script:PostureCurrentCollector = $null }
            $state = Get-PostureJournalState -Folder $f
            $state.files['inner'].step | Should -Be 'Inner'
            $state.files['outer'].step | Should -Be 'Outer'
            $script:PostureCurrentStep | Should -BeNullOrEmpty
        }
    }
}

Describe 'A file left from an earlier attempt' {
    BeforeAll {
        # First attempt: both steps write their file. Second attempt: one step fails before writing, the other
        # writes what it could read and then fails on purpose (as the Azure and role holder steps do).
        $script:Run = Join-Path $script:Root 'stale'
        New-Item -ItemType Directory -Path $script:Run | Out-Null
        InModuleScope TenantKeep.Posture -Parameters @{ F = $script:Run } {
            param($F)
            $script:PostureJournalFolder = $F; $script:PostureCurrentCollector = 'Test'
            try {
                $null = Invoke-PostureStep -Label 'Refused later' -Folder $F -Script { $null = Write-PostureEvidence -Folder $F -Name 'e' -InputObject @(@{ old = $true }) -AsArray -Quiet }
                $null = Invoke-PostureStep -Label 'Partial later' -Folder $F -Script { $null = Write-PostureEvidence -Folder $F -Name 'p' -InputObject @(@{ attempt = 1 }) -AsArray -Quiet }
                $null = Invoke-PostureStep -Label 'Untouched' -Folder $F -Script { $null = Write-PostureEvidence -Folder $F -Name 'u' -InputObject @(@{ attempt = 1 }) -AsArray -Quiet }
                $null = Invoke-PostureStep -Label 'Refused later' -Folder $F -Script { throw 'Authorization_RequestDenied: the role was taken away' } -WarningAction SilentlyContinue
                $null = Invoke-PostureStep -Label 'Partial later' -Folder $F -Script { $null = Write-PostureEvidence -Folder $F -Name 'p' -InputObject @(@{ attempt = 2 }) -AsArray -Quiet; throw 'one subscription refused' } -WarningAction SilentlyContinue
            }
            finally { $script:PostureJournalFolder = $null; $script:PostureCurrentCollector = $null }
        }
    }

    It 'is named as stale, and only that one' {
        InModuleScope TenantKeep.Posture -Parameters @{ F = $script:Run } { param($F) @(Get-PostureStaleEvidence -Folder $F) | Should -Be @('e') }
    }

    It 'is not read by any reader, while a file written in the attempt that failed and one never tried again are' {
        InModuleScope TenantKeep.Posture -Parameters @{ F = $script:Run } {
            param($F)
            Clear-PostureEvidenceCache -Confirm:$false
            Join-Path $F 'e.json' | Should -Exist -Because 'the file is still on disk; it is the reading that stops'
            Read-PostureEvidenceFile -Folder $F -Name 'e' | Should -BeNullOrEmpty
            Read-PostureEvidenceRow -Folder $F -Name 'e' -OnRow { throw 'a stale file was read' } | Should -BeFalse
            Find-PostureEvidenceRow -Folder $F -Name 'e' -Key 'old' -Value 'True' | Should -BeNullOrEmpty
            $p = Read-PostureEvidenceFile -Folder $F -Name 'p'
            @($p)[0]['attempt'] | Should -Be 2 -Because 'what a step wrote before it failed is this attempt''s evidence'
            $u = Read-PostureEvidenceFile -Folder $F -Name 'u'
            @($u)[0]['attempt'] | Should -Be 1
        }
    }

    It 'makes a check that needs it not evaluated, and says the file is left from an earlier attempt' {
        . (Join-Path $PSScriptRoot 'Fixtures' 'CheckEngineFixture.ps1')
        $fx = Initialize-CheckEngineFixture -Root (Join-Path $script:Root 'fx')
        InModuleScope TenantKeep.Posture -Parameters @{ Fx = $fx; Ev = $script:Run } {
            param($Fx, $Ev)
            $catalog = Import-PostureCheckCatalog -Path $Fx.Checks
            $run = Invoke-PostureCheckEvaluation -Catalog $catalog -Baseline (Import-PostureBaseline -Baseline (Join-Path $Fx.Baselines 'standard.json')) -OrgProfile (Import-PostureProfile) -Evidence $Ev -FactProvider @{ test = $Fx.Provider }
            $r = @($run.results | Where-Object { $_.id -eq 'TS-001' })[0]
            $r.status | Should -Be 'notEvaluated' -Because 'TS-001 names e.json as its evidence'
            $r.reason | Should -Match 'e is left from an earlier attempt and the step that writes it did not write it again'
        }
    }

    It 'is nothing at all in a folder with no journal' {
        InModuleScope TenantKeep.Posture -Parameters @{ Root = $script:Root } {
            param($Root)
            $f = Join-Path $Root 'nojournal'; New-Item -ItemType Directory -Path $f | Out-Null
            @(Get-PostureStaleEvidence -Folder $f).Count | Should -Be 0
            (Get-PostureJournalState -Folder $f).present | Should -BeFalse
        }
    }
}

Describe 'Run Health for a collection that stopped' {
    It 'says which domain did not finish, the step it stopped in, the file left from an earlier attempt and the write that was cut short' {
        . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
        $ev = Initialize-CollectionFixture -Root (Join-Path $script:Root 'stopped-run')
        @{ tenantId = '11111111-1111-1111-1111-111111111111'; client = $script:Root; planned = @('Entra', 'Defender'); skipped = @{}; resumes = @() } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $ev 'run.json')
        $lines = @(
            @{ kind = 'run'; state = 'started'; collectors = @('Entra', 'Defender') }
            @{ kind = 'collector'; state = 'started'; collector = 'Entra' }
            @{ kind = 'step'; state = 'started'; collector = 'Entra'; step = 'Users' }, @{ kind = 'file'; collector = 'Entra'; step = 'Users'; name = '06-users.json'; rows = 7; bytes = 900 }, @{ kind = 'step'; state = 'done'; collector = 'Entra'; step = 'Users' }
            @{ kind = 'collector'; state = 'done'; collector = 'Entra' }
            # A second attempt at the users, refused: the file from the first is still on disk.
            @{ kind = 'collector'; state = 'started'; collector = 'Entra' }
            @{ kind = 'step'; state = 'started'; collector = 'Entra'; step = 'Users' }, @{ kind = 'step'; state = 'failed'; collector = 'Entra'; step = 'Users'; cause = 'permission'; message = 'Forbidden' }
            @{ kind = 'collector'; state = 'done'; collector = 'Entra' }
            @{ kind = 'collector'; state = 'started'; collector = 'Defender' }
            @{ kind = 'step'; state = 'started'; collector = 'Defender'; step = 'Defender devices' }
        ) | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 5 }
        Set-Content -LiteralPath (Join-Path $ev 'journal.jsonl') -Value $lines
        Set-Content -LiteralPath (Join-Path $ev 'mde-01-devices.csv.part') -Value 'DeviceId,DeviceName'
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache -Confirm:$false }

        $r = New-PostureReport -Evidence $ev -PassThru
        $rh = $r.Report.runHealth
        @($rh.notFinished) | Should -Be @('Defender')
        @($rh.stoppedIn | ForEach-Object { "$($_.collector): $($_.step)" }) | Should -Be @('Defender: Defender devices')
        @($rh.stale | ForEach-Object { "$($_.file) ($($_.step))" }) | Should -Be @('06-users (Users)')
        @($rh.cutShort) | Should -Be @('mde-01-devices.csv.part')
        $html = Get-Content -Raw (@($r.Files) -like '*.html')[0]
        $html | Should -Match 'The collection stopped before the end\.</strong> Defender did not finish'
        $html | Should -Match 'Where the Collection Stopped'
        $html | Should -Match '<td>Defender</td><td>Defender devices</td>'
        $html | Should -Match '<code>06-users</code></td><td>Entra</td><td>Users</td>'
        $html | Should -Match '<code>mde-01-devices\.csv\.part</code>'
        $html | Should -Not -Match 'Every collection step ran'
        $md = Get-Content -Raw (@($r.Files) -like '*.md')[0]
        $md | Should -Match '### Where the collection stopped'
        $md | Should -Match 'Did not finish: Defender'
        # The users file is on disk and is not read: no check that requires it has an answer from it.
        $needUsers = @($r.Report.results | Where-Object { $_.id -in 'UX-009', 'UX-010', 'UX-020', 'ID-004', 'ID-005' })
        $needUsers.Count | Should -Be 5
        @($needUsers | Where-Object { $_.status -ne 'notEvaluated' }).Count | Should -Be 0 -Because 'a file left from an earlier attempt answers no check'
    }

    It 'lists the checks judged on part of the data, each with how much was read' {
        . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
        $ev = Initialize-CollectionFixture -Root (Join-Path $script:Root 'part-run')
        $r = New-PostureReport -Evidence $ev -PassThru
        $r.Report.runHealth.Contains('judgedOnPart') | Should -BeTrue
        # The same report with one answer marked as judged on part, through both renderers.
        $r.Report.runHealth.judgedOnPart = @([ordered]@{ id = 'AZ-014'; title = 'Storage accounts refuse public access'; status = 'fail'; note = 'Judged on 200 of 260 subscriptions; the other 60 were not read.' })
        InModuleScope TenantKeep.Posture -Parameters @{ Report = $r.Report } {
            param($Report)
            $html = ConvertTo-PostureReportHtml -Report $Report
            $html | Should -Match 'Judged on Part of the Data'
            $html | Should -Match '<code>AZ-014</code></td><td>Storage accounts refuse public access</td><td><span class="status fail">Fail</span></td><td>Judged on 200 of 260 subscriptions; the other 60 were not read\.</td>'
            $md = ConvertTo-PostureReportMarkdown -Report $Report
            $md | Should -Match '### Judged on part of the data'
            $md | Should -Match '\| AZ-014 \| Storage accounts refuse public access \| Fail \| Judged on 200 of 260 subscriptions; the other 60 were not read\. \|'
        }
    }
}
