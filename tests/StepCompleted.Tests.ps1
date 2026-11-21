# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Invoke-PostureCollection -StepCompleted and -SkipFinished: what a caller that keeps a copy of the run as it goes
# (the Automation runbook) is handed, and how a run it continues leaves finished domains alone.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-stepdone-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    Mock -ModuleName TenantKeep.Posture Write-Host { }

    # A collection of two domains with made-up steps; -Fail makes one step fail after writing a file.
    $script:Collect = {
        param([string] $Folder, [scriptblock] $StepCompleted, [switch] $SkipFinished, [string[]] $Collector = @('Entra', 'Intune'))
        InModuleScope TenantKeep.Posture -Parameters @{ Folder = $Folder; StepCompleted = $StepCompleted; SkipFinished = [bool]$SkipFinished; Collector = $Collector } {
            param($Folder, $StepCompleted, $SkipFinished, $Collector)
            Mock Get-MgContext { [pscustomobject]@{ TenantId = 'tenant-guid'; Account = 'reader@contoso.example'; AuthType = 'AppOnly'; Scopes = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All') } }
            Mock Start-Transcript { }
            Mock Stop-Transcript { }
            Mock Invoke-PostureEntraCollection {
                $script:TestRan.Add('Entra')
                $null = Invoke-PostureStep -Label 'Organization' -Folder $Folder -Script { $null = Write-PostureEvidence -Folder $Folder -Name '01-organization' -InputObject @(@{ id = 't' }) -AsArray -Quiet }
                $null = Invoke-PostureStep -Label 'Users' -Folder $Folder -Script {
                    $s = Open-PostureEvidenceStream -Folder $Folder -Name '06-users' -Csv -Confirm:$false
                    Add-PostureEvidenceRow -Stream $s -Row ([ordered]@{ Id = 'u1' })
                    $null = Close-PostureEvidenceStream -Stream $s -Quiet
                    # A step inside the step hands over its own file.
                    $null = Invoke-PostureStep -Label 'Users summary' -Folder $Folder -Script { $null = Write-PostureEvidence -Folder $Folder -Name '06-users-summary' -InputObject @{ Total = 1 } -Quiet }
                    $null = Write-PostureEvidence -Folder $Folder -Name '06-users-admins' -InputObject @(@{ Id = 'u1' }) -AsArray -Csv -Quiet
                }
                $null = Invoke-PostureStep -Label 'Risky users' -Folder $Folder -Script {
                    $null = Write-PostureEvidence -Folder $Folder -Name '11-risky-users-summary' -InputObject @{ Read = $false } -Quiet
                    throw 'Authorization_RequestDenied: Insufficient privileges'
                } -WarningAction SilentlyContinue
                @{ files = @() }
            }
            Mock Invoke-PostureIntuneCollection {
                $script:TestRan.Add('Intune')
                $null = Invoke-PostureStep -Label 'Intune apps' -Folder $Folder -Script { $null = Write-PostureEvidence -Folder $Folder -Name '09-intune-apps' -InputObject @() -AsArray -Quiet }
                @{ files = @() }
            }
            $script:TestRan = [System.Collections.Generic.List[string]]::new()
            $more = @{}; if ($StepCompleted) { $more.StepCompleted = $StepCompleted }
            $null = Invoke-PostureCollection -Collector $Collector -SkipCaSnapshot -OutputFolder $Folder -SkipFinished:$SkipFinished -PassThru -WarningAction SilentlyContinue @more
            $ran = @($script:TestRan); Remove-Variable -Name TestRan -Scope Script
            $ran
        }
    }
}

AfterAll { Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'Invoke-PostureCollection -StepCompleted' {
    BeforeAll {
        $script:Run = Join-Path $script:Root 'run'; New-Item -ItemType Directory -Path $script:Run | Out-Null
        $script:Seen = [System.Collections.Generic.List[object]]::new()
        # The block is the caller's: it reads the caller's variables, as the runbook's reads its storage helpers.
        $null = & $script:Collect $script:Run { param($done) $script:Seen.Add([pscustomobject]@{ collector = $done.collector; step = $done.step; state = $done.state; files = @($done.files | ForEach-Object { Split-Path $_ -Leaf }); record = @($done.record | ForEach-Object { Split-Path $_ -Leaf }); folder = $done.folder; exists = (@($done.files | Where-Object { -not (Test-Path -LiteralPath $_) }).Count -eq 0) }) }
        $script:By = { param([string] $Step) @($script:Seen | Where-Object { $_.step -eq $Step }) }
    }

    It 'is called once for each step, with the files that step closed, JSON and CSV' {
        (& $script:By 'Organization').files | Should -Be @('01-organization.json')
        (& $script:By 'Users summary').files | Should -Be @('06-users-summary.json')
        (& $script:By 'Users').files | Should -Be @('06-users.json', '06-users.csv', '06-users-admins.json', '06-users-admins.csv') -Because 'the file of the step inside it was handed over by that step'
        (& $script:By 'Intune apps').files | Should -Be @('09-intune-apps.json')
        @($script:Seen | Where-Object { $_.step }).Count | Should -Be 5
        @($script:Seen | Where-Object { -not $_.exists }).Count | Should -Be 0 -Because 'only finished files are handed over, under their final names'
        @($script:Seen | ForEach-Object { $_.files } | Where-Object { $_ -match '\.part$' }).Count | Should -Be 0
    }

    It 'hands over what a step wrote before it failed, and says the step failed' {
        $risky = & $script:By 'Risky users'
        $risky.state | Should -Be 'failed'
        $risky.files | Should -Be @('11-risky-users-summary.json')
        $risky.record | Should -Contain 'errors.txt'
        $risky.record | Should -Contain 'errors.jsonl'
        (& $script:By 'Organization').state | Should -Be 'done'
    }

    It 'is called when a domain finishes, with the manifest, and always with the journal' {
        $ends = @($script:Seen | Where-Object { $_.state -eq 'collector' })
        $ends.Count | Should -BeGreaterOrEqual 2
        @($ends | Where-Object { $_.files -contains 'collection.json' }).Count | Should -BeGreaterOrEqual 2
        @($script:Seen | Where-Object { $_.record -notcontains 'journal.jsonl' }).Count | Should -Be 0
        @($script:Seen | ForEach-Object { $_.folder } | Sort-Object -Unique) | Should -Be @($script:Run)
        @($script:Seen | Where-Object { $_.step -eq 'Organization' })[0].collector | Should -Be 'Entra'
    }

    It 'never stops the collection when the block throws' {
        $f = Join-Path $script:Root 'throws'; New-Item -ItemType Directory -Path $f | Out-Null
        & $script:Collect $f { throw 'the storage account said no' } | Should -Be @('Entra', 'Intune')
        Join-Path $f '09-intune-apps.json' | Should -Exist
        (Get-Content -Raw (Join-Path $f 'collection.json') | ConvertFrom-Json).collectors | Should -Be @('Entra', 'Intune')
    }

    It 'says once that the block failed, however many steps follow' {
        InModuleScope TenantKeep.Posture -Parameters @{ Root = $script:Root } {
            param($Root)
            $f = Join-Path $Root 'warn-once'; New-Item -ItemType Directory -Path $f | Out-Null
            $script:PostureStepCompleted = { throw 'the storage account said no' }; $script:PostureStepCompletedWarned = $false
            try {
                $warnings = @(foreach ($step in 'A', 'B', 'C') { Invoke-PostureStepCompleted -Folder $f -Step $step -State done 3>&1 })
                $warnings.Count | Should -Be 1
                [string]$warnings[0] | Should -Match "The -StepCompleted block failed after 'A': the storage account said no The collection carries on"
            }
            finally { $script:PostureStepCompleted = $null; $script:PostureStepCompletedWarned = $false; $script:PostureStepFiles.Clear() }
        }
    }

    It 'leaves nothing behind for the next collection, and costs nothing without a block' {
        InModuleScope TenantKeep.Posture { $script:PostureStepCompleted | Should -BeNullOrEmpty; $script:PostureStepFiles.Count | Should -Be 0 }
        $f = Join-Path $script:Root 'plain'; New-Item -ItemType Directory -Path $f | Out-Null
        $null = & $script:Collect $f
        InModuleScope TenantKeep.Posture { $script:PostureStepFiles.Count | Should -Be 0 }
    }
}

Describe 'Invoke-PostureCollection -SkipFinished' {
    It 'does not collect again a domain the run records as finished, and collects the rest' {
        $f = Join-Path $script:Root 'continue'; New-Item -ItemType Directory -Path $f | Out-Null
        & $script:Collect $f $null -Collector Entra | Should -Be @('Entra')
        & $script:Collect $f $null -SkipFinished | Should -Be @('Intune') -Because 'Entra finished in the first collection'
        & $script:Collect $f $null -SkipFinished | Should -BeNullOrEmpty
        & $script:Collect $f $null | Should -Be @('Entra', 'Intune') -Because 'without the switch a named domain is collected'
    }

    It 'collects again a domain that was started again and did not finish' {
        $f = Join-Path $script:Root 'unfinished'; New-Item -ItemType Directory -Path $f | Out-Null
        $null = & $script:Collect $f
        # A later attempt at Intune began and the job was stopped: the journal's last word on it is "started".
        Add-Content -LiteralPath (Join-Path $f 'journal.jsonl') -Value (@{ timeUtc = [datetime]::UtcNow.ToString('o'); kind = 'collector'; state = 'started'; collector = 'Intune' } | ConvertTo-Json -Compress)
        & $script:Collect $f $null -SkipFinished | Should -Be @('Intune')
    }
}
