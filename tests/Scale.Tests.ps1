# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# The report must cost about the same memory on a large tenant as on a small one: the big lists are read a row at a
# time and only what a check needs is kept. This test grows the made-up demo tenant to 20,000 users (devices,
# groups, sites and mailboxes in proportion), runs the real New-PostureReport on both in a fresh process each, and
# holds the difference in peak memory to a budget. A second pass runs the fact providers one by one and holds what
# each leaves in memory to a budget of its own, so a failure names the provider.
#
# The budgets are ceilings, not targets. They were set from the measurements of 2026-11-21 (peak 374 MB on the
# demo and 709 MB at 20,000 users; the experience provider keeping 70 MB) and come down as the whole-file reads go.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    . (Join-Path $PSScriptRoot 'Fixtures' 'New-PostureScaleEvidence.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-scale-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $script:Users = 20000
    # Megabytes. PeakGrowth: how much higher the report's peak may be at 20,000 users than on the demo.
    # ProviderKeeps: how much one fact provider may leave in memory after it returns.
    $script:Budget = @{ PeakGrowth = 450; ProviderKeeps = 100 }

    $script:Small = & (Join-Path $PSScriptRoot '..' 'samples' 'demo' 'New-PostureDemoRun.ps1') -Path (Join-Path $script:Root 'small')
    $script:Big = New-PostureScaleEvidence -Path (Join-Path $script:Root 'big') -Users $script:Users

    # A fresh PowerShell for each measurement, watched from here: the working set is sampled ten times a second
    # and the highest sample is the peak. (The process's own peak counter reads zero on macOS.)
    $script:Measure = {
        param([string] $Run, [string] $Name, [string] $Mode = 'Report')
        $out = Join-Path $script:Root $Name
        $start = [System.Diagnostics.ProcessStartInfo]::new([Environment]::ProcessPath)
        foreach ($a in '-NoProfile', '-File', (Join-Path $PSScriptRoot 'Fixtures' 'Measure-PostureReport.ps1'), '-Repo', (Join-Path $PSScriptRoot '..'), '-Run', $Run, '-Out', $out, '-Mode', $Mode) { $start.ArgumentList.Add([string]$a) }
        $start.UseShellExecute = $false; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
        $process = [System.Diagnostics.Process]::Start($start)
        $said = $process.StandardOutput.ReadToEndAsync(); $failed = $process.StandardError.ReadToEndAsync()
        $peak = [long]0
        while (-not $process.HasExited) {
            try { $process.Refresh(); $peak = [Math]::Max($peak, $process.WorkingSet64) } catch { Write-Verbose $_.Exception.Message }
            Start-Sleep -Milliseconds 100
        }
        $file = Join-Path $out $(if ($Mode -eq 'Providers') { 'providers.json' } else { 'measure.json' })
        if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $file)) { throw "The measured run of $Name did not finish (exit $($process.ExitCode)): $($failed.Result) $($said.Result)" }
        @{ peakMB = [int]($peak / 1MB); answer = (Get-Content -Raw -LiteralPath $file | ConvertFrom-Json -AsHashtable) }
    }
    $script:SmallReport = & $script:Measure $script:Small.Path 'report-small'
    $script:BigReport = & $script:Measure $script:Big.Path 'report-big'
    $script:Providers = (& $script:Measure $script:Big.Path 'providers-big' 'Providers').answer
}

AfterAll { Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'The report on a tenant of 20,000 users' {
    It 'grew the demo to the size it says' {
        $script:Big.Rows['06-users'] | Should -Be $script:Users
        $script:Big.Rows['05-auth-registration'] | Should -Be $script:Users
        @(Get-ChildItem -LiteralPath $script:Big.Evidence -Filter '*.part').Count | Should -Be 0
    }

    It 'judges every check it judges on the demo, and stops no provider' {
        @($script:BigReport.answer.providersStopped) | Should -BeNullOrEmpty
        $script:BigReport.answer.results | Should -Be $script:SmallReport.answer.results
        $script:BigReport.answer.judged | Should -Be $script:SmallReport.answer.judged -Because 'more rows of the same tenant change no check from an answer to none'
    }

    It 'peaks within the budget of the demo''s peak' {
        $growth = $script:BigReport.peakMB - $script:SmallReport.peakMB
        $growth | Should -BeLessOrEqual $script:Budget.PeakGrowth -Because "the report peaked at $($script:SmallReport.peakMB) MB on the demo and $($script:BigReport.peakMB) MB at $($script:Users) users; memory that grows with the tenant means a large list was loaded whole"
    }

    It 'keeps the page a size a browser opens at once' {
        $script:BigReport.answer.reportMB | Should -BeLessOrEqual 5 -Because 'the page carries totals and the first rows of a list, never the lists'
    }

    It 'leaves no large list in memory after a provider returns' {
        $over = @($script:Providers | Where-Object { [double]$_.retainedMB -gt $script:Budget.ProviderKeeps } | ForEach-Object { "$($_.domain) keeps $($_.retainedMB) MB" })
        $over | Should -BeNullOrEmpty -Because "each provider may keep $($script:Budget.ProviderKeeps) MB at most"
        @($script:Providers | Where-Object { $_.error } | ForEach-Object { "$($_.domain): $($_.error)" }) | Should -BeNullOrEmpty
    }
}
