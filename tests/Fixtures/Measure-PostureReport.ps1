# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Version 7.4

# Runs the real New-PostureReport (engine, model, HTML, Markdown, checks.json, affected lists) against a made-up run
# folder in this process and nothing else, so whoever started the process can watch its memory. Scale.Tests.ps1
# starts it once on the demo and once on the same tenant grown large, and holds the difference to a budget.
#
# -Mode Providers runs each fact provider in turn instead, as one evaluation does (the evidence cache is not cleared
# between them), and records what each left in memory after a full collection: a provider that loads a large list
# whole and leaves it in the cache shows up under its own name.
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Repo,
    [Parameter(Mandatory)] [string] $Run,
    [Parameter(Mandatory)] [string] $Out,
    [ValidateSet('Report', 'Providers')] [string] $Mode = 'Report'
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $Repo 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
$module = Get-Module TenantKeep.Posture
& $module { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'scale test, made-up data' } }
if (-not (Test-Path -LiteralPath $Out)) { New-Item -ItemType Directory -Path $Out | Out-Null }

if ($Mode -eq 'Providers') {
    $ev = Join-Path $Run 'evidence'
    $rows = & $module {
        param($ev, $profilePath)
        $catalog = Import-PostureCheckCatalog
        $orgProfile = Import-PostureProfile -Path $profilePath
        foreach ($domain in $catalog.domains.get_Keys()) {
            $fn = "Get-Posture$($domain.Substring(0, 1).ToUpperInvariant() + $domain.Substring(1))Fact"
            if (-not (Get-Command -Name $fn -ErrorAction SilentlyContinue)) { continue }
            $before = [System.GC]::GetTotalMemory($true)
            $clock = [System.Diagnostics.Stopwatch]::StartNew(); $failure = $null
            try { $null = & $fn -Evidence $ev -OrgProfile $orgProfile -Thresholds @{} } catch { $failure = $_.Exception.Message }
            $clock.Stop()
            [ordered]@{ domain = $domain; seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 1); retainedMB = [Math]::Round(([System.GC]::GetTotalMemory($true) - $before) / 1MB, 1); error = $failure }
        }
    } $ev (Join-Path $Run 'client' 'profile.json')
    [System.IO.File]::WriteAllText((Join-Path $Out 'providers.json'), (ConvertTo-Json -InputObject @($rows) -Depth 4))
    return
}

$clock = [System.Diagnostics.Stopwatch]::StartNew()
$r = New-PostureReport -Evidence (Join-Path $Run 'evidence') -Client (Join-Path $Run 'client') -OutputPath $Out -PassThru -WarningAction SilentlyContinue
$clock.Stop()
$stopped = @($r.Run.results | Where-Object { [string]$_.reason -match 'Fact provider for' })
$answer = [ordered]@{
    seconds   = [Math]::Round($clock.Elapsed.TotalSeconds, 1)
    managedMB = [int]([System.GC]::GetTotalMemory($false) / 1MB)
    results   = @($r.Run.results).Count
    judged    = @($r.Run.results | Where-Object { $_.status -in 'pass', 'fail' }).Count
    providersStopped = @($stopped | ForEach-Object { [string]$_.reason } | Sort-Object -Unique)
    reportMB  = [Math]::Round((Get-Item -LiteralPath (Join-Path $Out 'report.html')).Length / 1MB, 2)
}
[System.IO.File]::WriteAllText((Join-Path $Out 'measure.json'), (ConvertTo-Json -InputObject $answer -Depth 4))
