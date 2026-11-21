# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Export-PostureDiagnostics {
    <#
    .SYNOPSIS
        Puts a run's logs in one zip to send to whoever supports the module, with the tenant's names, addresses and ids
        taken out, and none of the evidence.
    .DESCRIPTION
        When a run goes wrong somewhere you cannot hand the run folder over, this is what to send instead. The zip in
        the run's share/ folder holds:

          summary.txt      the module, PowerShell and OS versions, the run's plan, and every failure as a support
                           block: the step, its cause, the request it was making, Microsoft's message, where in the
                           module it stopped
          errors.jsonl, errors.txt, run.json, calls.json, imports.json, collection.json, transcript.txt
                           the run's own logs, each with the same names taken out

        It never includes the evidence files, the report, checks.json, findings or the redaction key. Names are taken
        out by pattern and by the names the run knows (tenant, client, account): read summary.txt before sending, as
        a name typed into free text can survive. Nothing is sent anywhere by this cmdlet.
    .PARAMETER Run
        The run folder (or its evidence folder).
    .PARAMETER OutputPath
        Where to write the zip. Default: share/diagnostics-<yyyyMMdd-HHmm>.zip in the run folder.
    .EXAMPLE
        Export-PostureDiagnostics -Run ~/tenantkeep/evidence/20261120-0957
    .OUTPUTS
        The zip's path and what it holds.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Diagnostics names the bundle as a whole, as Findings names the list.')]
    param(
        [Parameter(Mandatory, Position = 0)] [string] $Run,
        [string] $OutputPath
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Run)
    if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw "Run folder not found: $path" }
    $layout = Get-PostureRunLayout -Folder $path
    if ($layout.layout -ne 'folders') { throw "$path is not a run folder (evidence, errors and logs inside)." }
    $readJson = { param([string] $File) if (Test-Path -LiteralPath $File -PathType Leaf) { try { Get-Content -Raw -LiteralPath $File | ConvertFrom-Json -AsHashtable -Depth 10 } catch { $null } } else { $null } }

    # The names this run knows, taken out of everything: the tenant's display name, the client folder, the account.
    $plan = & $readJson (Join-Path $layout.logs 'run.json')
    $org = & $readJson (Join-Path $layout.evidence '01-organization.json')
    $names = @(
        $(if ($org) { [string](Get-PostureValue @($org)[0] 'displayName') })
        $(if ($plan -and $plan.Contains('client') -and $plan['client']) { Split-Path ([string]$plan['client']) -Leaf })
        $(if ($plan -and $plan.Contains('runAs') -and $plan['runAs']) { [string](Get-PostureValue $plan['runAs'] 'account') })
    ) | Where-Object { $_ }
    $build = $(if (Get-Variable -Name PostureBuildState -Scope Script -ValueOnly -ErrorAction SilentlyContinue) { [string]$script:PostureBuildState.detail } else { 'development copy' })
    $runName = Split-Path $layout.root -Leaf

    $failures = @($(try { Read-PostureRunFailure -Folder $layout.root } catch { @() }))
    $summary = [System.Collections.Generic.List[string]]::new()
    $summary.Add('TenantKeep Posture diagnostics')
    $summary.Add("Module: $script:ModuleVersion ($build)")
    $summary.Add("PowerShell: $($PSVersionTable.PSVersion) on $([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)")
    $summary.Add("Run: $runName  Exported: $([datetime]::UtcNow.ToString('u'))")
    if ($plan) {
        $summary.Add("Planned: $(@($plan['planned']) -join ', ')")
        $skipped = $(if ($plan.Contains('skipped') -and $plan['skipped']) { $plan['skipped'] } else { @{} })
        foreach ($k in @($skipped.Keys)) { $summary.Add("Skipped $($k): $($skipped[$k])") }
    }
    $summary.Add("Failures: $($failures.Count)$(if ($failures.Count) { ' (' + ((@($failures | Group-Object { [string]$_['cause'] } | ForEach-Object { "$($_.Count) $($_.Name)" })) -join ', ') + ')' })")
    foreach ($f in $failures) { $summary.Add(''); $summary.Add((Get-PostureSupportDetail -Failure $f -RunName $runName -Build $build -Name $names)) }
    $summary.Add('')
    $summary.Add('Names, addresses and ids are taken out by pattern. Read this file before sending it.')

    $sources = [ordered]@{
        'errors.jsonl' = Join-Path $layout.errors 'errors.jsonl'; 'errors.txt' = Join-Path $layout.errors 'errors.txt'
        'run.json' = Join-Path $layout.logs 'run.json'; 'calls.json' = Join-Path $layout.logs 'calls.json'; 'imports.json' = Join-Path $layout.logs 'imports.json'
        'collection.json' = Join-Path $layout.evidence 'collection.json'; 'transcript.txt' = Join-Path $layout.logs 'transcript.txt'
    }
    $zip = $(if ($OutputPath) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath) } else { Join-Path $layout.root 'share' "diagnostics-$((Get-Date).ToString('yyyyMMdd-HHmm')).zip" })
    if (-not $PSCmdlet.ShouldProcess($zip, 'Write the diagnostics zip')) { return }

    $temp = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-diag-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $temp -Force | Out-Null
    try {
        $utf8 = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText((Join-Path $temp 'summary.txt'), (ConvertTo-PostureSupportText -Text ($summary -join "`n") -Name $names), $utf8)
        $included = [System.Collections.Generic.List[string]]::new(); $included.Add('summary.txt')
        foreach ($n in $sources.Keys) {
            if (-not (Test-Path -LiteralPath $sources[$n] -PathType Leaf)) { continue }
            [System.IO.File]::WriteAllText((Join-Path $temp $n), (ConvertTo-PostureSupportText -Text (Get-Content -Raw -LiteralPath $sources[$n]) -Name $names), $utf8)
            $included.Add($n)
        }
        New-Item -ItemType Directory -Path (Split-Path $zip -Parent) -Force | Out-Null
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
        [System.IO.Compression.ZipFile]::CreateFromDirectory($temp, $zip)
    }
    finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
    return [pscustomobject]@{ Path = $zip; Files = @($included); Failures = $failures.Count; Note = 'Names, addresses and ids are taken out by pattern; read summary.txt before sending. No evidence or report is inside.' }
}
