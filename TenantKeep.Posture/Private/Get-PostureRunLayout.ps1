# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# A run folder made by Start-PostureRun since 2026-11-20:
#   <name>/report.html, report.md, findings.csv, findings.json, README.txt   what people open
#   <name>/evidence/   every collector file      <name>/affected/   every affected object per check
#   <name>/errors/     what failed and why        <name>/logs/       transcript, run plan, checks.json, progress
# Older runs, and the folders Invoke-PostureCollection and the Automation runbook make, keep everything in one
# folder; the layout below answers both, so every reader asks it instead of joining file names to a folder.

function Get-PostureRunLayout {
    <#
    .SYNOPSIS
        Where a run's parts live, given the run folder or its evidence folder: root, evidence, errors, logs, affected.
        A one-folder run answers its own folder for every part.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Folder)

    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Folder).TrimEnd([System.IO.Path]::DirectorySeparatorChar, '/')
    $root = $null
    if ((Split-Path $full -Leaf) -eq 'evidence' -and (Test-Path -LiteralPath (Join-Path (Split-Path $full -Parent) 'logs') -PathType Container)) { $root = Split-Path $full -Parent }
    elseif ((Test-Path -LiteralPath (Join-Path $full 'evidence') -PathType Container) -and (Test-Path -LiteralPath (Join-Path $full 'logs') -PathType Container)) { $root = $full }
    if ($root) {
        return @{ layout = 'folders'; root = $root; evidence = (Join-Path $root 'evidence'); errors = (Join-Path $root 'errors'); logs = (Join-Path $root 'logs'); affected = (Join-Path $root 'affected') }
    }
    return @{ layout = 'flat'; root = $full; evidence = $full; errors = $full; logs = $full; affected = (Join-Path $full 'affected') }
}

function New-PostureRunFolder {
    <#
    .SYNOPSIS
        Creates a run folder in the folders layout under -OutRoot, named -Name (made safe for every file system) or
        the date and time, with -2, -3 ... when the name is taken. Returns the layout.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $OutRoot,
        [string] $Name,
        [datetime] $Timestamp = (Get-Date)
    )

    $ErrorActionPreference = 'Stop'
    $root = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutRoot)
    $base = $(if ($Name) { (($Name -replace '[\\/:*?"<>|\x00-\x1f]', '-') -replace '\s+', ' ').Trim(' ', '.') } else { $Timestamp.ToString('yyyy-MM-dd-HHmm') })
    if (-not $base) { throw "-Name '$Name' has nothing left once the characters a folder name cannot hold are removed." }
    $path = Join-Path $root $base; $n = 2
    while (Test-Path -LiteralPath $path) { $path = Join-Path $root "$base-$n"; $n++ }
    if (-not $PSCmdlet.ShouldProcess($path, 'Create the run folder')) { return $null }
    foreach ($part in 'evidence', 'errors', 'logs') { New-Item -ItemType Directory -Path (Join-Path $path $part) -Force | Out-Null }
    return (Get-PostureRunLayout -Folder $path)
}

function Get-PostureRunInfo {
    <#
    .SYNOPSIS
        Every run under -Root that Start-PostureRun made or that has results: path, start time, tenant, client, and
        where its checks.json is. Newest first. Names can be anything, so runs are told apart by run.json and dated
        by it (or, for older runs, by their yyyyMMdd-HHmm name).
    #>
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param([Parameter(Mandatory)] [string] $Root)

    $ErrorActionPreference = 'Stop'
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return @() }
    $runs = foreach ($d in Get-ChildItem -LiteralPath $Root -Directory) {
        $layout = Get-PostureRunLayout -Folder $d.FullName
        $planPath = Join-Path $layout.logs 'run.json'
        $plan = $null
        if (Test-Path -LiteralPath $planPath) { try { $plan = Get-Content -Raw -LiteralPath $planPath | ConvertFrom-Json -AsHashtable -Depth 10 } catch { $plan = $null } }
        $checks = Join-Path $layout.logs 'checks.json'
        if (-not $plan -and -not ($d.Name -match '^\d{8}-\d{4}$')) { continue }
        $started = $null
        if ($plan -and $plan['startedUtc']) { $started = ConvertTo-PostureUtcDateTime $plan['startedUtc'] }
        elseif ($d.Name -match '^(\d{8})-(\d{4})$') { $started = [datetime]::ParseExact($d.Name, 'yyyyMMdd-HHmm', [cultureinfo]::InvariantCulture) }
        else { $started = $d.CreationTimeUtc }
        $tenant = $(if ($plan) { [string]$plan['tenantId'] } else { $null })
        if (-not $tenant) {
            $manifest = Join-Path $layout.evidence 'collection.json'
            if (Test-Path -LiteralPath $manifest) { try { $tenant = [string]((Get-Content -Raw -LiteralPath $manifest | ConvertFrom-Json -AsHashtable)['tenantId']) } catch { $tenant = $null } }
        }
        @{ path = $d.FullName; layout = $layout; started = $started; tenantId = $tenant; client = $(if ($plan) { [string]$plan['client'] } else { $null }); plan = $plan; checks = $(if (Test-Path -LiteralPath $checks) { $checks } else { $null }) }
    }
    return @($runs | Sort-Object { $_.started } -Descending)
}

function Write-PostureRunReadme {
    <#
    .SYNOPSIS
        README.txt at the top of a run folder: what each file and folder is, in plain words.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)] [hashtable] $Layout)

    $ErrorActionPreference = 'Stop'
    if ($Layout.layout -ne 'folders') { return }
    $path = Join-Path $Layout.root 'README.txt'
    if (-not $PSCmdlet.ShouldProcess($path, 'Write README.txt')) { return }
    $text = @'
TenantKeep Posture run

  report.html     Open this. The assessment: score, what to fix first, every check, charts.
  report.md       The same report as plain text, for documents, tickets and AI tools.
  findings.csv    What to fix, most important first, for a spreadsheet or a ticketing system.
  findings.json   The same list with every detail, in a shape tools and AI read directly.

  evidence/       Everything collected from the tenant, one file per area, as Microsoft returned it.
                  01 to 11 Entra ID and Intune, exo- Exchange Online, pv- Purview, spo- SharePoint and OneDrive,
                  teams- Teams, def- Defender, az- Azure, ad- on-premises AD, policies.json and its neighbours
                  the Conditional Access snapshot, 06-signins- the sign-in log.
  affected/       Every affected account, device, site or app per check, one CSV per check id.
  errors/         What could not be read and why. The report's Run Health page explains it in plain words.
  logs/           The console transcript, the run plan (run.json), the check results (checks.json).

Collect again only what failed:   Resume-PostureRun
Nothing here was written to the tenant. Keep this folder private: the evidence names people, devices and settings.
'@
    [System.IO.File]::WriteAllText($path, $text, [System.Text.UTF8Encoding]::new($false))
}
