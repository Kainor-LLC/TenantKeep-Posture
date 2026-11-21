# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Import-PostureEvidence {
    <#
    .SYNOPSIS
        Brings evidence collected on another machine into a run: the Windows SharePoint collector's folder, the Windows
        AD collector's folder, or a SharePoint-only run made elsewhere. Checks before it copies anything.
    .DESCRIPTION
        Split collection: most of a run on one machine (a Mac, say), the SharePoint admin read on a Windows cloud PC
        (collectors/windows/Get-SpoBaseline.ps1, or Start-PostureRun -Collector SharePoint there), the AD read on a
        domain-joined Windows machine (collectors/windows/Get-ADBaseline.ps1). This puts the pieces in one run.

        What it checks:
          - bundle.json, which both Windows collectors write: the kind (sharepoint or ad), the tenant, and a SHA-256
            per file. Every listed file must be there and match; a file that was changed after collection is refused.
          - The tenant: SharePoint evidence must belong to the run's tenant (the bundle's, or the source run's).
          - The names: only the files the checks read (spo-* for SharePoint, ad-* for AD) are copied; nothing else.
          - The run: a file already in the run that differs is refused unless -Force.
        An AD folder written before bundle.json existed is accepted with a warning (names checked, no hashes).
        The source's errors.txt is added to the run's errors, and the import is recorded in logs/imports.json, which
        the report's Run Health lists. A .zip of the folder works as -Path.

        Nothing is read from or written to the tenant. Rebuild the report afterwards (New-PostureReport).
    .PARAMETER Path
        The collector's output folder, a .zip of it, or another run's folder.
    .PARAMETER Run
        The run folder (or its evidence folder) to bring the files into.
    .PARAMETER Force
        Replace files already in the run that differ from the imported ones.
    .EXAMPLE
        Import-PostureEvidence -Path /Volumes/share/spo-baseline-20261120-1015 -Run ~/tenantkeep/evidence/20261120-0957
        New-PostureReport -Evidence ~/tenantkeep/evidence/20261120-0957
    .EXAMPLE
        Import-PostureEvidence -Path ~/Downloads/ad-baseline.zip -Run ~/tenantkeep/evidence/20261120-0957
    .OUTPUTS
        What was imported: kind, source, files, and the files left alone.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)] [string] $Path,
        [Parameter(Mandatory)] [string] $Run,
        [switch] $Force
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $resolve = { param([string] $p) $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p) }
    $runPath = & $resolve $Run
    if (-not (Test-Path -LiteralPath $runPath -PathType Container)) { throw "Run folder not found: $runPath" }
    $layout = Get-PostureRunLayout -Folder $runPath
    if ($layout.layout -ne 'folders') { throw "$runPath is not a run folder (evidence, errors and logs inside)." }
    $readJson = { param([string] $File) if (Test-Path -LiteralPath $File -PathType Leaf) { Get-Content -Raw -LiteralPath $File | ConvertFrom-Json -AsHashtable -Depth 10 } else { $null } }
    $tenantOf = {
        param($l)
        $plan = & $readJson (Join-Path $l.logs 'run.json')
        if ($plan -and $plan.Contains('tenantId') -and $plan['tenantId']) { return [string]$plan['tenantId'] }
        $collection = & $readJson (Join-Path $l.evidence 'collection.json')
        if ($collection -and $collection.Contains('tenantId')) { return [string]$collection['tenantId'] }
        return ''
    }
    $runTenant = & $tenantOf $layout

    # The source: a folder, a zip of one (unpacked to a temporary folder), or another run.
    $source = & $resolve $Path
    $temp = $null
    if ((Test-Path -LiteralPath $source -PathType Leaf) -and $source -match '\.zip$') {
        $temp = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-import-$([guid]::NewGuid().ToString('n'))"
        # .NET refuses entries that would land outside the folder.
        [System.IO.Compression.ZipFile]::ExtractToDirectory($source, $temp)
        $inner = @(Get-ChildItem -LiteralPath $temp -Directory)
        $source = $(if (-not (Test-Path -LiteralPath (Join-Path $temp 'bundle.json')) -and $inner.Count -eq 1) { $inner[0].FullName } else { $temp })
    }
    try {
        if (-not (Test-Path -LiteralPath $source -PathType Container)) { throw "Not a folder or a .zip: $Path" }
        $pattern = @{ sharepoint = '^spo-(tenant-settings|restricted-search|sites-summary)\.json$|^spo-sites\.(csv|json)$'; ad = '^ad-\d{2}-[a-z0-9-]+\.(json|csv)$' }
        $bundle = & $readJson (Join-Path $source 'bundle.json')
        $hashes = @{}
        $sourceLayout = Get-PostureRunLayout -Folder $source
        if ($bundle) {
            $kind = [string]$bundle['kind']
            if (-not $pattern.ContainsKey($kind)) { throw "bundle.json names kind '$kind'; expected sharepoint or ad." }
            foreach ($f in @($bundle['files'])) { $hashes[[string]$f['name']] = ([string]$f['sha256']).ToLowerInvariant() }
            $from = $source
            $sourceTenant = $(if ($bundle.Contains('tenantId')) { [string]$bundle['tenantId'] } else { '' })
        }
        elseif ($sourceLayout.layout -eq 'folders') {
            # Another run (the SharePoint collector run elsewhere): its own record says the tenant.
            $from = $sourceLayout.evidence
            $sourceTenant = & $tenantOf $sourceLayout
            $kind = $(if (@(Get-ChildItem -LiteralPath $from -File | Where-Object { $_.Name -match $pattern.sharepoint }).Count) { 'sharepoint' } else { 'ad' })
        }
        else {
            $from = $source
            $sourceTenant = ''
            $names = @(Get-ChildItem -LiteralPath $from -File | Where-Object { $_.Name -match '\.(json|csv)$' } | ForEach-Object { $_.Name })
            if (@($names | Where-Object { $_ -match $pattern.ad }).Count -eq 0) { throw "$source has no bundle.json and no AD collector files. Point -Path at the folder Get-SpoBaseline.ps1 or Get-ADBaseline.ps1 wrote." }
            $kind = 'ad'
            Write-Warning "$source has no bundle.json (an AD collector folder from before it wrote one): names are checked, contents are not."
        }
        if ($kind -eq 'sharepoint') {
            if (-not $sourceTenant) { throw 'The SharePoint evidence does not say its tenant; it cannot be checked against the run. Collect it again with Get-SpoBaseline.ps1.' }
            if (-not $runTenant) { throw "The run at $($layout.root) does not record its tenant (logs/run.json or evidence/collection.json), so SharePoint evidence cannot be checked against it." }
            if ($sourceTenant -ne $runTenant) { throw "The SharePoint evidence is from tenant $sourceTenant; the run is tenant $runTenant. Nothing was copied." }
        }

        # Which files, checked before any copy.
        $candidates = @(Get-ChildItem -LiteralPath $from -File | Where-Object { $_.Name -match $pattern[$kind] })
        if ($bundle) {
            foreach ($name in $hashes.Keys) {
                if ($name -notmatch $pattern[$kind]) { throw "bundle.json lists $name, which is not a $kind evidence file." }
                $file = Join-Path $from $name
                if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "bundle.json lists $name, which is not in the folder." }
                $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()
                if ($actual -ne $hashes[$name]) { throw "$name does not match the SHA-256 in bundle.json: it changed after collection. Nothing was copied." }
            }
            $candidates = @($candidates | Where-Object { $hashes.ContainsKey($_.Name) })
        }
        if ($candidates.Count -eq 0) { throw "No $kind evidence files in $from." }
        $copy = [System.Collections.Generic.List[string]]::new(); $same = [System.Collections.Generic.List[string]]::new()
        foreach ($c in $candidates) {
            $target = Join-Path $layout.evidence $c.Name
            if (Test-Path -LiteralPath $target -PathType Leaf) {
                if ((Get-FileHash -Algorithm SHA256 -LiteralPath $target).Hash -eq (Get-FileHash -Algorithm SHA256 -LiteralPath $c.FullName).Hash) { $same.Add($c.Name); continue }
                if (-not $Force) { throw "$($c.Name) is already in the run and differs. Pass -Force to replace it. Nothing was copied." }
            }
            $copy.Add($c.Name)
        }

        $label = @{ sharepoint = 'SharePoint admin read'; ad = 'Active Directory' }[$kind]
        if ($PSCmdlet.ShouldProcess($layout.root, "Import $($copy.Count) $label file(s)")) {
            foreach ($name in $copy) { Copy-Item -LiteralPath (Join-Path $from $name) -Destination (Join-Path $layout.evidence $name) -Force }
            $sourceErrors = @(@((Join-Path $source 'errors.txt'), (Join-Path $sourceLayout.errors 'errors.txt')) | Select-Object -Unique | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
            if ($sourceErrors.Count) {
                New-Item -ItemType Directory -Path $layout.errors -Force | Out-Null
                Add-Content -LiteralPath (Join-Path $layout.errors 'errors.txt') -Value @(Get-Content -LiteralPath $sourceErrors[0] | Where-Object { $_ })
            }
            $record = [ordered]@{
                kind = $kind; label = $label; source = $source; importedUtc = [datetime]::UtcNow.ToString('o'); checked = $(if ($bundle) { 'sha256' } else { 'names only' })
                collector = $(if ($bundle -and $bundle.Contains('collector')) { [string]$bundle['collector'] } else { '' })
                collectedUtc = $(if ($bundle -and $bundle.Contains('collectedUtc')) { [string]$bundle['collectedUtc'] } else { '' })
                account = $(if ($bundle -and $bundle.Contains('account')) { [string]$bundle['account'] } else { '' })
                files = @($copy); unchanged = @($same)
            }
            $logPath = Join-Path $layout.logs 'imports.json'
            $log = @(& $readJson $logPath | Where-Object { $_ })
            $all = @($log) + @($record)
            [System.IO.File]::WriteAllText($logPath, (ConvertTo-Json -InputObject $all -Depth 6), [System.Text.UTF8Encoding]::new($false))
            Clear-PostureEvidenceCache
        }
        return [pscustomobject]@{ Run = $layout.root; Kind = $kind; Source = $source; Files = @($copy); Unchanged = @($same); Checked = $(if ($bundle) { 'sha256' } else { 'names only' }) }
    }
    finally { if ($temp -and (Test-Path -LiteralPath $temp)) { Remove-Item -LiteralPath $temp -Recurse -Force } }
}
