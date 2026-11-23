#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
  Build script for TenantKeep.Posture.
.DESCRIPTION
  Tasks: Analyze, Test, Build, Sign, Verify, Integrity, Package, Catalog (the public catalog page for the website), Publish (the
  PowerShell Gallery), LicensingData (licensing/bundles.json from licensing/bundle-list.json and Microsoft's service plan CSV), AttackData
  (checks/attack.json, the MITRE ATT&CK techniques the checks name, checked against MITRE's release), ScubaData
  (checks/references/cisa-scuba.json, every policy of CISA's SCuBA baselines from a ScubaGear release), SecureScoreData
  (checks/references/secure-score.json, Microsoft's Secure Score actions by id from a run's control list), MaesterData
  (checks/references/maester.json, the ids and titles of Maester's tests from a Maester release), Upkeep (a
  report of what has gone stale: Microsoft's licensing list, ATT&CK, module versions, Graph APIs a check waits on, Learn links; run weekly on
  GitHub by .github/workflows/upkeep.yml, never by the module), Demo (the sample report and the website's screenshots from
  Fernquill Engineering, the made-up tenant samples/demo/New-PostureDemoRun.ps1 writes). Package and Publish need Sign or Verify in the same run, or -Unsigned said explicitly; the integrity
  manifest is required either way. Sign needs a local
  code-signing certificate and is the emergency path; releases are signed by the release workflow through Azure Artifact Signing,
  after which Verify checks that every staged file carries a valid Authenticode signature. Integrity needs the licence signing key (PEM
  or Key Vault) and writes the signed integrity.json the module checks at import (docs/licensing.md, Hardening). Package refuses to run
  without integrity.json and without Sign or Verify in the same run. Sign and Verify are Windows-only; the rest runs everywhere.
.EXAMPLE
  ./build.ps1 -Task Analyze, Test
.EXAMPLE
  ./build.ps1 -Task LicensingData -LicensingCsv './Product names and service plan identifiers for licensing.csv'
  # the CSV from learn.microsoft.com/entra/identity/users/licensing-service-plan-reference; review the diff before committing
.EXAMPLE
  ./build.ps1 -Task AttackData -AttackStix ./enterprise-attack-20.1.json
  # MITRE's STIX bundle for the version checks/catalog.json pins, from github.com/mitre-attack/attack-stix-data
.EXAMPLE
  ./build.ps1 -Task Demo
  # out/demo/fernquill (run folder and report) and out/demo/screens/*.png; screenshots need Edge or Chrome
.EXAMPLE
  ./build.ps1 -Task Package -CertificatePath ./signing.pfx
  # password from TENANTKEEP_SIGNING_PASSWORD
.EXAMPLE
  ./build.ps1 -Task Package -CertificateThumbprint ABC123...
  # Windows cert store, or TENANTKEEP_SIGNING_THUMBPRINT
.NOTES
  checks/ and baselines/ are staged into the module at Build time once they exist (CLAUDE.md layout keeps them at the root). (verify) PowerShell Gallery layout for sibling data folders.
#>
[CmdletBinding()]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Build script output is for the console, not the pipeline.')]
param(
    [ValidateSet('Analyze', 'Test', 'Build', 'Sign', 'Verify', 'Integrity', 'Package', 'Clean', 'Catalog', 'Publish', 'LicensingData', 'AttackData', 'ScubaData', 'SecureScoreData', 'MaesterData', 'Upkeep', 'Demo')]
    [string[]] $Task = @('Analyze', 'Test'),

    [string] $CertificateThumbprint = $env:TENANTKEEP_SIGNING_THUMBPRINT,
    [string] $CertificatePath       = $env:TENANTKEEP_SIGNING_PFX,
    [string] $TimestampServer       = 'http://timestamp.digicert.com',

    [switch] $SkipInstall,

    # Catalog task only: where catalog.md and catalog.html land. Default: out/.
    [string] $CatalogPath,

    # LicensingData task: Microsoft's "Product names and service plan identifiers for licensing" CSV, downloaded by hand.
    [string] $LicensingCsv,

    # AttackData task: MITRE's enterprise ATT&CK STIX bundle (enterprise-attack-<version>.json), downloaded by hand.
    [string] $AttackStix,

    # ScubaData task: the folder PowerShell/ScubaGear/baselines from a ScubaGear release, downloaded by hand.
    [string] $ScubaBaselines,

    # SecureScoreData task: a run's def-06-secure-score-controls.json. Only each action's id and title are read.
    [string] $SecureScoreControls,

    # MaesterData task: the tests folder of a Maester release (github.com/maester365/maester), downloaded by hand.
    [string] $MaesterTests,

    # Upkeep task: where the report goes (default out/upkeep.md), and -Offline to skip every check that needs the network.
    [string] $UpkeepReport,
    [switch] $Offline,

    # Publish task: the PowerShell Gallery API key (TENANTKEEP_GALLERY_KEY).
    [string] $GalleryApiKey = $env:TENANTKEEP_GALLERY_KEY,

    # Package and Publish without Authenticode signatures, said out loud. The integrity manifest is still required, so the build
    # reads as a release in every report; only the OS-level signature is missing. Used until the signing account is validated.
    [switch] $Unsigned,

    # Integrity task: the licence signing key that signs integrity.json. A PEM path (TENANTKEEP_LICENCE_KEY) or a Key Vault key.
    [string] $LicenseKeyPath = $env:TENANTKEEP_LICENCE_KEY,
    [string] $LicenseKeyId   = 'kainor-2026-10',
    [string] $VaultName,
    [string] $KeyName
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root       = $PSScriptRoot
$ModuleName = 'TenantKeep.Posture'
$SrcPath    = Join-Path $Root $ModuleName
$OutRoot    = Join-Path $Root 'out'
$Manifest   = Join-Path $SrcPath "$ModuleName.psd1"

function Write-Task([string] $Name) { Write-Host "`n==> $Name" -ForegroundColor Cyan }

function Install-BuildDependency {
    param([string] $Name, [string] $MinimumVersion)
    $have = Get-Module -ListAvailable -Name $Name | Where-Object { $_.Version -ge [version]$MinimumVersion } | Select-Object -First 1
    if ($have) { return }
    if ($SkipInstall) { throw "$Name >= $MinimumVersion is required. Install it or drop -SkipInstall." }
    Write-Host "Installing $Name >= $MinimumVersion"
    if (Get-Command Install-PSResource -ErrorAction SilentlyContinue) {
        Install-PSResource -Name $Name -Version "[$MinimumVersion,)" -Scope CurrentUser -TrustRepository -Quiet
    }
    else {
        Install-Module -Name $Name -MinimumVersion $MinimumVersion -Scope CurrentUser -Force
    }
}

function Get-ModuleVersion {
    (Import-PowerShellDataFile -Path $Manifest).ModuleVersion
}

function Get-SigningCertificate {
    <#
      Resolves the code-signing certificate or throws. This is the gate: no cert, no Sign, no Package.
    #>
    $cert = $null

    if ($CertificatePath) {
        if (-not (Test-Path -LiteralPath $CertificatePath)) { throw "Signing certificate not found at '$CertificatePath'." }
        $password = $env:TENANTKEEP_SIGNING_PASSWORD
        if (-not $password) { throw 'TENANTKEEP_SIGNING_PASSWORD is not set; it must hold the PFX password.' }
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            (Resolve-Path -LiteralPath $CertificatePath).Path, $password,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
    }
    elseif ($CertificateThumbprint) {
        if (-not $IsWindows) { throw 'Certificate store lookup by thumbprint is Windows-only. Use -CertificatePath on this platform.' }
        $cert = Get-ChildItem -Path 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
            Where-Object Thumbprint -eq $CertificateThumbprint | Select-Object -First 1
        if (-not $cert) { throw "No certificate with thumbprint '$CertificateThumbprint' in CurrentUser\My or LocalMachine\My." }
    }
    else {
        throw 'No signing certificate. Pass -CertificatePath (PFX) or -CertificateThumbprint, or set TENANTKEEP_SIGNING_PFX / TENANTKEEP_SIGNING_THUMBPRINT. Releases must be Authenticode-signed (spec section 6).'
    }

    if (-not $cert.HasPrivateKey) { throw "Certificate '$($cert.Subject)' has no private key." }
    $codeSigningOid = '1.3.6.1.5.5.7.3.3'
    $eku = $cert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] }
    $hasCodeSigning = $eku -and ($eku.EnhancedKeyUsages | Where-Object Value -eq $codeSigningOid)
    if (-not $hasCodeSigning) { throw "Certificate '$($cert.Subject)' is not a code-signing certificate (missing EKU $codeSigningOid)." }
    if ($cert.NotAfter -lt (Get-Date)) { throw "Certificate '$($cert.Subject)' expired on $($cert.NotAfter.ToString('u'))." }

    Write-Host "Signing with: $($cert.Subject) (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))"
    return $cert
}

function Invoke-Publish {
    <#
      Publishes the staged module to the PowerShell Gallery. The stage must carry integrity.json (a release build), and the run
      must have signed it (Sign), verified it (Verify) or said -Unsigned. A version already on the Gallery is left alone, so a
      rerun is safe. The API key comes from -GalleryApiKey or TENANTKEEP_GALLERY_KEY and is never written anywhere.
    #>
    param([string] $Stage)
    Write-Task 'Publish'
    if (-not $Stage) { $Stage = Join-Path $OutRoot $ModuleName (Get-ModuleVersion) }
    $manifestPath = Join-Path $Stage "$ModuleName.psd1"
    if (-not (Test-Path -LiteralPath $manifestPath)) { throw "No staged module at $Stage; run Build first." }
    if (-not $GalleryApiKey) { throw 'Publish needs the PowerShell Gallery API key: -GalleryApiKey or TENANTKEEP_GALLERY_KEY.' }
    $data = Import-PowerShellDataFile -Path $manifestPath
    $pre = [string]$data.PrivateData.PSData.Prerelease
    $full = "$($data.ModuleVersion)$(if ($pre) { "-$pre" })"
    if (-not (Test-Path -LiteralPath (Join-Path $Stage 'integrity.json'))) { throw 'The stage has no integrity.json; run Integrity before Publish so the build reads as a release.' }
    if (-not $script:Verified -and $tasks -notcontains 'Sign' -and -not $Unsigned) { throw 'Publish needs Sign or Verify in the same run, or -Unsigned to publish without Authenticode signatures on purpose.' }
    # The newest PSResourceGet installed, loaded explicitly: the one built into the Windows runner image answered the Gallery
    # push with 404 on 2026-10-27 where 1.2.0 on the Mac had published fine the day before.
    $prg = Get-Module -ListAvailable -Name Microsoft.PowerShell.PSResourceGet | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $prg) { throw 'Publish needs Microsoft.PowerShell.PSResourceGet; install it first.' }
    if ($prg.Version -lt [version]'1.1.0') { throw "Microsoft.PowerShell.PSResourceGet $($prg.Version) is too old to publish reliably; install 1.1.0 or later." }
    Import-Module -Name $prg.Path -Force
    Write-Host "Publishing with Microsoft.PowerShell.PSResourceGet $($prg.Version)"
    $existing = Find-PSResource -Name $ModuleName -Version $full -Prerelease -Repository PSGallery -ErrorAction SilentlyContinue
    if ($existing) { Write-Host "$ModuleName $full is already on the PowerShell Gallery; nothing to publish."; return }
    if ($Unsigned -and -not $script:Verified -and $tasks -notcontains 'Sign') { Write-Warning "Publishing $full without Authenticode signatures (-Unsigned)." }
    # The Gallery answers intermittent 404s from CI runners (2026-10-27, on a search and on a push, minutes apart). Retry a few
    # times, checking first whether an earlier attempt landed, so a retry never tries to push the same version twice.
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        try { Publish-PSResource -Path $Stage -Repository PSGallery -ApiKey $GalleryApiKey -ErrorAction Stop; break }
        catch {
            Start-Sleep -Seconds (20 * $attempt)
            if (Find-PSResource -Name $ModuleName -Version $full -Prerelease -Repository PSGallery -ErrorAction SilentlyContinue) { Write-Host "Attempt $attempt reported an error but $full is on the Gallery."; break }
            if ($attempt -eq 4) { throw }
            Write-Warning "Gallery push failed (attempt $attempt, retrying): $($_.Exception.Message)"
        }
    }
    Write-Host "Published $ModuleName $full to the PowerShell Gallery"
}

function Invoke-LicensingData {
    # bundles.json: for each SKU the advisor compares, its name and the features its service plans grant. Built from
    # Microsoft's CSV so no plan list is typed by hand; a SKU the CSV lacks keeps the plans written in bundle-list.json.
    Write-Task 'LicensingData'
    if (-not $LicensingCsv -or -not (Test-Path -LiteralPath $LicensingCsv)) { throw '-LicensingCsv: the service plan CSV from learn.microsoft.com/entra/identity/users/licensing-service-plan-reference' }
    $dir = Join-Path $Root 'licensing'
    $features = @((Get-Content -Raw (Join-Path $dir 'features.json') | ConvertFrom-Json -AsHashtable).features)
    $list = Get-Content -Raw (Join-Path $dir 'bundle-list.json') | ConvertFrom-Json -AsHashtable
    $rows = @(Import-Csv -LiteralPath $LicensingCsv)
    $plansOf = @{}; $nameOf = @{}
    foreach ($r in $rows) {
        if (-not $plansOf.ContainsKey($r.String_Id)) { $plansOf[$r.String_Id] = [System.Collections.Generic.HashSet[string]]::new(); $nameOf[$r.String_Id] = $r.Product_Display_Name }
        $null = $plansOf[$r.String_Id].Add($r.Service_Plan_Name.Trim())
    }
    $out = foreach ($s in $list.skus) {
        $id = [string]$s.sku
        $plans = $(if ($plansOf.ContainsKey($id)) { @($plansOf[$id]) } elseif ($s.Contains('plans')) { @($s.plans) } elseif ($s.Contains('features')) { @() } else { throw "bundle-list.json: $id is not in the CSV and names no plans or features" })
        $have = [System.Collections.Generic.HashSet[string]]::new()
        # A SKU Microsoft's list does not have yet can name its features directly (marked verify).
        if (-not $plansOf.ContainsKey($id) -and $s.Contains('features')) { foreach ($x in @($s.features)) { $null = $have.Add([string]$x) } }
        foreach ($f in $features) { if (@($f.plans | Where-Object { $_ -in $plans }).Count) { $null = $have.Add($f.id) } }
        # Included and implied features (Plan 2 includes Plan 1; Copilot implies SharePoint Advanced Management).
        do {
            $before = $have.Count
            foreach ($f in $features) {
                if ($have.Contains($f.id) -and $f.Contains('includes')) { foreach ($i in @($f.includes)) { $null = $have.Add($i) } }
                if ($f.Contains('impliedBy') -and @($f.impliedBy | Where-Object { $have.Contains($_) }).Count) { $null = $have.Add($f.id) }
            }
        } while ($have.Count -gt $before)
        $b = [ordered]@{ sku = $id; name = $(if ($s.Contains('name')) { $s.name } else { $nameOf[$id] }); kind = $s.kind; features = @($features | Where-Object { $have.Contains($_.id) } | ForEach-Object { $_.id }) }
        foreach ($k in 'token', 'seatCap', 'verify', 'requiresBase', 'companion') { if ($s.Contains($k)) { $b[$k] = $s[$k] } }
        $b
    }
    $doc = [ordered]@{ description = 'Generated by build.ps1 -Task LicensingData from bundle-list.json and Microsoft''s service plan CSV. Do not edit by hand.'; reviewed = $list.reviewed; source = 'https://learn.microsoft.com/entra/identity/users/licensing-service-plan-reference'; bundles = @($out) }
    $path = Join-Path $dir 'bundles.json'
    [System.IO.File]::WriteAllText($path, ($doc | ConvertTo-Json -Depth 6) + "`n", [System.Text.UTF8Encoding]::new($false))
    Write-Host "Wrote $path ($(@($out).Count) SKUs)"
}

function Invoke-ScubaData {
    # checks/references/cisa-scuba.json: every policy id and statement of CISA's SCuBA baselines, read from the Markdown
    # files of the ScubaGear release the file's version names. items is written here; notCovered and the rest are kept.
    # To move releases: change version and source in the file, run this with that release's baselines folder, then run
    # the tests, which name every policy that is new, gone or renumbered until the checks and notCovered agree again.
    Write-Task 'ScubaData'
    if (-not $ScubaBaselines -or -not (Test-Path -LiteralPath $ScubaBaselines -PathType Container)) { throw '-ScubaBaselines: the folder PowerShell/ScubaGear/baselines from a release of github.com/cisagov/ScubaGear' }
    $file = Join-Path $Root 'checks' 'references' 'cisa-scuba.json'
    $doc = Get-Content -Raw -LiteralPath $file | ConvertFrom-Json -AsHashtable -Depth 10
    $found = @{}
    foreach ($md in Get-ChildItem -LiteralPath $ScubaBaselines -Filter '*.md' | Where-Object { $_.Name -ne 'removedpolicies.md' } | Sort-Object Name) {
        $lines = [System.IO.File]::ReadAllLines($md.FullName)
        for ($i = 0; $i -lt $lines.Count; $i++) {
            # A policy is a heading that is its id, followed by its statement on the next line with text.
            if ($lines[$i].Trim() -notmatch '^#{3,5}\s+(MS\.[A-Z]+\.\d+\.\d+v\d+)$') { continue }
            $id = $Matches[1]
            $text = ''
            for ($j = $i + 1; $j -lt [Math]::Min($i + 8, $lines.Count); $j++) { $t = $lines[$j].Trim(); if ($t -and -not $t.StartsWith('<')) { $text = $t; break } }
            # A mail address in a statement is written as words: the repository's commit guard lets no real mail domain in,
            # and the one policy that names a mailbox applies to US federal agencies only.
            $found[$id] = ($text -replace '`?[\w.+-]+@[\w-]+(\.[\w-]+)+`?', 'the mailbox CISA names')
        }
    }
    if ($found.Count -lt 50) { throw "Only $($found.Count) policy ids under $ScubaBaselines; that is not a ScubaGear baselines folder." }
    $items = [ordered]@{}
    foreach ($id in ($found.get_Keys() | Sort-Object { ($_ -split '\.')[1] }, { [int]($_ -split '\.')[2] }, { [int](($_ -split '\.')[3] -replace 'v\d+$') })) { $items[$id] = $found[$id] }
    $out = [ordered]@{}
    foreach ($k in 'name', 'title', 'source', 'version', 'notice', 'checkKeys') { $out[$k] = $doc[$k] }
    $out['items'] = $items
    $out['notCovered'] = $(if ($doc.Contains('notCovered') -and $doc['notCovered']) { $doc['notCovered'] } else { [ordered]@{} })
    [System.IO.File]::WriteAllText($file, ((ConvertTo-Json -InputObject $out -Depth 10) -replace "`r`n", "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
    Write-Host "  $($items.Count) policies of $($doc['title']) $($doc['version']) written to checks/references/cisa-scuba.json"
}

function Invoke-SecureScoreData {
    # checks/references/secure-score.json: Microsoft's Secure Score actions by id, with Microsoft's title, so a check
    # can only name an action that exists. Microsoft publishes no list; a tenant's own control profiles are the list,
    # and each tenant has the actions for its products. So this adds what the given run has and removes nothing, and
    # reads the id and the title only, never a score or a state.
    Write-Task 'SecureScoreData'
    if (-not $SecureScoreControls -or -not (Test-Path -LiteralPath $SecureScoreControls -PathType Leaf)) { throw '-SecureScoreControls: def-06-secure-score-controls.json from a run''s evidence folder' }
    $file = Join-Path $Root 'checks' 'references' 'secure-score.json'
    $doc = Get-Content -Raw -LiteralPath $file | ConvertFrom-Json -AsHashtable -Depth 10
    $all = @{}
    if ($doc['items'] -is [System.Collections.IDictionary]) { foreach ($k in @($doc['items'].get_Keys())) { $all[[string]$k] = [string]$doc['items'][$k] } }
    $before = $all.Count
    foreach ($control in @(Get-Content -Raw -LiteralPath $SecureScoreControls | ConvertFrom-Json)) {
        $id = [string]$control.Id
        if ($id -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{1,79}$') { continue }
        $all[$id] = (([string]$control.Title) -replace '\s+', ' ').Trim()
    }
    if ($all.Count -lt 50) { throw "Only $($all.Count) actions in $SecureScoreControls; that is not a Secure Score control list." }
    $items = [ordered]@{}
    foreach ($id in ($all.get_Keys() | Sort-Object { $_.ToLowerInvariant() }, { $_ })) { $items[$id] = $all[$id] }
    $out = [ordered]@{}
    foreach ($k in 'name', 'title', 'source') { $out[$k] = $doc[$k] }
    $out['version'] = [datetime]::UtcNow.ToString('yyyy-MM-dd')
    foreach ($k in 'notice', 'passThrough', 'checkKeys') { $out[$k] = $doc[$k] }
    $out['items'] = $items
    $out['notCovered'] = $(if ($doc.Contains('notCovered') -and $doc['notCovered']) { $doc['notCovered'] } else { [ordered]@{} })
    [System.IO.File]::WriteAllText($file, ((ConvertTo-Json -InputObject $out -Depth 10) -replace "`r`n", "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
    Write-Host "  $($items.Count) Secure Score actions in checks/references/secure-score.json ($($items.Count - $before) new)"
}

function Invoke-MaesterData {
    # checks/references/maester.json: the id and title of every Maester test in the families the file lists, read from
    # the tests folder of the Maester release the file's version names. items is written here; families, notCovered
    # and the rest are kept. A family is a folder under tests (eidsca, orca, maester, ...): add one to families once
    # its tests have been compared with the catalog, run this, then run the tests, which name each one that still has
    # neither a check nor a reason. Both of Maester's layouts are read: a test function with a MaesterTest attribute,
    # and the older It "ID: title".
    Write-Task 'MaesterData'
    if (-not $MaesterTests -or -not (Test-Path -LiteralPath $MaesterTests -PathType Container)) { throw '-MaesterTests: the tests folder of a release of github.com/maester365/maester' }
    $file = Join-Path $Root 'checks' 'references' 'maester.json'
    $doc = Get-Content -Raw -LiteralPath $file | ConvertFrom-Json -AsHashtable -Depth 10
    $families = @($doc['families'] | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $found = [ordered]@{}
    foreach ($family in $families) {
        $folder = @(Get-ChildItem -LiteralPath $MaesterTests -Directory | Where-Object { $_.Name.ToLowerInvariant() -eq $family })
        if ($folder.Count -eq 0) { throw "No folder '$family' under $MaesterTests." }
        $ofFamily = @{}
        foreach ($script in Get-ChildItem -LiteralPath $folder[0].FullName -Recurse -Filter '*.ps1' | Sort-Object FullName) {
            $text = [System.IO.File]::ReadAllText($script.FullName)
            foreach ($m in [regex]::Matches($text, '(?s)\[MaesterTest\((.*?)\)\]')) {
                $id = [regex]::Match($m.Groups[1].Value, "Id\s*=\s*'([^']+)'").Groups[1].Value
                $title = [regex]::Match($m.Groups[1].Value, "Title\s*=\s*'((?:[^']|'')*)'").Groups[1].Value.Replace("''", "'")
                if ($id -and -not $ofFamily.ContainsKey($id)) { $ofFamily[$id] = $title }
            }
            foreach ($m in [regex]::Matches($text, '(?m)^\s*It\s+(["''])((?:(?!\1).)+)\1')) {
                $named = [regex]::Match($m.Groups[2].Value, '^([A-Z][A-Za-z]*(?:[.\-][A-Za-z0-9]+)+)\s*:\s*(.+)$')
                if ($named.Success -and -not $ofFamily.ContainsKey($named.Groups[1].Value)) { $ofFamily[$named.Groups[1].Value] = $named.Groups[2].Value }
            }
        }
        if ($ofFamily.Count -eq 0) { throw "No test ids found in $($folder[0].FullName)." }
        # In the order a reader expects: letters, then the numbers in them as numbers (ORCA.99 before ORCA.100).
        $natural = { param([string] $id) [regex]::Replace($id, '\d+', { param($n) $n.Value.PadLeft(8, '0') }) }
        foreach ($id in ($ofFamily.get_Keys() | Sort-Object { & $natural $_ })) {
            # A title ends where Maester adds its own link, and the commit guard lets no stray address in.
            $found[$id] = ((($ofFamily[$id] -replace '\s*See https?://\S+\s*$', '') -replace '\s+', ' ').Trim()).TrimEnd('.')
        }
        Write-Host "  $family`: $($ofFamily.Count) tests"
    }
    $out = [ordered]@{}
    foreach ($k in 'name', 'title', 'source', 'version', 'notice', 'families', 'checkKeys') { $out[$k] = $doc[$k] }
    $out['items'] = $found
    $out['notCovered'] = $(if ($doc.Contains('notCovered') -and $doc['notCovered']) { $doc['notCovered'] } else { [ordered]@{} })
    [System.IO.File]::WriteAllText($file, ((ConvertTo-Json -InputObject $out -Depth 10) -replace "`r`n", "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
    Write-Host "  $($found.Count) tests of Maester $($doc['version']) written to checks/references/maester.json"
}

function Invoke-AttackData {
    # checks/attack.json: each MITRE ATT&CK technique a check names, with its name and tactics, from MITRE's STIX release
    # of the version checks/catalog.json pins. An id the release lacks, revoked or deprecated fails the task with the
    # check named, so a mapping cannot go stale quietly. MITRE ships in April and October: move the pin, rerun, fix.
    Write-Task 'AttackData'
    if (-not $AttackStix -or -not (Test-Path -LiteralPath $AttackStix)) { throw '-AttackStix: enterprise-attack-<version>.json from github.com/mitre-attack/attack-stix-data' }
    $dir = Join-Path $Root 'checks'
    $pin = [string](Get-Content -Raw (Join-Path $dir 'catalog.json') | ConvertFrom-Json -AsHashtable).attack.version
    $objects = @((Get-Content -Raw -LiteralPath $AttackStix | ConvertFrom-Json -AsHashtable -Depth 20).objects)
    $release = [string](@($objects | Where-Object { $_.type -eq 'x-mitre-collection' })[0].x_mitre_version)
    # What a caller reads (the Upkeep task, the tests) goes out as plain lines first, here and for the mappings below:
    # the error view joins a message's lines and wraps them to the console's width, which differs by machine.
    if ($release -ne $pin) {
        Write-Host "ATT&CK release: the bundle is $release, checks/catalog.json pins $pin"
        throw "$AttackStix is ATT&CK $release; checks/catalog.json pins $pin. Change attack.version there to move releases, then run this again."
    }
    $idOf = { param($o) [string]@($o.external_references | Where-Object { $_.source_name -eq 'mitre-attack' })[0].external_id }
    $byRef = @{}; foreach ($o in $objects) { $byRef[[string]$o.id] = $o }
    $tech = @{}
    foreach ($o in $objects | Where-Object { $_.type -eq 'attack-pattern' }) {
        $id = & $idOf $o
        # A revoked object keeps its old id; a live one with the same id wins.
        if (-not $tech.ContainsKey($id) -or $tech[$id].Contains('revoked')) { $tech[$id] = $o }
    }
    $revokedBy = @{}; foreach ($r in $objects | Where-Object { $_.type -eq 'relationship' -and $_.relationship_type -eq 'revoked-by' }) { $revokedBy[[string]$r.source_ref] = $byRef[[string]$r.target_ref] }
    $tactics = @(@($objects | Where-Object { $_.type -eq 'x-mitre-matrix' })[0].tactic_refs | ForEach-Object { $t = $byRef[[string]$_]; [ordered]@{ id = & $idOf $t; key = [string]$t.x_mitre_shortname; name = [string]$t.name } })
    $order = @($tactics | ForEach-Object { $_.key })

    $used = [ordered]@{}; $problems = [System.Collections.Generic.List[string]]::new()
    foreach ($f in Get-ChildItem -Path $dir -Filter '*.json' | Where-Object { $_.Name -notin 'attack.json', 'catalog.json', 'chains.json', 'facts.json', 'journeys.json', 'layers.json', 'outcomes.json', 'projects.json' }) {
        foreach ($c in @((Get-Content -Raw $f.FullName | ConvertFrom-Json -AsHashtable -Depth 20).checks)) {
            if (-not $c.Contains('attack')) { continue }
            foreach ($id in @($c.attack)) {
                $o = $tech[[string]$id]
                if (-not $o) { $problems.Add("$($c.id) names $id, which ATT&CK $release does not have"); continue }
                if ($o.Contains('revoked') -and $o.revoked) {
                    $next = $revokedBy[[string]$o.id]
                    $problems.Add("$($c.id) names $id, revoked in ATT&CK $release$(if ($next) { " by $(& $idOf $next) ($($next.name))" })"); continue
                }
                if ($o.Contains('x_mitre_deprecated') -and $o.x_mitre_deprecated) { $problems.Add("$($c.id) names $id, deprecated in ATT&CK $release"); continue }
                $used[[string]$id] = $o
            }
        }
    }
    if ($problems.Count) {
        foreach ($p in $problems) { Write-Host "ATT&CK mapping: $p" }
        throw "ATT&CK mappings to fix:`n  $($problems -join "`n  ")"
    }

    $out = foreach ($id in @($used.Keys | Sort-Object)) {
        $o = $used[$id]
        $name = [string]$o.name
        if ($id.Contains('.')) { $name = "$($tech[$id.Split('.')[0]].name): $name" }
        $phases = @($o.kill_chain_phases | Where-Object { $_.kill_chain_name -eq 'mitre-attack' } | ForEach-Object { [string]$_.phase_name })
        [ordered]@{ id = $id; name = $name; tactics = @($order | Where-Object { $_ -in $phases }); url = "https://attack.mitre.org/techniques/$($id.Replace('.', '/'))/" }
    }
    # MITRE's terms of use: a copy carries the copyright designation and the licence (attack.mitre.org/resources/legal-and-branding/terms-of-use).
    $year = ([datetime]@($objects | Where-Object { $_.type -eq 'x-mitre-collection' })[0].modified).Year
    $doc = [ordered]@{
        description = 'Generated by build.ps1 -Task AttackData from the checks'' attack ids and MITRE''s STIX release. Do not edit by hand.'
        version     = $release
        domain      = 'enterprise-attack'
        source      = 'https://github.com/mitre-attack/attack-stix-data'
        notice      = "$([char]0x00A9) $year The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation."
        license     = 'The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE''s copyright designation and this license in any such copy.'
        tactics     = $tactics
        techniques  = @($out)
    }
    $path = Join-Path $dir 'attack.json'
    # Line feeds whichever platform runs the task, so the committed file does not change with the machine.
    [System.IO.File]::WriteAllText($path, (($doc | ConvertTo-Json -Depth 6) -replace "`r`n", "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
    Write-Host "Wrote $path (ATT&CK $release, $(@($out).Count) techniques)"
}

function Invoke-Upkeep {
    # What has gone stale since the data was last reviewed, as a Markdown report: Microsoft's licensing list against
    # bundles.json, a newer ATT&CK release or a mapped technique MITRE withdrew, newer major or minor versions of the
    # modules the collectors were tested with, a beta Graph API a check waits on reaching v1.0, Learn links that no
    # longer answer, and data files past their review date. Runs on GitHub (.github/workflows/upkeep.yml), which files the report as an issue; the module never calls out.
    Write-Task 'Upkeep'
    $target = $(if ($UpkeepReport) { $UpkeepReport } else { Join-Path $OutRoot 'upkeep.md' })
    New-Item -ItemType Directory -Path (Split-Path $target -Parent) -Force | Out-Null
    $findings = [System.Collections.Generic.List[string]]::new()
    $notes = [System.Collections.Generic.List[string]]::new()
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-upkeep-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $temp -Force | Out-Null
    try {
        # Review dates in the licensing data (180 days, like the test that skips past them).
        foreach ($f in Get-ChildItem (Join-Path $Root 'licensing') -Filter '*.json') {
            $j = Get-Content -Raw $f.FullName | ConvertFrom-Json
            if ($j.PSObject.Properties['reviewed'] -and ([datetime]::UtcNow - [datetime]$j.reviewed).TotalDays -gt 180) { $findings.Add("licensing/$($f.Name) was last reviewed on $($j.reviewed): check it against Microsoft's service plan list and bump 'reviewed'.") }
        }
        if ($Offline) { $notes.Add('Offline: the licensing list, ATT&CK, module versions, Graph APIs and Learn links were not checked.') }
        else {
            # Microsoft's licensing list: rebuild bundles.json from it into a copy and compare (verify the download URL stays put).
            try {
                $csv = Join-Path $temp 'plans.csv'
                Invoke-WebRequest -Uri 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv' -OutFile $csv -UseBasicParsing
                $copy = Join-Path $temp 'repo'
                New-Item -ItemType Directory -Path $copy -Force | Out-Null
                Copy-Item -Path (Join-Path $Root 'licensing') -Destination $copy -Recurse
                Copy-Item -Path (Join-Path $Root 'build.ps1') -Destination $copy
                & pwsh -NoProfile -File (Join-Path $copy 'build.ps1') -Task LicensingData -LicensingCsv $csv *> $null
                $old = Get-Content -Raw (Join-Path $Root 'licensing' 'bundles.json') | ConvertFrom-Json
                $new = Get-Content -Raw (Join-Path $copy 'licensing' 'bundles.json') | ConvertFrom-Json
                foreach ($b in $new.bundles) {
                    $was = @($old.bundles | Where-Object sku -eq $b.sku)
                    if ($was.Count -eq 0) { continue }
                    $added = @($b.features | Where-Object { $_ -notin @($was[0].features) }); $gone = @($was[0].features | Where-Object { $_ -notin @($b.features) })
                    if ($added.Count -or $gone.Count) { $findings.Add("Microsoft's licensing list changes $($b.sku): $(if ($added.Count) { "adds $($added -join ', ')" })$(if ($added.Count -and $gone.Count) { '; ' })$(if ($gone.Count) { "drops $($gone -join ', ')" }). Run build.ps1 -Task LicensingData with the new CSV.") }
                }
            }
            catch { $notes.Add("Licensing list not checked: $($_.Exception.Message)") }

            # ATT&CK: a newer release than the pin, and any mapped id it revoked or deprecated.
            try {
                $index = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json'
                $latest = @(@($index.collections | Where-Object { $_.name -match 'Enterprise' })[0].versions | Sort-Object { [version]$_.version } -Descending)[0]
                $pin = (Get-Content -Raw (Join-Path $Root 'checks' 'catalog.json') | ConvertFrom-Json).attack.version
                if ([version]$latest.version -gt [version]$pin) {
                    $stix = Join-Path $temp 'enterprise-attack.json'
                    Invoke-WebRequest -Uri $latest.url -OutFile $stix -UseBasicParsing
                    $copy = Join-Path $temp 'attack'
                    New-Item -ItemType Directory -Path $copy -Force | Out-Null
                    Copy-Item -Path (Join-Path $Root 'checks') -Destination $copy -Recurse
                    Copy-Item -Path (Join-Path $Root 'build.ps1') -Destination $copy
                    $cat = Join-Path $copy 'checks' 'catalog.json'
                    (Get-Content -Raw $cat) -replace ('"version": "' + [regex]::Escape($pin) + '"'), ('"version": "' + $latest.version + '"') | Set-Content $cat
                    $out = & pwsh -NoProfile -File (Join-Path $copy 'build.ps1') -Task AttackData -AttackStix $stix 2>&1 | Out-String
                    # The task's own lines, one problem each; the error text under them is wrapped and would be cut.
                    $problems = @([regex]::Matches($out, '(?m)^ATT&CK mapping: ([^\r\n]+)') | ForEach-Object { $_.Groups[1].Value.Trim() })
                    $findings.Add("ATT&CK $($latest.version) is out; the catalog pins $pin. $(if ($problems.Count) { 'Mappings to fix first: ' + ($problems -join '; ') + '.' } else { 'Every mapped technique is still current: move the pin and run build.ps1 -Task AttackData.' })")
                }
            }
            catch { $notes.Add("ATT&CK not checked: $($_.Exception.Message)") }

            # Modules: a newer major or minor version than the one the collectors were tested with.
            $tested = @{}
            foreach ($m in [regex]::Matches((Get-Content -Raw (Join-Path $SrcPath 'Private' 'Get-PostureModuleRequirement.ps1')), "name = '([^']+)'; tested = '([^']+)'")) { $tested[$m.Groups[1].Value] = [version]$m.Groups[2].Value }
            foreach ($name in $tested.Keys | Sort-Object) {
                try {
                    $g = Find-Module -Name $name -Repository PSGallery -ErrorAction Stop
                    $v = [version]$g.Version
                    if ($v.Major -gt $tested[$name].Major -or ($v.Major -eq $tested[$name].Major -and $v.Minor -gt $tested[$name].Minor)) { $findings.Add("$name $v is out; the collectors were tested with $($tested[$name]). Test a collection with it and bump 'tested' in Get-PostureModuleRequirement.") }
                }
                catch { $notes.Add("$name not checked: $($_.Exception.Message)") }
            }

            # Graph APIs a check waits on: in beta only today, so the check asks for an attestation instead. When the type
            # appears in Graph's published v1.0 schema (no sign-in needed), the check can read it.
            $waiting = @(
                @{ Type = 'copilotPolicySetting'; Check = 'CP-015'; What = 'the Copilot policy settings (web search, image generation and the rest)'; Then = 'read the settings it covers in the collector (delegated CopilotPolicySettings.Read) and keep the attestation for agents and connectors' }
            )
            try {
                $schema = Join-Path $temp 'graph-v1.0-metadata.xml'
                Invoke-WebRequest -Uri 'https://graph.microsoft.com/v1.0/$metadata' -OutFile $schema -UseBasicParsing
                $text = [System.IO.File]::ReadAllText($schema)
                foreach ($w in $waiting) { if ($text.Contains("Name=`"$($w.Type)`"")) { $findings.Add("$($w.Check): Microsoft Graph v1.0 now has $($w.Type), $($w.What). Time to $($w.Then).") } }
            }
            catch { $notes.Add("Graph v1.0 schema not checked: $($_.Exception.Message)") }

            # Learn links in the catalog that no longer answer.
            $links = @(Get-ChildItem (Join-Path $Root 'checks') -Filter '*.json' | Where-Object { $_.Name -notin 'attack.json', 'catalog.json', 'chains.json', 'facts.json', 'journeys.json', 'layers.json', 'outcomes.json', 'projects.json' } | ForEach-Object { (Get-Content -Raw $_.FullName | ConvertFrom-Json).checks } | Where-Object { $_.learn } | Group-Object learn)
            foreach ($l in $links) {
                $code = 0
                try { $code = [int](Invoke-WebRequest -Uri $l.Name -Method Head -MaximumRedirection 5 -UseBasicParsing -ErrorAction Stop).StatusCode } catch { $code = $(if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { -1 }) }
                if ($code -eq 404 -or $code -eq 410) { $findings.Add("Learn link gone ($code) for $(@($l.Group | ForEach-Object { $_.id }) -join ', '): $($l.Name)") }
            }
        }
    }
    finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
    $md = [System.Collections.Generic.List[string]]::new()
    $md.Add("# Weekly upkeep, $([datetime]::UtcNow.ToString('yyyy-MM-dd'))"); $md.Add('')
    if ($findings.Count) { $md.Add("$($findings.Count) thing(s) to look at:"); $md.Add(''); foreach ($f in $findings) { $md.Add("- [ ] $f") } }
    else { $md.Add('Nothing has gone stale.') }
    if ($notes.Count) { $md.Add(''); $md.Add('Not checked this time:'); $md.Add(''); foreach ($n in $notes) { $md.Add("- $n") } }
    $md.Add(''); $md.Add('Written by build.ps1 -Task Upkeep. The module itself never calls out; this runs on GitHub only.')
    [System.IO.File]::WriteAllText($target, ($md -join "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
    Write-Host "Upkeep: $($findings.Count) finding(s) -> $target"
}

function Invoke-Demo {
    # The sample report and the website's screenshots, from the made-up tenant in samples/demo. Never a real tenant:
    # public screenshots come from here only. The demo carries no licence file, so the full tier is set for the render
    # alone, the way the tests do, and the header says the data is made up.
    Write-Task 'Demo'
    $demo = Join-Path $OutRoot 'demo'
    if (Test-Path -LiteralPath $demo) { Remove-Item -LiteralPath $demo -Recurse -Force }
    $run = Join-Path $demo 'fernquill'
    $made = & (Join-Path $Root 'samples' 'demo' 'New-PostureDemoRun.ps1') -Path $run
    Import-Module $Manifest -Force
    & (Get-Module $ModuleName) {
        $script:PostureEntitlementOverride = @{ licensed = $true; tier = 'full'; customer = 'Fernquill Engineering (demo)'; licenceId = 'demo'; expiresUtc = '2027-12-31T00:00:00Z'; source = 'demo tenant, made-up data' }
        $script:PostureBuildState = @{ state = 'demo'; detail = 'Sample report: Fernquill Engineering is a made-up tenant and every value in it is invented.'; version = $script:ModuleVersion; changed = @() }
    }
    try { $null = New-PostureReport -Evidence $run -Client $made.Client }
    finally { Remove-Module $ModuleName -Force -ErrorAction SilentlyContinue }
    $report = Join-Path $run 'report.html'
    # The report names the folders it was built from. A published sample shows where they sit on a customer's machine
    # instead, and nothing from this one: the build stops if a path from this machine is left.
    $shown = [ordered]@{ $made.Client = '~/tenantkeep/clients/fernquill'; $run = '~/tenantkeep/evidence/2026-11-16-0900' }
    foreach ($f in Get-ChildItem -LiteralPath $run -File | Where-Object { $_.Extension -in '.html', '.md', '.json', '.csv' }) {
        $text = [System.IO.File]::ReadAllText($f.FullName)
        foreach ($k in $shown.Keys) { $text = $text.Replace($k, $shown[$k]).Replace($k.Replace($HOME, '~'), $shown[$k]) }
        [System.IO.File]::WriteAllText($f.FullName, $text, [System.Text.UTF8Encoding]::new($false))
        foreach ($leak in @($HOME, $Root, [System.IO.Path]::GetTempPath().TrimEnd('/', '\')) | Where-Object { $_ }) {
            if ($text.Contains($leak)) { throw "$($f.Name) still holds a path from this machine ($leak); the sample cannot be published." }
        }
    }
    Write-Host "Demo report: $report ($($made.Files) evidence files, $($made.Users) users, $($made.Devices) devices)"

    # Screenshots: headless Edge or Chrome, light theme, one per view.
    $browser = @($env:TENANTKEEP_BROWSER, '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe', 'C:\Program Files\Google\Chrome\Application\chrome.exe', '/usr/bin/microsoft-edge', '/usr/bin/google-chrome', '/usr/bin/chromium') |
        Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
    if (-not $browser) { Write-Warning 'No Edge or Chrome found (set TENANTKEEP_BROWSER): the report is written, the screenshots are not.'; return }
    $screens = Join-Path $demo 'screens'
    New-Item -ItemType Directory -Path $screens -Force | Out-Null
    # A file URL by hand: [uri] reads a bare Unix path as relative. Each segment escaped, a Windows drive kept as is.
    $url = 'file:///' + ((($report -replace '\\', '/').TrimStart('/') -split '/' | ForEach-Object { if ($_ -match '^[A-Za-z]:$') { $_ } else { [uri]::EscapeDataString($_) } }) -join '/')
    foreach ($view in 'overview', 'recommendations', 'domains', 'ca', 'attack', 'copilot') {
        $png = Join-Path $screens "$view.png"
        & $browser --headless=new --disable-gpu --hide-scrollbars --blink-settings=preferredColorScheme=1 --force-device-scale-factor=2 '--window-size=1280,860' "--screenshot=$png" "$url#$view" 2>$null | Out-Null
        if (Test-Path -LiteralPath $png) { Write-Host "  $view.png" } else { Write-Warning "No screenshot for $view." }
    }
}

function Invoke-Catalog {
    # The public catalog page for the website (CLAUDE.md, Licensing): ids, titles, the narrative and the licence required.
    # No pass logic, no remediation, no framework mappings: those are the product.
    Write-Task 'Catalog'
    $target = $(if ($CatalogPath) { $CatalogPath } else { $OutRoot })
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    $catalogDoc = Get-Content -Raw (Join-Path $Root 'checks' 'catalog.json') | ConvertFrom-Json
    $labels = @{}; foreach ($d in @($catalogDoc.domains)) { $labels[[string]$d.key] = [string]$d.label }
    $order = @($catalogDoc.domains | ForEach-Object { [string]$_.key })
    $version = (Get-Content -Raw (Join-Path $Root 'checks' 'catalog.json') | ConvertFrom-Json).version
    $files = Get-ChildItem -Path (Join-Path $Root 'checks') -Filter '*.json' | Where-Object { $_.Name -notin 'attack.json', 'catalog.json', 'chains.json', 'facts.json', 'journeys.json', 'layers.json', 'outcomes.json', 'projects.json' }
    $byDomain = @{}
    foreach ($f in $files) { $d = Get-Content -Raw $f.FullName | ConvertFrom-Json; $byDomain[[string]$d.domain] = @($d.checks) }
    $md = [System.Collections.Generic.List[string]]::new()
    $md.Add("# TenantKeep Posture check catalog $version"); $md.Add('')
    $md.Add('Every check the product evaluates, by domain. The pass logic, remediation and framework mappings are part of the product; this page lists what is checked and the licence each check needs.'); $md.Add('')
    $total = 0
    $esc = { param([string] $x) $x -replace '\|', '\|' }
    foreach ($dom in $order) {
        if (-not $byDomain.ContainsKey($dom)) { continue }
        $checks = @($byDomain[$dom]); $total += $checks.Count
        $md.Add("## $($labels[$dom]) ($($checks.Count))"); $md.Add(''); $md.Add('| ID | Check | Severity | Licence | What it means |'); $md.Add('|---|---|---|---|---|')
        foreach ($c in $checks) { $md.Add("| $($c.id) | $(& $esc $c.title) | $($c.severityDefault) | $(if (@($c.license).Count -gt 0) { @($c.license) -join ', ' } else { 'none' }) | $(& $esc $c.narrative) |") }
        $md.Add('')
    }
    $md.Add("$total checks in $($order.Where({ $byDomain.ContainsKey($_) }).Count) domains. Generated by build.ps1 -Task Catalog from checks/; never edited by hand.")
    $mdPath = Join-Path $target 'catalog.md'
    [System.IO.File]::WriteAllText($mdPath, ($md -join "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
    $h = { param([string] $x) [System.Net.WebUtility]::HtmlEncode($x) }
    $html = [System.Collections.Generic.List[string]]::new()
    $html.Add('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>TenantKeep Posture check catalog</title><style>body{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#1b1b1b}table{border-collapse:collapse;width:100%;margin-bottom:2rem}th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top;font-size:.92rem}th{background:#f3f3f3}h2{margin-top:2rem}</style></head><body>')
    $html.Add("<h1>TenantKeep Posture check catalog $(& $h $version)</h1><p>Every check the product evaluates, by domain. The pass logic, remediation and framework mappings are part of the product; this page lists what is checked and the licence each check needs.</p>")
    foreach ($dom in $order) {
        if (-not $byDomain.ContainsKey($dom)) { continue }
        $checks = @($byDomain[$dom])
        $html.Add("<h2>$(& $h $labels[$dom]) ($($checks.Count))</h2><table><thead><tr><th>ID</th><th>Check</th><th>Severity</th><th>Licence</th><th>What it means</th></tr></thead><tbody>")
        foreach ($c in $checks) { $html.Add("<tr><td>$(& $h $c.id)</td><td>$(& $h $c.title)</td><td>$(& $h $c.severityDefault)</td><td>$(& $h $(if (@($c.license).Count -gt 0) { @($c.license) -join ', ' } else { 'none' }))</td><td>$(& $h $c.narrative)</td></tr>") }
        $html.Add('</tbody></table>')
    }
    $html.Add("<p>$total checks. Generated by build.ps1 -Task Catalog from checks/; never edited by hand.</p></body></html>")
    $htmlPath = Join-Path $target 'catalog.html'
    [System.IO.File]::WriteAllText($htmlPath, ($html -join "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
    Write-Host "Catalog: $total checks -> $mdPath, $htmlPath"
}

function Invoke-Clean {
    Write-Task 'Clean'
    if (Test-Path $OutRoot) { Remove-Item -LiteralPath $OutRoot -Recurse -Force }
}

function Invoke-Analyze {
    Write-Task 'Analyze'
    Install-BuildDependency -Name PSScriptAnalyzer -MinimumVersion 1.22.0
    # Runner images ship an older PSScriptAnalyzer next to the one installed above; auto-loading between the two failed
    # twice on ubuntu-latest inside Invoke-ScriptAnalyzer with internal errors (2026-10-25). Load the newest explicitly.
    $analyzer = Get-Module -ListAvailable -Name PSScriptAnalyzer | Sort-Object Version -Descending | Select-Object -First 1
    Import-Module -Name $analyzer.Path -Force
    Write-Host "PSScriptAnalyzer $($analyzer.Version) from $($analyzer.ModuleBase)"
    $settings = Join-Path $Root 'PSScriptAnalyzerSettings.psd1'
    $paths = @($SrcPath, (Join-Path $Root 'tests'), (Join-Path $Root '.githooks'), (Join-Path $Root 'deploy'), (Join-Path $Root 'build.ps1'))

    # A file that does not parse is a hard failure; Invoke-ScriptAnalyzer does not reliably report that.
    $parseErrors = foreach ($file in (Get-ChildItem -Path $paths -Recurse -Include '*.ps1', '*.psm1', '*.psd1')) {
        $tokens = $null; $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
        foreach ($e in @($errors)) { "$($file.FullName):$($e.Extent.StartLineNumber):$($e.Extent.StartColumnNumber) $($e.Message)" }
    }
    if ($parseErrors) { $parseErrors | Write-Host; throw "$(@($parseErrors).Count) parse error(s)." }
    # An exception here is the analyzer failing, not a finding; one retry after a reload, with the warning left in the log.
    $results = try { foreach ($p in $paths) { Invoke-ScriptAnalyzer -Path $p -Recurse -Settings $settings } }
    catch {
        Write-Warning "Invoke-ScriptAnalyzer failed and is retried once: $($_.Exception.Message)"
        Import-Module -Name $analyzer.Path -Force
        foreach ($p in $paths) { Invoke-ScriptAnalyzer -Path $p -Recurse -Settings $settings }
    }
    if ($results) {
        $results | Format-Table -AutoSize RuleName, Severity, ScriptName, Line, Message | Out-String -Width 200 | Write-Host
        throw "PSScriptAnalyzer reported $(@($results).Count) finding(s)."
    }
    Write-Host 'PSScriptAnalyzer: clean'
}

function Clear-GitHookEnvironment {
    # Under a git hook, git's own variables are set, and from a linked worktree GIT_DIR is this repository's
    # absolute path: a test that makes a throwaway repository would then commit to this one. Tests run without them.
    $names = @(& git rev-parse --local-env-vars 2>$null)
    if (-not $names.Count) { $names = @('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR', 'GIT_PREFIX', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES') }
    foreach ($name in $names) { if ($name -and (Test-Path "Env:$name")) { Remove-Item "Env:$name" } }
}

function Invoke-Test {
    Write-Task 'Test'
    Clear-GitHookEnvironment
    Install-BuildDependency -Name Pester -MinimumVersion 5.5.0
    Import-Module Pester
    New-Item -ItemType Directory -Path $OutRoot -Force | Out-Null

    $config = New-PesterConfiguration
    $config.Run.Path = Join-Path $Root 'tests'
    $config.Run.Exit = $false
    $config.Run.PassThru = $true
    $config.Output.Verbosity = 'Detailed'
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputFormat = 'NUnitXml'
    $config.TestResult.OutputPath = Join-Path $OutRoot 'test-results.xml'

    $result = Invoke-Pester -Configuration $config
    if ($result.FailedCount -gt 0) { throw "$($result.FailedCount) test(s) failed." }
}

function Invoke-Build {
    Write-Task 'Build'
    $version = Get-ModuleVersion
    $stage = Join-Path $OutRoot $ModuleName $version
    if (Test-Path $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Copy-Item -Path (Join-Path $SrcPath '*') -Destination $stage -Recurse -Exclude '.gitkeep'
    foreach ($data in 'checks', 'baselines', 'templates', 'licensing') {
        $src = Join-Path $Root $data
        if (Test-Path $src) { Copy-Item -Path $src -Destination (Join-Path $stage $data) -Recurse -Exclude '.gitkeep' }
    }
    # The Windows collectors ship inside the module, so Export-PostureCollector can hand one over with its
    # instructions wherever the module is installed, and a signed release signs them with everything else.
    $windowsCollectors = Join-Path $Root 'collectors' 'windows'
    if (Test-Path $windowsCollectors) {
        New-Item -ItemType Directory -Path (Join-Path $stage 'collectors' 'windows') -Force | Out-Null
        Copy-Item -Path (Join-Path $windowsCollectors '*.ps1') -Destination (Join-Path $stage 'collectors' 'windows')
    }
    # The scheduling scripts ship inside the module so a runbook can find them next to the manifest.
    $schedules = Join-Path $Root 'deploy' 'schedules'
    if (Test-Path $schedules) {
        New-Item -ItemType Directory -Path (Join-Path $stage 'schedules') -Force | Out-Null
        Copy-Item -Path (Join-Path $schedules '*.ps1') -Destination (Join-Path $stage 'schedules')
    }

    # The export list is derived from Public/, so the manifest can never drift from the source tree.
    $publicFunctions = @(Get-ChildItem -Path (Join-Path $stage 'Public') -Filter '*.ps1' | Select-Object -ExpandProperty BaseName | Sort-Object)
    Update-ModuleManifest -Path (Join-Path $stage "$ModuleName.psd1") -FunctionsToExport $publicFunctions
    $null = Test-ModuleManifest -Path (Join-Path $stage "$ModuleName.psd1")

    Write-Host "Staged $ModuleName $version with $($publicFunctions.Count) exported function(s) at $stage"
    return $stage
}

function Invoke-Sign {
    param([string] $Stage)
    Write-Task 'Sign'
    $cert = Get-SigningCertificate
    if (-not $IsWindows) {
        throw 'Authenticode signing (Set-AuthenticodeSignature) is only available on Windows. Run Sign or Package on a Windows machine or runner.'
    }
    $files = Get-ChildItem -Path $Stage -Recurse -Include '*.ps1', '*.psm1', '*.psd1'
    foreach ($f in $files) {
        $sig = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampServer -IncludeChain All
        if ($sig.Status -ne 'Valid') { throw "Signing failed for $($f.FullName): $($sig.Status) $($sig.StatusMessage)" }
    }
    Write-Host "Signed $($files.Count) file(s)"
}

function Invoke-Verify {
    <#
      Every staged .ps1, .psm1 and .psd1 must carry a valid Authenticode signature. This is the gate for a stage signed outside this
      script (the release workflow, Azure Artifact Signing): Package accepts Verify in place of Sign.
    #>
    param([string] $Stage)
    Write-Task 'Verify'
    if (-not $Stage) { $Stage = Join-Path $OutRoot $ModuleName (Get-ModuleVersion) }
    if (-not (Test-Path -LiteralPath (Join-Path $Stage "$ModuleName.psd1"))) { throw "No staged module at $Stage; run Build first." }
    if (-not $IsWindows) { throw 'Verify checks Authenticode signatures with Get-AuthenticodeSignature, which is Windows-only.' }
    $files = @(Get-ChildItem -Path $Stage -Recurse -Include '*.ps1', '*.psm1', '*.psd1')
    $bad = foreach ($f in $files) {
        $sig = Get-AuthenticodeSignature -FilePath $f.FullName
        if ($sig.Status -ne 'Valid') { "$($f.FullName): $($sig.Status) $($sig.StatusMessage)" }
    }
    if ($bad) { $bad | Write-Host; throw "$(@($bad).Count) file(s) without a valid Authenticode signature." }
    $signer = (Get-AuthenticodeSignature -FilePath $files[0].FullName).SignerCertificate
    Write-Host "Verified $($files.Count) signed file(s). Signer: $($signer.Subject) (expires $($signer.NotAfter.ToString('yyyy-MM-dd')))"
    $script:Verified = $true
}

function Invoke-Integrity {
    param([string] $Stage)
    Write-Task 'Integrity'
    if (-not $Stage) { $Stage = Join-Path $OutRoot $ModuleName (Get-ModuleVersion) }
    if (-not (Test-Path -LiteralPath (Join-Path $Stage "$ModuleName.psd1"))) { throw "No staged module at $Stage; run Build first." }
    Import-Module (Join-Path $SrcPath "$ModuleName.psd1") -Force
    $m = Get-Module $ModuleName
    if ($VaultName -and $KeyName) {
        $vault = $VaultName; $key = $KeyName
        $signer = {
            param([byte[]] $bytes)
            $digest = [System.Security.Cryptography.SHA256]::HashData($bytes)
            $all = & az keyvault key sign --vault-name $vault --name $key --algorithm ES256 --digest ([Convert]::ToBase64String($digest)) --output json 2>&1
            if ($LASTEXITCODE -ne 0) { throw "az keyvault key sign failed: $all" }
            # az writes its warnings and notices to the error stream; only its output is the JSON.
            $raw = @($all | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })
            $b64 = ([string](($raw | ConvertFrom-Json).signature)).Replace('-', '+').Replace('_', '/'); while ($b64.Length % 4) { $b64 += '=' }   # base64url, confirmed with azure-cli 2.90
            , [Convert]::FromBase64String($b64)
        }.GetNewClosure()
        $path = & $m { param($Root, $KeyId, $Signer) New-PostureIntegrityManifest -ModuleRoot $Root -KeyId $KeyId -Signer $Signer } $Stage $LicenseKeyId $signer
    }
    else {
        if (-not $LicenseKeyPath) { throw 'Integrity needs the licence signing key: -LicenseKeyPath (or TENANTKEEP_LICENCE_KEY), or -VaultName and -KeyName.' }
        if (-not (Test-Path -LiteralPath $LicenseKeyPath -PathType Leaf)) { throw "Licence signing key not found: $LicenseKeyPath" }
        $path = & $m { param($Root, $KeyId, $Pem) New-PostureIntegrityManifest -ModuleRoot $Root -KeyId $KeyId -PrivateKeyPath $Pem } $Stage $LicenseKeyId $LicenseKeyPath
    }
    $state = & $m { param($Root) Test-PostureIntegrity -ModuleRoot $Root } $Stage
    if ($state.state -ne 'release') { throw "Integrity manifest written but the staged module does not verify as a release: $($state.detail)" }
    Write-Host "Integrity manifest: $path ($($state.detail))"
}

function Invoke-Package {
    param([string] $Stage)
    Write-Task 'Package'
    $version = Get-ModuleVersion
    if (-not (Test-Path -LiteralPath (Join-Path $OutRoot $ModuleName $version 'integrity.json'))) { throw 'No integrity.json in the staged module; run Integrity before Package.' }
    if (-not $script:Verified -and $tasks -notcontains 'Sign' -and -not $Unsigned) { throw 'Package needs Sign (local certificate) or Verify (a stage signed by the release workflow) in the same run, or -Unsigned to package without Authenticode signatures on purpose.' }
    $suffix = $(if ($script:Verified -or $tasks -contains 'Sign') { '' } else { Write-Warning 'Packaging without Authenticode signatures (-Unsigned). The integrity manifest still makes this a release build.'; '-unsigned' })
    $pre = [string](Import-PowerShellDataFile -Path $Manifest).PrivateData.PSData.Prerelease
    $zip = Join-Path $OutRoot "$ModuleName-$version$(if ($pre) { "-$pre" })$suffix.zip"
    if (Test-Path $zip) { Remove-Item -LiteralPath $zip -Force }
    Compress-Archive -Path (Join-Path $OutRoot $ModuleName) -DestinationPath $zip
    $hash = (Get-FileHash -Path $zip -Algorithm SHA256).Hash
    # Lower case and a bare newline, so shasum -c and sha256sum -c read it on every platform (a Windows runner wrote CRLF, 2026-10-27).
    [System.IO.File]::WriteAllText("$zip.sha256", "$($hash.ToLowerInvariant())  $(Split-Path $zip -Leaf)`n", [System.Text.UTF8Encoding]::new($false))
    Write-Host "Packaged $zip`nSHA256 $hash"
}

# Package implies Build and Sign. Sign implies Build. The cert check runs first so a missing cert fails fast.
$script:Verified = $false
$tasks = [System.Collections.Generic.List[string]]::new($Task)
if ($tasks -contains 'Package' -and $tasks -notcontains 'Sign' -and $tasks -notcontains 'Verify' -and -not $Unsigned) { $tasks.Add('Sign') }
if ($tasks -contains 'Sign'    -and $tasks -notcontains 'Build') { $tasks.Add('Build') }
if ($tasks -contains 'Sign') { $null = Get-SigningCertificate }

$stage = $null
foreach ($t in @('LicensingData', 'AttackData', 'ScubaData', 'SecureScoreData', 'MaesterData', 'Upkeep', 'Demo', 'Clean', 'Analyze', 'Test', 'Build', 'Sign', 'Verify', 'Integrity', 'Package', 'Catalog', 'Publish')) {
    if ($tasks -notcontains $t) { continue }
    switch ($t) {
        'Clean' { Invoke-Clean }
        'Analyze' { Invoke-Analyze }
        'Test' { Invoke-Test }
        'Build' { $stage = Invoke-Build }
        'Sign' { Invoke-Sign -Stage $stage }
        'Verify' { Invoke-Verify -Stage $stage }
        'Integrity' { Invoke-Integrity -Stage $stage }
        'Package' { Invoke-Package -Stage $stage }
        'Catalog' { Invoke-Catalog }
        'LicensingData' { Invoke-LicensingData }
        'AttackData' { Invoke-AttackData }
        'ScubaData' { Invoke-ScubaData }
        'SecureScoreData' { Invoke-SecureScoreData }
        'MaesterData' { Invoke-MaesterData }
        'Upkeep' { Invoke-Upkeep }
        'Demo' { Invoke-Demo }
        'Publish' { Invoke-Publish -Stage $stage }
    }
}
Write-Host "`nDone: $($tasks -join ', ')" -ForegroundColor Green
