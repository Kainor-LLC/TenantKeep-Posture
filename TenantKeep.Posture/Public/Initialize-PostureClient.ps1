# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Initialize-PostureClient {
    <#
    .SYNOPSIS
        Sets up a client folder where you want it, with the licence in place, so Start-PostureRun has everything on the first run.
    .DESCRIPTION
        One-time, local, and the only thing it touches is the folder it creates: profile.json seeded with the tenant and
        client name, imports/ and hybrid/ for the files you provide, and tenantkeep.lic copied in when you pass
        -LicensePath. The licence is verified before anything is written: an ECDSA signature against the public keys
        built into the module, the tenant it names, its expiry. Nothing is sent anywhere and nothing in the tenant
        is read or changed. Without a licence the folder still works and the Conditional Access domain runs free.
    .PARAMETER Path
        The client folder. Default: ~/tenantkeep/clients/<client name, lower case, spaces to dashes>, so either -Path
        or a client name (-ClientName, or the customer named in the licence) is needed.
    .PARAMETER LicensePath
        The licence file to verify and copy into the folder as tenantkeep.lic.
    .PARAMETER TenantId
        The tenant this folder is for. The licence must name it; Start-PostureRun -Client refuses a sign-in to any other.
        Default: the tenant the licence names.
    .PARAMETER ClientName
        How the report names the customer. Default: the customer named in the licence.
    .PARAMETER PassThru
        Return the folder, licence status and tenant as an object instead of printing them.
    .EXAMPLE
        Initialize-PostureClient -LicensePath ~/Downloads/tenantkeep.lic
    .EXAMPLE
        Initialize-PostureClient -Path /Volumes/Clients/Contoso/posture -LicensePath ./tenantkeep.lic -TenantId contoso.onmicrosoft.com
    .EXAMPLE
        Initialize-PostureClient -Path ~/tenantkeep/clients/contoso -ClientName 'Contoso Ltd'   # no licence yet: Conditional Access only
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string], [pscustomobject])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Setup summary for the admin at the console.')]
    param(
        [string] $Path,
        [string] $LicensePath,
        [ValidatePattern('^([0-9a-fA-F-]{36}|[A-Za-z0-9.-]+\.[A-Za-z]{2,})$')] [string] $TenantId,
        [string] $ClientName,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    # 1. The licence, verified before anything is written.
    $licence = $null
    if ($LicensePath) {
        $LicensePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LicensePath)
        if (-not (Test-Path -LiteralPath $LicensePath -PathType Leaf)) { throw "No licence file at $LicensePath." }
        $r = Test-PostureLicense -Path $LicensePath -TenantId $TenantId
        if (-not $r.valid) { throw "The licence at $LicensePath is not usable: $($r.reason)" }
        $licence = $r.licence
        if (-not $TenantId) { $TenantId = [string]$licence.tenantId }
        if (-not $ClientName) { $ClientName = [string]$licence.customer }
    }

    # 2. The folder.
    if (-not $Path) {
        if (-not $ClientName) { throw 'Pass -Path, or -ClientName, or a licence that names the customer, so the folder has a name.' }
        $slug = ($ClientName.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
        if (-not $slug) { throw "'$ClientName' leaves nothing usable for a folder name; pass -Path." }
        $Path = Join-Path $HOME 'tenantkeep' 'clients' $slug
    }
    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if (-not $PSCmdlet.ShouldProcess($Path, 'Create the client folder')) { return }
    New-Item -ItemType Directory -Path $Path, (Join-Path $Path 'imports'), (Join-Path $Path 'hybrid') -Force | Out-Null

    # 3. The licence copy, the profile seed. Existing files are left alone.
    $licenceTarget = Join-Path $Path 'tenantkeep.lic'
    if ($licence) {
        if ((Resolve-Path -LiteralPath $LicensePath).Path -ne $licenceTarget) { Copy-Item -LiteralPath $LicensePath -Destination $licenceTarget -Force }
    }
    $profilePath = Join-Path $Path 'profile.json'
    if (-not (Test-Path -LiteralPath $profilePath)) {
        $seed = [ordered]@{}
        if ($TenantId) { $seed['tenantId'] = $TenantId }
        if ($ClientName) { $seed['clientName'] = $ClientName }
        if ($seed.Count -gt 0) { [System.IO.File]::WriteAllText($profilePath, ($seed | ConvertTo-Json) + "`n", [System.Text.UTF8Encoding]::new($false)) }
    }
    elseif ($TenantId) {
        $existing = Get-Content -Raw -LiteralPath $profilePath | ConvertFrom-Json -AsHashtable -Depth 10
        $recorded = [string]$(if ($existing.Contains('tenantId')) { $existing['tenantId'] })
        if ($recorded -and $recorded -ne $TenantId) { throw "$profilePath already belongs to tenant $recorded, not $TenantId. Use another folder." }
    }

    # 4. What the admin has now.
    $status = Get-PostureLicense -Path $(if (Test-Path -LiteralPath $licenceTarget) { $licenceTarget } else { [System.IO.Path]::Combine($Path, 'no-licence') }) -TenantId $TenantId
    $tierLine = $(if ($status.Valid) { "$($status.Tier) tier for $($status.Customer), expires $(([datetime]$status.ExpiresUtc).ToString('yyyy-MM-dd'))" } else { 'no licence: the Conditional Access domain runs free, everything else needs the Full tier (https://tenantkeep.app/licensing/)' })
    $next = "Start-PostureRun -Client '$Path'$(if ($TenantId) { " -TenantId $TenantId" })"
    if ($PassThru) {
        return [pscustomobject]@{ Path = $Path; TenantId = $TenantId; ClientName = $ClientName; Licence = $status; Next = $next }
    }
    Write-Host "Client folder: $Path"
    Write-Host "Licence:       $tierLine"
    if ($TenantId) { Write-Host "Tenant:        $TenantId" }
    Write-Host "Next:          $next"
    return $Path
}
