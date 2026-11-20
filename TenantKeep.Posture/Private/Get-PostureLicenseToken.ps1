# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# The licensing data files, read once per session.
$script:PostureLicensingData = $null

function Get-PostureLicensingData {
    <#
    .SYNOPSIS
        licensing/features.json, bundles.json and goals.json, read once per session: the one place plan names, SKUs
        and goals live.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([string] $Path)

    $ErrorActionPreference = 'Stop'
    if (-not $Path) { $Path = Get-PostureDataFolder -Name 'licensing' }
    if ($script:PostureLicensingData -and $script:PostureLicensingData.path -eq $Path) { return $script:PostureLicensingData }
    $read = { param([string] $Name) Get-Content -Raw -LiteralPath (Join-Path $Path $Name) | ConvertFrom-Json -AsHashtable -Depth 10 }
    $features = & $read 'features.json'; $bundles = & $read 'bundles.json'; $goals = & $read 'goals.json'
    $byId = [ordered]@{}; foreach ($f in $features.features) { $byId[[string]$f.id] = $f }
    $script:PostureLicensingData = @{
        path = $Path; features = $byId; bundles = @($bundles.bundles); goals = @($goals.goals)
        reviewed = @{ features = [string]$features.reviewed; bundles = [string]$bundles.reviewed; goals = [string]$goals.reviewed }
    }
    return $script:PostureLicensingData
}

function Get-PostureOwnedFeature {
    <#
    .SYNOPSIS
        The licensed features a tenant holds, from its subscribed SKUs' service plans, with what each Plan 2 includes
        and what Copilot implies. Suspended and deleted SKUs do not count.
    .PARAMETER Sku
        Objects shaped like Graph subscribedSkus (skuPartNumber, servicePlans[].servicePlanName, capabilityStatus) or
        the 01-subscribed-skus evidence rows (SkuPartNumber, ServicePlans as a ';'-joined string).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter()] [AllowEmptyCollection()] [object[]] $Sku = @())

    $ErrorActionPreference = 'Stop'
    $data = Get-PostureLicensingData
    $plans = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $have = [System.Collections.Generic.HashSet[string]]::new()
    $bundleOf = @{}; foreach ($b in $data.bundles) { $bundleOf[[string]$b.sku] = $b }
    foreach ($s in $Sku) {
        if ($null -eq $s) { continue }
        $status = [string](Get-PostureValue $s 'capabilityStatus'); if (-not $status) { $status = [string](Get-PostureValue $s 'CapabilityStatus') }
        if ($status -in 'Suspended', 'Deleted', 'LockedOut') { continue }
        # A SKU the advisor knows brings its features even when its plans were not recorded.
        $part = [string](Get-PostureValue $s 'skuPartNumber'); if (-not $part) { $part = [string](Get-PostureValue $s 'SkuPartNumber') }
        if ($part -and $bundleOf.ContainsKey($part)) { foreach ($f in @($bundleOf[$part].features)) { $null = $have.Add([string]$f) } }
        $sp = Get-PostureValue $s 'servicePlans'; if ($null -eq $sp) { $sp = Get-PostureValue $s 'ServicePlans' }
        $names = $(if ($sp -is [string]) { @($sp -split ';') } else { @($sp | ForEach-Object { if ($_ -is [string]) { $_ } else { Get-PostureValue $_ 'servicePlanName' } }) })
        foreach ($n in $names) { if ($n) { $null = $plans.Add(([string]$n).Trim()) } }
    }
    foreach ($f in $data.features.Values) { if (@($f.plans | Where-Object { $plans.Contains([string]$_) }).Count) { $null = $have.Add([string]$f.id) } }
    do {
        $before = $have.Count
        foreach ($f in $data.features.Values) {
            if ($have.Contains([string]$f.id) -and $f.Contains('includes')) { foreach ($i in @($f.includes)) { $null = $have.Add([string]$i) } }
            if ($f.Contains('impliedBy') -and @($f.impliedBy | Where-Object { $have.Contains([string]$_) }).Count) { $null = $have.Add([string]$f.id) }
        }
    } while ($have.Count -gt $before)
    return @($data.features.Keys | Where-Object { $have.Contains($_) })
}

function Get-PostureLicenseToken {
    <#
    .SYNOPSIS
        Maps subscribed SKUs to the licence tokens the check catalog gates on (P1, P2, Intune, MDE2, Purview, ...).
    .DESCRIPTION
        Feature tokens come from the service plans (licensing/features.json), so a bundle such as Business Premium
        yields P1, Intune, MDO1 and MDEBusiness; bundle tokens (E3, E5, BusinessPremium, EntraSuite, IntuneSuite,
        Copilot) come from the SKU itself (licensing/bundles.json).
    .PARAMETER Sku
        As for Get-PostureOwnedFeature.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter()] [AllowEmptyCollection()] [object[]] $Sku = @())

    $ErrorActionPreference = 'Stop'
    $data = Get-PostureLicensingData
    $tokens = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in Get-PostureOwnedFeature -Sku $Sku) { if ($data.features[$id].token) { $null = $tokens.Add([string]$data.features[$id].token) } }
    $bundleToken = @{}; foreach ($b in $data.bundles) { if ($b.Contains('token')) { $bundleToken[[string]$b.sku] = [string]$b.token } }
    foreach ($s in $Sku) {
        if ($null -eq $s) { continue }
        $status = [string](Get-PostureValue $s 'capabilityStatus'); if (-not $status) { $status = [string](Get-PostureValue $s 'CapabilityStatus') }
        if ($status -in 'Suspended', 'Deleted', 'LockedOut') { continue }
        $part = [string](Get-PostureValue $s 'skuPartNumber'); if (-not $part) { $part = [string](Get-PostureValue $s 'SkuPartNumber') }
        if ($part -and $bundleToken.ContainsKey($part)) { $null = $tokens.Add($bundleToken[$part]) }
    }
    return @($tokens | Sort-Object)
}
