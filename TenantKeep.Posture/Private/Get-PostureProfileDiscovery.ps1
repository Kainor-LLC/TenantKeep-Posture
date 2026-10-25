# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureProfileDiscovery {
    <#
    .SYNOPSIS
        Reads what an evidence folder already says about the tenant, so the profile wizard asks only the questions
        evidence cannot answer: licenses, platforms, identity model, BYOD stance, external collaboration, Copilot
        status, tenant id and display name.
    .DESCRIPTION
        Every value comes with the file it was read from and a note on the rule. Rules:
          licenses: service plans and SKUs through Get-PostureLicenseToken.
          platforms: a platform is in scope with 5 or more devices, or 2% of the fleet, across Intune managed devices
            and Entra devices (verify the floor against customer feedback).
          identityModel: onPremisesSyncEnabled on the organization; a federated verified domain means ADFS or another
            federation (hybrid-adfs); otherwise hybrid-connect (verify: Cloud Sync is not distinguishable from Connect
            in the organization object).
          byod: mdm when 5 or more Intune devices are personally owned; else mam when an app protection policy is
            assigned; else none.
          externalCollaboration: locked when there are no guests and SharePoint sharing is disabled; governed when
            guests exist and expiration, a domain list or a Teams allow list is in place; else open.
          copilot: deployed when Copilot seats consumed reach half the members, pilot when any are consumed, else none.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Evidence)

    $ErrorActionPreference = 'Stop'
    if (-not (Test-Path -LiteralPath $Evidence -PathType Container)) { throw "Evidence folder not found: $Evidence" }
    $load = {
        param([string] $Name)
        $f = Join-Path $Evidence "$Name.json"
        if (-not (Test-Path -LiteralPath $f)) { return $null }
        $text = Get-Content -Raw -LiteralPath $f
        if ([string]::IsNullOrWhiteSpace($text)) { return , @() }
        $parsed = ConvertFrom-Json -InputObject $text -AsHashtable -Depth 20
        if ($null -eq $parsed) { return , @() }
        return $parsed
    }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $rows = { param($o) @($o | Where-Object { $_ }) }
    $facts = [ordered]@{}; $sources = [ordered]@{}

    # Tenant and name
    $manifest = & $load 'collection'
    if ($null -ne $manifest -and (& $v $manifest 'tenantId')) { $facts.tenantId = [string](& $v $manifest 'tenantId'); $sources.tenantId = 'collection.json' }
    $org = & $load '01-organization'
    $org1 = @(& $rows $org | Select-Object -First 1)
    if ($org1.Count -gt 0 -and (& $v $org1[0] 'displayName')) { $facts.clientName = [string](& $v $org1[0] 'displayName'); $sources.clientName = '01-organization.json' }

    # Licenses
    $skus = & $load '01-subscribed-skus'
    if ($null -ne $skus) {
        $facts.licenses = @(Get-PostureLicenseToken -Sku @(& $rows $skus))
        $sources.licenses = '01-subscribed-skus.json (service plans and SKUs)'
    }

    # Platforms
    $managed = & $load '09-intune-managed-devices'; $entra = & $load '08-entra-devices'
    if ($null -ne $managed -or $null -ne $entra) {
        $map = { param([string] $os) switch -Regex ($os) { '^(Windows|WindowsMDM)' { 'windows'; break } '^(macOS|MacMDM|Mac)' { 'macOS'; break } '^(iOS|iPadOS|IPhone|iPhone|iPad)' { 'iOS'; break } '^Android' { 'android'; break } '(?i)linux|ubuntu' { 'linux'; break } default { $null } } }
        $counts = @{}
        $all = @(@(& $rows $managed) + @(& $rows $entra))
        foreach ($d in $all) { $p = & $map ([string](& $v $d 'OperatingSystem')); if ($p) { $counts[$p] = 1 + $(if ($counts.ContainsKey($p)) { $counts[$p] } else { 0 }) } }
        $total = [Math]::Max(1, $all.Count)
        $facts.platforms = @($counts.Keys | Where-Object { $counts[$_] -ge 5 -or $counts[$_] -ge 0.02 * $total } | Sort-Object)
        $sources.platforms = "09-intune-managed-devices.json and 08-entra-devices.json: $(@($counts.Keys | Sort-Object | ForEach-Object { "$_ $($counts[$_])" }) -join ', ')"
    }

    # Identity model
    if ($org1.Count -gt 0) {
        $synced = (& $v $org1[0] 'onPremisesSyncEnabled') -eq $true
        $domains = & $load '01-domains'
        $federated = @(& $rows $domains | Where-Object { [string](& $v $_ 'AuthenticationType') -eq 'Federated' })
        $facts.identityModel = $(if (-not $synced) { 'cloud-only' } elseif ($federated.Count -gt 0) { 'hybrid-adfs' } else { 'hybrid-connect' })
        $sources.identityModel = "01-organization.json onPremisesSyncEnabled=$synced$(if ($null -ne $domains) { ", 01-domains.json federated=$($federated.Count)" } else { ' (01-domains.json not collected; federation unknown)' }) (verify: Cloud Sync reads as hybrid-connect)"
    }

    # BYOD
    $mam = & $load '09-intune-app-protection-policies'
    if ($null -ne $managed -or $null -ne $mam) {
        $personal = @(& $rows $managed | Where-Object { [string](& $v $_ 'ManagedDeviceOwnerType') -eq 'personal' }).Count
        $assigned = @(& $rows $mam | Where-Object { (& $v $_ 'IsAssigned') -eq $true }).Count
        $facts.byod = $(if ($personal -ge 5) { 'mdm' } elseif ($assigned -gt 0) { 'mam' } else { 'none' })
        $sources.byod = "09-intune-managed-devices.json personal=$personal, 09-intune-app-protection-policies.json assigned=$assigned (mam means a policy is assigned, not that every phone has it)"
    }

    # External collaboration
    $users = & $load '06-users-summary'; $spo = & $load 'spo-tenant-settings'; $fed = & $load 'teams-federation'
    if ($null -ne $users) {
        $guests = [int](& $v $users 'Guests')
        $sharing = $(if ($null -ne $spo) { [string](& $v $spo 'SharingCapability') } else { $null })
        $spoGoverned = $null -ne $spo -and ((& $v $spo 'ExternalUserExpirationRequired') -eq $true -or [string](& $v $spo 'SharingDomainRestrictionMode') -in @('AllowList', 'BlockList'))
        $fedGoverned = $null -ne $fed -and (& $v $fed 'AllowFederatedUsers') -eq $true -and [string](& $v $fed 'AllowedDomains') -notmatch 'AllowAllKnownDomains'
        $governed = $spoGoverned -or $fedGoverned
        $facts.externalCollaboration = $(if ($guests -eq 0 -and $sharing -eq 'Disabled') { 'locked' } elseif ($guests -gt 0 -and $governed) { 'governed' } elseif ($guests -eq 0 -and $null -eq $spo) { 'locked' } else { 'open' })
        $sources.externalCollaboration = "06-users-summary.json guests=$guests$(if ($sharing) { ", spo-tenant-settings.json sharing=$sharing" }), governance controls $(if ($governed) { 'present' } else { 'absent' })"
    }

    # Copilot
    if ($null -ne $skus -and $facts.Contains('licenses')) {
        $copilotSkus = @(& $rows $skus | Where-Object { [string](& $v $_ 'skuPartNumber') -match '(?i)copilot' -or [string](& $v $_ 'SkuPartNumber') -match '(?i)copilot' })
        $consumed = 0; foreach ($s in $copilotSkus) { $c = & $v $s 'consumedUnits'; if ($null -eq $c) { $c = & $v $s 'ConsumedUnits' }; $consumed += [int]$c }
        $members = $(if ($null -ne $users) { [int](& $v $users 'Members') } else { 0 })
        $facts.copilot = $(if ($copilotSkus.Count -eq 0) { 'none' } elseif ($members -gt 0 -and $consumed -ge 0.5 * $members) { 'deployed' } elseif ($consumed -gt 0) { 'pilot' } else { 'none' })
        $sources.copilot = "01-subscribed-skus.json Copilot seats consumed=$consumed, members=$members"
    }

    return @{ facts = $facts; sources = $sources; evidence = (Resolve-Path -LiteralPath $Evidence).Path }
}
