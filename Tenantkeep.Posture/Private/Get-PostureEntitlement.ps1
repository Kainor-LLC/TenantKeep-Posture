# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureEntitlement {
    <#
    .SYNOPSIS
        What this run is allowed to evaluate. The Conditional Access domain and the three CA cmdlets are free (spec 5.5);
        every other domain needs a Full licence bound to the evidence's tenant.
    .DESCRIPTION
        The licence file is looked for in this order: -LicensePath, the TENANTKEEP_LICENSE environment variable, the
        client folder's tenantkeep.lic, then ~/tenantkeep/tenantkeep.lic. The tenant id comes from the evidence
        (collection.json, else metadata.json). Evidence without a tenant id gets the free tier: the module cannot bind a
        licence to it.

        The test suite sets $script:PostureEntitlementOverride inside the module scope to run the catalog against
        fixtures without a licence. Nothing outside the module can set it; editing the module files is the only way,
        and the licence terms cover that.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [string] $LicensePath,
        [string] $ClientFolder
    )
    $ErrorActionPreference = 'Stop'
    $override = Get-Variable -Name PostureEntitlementOverride -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($override) { return @{ licensed = $true; tier = [string]$override.tier; domains = '*'; reason = "Entitlement override: $($override.source)"; source = 'override'; licence = $null } }

    $read = { param([string] $Name) $f = Join-Path $Evidence "$Name.json"; if (Test-Path -LiteralPath $f) { try { Get-Content -Raw -LiteralPath $f | ConvertFrom-Json -AsHashtable -Depth 10 } catch { $null } } }
    $meta = & $read 'collection'; if (-not $meta) { $meta = & $read 'metadata' }
    $tenantId = [string]$(if ($meta -and $meta.Contains('tenantId')) { $meta['tenantId'] })
    $collected = $(if ($meta -and $meta.Contains('timestampUtc') -and $meta['timestampUtc']) { ConvertTo-PostureUtcDateTime $meta['timestampUtc'] })
    $asOf = [datetime]::UtcNow; if ($collected -and $collected -gt $asOf) { $asOf = $collected }

    $free = { param([string] $why) @{ licensed = $false; tier = 'none'; domains = @('ca'); reason = $why; source = $null; licence = $null; tenantId = $tenantId } }
    if (-not $tenantId) { return & $free 'The evidence folder has no collection.json or metadata.json with a tenant id, so no licence can be bound to it. Collect with Invoke-PostureCollection to get the full report.' }

    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($LicensePath) { $candidates.Add($LicensePath) }
    if ($env:TENANTKEEP_LICENSE) { $candidates.Add($env:TENANTKEEP_LICENSE) }
    if ($ClientFolder) { $candidates.Add((Join-Path $ClientFolder 'tenantkeep.lic')) }
    $candidates.Add((Join-Path $HOME 'tenantkeep' 'tenantkeep.lic'))
    $path = $null
    foreach ($c in $candidates) { $p = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($c); if (Test-Path -LiteralPath $p -PathType Leaf) { $path = $p; break } }
    if (-not $path) { return & $free "No licence file found (looked for $($candidates -join ', ')). The Conditional Access domain is evaluated; the other domains need a Tenantkeep Posture licence (docs/licensing.md)." }

    $check = Test-PostureLicense -Path $path -TenantId $tenantId -AsOfUtc $asOf
    if (-not $check.valid) { return & $free "$($check.reason) The Conditional Access domain is evaluated; the other domains need a valid licence (docs/licensing.md)." }
    $domains = $(if ($check.tier -eq 'full') { '*' } else { @('ca') })
    $reason = $(if ($check.tier -eq 'full') { $null } else { 'Tenantkeep CA licence: the Conditional Access domain and the scheduled CA cycle. The other domains need the Posture (full) tier.' })
    return @{ licensed = $true; tier = $check.tier; domains = $domains; reason = $reason; source = $path; licence = $check.licence; tenantId = $tenantId }
}

function ConvertTo-PostureEntitlementRecord {
    <# .SYNOPSIS What checks.json and the report record about the licence: tier, customer, expiry, reason. Never the file contents. #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Entitlement)
    $lic = $Entitlement['licence']
    return [ordered]@{
        licensed   = [bool]$Entitlement['licensed']
        tier       = [string]$Entitlement['tier']
        customer   = $(if ($lic) { [string]$lic['customer'] } else { $null })
        expiresUtc = $(if ($lic) { [string]$lic['expiresUtc'] } else { $null })
        licenceId  = $(if ($lic) { [string]$lic['licenceId'] } else { $null })
        reason     = $(if ($Entitlement['reason']) { [string]$Entitlement['reason'] } else { $null })
    }
}

function Confirm-PostureEntitlement {
    <#
    .SYNOPSIS
        Re-verifies an entitlement where it is consumed (the report model, the findings export) rather than trusting
        the record the engine made. A licensed entitlement must still verify from its file; anything else is the free tier.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Entitlement)
    $ErrorActionPreference = 'Stop'
    if ([string]$Entitlement['source'] -eq 'override') {
        $override = Get-Variable -Name PostureEntitlementOverride -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if ($override) { return $Entitlement }
        return @{ licensed = $false; tier = 'none'; domains = @('ca'); reason = 'Entitlement override claimed but not set.'; source = $null; licence = $null }
    }
    if (-not $Entitlement['licensed']) { return $Entitlement }
    $path = [string]$Entitlement['source']; $tenantId = [string]$(if ($Entitlement.Contains('tenantId')) { $Entitlement['tenantId'] })
    if (-not $path -or -not $tenantId) { return @{ licensed = $false; tier = 'none'; domains = @('ca'); reason = 'Licence could not be re-verified (no file or tenant id). The Conditional Access domain is evaluated.'; source = $null; licence = $null; tenantId = $tenantId } }
    $check = Test-PostureLicense -Path $path -TenantId $tenantId
    if (-not $check.valid) { return @{ licensed = $false; tier = 'none'; domains = @('ca'); reason = "$($check.reason) The Conditional Access domain is evaluated."; source = $null; licence = $null; tenantId = $tenantId } }
    $domains = $(if ($check.tier -eq 'full') { '*' } else { @('ca') })
    return @{ licensed = $true; tier = $check.tier; domains = $domains; reason = $Entitlement['reason']; source = $path; licence = $check.licence; tenantId = $tenantId }
}

function Limit-PostureResultsToEntitlement {
    <# .SYNOPSIS Applies an entitlement to a result list: checks outside the licensed domains become not evaluated with the licence reason. #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Results, [Parameter(Mandatory)] [System.Collections.IDictionary] $Entitlement)
    $domains = $Entitlement['domains']
    if ($domains -is [string] -and $domains -eq '*') { return , $Results }
    $allowed = @($domains); $reason = "Not licensed. $($Entitlement['reason'])"
    return , @($Results | ForEach-Object {
            if ([string]$_['domain'] -in $allowed -or [string]$_['status'] -in @('notApplicable', 'notEvaluated')) { $_ }
            else { $x = [ordered]@{}; foreach ($k in $_.Keys) { $x[$k] = $_[$k] }; $x['status'] = 'notEvaluated'; $x['reason'] = $reason; $x['affected'] = @(); $x['affectedCount'] = 0; $x }
        })
}
