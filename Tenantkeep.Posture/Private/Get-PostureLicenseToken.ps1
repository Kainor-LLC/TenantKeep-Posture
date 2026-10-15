# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureLicenseToken {
    <#
    .SYNOPSIS
        Maps subscribed SKUs and their service plans to the license tokens the check catalog gates on.
    .DESCRIPTION
        Tokens: E3, E5, BusinessPremium, P1, P2, Intune, IntuneSuite, EntraSuite, MDO1, MDO2, MDE1, MDE2, MDEBusiness,
        Purview, Copilot, SAM. Derived from service plan names, so a bundle such as Business Premium yields P1,
        Intune, MDO1 and MDEBusiness as well, and Copilot yields SAM. (verify) plan names for Entra Suite, Intune Suite and SAM.
    .PARAMETER Sku
        Objects shaped like Graph subscribedSkus (skuPartNumber, servicePlans[].servicePlanName) or the audit
        plan's 01-subscribed-skus rows (SkuPartNumber, ServicePlans as a ';'-joined string).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()] [AllowEmptyCollection()] [object[]] $Sku = @()
    )

    $ErrorActionPreference = 'Stop'
    $byPlan = @{
        'AAD_PREMIUM'                 = 'P1'
        'AAD_PREMIUM_P2'              = 'P2'
        'INTUNE_A'                    = 'Intune'
        'ATP_ENTERPRISE'              = 'MDO1'
        'THREAT_INTELLIGENCE'         = 'MDO2'
        'WINDEFATP'                   = 'MDE2'
        'MDE_SMB'                     = 'MDEBusiness'
        'DEFENDER_ENDPOINT_P1'        = 'MDE1'
        'MICROSOFT_365_COPILOT'       = 'Copilot'
        'M365_COPILOT'                = 'Copilot'
        'MIP_S_CLP2'                  = 'Purview'
        'INFORMATION_PROTECTION_COMPLIANCE' = 'Purview'
        'INTUNE_P2'                   = 'IntuneSuite'
        'Intune_Suite'                = 'IntuneSuite'
        'AAD_ID_GOVERNANCE'           = 'EntraSuite'
        'Entra_Suite'                 = 'EntraSuite'
        'SHAREPOINT_ADVANCED_MANAGEMENT' = 'SAM'
    }
    $bySku = @{
        'SPE_E3' = 'E3'; 'SPE_E3_USGOV_DOD' = 'E3'; 'SPE_E3_USGOV_GCCHIGH' = 'E3'; 'ENTERPRISEPACK' = 'E3'
        'SPE_E5' = 'E5'; 'ENTERPRISEPREMIUM' = 'E5'; 'SPE_E5_USGOV_DOD' = 'E5'; 'SPE_E5_USGOV_GCCHIGH' = 'E5'
        'SPB' = 'BusinessPremium'
        'Microsoft_365_Copilot' = 'Copilot'
        'Microsoft_Entra_Suite' = 'EntraSuite'
        'Microsoft_Intune_Suite' = 'IntuneSuite'
    }
    $tokens = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $Sku) {
        if ($null -eq $s) { continue }
        $part = [string](Get-PostureValue $s 'skuPartNumber')
        if (-not $part) { $part = [string](Get-PostureValue $s 'SkuPartNumber') }
        if ($part -and $bySku.ContainsKey($part)) { $null = $tokens.Add($bySku[$part]) }
        $plans = Get-PostureValue $s 'servicePlans'
        if ($null -eq $plans) { $plans = Get-PostureValue $s 'ServicePlans' }
        $names = if ($plans -is [string]) { @($plans -split ';') } else { @($plans | ForEach-Object { if ($_ -is [string]) { $_ } else { Get-PostureValue $_ 'servicePlanName' } }) }
        foreach ($n in $names) { $n = [string]$n; if ($n -and $byPlan.ContainsKey($n)) { $null = $tokens.Add($byPlan[$n]) } }
    }
    # Microsoft 365 Copilot includes SharePoint Advanced Management (verify: announced for Copilot licenses in 2025; confirm the plan name appears under the Copilot SKU on a live tenant).
    if ($tokens.Contains('Copilot')) { $null = $tokens.Add('SAM') }
    return @($tokens | Sort-Object)
}
