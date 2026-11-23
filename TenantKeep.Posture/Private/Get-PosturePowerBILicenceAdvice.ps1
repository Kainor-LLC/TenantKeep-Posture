# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PosturePowerBILicenceAdvice {
    <#
    .SYNOPSIS
        What to do when Power BI answers UserNotLicensed, from the licences Entra shows on the account that signed in.
    .DESCRIPTION
        Power BI answers its tenant settings to no account without a Power BI or Fabric licence, whatever its role,
        and it gives the same refusal in situations that need different things done: the account has no licence that
        includes Power BI; it has one with Power BI switched off, or not ready yet; or the licence is in place and
        Power BI has not taken it up, which is what an administrator who has just assigned it would see (reported
        from a live run on 2026-11-23, where the refusal went on after the licence was assigned; verify that this
        was the case there). One read of the account's own licences tells them apart: GET me/licenseDetails, which
        the sign-in already covers.

        Only for a person signed in through the module. A managed identity has no licences to read, and Power BI
        lets it in through a tenant setting instead. Returns nothing when the licences could not be read, and the
        caller then says what it can without them.

        A Power BI service plan is one whose name starts BI_AZURE_P: BI_AZURE_P0 is the free one in Microsoft
        Fabric (Free) and BI_AZURE_P2 is Power BI Pro. The other names (P1, P3, the government ones) follow the
        same pattern (verify against Microsoft's "Product names and service plan identifiers for licensing").
        Microsoft gives no time for Power BI to take up a new licence; its pages say only that signing in to the
        portal is when an account gets one, which is why every answer here sends the account there.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $ErrorActionPreference = 'Stop'
    if (-not $script:PostureSession) { return $null }

    # The step that failed is the Power BI read. This read must not take its place in the record of the failure.
    $lastCall = [string]$script:PostureLastCall
    try { $held = @(Invoke-PostureGraphRequest -ApiVersion v1.0 -Uri 'me/licenseDetails?$select=skuPartNumber,servicePlans' | Where-Object { $_ }) }
    catch {
        Write-Verbose "The licences of the account that signed in could not be read: $($_.Exception.Message)"
        return $null
    }
    finally { $script:PostureLastCall = $lastCall }

    # The best state of any Power BI service plan on the account: ready (Success), switched off (Disabled), or
    # anything else Entra reports, which is a plan that is not ready.
    $best = $null
    foreach ($licence in $held) {
        foreach ($plan in @($licence['servicePlans'] | Where-Object { $_ })) {
            if ([string]$plan['servicePlanName'] -notmatch '^BI_AZURE_P') { continue }
            $status = [string]$plan['provisioningStatus']
            $score = $(if ($status -eq 'Success') { 3 } elseif ($status -eq 'Disabled') { 1 } else { 2 })
            if (-not $best -or $score -gt $best.score) { $best = @{ score = $score; status = $status; sku = [string]$licence['skuPartNumber'] } }
        }
    }

    $account = [string]$script:PostureSession['account']
    $who = $(if ($account) { "the account that signed in ($account)" } else { 'the account that signed in' })
    $again = 'collect again (Resume-PostureRun -Collector PowerBI)'
    if (-not $best) {
        $count = $held.Count
        $has = $(if ($count -eq 0) { 'Entra shows no licence on it' } elseif ($count -eq 1) { 'Entra shows one licence on it, without Power BI' } else { "Entra shows $count licences on it, none with Power BI" })
        return "Power BI refused $who because it has no Power BI or Fabric licence: $has. Give that account the free Microsoft Fabric licence, open app.powerbi.com with it once, and $again."
    }

    $known = @{ POWER_BI_STANDARD = 'Microsoft Fabric (Free)'; POWER_BI_PRO = 'Power BI Pro'; PBI_PREMIUM_PER_USER = 'Power BI Premium Per User' }
    $sku = $(if ($known.ContainsKey($best.sku)) { $known[$best.sku] } elseif ($best.sku) { $best.sku } else { 'a licence' })
    switch ($best.score) {
        3 { return "Power BI refused $who, although Entra shows a licence with Power BI on it ($sku). The licence is in place and Power BI has not taken it up yet. Sign in at app.powerbi.com with that account once, in a private window so no other account is used, wait a few minutes, and $again. Microsoft gives no time for this: if it is refused again, try later." }
        1 { return "Power BI refused $who. Its licence ($sku) includes Power BI, and Power BI is switched off in it. Switch Power BI on among that licence's apps, or give the account the free Microsoft Fabric licence, then open app.powerbi.com with it once and $again." }
        default { return "Power BI refused $who. Its licence ($sku) includes Power BI, and Entra says that part is not ready yet ($($best.status)). Wait a few minutes, open app.powerbi.com with the account once, and $again." }
    }
}
