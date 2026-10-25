# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureCaStrengthLevel {
    <#
    .SYNOPSIS
        Ranks what a policy demands: 3 phishing-resistant, 2 passwordless, 1 any MFA, 0 nothing.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Policy
    )

    $ErrorActionPreference = 'Stop'
    $phishingResistant = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor')
    $st = $Policy.grant.authenticationStrength
    if ($st -and @($st.allowedCombinations).Count -gt 0) {
        $combos = @($st.allowedCombinations)
        if (@($combos | Where-Object { $_ -notin $phishingResistant }).Count -eq 0) { return 3 }
        if (@($combos | Where-Object { $_ -match 'password' }).Count -eq 0) { return 2 }
        return 1
    }
    if ($st) { return 1 }
    if (@($Policy.grant.builtInControls) -contains 'mfa') { return 1 }
    return 0
}

function Get-PostureCaRiskChange {
    <#
    .SYNOPSIS
        Applies the spec 5.3 risk-relevant change rules to a Compare-PostureCaModel result.
    .DESCRIPTION
        Rules: exclusionAdded (to an MFA or legacy-auth policy), stateWeakened (enabled to report-only or disabled),
        breakGlassExclusionRemoved, trustedLocationAdded (new trusted location, location made trusted, or ranges
        changed on a trusted location), authStrengthWeakened (policy demands less, or a strength definition allows
        more), deviceComplianceRemoved, deletedReference (new), and enabledPolicyRemoved, which the spec list omits
        but is the loudest change of all.
    .PARAMETER BreakGlass
        UPNs or display names of break-glass accounts. Default: any excluded user whose name or UPN matches
        break-glass or emergency.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Diff,
        [string[]] $BreakGlass
    )

    $ErrorActionPreference = 'Stop'
    $risks = [System.Collections.Generic.List[object]]::new()
    $add = { param([string] $Rule, [string] $Subject, [string] $Id, [string] $Detail) $risks.Add([ordered]@{ rule = $Rule; subject = $Subject; id = $Id; detail = $Detail }) }
    $split = { param([string] $s) if ([string]::IsNullOrEmpty($s)) { @() } else { @($s -split '; ') } }

    $isBreakGlass = {
        param($Ref)
        $name = [string]$Ref.name; $upn = [string](Get-PostureValue $Ref 'userPrincipalName')
        if ($BreakGlass) { return [bool]($BreakGlass | Where-Object { $_ -eq $name -or $_ -eq $upn }) }
        return ($name -match '(?i)break.?glass|emergency') -or ($upn -match '(?i)break.?glass|emergency')
    }
    $isMfaOrLegacy = {
        param($P)
        if ((Get-PostureCaStrengthLevel -Policy $P) -ge 1) { return $true }
        $types = @($P.conditions.clientAppTypes)
        $legacyOnly = $types.Count -gt 0 -and @($types | Where-Object { $_ -notin @('exchangeActiveSync', 'other') }).Count -eq 0
        return $legacyOnly -and (@($P.grant.builtInControls) -contains 'block')
    }

    foreach ($r in @($Diff.policies.removed)) {
        if ($r.state -eq 'enabled') { & $add 'enabledPolicyRemoved' $r.name $r.id 'An enabled policy was deleted. Whatever it enforced is no longer enforced.' }
    }
    foreach ($a in @($Diff.policies.added)) {
        $deleted = @($a.after.healthFlags | Where-Object { $_.code -eq 'deletedReference' })
        foreach ($f in $deleted) { & $add 'deletedReference' $a.name $a.id $f.message }
    }

    foreach ($c in @($Diff.policies.changed)) {
        $b = $c.before; $a = $c.after
        if ($c.stateChanged -and $c.stateBefore -eq 'enabled' -and $c.stateAfter -in @('reportOnly', 'disabled')) {
            & $add 'stateWeakened' $c.name $c.id "Moved from enabled to $($c.stateAfter). It no longer enforces anything."
        }
        if (& $isMfaOrLegacy $a) {
            foreach ($path in 'assignments.excludeUsers', 'assignments.excludeGroups', 'assignments.excludeRoles') {
                $field = $c.fields | Where-Object { $_.path -eq $path }
                if (-not $field) { continue }
                $new = @((& $split $field.after) | Where-Object { $_ -notin (& $split $field.before) })
                if ($new.Count -gt 0) { & $add 'exclusionAdded' $c.name $c.id "Exclusion added on an MFA or legacy-auth policy: $($new -join ', ') ($($path -replace '^assignments\.', ''))." }
            }
        }
        $afterIds = @($a.assignments.excludeUsers | ForEach-Object { $_.id })
        foreach ($u in @($b.assignments.excludeUsers)) {
            if ($u.id -notin $afterIds -and (& $isBreakGlass $u)) {
                & $add 'breakGlassExclusionRemoved' $c.name $c.id "Break-glass account $($u.name) was removed from the exclusions. A policy misfire can now lock the tenant out."
            }
        }
        $lb = Get-PostureCaStrengthLevel -Policy $b; $la = Get-PostureCaStrengthLevel -Policy $a
        if ($la -lt $lb) {
            $labels = @('no MFA requirement', 'any MFA', 'passwordless MFA', 'phishing-resistant MFA')
            & $add 'authStrengthWeakened' $c.name $c.id "Required strength dropped from $($labels[$lb]) to $($labels[$la])."
        }
        $deviceControls = @('compliantDevice', 'domainJoinedDevice')
        $hadDevice = @($b.grant.builtInControls | Where-Object { $_ -in $deviceControls }).Count -gt 0
        $hasDevice = @($a.grant.builtInControls | Where-Object { $_ -in $deviceControls }).Count -gt 0
        if ($hadDevice -and -not $hasDevice) { & $add 'deviceComplianceRemoved' $c.name $c.id 'The device compliance or hybrid-join requirement was removed.' }
        $beforeDeleted = @($b.healthFlags | Where-Object { $_.code -eq 'deletedReference' } | ForEach-Object { $_.message })
        foreach ($f in @($a.healthFlags | Where-Object { $_.code -eq 'deletedReference' })) {
            if ($f.message -notin $beforeDeleted) { & $add 'deletedReference' $c.name $c.id $f.message }
        }
    }

    foreach ($l in @($Diff.locations.added)) {
        if (Get-PostureValue $l.after 'isTrusted') { & $add 'trustedLocationAdded' $l.name $l.id 'A new trusted named location. Policies that exclude trusted locations now skip it.' }
    }
    foreach ($l in @($Diff.locations.changed)) {
        $trustedField = $l.fields | Where-Object { $_.path -eq 'isTrusted' }
        if ($trustedField -and $trustedField.after -eq 'True') { & $add 'trustedLocationAdded' $l.name $l.id 'An existing named location was marked trusted.' }
        elseif ((Get-PostureValue $l.after 'isTrusted') -and @($l.fields | Where-Object { $_.path -like 'ipRanges*' -or $_.path -like 'countriesAndRegions*' }).Count -gt 0) {
            & $add 'trustedLocationAdded' $l.name $l.id 'The ranges of a trusted named location changed. Every policy that excludes trusted locations is affected.'
        }
    }

    foreach ($s in @($Diff.strengths.changed)) {
        $field = $s.fields | Where-Object { $_.path -eq 'allowedCombinations' }
        if (-not $field) { continue }
        $gained = @((& $split $field.after) | Where-Object { $_ -notin (& $split $field.before) })
        if ($gained.Count -gt 0) { & $add 'authStrengthWeakened' $s.name $s.id "Strength definition now also allows: $($gained -join ', '). Every policy using it accepts weaker sign-ins." }
    }

    return $risks.ToArray()
}
