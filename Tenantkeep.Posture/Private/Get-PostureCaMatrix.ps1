# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureCaMatrix {
    <#
    .SYNOPSIS
        Policy matrix (spec 5.2): policies as rows, personas and app groups as columns, the control applied in each cell.
    .DESCRIPTION
        Default columns: All users, Admin roles, Guests, Workload identities; All apps, Office 365, Admin portals,
        Register security info. A cell holds the short control label when the policy targets that column, with
        a state suffix for report-only or disabled policies, and is empty otherwise.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Policy,
        [string[]] $Column
    )

    $ErrorActionPreference = 'Stop'

    $has = { param($Refs, [string] $Id) [bool]@(@($Refs) | Where-Object { $_ -and $_.id -eq $Id }) }
    $definitions = [ordered]@{
        allUsers             = @{ label = 'All users'; group = 'persona'; test = { param($p) & $has $p.assignments.includeUsers 'All' } }
        adminRoles           = @{ label = 'Admin roles'; group = 'persona'; test = { param($p) @($p.assignments.includeRoles).Count -gt 0 -or ((& $has $p.assignments.includeUsers 'All') -and @($p.assignments.excludeRoles).Count -eq 0) } }
        guests               = @{ label = 'Guests'; group = 'persona'; test = { param($p) (& $has $p.assignments.includeUsers 'GuestsOrExternalUsers') -or [bool]$p.assignments.includeGuestsOrExternal -or ((& $has $p.assignments.includeUsers 'All') -and -not $p.assignments.excludeGuestsOrExternal -and -not (& $has $p.assignments.excludeUsers 'GuestsOrExternalUsers')) } }
        workloadIdentities   = @{ label = 'Workload identities'; group = 'persona'; test = { param($p) @($p.assignments.includeServicePrincipals).Count -gt 0 } }
        allApps              = @{ label = 'All apps'; group = 'app'; test = { param($p) & $has $p.targets.includeApplications 'All' } }
        office365            = @{ label = 'Office 365'; group = 'app'; test = { param($p) ((& $has $p.targets.includeApplications 'Office365') -or (& $has $p.targets.includeApplications 'All')) -and -not (& $has $p.targets.excludeApplications 'Office365') } }
        adminPortals         = @{ label = 'Admin portals'; group = 'app'; test = { param($p) ((& $has $p.targets.includeApplications 'MicrosoftAdminPortals') -or (& $has $p.targets.includeApplications 'All')) -and -not (& $has $p.targets.excludeApplications 'MicrosoftAdminPortals') } }
        registerSecurityInfo = @{ label = 'Register security info'; group = 'app'; test = { param($p) & $has $p.targets.userActions 'urn:user:registersecurityinfo' } }
    }

    $keys = if ($Column) { @($Column) } else { @($definitions.Keys) }
    $unknown = @($keys | Where-Object { -not $definitions.Contains($_) })
    if ($unknown.Count -gt 0) { throw "Unknown matrix column(s): $($unknown -join ', '). Known: $($definitions.Keys -join ', ')" }

    $rows = foreach ($p in $Policy) {
        $control = Get-PostureCaControlLabel -Policy $p
        $suffix = switch ($p.state) { 'reportOnly' { ' (report-only)' } 'disabled' { ' (disabled)' } default { '' } }
        $cells = [ordered]@{}
        foreach ($k in $keys) {
            $applies = [bool](& $definitions[$k].test $p)
            $cells[$k] = if ($applies) { "$control$suffix" } else { '' }
        }
        [ordered]@{ id = $p.id; name = $p.name; state = $p.state; control = $control; cells = $cells }
    }

    return [ordered]@{
        columns = @($keys | ForEach-Object { [ordered]@{ key = $_; label = $definitions[$_].label; group = $definitions[$_].group } })
        rows    = @($rows)
    }
}

function Get-PostureCaControlLabel {
    <#
    .SYNOPSIS
        Short label for a policy's grant controls, for matrix cells and proposed names: "Block", "MFA", "Phishing-resistant MFA", "MFA + Compliant device".
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Policy
    )

    $ErrorActionPreference = 'Stop'
    $short = @{
        block = 'Block'; mfa = 'MFA'; compliantDevice = 'Compliant device'; domainJoinedDevice = 'Hybrid joined'
        approvedApplication = 'Approved app'; compliantApplication = 'App protection'; passwordChange = 'Password change'
    }
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($c in @($Policy.grant.builtInControls)) { $parts.Add($(if ($short.ContainsKey($c)) { $short[$c] } else { $c })) }
    if ($Policy.grant.authenticationStrength) { $parts.Add($Policy.grant.authenticationStrength.name) }
    if (@($Policy.grant.termsOfUse).Count -gt 0) { $parts.Add('Terms of use') }
    if ($parts.Count -eq 0) {
        $s = $Policy.session
        if ($s.signInFrequency -or $s.persistentBrowser -or $s.applicationEnforcedRestrictions -or $s.cloudAppSecurity -or $s.secureSignInSession) { return 'Session controls' }
        return 'No controls'
    }
    $joiner = if ($Policy.grant.operator -eq 'AND') { ' + ' } else { ' / ' }
    return ($parts -join $joiner)
}
