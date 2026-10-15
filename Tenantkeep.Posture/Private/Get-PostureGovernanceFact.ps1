# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureGovernanceFact {
    <#
    .SYNOPSIS
        Fact provider for the governance domain (spec 4.8): inactive members, access reviews on roles and guests,
        access packages, lifecycle workflows, PIM for Groups, the SSO protocol mix, SAML certificate expiry,
        administrative units, application owners and an HR-driven provisioning connector.
    .DESCRIPTION
        Reads 06-users-summary, 07-groups, 10-service-principals and the gov-* files. Thresholds read:
        maxInactiveMemberPct, maxPasswordSsoPct, samlCertWarningDays, adminUnitScaleUsers. The interview items in the
        spec (deprovisioning SLA, orphan accounts against an HR extract, SCIM error review) are not checks yet.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [Parameter()] [System.Collections.IDictionary] $OrgProfile = @{},
        [Parameter()] [System.Collections.IDictionary] $Thresholds = @{},
        [datetime] $AsOf = [datetime]::UtcNow
    )

    $ErrorActionPreference = 'Stop'
    $t = @{ maxInactiveMemberPct = 5; maxPasswordSsoPct = 10; samlCertWarningDays = 90; adminUnitScaleUsers = 1000 }
    foreach ($k in @($Thresholds.Keys)) { $t[$k] = $Thresholds[$k] }
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
    $pct = { param([double] $n, [double] $d) if ($d -le 0) { 0 } else { [Math]::Round(100.0 * $n / $d, 1) } }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    $missing = { param([string[]] $Ids, [string] $File, [string] $Scope) foreach ($id in $Ids) { $notEvaluated[$id] = "$File.json was not collected (Entra collector; needs $Scope; check errors.txt)." } }

    $users = & $load '06-users-summary'
    if ($null -eq $users) { return @{ available = $false; reason = 'No identity evidence in the folder (Invoke-PostureCollection -Collector Entra).' } }
    $facts.members = [int](& $v $users 'Members')
    $facts.guests = [int](& $v $users 'Guests')
    $facts.enabledInactiveMembers = [int](& $v $users 'EnabledInactiveMembers')
    $facts.inactiveMemberPct = & $pct $facts.enabledInactiveMembers $facts.members
    if ((& $v $users 'SignInActivityAvailable') -eq $false) { $notEvaluated['GV-001'] = 'Sign-in activity was not collected (AuditLog.Read.All); inactive members cannot be counted.' }
    $facts.staleDays = & $v $users 'StaleDays'

    # Access reviews (GV-002, GV-003)
    $reviews = & $load 'gov-01-access-reviews'
    if ($null -eq $reviews) { & $missing @('GV-002', 'GV-003') 'gov-01-access-reviews' 'AccessReview.Read.All' }
    else {
        $active = @(& $rows $reviews | Where-Object { $_.Recurring -eq $true -and [string]$_.Status -notin @('Completed', 'Canceled') })
        $facts.accessReviewDefinitions = @(& $rows $reviews).Count
        # (verify) the scope query shapes: role reviews point at roleManagement/directory or privilegedAccess; guest reviews filter userType eq 'Guest'
        $facts.privilegedRoleReviews = @($active | Where-Object { [string]$_.ScopeQuery -match 'roleManagement/directory|privilegedAccess|roleAssignment' }).Count
        $facts.guestReviews = @($active | Where-Object { [string]$_.ScopeQuery -match "userType eq 'Guest'|userType eq ''Guest''|/guest" }).Count
    }

    # Access packages (GV-004)
    $ap = & $load 'gov-02-access-packages-summary'
    if ($null -eq $ap) { & $missing @('GV-004') 'gov-02-access-packages-summary' 'EntitlementManagement.Read.All' }
    else { $facts.accessPackages = [int](& $v $ap 'Packages'); $facts.accessPackageCatalogs = [int](& $v $ap 'Catalogs'); $facts.connectedOrganizations = [int](& $v $ap 'ConnectedOrganizations') }

    # Lifecycle workflows (GV-005)
    $wf = & $load 'gov-03-lifecycle-workflows'
    if ($null -eq $wf) { & $missing @('GV-005') 'gov-03-lifecycle-workflows' 'LifecycleWorkflows.Read.All' }
    else {
        $enabled = @(& $rows $wf | Where-Object { $_.IsEnabled -eq $true })
        $facts.lifecycleWorkflowsEnabled = $enabled.Count
        $facts.joinerWorkflow = @($enabled | Where-Object { [string]$_.Category -match '(?i)joiner' }).Count -gt 0
        $facts.leaverWorkflow = @($enabled | Where-Object { [string]$_.Category -match '(?i)leaver' }).Count -gt 0
    }

    # PIM for Groups (GV-006)
    $groups = & $load '07-groups'; $pim = & $load 'gov-04-pim-groups-summary'
    if ($null -eq $groups) { & $missing @('GV-006') '07-groups' 'Group.Read.All' }
    elseif ($null -eq $pim) { & $missing @('GV-006') 'gov-04-pim-groups-summary' 'PrivilegedEligibilitySchedule.Read.AzureADGroup' }
    else {
        $facts.roleAssignableGroups = @(& $rows $groups | Where-Object { $_.IsAssignableToRole -eq $true }).Count
        $facts.pimManagedGroups = [int](& $v $pim 'Groups')
        $facts.pimEligibleGroupAssignments = [int](& $v $pim 'EligibleAssignments')
    }

    # Service principals: SSO mix (GV-007), SAML certificates (GV-008), owners (GV-010), HR connector (GV-011)
    $sps = & $load '10-service-principals'
    if ($null -eq $sps) { & $missing @('GV-007', 'GV-008', 'GV-010', 'GV-011') '10-service-principals' 'Directory.Read.All' }
    else {
        $apps = @(& $rows $sps | Where-Object { $_.IsEnterpriseAppListed -eq $true -and $_.AccountEnabled -ne $false })
        $facts.enterpriseApps = $apps.Count
        $byMode = @{}
        foreach ($a in $apps) { $m = [string]$a.PreferredSingleSignOnMode; if (-not $m) { $m = 'none' }; $byMode[$m] = 1 + $(if ($byMode.ContainsKey($m)) { $byMode[$m] } else { 0 }) }
        $facts.ssoByMode = [ordered]@{}; foreach ($k in ($byMode.Keys | Sort-Object)) { $facts.ssoByMode[$k] = $byMode[$k] }
        $federated = @($apps | Where-Object { [string]$_.PreferredSingleSignOnMode -in @('saml', 'oidc') }).Count
        $password = @($apps | Where-Object { [string]$_.PreferredSingleSignOnMode -eq 'password' })
        $facts.ssoFederatedApps = $federated
        $facts.ssoPasswordApps = $password.Count
        $facts.passwordSsoPct = & $pct $password.Count ($federated + $password.Count)
        $affected.passwordSsoApps = @($password | ForEach-Object { [ordered]@{ name = [string]$_.DisplayName; detail = 'password-based single sign-on' } })

        $warn = $AsOf.AddDays([int]$t.samlCertWarningDays)
        # Only applications signed in through SAML: every service principal can carry a Verify key, including first-party and retired apps.
        $expiring = @($apps | Where-Object { [string]$_.PreferredSingleSignOnMode -eq 'saml' -and $_.SamlCertExpiry } | Where-Object { $d = ConvertTo-PostureUtcDateTime $_.SamlCertExpiry; $d -and $d -lt $warn })
        $facts.samlCertsExpiringSoon = $expiring.Count
        $affected.samlCertsExpiringSoon = @($expiring | ForEach-Object { [ordered]@{ name = [string]$_.DisplayName; detail = "SAML signing certificate expires $((ConvertTo-PostureUtcDateTime $_.SamlCertExpiry).ToString('yyyy-MM-dd'))" } })

        if (@($apps | Where-Object { $_.Contains('OwnerCount') }).Count -eq 0 -and $apps.Count -gt 0) { $notEvaluated['GV-010'] = '10-service-principals.json predates the owner count; collect again.' }
        else {
            $ownerless = @($apps | Where-Object { [int]$_.OwnerCount -eq 0 })
            $facts.enterpriseAppsWithoutOwner = $ownerless.Count
            $affected.enterpriseAppsWithoutOwner = @($ownerless | ForEach-Object { [ordered]@{ name = [string]$_.DisplayName; detail = 'enterprise application with no owner' } })
        }

        # (verify) HR connector detection by name; API-driven inbound provisioning apps carry the template name
        $hr = @(& $rows $sps | Where-Object { [string]$_.DisplayName -match '(?i)workday|successfactors|api-driven|oracle hcm|oracle fusion|\bukg\b|bamboohr|\badp\b' })
        $facts.hrProvisioningConnectors = $hr.Count
    }

    # Administrative units (GV-009)
    $aus = & $load 'gov-05-administrative-units'
    if ($null -eq $aus) { & $missing @('GV-009') 'gov-05-administrative-units' 'AdministrativeUnit.Read.All' }
    else { $facts.administrativeUnits = @(& $rows $aus).Count }

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('06-users-summary.json', '10-service-principals.json') }
}
