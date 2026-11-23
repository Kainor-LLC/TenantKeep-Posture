# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PosturePowerPlatformFact {
    <#
    .SYNOPSIS
        Fact provider for the Power Platform and Power BI domain: the Power BI tenant settings (pbi-01) and the
        Power Platform tenant settings, environments, DLP policies and tenant isolation (pp-01 to pp-04).
    .DESCRIPTION
        The two halves come from two collectors that a tenant approves together and a run may still read apart: a
        missing file takes away the answers that need it and no others. A Power BI setting that is not in the list
        (Microsoft renames them) is no answer for its check, never a pass.

        BI-001 to BI-008 read one tenant setting each, by the name the Fabric admin API gives it. A setting that is on
        for named security groups only counts as restricted where CISA's baseline says it does (guest access,
        inviting outside users, service principals). PP-001 to PP-007 read the Power Platform tenant settings, which
        environments each DLP policy covers, and whether tenant isolation is on.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [Parameter()] [System.Collections.IDictionary] $OrgProfile = @{},
        [Parameter()] [System.Collections.IDictionary] $Thresholds = @{}
    )

    $ErrorActionPreference = 'Stop'
    $load = {
        param([string] $Name)
        $parsed = Read-PostureEvidenceFile -Folder $Evidence -Name $Name
        if ($null -eq $parsed) { return $null }
        if ($parsed -is [array] -and $parsed.Count -eq 0) { return , @() }
        return $parsed
    }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $rows = { param($o) @($o | Where-Object { $_ }) }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    $biChecks = 'BI-001', 'BI-002', 'BI-003', 'BI-004', 'BI-005', 'BI-006', 'BI-007', 'BI-008'
    $how = 'the tenant approves the optional Power BI and Power Platform reads once, then Resume-PostureRun -Collector'

    if (@(Get-ChildItem -LiteralPath $Evidence -Filter 'pbi-*.json' -ErrorAction SilentlyContinue).Count -eq 0 -and @(Get-ChildItem -LiteralPath $Evidence -Filter 'pp-*.json' -ErrorAction SilentlyContinue).Count -eq 0) {
        return @{ available = $false; reason = "No Power BI or Power Platform evidence in the folder ($how PowerBI, PowerPlatform)." }
    }

    # ---------- Power BI ----------
    $settings = & $load 'pbi-01-tenant-settings'
    if ($null -eq $settings) { foreach ($id in $biChecks) { $notEvaluated[$id] = "pbi-01-tenant-settings.json was not collected ($how PowerBI; check errors.txt)." } }
    elseif (@(& $rows $settings).Count -eq 0) { foreach ($id in $biChecks) { $notEvaluated[$id] = 'The Power BI tenant settings came back empty. Every tenant has them, so the sign-in was not allowed to see them.' } }
    else {
        $byName = @{}
        foreach ($s in @(& $rows $settings)) { $n = [string](& $v $s 'SettingName'); if ($n) { $byName[$n.ToLowerInvariant()] = $s } }
        $facts.powerBiSettingsRead = $byName.get_Count()
        # A setting by name: on or off, and whether it is held to named groups. Not in the list is no answer.
        $read = {
            param([string] $Id, [string] $Name)
            $s = $byName[$Name.ToLowerInvariant()]
            if ($null -eq $s) { $notEvaluated[$Id] = "Power BI did not return the tenant setting $Name. Microsoft may have renamed it; check it in the Fabric admin portal."; return $null }
            @{ on = [bool]((& $v $s 'Enabled') -eq $true); groups = @(@(& $v $s 'EnabledSecurityGroups') | Where-Object { $_ }) }
        }
        # On for everyone: on, with no security group to hold it to. On for named groups is the restricted state.
        $open = { param($s) [bool]($s.on -and @($s.groups).Count -eq 0) }
        $scope = { param($s) if (-not $s.on) { 'off' } elseif (@($s.groups).Count -gt 0) { "on for $(@($s.groups).Count) security group(s)" } else { 'on for the entire organisation' } }

        $s = & $read 'BI-001' 'PublishToWeb'
        if ($s) { $facts.powerBiPublishToWeb = (& $scope $s); $facts.powerBiPublishToWebOn = [bool]$s.on }
        $s = & $read 'BI-002' 'AllowGuestUserToAccessSharedContent'
        if ($s) { $facts.powerBiGuestAccess = (& $scope $s); $facts.powerBiGuestAccessOpen = (& $open $s) }
        $s = & $read 'BI-003' 'ExternalSharingV2'
        if ($s) { $facts.powerBiGuestInvites = (& $scope $s); $facts.powerBiGuestInvitesOpen = (& $open $s) }
        $s = & $read 'BI-004' 'ServicePrincipalAccessPermissionAPIs'
        if ($s) { $facts.powerBiServicePrincipalApis = (& $scope $s); $facts.powerBiServicePrincipalApisOpen = (& $open $s) }
        $s = & $read 'BI-005' 'AllowServicePrincipalsCreateAndUseProfiles'
        if ($s) { $facts.powerBiServicePrincipalProfiles = (& $scope $s); $facts.powerBiServicePrincipalProfilesOpen = (& $open $s) }
        $s = & $read 'BI-006' 'BlockResourceKeyAuthentication'
        if ($s) { $facts.powerBiResourceKeysBlocked = [bool]$s.on }
        $s = & $read 'BI-007' 'RScriptVisual'
        if ($s) { $facts.powerBiScriptVisualsOn = [bool]$s.on }
        $s = & $read 'BI-008' 'EimInformationProtectionEdit'
        if ($s) { $facts.powerBiSensitivityLabelsOn = [bool]$s.on }
    }

    # ---------- Power Platform ----------
    $missing = { param([string[]] $Ids, [string] $File) foreach ($id in $Ids) { $notEvaluated[$id] = "$File.json was not collected ($how PowerPlatform; check errors.txt)." } }
    $tenant = & $load 'pp-01-tenant-settings'
    if ($null -eq $tenant) { & $missing @('PP-001', 'PP-002', 'PP-006', 'PP-007') 'pp-01-tenant-settings' }
    else {
        # Each is a switch that turns something off for people who are not administrators: true is the restricted state.
        $switch = {
            param([string] $Id, [string] $Path, [string] $Fact, [string] $What)
            $value = & $v $tenant $Path
            if ($null -eq $value) { $notEvaluated[$Id] = "The Power Platform tenant settings did not say whether $What." } else { $facts[$Fact] = [bool]($value -ne $true) }
        }
        & $switch 'PP-001' 'disableEnvironmentCreationByNonAdminUsers' 'anyoneCreatesEnvironments' 'people who are not administrators may create production and sandbox environments'
        & $switch 'PP-002' 'disableTrialEnvironmentCreationByNonAdminUsers' 'anyoneCreatesTrialEnvironments' 'people who are not administrators may create trial environments'
        & $switch 'PP-006' 'disablePortalsCreationByNonAdminUsers' 'anyoneCreatesPowerPages' 'people who are not administrators may create Power Pages sites'
        & $switch 'PP-007' 'powerPlatform.powerApps.disableShareWithEveryone' 'appsShareWithEveryone' 'an app may be shared with Everyone'
    }

    # PP-003 and PP-004: which environments a DLP policy reaches. A policy covers every environment, only the ones
    # it names, or all but the ones it names.
    $environments = & $load 'pp-02-environments'; $policies = & $load 'pp-03-dlp-policies'
    if ($null -eq $environments) { & $missing @('PP-003', 'PP-004') 'pp-02-environments' }
    elseif ($null -eq $policies) { & $missing @('PP-003', 'PP-004') 'pp-03-dlp-policies' }
    else {
        $envRows = @(& $rows $environments); $policyRows = @(& $rows $policies)
        $covers = {
            param([string] $EnvironmentName)
            [bool]@($policyRows | Where-Object {
                    $kind = [string](& $v $_ 'EnvironmentType'); $named = @(@(& $v $_ 'Environments') | ForEach-Object { [string]$_ })
                    $kind -eq 'AllEnvironments' -or ($kind -eq 'OnlyEnvironments' -and $named -contains $EnvironmentName) -or ($kind -eq 'ExceptEnvironments' -and $named -notcontains $EnvironmentName)
                }).Count
        }
        $facts.powerPlatformEnvironments = $envRows.Count
        $facts.powerPlatformDlpPolicies = $policyRows.Count
        $default = @($envRows | Where-Object { (& $v $_ 'IsDefault') -eq $true })
        if ($default.Count -eq 0) { $notEvaluated['PP-003'] = 'The environment list that was read has no default environment in it, so the list is not whole.' }
        else { $facts.defaultEnvironmentHasDlp = [bool](& $covers ([string](& $v $default[0] 'Name'))) }
        $others = @($envRows | Where-Object { (& $v $_ 'IsDefault') -ne $true })
        $bare = @($others | Where-Object { -not (& $covers ([string](& $v $_ 'Name'))) })
        $facts.environmentsWithoutDlp = $bare.Count
        $affected.environmentsWithoutDlp = @($bare | Select-Object -First 500 | ForEach-Object { [ordered]@{ name = [string]$(if (& $v $_ 'DisplayName') { & $v $_ 'DisplayName' } else { & $v $_ 'Name' }); detail = "no DLP policy applies ($([string](& $v $_ 'Sku')))" } })
    }

    # PP-005: tenant isolation, which stops a connector in this tenant signing in to another tenant and the reverse.
    $isolation = & $load 'pp-04-tenant-isolation'
    if ($null -eq $isolation) { & $missing @('PP-005') 'pp-04-tenant-isolation' }
    elseif ($null -eq (& $v $isolation 'IsDisabled')) { $notEvaluated['PP-005'] = 'The tenant isolation policy did not say whether it is on.' }
    else {
        $facts.tenantIsolationOn = [bool]((& $v $isolation 'IsDisabled') -eq $false)
        $facts.tenantIsolationAllowedTenants = [int](& $v $isolation 'AllowedTenants')
    }

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('pbi-01-tenant-settings.json', 'pp-01-tenant-settings.json') }
}
