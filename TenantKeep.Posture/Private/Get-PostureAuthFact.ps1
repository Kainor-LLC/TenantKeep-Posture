# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# Device-bound phishing-resistant methods: what AU-008 asks of every administrator and what the report's admin
# table and chart count as phishing-resistant. A synced passkey resists phishing too but lives in a consumer
# account's keychain, so for privileged accounts it is shown on its own, not counted here.
$script:PostureDeviceBoundMethods = @('fido2', 'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'passKeyDeviceBoundWindowsHello', 'windowsHelloForBusiness', 'x509Certificate', 'x509CertificateMultiFactor')

function Get-PostureAuthFact {
    <#
    .SYNOPSIS
        Fact provider for the authentication methods domain (spec 4.2). Reads the authentication methods policy and
        the registration report from a collection folder.
    .DESCRIPTION
        Files read: 02-authentication-methods-policy, 05-auth-registration, 05-auth-registration-summary,
        04-role-assignments-active. Thresholds read: minMfaRegisteredPct, minPasswordlessCapablePct.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [Parameter()] [System.Collections.IDictionary] $OrgProfile = @{},
        [Parameter()] [System.Collections.IDictionary] $Thresholds = @{}
    )

    $ErrorActionPreference = 'Stop'
    # Parsed once per evaluation and shared with the other domains (Read-PostureEvidenceFile); a missing file is
    # $null, an empty one an empty array.
    $load = {
        param([string] $Name)
        $parsed = Read-PostureEvidenceFile -Folder $Evidence -Name $Name
        if ($null -eq $parsed) { return $null }
        if ($parsed -is [array] -and $parsed.Count -eq 0) { return , @() }
        return $parsed
    }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}; $notes = @{}

    $policy = & $load '02-authentication-methods-policy'
    if ($null -eq $policy) {
        foreach ($id in 'AU-001', 'AU-002', 'AU-003', 'AU-004', 'AU-005') { $notEvaluated[$id] = '02-authentication-methods-policy.json was not collected.' }
    }
    elseif (@(& $v $policy 'authenticationMethodConfigurations' | Where-Object { $_ }).Count -eq 0) {
        # The policy always lists its methods. A file without them is not a tenant with every method off.
        foreach ($id in 'AU-001', 'AU-002', 'AU-003', 'AU-004', 'AU-005') { $notEvaluated[$id] = '02-authentication-methods-policy.json lists no authentication methods, so the policy was not read whole. Collect Entra again (Resume-PostureRun -Collector Entra).' }
    }
    else {
        $configs = @(& $v $policy 'authenticationMethodConfigurations' | Where-Object { $_ })
        $cfg = { param([string] $Id) @($configs | Where-Object { [string]$_.id -eq $Id }) | Select-Object -First 1 }
        $enabledForAll = {
            param($c)
            if (-not $c -or (& $v $c 'state') -ne 'enabled') { return $false }
            return [bool](@(& $v $c 'includeTargets') | Where-Object { (& $v $_ 'id') -eq 'all_users' })
        }
        $enabled = { param($c) [bool]($c -and (& $v $c 'state') -eq 'enabled') }

        $sms = & $cfg 'Sms'; $voice = & $cfg 'Voice'
        $facts.smsEnabled = & $enabled $sms
        $facts.smsEnabledForAllUsers = & $enabledForAll $sms
        $facts.voiceEnabled = & $enabled $voice
        $facts.voiceEnabledForAllUsers = & $enabledForAll $voice

        $auth = & $cfg 'MicrosoftAuthenticator'
        $facts.authenticatorEnabled = & $enabled $auth
        $facts.authenticatorAppInformation = ((& $v $auth 'featureSettings.displayAppInformationRequiredState.state') -eq 'enabled')
        $facts.authenticatorLocationInformation = ((& $v $auth 'featureSettings.displayLocationInformationRequiredState.state') -eq 'enabled')

        $fido = & $cfg 'Fido2'
        $facts.fido2Enabled = & $enabled $fido
        $facts.fido2KeyRestrictionsEnforced = [bool](& $v $fido 'keyRestrictions.isEnforced')
        $facts.fido2AttestationEnforced = [bool](& $v $fido 'isAttestationEnforced')

        $facts.policyMigrationState = [string](& $v $policy 'policyMigrationState')

        $tap = & $cfg 'TemporaryAccessPass'
        $facts.tapEnabled = & $enabled $tap
        $facts.tapOneTimeDefault = [bool](& $v $tap 'isUsableOnce')

        $facts.methodsEnabled = (@($configs | Where-Object { (& $v $_ 'state') -eq 'enabled' } | ForEach-Object { $_.id }) -join ', ')
    }

    $summary = & $load '05-auth-registration-summary'
    if ($null -eq $summary) { foreach ($id in 'AU-006', 'AU-007') { $notEvaluated[$id] = '05-auth-registration-summary.json was not collected (needs AuditLog.Read.All and UserAuthenticationMethod.Read.All).' } }
    else {
        $facts.mfaRegisteredPct = [double](& $v $summary 'MfaRegisteredPct')
        $facts.passwordlessCapablePct = [double](& $v $summary 'PasswordlessCapablePct')
        $facts.ssprRegisteredPct = [double](& $v $summary 'SsprRegisteredPct')
        $facts.totalMembers = [int](& $v $summary 'TotalMembers')
        $facts.usersWithSms = [int](& $v $summary 'UsersWithSms')
    }

    # The admin-only file the collector writes; the full one for runs made before it existed.
    $reg = & $load '05-auth-registration-admins'
    if ($null -eq $reg) { $reg = & $load '05-auth-registration' }
    if ($null -eq $reg) { $notEvaluated['AU-008'] = '05-auth-registration.json was not collected.' }
    else {
        # Everyone who holds a role: directly, as eligible, or through a group (04-role-holders). Graph's own flag
        # as well, which covers a folder without the role files.
        $holders = Get-PostureRoleHolder -Folder $Evidence
        $adminUpns = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($u in $holders.upns) { $null = $adminUpns.Add($u) }
        foreach ($r in @($reg | Where-Object { $_ -and $_.IsAdmin -eq $true })) { $null = $adminUpns.Add([string]$r.UserPrincipalName) }
        $phishing = $script:PostureDeviceBoundMethods
        $without = @($reg | Where-Object { $_ -and $adminUpns.Contains([string]$_.UserPrincipalName) } | Where-Object {
                $methods = @(([string]$_.MethodsRegistered) -split ';' | Where-Object { $_ })
                @($methods | Where-Object { $_ -in $phishing }).Count -eq 0
            })
        $facts.admins = $adminUpns.Count
        $facts.adminsWithoutPhishingResistant = $without.Count
        $affected.adminsWithoutPhishingResistant = @($without | ForEach-Object { [ordered]@{ name = $_.UserPrincipalName; detail = "registered: $(if ($_.MethodsRegistered) { $_.MethodsRegistered } else { 'nothing' })" } })
        # A group that holds a role and was not opened: its people are administrators nobody looked at.
        $gap = Get-PostureRoleHolderGap -Holder $holders
        if ($gap -and $without.Count -gt 0) { $notes['AU-008'] = "Judged on the $($adminUpns.Count) administrators that were read; $gap." }
        elseif ($gap) { $notEvaluated['AU-008'] = "No administrator without a phishing-resistant method among the $($adminUpns.Count) that were read, but $gap. Collect Entra again (Resume-PostureRun -Collector Entra)." }
    }

    $perUser = & $load '05-per-user-mfa-summary'
    $perUserRows = & $load '05-per-user-mfa'
    if ($null -eq $perUser) { $notEvaluated['AU-009'] = '05-per-user-mfa-summary.json was not collected (skipped with -SkipPerUserMfa, or UserAuthenticationMethod.Read.All missing).' }
    elseif ([int](& $v $perUser 'Users') -gt 0 -and [int](& $v $perUser 'Errors') -ge [int](& $v $perUser 'Users')) {
        $notEvaluated['AU-009'] = "Every per-user MFA read failed ($(& $v $perUser 'FirstError')); the state is unknown."
    }
    else {
        $facts.perUserMfaEnforced = [int](& $v $perUser 'Enforced')
        $facts.perUserMfaEnabled = [int](& $v $perUser 'Enabled')
        $facts.perUserMfaReadErrors = [int](& $v $perUser 'Errors')
        $affected.perUserMfaEnforced = @(@($perUserRows) | Where-Object { $_ -and $_.PerUserMfaState -in @('enforced', 'enabled') } | ForEach-Object { [ordered]@{ name = $_.UserPrincipalName; detail = "per-user MFA $($_.PerUserMfaState)" } })
    }

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; notes = $notes; evidence = @('02-authentication-methods-policy.json', '05-auth-registration.json', '05-auth-registration-summary.json') }
}
