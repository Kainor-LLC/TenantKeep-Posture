# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
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
    $load = {
        param([string] $Name)
        $f = Join-Path $Evidence "$Name.json"
        if (-not (Test-Path -LiteralPath $f)) { return $null }
        $text = Get-Content -Raw -LiteralPath $f
        if ([string]::IsNullOrWhiteSpace($text)) { return , @() }
        $parsed = ConvertFrom-Json -InputObject $text -AsHashtable -Depth 20
        # An empty JSON array parses to nothing; keep it distinct from a missing file.
        if ($null -eq $parsed) { return , @() }
        return $parsed
    }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}

    $policy = & $load '02-authentication-methods-policy'
    if ($null -eq $policy) {
        foreach ($id in 'AU-001', 'AU-002', 'AU-003', 'AU-004', 'AU-005') { $notEvaluated[$id] = '02-authentication-methods-policy.json was not collected.' }
    }
    else {
        $configs = @(& $v $policy 'authenticationMethodConfigurations')
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

    $reg = & $load '05-auth-registration'
    $active = & $load '04-role-assignments-active'
    if ($null -eq $reg) { $notEvaluated['AU-008'] = '05-auth-registration.json was not collected.' }
    else {
        $adminUpns = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($r in @($reg | Where-Object { $_.IsAdmin -eq $true })) { $null = $adminUpns.Add([string]$r.UserPrincipalName) }
        foreach ($a in @($active | Where-Object { $_.PrincipalType -eq 'user' -and $_.PrincipalUpn })) { $null = $adminUpns.Add([string]$a.PrincipalUpn) }
        $phishing = 'fido2', 'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'passKeyDeviceBoundWindowsHello', 'windowsHelloForBusiness', 'x509Certificate', 'x509CertificateMultiFactor'
        $without = @($reg | Where-Object { $adminUpns.Contains([string]$_.UserPrincipalName) } | Where-Object {
                $methods = @(([string]$_.MethodsRegistered) -split ';' | Where-Object { $_ })
                @($methods | Where-Object { $_ -in $phishing }).Count -eq 0
            })
        $facts.admins = $adminUpns.Count
        $facts.adminsWithoutPhishingResistant = $without.Count
        $affected.adminsWithoutPhishingResistant = @($without | ForEach-Object { [ordered]@{ name = $_.UserPrincipalName; detail = "registered: $(if ($_.MethodsRegistered) { $_.MethodsRegistered } else { 'nothing' })" } })
    }

    $notEvaluated['AU-009'] = 'Legacy per-user MFA state is not collected yet (planned A.1 addition).'

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('02-authentication-methods-policy.json', '05-auth-registration.json', '05-auth-registration-summary.json') }
}
