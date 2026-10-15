# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureHybridFact {
    <#
    .SYNOPSIS
        Fact provider for the hybrid domain (spec 4.14): the Entra side from the cloud collectors (sync features,
        federation, Connect Health) and the Active Directory side from the ad-* files the Windows collector wrote.
    .DESCRIPTION
        Thresholds read: maxDomainAdmins, maxKrbtgtAgeDays, maxAdminPasswordAgeDays, minLapsPct, minPasswordLength,
        maxSsoKeyAgeDays. The AD files come from collectors/windows/Get-ADBaseline.ps1, copied into the evidence
        folder; without them the AD checks are not evaluated and say so.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [Parameter()] [System.Collections.IDictionary] $OrgProfile = @{},
        [Parameter()] [System.Collections.IDictionary] $Thresholds = @{}
    )

    $ErrorActionPreference = 'Stop'
    $t = @{ maxDomainAdmins = 5; maxKrbtgtAgeDays = 180; maxAdminPasswordAgeDays = 365; minLapsPct = 95; minPasswordLength = 14; maxSsoKeyAgeDays = 30 }
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
    $pct = { param([double] $n, [double] $d) if ($d -le 0) { $null } else { [Math]::Round(100.0 * $n / $d, 1) } }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    $adMissing = { param([string[]] $Ids, [string] $File) foreach ($id in $Ids) { $notEvaluated[$id] = "$File.json was not collected: run collectors/windows/Get-ADBaseline.ps1 on a domain-joined Windows machine and copy its folder into the evidence folder." } }

    $sync = & $load '01-onprem-sync-features'; $domains = & $load '01-domains'; $health = & $load 'az-08-entra-connect-health'
    $forest = & $load 'ad-01-forest-domain'
    if ($null -eq $sync -and $null -eq $forest) { return @{ available = $false; reason = 'No hybrid evidence: neither the Entra sync features nor the ad-* files from the Windows collector are in the folder.' } }

    # Entra side (HY-001 to HY-004)
    if ($null -eq $sync -or @(& $rows $sync).Count -eq 0) { foreach ($id in 'HY-001', 'HY-002') { $notEvaluated[$id] = '01-onprem-sync-features.json is empty or missing (OnPremDirectorySynchronization.Read.All); the tenant may not be synced.' } }
    else {
        $s1 = @(& $rows $sync)[0]
        $facts.passwordHashSync = (& $v $s1 'features.passwordSyncEnabled') -eq $true
        $facts.blockSoftMatch = (& $v $s1 'features.blockSoftMatchEnabled') -eq $true
        $facts.blockHardMatchTakeover = (& $v $s1 'features.blockCloudObjectTakeoverThroughHardMatchEnabled') -eq $true
        $facts.passwordWriteback = (& $v $s1 'features.passwordWritebackEnabled') -eq $true
    }
    if ($null -eq $domains) { $notEvaluated['HY-003'] = '01-domains.json was not collected (Entra collector).' }
    else { $facts.federatedDomains = @(& $rows $domains | Where-Object { [string]$_.AuthenticationType -eq 'Federated' }).Count }
    if ($null -eq $health) { $notEvaluated['HY-004'] = 'az-08-entra-connect-health.json was not collected (Azure collector).' }
    else { $h = @(& $rows $health); $facts.connectHealthServices = $h.Count; $facts.connectHealthActiveAlerts = @($h | ForEach-Object { [int]$(if ($null -ne $_.ActiveAlerts) { $_.ActiveAlerts } else { 0 }) } | Measure-Object -Sum).Sum }

    # AD side
    $adIds = @('HY-010', 'HY-011', 'HY-012', 'HY-013', 'HY-014', 'HY-015', 'HY-016', 'HY-017', 'HY-018', 'HY-019', 'HY-020', 'HY-021', 'HY-022', 'HY-023', 'HY-024', 'HY-025', 'HY-026', 'HY-027', 'HY-028', 'HY-029')
    if ($null -eq $forest) { & $adMissing $adIds 'ad-01-forest-domain'; return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('01-onprem-sync-features.json') } }

    $facts.forestFunctionalLevel = [string](& $v $forest 'ForestFunctionalLevel'); $facts.domainFunctionalLevel = [string](& $v $forest 'DomainFunctionalLevel')
    $level = { param([string] $m) if ($m -match '(\d{4})') { [int]$Matches[1] } else { 0 } }
    $facts.functionalLevelsAtLeast2016 = ((& $level $facts.forestFunctionalLevel) -ge 2016) -and ((& $level $facts.domainFunctionalLevel) -ge 2016)
    $facts.recycleBinEnabled = (& $v $forest 'RecycleBinEnabled') -eq $true
    $facts.machineAccountQuota = [int](& $v $forest 'MachineAccountQuota')
    $facts.minPasswordLength = [int](& $v $forest 'PasswordPolicy.MinPasswordLength'); $facts.lockoutThreshold = [int](& $v $forest 'PasswordPolicy.LockoutThreshold'); $facts.reversibleEncryption = (& $v $forest 'PasswordPolicy.ReversibleEncryptionEnabled') -eq $true
    $facts.passwordPolicyOk = $facts.minPasswordLength -ge [int]$t.minPasswordLength -and $facts.lockoutThreshold -gt 0 -and -not $facts.reversibleEncryption

    $dcs = & $load 'ad-02-domain-controllers'
    if ($null -eq $dcs) { & $adMissing @('HY-022') 'ad-02-domain-controllers' }
    else { $d = @(& $rows $dcs); $facts.domainControllers = $d.Count; $unsupported = @($d | Where-Object { $_.Supported -ne $true }); $facts.domainControllersUnsupported = $unsupported.Count; $affected.domainControllersUnsupported = @($unsupported | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = [string]$_.OperatingSystem } }) }

    $groups = & $load 'ad-03-privileged-groups'
    if ($null -eq $groups) { & $adMissing @('HY-010', 'HY-011', 'HY-012') 'ad-03-privileged-groups' }
    else {
        $g = @(& $rows $groups)
        $members = { param([string] $name) @($g | Where-Object { [string]$_.Group -eq $name }) }
        $da = & $members 'Domain Admins'
        $facts.domainAdmins = $da.Count
        $affected.domainAdmins = @($da | ForEach-Object { [ordered]@{ name = [string]$_.SamAccountName; detail = "Domain Admins ($($_.ObjectClass))" } })
        $ea = @(& $members 'Enterprise Admins') + @(& $members 'Schema Admins')
        $facts.enterpriseAndSchemaAdmins = $ea.Count
        $affected.enterpriseAndSchemaAdmins = @($ea | ForEach-Object { [ordered]@{ name = [string]$_.SamAccountName; detail = [string]$_.Group } })
        $ops = @($g | Where-Object { [string]$_.Group -in @('Account Operators', 'Server Operators', 'Print Operators', 'Backup Operators', 'DnsAdmins', 'Group Policy Creator Owners') })
        $facts.operatorGroupMembers = $ops.Count
        $affected.operatorGroupMembers = @($ops | ForEach-Object { [ordered]@{ name = [string]$_.SamAccountName; detail = [string]$_.Group } })
    }

    $admins = & $load 'ad-03-admin-accounts'
    if ($null -eq $admins) { & $adMissing @('HY-013') 'ad-03-admin-accounts' }
    else {
        $a = @(& $rows $admins | Where-Object { $_.Enabled -ne $false -and [string]$_.SamAccountName -ne 'krbtgt' })
        $bad = @($a | ForEach-Object {
                $issues = @()
                if ($_.InProtectedUsers -ne $true) { $issues += 'not in Protected Users' }
                if ($_.AccountNotDelegated -ne $true) { $issues += 'delegation allowed' }
                if ($_.HasSpn -eq $true) { $issues += 'has an SPN' }
                if ($_.HasMailbox -eq $true) { $issues += 'has a mailbox' }
                if ($null -ne $_.PasswordAgeDays -and [int]$_.PasswordAgeDays -gt [int]$t.maxAdminPasswordAgeDays) { $issues += "password $($_.PasswordAgeDays) days old" }
                if ($issues.Count -gt 0) { [ordered]@{ name = [string]$_.SamAccountName; detail = ($issues -join ', ') } }
            })
        $facts.adminAccounts = $a.Count
        $facts.adminAccountsWithIssues = $bad.Count
        $affected.adminAccountsWithIssues = @($bad)
    }

    $builtin = & $load 'ad-04-builtin-accounts'
    if ($null -eq $builtin) { & $adMissing @('HY-014', 'HY-015') 'ad-04-builtin-accounts' }
    else {
        $facts.krbtgtPasswordAgeDays = [int](& $v $builtin 'KrbtgtPasswordAgeDays')
        $facts.builtinAdministratorEnabled = (& $v $builtin 'BuiltinAdministratorEnabled') -eq $true
        $facts.guestEnabled = (& $v $builtin 'GuestEnabled') -eq $true
    }

    $deleg = & $load 'ad-05-delegation'
    if ($null -eq $deleg) { & $adMissing @('HY-017') 'ad-05-delegation' }
    else { $u = @(& $rows $deleg | Where-Object { $_.Unconstrained -eq $true -and $_.IsDomainController -ne $true }); $facts.unconstrainedDelegationNonDc = $u.Count; $affected.unconstrainedDelegationNonDc = @($u | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = "$($_.ObjectClass) trusted for unconstrained delegation" } }) }

    $kerb = & $load 'ad-05-kerberoastable'; $asrep = & $load 'ad-05-asrep-roastable'
    if ($null -eq $kerb) { & $adMissing @('HY-018') 'ad-05-kerberoastable' }
    else { $k = @(& $rows $kerb | Where-Object { $_.Enabled -ne $false }); $facts.kerberoastableAccounts = $k.Count; $affected.kerberoastableAccounts = @($k | ForEach-Object { [ordered]@{ name = [string]$_.SamAccountName; detail = "$($_.Spns) SPN(s), password $($_.PasswordAgeDays) days old$(if ($_.AesOnly -ne $true) { ', RC4 allowed' })$(if ($_.Privileged) { ', privileged' })" } }) }
    if ($null -eq $asrep) { & $adMissing @('HY-019') 'ad-05-asrep-roastable' }
    else { $r = @(& $rows $asrep | Where-Object { $_.Enabled -ne $false }); $facts.asrepRoastableAccounts = $r.Count; $affected.asrepRoastableAccounts = @($r | ForEach-Object { [ordered]@{ name = [string]$_.SamAccountName; detail = 'Kerberos pre-authentication not required' } }) }

    $comp = & $load 'ad-06-computers-summary'
    if ($null -eq $comp) { & $adMissing @('HY-020') 'ad-06-computers-summary' }
    else {
        $facts.activeWindowsNonDc = [int](& $v $comp 'ActiveWindowsNonDc'); $facts.windowsLapsComputers = [int](& $v $comp 'WindowsLaps'); $facts.legacyLapsComputers = [int](& $v $comp 'LegacyLaps')
        $facts.lapsPct = & $pct $facts.windowsLapsComputers $facts.activeWindowsNonDc
        if ($facts.activeWindowsNonDc -eq 0) { $notEvaluated['HY-020'] = 'No active Windows member computers.' }
        $facts.lapsSchemaPresent = ((& $v $comp 'WindowsLapsSchema') -eq $true) -or ((& $v $comp 'LegacyLapsSchema') -eq $true)
    }

    $users = & $load 'ad-07-users-summary'
    if ($null -eq $users) { & $adMissing @('HY-024', 'HY-026') 'ad-07-users-summary' }
    else {
        $facts.staleEnabledUsers = [int](& $v $users 'StaleEnabled'); $facts.passwordNeverExpiresHumans = [int](& $v $users 'PasswordNeverExpiresEnabledHumans'); $facts.enabledUsers = [int](& $v $users 'Enabled'); $facts.staleUserPct = & $pct $facts.staleEnabledUsers $facts.enabledUsers
        $staleList = & $load 'ad-07-stale-users'; $neverList = & $load 'ad-07-password-never-expires'
        $affected.staleEnabledUsers = @(& $rows $staleList | ForEach-Object { [ordered]@{ name = [string]$_.SamAccountName; detail = $(if ($_.LastLogon) { "last logon $([string]$_.LastLogon)" } else { 'never signed in' }) } })
        $affected.passwordNeverExpiresHumans = @(& $rows $neverList | ForEach-Object { [ordered]@{ name = [string]$_.SamAccountName; detail = "password set $([string]$_.PasswordLastSet)" } })
    }

    $trusts = & $load 'ad-01-trusts'
    if ($null -eq $trusts) { & $adMissing @('HY-027') 'ad-01-trusts' }
    else { $tr = @(& $rows $trusts | Where-Object { $_.IntraForest -ne $true }); $facts.externalTrusts = $tr.Count; $weak = @($tr | Where-Object { $_.SidFilteringQuarantined -ne $true -and $_.SidFilteringForestAware -ne $true }); $facts.trustsWithoutSidFiltering = $weak.Count; $affected.trustsWithoutSidFiltering = @($weak | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = "$($_.TrustType) $($_.Direction), SID filtering off" } }) }

    $entra = & $load 'ad-10-entra-accounts'
    if ($null -eq $entra) { & $adMissing @('HY-028') 'ad-10-entra-accounts' }
    else { $facts.seamlessSsoPresent = (& $v $entra 'SeamlessSsoPresent') -eq $true; $facts.seamlessSsoKeyAgeDays = & $v $entra 'SeamlessSsoKeyAgeDays'; $facts.cloudKerberosTrustPresent = (& $v $entra 'CloudKerberosTrustPresent') -eq $true; if (-not $facts.seamlessSsoPresent) { $notEvaluated['HY-028'] = 'Seamless SSO is not deployed (no AZUREADSSOACC account).' } }

    $adcs = & $load 'ad-09-adcs'; $tpl = & $load 'ad-09-adcs-templates'
    if ($null -eq $adcs) { & $adMissing @('HY-029') 'ad-09-adcs' }
    else {
        $facts.adcsPresent = (& $v $adcs 'Present') -eq $true
        $esc1 = @(& $rows $tpl | Where-Object { $_.Esc1Candidate -eq $true })
        $facts.adcsEsc1Templates = $esc1.Count
        $affected.adcsEsc1Templates = @($esc1 | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = 'published, enrollee supplies subject, client authentication, no approval or signature' } })
        if (-not $facts.adcsPresent) { $notEvaluated['HY-029'] = 'No enrollment services in the forest (AD CS not present).' }
    }

    $gpos = & $load 'ad-08-gpos'
    if ($null -ne $gpos) { $gp = @(& $rows $gpos); $facts.gpos = $gp.Count; $facts.gposWithCpassword = @($gp | Where-Object { $_.HasCpassword -eq $true }).Count; $facts.unlinkedGpos = @($gp | Where-Object { [int]$_.Links -eq 0 }).Count; $affected.gposWithCpassword = @($gp | Where-Object { $_.HasCpassword -eq $true } | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = 'cpassword in the GPO report' } }) }
    else { $notEvaluated['HY-030'] = 'ad-08-gpos.json was not collected (GroupPolicy module missing on the jump box, or the step failed).' }

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('01-onprem-sync-features.json', 'ad-01-forest-domain.json') }
}
