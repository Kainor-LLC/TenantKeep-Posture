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
    $t = @{ maxDomainAdmins = 5; maxKrbtgtAgeDays = 180; maxAdminPasswordAgeDays = 365; minLapsPct = 95; minPasswordLength = 14; maxSsoKeyAgeDays = 30; minCloudManagedGroupPct = 50 }
    foreach ($k in @($Thresholds.Keys)) { $t[$k] = $Thresholds[$k] }
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
    $rows = { param($o) @($o | Where-Object { $_ }) }
    $pct = { param([double] $n, [double] $d) if ($d -le 0) { $null } else { [Math]::Round(100.0 * $n / $d, 1) } }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    # A list of affected objects holds 500 at most; affectedCounts carries how many there are when the list is cut.
    $affectedCounts = @{}
    # Checks judged on part of the data: the engine turns a pass into no answer and puts a note on a fail.
    $partial = @{}
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

    # HY-032 and HY-033: groups managed in AD or in Entra. A group synced from AD is changed in AD, so whoever can edit it
    # there decides who a Conditional Access policy leaves out or who gets a licence. Read a row at a time.
    $caRef = @{}
    $pol = & $load 'policies'
    $polItems = @($(if ($pol -is [System.Collections.IDictionary] -and $pol.Contains('value')) { $pol['value'] } else { $pol }) | Where-Object { $_ })
    foreach ($cp in @($polItems | Where-Object { [string](& $v $_ 'state') -eq 'enabled' })) {
        $name = [string](& $v $cp 'displayName')
        foreach ($gid in @(& $v $cp 'conditions.users.excludeGroups' | Where-Object { $_ })) { if (-not $caRef.ContainsKey([string]$gid)) { $caRef[[string]$gid] = [System.Collections.Generic.List[string]]::new() }; $caRef[[string]$gid].Add("left out of Conditional Access policy '$name'") }
        foreach ($gid in @(& $v $cp 'conditions.users.includeGroups' | Where-Object { $_ })) { if (-not $caRef.ContainsKey([string]$gid)) { $caRef[[string]$gid] = [System.Collections.Generic.List[string]]::new() }; $caRef[[string]$gid].Add("in Conditional Access policy '$name'") }
    }
    $gs = @{ synced = 0; fromAd = 0; withSource = $false; access = 0 }
    $accessGroups = [System.Collections.Generic.List[object]]::new()
    $haveGroups = Read-PostureEvidenceRow -Folder $Evidence -Name '07-groups' -OnRow {
        param($_row)
        $source = [string](& $v $_row 'Source')
        if ($source) { $gs.withSource = $true }
        if (Test-PostureTrue (& $v $_row 'OnPremisesSyncEnabled')) {
            $gs.synced++
            $why = @($(if ($caRef.ContainsKey([string](& $v $_row 'Id'))) { $caRef[[string](& $v $_row 'Id')] }) + @($(if (Test-PostureTrue (& $v $_row 'Licensed')) { 'assigns licences' })))
            if ($why.Count) { $gs.access++ }
            if ($why.Count -and $accessGroups.Count -lt 500) { $accessGroups.Add([ordered]@{ name = [string](& $v $_row 'DisplayName'); detail = "synced from AD, $($why -join '; ')" }) }
        }
        elseif ($source -eq 'EntraFromAD') { $gs.fromAd++ }
    }
    if (-not $haveGroups) { foreach ($id in 'HY-032', 'HY-033') { $notEvaluated[$id] = '07-groups was not collected (the Entra collector).' } }
    else {
        if ($null -eq $pol) { $notEvaluated['HY-032'] = 'policies.json (the Conditional Access snapshot) is not in the folder, so the groups the policies use are unknown.' }
        else { $facts.syncedAccessGroups = $gs.access; $affected.syncedAccessGroups = @($accessGroups); $affectedCounts.syncedAccessGroups = $gs.access }
        $facts.syncedGroups = $gs.synced
        if (-not $gs.withSource -and $gs.synced -gt 0) { $notEvaluated['HY-033'] = '07-groups was collected before TenantKeep read where groups are managed. Collect Entra again (Resume-PostureRun -Collector Entra).' }
        else { $facts.groupsManagedInEntraFromAd = $gs.fromAd; $facts.cloudManagedGroupPct = $(if (($gs.synced + $gs.fromAd) -gt 0) { & $pct $gs.fromAd ($gs.synced + $gs.fromAd) } else { 100 }) }
    }
    $usersSummary = & $load '06-users-summary'
    if ($usersSummary) { $facts.syncedUsers = [int](& $v $usersSummary 'Synced'); $facts.usersManagedInEntraFromAd = [int](& $v $usersSummary 'EntraManagedFromAd'); $facts.cloudOnlyMembers = [int](& $v $usersSummary 'CloudOnlyMembers') }

    # AD side
    $adIds = @('HY-010', 'HY-011', 'HY-012', 'HY-013', 'HY-014', 'HY-015', 'HY-016', 'HY-017', 'HY-018', 'HY-019', 'HY-020', 'HY-021', 'HY-022', 'HY-023', 'HY-024', 'HY-025', 'HY-026', 'HY-027', 'HY-028', 'HY-029')
    if ($null -eq $forest) { & $adMissing $adIds 'ad-01-forest-domain'; return @{ available = $true; facts = $facts; affected = $affected; affectedCounts = $affectedCounts; notEvaluated = $notEvaluated; evidence = @('01-onprem-sync-features.json') } }

    $facts.forestFunctionalLevel = [string](& $v $forest 'ForestFunctionalLevel'); $facts.domainFunctionalLevel = [string](& $v $forest 'DomainFunctionalLevel')
    $level = { param([string] $m) if ($m -match '(\d{4})') { [int]$Matches[1] } else { 0 } }
    $facts.functionalLevelsAtLeast2016 = ((& $level $facts.forestFunctionalLevel) -ge 2016) -and ((& $level $facts.domainFunctionalLevel) -ge 2016)
    $facts.recycleBinEnabled = (& $v $forest 'RecycleBinEnabled') -eq $true
    $facts.machineAccountQuota = [int](& $v $forest 'MachineAccountQuota')
    $facts.minPasswordLength = [int](& $v $forest 'PasswordPolicy.MinPasswordLength'); $facts.lockoutThreshold = [int](& $v $forest 'PasswordPolicy.LockoutThreshold'); $facts.reversibleEncryption = (& $v $forest 'PasswordPolicy.ReversibleEncryptionEnabled') -eq $true
    $facts.passwordPolicyOk = $facts.minPasswordLength -ge [int]$t.minPasswordLength -and $facts.lockoutThreshold -gt 0 -and -not $facts.reversibleEncryption
    # NIST SP 800-63B: no periodic change. A maximum age of zero, or the effectively unlimited value, means never.
    $maxAge = [double](& $v $forest 'PasswordPolicy.MaxPasswordAgeDays')
    $facts.adPasswordMaxAgeDays = [int][Math]::Min($maxAge, 99999)
    $facts.adPasswordsExpire = ($maxAge -gt 0 -and $maxAge -lt 3650)

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
    if ($null -ne $gpos) {
        $gp = @(& $rows $gpos); $facts.gpos = $gp.Count
        $withPassword = @($gp | Where-Object { $_.HasCpassword -eq $true }).Count
        # Whether the preference files in SYSVOL were read: the collector says so since 2026-11-21 (ad-08-gpos-summary,
        # and HasCpassword empty on each row when they were not). Not read is unknown, never "no stored password".
        $gpoSummary = & $load 'ad-08-gpos-summary'
        $notScanned = ($null -ne $gpoSummary -and (& $v $gpoSummary 'SysvolScanned') -eq $false) -or @($gp | Where-Object { $_ -is [System.Collections.IDictionary] -and $_.Contains('HasCpassword') -and $null -eq $_['HasCpassword'] }).Count -gt 0
        $facts.gposWithCpassword = $(if ($notScanned -and $withPassword -eq 0) { $null } else { $withPassword })
        if ($null -eq $facts.gposWithCpassword) { $notEvaluated['HY-030'] = 'The Group Policy preference files in SYSVOL could not be read when Active Directory was collected, so whether a policy stores a password is unknown. Run collectors/windows/Get-ADBaseline.ps1 again from a machine that can read SYSVOL.' }
        $facts.unlinkedGpos = @($gp | Where-Object { [int]$_.Links -eq 0 }).Count
        $affected.gposWithCpassword = @($gp | Where-Object { $_.HasCpassword -eq $true } | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = 'cpassword in the GPO report' } })
    }
    else { $notEvaluated['HY-030'] = 'ad-08-gpos.json was not collected (GroupPolicy module missing on the jump box, or the step failed).' }

    # A forest with more than one domain, read on one of them: the collector reads one domain for each run. The
    # checks on that domain's accounts, groups, policies and computers speak for that domain and no other. The
    # Recycle Bin and the certificate templates are the forest's and are whole.
    $inForest = [Math]::Max([int](& $v $forest 'DomainCount'), @(& $v $forest 'ForestDomains' | Where-Object { $_ }).Count)
    $readDomains = [Math]::Max(1, @(& $v $forest 'DomainsCollected' | Where-Object { $_ }).Count)
    if ($inForest -gt $readDomains) {
        $domainName = [string](& $v $forest 'DomainName'); $where = $(if ($domainName) { "the domain $domainName" } else { 'one domain' })
        foreach ($id in 'HY-010', 'HY-011', 'HY-012', 'HY-013', 'HY-014', 'HY-015', 'HY-016', 'HY-017', 'HY-018', 'HY-019', 'HY-020', 'HY-021', 'HY-022', 'HY-024', 'HY-025', 'HY-026', 'HY-027', 'HY-028', 'HY-030', 'HY-031') {
            $partial[$id] = @{
                note     = "Judged on $where, one of $inForest in the forest; the other $($inForest - $readDomains) were not read."
                noAnswer = "Nothing wrong was found in $where, but the forest has $inForest domains and the other $($inForest - $readDomains) were not read: the collector reads one domain for each run, so there is no answer for the forest."
            }
        }
    }

    return @{ available = $true; facts = $facts; affected = $affected; affectedCounts = $affectedCounts; notEvaluated = $notEvaluated; partial = $partial; evidence = @('01-onprem-sync-features.json', 'ad-01-forest-domain.json') }
}
