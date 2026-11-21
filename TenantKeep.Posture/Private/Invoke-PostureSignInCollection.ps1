# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# Client apps Entra reports for sign-ins that use a legacy protocol (basic authentication, no MFA possible).
$script:PostureLegacyClientApps = @('Exchange ActiveSync', 'IMAP4', 'POP3', 'SMTP', 'Authenticated SMTP', 'Exchange Web Services', 'MAPI Over HTTP', 'Offline Address Book', 'Other clients', 'AutoDiscover', 'Exchange Online PowerShell', 'Outlook Anywhere (RPC over HTTP)', 'Reporting Web Services', 'Universal Outlook')

function Invoke-PostureSignInCollection {
    <#
    .SYNOPSIS
        Reads the Entra sign-in log for the last -Days days, at any volume, and writes what the checks and charts
        need: totals, legacy-protocol sign-ins by user, Conditional Access outcomes, what each report-only policy would
        have done, every role holder's sign-ins and how many were single-factor, failures by error code and the
        addresses where many accounts failed (password spray), sign-ins per day and per country. The raw records are
        never kept; every per-object tally is capped.
    .DESCRIPTION
        Built for tenants with millions of sign-ins and runs of hours:
          - Pages of 1,000 records with only the fields counted ($select), streamed and tallied page by page, so
            memory stays flat however many there are.
          - Every page goes through the Graph wrapper's retry policy (throttling, transient failures, an expired
            token renewed from the sign-in).
          - Every few pages the tallies and the page link are saved to .signins-checkpoint.json in the run folder.
            When a read fails anyway, the step waits and carries on from the checkpoint by itself, up to
            -SelfRetries times; a page link Graph no longer accepts is replaced by a new query from the oldest
            record already counted. If it still cannot finish, the checkpoint stays and Resume-PostureRun (or the
            next attempt into the same folder) continues from the page it stopped at.
        Needs AuditLog.Read.All with Reports Reader, Security Reader or Global Reader, and Entra ID P1 or P2.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [ValidateRange(1, 30)] [int] $Days = 7,
        [datetime] $AsOf = [datetime]::UtcNow,
        [int] $CheckpointPages = 10,
        [int] $SelfRetries = 5,
        [int] $SelfRetryWaitSeconds = 60,
        [int] $TopUsers = 500
    )

    $ErrorActionPreference = 'Stop'
    $null = Assert-PostureGraphScope -RequiredScope @('AuditLog.Read.All')
    $files = [System.Collections.Generic.List[string]]::new()
    $checkpointPath = Join-Path $Folder '.signins-checkpoint.json'
    $windowEnd = $AsOf.ToUniversalTime()
    $windowStart = $windowEnd.AddDays(-$Days)

    $state = $null
    if (Test-Path -LiteralPath $checkpointPath) {
        try { $state = Get-Content -Raw -LiteralPath $checkpointPath | ConvertFrom-Json -AsHashtable -Depth 10 } catch { $state = $null }
        # A checkpoint for another window (a different -Days) starts over.
        if ($state -and [int]$state['days'] -ne $Days) { $state = $null }
    }
    if ($state) {
        $windowStart = ConvertTo-PostureUtcDateTime $state['windowStartUtc']; $windowEnd = ConvertTo-PostureUtcDateTime $state['windowEndUtc']
        Write-Verbose "Sign-in log: continuing from the checkpoint ($($state['count']) records, $($state['pages']) pages)."
    }
    else {
        $state = @{
            days = $Days; windowStartUtc = $windowStart.ToString('o'); windowEndUtc = $windowEnd.ToString('o'); nextLink = $null; oldestUtc = $null; boundaryIds = @()
            pages = 0; count = 0; byClientApp = @{}; byCaStatus = @{}; failures = 0; interactive = 0; byDay = @{}; byCountry = @{}; risky = 0; legacy = 0; legacyUsers = @{}
            mfaRequired = 0; completed = $false; reportOnly = @{}; admins = @{}; errorCodes = @{}; failedByIp = @{}; ipCapReached = $false
        }
    }
    # Everyone who holds a role (directly, as eligible, through a group) from the Entra collector's files in this
    # folder, for the admin tallies.
    $adminSet = (Get-PostureRoleHolder -Folder $Folder).upns
    foreach ($k in 'reportOnly', 'admins', 'errorCodes', 'failedByIp', 'caByMfa', 'deviceTrust', 'legacyKeys') { if (-not $state.ContainsKey($k)) { $state[$k] = @{} } }
    foreach ($k in 'legacyCapped') { if (-not $state.ContainsKey($k)) { $state[$k] = $false } }
    # Where the question is only "how many different accounts" (per address for the spray pattern, per report-only
    # policy, legacy sign-ins in all), an account is remembered by a keyed hash, never by its name. The tallies and
    # the checkpoint on disk then hold no list of who failed to sign in from where. The key is made for this read
    # and kept in the checkpoint, so a restart counts the same account once.
    $carriedNames = -not ($state.ContainsKey('salt') -and $state['salt'])
    if ($carriedNames) { $bytes = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes); $state['salt'] = [System.Convert]::ToHexString($bytes) }
    $hasher = [System.Security.Cryptography.HMACSHA256]::new([System.Convert]::FromHexString([string]$state['salt']))
    $accountKey = { param([string] $Name) [System.Convert]::ToHexString($hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Name.ToLowerInvariant())), 0, 8) }
    if ($carriedNames) {
        # A checkpoint written before 2026-11-21 holds the names: they are replaced by their keys before anything is read.
        foreach ($ip in @($state.failedByIp.get_Keys())) { $keys = @{}; foreach ($name in @($state.failedByIp[$ip].get_Keys())) { $keys[(& $accountKey ([string]$name))] = 1 }; $state.failedByIp[$ip] = $keys }
        foreach ($id in @($state.reportOnly.get_Keys())) { $keys = @{}; foreach ($name in @($state.reportOnly[$id]['users'].get_Keys())) { $keys[(& $accountKey ([string]$name))] = 1 }; $state.reportOnly[$id]['users'] = $keys }
        foreach ($name in @($state.legacyUsers.get_Keys())) { $state.legacyKeys[(& $accountKey ([string]$name))] = 1 }
    }
    # Every tally has a ceiling: addresses, accounts per address, accounts per policy, legacy accounts listed and counted.
    $maxIps = 20000; $maxAccountsPerIp = 200; $maxPolicyUsers = 5000; $maxLegacyListed = 5000; $maxLegacyKeys = 500000
    $saveCheckpoint = { Save-PostureJsonFile -Path $checkpointPath -InputObject $state -Confirm:$false }
    $select = 'id,createdDateTime,userPrincipalName,appDisplayName,clientAppUsed,isInteractive,conditionalAccessStatus,status,authenticationRequirement,riskLevelDuringSignIn,location,ipAddress,appliedConditionalAccessPolicies,deviceDetail'
    $legacySet = [System.Collections.Generic.HashSet[string]]::new([string[]]$script:PostureLegacyClientApps, [System.StringComparer]::OrdinalIgnoreCase)
    $bump = { param([hashtable] $Map, [string] $Key) if (-not $Key) { $Key = '(none)' }; $Map[$Key] = 1 + $(if ($Map.ContainsKey($Key)) { [long]$Map[$Key] } else { 0 }) }

    # failedByIp[address], legacyUsers and each report-only policy's users are dictionaries keyed by the user name in the
    # log, which is whatever was typed at the sign-in. Their members are read through get_Count() and get_Keys():
    # .Count on a dictionary that holds an entry named Count answers with that entry.
    $onPage = {
        param($page, $info)
        $boundary = [System.Collections.Generic.HashSet[string]]::new([string[]]@($state.boundaryIds))
        $oldest = $state.oldestUtc
        # The ids at the oldest second counted so far. They carry over from page to page while that second stays the
        # oldest: more than one page can share a second, and a restart from it must skip every record already counted.
        $edge = [System.Collections.Generic.List[string]]::new([string[]]@($state.boundaryIds))
        foreach ($r in $page) {
            if ($boundary.Contains([string]$r['id'])) { continue }   # already counted before a restart at this second
            $state.count++
            # The JSON reader turns the timestamp into a DateTime; as culture text ("11/15/2026 ...") it would sort
            # wrongly across a year end and key the days by month first. ISO 8601 UTC sorts as text.
            $cd = $r['createdDateTime']
            $created = $(if ($cd -is [datetime]) { $cd.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { [string]$cd })
            if (-not $oldest -or $created -lt $oldest) { $oldest = $created; $edge.Clear() }
            if ($created -eq $oldest) { $edge.Add([string]$r['id']) }
            $app = [string]$r['clientAppUsed']
            & $bump $state.byClientApp $app
            & $bump $state.byCaStatus ([string]$r['conditionalAccessStatus'])
            if ($created.Length -ge 10) { & $bump $state.byDay $created.Substring(0, 10) }
            $loc = $r['location']; & $bump $state.byCountry $(if ($loc) { [string]$loc['countryOrRegion'] } else { '' })
            $st = $r['status']; $code = $(if ($st) { [int]$st['errorCode'] } else { 0 })
            $upn = [string]$r['userPrincipalName']
            if ($code -ne 0) {
                $state.failures++
                & $bump $state.errorCodes ([string]$code)
                # Many accounts failing from one address is the password spray pattern; tracked for bad password and lockout.
                if ($code -in 50126, 50053) {
                    $ip = [string]$r['ipAddress']
                    if ($ip -and ($state.failedByIp.ContainsKey($ip) -or $state.failedByIp.get_Count() -lt $maxIps)) {
                        if (-not $state.failedByIp.ContainsKey($ip)) { $state.failedByIp[$ip] = @{} }
                        if ($state.failedByIp[$ip].get_Count() -lt $maxAccountsPerIp) { $state.failedByIp[$ip][(& $accountKey $upn)] = 1 }
                    }
                    elseif ($ip) { $state.ipCapReached = $true }
                }
            }
            # For the report's flows, the sign-ins that got in: CA applied or not by MFA or single factor, and the
            # device they came from, managed and compliant, managed only, or unmanaged.
            if ($code -eq 0) {
                $ca = $(if ([string]$r['conditionalAccessStatus'] -in 'success', 'failure') { 'caApplied' } else { 'noCa' })
                $mfa = $(if ([string]$r['authenticationRequirement'] -eq 'multiFactorAuthentication') { 'mfa' } else { 'singleFactor' })
                & $bump $state.caByMfa "$ca|$mfa"
                $dd = $r['deviceDetail']
                & $bump $state.deviceTrust $(if ($dd -and $dd['isManaged'] -eq $true) { if ($dd['isCompliant'] -eq $true) { 'managedCompliant' } else { 'managedNoncompliant' } } else { 'unmanaged' })
            }
            # What each report-only policy would have done to this sign-in.
            foreach ($pol in @($r['appliedConditionalAccessPolicies'])) {
                if (-not $pol) { continue }
                $res = [string]$pol['result']
                if (-not $res.StartsWith('reportOnly') -or $res -eq 'reportOnlyNotApplied') { continue }
                $policyId = [string]$pol['id']
                if (-not $state.reportOnly.ContainsKey($policyId)) { $state.reportOnly[$policyId] = @{ name = [string]$pol['displayName']; wouldBlock = 0; wouldInterrupt = 0; wouldPass = 0; users = @{} } }
                $ro = $state.reportOnly[$policyId]
                switch ($res) { 'reportOnlyFailure' { $ro.wouldBlock++ } 'reportOnlyInterrupted' { $ro.wouldInterrupt++ } default { $ro.wouldPass++ } }
                if ($res -ne 'reportOnlySuccess' -and $ro.users.get_Count() -lt $maxPolicyUsers) { $ro.users[(& $accountKey $upn)] = 1 }
            }
            if ($adminSet.Contains($upn)) {
                if (-not $state.admins.ContainsKey($upn)) { $state.admins[$upn] = @{ signIns = 0; singleFactor = 0; failures = 0; last = $created } }
                $ad = $state.admins[$upn]; $ad.signIns++
                if ([string]$r['authenticationRequirement'] -eq 'singleFactorAuthentication' -and $code -eq 0) { $ad.singleFactor++ }
                if ($code -ne 0) { $ad.failures++ }
                if ($created -gt [string]$ad.last) { $ad.last = $created }
            }
            if ($r['isInteractive']) { $state.interactive++ }
            if ([string]$r['authenticationRequirement'] -eq 'multiFactorAuthentication') { $state.mfaRequired++ }
            $risk = [string]$r['riskLevelDuringSignIn']; if ($risk -and $risk -notin 'none', 'hidden', 'unknownFutureValue') { $state.risky++ }
            if ($legacySet.Contains($app)) {
                $state.legacy++
                $legacyKey = & $accountKey $upn
                if ($state.legacyKeys.ContainsKey($legacyKey) -or $state.legacyKeys.get_Count() -lt $maxLegacyKeys) { $state.legacyKeys[$legacyKey] = 1 } else { $state.legacyCapped = $true }
                if ($state.legacyUsers.ContainsKey($upn) -or $state.legacyUsers.get_Count() -lt $maxLegacyListed) {
                    if (-not $state.legacyUsers.ContainsKey($upn)) { $state.legacyUsers[$upn] = @{ count = 0; apps = @{}; last = $created } }
                    $lu = $state.legacyUsers[$upn]; $lu['count']++; & $bump $lu['apps'] $app; if ($created -gt [string]$lu['last']) { $lu['last'] = $created }
                }
            }
        }
        $state.oldestUtc = $oldest
        if ($edge.Count -gt 0) { $state.boundaryIds = @($edge) }
        $state.pages++
        $state.nextLink = $info.nextLink
        if ($script:PostureProgress) { $script:PostureProgress.label = "sign-in log: $('{0:N0}' -f $state.count) records, back to $(if ($oldest) { $oldest.Substring(0, [Math]::Min(16, $oldest.Length)) })"; Write-PostureProgress }
        if ($state.pages % $CheckpointPages -eq 0) { & $saveCheckpoint }
    }

    $attempt = 0
    while (-not $state.completed) {
        try {
            # beta: authenticationRequirement (MFA required or single factor) exists only there; v1.0 refuses it in $select (seen live 2026-11-20).
            if ($state.nextLink) { $null = Invoke-PostureGraphRequest -Uri 'auditLogs/signIns' -StartAt $state.nextLink -ApiVersion 'beta' -Label 'Sign-in log' -OnPage $onPage }
            else {
                # From the start of the window, or after a refused page link from the oldest record already counted.
                $until = $(if ($state.oldestUtc) { $state.oldestUtc } else { $windowEnd.ToString('yyyy-MM-ddTHH:mm:ssZ') })
                $filter = "createdDateTime ge $($windowStart.ToString('yyyy-MM-ddTHH:mm:ssZ')) and createdDateTime le $until"
                $null = Invoke-PostureGraphRequest -Uri "auditLogs/signIns?`$filter=$filter&`$select=$select&`$top=1000" -ApiVersion 'beta' -Label 'Sign-in log' -OnPage $onPage
            }
            $state.completed = $true
        }
        catch {
            $message = [string]$_.Exception.Message
            $attempt++
            & $saveCheckpoint
            $cause = Get-PostureFailureCause -Message $message
            $badRequest = $message -match '(?i)(BadRequest|\b400\b|\b410\b|Gone|skiptoken)'
            # Refused, unlicensed, or a query Graph rejects outright: waiting will not change the answer.
            if ($cause -in 'permission', 'licence' -or $attempt -gt $SelfRetries -or ($badRequest -and -not $state.nextLink)) { throw }
            # A page link Graph no longer accepts (400 or 410 on a skip token): query again from the oldest record counted.
            if ($state.nextLink -and $badRequest) { $state.nextLink = $null }
            Write-Warning "Sign-in log read stopped at $($state.count) records ($message); carrying on from the checkpoint in $SelfRetryWaitSeconds s (attempt $attempt of $SelfRetries)."
            if ($SelfRetryWaitSeconds -gt 0) { Start-Sleep -Seconds $SelfRetryWaitSeconds }
        }
    }

    # Results: the tallies, the legacy users (most active first, capped), and the checkpoint removed.
    $legacyRows = @($state.legacyUsers.get_Keys() | ForEach-Object { $u = $state.legacyUsers[$_]; [ordered]@{ UserPrincipalName = $_; SignIns = [long]$u['count']; ClientApps = (@($u['apps'].get_Keys() | Sort-Object { - [long]$u['apps'][$_] }) -join ';'); LastSignIn = $u['last'] } } | Sort-Object { - $_.SignIns } | Select-Object -First $TopUsers)
    $sorted = { param([hashtable] $Map) $o = [ordered]@{}; foreach ($k in @($Map.get_Keys() | Sort-Object { - [long]$Map[$_] })) { $o[$k] = [long]$Map[$k] }; $o }
    $byKey = { param([hashtable] $Map) $o = [ordered]@{}; foreach ($k in @($Map.get_Keys() | Sort-Object)) { $o[$k] = [long]$Map[$k] }; $o }
    $summary = [ordered]@{
        WindowStartUtc = $state.windowStartUtc; WindowEndUtc = $state.windowEndUtc; Days = $Days; SignIns = [long]$state.count; Interactive = [long]$state.interactive
        Failures = [long]$state.failures; MfaRequired = [long]$state.mfaRequired; Risky = [long]$state.risky
        # What these counts are counts of. auditLogs/signIns returns interactive user sign-ins unless asked otherwise:
        # non-interactive and service principal sign-ins are not in them. (verify) live, plan check 2.
        Scope = 'Interactive user sign-ins, as auditLogs/signIns returns them by default. Non-interactive and service principal sign-ins are not counted.'
        LegacySignIns = [long]$state.legacy; LegacyUsers = [Math]::Max($state.legacyKeys.get_Count(), $state.legacyUsers.get_Count()); LegacyUsersCapped = [bool]$state.legacyCapped; Pages = $state.pages
        ByClientApp = (& $sorted $state.byClientApp); ByConditionalAccessStatus = (& $sorted $state.byCaStatus)
        ByDay = (& $byKey $state.byDay)
        ByCountry = (& $sorted $state.byCountry)
        FailuresByErrorCode = (& $sorted $state.errorCodes)
        ReportOnlyPolicies = @($state.reportOnly.get_Keys() | ForEach-Object { $ro = $state.reportOnly[$_]; [ordered]@{ Id = $_; Name = $ro.name; WouldBlock = [long]$ro.wouldBlock; WouldInterrupt = [long]$ro.wouldInterrupt; WouldPass = [long]$ro.wouldPass; UsersAffected = $ro.users.get_Count() } } | Sort-Object { - ($_.WouldBlock + $_.WouldInterrupt) })
        AdminSignIns = @($state.admins.get_Keys() | ForEach-Object { $ad = $state.admins[$_]; [ordered]@{ UserPrincipalName = $_; SignIns = [long]$ad.signIns; SingleFactor = [long]$ad.singleFactor; Failures = [long]$ad.failures; LastSignIn = $ad.last } } | Sort-Object { - $_.SingleFactor }, { - $_.SignIns })
        # AccountsFailed is how many different accounts failed from the address; at the ceiling it means that many or more.
        SprayAddresses = @($state.failedByIp.get_Keys() | Where-Object { $state.failedByIp[$_].get_Count() -ge 10 } | ForEach-Object { $n = $state.failedByIp[$_].get_Count(); [ordered]@{ IpAddress = $_; AccountsFailed = $n; AccountsFailedOrMore = ($n -ge $maxAccountsPerIp) } } | Sort-Object { - $_.AccountsFailed } | Select-Object -First 50)
        SprayTrackingCapped = [bool]$state.ipCapReached
        # Successful sign-ins only. CaByMfa keys: caApplied or noCa, then mfa or singleFactor ("caApplied|mfa").
        CaByMfa = (& $byKey $state.caByMfa)
        DeviceTrust = (& $byKey $state.deviceTrust)
    }
    $files.Add((Write-PostureEvidence -Folder $Folder -Name '06-signins-summary' -InputObject $summary))
    $files.Add((Write-PostureEvidence -Folder $Folder -Name '06-signins-legacy-users' -InputObject $legacyRows -AsArray -Csv))
    if (Test-Path -LiteralPath $checkpointPath) { Remove-Item -LiteralPath $checkpointPath -Force }
    $hasher.Dispose()
    return @{ files = $files.ToArray() }
}
