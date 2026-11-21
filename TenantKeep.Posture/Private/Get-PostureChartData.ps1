# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureChartData {
    <#
    .SYNOPSIS
        The numbers behind the report's charts, each with a one-line takeaway: header tiles, users by method
        strength (all and administrators), sign-ins through Conditional Access to MFA, sign-ins by device trust,
        managed devices by platform, join type and compliance, and the compliance, ownership and antivirus mixes.
    .DESCRIPTION
        Counts only, never names. Read from summaries where the collectors write them; the managed device list is
        the one row-level file, and the evidence cache shares it with the device checks. A chart whose evidence was
        not collected is left out rather than drawn empty.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [object[]] $Admin = @(),
        [System.Collections.IDictionary] $DomainFacts = @{}
    )

    $ErrorActionPreference = 'Stop'
    $load = { param([string] $Name) Read-PostureEvidenceFile -Folder $Evidence -Name $Name }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $num = { param($x) [double]$(if ($null -eq $x) { 0 } else { $x }) }
    $pct = { param([double] $n, [double] $d) if ($d -le 0) { 0 } else { [int][Math]::Round(100 * $n / $d) } }
    $fmt = { param($x) Format-PostureChartNumber ([double]$x) }
    $out = [ordered]@{}

    # Header tiles.
    $tiles = [System.Collections.Generic.List[object]]::new()
    $users = & $load '06-users-summary'
    if ($users) { $tiles.Add([ordered]@{ label = 'Members'; value = (& $num (& $v $users 'Members')); sub = "$(& $fmt (& $num (& $v $users 'Guests'))) guests" }) }
    $groups = & $load '07-groups'
    if ($null -ne $groups) { $tiles.Add([ordered]@{ label = 'Groups'; value = [double]@($groups | Where-Object { $_ }).Count; sub = '' }) }
    $apps = & $load '10-app-registrations'
    if ($null -ne $apps) { $tiles.Add([ordered]@{ label = 'App registrations'; value = [double]@($apps | Where-Object { $_ }).Count; sub = '' }) }
    $joinOs = & $load '08-entra-devices-by-join-os'
    if ($null -ne $joinOs) { $tiles.Add([ordered]@{ label = 'Entra devices'; value = [double](@($joinOs | Where-Object { $_ } | ForEach-Object { & $num (& $v $_ 'Count') }) | Measure-Object -Sum).Sum; sub = '' }) }
    $managed = & $load '09-intune-managed-devices'
    $managedRows = @($managed | Where-Object { $_ })
    if ($null -ne $managed) {
        $compliant = @($managedRows | Where-Object { [string](& $v $_ 'ComplianceState') -eq 'compliant' }).Count
        $tiles.Add([ordered]@{ label = 'Managed devices'; value = [double]$managedRows.Count; sub = "$(& $pct $compliant $managedRows.Count)% compliant" })
    }
    $signins = & $load '06-signins-summary'
    if ($signins) { $tiles.Add([ordered]@{ label = 'Sign-ins read'; value = (& $num (& $v $signins 'SignIns')); sub = "last $(& $v $signins 'Days') days" }) }
    $out.tiles = @($tiles)

    # Users by their strongest registered method.
    $reg = & $load '05-auth-registration-summary'
    $sm = $(if ($reg) { & $v $reg 'StrongestMethod' } else { $null })
    if ($sm) {
        $pr = & $num (& $v $sm 'PhishingResistant'); $pl = & $num (& $v $sm 'Passwordless'); $au = & $num (& $v $sm 'Authenticator'); $ph = & $num (& $v $sm 'PhoneOnly'); $no = & $num (& $v $sm 'None')
        $all = $pr + $pl + $au + $ph + $no
        if ($all -gt 0) {
            $out.authUsers = [ordered]@{
                column   = @(, @(@{ id = 'all'; label = 'Members'; tone = 'c1' }), @(@{ id = 'pr'; label = 'Phishing-resistant'; tone = 'ok' }, @{ id = 'ph'; label = 'Phishable'; tone = 'warn' }, @{ id = 'no'; label = 'No MFA'; tone = 'err' }), @(@{ id = 'm-pr'; label = 'Passkey, key or Windows Hello'; tone = 'ok' }, @{ id = 'm-pl'; label = 'Authenticator phone sign-in'; tone = 'warn' }, @{ id = 'm-au'; label = 'Authenticator push or code'; tone = 'warn' }, @{ id = 'm-ph'; label = 'Phone (SMS or call)'; tone = 'warn' }, @{ id = 'm-no'; label = 'Nothing registered'; tone = 'err' }))
                flow     = @(@{ from = 'all'; to = 'pr'; value = $pr }, @{ from = 'all'; to = 'ph'; value = $pl + $au + $ph }, @{ from = 'all'; to = 'no'; value = $no }, @{ from = 'pr'; to = 'm-pr'; value = $pr }, @{ from = 'ph'; to = 'm-pl'; value = $pl }, @{ from = 'ph'; to = 'm-au'; value = $au }, @{ from = 'ph'; to = 'm-ph'; value = $ph }, @{ from = 'no'; to = 'm-no'; value = $no })
                takeaway = "$(& $pct $pr $all)% of the $(& $fmt $all) members in the registration report have a phishing-resistant method; $(& $pct $no $all)% have no MFA method at all."
            }
        }
    }
    # Administrators by their strongest method, from the report's admin table.
    $people = @($Admin | Where-Object { $_ -and [string]$_.type -eq 'user' })
    if ($people.Count -gt 0) {
        $bucket = { param([string] $m) switch ($m) { 'Phishing-resistant' { 'pr' } 'Windows Hello for Business' { 'pr' } 'Synced passkey' { 'sy' } 'None' { 'no' } 'Unknown' { 'un' } default { 'ph' } } }
        $count = @{ pr = 0; sy = 0; ph = 0; no = 0; un = 0 }
        foreach ($p in $people) { $count[(& $bucket ([string]$p.strongestMethod))]++ }
        $out.authAdmins = [ordered]@{
            segment  = @(@{ label = 'Device-bound phishing-resistant'; value = $count.pr; tone = 'ok' }, @{ label = 'Synced passkey only'; value = $count.sy; tone = 'c1' }, @{ label = 'Phishable'; value = $count.ph; tone = 'warn' }, @{ label = 'No MFA method'; value = $count.no; tone = 'err' }, @{ label = 'Not known'; value = $count.un; tone = 'na' })
            takeaway = "$($count.pr) of $($people.Count) administrators have a device-bound phishing-resistant method$(if ($count.sy) { "; $($count.sy) more $(if ($count.sy -eq 1) { 'has' } else { 'have' }) only a synced passkey" })."
        }
    }

    # Sign-ins that got in: through Conditional Access or not, then MFA or single factor.
    $caTally = $(if ($signins) { & $v $signins 'CaByMfa' } else { $null })
    if ($caTally -and @($caTally.Keys).Count -gt 0) {
        $c = { param([string] $k) & $num $caTally[$k] }
        $inCaMfa = & $c 'caApplied|mfa'; $inCaSingle = & $c 'caApplied|singleFactor'; $noCaMfa = & $c 'noCa|mfa'; $noCaSingle = & $c 'noCa|singleFactor'
        $tot = $inCaMfa + $inCaSingle + $noCaMfa + $noCaSingle
        $out.signInCa = [ordered]@{
            column   = @(, @(@{ id = 's'; label = 'Sign-ins'; tone = 'c1' }), @(@{ id = 'ca'; label = 'Conditional Access applied'; tone = 'c3' }, @{ id = 'noca'; label = 'No policy applied'; tone = 'na' }), @(@{ id = 'mfa'; label = 'MFA'; tone = 'ok' }, @{ id = 'sf'; label = 'Single factor'; tone = 'err' }))
            flow     = @(@{ from = 's'; to = 'ca'; value = $inCaMfa + $inCaSingle }, @{ from = 's'; to = 'noca'; value = $noCaMfa + $noCaSingle }, @{ from = 'ca'; to = 'mfa'; value = $inCaMfa }, @{ from = 'ca'; to = 'sf'; value = $inCaSingle }, @{ from = 'noca'; to = 'mfa'; value = $noCaMfa }, @{ from = 'noca'; to = 'sf'; value = $noCaSingle })
            takeaway = "Over the last $(& $v $signins 'Days') days, $(& $pct $inCaMfa $tot)% of successful sign-ins went through Conditional Access with MFA; $(& $pct $noCaSingle $tot)% had neither."
        }
    }
    $dt = $(if ($signins) { & $v $signins 'DeviceTrust' } else { $null })
    if ($dt -and @($dt.Keys).Count -gt 0) {
        $mc = & $num $dt['managedCompliant']; $mn = & $num $dt['managedNoncompliant']; $un = & $num $dt['unmanaged']; $tot = $mc + $mn + $un
        $out.signInDevice = [ordered]@{
            column   = @(, @(@{ id = 's'; label = 'Sign-ins'; tone = 'c1' }), @(@{ id = 'm'; label = 'Managed device'; tone = 'c3' }, @{ id = 'u'; label = 'Unmanaged device'; tone = 'na' }), @(@{ id = 'mc'; label = 'Compliant'; tone = 'ok' }, @{ id = 'mn'; label = 'Not compliant'; tone = 'err' }, @{ id = 'uu'; label = 'Unknown device'; tone = 'na' }))
            flow     = @(@{ from = 's'; to = 'm'; value = $mc + $mn }, @{ from = 's'; to = 'u'; value = $un }, @{ from = 'm'; to = 'mc'; value = $mc }, @{ from = 'm'; to = 'mn'; value = $mn }, @{ from = 'u'; to = 'uu'; value = $un })
            takeaway = "$(& $pct $mc $tot)% of successful sign-ins came from a managed, compliant device; $(& $pct $un $tot)% from a device the organisation does not manage."
        }
    }

    # Managed devices: platform, then join type, then compliance.
    if ($managedRows.Count -gt 0) {
        $joinLabel = @{ azureADJoined = 'Entra joined'; hybridAzureADJoined = 'Hybrid joined'; azureADRegistered = 'Registered (personal)' }
        $compLabel = @{ compliant = 'Compliant'; noncompliant = 'Not compliant' }
        $plat = [ordered]@{}; $pj = @{}; $jc = @{}; $joins = [ordered]@{}; $comps = [ordered]@{}
        foreach ($d in $managedRows) {
            $os = [string](& $v $d 'OperatingSystem'); if (-not $os) { $os = 'Other' }
            $j = [string](& $v $d 'JoinType'); $j = $(if ($joinLabel.ContainsKey($j)) { $joinLabel[$j] } else { 'Join type not reported' })
            $cs = [string](& $v $d 'ComplianceState'); $cs = $(if ($compLabel.ContainsKey($cs)) { $compLabel[$cs] } else { 'Unknown or in grace' })
            $plat[$os] = 1 + $(if ($plat.Contains($os)) { $plat[$os] } else { 0 }); $joins[$j] = $true; $comps[$cs] = $true
            $pj["$os|$j"] = 1 + $(if ($pj.ContainsKey("$os|$j")) { $pj["$os|$j"] } else { 0 })
            $jc["$j|$cs"] = 1 + $(if ($jc.ContainsKey("$j|$cs")) { $jc["$j|$cs"] } else { 0 })
        }
        # Five platforms at most, each with its own fixed slot; the rest fold into Other.
        $slot = @{ Windows = 'c1'; macOS = 'c2'; iOS = 'c3'; Android = 'c4'; Linux = 'c5' }
        $platNodes = @($plat.Keys | Sort-Object { - $plat[$_] } | ForEach-Object { @{ id = "p-$_"; label = $_; tone = $(if ($slot.ContainsKey($_)) { $slot[$_] } else { 'na' }) } })
        $compTone = @{ 'Compliant' = 'ok'; 'Not compliant' = 'err'; 'Unknown or in grace' = 'na' }
        $flows = @(@($pj.Keys | ForEach-Object { $a, $b = $_ -split '\|', 2; @{ from = "p-$a"; to = "j-$b"; value = $pj[$_] } }) + @($jc.Keys | ForEach-Object { $a, $b = $_ -split '\|', 2; @{ from = "j-$a"; to = "c-$b"; value = $jc[$_] } }))
        $nComp = @($managedRows | Where-Object { [string](& $v $_ 'ComplianceState') -eq 'compliant' }).Count
        $out.devices = [ordered]@{
            column   = @($platNodes, @($joins.Keys | ForEach-Object { @{ id = "j-$_"; label = $_; tone = 'c1' } }), @($comps.Keys | ForEach-Object { @{ id = "c-$_"; label = $_; tone = $compTone[$_] } }))
            flow     = $flows
            takeaway = "$(& $pct $nComp $managedRows.Count)% of $(& $fmt $managedRows.Count) managed devices are compliant."
        }
        $own = @{ company = 0; personal = 0; other = 0 }
        foreach ($d in $managedRows) { $o = [string](& $v $d 'ManagedDeviceOwnerType'); if ($own.ContainsKey($o)) { $own[$o]++ } else { $own.other++ } }
        $out.ownership = [ordered]@{
            segment  = @(@{ label = 'Corporate'; value = $own.company; tone = 'c1' }, @{ label = 'Personal'; value = $own.personal; tone = 'c2' }, @{ label = 'Not reported'; value = $own.other; tone = 'na' })
            takeaway = "$(& $pct $own.personal $managedRows.Count)% of managed devices are personally owned."
        }
    }
    $comp = & $load '09-intune-summary-compliance'
    if ($null -ne $comp -and @($comp | Where-Object { $_ }).Count -gt 0) {
        $t = @{ Compliant = 0; Noncompliant = 0; Other = 0 }
        foreach ($r in @($comp | Where-Object { $_ })) { $st = @(([string](& $v $r 'Name')) -split ',\s*', 2)[-1]; $k = $(switch ($st) { 'compliant' { 'Compliant' } 'noncompliant' { 'Noncompliant' } default { 'Other' } }); $t[$k] += [int](& $v $r 'Count') }
        $all = $t.Compliant + $t.Noncompliant + $t.Other
        $out.compliance = [ordered]@{
            segment  = @(@{ label = 'Compliant'; value = $t.Compliant; tone = 'ok' }, @{ label = 'Not compliant'; value = $t.Noncompliant; tone = 'err' }, @{ label = 'Unknown or in grace'; value = $t.Other; tone = 'na' })
            takeaway = "$(& $pct $t.Compliant $all)% of devices are compliant; $($t.Noncompliant) $(if ($t.Noncompliant -eq 1) { 'is' } else { 'are' }) not."
        }
    }
    # Defender Antivirus mode from advanced hunting: 0 active, 1 passive, 4 EDR in block mode (verify the codes).
    $av = & $load 'def-02-av-state-summary'
    $modes = @(if ($av) { @(& $v $av 'ByMode' | Where-Object { $_ }) })
    if ($modes.Count -gt 0) {
        $t = @{ active = 0; passive = 0; other = 0 }
        foreach ($m in $modes) { $code = [string](& $v $m 'Name'); $n = [int](& $v $m 'Count'); switch ($code) { '0' { $t.active += $n } '1' { $t.passive += $n } default { $t.other += $n } } }
        $all = $t.active + $t.passive + $t.other
        $out.antivirus = [ordered]@{
            segment  = @(@{ label = 'Active'; value = $t.active; tone = 'ok' }, @{ label = 'Passive'; value = $t.passive; tone = 'warn' }, @{ label = 'Other or off'; value = $t.other; tone = 'err' })
            takeaway = "Defender Antivirus is active on $(& $pct $t.active $all)% of onboarded devices."
        }
    }
    # Detail charts for the Domains view: counts only, each left out when its evidence is missing.
    $topOf = { param($map, [int] $n) @(@($map.Keys) | Sort-Object { - [double]$map[$_] } | Select-Object -First $n | ForEach-Object { [ordered]@{ label = [string]$_; value = [double]$map[$_] } }) }
    $toDay = { param($k) $d = [datetime]::MinValue; foreach ($f in 'yyyy-MM-dd', 'M/d/yyyy', 'MM/dd/yyyy') { if ([datetime]::TryParseExact([string]$k, $f, [cultureinfo]::InvariantCulture, 'None', [ref]$d)) { return $d } }; $null }
    if ($signins) {
        $byDay = & $v $signins 'ByDay'
        if ($byDay -and @($byDay.Keys).Count -ge 2) {
            $seen = @{}; foreach ($k in @($byDay.Keys)) { $d = & $toDay $k; if ($d) { $seen[$d.ToString('yyyy-MM-dd')] = [double]$byDay[$k] } }
            # Every day in the window, with zero where nobody signed in, so the line does not skip quiet days.
            $days = @($seen.Keys | Sort-Object)
            $pts = @(if ($days.Count) { for ($d = [datetime]::ParseExact($days[0], 'yyyy-MM-dd', [cultureinfo]::InvariantCulture); $d -le [datetime]::ParseExact($days[-1], 'yyyy-MM-dd', [cultureinfo]::InvariantCulture); $d = $d.AddDays(1)) { $key = $d.ToString('yyyy-MM-dd'); [ordered]@{ day = $d; label = $d.ToString('MM-dd'); value = $(if ($seen.ContainsKey($key)) { $seen[$key] } else { 0 }) } } })
            $peak = @($pts | Sort-Object { - $_.value })[0]
            $out.signInsByDay = [ordered]@{ point = @($pts | ForEach-Object { [ordered]@{ label = $_.label; value = $_.value } }); takeaway = "Busiest day $($peak.label) with $(& $fmt $peak.value) sign-ins." }
        }
        $byCountry = & $v $signins 'ByCountry'
        if ($byCountry -and @($byCountry.Keys).Count) { $top = @(& $topOf $byCountry 10); $out.signInCountries = [ordered]@{ item = $top; takeaway = "$(@($byCountry.Keys).Count) countr$(if (@($byCountry.Keys).Count -eq 1) { 'y' } else { 'ies' }); most sign-ins from $($top[0].label)." } }
        $codes = & $v $signins 'FailuresByErrorCode'
        if ($codes -and @($codes.Keys).Count) {
            # The codes people meet most, in words (Entra sign-in error codes).
            $meaning = @{ '50126' = 'wrong password'; '50053' = 'account locked'; '50074' = 'MFA required'; '50076' = 'MFA required'; '500121' = 'MFA not completed'; '50140' = 'stay signed in prompt'; '65001' = 'consent needed'; '53003' = 'blocked by Conditional Access'; '50158' = 'external challenge'; '50057' = 'account disabled'; '50055' = 'password expired'; '530032' = 'blocked by security defaults' }
            $out.signInFailures = [ordered]@{ item = @(& $topOf $codes 10 | ForEach-Object { [ordered]@{ label = "$($_.label)$(if ($meaning.ContainsKey($_.label)) { " $($meaning[$_.label])" })"; value = $_.value; tone = 'err' } }); takeaway = "$(& $fmt (& $num (& $v $signins 'Failures'))) failed sign-ins; the commonest error is $(@(& $topOf $codes 1)[0].label)." }
        }
    }
    $builds = & $load '09-intune-summary-windows-builds'
    if ($null -ne $builds -and @($builds | Where-Object { $_ }).Count) {
        $bmap = @{}; foreach ($b in @($builds | Where-Object { $_ })) { $bmap[[string](& $v $b 'Name')] = [double](& $v $b 'Count') }
        $out.windowsBuilds = [ordered]@{ item = @(& $topOf $bmap 8); takeaway = "$(@($bmap.Keys).Count) Windows build$(if (@($bmap.Keys).Count -ne 1) { 's' }) in the fleet." }
    }
    if ($managedRows.Count) {
        $enc = @($managedRows | Where-Object { (& $v $_ 'IsEncrypted') -eq $true }).Count
        $out.encryption = [ordered]@{ segment = @(@{ label = 'Encrypted'; value = $enc; tone = 'ok' }, @{ label = 'Not encrypted'; value = $managedRows.Count - $enc; tone = 'err' }); takeaway = "$(& $pct $enc $managedRows.Count)% of managed devices report encryption." }
        $age = [ordered]@{ 'Last 7 days' = 0; '8 to 30 days' = 0; '31 to 90 days' = 0; 'Over 90 days' = 0 }
        foreach ($d in $managedRows) {
            $ls = & $v $d 'LastSyncDateTime'; $t = $(if ($ls -is [datetime]) { $ls } else { $p = [datetime]::MinValue; if ([datetime]::TryParse([string]$ls, [cultureinfo]::InvariantCulture, 'AdjustToUniversal', [ref]$p)) { $p } else { $null } })
            if (-not $t) { continue }
            $days = ([datetime]::UtcNow - $t.ToUniversalTime()).TotalDays
            $age[$(if ($days -le 7) { 'Last 7 days' } elseif ($days -le 30) { '8 to 30 days' } elseif ($days -le 90) { '31 to 90 days' } else { 'Over 90 days' })]++
        }
        $out.checkIn = [ordered]@{ item = @($age.Keys | ForEach-Object { [ordered]@{ label = $_; value = $age[$_]; tone = $(if ($_ -eq 'Over 90 days') { 'err' } elseif ($_ -eq '31 to 90 days') { 'warn' } else { 'c1' }) } }); takeaway = "$($age['Over 90 days'] + $age['31 to 90 days']) managed device(s) have not checked in for a month or more." }
    }
    # Microsoft Secure Score: where the points are by category, and the actions worth most (Microsoft's links).
    $controls = & $load 'def-06-secure-score-controls'
    if ($null -ne $controls) {
        $live = @(@($controls) | Where-Object { $_ -and [string](& $v $_ 'State') -notin 'Ignored', 'ThirdParty' -and $null -ne (& $v $_ 'Score') -and [double](& $v $_ 'MaxScore') -gt 0 })
        if ($live.Count) {
            $cats = [ordered]@{}
            foreach ($c in $live) { $k = [string](& $v $c 'Category'); if (-not $cats.Contains($k)) { $cats[$k] = @{ earned = 0.0; max = 0.0 } }; $cats[$k].earned += [double](& $v $c 'Score'); $cats[$k].max += [double](& $v $c 'MaxScore') }
            $out.secureScoreCategories = [ordered]@{ rows = @($cats.Keys | ForEach-Object { [ordered]@{ label = $_; earned = [Math]::Round($cats[$_].earned, 1); available = [Math]::Round($cats[$_].max - $cats[$_].earned, 1) } }); takeaway = 'Points earned and still available, per Secure Score category.' }
            $top = @($live | Sort-Object { - ([double](& $v $_ 'MaxScore') - [double](& $v $_ 'Score')) }, { [string](& $v $_ 'Title') } | Where-Object { ([double](& $v $_ 'MaxScore') - [double](& $v $_ 'Score')) -gt 0 } | Select-Object -First 10)
            $out.secureScoreActions = [ordered]@{
                rows = @($top | ForEach-Object { [ordered]@{ title = [string](& $v $_ 'Title'); category = [string](& $v $_ 'Category'); points = [Math]::Round([double](& $v $_ 'MaxScore') - [double](& $v $_ 'Score'), 1); cost = [string](& $v $_ 'ImplementationCost'); userImpact = [string](& $v $_ 'UserImpact'); url = [string](& $v $_ 'ActionUrl') } })
                takeaway = "The $(@($top).Count) improvement actions worth the most points, as Microsoft scores them."
            }
        }
    }
    # Defender for Cloud: secure score per subscription and open recommendations (the Azure collector).
    $azScores = & $load 'az-02-secure-scores'
    if ($null -ne $azScores -and @($azScores | Where-Object { $_ }).Count) {
        $names = @{}; foreach ($sx in @(& $load 'az-01-subscriptions') | Where-Object { $_ }) { $names[[string](& $v $sx 'SubscriptionId')] = [string](& $v $sx 'Name') }
        $out.azureSecureScore = [ordered]@{
            item     = @(@($azScores) | Where-Object { $_ } | ForEach-Object { $p = [double](& $v $_ 'Percentage'); if ($p -le 1) { $p = $p * 100 }; $sid = [string](& $v $_ 'SubscriptionId'); [ordered]@{ label = $(if ($names.ContainsKey($sid)) { $names[$sid] } else { $sid }); value = [Math]::Round($p); tone = 'c1' } })
            takeaway = 'Defender for Cloud secure score per subscription.'
        }
    }
    $azSummary = & $load 'az-02-assessments-summary'
    if ($null -ne $azSummary) {
        $sev = [ordered]@{ High = 0; Medium = 0; Low = 0 }
        foreach ($r in @($azSummary) | Where-Object { $_ -and [string](& $v $_ 'Status') -eq 'Unhealthy' }) { $k = [string](& $v $r 'Severity'); if ($sev.Contains($k)) { $sev[$k] += [int](& $v $r 'Count') } }
        $out.azureRecommendations = [ordered]@{ segment = @(@{ label = 'High'; value = $sev.High; tone = 'err' }, @{ label = 'Medium'; value = $sev.Medium; tone = 'warn' }, @{ label = 'Low'; value = $sev.Low; tone = 'c1' }); takeaway = "$($sev.High) high-severity recommendation(s) open in Defender for Cloud." }
    }
    $azTop = & $load 'az-02-assessments-top'
    if ($null -ne $azTop -and @($azTop | Where-Object { $_ }).Count) { $out.azureTopRecommendations = [ordered]@{ rows = @(@($azTop) | Where-Object { $_ } | Select-Object -First 10 | ForEach-Object { [ordered]@{ title = [string](& $v $_ 'Recommendation'); severity = [string](& $v $_ 'Severity'); affected = [int](& $v $_ 'Affected') } }) } }

    # Global Secure Access: which traffic goes through it (NET-001 to NET-004).
    $nw = $(if ($DomainFacts.Contains('network')) { $DomainFacts['network'] } else { $null })
    if ($nw -and ($nw.Contains('microsoftProfileEnabled') -or $nw.Contains('internetProfileEnabled') -or $nw.Contains('privateProfileEnabled'))) {
        $flag = { param([string] $k) $nw.Contains($k) -and [bool]$nw[$k] }
        $out.networkProfiles = [ordered]@{
            rows     = @(
                [ordered]@{ label = 'Microsoft 365 traffic'; on = (& $flag 'microsoftProfileEnabled'); detail = 'compliant network check and tenant restrictions' }
                [ordered]@{ label = 'Internet traffic'; on = (& $flag 'internetProfileEnabled'); detail = "$(if ($nw.Contains('webFilteringPolicies')) { [int]$nw['webFilteringPolicies'] } else { 0 }) web filtering policy(ies)" }
                [ordered]@{ label = 'Private apps'; on = (& $flag 'privateProfileEnabled'); detail = 'Private Access in place of a VPN' }
                [ordered]@{ label = 'Original source address'; on = (& $flag 'signalingEnabled'); detail = 'Conditional Access sees the real IP' }
            )
            takeaway = "$(@('microsoftProfileEnabled', 'internetProfileEnabled', 'privateProfileEnabled' | Where-Object { & $flag $_ }).Count) of 3 traffic profiles are forwarding through Global Secure Access."
        }
    }
    # Hybrid identity: privileged group sizes, key ages and the AD weaknesses attackers look for first.
    $hy2 = $(if ($DomainFacts.Contains('hybrid')) { $DomainFacts['hybrid'] } else { $null })
    $priv = & $load 'ad-03-privileged-groups'
    if ($null -ne $priv -and @($priv | Where-Object { $_ }).Count) {
        $byGroup = [ordered]@{}; foreach ($r in @($priv) | Where-Object { $_ }) { $g = [string](& $v $r 'Group'); $byGroup[$g] = 1 + $(if ($byGroup.Contains($g)) { $byGroup[$g] } else { 0 }) }
        $out.privilegedGroups = [ordered]@{ item = @($byGroup.Keys | ForEach-Object { [ordered]@{ label = $_; value = $byGroup[$_]; tone = 'c1' } } | Sort-Object { - $_.value }); takeaway = "Members of AD's privileged groups, counted through nested groups." }
    }
    if ($hy2 -and $hy2.Contains('krbtgtPasswordAgeDays')) {
        $ages = @([ordered]@{ label = 'krbtgt password'; value = [int]$hy2['krbtgtPasswordAgeDays']; tone = $(if ([int]$hy2['krbtgtPasswordAgeDays'] -gt 180) { 'err' } else { 'ok' }) })
        if ($hy2.Contains('seamlessSsoKeyAgeDays') -and $null -ne $hy2['seamlessSsoKeyAgeDays']) { $ages += [ordered]@{ label = 'Seamless SSO key'; value = [int]$hy2['seamlessSsoKeyAgeDays']; tone = $(if ([int]$hy2['seamlessSsoKeyAgeDays'] -gt 30) { 'err' } else { 'ok' }) } }
        $out.keyAges = [ordered]@{ item = $ages; takeaway = 'Days since each key was last changed; red when older than the check allows.' }
        $risk = { param([string] $label, [string] $k, [string] $why) if ($hy2.Contains($k) -and $null -ne $hy2[$k]) { [ordered]@{ label = $label; value = [int]$hy2[$k]; detail = $why } } }
        $out.adExposure = [ordered]@{
            rows     = @(
                & $risk 'Kerberoastable accounts' 'kerberoastableAccounts' 'service tickets crackable offline'
                & $risk 'AS-REP roastable accounts' 'asrepRoastableAccounts' 'no pre-authentication'
                & $risk 'Unconstrained delegation' 'unconstrainedDelegationNonDc' 'computers that can impersonate anyone'
                & $risk 'GPOs holding passwords' 'gposWithCpassword' 'readable by every user'
                & $risk 'Stale enabled users' 'staleEnabledUsers' 'accounts nobody watches'
                & $risk 'Operator group members' 'operatorGroupMembers' 'backup and server operators'
            ) | Where-Object { $_ }
            takeaway = 'What attackers look for first in Active Directory; anything above zero is worth a look.'
        }
    }

    # Who manages the Windows fleet, and how far co-management has gone (DEV-019 to DEV-021).
    $dv = $(if ($DomainFacts.Contains('devices')) { $DomainFacts['devices'] } else { $null })
    if ($dv -and $dv.Contains('windowsIntuneOnly')) {
        $adOnly = $(if ($dv.Contains('adOnlyWindowsDevices')) { [int]$dv['adOnlyWindowsDevices'] } else { 0 })
        $seg = @(
            @{ label = 'Intune alone'; value = [int]$dv['windowsIntuneOnly']; tone = 'c1' }
            @{ label = 'Co-managed with Configuration Manager'; value = [int]$dv['windowsCoManaged']; tone = 'c2' }
            @{ label = 'Configuration Manager alone'; value = [int]$dv['windowsConfigMgrOnly']; tone = 'c3' }
            @{ label = 'Group Policy only (no cloud management)'; value = $adOnly; tone = 'c4' }
            @{ label = 'Defender security settings only'; value = [int]$dv['windowsSecuritySettingsOnly']; tone = 'c5' }
        )
        $total = [int](($seg | ForEach-Object { $_.value } | Measure-Object -Sum).Sum)
        if ($total -gt 0) {
            $cloud = [int]$dv['windowsIntuneOnly'] + [int]$dv['windowsCoManaged']
            $out.deviceManagement = [ordered]@{ segment = $seg; takeaway = "$(& $pct $cloud $total)% of $(& $fmt $total) Windows devices are managed by Intune, alone or with Configuration Manager." }
        }
        if ($dv.Contains('coManagementWorkloads') -and [int]$(if ($dv.Contains('coManagedDevices')) { $dv['coManagedDevices'] } else { 0 }) -gt 0) {
            $n = [int]$dv['coManagedDevices']
            $label = @{ compliancePolicy = 'Compliance policies'; deviceConfiguration = 'Device configuration'; windowsUpdateForBusiness = 'Windows Update policies'; endpointProtection = 'Endpoint protection'; resourceAccess = 'Resource access'; modernApps = 'Client apps'; officeApps = 'Office Click-to-Run'; inventory = 'Inventory' }
            $out.coManagement = [ordered]@{
                devices  = $n
                rows     = @(@($dv['coManagementWorkloads']) | Where-Object { $label.ContainsKey([string]$_['name']) } | ForEach-Object { [ordered]@{ label = $label[[string]$_['name']]; onIntune = [int]$_['onIntune']; onConfigMgr = [Math]::Max(0, $n - [int]$_['onIntune']) } })
                takeaway = "Workloads moved to Intune across $(& $fmt $n) co-managed devices."
            }
        }
    }
    # Where users and groups are managed: AD, Entra after leaving AD, or created in Entra (HY-032, HY-033).
    $hy = $(if ($DomainFacts.Contains('hybrid')) { $DomainFacts['hybrid'] } else { $null })
    # Only where something comes from AD: a cloud-only tenant has nothing to show here.
    $fromAdCount = 0; foreach ($k in 'syncedUsers', 'syncedGroups', 'usersManagedInEntraFromAd', 'groupsManagedInEntraFromAd') { if ($hy -and $hy.Contains($k)) { $fromAdCount += [int]$hy[$k] } }
    if ($hy -and $fromAdCount -gt 0) {
        $rowsOut = [System.Collections.Generic.List[object]]::new()
        if ($hy.Contains('syncedUsers')) {
            $fromAd = [int]$hy['usersManagedInEntraFromAd']
            $rowsOut.Add([ordered]@{ label = 'Users'; segment = @(@{ label = 'Managed in AD'; value = [int]$hy['syncedUsers']; tone = 'c3' }, @{ label = 'Moved from AD to Entra'; value = $fromAd; tone = 'c2' }, @{ label = 'Created in Entra'; value = [Math]::Max(0, [int]$hy['cloudOnlyMembers'] - $fromAd); tone = 'c1' }) })
        }
        if ($hy.Contains('syncedGroups') -and $hy.Contains('groupsManagedInEntraFromAd')) {
            $rowsOut.Add([ordered]@{ label = 'Groups that came from AD'; segment = @(@{ label = 'Managed in AD'; value = [int]$hy['syncedGroups']; tone = 'c3' }, @{ label = 'Moved from AD to Entra'; value = [int]$hy['groupsManagedInEntraFromAd']; tone = 'c2' }) })
        }
        $inAd = $(if ($hy.Contains('syncedGroups')) { [int]$hy['syncedGroups'] } else { 0 })
        $out.identitySource = [ordered]@{ rows = @($rowsOut); takeaway = $(if ($hy.Contains('syncedAccessGroups') -and [int]$hy['syncedAccessGroups'] -gt 0) { "$($hy['syncedAccessGroups']) group(s) still managed in AD decide cloud access." } else { "$inAd group(s) are still managed in AD." }) }
    }
    # Macs a partner MDM manages, as Entra sees them (DEV-022, DEV-023).
    if ($dv -and $dv.Contains('macPartnerExpected') -and $dv['macPartnerExpected'] -and $dv.Contains('macsInEntra') -and [int]$dv['macsInEntra'] -gt 0) {
        $okMacs = [int]$dv['macsCompliantInEntra']; $allMacs = [int]$dv['macsInEntra']
        $who = $(if (@($dv['macPartners']).Count) { @($dv['macPartners']) -join ', ' } else { 'the Mac MDM' })
        $out.macCompliance = [ordered]@{
            segment  = @(@{ label = 'Compliant'; value = $okMacs; tone = 'ok' }, @{ label = 'Not compliant or not reported'; value = ($allMacs - $okMacs); tone = 'err' })
            takeaway = "$okMacs of $allMacs Macs in use are compliant in Entra, as reported by $who."
        }
    }
    $ep = $(if ($DomainFacts.Contains('endpoint')) { $DomainFacts['endpoint'] } else { $null })
    if ($ep -and $ep.Contains('asrRulesBlock')) {
        $out.asr = [ordered]@{ segment = @(@{ label = 'Block'; value = [int]$ep['asrRulesBlock']; tone = 'ok' }, @{ label = 'Audit'; value = [int]$ep['asrRulesAudit']; tone = 'warn' }, @{ label = 'Off'; value = [int]$ep['asrRulesOff']; tone = 'err' }, @{ label = 'Not configured'; value = [int]$ep['asrRulesNotConfigured']; tone = 'na' }); takeaway = "$([int]$ep['asrRulesBlock']) attack surface reduction rules block; $([int]$ep['asrRulesAudit'] + [int]$ep['asrRulesOff'] + [int]$ep['asrRulesNotConfigured']) do not." }
    }
    $vul = & $load 'def-04-vulnerabilities-summary'
    if ($vul) { $out.vulnerabilities = [ordered]@{ item = @([ordered]@{ label = 'Critical CVEs open'; value = (& $num (& $v $vul 'CriticalCves')); tone = 'err' }, [ordered]@{ label = 'Open over 30 days'; value = (& $num (& $v $vul 'CriticalCvesOver30d')); tone = 'err' }, [ordered]@{ label = 'Devices affected'; value = (& $num (& $v $vul 'DevicesWithCriticalCves')); tone = 'warn' }); takeaway = "$(& $fmt (& $num (& $v $vul 'CriticalCvesOver30d'))) critical vulnerabilities have been open for more than 30 days." } }
    $ss = & $load 'def-06-secure-score'
    if ($ss -and (& $num (& $v $ss 'MaxScore')) -gt 0) {
        $mine = [Math]::Round(100 * (& $num (& $v $ss 'CurrentScore')) / (& $num (& $v $ss 'MaxScore')))
        $items = @([ordered]@{ label = 'This tenant'; value = $mine; tone = 'c1' })
        foreach ($a in @(& $v $ss 'AverageComparativeScores' | Where-Object { $_ })) { $items += [ordered]@{ label = $(switch ([string](& $v $a 'Basis')) { 'AllTenants' { 'All tenants (average)' } 'TotalSeats' { 'Tenants of a similar size' } default { [string](& $v $a 'Basis') } }); value = [Math]::Round((& $num (& $v $a 'AverageScore'))); tone = 'na' } }
        $out.secureScore = [ordered]@{ item = $items; takeaway = "Microsoft Secure Score $mine% (verify: Microsoft's averages read as percentages)." }
    }
    $guests = & $load '06-users-guests'
    if ($null -ne $guests -and @($guests | Where-Object { $_ }).Count) {
        $g = [ordered]@{ 'Last 30 days' = 0; '31 to 90 days' = 0; 'Over 90 days' = 0; 'Never signed in' = 0 }
        foreach ($u in @($guests | Where-Object { $_ })) {
            $ls = & $v $u 'LastInteractiveSignIn'
            if (-not $ls) { $g['Never signed in']++; continue }
            $t = $(if ($ls -is [datetime]) { $ls } else { $p = [datetime]::MinValue; if ([datetime]::TryParse([string]$ls, [cultureinfo]::InvariantCulture, 'AdjustToUniversal', [ref]$p)) { $p } else { $null } })
            if (-not $t) { $g['Never signed in']++; continue }
            $days = ([datetime]::UtcNow - $t.ToUniversalTime()).TotalDays
            $g[$(if ($days -le 30) { 'Last 30 days' } elseif ($days -le 90) { '31 to 90 days' } else { 'Over 90 days' })]++
        }
        $out.guestAge = [ordered]@{ item = @($g.Keys | ForEach-Object { [ordered]@{ label = $_; value = $g[$_]; tone = $(if ($_ -in 'Over 90 days', 'Never signed in') { 'warn' } else { 'c1' }) } }); takeaway = "$($g['Over 90 days'] + $g['Never signed in']) of $(@($guests | Where-Object { $_ }).Count) guests have not signed in for 90 days or ever." }
    }
    $risky = & $load '11-risky-users'
    if ($null -ne $risky -and @($risky | Where-Object { $_ }).Count) {
        $rl = @{}; foreach ($u in @($risky | Where-Object { $_ })) { $k = [string](& $v $u 'RiskLevel'); if (-not $k) { $k = 'unknown' }; $rl[$k] = 1 + $(if ($rl.ContainsKey($k)) { $rl[$k] } else { 0 }) }
        $out.riskyUsers = [ordered]@{ item = @('high', 'medium', 'low', 'unknown' | Where-Object { $rl.ContainsKey($_) } | ForEach-Object { [ordered]@{ label = $_; value = $rl[$_]; tone = @{ high = 'err'; medium = 'warn'; low = 'c1'; unknown = 'na' }[$_] } }); takeaway = "$(if ($rl.ContainsKey('high')) { $rl['high'] } else { 0 }) user(s) at high risk in Identity Protection." }
    }
    $sites = & $load 'spo-sites'
    if ($null -ne $sites -and @($sites | Where-Object { $_ }).Count) {
        $sharingLabel = @{ Disabled = 'Only people in the organisation'; ExistingExternalUserSharingOnly = 'Existing guests'; ExternalUserSharingOnly = 'New and existing guests'; ExternalUserAndGuestSharing = 'Anyone' }
        $sc = @{}; foreach ($st in @($sites | Where-Object { $_ -and (& $v $_ 'IsOneDrive') -ne $true })) { $k = [string](& $v $st 'SharingCapability'); $k = $(if ($sharingLabel.ContainsKey($k)) { $sharingLabel[$k] } elseif ($k) { $k } else { 'Not reported' }); $sc[$k] = 1 + $(if ($sc.ContainsKey($k)) { $sc[$k] } else { 0 }) }
        $order = @('Anyone', 'New and existing guests', 'Existing guests', 'Only people in the organisation')
        $out.siteSharing = [ordered]@{ item = @(@($order | Where-Object { $sc.ContainsKey($_) }) + @($sc.Keys | Where-Object { $_ -notin $order }) | ForEach-Object { [ordered]@{ label = $_; value = $sc[$_]; tone = $(if ($_ -eq 'Anyone') { 'err' } elseif ($_ -eq 'New and existing guests') { 'warn' } else { 'c1' }) } }); takeaway = "$(if ($sc.ContainsKey('Anyone')) { $sc['Anyone'] } else { 0 }) site(s) allow Anyone links." }
    }
    $iw = & $load 'def-05-incidents-weekly'
    if ($iw -and @(& $v $iw 'Weeks').Count -ge 2) {
        $wk = @(& $v $iw 'Weeks' | Where-Object { $_ })
        $high = [int](@($wk | ForEach-Object { [int](& $v $_ 'High') }) | Measure-Object -Sum).Sum
        $out.incidentsWeekly = [ordered]@{ point = @($wk | ForEach-Object { [ordered]@{ label = ([string](& $v $_ 'WeekStart')).Substring(5); value = [double](& $v $_ 'Total') } }); takeaway = "$(& $num (& $v $iw 'Incidents')) incident(s) in the last 90 days, $high of them high severity." }
    }
    # Sensitivity against exposure: sites by label (rows) and sharing level (columns). Labelled content open to
    # Anyone is the corner to look at first.
    if ($null -ne $sites -and @($sites | Where-Object { $_ }).Count) {
        $labelName = @{}; foreach ($l in @(& $load 'pv-01-sensitivity-labels' | Where-Object { $_ })) { $labelName[[string](& $v $l 'Guid')] = [string]$(if (& $v $l 'DisplayName') { & $v $l 'DisplayName' } else { & $v $l 'Name' }) }
        $levels = @('Only people in the organisation', 'Existing guests', 'New and existing guests', 'Anyone')
        $levelOf = @{ Disabled = 'Only people in the organisation'; ExistingExternalUserSharingOnly = 'Existing guests'; ExternalUserSharingOnly = 'New and existing guests'; ExternalUserAndGuestSharing = 'Anyone' }
        $cells = @{}; $rowsSeen = [ordered]@{}
        foreach ($st in @($sites | Where-Object { $_ -and (& $v $_ 'IsOneDrive') -ne $true })) {
            $lab = [string](& $v $st 'SensitivityLabel'); $lab = $(if (-not $lab) { 'No label' } elseif ($labelName.ContainsKey($lab)) { $labelName[$lab] } else { 'Label ' + $lab.Substring(0, [Math]::Min(8, $lab.Length)) })
            $lev = $levelOf[[string](& $v $st 'SharingCapability')]; if (-not $lev) { continue }
            $rowsSeen[$lab] = $true; $cells["$lab|$lev"] = 1 + $(if ($cells.ContainsKey("$lab|$lev")) { $cells["$lab|$lev"] } else { 0 })
        }
        if ($rowsSeen.Count) {
            $labelledAnyone = [int](@($rowsSeen.Keys | Where-Object { $_ -ne 'No label' } | ForEach-Object { if ($cells.ContainsKey("$_|Anyone")) { $cells["$_|Anyone"] } else { 0 } }) + 0 | Measure-Object -Sum).Sum
            $unlabelled = [int](@($levels | ForEach-Object { if ($cells.ContainsKey("No label|$_")) { $cells["No label|$_"] } else { 0 } }) | Measure-Object -Sum).Sum
            $out.sensitivityExposure = [ordered]@{ rows = @(@($rowsSeen.Keys | Where-Object { $_ -ne 'No label' } | Sort-Object) + @($(if ($rowsSeen.Contains('No label')) { 'No label' }))); columns = $levels; cells = $cells; takeaway = "$labelledAnyone labelled site(s) allow Anyone links; $unlabelled site(s) carry no label." }
        }
    }
    # The most exposed sites, from the SharePoint Advanced Management report when one has been imported.
    $dag = & $load 'spo-dag-site-permissions'
    if ($dag -and @(& $v $dag 'top').Count) {
        $out.topExposed = [ordered]@{ sites = @(& $v $dag 'top' | Where-Object { $_ } | Select-Object -First 15 | ForEach-Object { [ordered]@{ name = [string]$(if (& $v $_ 'name') { & $v $_ 'name' } else { & $v $_ 'url' }); anyone = [int](& $v $_ 'anyone'); org = [int](& $v $_ 'org'); eeeu = [int](& $v $_ 'eeeu'); everyone = [int](& $v $_ 'everyone') } }); takeaway = "$(& $num (& $v $dag 'exposedSites')) site(s) shared with Anyone links, organisation-wide links or Everyone; the most exposed first." }
    }
    $dlp = & $load 'pv-02-dlp-policies'
    if ($null -ne $dlp -and @($dlp | Where-Object { $_ }).Count) {
        $modeLabel = @{ Enable = 'Enforced'; TestWithNotifications = 'Simulation with tips'; TestWithoutNotifications = 'Simulation'; Disable = 'Off' }
        $dm = [ordered]@{}; foreach ($pol in @($dlp | Where-Object { $_ })) { $k = [string](& $v $pol 'Mode'); $k = $(if ($modeLabel.ContainsKey($k)) { $modeLabel[$k] } else { $k }); $dm[$k] = 1 + $(if ($dm.Contains($k)) { $dm[$k] } else { 0 }) }
        $out.dlpModes = [ordered]@{ item = @($dm.Keys | ForEach-Object { [ordered]@{ label = $_; value = $dm[$_]; tone = $(if ($_ -eq 'Enforced') { 'ok' } elseif ($_ -eq 'Off') { 'na' } else { 'warn' }) } }); takeaway = "$(if ($dm.Contains('Enforced')) { $dm['Enforced'] } else { 0 }) of $(@($dlp | Where-Object { $_ }).Count) DLP policies are enforced." }
    }
    return $out
}
