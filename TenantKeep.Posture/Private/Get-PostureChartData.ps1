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
        [object[]] $Admin = @()
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
    return $out
}
