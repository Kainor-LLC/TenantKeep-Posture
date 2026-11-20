# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureInventory {
    <#
    .SYNOPSIS
        The report's Inventory view: what the tenant has, not whether it passes. Mail domains with SPF, DKIM and
        DMARC, transport rules, mail connectors, devices by platform and compliance, compliance policies,
        configuration profiles, endpoint security policies, privileged roles and Conditional Access by state.
    .DESCRIPTION
        Each section is a table (columns, rows of text) with the evidence files it came from, so the renderer stays
        generic. A section whose files were not collected comes back with a note saying which file and no rows; a
        collected file with nothing in it is an empty table with a note that says so.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [int] $MaxRows = 500
    )

    $ErrorActionPreference = 'Stop'
    $load = { param([string] $Name) Read-PostureEvidenceFile -Folder $Evidence -Name $Name }
    $rows = { param($o) @(@($o) | Where-Object { $_ }) }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $yesNo = { param($b) if ($b -eq $true) { 'yes' } elseif ($b -eq $false) { 'no' } else { '' } }
    # The JSON reader turns ISO dates into DateTime values; a date is shown as yyyy-MM-dd either way.
    $day = { param($d) if ($null -eq $d -or "$d" -eq '') { '' } elseif ($d -is [datetime]) { $d.ToUniversalTime().ToString('yyyy-MM-dd') } else { ([string]$d).Substring(0, [Math]::Min(10, ([string]$d).Length)) } }
    # A Graph type or family name as words (windowsUpdateForBusinessConfiguration: Windows update for business configuration).
    $words = { param([string] $t) if (-not $t) { return '' }; $x = ($t -creplace '([a-z0-9])([A-Z])', '$1 $2').ToLowerInvariant(); $x.Substring(0, 1).ToUpperInvariant() + $x.Substring(1) }
    $platformName = { param([string] $t) switch -Regex ($t) { '^windows' { 'Windows' } '^macOS' { 'macOS' } '^ios' { 'iOS' } '^(android|aosp)' { 'Android' } default { $t } } }
    $join = { param($x) (@($x) | Where-Object { $_ } | ForEach-Object { [string]$_ }) -join ', ' }
    $section = {
        param([string] $Key, [string] $Title, [string] $Domain, [string[]] $Source, [string[]] $Columns, $Rows, [string] $Note)
        $all = @($Rows)
        [ordered]@{
            key = $Key; title = $Title; domain = $Domain; source = @($Source); columns = @($Columns)
            rows = @($all | Select-Object -First $MaxRows); total = $all.Count
            note = $(if ($Note) { $Note } elseif ($all.Count -gt $MaxRows) { "The first $MaxRows of $($all.Count); every row is in $($Source[0])." } else { $null })
        }
    }
    $notCollected = { param([string] $Key, [string] $Title, [string] $Domain, [string[]] $Source, [string] $Collector) & $section $Key $Title $Domain $Source @() @() "Not collected: $($Source[0]) comes from the $Collector collector." }
    $out = [System.Collections.Generic.List[object]]::new()

    # Mail domains: accepted domains joined to DKIM and the DNS records read for them.
    $accepted = & $load 'exo-02-accepted-domains'; $dkim = & $load 'exo-02-dkim'; $dns = & $load 'dns-01-mail-records'
    if ($null -eq $accepted -and $null -eq $dns) { $out.Add((& $notCollected 'mail-domains' 'Mail Domains' 'email' @('exo-02-accepted-domains.json', 'dns-01-mail-records.json') 'Exchange')) }
    else {
        $dkimBy = @{}; foreach ($d in & $rows $dkim) { $dkimBy[([string](& $v $d 'Domain')).ToLowerInvariant()] = $d }
        $dnsBy = @{}; foreach ($d in & $rows $dns) { $dnsBy[([string](& $v $d 'Domain')).ToLowerInvariant()] = $d }
        $names = @($(if ($null -ne $accepted) { & $rows $accepted | ForEach-Object { [string](& $v $_ 'DomainName') } } else { $dnsBy.Keys }) | Where-Object { $_ } | Sort-Object -Unique)
        $typeBy = @{}; foreach ($a in & $rows $accepted) { $typeBy[([string](& $v $a 'DomainName')).ToLowerInvariant()] = "$(& $v $a 'DomainType')$(if ((& $v $a 'Default') -eq $true) { ', default' })" }
        $spfOf = { param([string] $s) if (-not $s) { 'missing' } elseif ($s -match '-all\s*$') { 'hard fail (-all)' } elseif ($s -match '~all\s*$') { 'soft fail (~all)' } elseif ($s -match '[?+]all\s*$') { 'neutral or pass-all' } else { 'no all mechanism' } }
        $dmarcOf = { param([string] $s) if (-not $s) { 'missing' } elseif ($s -match '(?i)\bp\s*=\s*(\w+)') { $Matches[1].ToLowerInvariant() } else { 'no policy tag' } }
        $mail = foreach ($n in $names) {
            $k = $n.ToLowerInvariant(); $dk = $dkimBy[$k]; $dn = $dnsBy[$k]
            # Microsoft runs DNS for the onmicrosoft.com domains; the collector reads only the tenant's own.
            $na = $(if ($k -like '*.onmicrosoft.com') { 'Microsoft managed' } else { 'not read' })
            [ordered]@{
                Domain = $n; Type = [string]$typeBy[$k]
                DKIM   = $(if ($dk) { if ((& $v $dk 'Enabled') -eq $true) { 'on' } else { "off$(if (& $v $dk 'Status') { " ($(& $v $dk 'Status'))" })" } } elseif ($k -like '*.onmicrosoft.com') { 'Microsoft signs' } else { 'not read' })
                SPF    = $(if ($dn) { & $spfOf ([string](& $v $dn 'SPF')) } else { $na })
                DMARC  = $(if ($dn) { & $dmarcOf ([string](& $v $dn 'DMARC')) } else { $na })
                'MTA-STS' = $(if ($dn) { if ([string](& $v $dn 'MTASTS')) { 'published' } else { 'missing' } } else { $na })
                MX     = $(if ($dn) { $mx = [string](& $v $dn 'MX'); if (-not $mx) { 'none' } elseif ($mx -match '(?i)mail\.protection\.outlook\.com') { 'Exchange Online Protection' } else { $mx } } else { $na })
            }
        }
        $out.Add((& $section 'mail-domains' 'Mail Domains' 'email' @('exo-02-accepted-domains.json', 'exo-02-dkim.json', 'dns-01-mail-records.json') @('Domain', 'Type', 'DKIM', 'SPF', 'DMARC', 'MTA-STS', 'MX') $mail $null))
    }

    # Transport rules and connectors.
    $tr = & $load 'exo-03-transport-rules'
    if ($null -eq $tr) { $out.Add((& $notCollected 'transport-rules' 'Transport Rules' 'email' @('exo-03-transport-rules.json') 'Exchange')) }
    else {
        $list = @(& $rows $tr | Sort-Object { [int](& $v $_ 'Priority') } | ForEach-Object { [ordered]@{ Priority = [string](& $v $_ 'Priority'); Name = [string](& $v $_ 'Name'); State = [string](& $v $_ 'State'); Mode = [string](& $v $_ 'Mode'); 'Sets SCL' = [string](& $v $_ 'SetSCL'); 'Sender IPs' = (& $join (& $v $_ 'SenderIpRanges')) } })
        $out.Add((& $section 'transport-rules' 'Transport Rules' 'email' @('exo-03-transport-rules.json') @('Priority', 'Name', 'State', 'Mode', 'Sets SCL', 'Sender IPs') $list $(if ($list.Count -eq 0) { 'No transport rules.' })))
    }
    $in = & $load 'exo-03-inbound-connectors'; $ob = & $load 'exo-03-outbound-connectors'
    if ($null -eq $in -and $null -eq $ob) { $out.Add((& $notCollected 'connectors' 'Mail Connectors' 'email' @('exo-03-inbound-connectors.json', 'exo-03-outbound-connectors.json') 'Exchange')) }
    else {
        $list = @(@(& $rows $in | ForEach-Object { [ordered]@{ Direction = 'Inbound'; Name = [string](& $v $_ 'Name'); Enabled = (& $yesNo (& $v $_ 'Enabled')); Type = [string](& $v $_ 'ConnectorType'); Scope = (& $join @(@(& $v $_ 'SenderDomains') + @(& $v $_ 'SenderIPAddresses'))); TLS = [string](& $v $_ 'TlsSenderCertificateName') } }) +
            @(& $rows $ob | ForEach-Object { [ordered]@{ Direction = 'Outbound'; Name = [string](& $v $_ 'Name'); Enabled = (& $yesNo (& $v $_ 'Enabled')); Type = [string](& $v $_ 'ConnectorType'); Scope = (& $join @(@(& $v $_ 'RecipientDomains') + @(& $v $_ 'SmartHosts'))); TLS = [string](& $v $_ 'TlsSettings') } }))
        $out.Add((& $section 'connectors' 'Mail Connectors' 'email' @('exo-03-inbound-connectors.json', 'exo-03-outbound-connectors.json') @('Direction', 'Name', 'Enabled', 'Type', 'Scope', 'TLS') $list $(if ($list.Count -eq 0) { 'No inbound or outbound connectors: mail flows straight through Exchange Online Protection.' })))
    }

    # Devices by platform and compliance, from the Intune summary ("Windows, compliant": count).
    $comp = & $load '09-intune-summary-compliance'
    if ($null -eq $comp) { $out.Add((& $notCollected 'device-compliance' 'Devices by Platform and Compliance' 'devices' @('09-intune-summary-compliance.json') 'Intune')) }
    else {
        $pivot = [ordered]@{}
        foreach ($r in & $rows $comp) {
            $parts = @(([string](& $v $r 'Name')) -split ',\s*', 2); $pl = $parts[0]; $st = $(if ($parts.Count -gt 1) { $parts[1] } else { 'unknown' })
            if (-not $pivot.Contains($pl)) { $pivot[$pl] = [ordered]@{ Compliant = 0; Noncompliant = 0; Other = 0 } }
            $col = $(switch ($st) { 'compliant' { 'Compliant' } 'noncompliant' { 'Noncompliant' } default { 'Other' } })
            $pivot[$pl][$col] += [int](& $v $r 'Count')
        }
        $list = @($pivot.Keys | ForEach-Object { $p = $pivot[$_]; [ordered]@{ Platform = $_; Compliant = [string]$p.Compliant; Noncompliant = [string]$p.Noncompliant; 'Unknown or grace' = [string]$p.Other; Total = [string]($p.Compliant + $p.Noncompliant + $p.Other) } })
        $out.Add((& $section 'device-compliance' 'Devices by Platform and Compliance' 'devices' @('09-intune-summary-compliance.json') @('Platform', 'Compliant', 'Noncompliant', 'Unknown or grace', 'Total') $list $(if ($list.Count -eq 0) { 'No managed devices.' })))
    }

    # Intune policies with their assignment counts.
    $cp = & $load '09-intune-compliance-policies'
    if ($null -eq $cp) { $out.Add((& $notCollected 'compliance-policies' 'Compliance Policies' 'devices' @('09-intune-compliance-policies.json') 'Intune')) }
    else {
        $list = @(& $rows $cp | Sort-Object { [string](& $v $_ 'Type') }, { [string](& $v $_ 'DisplayName') } | ForEach-Object { [ordered]@{ Name = [string](& $v $_ 'DisplayName'); Platform = (& $platformName ([string](& $v $_ 'Type'))); Assignments = [string](& $v $_ 'Assignments'); 'Device risk' = $(if ((& $v $_ 'DeviceThreatProtectionEnabled') -eq $true) { [string](& $v $_ 'DeviceThreatProtectionRequiredSecurityLevel') } elseif ($null -ne (& $v $_ 'DeviceThreatProtectionEnabled')) { 'not required' } else { '' }) } })
        $out.Add((& $section 'compliance-policies' 'Compliance Policies' 'devices' @('09-intune-compliance-policies.json') @('Name', 'Platform', 'Assignments', 'Device risk') $list $(if ($list.Count -eq 0) { 'No compliance policies.' })))
    }
    $tpl = & $load '09-intune-config-profiles-templates'; $sc = & $load '09-intune-config-profiles-settings-catalog'
    if ($null -eq $tpl -and $null -eq $sc) {
        $out.Add((& $notCollected 'config-profiles' 'Configuration Profiles' 'devices' @('09-intune-config-profiles-templates.json', '09-intune-config-profiles-settings-catalog.json') 'Intune'))
        $out.Add((& $notCollected 'endpoint-security' 'Endpoint Security Policies' 'endpoint' @('09-intune-config-profiles-settings-catalog.json') 'Intune'))
    }
    else {
        $isEs = { param($p) [string](& $v $p 'TemplateFamily') -like 'endpointSecurity*' }
        $profiles = @(@(& $rows $tpl | ForEach-Object { [ordered]@{ Name = [string](& $v $_ 'DisplayName'); Kind = (& $words ([string](& $v $_ 'Type'))); Platforms = ''; Assignments = [string](& $v $_ 'Assignments') } }) +
            @(& $rows $sc | Where-Object { -not (& $isEs $_) } | ForEach-Object { [ordered]@{ Name = [string](& $v $_ 'Name'); Kind = $(if (& $v $_ 'TemplateDisplayName') { [string](& $v $_ 'TemplateDisplayName') } else { 'Settings catalog' }); Platforms = [string](& $v $_ 'Platforms'); Assignments = [string](& $v $_ 'Assignments') } }) | Sort-Object { $_.Name })
        $out.Add((& $section 'config-profiles' 'Configuration Profiles' 'devices' @('09-intune-config-profiles-templates.json', '09-intune-config-profiles-settings-catalog.json') @('Name', 'Kind', 'Platforms', 'Assignments') $profiles $(if ($profiles.Count -eq 0) { 'No configuration profiles.' })))
        $es = @(& $rows $sc | Where-Object { & $isEs $_ } | Sort-Object { [string](& $v $_ 'TemplateFamily') }, { [string](& $v $_ 'Name') } | ForEach-Object { [ordered]@{ Name = [string](& $v $_ 'Name'); Type = (& $words ([string](& $v $_ 'TemplateFamily') -replace '^endpointSecurity', '')); Template = [string](& $v $_ 'TemplateDisplayName'); Platforms = [string](& $v $_ 'Platforms'); Assignments = [string](& $v $_ 'Assignments') } })
        $out.Add((& $section 'endpoint-security' 'Endpoint Security Policies' 'endpoint' @('09-intune-config-profiles-settings-catalog.json') @('Name', 'Type', 'Template', 'Platforms', 'Assignments') $es $(if ($es.Count -eq 0) { 'No endpoint security policies.' })))
    }

    # Group Policy analytics: each imported GPO and how much of it MDM can replace.
    $gpa = & $load '09-intune-gpo-analytics'
    if ($null -ne $gpa) {
        $list = @(& $rows $gpa | Sort-Object { [double](& $v $_ 'SupportedPercent') } | ForEach-Object { [ordered]@{ GPO = [string](& $v $_ 'DisplayName'); 'Supported in MDM (%)' = [string](& $v $_ 'SupportedPercent'); Settings = [string](& $v $_ 'TotalSettings'); Readiness = (& $words ([string](& $v $_ 'MigrationReadiness'))); 'Linked in AD' = (& $yesNo (& $v $_ 'TargetedInActiveDirectory')) } })
        $out.Add((& $section 'gpo-analytics' 'Group Policy Analytics' 'devices' @('09-intune-gpo-analytics.json') @('GPO', 'Supported in MDM (%)', 'Settings', 'Readiness', 'Linked in AD') $list $(if ($list.Count -eq 0) { 'No GPOs imported into Group Policy analytics.' })))
    }

    # Privileged roles: who holds each role permanently, activated now, or eligible through PIM.
    $active = & $load '04-role-assignments-active'; $eligible = & $load '04-role-assignments-pim-eligible'
    if ($null -eq $active) { $out.Add((& $notCollected 'roles' 'Privileged Roles' 'identity' @('04-role-assignments-active.json', '04-role-assignments-pim-eligible.json') 'Entra')) }
    else {
        $byRole = [ordered]@{}
        $bump = { param([string] $Role, [string] $Col) if (-not $byRole.Contains($Role)) { $byRole[$Role] = [ordered]@{ Permanent = 0; Activated = 0; Eligible = 0 } }; $byRole[$Role][$Col]++ }
        foreach ($a in & $rows $active) { & $bump ([string](& $v $a 'Role')) $(if ([string](& $v $a 'AssignmentType') -eq 'Activated') { 'Activated' } else { 'Permanent' }) }
        foreach ($e in & $rows $eligible) { & $bump ([string](& $v $e 'Role')) 'Eligible' }
        $list = @($byRole.Keys | Sort-Object { - ($byRole[$_].Permanent + $byRole[$_].Activated + $byRole[$_].Eligible) }, { $_ } | ForEach-Object { $x = $byRole[$_]; [ordered]@{ Role = $_; Permanent = [string]$x.Permanent; 'Activated now' = [string]$x.Activated; Eligible = [string]$x.Eligible } })
        $out.Add((& $section 'roles' 'Privileged Roles' 'identity' @('04-role-assignments-active.json', '04-role-assignments-pim-eligible.json') @('Role', 'Permanent', 'Activated now', 'Eligible') $list $(if ($null -eq $eligible) { 'PIM eligibility was not collected; eligible counts read 0.' })))
    }

    # Conditional Access policies by state.
    $pol = & $load 'policies'
    if ($null -eq $pol) { $out.Add((& $notCollected 'ca-policies' 'Conditional Access Policies' 'ca' @('policies.json') 'Conditional Access snapshot')) }
    else {
        $items = @($(if ($pol -is [System.Collections.IDictionary] -and $pol.Contains('value')) { $pol['value'] } else { $pol }) | Where-Object { $_ })
        $stateLabel = @{ enabled = 'On'; disabled = 'Off'; enabledForReportingButNotEnforced = 'Report-only' }
        $order = @{ enabled = 1; enabledForReportingButNotEnforced = 2; disabled = 3 }
        $list = @($items | Sort-Object { $s = [string](& $v $_ 'state'); if ($order.ContainsKey($s)) { $order[$s] } else { 4 } }, { [string](& $v $_ 'displayName') } | ForEach-Object { $s = [string](& $v $_ 'state'); [ordered]@{ Name = [string](& $v $_ 'displayName'); State = $(if ($stateLabel.ContainsKey($s)) { $stateLabel[$s] } else { $s }); Modified = $(& $day (& $v $_ 'modifiedDateTime')) } })
        $counts = @('On', 'Report-only', 'Off' | ForEach-Object { $st = $_; "$(@($list | Where-Object { $_.State -eq $st }).Count) $($st.ToLowerInvariant())" }) -join ', '
        $out.Add((& $section 'ca-policies' 'Conditional Access Policies' 'ca' @('policies.json') @('Name', 'State', 'Modified') $list $(if ($list.Count -eq 0) { 'No Conditional Access policies.' } else { "$($list.Count) policies: $counts." })))
    }
    return @($out)
}
