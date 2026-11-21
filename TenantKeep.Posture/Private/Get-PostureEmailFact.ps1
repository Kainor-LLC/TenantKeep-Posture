# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureEmailFact {
    <#
    .SYNOPSIS
        Fact provider for the email domain (spec 4.10) from the A.2 Exchange Online files: preset policies, anti-phish,
        Safe Links and Attachments, ZAP, quarantine, forwarding, connection filter, SCL bypass rules, Enhanced
        Filtering, DKIM, SPF, DMARC, MTA-STS and TLS-RPT, legacy protocols, shared mailbox sign-in, auditing, attack
        simulation and ARC.
    .DESCRIPTION
        Thresholds read: minDmarcPolicy (quarantine or reject), spfRequireHardFail, maxDaysSinceSimulation.
        Profile read: licenses (E5 or MDE2 make Safe Documents expected).
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
    $t = @{ minDmarcPolicy = 'reject'; spfRequireHardFail = $true; maxDaysSinceSimulation = 90 }
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
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    # A list of affected objects holds 500 at most; affectedCounts carries how many there are when the list is cut.
    $affectedCounts = @{}
    $missing = { param([string[]] $Ids, [string] $File) foreach ($id in $Ids) { $notEvaluated[$id] = "$File.json was not collected (Invoke-PostureCollection -Collector Exchange; check errors.txt)." } }

    if (@(Get-ChildItem -LiteralPath $Evidence -Filter 'exo-*.json' -ErrorAction SilentlyContinue).Count -eq 0) {
        return @{ available = $false; reason = 'No Exchange Online evidence in the folder (Invoke-PostureCollection -Collector Exchange needs a Connect-ExchangeOnline session).' }
    }

    # Accepted domains: the custom authoritative ones are what DKIM and the DNS checks cover.
    $accepted = & $load 'exo-02-accepted-domains'
    $acceptedNames = @(& $rows $accepted | ForEach-Object { ([string]$_.DomainName).ToLowerInvariant() })
    $custom = @(& $rows $accepted | Where-Object { [string]$_.DomainType -eq 'Authoritative' -and [string]$_.DomainName -notmatch '(?i)\.onmicrosoft\.com$' } | ForEach-Object { ([string]$_.DomainName).ToLowerInvariant() })
    $facts.customDomains = $custom.Count

    # Preset security policies (EM-001, EM-002)
    foreach ($pair in @(@('exo-04-preset-rules-eop', 'Eop', 'EM-001'), @('exo-04-preset-rules-mdo', 'Mdo', 'EM-002'))) {
        $file, $kind, $id = $pair
        $r = & $load $file
        if ($null -eq $r) { & $missing @($id) $file; continue }
        $enabled = @(& $rows $r | Where-Object { [string]$_.State -eq 'Enabled' -and [string]$_.Name -match '(?i)standard|strict' })
        $all = @($enabled | Where-Object { @($_.SentTo | Where-Object { $_ }).Count -eq 0 -and @($_.SentToMemberOf | Where-Object { $_ }).Count -eq 0 -and @($_.RecipientDomainIs | Where-Object { $_ }).Count -eq 0 })
        $facts["preset${kind}Enabled"] = $enabled.Count -gt 0
        $facts["preset${kind}AllUsers"] = $all.Count -gt 0
        $facts["preset${kind}Names"] = @($enabled | ForEach-Object { [string]$_.Name })
    }

    # Anti-phish (EM-003 spoof, EM-004 impersonation)
    $ap = & $load 'exo-04-antiphish'
    if ($null -eq $ap) { & $missing @('EM-003', 'EM-004') 'exo-04-antiphish' }
    else {
        $pol = @(& $rows $ap | Where-Object { $_.Enabled -ne $false })
        $facts.antiPhishPolicies = $pol.Count
        $spoofGaps = @($pol | Where-Object { $_.EnableSpoofIntelligence -ne $true -or $_.HonorDmarcPolicy -ne $true })
        $facts.antiPhishSpoofGaps = $spoofGaps.Count
        $affected.antiPhishSpoofGaps = @($spoofGaps | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = "spoof intelligence $($_.EnableSpoofIntelligence), DMARC honoured $($_.HonorDmarcPolicy)" } })
        $impGaps = @($pol | Where-Object { $_.EnableTargetedUserProtection -ne $true -or @($_.TargetedUsersToProtect | Where-Object { $_ }).Count -eq 0 -or $_.EnableOrganizationDomainsProtection -ne $true -or $_.EnableMailboxIntelligence -ne $true })
        $facts.antiPhishImpersonationGaps = $impGaps.Count
        $affected.antiPhishImpersonationGaps = @($impGaps | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = "targeted users $(@($_.TargetedUsersToProtect | Where-Object { $_ }).Count), org domains $($_.EnableOrganizationDomainsProtection), mailbox intelligence $($_.EnableMailboxIntelligence)" } })
    }

    # Safe Links, Safe Attachments, global MDO settings (EM-005)
    $sl = & $load 'exo-05-mdo-safelinks'; $sa = & $load 'exo-05-mdo-safeattachments'; $g = & $load 'exo-05-mdo-global'
    if ($null -eq $sl -or $null -eq $sa -or $null -eq $g) { & $missing @('EM-005', 'EM-027') 'exo-05-mdo-*' }
    else {
        $facts.safeLinksComplete = @(& $rows $sl | Where-Object { $_.EnableSafeLinksForEmail -eq $true -and $_.EnableSafeLinksForTeams -eq $true -and $_.EnableSafeLinksForOffice -eq $true }).Count -gt 0
        $facts.safeAttachmentsEnabled = @(& $rows $sa | Where-Object { $_.Enable -eq $true -and [string]$_.Action -in @('Block', 'DynamicDelivery') }).Count -gt 0
        $g1 = @(& $rows $g | Select-Object -First 1)
        $facts.safeAttachmentsSpoEnabled = [bool]($g1.Count -gt 0 -and (& $v $g1[0] 'EnableATPForSPOTeamsODB') -eq $true)
        # EM-027: the parts a mail gateway does not reach, files and links in SharePoint, OneDrive, Teams and Office.
        $facts.safeLinksTeamsOffice = @(& $rows $sl | Where-Object { $_.EnableSafeLinksForTeams -eq $true -and $_.EnableSafeLinksForOffice -eq $true }).Count -gt 0
        $facts.safeDocumentsEnabled = [bool]($g1.Count -gt 0 -and (& $v $g1[0] 'EnableSafeDocs') -eq $true)
        $lic = @($OrgProfile['licenses'] | Where-Object { $_ })
        $facts.safeDocumentsExpected = [bool](@($lic | Where-Object { $_ -in @('E5', 'MDE2') }).Count -gt 0)
    }

    # ZAP (EM-006) and quarantine (EM-007) from the content filter and malware policies
    $cf = & $load 'exo-04-eop-content-filter'; $mw = & $load 'exo-04-eop-malware'
    if ($null -eq $cf) { & $missing @('EM-006', 'EM-007') 'exo-04-eop-content-filter' }
    else {
        $cfRows = @(& $rows $cf)
        $zapGaps = @(@($cfRows | Where-Object { $_.ZapEnabled -ne $true -or $_.SpamZapEnabled -ne $true -or $_.PhishZapEnabled -ne $true } | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = "content filter: ZAP $($_.ZapEnabled), spam $($_.SpamZapEnabled), phish $($_.PhishZapEnabled)" } }) +
            @($(if ($null -ne $mw) { @(& $rows $mw | Where-Object { $_.ZapEnabled -ne $true } | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = 'malware filter: ZAP off' } }) })))
        $facts.zapGaps = $zapGaps.Count
        $affected.zapGaps = $zapGaps
        $facts.highConfidencePhishAdminOnly = @($cfRows | Where-Object { [string]$_.HighConfidencePhishQuarantineTag -ne 'AdminOnlyAccessPolicy' }).Count -eq 0 -and $cfRows.Count -gt 0
        $affected.highConfidencePhishReleasable = @($cfRows | Where-Object { [string]$_.HighConfidencePhishQuarantineTag -ne 'AdminOnlyAccessPolicy' } | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = "high-confidence phish quarantine tag $($_.HighConfidencePhishQuarantineTag)" } })
        $q = & $load 'exo-05-quarantine-policies'
        $facts.quarantineNotificationsEnabled = $(if ($null -eq $q) { $null } else { @(& $rows $q | Where-Object { $_.ESNEnabled -eq $true }).Count -gt 0 })
    }

    # Automatic external forwarding (EM-008)
    $os = & $load 'exo-04-outbound-spam'
    if ($null -eq $os) { & $missing @('EM-008') 'exo-04-outbound-spam' }
    else {
        $open = @(& $rows $os | Where-Object { [string]$_.AutoForwardingMode -ne 'Off' })
        $facts.outboundPoliciesAllowingAutoForward = $open.Count
        $affected.outboundPoliciesAllowingAutoForward = @($open | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = "AutoForwardingMode $($_.AutoForwardingMode)" } })
        # EM-022: a mailbox over its sending limits is stopped, not only reported.
        $alertOnly = @(& $rows $os | Where-Object { $act = [string](Get-PostureValue $_ 'ActionWhenThresholdReached'); $act -and $act -notin 'BlockUser', 'BlockUserForToday' })
        $facts.outboundPoliciesAlertOnly = $alertOnly.Count
        $affected.outboundPoliciesAlertOnly = @($alertOnly | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = "when limits are reached: $(Get-PostureValue $_ 'ActionWhenThresholdReached')" } })
    }
    if ($null -eq $os) { & $missing @('EM-022') 'exo-04-outbound-spam' }
    # EM-023: the common attachment filter blocks the file types malware arrives in.
    if ($null -eq $mw) { & $missing @('EM-023') 'exo-04-eop-malware' }
    else {
        $noFilter = @(& $rows $mw | Where-Object { (Get-PostureValue $_ 'EnableFileFilter') -ne $true })
        $facts.malwarePoliciesWithoutFileFilter = $noFilter.Count
        $affected.malwarePoliciesWithoutFileFilter = @($noFilter | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = 'common attachment filter off' } })
    }

    # Connection filter allow list (EM-009)
    $conn = & $load 'exo-04-eop-connection-filter'
    if ($null -eq $conn) { & $missing @('EM-009') 'exo-04-eop-connection-filter' }
    else {
        $entries = @(& $rows $conn | ForEach-Object { $p = $_; @($p.IPAllowList | Where-Object { $_ }) | ForEach-Object { [ordered]@{ name = [string]$_; detail = "allow listed in $($p.Name)" } } })
        $facts.connectionFilterAllowListEntries = $entries.Count
        $affected.connectionFilterAllowListEntries = $entries
    }

    # SCL -1 transport rules (EM-010)
    $tr = & $load 'exo-03-transport-rules'
    if ($null -eq $tr) { & $missing @('EM-010') 'exo-03-transport-rules' }
    else {
        $bypass = @(& $rows $tr | Where-Object { [string]$_.State -eq 'Enabled' -and [string]$_.SetSCL -eq '-1' })
        $unscoped = @($bypass | Where-Object { @($_.SenderIpRanges | Where-Object { $_ }).Count -eq 0 -and @($_.HeaderContainsMessageHeader | Where-Object { $_ }).Count -eq 0 })
        $facts.sclBypassRules = $bypass.Count
        $facts.sclBypassRulesUnscoped = $unscoped.Count
        $affected.sclBypassRulesUnscoped = @($unscoped | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = "SCL -1 with no sender IP range or header condition (from scope $($_.FromScope))" } })
    }

    # Inbound connectors: Enhanced Filtering (EM-011) and ARC (EM-021)
    $ic = & $load 'exo-03-inbound-connectors'
    if ($null -eq $ic) { & $missing @('EM-011', 'EM-021', 'EM-024') 'exo-03-inbound-connectors' }
    else {
        $partner = @(& $rows $ic | Where-Object { $_.Enabled -ne $false -and [string]$_.ConnectorType -eq 'Partner' })
        $noEf = @($partner | Where-Object { (Get-PostureValue $_ 'EFSkipLastIP') -ne $true -and @(Get-PostureValue $_ 'EFSkipIPs' | Where-Object { $_ }).Count -eq 0 })
        $facts.partnerInboundConnectors = $partner.Count
        $facts.partnerConnectorsWithoutEnhancedFiltering = $noEf.Count
        # EM-024: a partner connector should accept mail only from that partner's addresses or certificate.
        $open = @($partner | Where-Object { (Get-PostureValue $_ 'RestrictDomainsToIPAddresses') -ne $true -and (Get-PostureValue $_ 'RestrictDomainsToCertificate') -ne $true })
        $facts.partnerConnectorsUnrestricted = $open.Count
        $affected.partnerConnectorsUnrestricted = @($open | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = 'accepts any sender address and certificate' } })
        $affected.partnerConnectorsWithoutEnhancedFiltering = @($noEf | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = "partner connector, Enhanced Filtering off, senders $(@(Get-PostureValue $_ 'SenderIPAddresses') -join ' ')" } })
    }
    $org = & $load 'exo-01-orgconfig'
    if ($null -eq $org) { & $missing @('EM-019', 'EM-021') 'exo-01-orgconfig' }
    else {
        $facts.arcTrustedSealers = @((& $v $org 'ArcTrustedSealers') | Where-Object { $_ }).Count
        $facts.mailboxAuditDisabledOrgWide = [bool]((& $v $org 'AuditDisabled') -eq $true)
    }

    # DKIM (EM-012)
    $dk = & $load 'exo-02-dkim'
    if ($null -eq $dk) { & $missing @('EM-012') 'exo-02-dkim' }
    else {
        $signed = @{}; foreach ($d in @(& $rows $dk)) { $signed[([string]$d.Domain).ToLowerInvariant()] = ($d.Enabled -eq $true) }
        $gaps = @($custom | Where-Object { -not ($signed.ContainsKey($_) -and $signed[$_]) })
        $facts.dkimDomainsWithoutSigning = $gaps.Count
        $affected.dkimDomainsWithoutSigning = @($gaps | ForEach-Object { [ordered]@{ name = $_; detail = $(if ($signed.ContainsKey($_)) { 'DKIM signing config present but disabled' } else { 'no DKIM signing config' }) } })
    }

    # Mail DNS (EM-013 DMARC, EM-014 SPF, EM-015 MTA-STS and TLS-RPT)
    $dns = & $load 'dns-01-mail-records'
    if ($null -eq $dns) { & $missing @('EM-013', 'EM-014', 'EM-015') 'dns-01-mail-records' }
    else {
        $dnsRows = @(& $rows $dns)
        $rank = @{ none = 0; quarantine = 1; reject = 2 }
        $minRank = $(if ($rank.ContainsKey([string]$t.minDmarcPolicy)) { $rank[[string]$t.minDmarcPolicy] } else { 2 })
        $dmarcGaps = @(); $spfGaps = @(); $stsGaps = @()
        # Records whose lookup failed are unknown for that domain (LookupFailed, written by the collector since 2026-11-21).
        $dnsUnknown = @{ DMARC = [System.Collections.Generic.List[string]]::new(); SPF = [System.Collections.Generic.List[string]]::new(); STS = [System.Collections.Generic.List[string]]::new() }
        foreach ($r in $dnsRows) {
            $d = [string]$r.Domain
            $lookupFailed = @(([string](& $v $r 'LookupFailed')) -split ';' | Where-Object { $_ })
            $dmarc = [string]$r.DMARC
            if ('DMARC' -in $lookupFailed) { $dnsUnknown.DMARC.Add($d) }
            elseif (-not $dmarc) { $dmarcGaps += , [ordered]@{ name = $d; detail = 'no DMARC record' } }
            else {
                $p = $(if ($dmarc -match '(?i)(?:^|;)\s*p\s*=\s*([a-z]+)') { $Matches[1].ToLowerInvariant() } else { 'none' })
                $rua = $dmarc -match '(?i)(?:^|;)\s*rua\s*='
                $pr = $(if ($rank.ContainsKey($p)) { $rank[$p] } else { 0 })
                if ($pr -lt $minRank) { $dmarcGaps += , [ordered]@{ name = $d; detail = "p=$p, target $($t.minDmarcPolicy)" } }
                elseif (-not $rua) { $dmarcGaps += , [ordered]@{ name = $d; detail = "p=$p but no rua reporting address" } }
            }
            $spf = [string]$r.SPF
            if ('SPF' -in $lookupFailed) { $dnsUnknown.SPF.Add($d) }
            elseif (-not $spf) { $spfGaps += , [ordered]@{ name = $d; detail = 'no SPF record' } }
            else {
                $lookups = @([regex]::Matches($spf, '(?i)(?:^|\s)(?:include:|a(?=[\s:/]|$)|mx(?=[\s:/]|$)|ptr|exists:|redirect=)')).Count
                $allTerm = $(if ($spf -match '(?i)([-~?+]?)all\s*$') { $Matches[1] } else { $null })
                if ($lookups -gt 10) { $spfGaps += , [ordered]@{ name = $d; detail = "$lookups lookup mechanisms in the record (limit 10, nested includes not counted)" } }
                elseif ($null -eq $allTerm) { $spfGaps += , [ordered]@{ name = $d; detail = 'no all mechanism' } }
                elseif ([bool]$t.spfRequireHardFail -and $allTerm -ne '-') { $spfGaps += , [ordered]@{ name = $d; detail = "ends with ${allTerm}all, not -all" } }
                elseif ($allTerm -in @('+', '?')) { $spfGaps += , [ordered]@{ name = $d; detail = "ends with ${allTerm}all" } }
            }
            if ('MTASTS' -in $lookupFailed -or 'TLSRPT' -in $lookupFailed) { $dnsUnknown.STS.Add($d) }
            elseif (-not [string]$r.MTASTS -or -not [string]$r.TLSRPT) { $stsGaps += , [ordered]@{ name = $d; detail = "MTA-STS $(if ($r.MTASTS) { 'published' } else { 'missing' }), TLS-RPT $(if ($r.TLSRPT) { 'published' } else { 'missing' })" } }
        }
        # A gap that was seen fails the check. With none seen and some domains unanswered, there is no answer yet.
        foreach ($pair in @(@('EM-013', 'DMARC', $dmarcGaps.Count, 'DMARC'), @('EM-014', 'SPF', $spfGaps.Count, 'SPF'), @('EM-015', 'STS', $stsGaps.Count, 'MTA-STS and TLS-RPT'))) {
            $unknownDomains = @($dnsUnknown[$pair[1]])
            if ($unknownDomains.Count -gt 0 -and $pair[2] -eq 0) { $notEvaluated[$pair[0]] = "The DNS lookup failed for $($unknownDomains.Count) domain(s) ($(@($unknownDomains | Select-Object -First 5) -join ', ')), so their $($pair[3]) records are unknown; no gap was found on the others. Collect Exchange again (Resume-PostureRun -Collector Exchange)." }
        }
        $facts.dnsLookupsFailed = @($dnsRows | Where-Object { [string](& $v $_ 'LookupFailed') }).Count
        $facts.dnsDomains = $dnsRows.Count
        $facts.dmarcGaps = $dmarcGaps.Count; $affected.dmarcGaps = @($dmarcGaps)
        $facts.spfGaps = $spfGaps.Count; $affected.spfGaps = @($spfGaps)
        $facts.mtaStsGaps = $stsGaps.Count; $affected.mtaStsGaps = @($stsGaps)
    }

    # Mailboxes (EM-016 forwarding, EM-018 shared mailbox sign-in, EM-019 auditing)
    # One pass over the mailbox list, a row at a time: the count, the forwarding mailboxes and the shared ones.
    $mbxCount = @{ n = 0 }; $forwarders = [System.Collections.Generic.List[object]]::new(); $sharedRows = [System.Collections.Generic.List[object]]::new()
    $haveMbx = Read-PostureEvidenceRow -Folder $Evidence -Name 'exo-09-mailboxes' -OnRow {
        param($_row)
        $mbxCount.n++
        if ($_row.ForwardingSmtpAddress -or $_row.ForwardingAddress) { $forwarders.Add($_row) }
        if ([string]$_row.RecipientTypeDetails -eq 'SharedMailbox') { $sharedRows.Add($_row) }
    }
    if (-not $haveMbx) { & $missing @('EM-016', 'EM-018') 'exo-09-mailboxes' }
    else {
        $facts.mailboxes = $mbxCount.n
        $fwd = @($forwarders | ForEach-Object {
                $smtp = ([string]$_.ForwardingSmtpAddress) -replace '^smtp:', ''
                $dom = $(if ($smtp -match '@(.+)$') { $Matches[1].ToLowerInvariant() } else { '' })
                $external = $smtp -and ($dom -notin $acceptedNames)
                if ($external) { [ordered]@{ name = [string]$_.UserPrincipalName; detail = "forwards to $smtp (external)" } }
                elseif (-not $smtp -and $_.ForwardingAddress) { [ordered]@{ name = [string]$_.UserPrincipalName; detail = "forwards to recipient $($_.ForwardingAddress) (verify it is internal)" } }
            })
        $facts.mailboxesForwardingExternally = $fwd.Count
        $affected.mailboxesForwardingExternally = $fwd

        $shared = @($sharedRows)
        $facts.sharedMailboxes = $shared.Count
        # Only the shared mailboxes' accounts, read a row at a time from the users file, not every user.
        $accounts = Find-PostureEvidenceRow -Folder $Evidence -Name '06-users' -Key 'Id' -Value @($shared | ForEach-Object { [string]$_.ExternalDirectoryObjectId })
        if ($null -eq $accounts) { $notEvaluated['EM-018'] = '06-users.json was not collected (Entra collector); the shared mailbox sign-in state needs it.' }
        else {
            $signIn = @($shared | Where-Object { $id = [string]$_.ExternalDirectoryObjectId; $id -and $accounts.ContainsKey($id) -and [string]$accounts[$id].AccountEnabled -eq 'True' })
            $facts.sharedMailboxesSignInEnabled = $signIn.Count
            $affected.sharedMailboxesSignInEnabled = @($signIn | ForEach-Object { [ordered]@{ name = [string]$_.UserPrincipalName; detail = 'shared mailbox whose account is enabled for sign-in' } })
        }
    }

    # Protocols (EM-017)
    $tc = & $load 'exo-01-transport-config'; $cas = & $load 'exo-10-cas-summary'
    if ($null -eq $tc -or $null -eq $cas) { & $missing @('EM-017') 'exo-01-transport-config, exo-10-cas-summary' }
    else {
        $facts.smtpClientAuthDisabled = [bool]((& $v $tc 'SmtpClientAuthenticationDisabled') -eq $true)
        $facts.mailboxesWithPop = [int](& $v $cas 'PopEnabled'); $facts.mailboxesWithImap = [int](& $v $cas 'ImapEnabled'); $facts.mailboxesWithSmtpAuthOverride = [int](& $v $cas 'SmtpAuthExplicitlyEnabled')
        $casRows = & $load 'exo-10-cas-mailboxes'
        $affected.legacyProtocolMailboxes = @(& $rows $casRows | Where-Object { $_.PopEnabled -eq $true -or $_.ImapEnabled -eq $true -or $_.SmtpClientAuthenticationDisabled -eq $false } | ForEach-Object { [ordered]@{ name = [string]$_.PrimarySmtpAddress; detail = (@($(if ($_.PopEnabled) { 'POP' }), $(if ($_.ImapEnabled) { 'IMAP' }), $(if ($_.SmtpClientAuthenticationDisabled -eq $false) { 'SMTP AUTH override' })) | Where-Object { $_ }) -join ', ' } })
    }

    # Audit (EM-019)
    $audit = & $load 'exo-01-audit-config'
    if ($null -eq $audit) { & $missing @('EM-019') 'exo-01-audit-config' }
    else { $facts.unifiedAuditLogEnabled = [bool]((& $v $audit 'UnifiedAuditLogIngestionEnabled') -eq $true) }

    # Attack simulation (EM-020)
    $sim = & $load 'exo-11-attack-simulations'
    if ($null -eq $sim) { & $missing @('EM-020') 'exo-11-attack-simulations' }
    else {
        $window = $AsOf.AddDays(-[int]$t.maxDaysSinceSimulation)
        $recent = @(& $rows $sim | Where-Object { $d = ConvertTo-PostureUtcDateTime $(if ($_.CompletionDateTime) { $_.CompletionDateTime } else { $_.LaunchDateTime }); $d -and $d -ge $window })
        $facts.attackSimulations = @(& $rows $sim).Count
        $facts.attackSimulationsInWindow = $recent.Count
    }

    # EM-026: with a gateway in front (MX pointing elsewhere, or an email vendor in the profile), mail must not be able
    # to reach Exchange Online directly and skip it: an enabled partner connector for every sender (*) that accepts mail
    # only from the gateway's addresses or certificate.
    $mxRows = & $load 'dns-01-mail-records'; $inbound = & $load 'exo-03-inbound-connectors'
    $tp = $(if ($OrgProfile.Contains('thirdParty') -and $OrgProfile['thirdParty']) { $OrgProfile['thirdParty'] } else { @{} })
    $emailVendor = $(if ($tp.Contains('email')) { [string]$tp['email'] } else { '' })
    if ($null -eq $inbound) { & $missing @('EM-026') 'exo-03-inbound-connectors' }
    else {
        $elsewhere = @(& $rows $mxRows | Where-Object { [string](& $v $_ 'MX') -and [string](& $v $_ 'MX') -notmatch '(?i)mail\.protection\.outlook\.com' })
        # A gateway is in front when an MX record points elsewhere or the profile names a vendor. Without the DNS
        # records and without a vendor it is unknown: no records is not the same as records that point at Microsoft.
        $mxUnknown = @(& $rows $mxRows | Where-Object { 'MX' -in @(([string](& $v $_ 'LookupFailed')) -split ';') })
        $facts.gatewayInFront = $(if ($elsewhere.Count -gt 0 -or ($emailVendor -and $emailVendor -ne 'none')) { $true } elseif ($null -eq $mxRows -or $mxUnknown.Count -gt 0) { $null } else { $false })
        $lock = @(& $rows $inbound | Where-Object { (& $v $_ 'Enabled') -eq $true -and [string](& $v $_ 'ConnectorType') -eq 'Partner' -and [string](& $v $_ 'SenderDomains') -match '\*' -and ((& $v $_ 'RestrictDomainsToIPAddresses') -eq $true -or (& $v $_ 'RestrictDomainsToCertificate') -eq $true) })
        $facts.gatewayLockedDown = $lock.Count -gt 0
        $affected.gatewayBypass = @($(if ($facts.gatewayInFront -and -not $facts.gatewayLockedDown) {
                    if ($elsewhere.Count) { $elsewhere | ForEach-Object { [ordered]@{ name = [string](& $v $_ 'Domain'); detail = "MX $([string](& $v $_ 'MX')); nothing stops mail sent straight to Exchange Online" } } }
                    else { [ordered]@{ name = $emailVendor; detail = 'no inbound connector limits mail to the gateway' } }
                }))
    }

    # EM-025: Exchange Online PowerShell only for administrators: either its app is closed to everyone else, or no one
    # but an administrator has the per-user setting on. Shared, room and equipment mailboxes do not sign in.
    $tools = Get-PostureAdminToolRestriction -Evidence $Evidence
    $exoApp = $(if ($tools) { @($tools | Where-Object { $_.appId -eq 'fb78d390-0c51-40cd-8e17-fdbfab77341b' })[0] } else { $null })
    # Unknown when the service principals were not collected, or when only a Conditional Access policy could close the app and the snapshot is missing.
    $facts.exoPowerShellAppRestricted = $(if ($null -eq $tools -or -not $exoApp) { $null } else { $exoApp.restricted })
    $admins = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $roleRows = & $load '04-role-assignments-active'
    foreach ($a in @($roleRows | Where-Object { $_ })) { $u = [string](& $v $a 'PrincipalUpn'); if ($u) { $null = $admins.Add($u) } }
    $psUsers = [System.Collections.Generic.List[object]]::new(); $psCount = @{ n = 0 }
    $havePs = Read-PostureEvidenceRow -Folder $Evidence -Name 'exo-12-remote-powershell-users' -OnRow {
        param($_row)
        $upn = [string](& $v $_row 'UserPrincipalName')
        if ([string](& $v $_row 'RecipientTypeDetails') -match '^(SharedMailbox|RoomMailbox|EquipmentMailbox|SchedulingMailbox)$' -or $admins.Contains($upn)) { return }
        $psCount.n++
        if ($psUsers.Count -lt 500) { $psUsers.Add([ordered]@{ name = $upn; detail = 'Exchange Online PowerShell on, not an administrator' }) }
    }
    if (-not $havePs -and $facts.exoPowerShellAppRestricted -ne $true) { $notEvaluated['EM-025'] = 'exo-12-remote-powershell-users was not collected: the Exchange collector reads it since 2026-11-20, unless -SkipMailboxEnumeration (Resume-PostureRun -Collector Exchange).' }
    else {
        # Unknown without the list, and unknown when accounts have it on but the role holders were not collected, so
        # administrators cannot be told from everyone else. None with it on is none either way.
        $facts.nonAdminRemotePowerShell = $(if (-not $havePs -or ($null -eq $roleRows -and $psCount.n -gt 0)) { $null } else { $psCount.n })
        $affected.nonAdminRemotePowerShell = @($(if ($null -ne $roleRows) { $psUsers }))
        if ($null -ne $roleRows) { $affectedCounts.nonAdminRemotePowerShell = $psCount.n }
    }

    return @{ available = $true; facts = $facts; affected = $affected; affectedCounts = $affectedCounts; notEvaluated = $notEvaluated; evidence = @('exo-01-orgconfig.json', 'dns-01-mail-records.json') }
}
