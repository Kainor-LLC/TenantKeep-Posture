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
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
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
    if ($null -eq $sl -or $null -eq $sa -or $null -eq $g) { & $missing @('EM-005') 'exo-05-mdo-*' }
    else {
        $facts.safeLinksComplete = @(& $rows $sl | Where-Object { $_.EnableSafeLinksForEmail -eq $true -and $_.EnableSafeLinksForTeams -eq $true -and $_.EnableSafeLinksForOffice -eq $true }).Count -gt 0
        $facts.safeAttachmentsEnabled = @(& $rows $sa | Where-Object { $_.Enable -eq $true -and [string]$_.Action -in @('Block', 'DynamicDelivery') }).Count -gt 0
        $g1 = @(& $rows $g | Select-Object -First 1)
        $facts.safeAttachmentsSpoEnabled = [bool]($g1.Count -gt 0 -and (& $v $g1[0] 'EnableATPForSPOTeamsODB') -eq $true)
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
        $facts.quarantineNotificationsEnabled = [bool]($null -ne $q -and @(& $rows $q | Where-Object { $_.ESNEnabled -eq $true }).Count -gt 0)
    }

    # Automatic external forwarding (EM-008)
    $os = & $load 'exo-04-outbound-spam'
    if ($null -eq $os) { & $missing @('EM-008') 'exo-04-outbound-spam' }
    else {
        $open = @(& $rows $os | Where-Object { [string]$_.AutoForwardingMode -ne 'Off' })
        $facts.outboundPoliciesAllowingAutoForward = $open.Count
        $affected.outboundPoliciesAllowingAutoForward = @($open | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = "AutoForwardingMode $($_.AutoForwardingMode)" } })
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
    if ($null -eq $ic) { & $missing @('EM-011', 'EM-021') 'exo-03-inbound-connectors' }
    else {
        $partner = @(& $rows $ic | Where-Object { $_.Enabled -ne $false -and [string]$_.ConnectorType -eq 'Partner' })
        $noEf = @($partner | Where-Object { $_.EFSkipLastIP -ne $true -and @($_.EFSkipIPs | Where-Object { $_ }).Count -eq 0 })
        $facts.partnerInboundConnectors = $partner.Count
        $facts.partnerConnectorsWithoutEnhancedFiltering = $noEf.Count
        $affected.partnerConnectorsWithoutEnhancedFiltering = @($noEf | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = "partner connector, Enhanced Filtering off, senders $(@($_.SenderIPAddresses) -join ' ')" } })
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
        foreach ($r in $dnsRows) {
            $d = [string]$r.Domain
            $dmarc = [string]$r.DMARC
            if (-not $dmarc) { $dmarcGaps += , [ordered]@{ name = $d; detail = 'no DMARC record' } }
            else {
                $p = $(if ($dmarc -match '(?i)(?:^|;)\s*p\s*=\s*([a-z]+)') { $Matches[1].ToLowerInvariant() } else { 'none' })
                $rua = $dmarc -match '(?i)(?:^|;)\s*rua\s*='
                $pr = $(if ($rank.ContainsKey($p)) { $rank[$p] } else { 0 })
                if ($pr -lt $minRank) { $dmarcGaps += , [ordered]@{ name = $d; detail = "p=$p, target $($t.minDmarcPolicy)" } }
                elseif (-not $rua) { $dmarcGaps += , [ordered]@{ name = $d; detail = "p=$p but no rua reporting address" } }
            }
            $spf = [string]$r.SPF
            if (-not $spf) { $spfGaps += , [ordered]@{ name = $d; detail = 'no SPF record' } }
            else {
                $lookups = @([regex]::Matches($spf, '(?i)(?:^|\s)(?:include:|a(?=[\s:/]|$)|mx(?=[\s:/]|$)|ptr|exists:|redirect=)')).Count
                $allTerm = $(if ($spf -match '(?i)([-~?+]?)all\s*$') { $Matches[1] } else { $null })
                if ($lookups -gt 10) { $spfGaps += , [ordered]@{ name = $d; detail = "$lookups lookup mechanisms in the record (limit 10, nested includes not counted)" } }
                elseif ($null -eq $allTerm) { $spfGaps += , [ordered]@{ name = $d; detail = 'no all mechanism' } }
                elseif ([bool]$t.spfRequireHardFail -and $allTerm -ne '-') { $spfGaps += , [ordered]@{ name = $d; detail = "ends with ${allTerm}all, not -all" } }
                elseif ($allTerm -in @('+', '?')) { $spfGaps += , [ordered]@{ name = $d; detail = "ends with ${allTerm}all" } }
            }
            if (-not [string]$r.MTASTS -or -not [string]$r.TLSRPT) { $stsGaps += , [ordered]@{ name = $d; detail = "MTA-STS $(if ($r.MTASTS) { 'published' } else { 'missing' }), TLS-RPT $(if ($r.TLSRPT) { 'published' } else { 'missing' })" } }
        }
        $facts.dnsDomains = $dnsRows.Count
        $facts.dmarcGaps = $dmarcGaps.Count; $affected.dmarcGaps = @($dmarcGaps)
        $facts.spfGaps = $spfGaps.Count; $affected.spfGaps = @($spfGaps)
        $facts.mtaStsGaps = $stsGaps.Count; $affected.mtaStsGaps = @($stsGaps)
    }

    # Mailboxes (EM-016 forwarding, EM-018 shared mailbox sign-in, EM-019 auditing)
    $mbx = & $load 'exo-09-mailboxes'
    if ($null -eq $mbx) { & $missing @('EM-016', 'EM-018') 'exo-09-mailboxes' }
    else {
        $m = @(& $rows $mbx)
        $facts.mailboxes = $m.Count
        $fwd = @($m | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } | ForEach-Object {
                $smtp = ([string]$_.ForwardingSmtpAddress) -replace '^smtp:', ''
                $dom = $(if ($smtp -match '@(.+)$') { $Matches[1].ToLowerInvariant() } else { '' })
                $external = $smtp -and ($dom -notin $acceptedNames)
                if ($external) { [ordered]@{ name = [string]$_.UserPrincipalName; detail = "forwards to $smtp (external)" } }
                elseif (-not $smtp -and $_.ForwardingAddress) { [ordered]@{ name = [string]$_.UserPrincipalName; detail = "forwards to recipient $($_.ForwardingAddress) (verify it is internal)" } }
            })
        $facts.mailboxesForwardingExternally = $fwd.Count
        $affected.mailboxesForwardingExternally = $fwd

        $shared = @($m | Where-Object { [string]$_.RecipientTypeDetails -eq 'SharedMailbox' })
        $facts.sharedMailboxes = $shared.Count
        $users = & $load '06-users'
        if ($null -eq $users) { $notEvaluated['EM-018'] = '06-users.json was not collected (Entra collector); the shared mailbox sign-in state needs it.' }
        else {
            $enabledIds = @{}; foreach ($u in @(& $rows $users | Where-Object { $_.AccountEnabled -eq $true })) { $enabledIds[[string]$u.Id] = $true }
            $signIn = @($shared | Where-Object { $_.ExternalDirectoryObjectId -and $enabledIds.ContainsKey([string]$_.ExternalDirectoryObjectId) })
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

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('exo-01-orgconfig.json', 'dns-01-mail-records.json') }
}
