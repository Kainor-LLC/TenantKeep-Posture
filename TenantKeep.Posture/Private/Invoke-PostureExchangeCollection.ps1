# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureExchangeCollection {
    <#
    .SYNOPSIS
        The A.2 Exchange Online collector plus the spec 4.10 additions: org and transport config, authentication and
        audit settings, accepted domains, DKIM, connectors, transport rules, EOP and MDO policies, preset policy
        rules, quarantine, remote domains, sharing and OWA policies, mobile settings, role groups, mailboxes and CAS
        protocols, and the mail DNS records (MX, SPF, DMARC, MTA-STS, TLS-RPT).
    .DESCRIPTION
        Needs a connected Exchange Online session (Connect-ExchangeOnline, read-only roles such as View-Only
        Organization Management). Never connects. One step per file; a failed cmdlet is one line in errors.txt.
        -SkipMailboxEnumeration skips the two mailbox-wide pulls that take 10 to 20 minutes at 20k mailboxes.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [switch] $SkipMailboxEnumeration
    )

    $ErrorActionPreference = 'Stop'
    $files = [System.Collections.Generic.List[string]]::new()
    $save = { param($Data, [string] $Name, [bool] $Csv = $false) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data -AsArray -Csv:$Csv)) }
    $saveOne = { param($Data, [string] $Name) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data)) }
    $exo = { param([string] $Name, [hashtable] $Params = @{}) @(Invoke-PostureExoCommand -Name $Name -Parameters $Params) }
    $flat = { param($Objects, [string[]] $Props) @($Objects | Where-Object { $_ } | ForEach-Object { if ($Props) { $_ | ConvertTo-PostureFlatObject -Property $Props } else { $_ | ConvertTo-PostureFlatObject } }) }

    $simple = @(
        ('Org config', 'Get-OrganizationConfig', 'exo-01-orgconfig', $true, @('Name', 'OAuth2ClientProfileEnabled', 'DefaultAuthenticationPolicy', 'AuditDisabled', 'IsDehydrated', 'SendFromAliasEnabled', 'FocusedInboxOn', 'MailTipsAllTipsEnabled', 'MailTipsExternalRecipientsTipsEnabled', 'MailTipsLargeAudienceThreshold', 'AutoExpandingArchiveEnabled', 'EwsEnabled', 'EwsApplicationAccessPolicy', 'ActivityBasedAuthenticationTimeoutEnabled', 'ActivityBasedAuthenticationTimeoutInterval', 'ArcTrustedSealers', 'SmtpClientAuthenticationDisabled', 'CustomerLockboxEnabled', 'RejectDirectSend')),
        ('Transport config', 'Get-TransportConfig', 'exo-01-transport-config', $true, @('SmtpClientAuthenticationDisabled', 'ExternalPostmasterAddress', 'MaxRecipientEnvelopeLimit', 'DSNConversionMode')),
        ('Authentication policies', 'Get-AuthenticationPolicy', 'exo-01-auth-policies', $false, $null),
        ('Audit config', 'Get-AdminAuditLogConfig', 'exo-01-audit-config', $true, @('UnifiedAuditLogIngestionEnabled', 'UnifiedAuditLogFirstOptInDate', 'AdminAuditLogEnabled')),
        ('Accepted domains', 'Get-AcceptedDomain', 'exo-02-accepted-domains', $false, @('DomainName', 'DomainType', 'Default', 'AuthenticationType', 'InitialDomain')),
        ('DKIM', 'Get-DkimSigningConfig', 'exo-02-dkim', $false, @('Domain', 'Enabled', 'Status', 'Selector1CNAME', 'Selector2CNAME', 'LastChecked', 'RotateOnDate')),
        ('Inbound connectors', 'Get-InboundConnector', 'exo-03-inbound-connectors', $false, @('Name', 'Enabled', 'ConnectorType', 'ConnectorSource', 'RestrictDomainsToIPAddresses', 'RestrictDomainsToCertificate', 'TreatMessagesAsInternal', 'EFSkipLastIP', 'EFSkipIPs', 'EFUsers', 'SenderIPAddresses', 'SenderDomains', 'TlsSenderCertificateName', 'WhenChanged')),
        ('Outbound connectors', 'Get-OutboundConnector', 'exo-03-outbound-connectors', $false, @('Name', 'Enabled', 'ConnectorType', 'UseMXRecord', 'SmartHosts', 'RecipientDomains', 'TlsSettings', 'TlsDomain', 'RouteAllMessagesViaOnPremises', 'WhenChanged')),
        ('Transport rules', 'Get-TransportRule', 'exo-03-transport-rules', $false, @('Name', 'State', 'Priority', 'Mode', 'SetSCL', 'SetHeaderName', 'SetHeaderValue', 'SenderIpRanges', 'FromScope', 'SentToScope', 'HeaderContainsMessageHeader', 'Description', 'WhenChanged')),
        ('EOP content filter', 'Get-HostedContentFilterPolicy', 'exo-04-eop-content-filter', $false, $null),
        ('EOP connection filter', 'Get-HostedConnectionFilterPolicy', 'exo-04-eop-connection-filter', $false, $null),
        ('EOP anti-malware', 'Get-MalwareFilterPolicy', 'exo-04-eop-malware', $false, $null),
        ('Anti-phish', 'Get-AntiPhishPolicy', 'exo-04-antiphish', $false, $null),
        ('Outbound spam', 'Get-HostedOutboundSpamFilterPolicy', 'exo-04-outbound-spam', $false, $null),
        ('Preset policy rules (EOP)', 'Get-EOPProtectionPolicyRule', 'exo-04-preset-rules-eop', $false, @('Name', 'State', 'Priority', 'SentTo', 'SentToMemberOf', 'RecipientDomainIs', 'ExceptIfSentTo', 'ExceptIfSentToMemberOf', 'ExceptIfRecipientDomainIs')),
        ('Preset policy rules (MDO)', 'Get-ATPProtectionPolicyRule', 'exo-04-preset-rules-mdo', $false, @('Name', 'State', 'Priority', 'SentTo', 'SentToMemberOf', 'RecipientDomainIs', 'ExceptIfSentTo', 'ExceptIfSentToMemberOf', 'ExceptIfRecipientDomainIs')),
        ('MDO Safe Links', 'Get-SafeLinksPolicy', 'exo-05-mdo-safelinks', $false, $null),
        ('MDO Safe Attachments', 'Get-SafeAttachmentPolicy', 'exo-05-mdo-safeattachments', $false, $null),
        ('MDO global settings', 'Get-AtpPolicyForO365', 'exo-05-mdo-global', $false, $null),
        ('External sender tag', 'Get-ExternalInOutlook', 'exo-13-external-in-outlook', $false, $null),
        ('User reported settings', 'Get-ReportSubmissionPolicy', 'exo-13-report-submission', $false, $null),
        ('Quarantine policies', 'Get-QuarantinePolicy', 'exo-05-quarantine-policies', $false, @('Name', 'EndUserQuarantinePermissions', 'ESNEnabled', 'QuarantinePolicyType', 'EndUserQuarantinePermissionsValue')),
        ('Remote domains', 'Get-RemoteDomain', 'exo-06-remote-domains', $false, @('Name', 'DomainName', 'AutoForwardEnabled', 'AutoReplyEnabled', 'AllowedOOFType', 'TNEFEnabled')),
        ('Sharing policies', 'Get-SharingPolicy', 'exo-06-sharing-policies', $false, $null),
        ('OWA mailbox policies', 'Get-OwaMailboxPolicy', 'exo-06-owa-policies', $false, @('Name', 'IsDefault', 'OfflineEnabledWin', 'OfflineEnabledWeb', 'ThirdPartyFileProvidersEnabled', 'ConditionalAccessPolicy', 'LinkedInEnabled')),
        ('ActiveSync org settings', 'Get-ActiveSyncOrganizationSettings', 'exo-07-eas-org-settings', $true, $null),
        ('Mobile device mailbox policies', 'Get-MobileDeviceMailboxPolicy', 'exo-07-mobile-device-policies', $false, $null),
        ('Role groups', 'Get-RoleGroup', 'exo-08-role-groups', $false, @('Name', 'Members', 'Roles'))
    )
    foreach ($step in $simple) {
        $label, $cmd, $name, $single, $props = $step
        Invoke-PostureStep -Label $label -Folder $Folder -Script {
            $objects = & $exo $cmd
            $rows = @(& $flat $objects $props)   # @( ) outside the call: a one-element array unrolls on return
            if ($single) { & $saveOne $(if ($rows.Count -gt 0) { $rows[0] } else { [ordered]@{} }) $name } else { & $save $rows $name $false }
        } | Out-Null
    }

    if (-not $SkipMailboxEnumeration) {
        # The two mailbox lists are the long reads here. Exchange has no page link to carry on from, so a list that
        # stopped part way is read again whole; one that finished in this run is kept when the run is resumed.
        $keepFiles = { param($kept) foreach ($f in @($kept.files)) { $files.Add((Join-Path $Folder "$([string]$f.name).json")) } }
        # Streamed as Exchange returns them: rows written one at a time, the summaries and the forwarding list kept.
        Invoke-PostureStep -Label 'Mailboxes' -Folder $Folder -KeepDone -WhenKept $keepFiles -Script {
            $byType = @{}; $forwarding = [System.Collections.Generic.List[object]]::new()
            $stream = Open-PostureEvidenceStream -Folder $Folder -Name 'exo-09-mailboxes' -Csv -Confirm:$false
            try {
                Invoke-PostureExoCommand -Name 'Get-EXOMailbox' -Parameters @{ ResultSize = 'Unlimited'; Properties = @('RecipientTypeDetails', 'LitigationHoldEnabled', 'InPlaceHolds', 'ArchiveStatus', 'ForwardingSmtpAddress', 'ForwardingAddress', 'DeliverToMailboxAndForward', 'AuditEnabled', 'WhenMailboxCreated', 'ExternalDirectoryObjectId') } -OnItem {
                    param($m)
                    $row = [ordered]@{
                        UserPrincipalName = [string]$m.UserPrincipalName; DisplayName = [string]$m.DisplayName; RecipientTypeDetails = [string]$m.RecipientTypeDetails; LitigationHoldEnabled = [bool]$m.LitigationHoldEnabled
                        InPlaceHoldCount = @($m.InPlaceHolds | Where-Object { $_ }).Count; ArchiveStatus = [string]$m.ArchiveStatus; ForwardingSmtpAddress = [string]$m.ForwardingSmtpAddress; ForwardingAddress = [string]$m.ForwardingAddress
                        DeliverToMailboxAndForward = [bool]$m.DeliverToMailboxAndForward; AuditEnabled = [bool]$m.AuditEnabled; WhenMailboxCreated = $m.WhenMailboxCreated; ExternalDirectoryObjectId = [string]$m.ExternalDirectoryObjectId
                    }
                    Add-PostureEvidenceRow -Stream $stream -Row $row
                    $t = $row.RecipientTypeDetails; $byType[$t] = 1 + $(if ($byType.ContainsKey($t)) { $byType[$t] } else { 0 })
                    if ($row.ForwardingSmtpAddress -or $row.ForwardingAddress) { $forwarding.Add($row) }
                }
                $files.Add((Close-PostureEvidenceStream -Stream $stream))
            }
            catch { Stop-PostureEvidenceStream -Stream $stream -Confirm:$false; throw }
            & $save @($byType.Keys | ForEach-Object { [ordered]@{ Name = $_; Count = $byType[$_] } }) 'exo-09-mailboxes-by-type' $true
            & $save @($forwarding) 'exo-09-mailboxes-with-forwarding' $true
        } | Out-Null
        Invoke-PostureStep -Label 'CAS mailbox protocols' -Folder $Folder -KeepDone -WhenKept $keepFiles -Script {
            $sum = [ordered]@{ Total = 0; ImapEnabled = 0; PopEnabled = 0; ActiveSyncEnabled = 0; SmtpAuthExplicitlyEnabled = 0 }
            $stream = Open-PostureEvidenceStream -Folder $Folder -Name 'exo-10-cas-mailboxes' -Csv -Confirm:$false
            try {
                Invoke-PostureExoCommand -Name 'Get-EXOCASMailbox' -Parameters @{ ResultSize = 'Unlimited'; Properties = @('ActiveSyncEnabled', 'ImapEnabled', 'PopEnabled', 'SmtpClientAuthenticationDisabled', 'OWAEnabled', 'MAPIEnabled', 'EwsEnabled') } -OnItem {
                    param($c)
                    $row = [ordered]@{ PrimarySmtpAddress = [string]$c.PrimarySmtpAddress; ActiveSyncEnabled = [bool]$c.ActiveSyncEnabled; ImapEnabled = [bool]$c.ImapEnabled; PopEnabled = [bool]$c.PopEnabled; SmtpClientAuthenticationDisabled = $c.SmtpClientAuthenticationDisabled; OWAEnabled = [bool]$c.OWAEnabled; MAPIEnabled = [bool]$c.MAPIEnabled; EwsEnabled = $c.EwsEnabled }
                    Add-PostureEvidenceRow -Stream $stream -Row $row
                    $sum.Total++
                    if ($row.ImapEnabled) { $sum.ImapEnabled++ }
                    if ($row.PopEnabled) { $sum.PopEnabled++ }
                    if ($row.ActiveSyncEnabled) { $sum.ActiveSyncEnabled++ }
                    if ($row.SmtpClientAuthenticationDisabled -eq $false) { $sum.SmtpAuthExplicitlyEnabled++ }
                }
                $files.Add((Close-PostureEvidenceStream -Stream $stream))
            }
            catch { Stop-PostureEvidenceStream -Stream $stream -Confirm:$false; throw }
            & $saveOne $sum 'exo-10-cas-summary'
        } | Out-Null
        Invoke-PostureStep -Label 'Exchange Online PowerShell access' -Folder $Folder -Script {
            # Not read at all when the Exchange Online PowerShell app is closed to everyone but the people assigned to
            # it: the Entra collector's service principals in this folder say so, and EM-025 passes on that alone.
            $tools = Get-PostureAdminToolRestriction -Evidence $Folder
            $exoApp = $(if ($tools) { @($tools | Where-Object { $_.appId -eq 'fb78d390-0c51-40cd-8e17-fdbfab77341b' })[0] })
            if ($exoApp -and $exoApp.restricted -eq $true) {
                & $saveOne ([ordered]@{ RemotePowerShellEnabled = $null; NonAdmin = $null; Listed = 0; AdminsExcluded = $false; Skipped = 'The Exchange Online PowerShell app is closed to everyone but the people assigned to it, so the per-user setting was not read.' }) 'exo-12-remote-powershell-summary'
                return
            }
            # The setting is on for every user unless someone turned it off, so the answer is most of the directory.
            # Everyone is counted. The list keeps the first 500 accounts that are people (shared, room and equipment
            # mailboxes do not sign in) and, when the role holders are in this folder, not administrators: those are
            # the accounts EM-025 is about. The filter on RemotePowerShellEnabled runs in Exchange (verify on a large
            # tenant that it is honoured server-side).
            $adminsKnown = Test-Path -LiteralPath (Join-Path $Folder '04-role-assignments-active.json')
            $admins = $(if ($adminsKnown) { (Get-PostureRoleHolder -Folder $Folder).upns })
            $count = @{ Enabled = 0; NonAdmin = 0; Listed = 0 }
            $stream = Open-PostureEvidenceStream -Folder $Folder -Name 'exo-12-remote-powershell-users' -Csv -Confirm:$false
            try {
                Invoke-PostureExoCommand -Name 'Get-User' -Parameters @{ ResultSize = 'Unlimited'; Filter = "RemotePowerShellEnabled -eq 'True'" } -OnItem {
                    param($u)
                    $count.Enabled++
                    if ([string]$u.RecipientTypeDetails -match '^(SharedMailbox|RoomMailbox|EquipmentMailbox|SchedulingMailbox)$') { return }
                    if ($adminsKnown -and $admins.Contains([string]$u.UserPrincipalName)) { return }
                    $count.NonAdmin++
                    if ($count.Listed -ge 500) { return }
                    Add-PostureEvidenceRow -Stream $stream -Row ([ordered]@{ UserPrincipalName = [string]$u.UserPrincipalName; RecipientTypeDetails = [string]$u.RecipientTypeDetails })
                    $count.Listed++
                }
                $files.Add((Close-PostureEvidenceStream -Stream $stream))
            }
            catch { Stop-PostureEvidenceStream -Stream $stream -Confirm:$false; throw }
            & $saveOne ([ordered]@{ RemotePowerShellEnabled = $count.Enabled; NonAdmin = $count.NonAdmin; Listed = $count.Listed; AdminsExcluded = [bool]$adminsKnown }) 'exo-12-remote-powershell-summary'
        } | Out-Null
    }

    Invoke-PostureStep -Label 'Attack simulations' -Folder $Folder -Script {
        $ctx = try { Assert-PostureGraphScope -RequiredScope 'AttackSimulation.Read.All' } catch { $null }
        if (-not $ctx) { Write-Verbose 'AttackSimulation.Read.All not granted; skipping attack simulations.'; return }
        $sims = @(Invoke-PostureGraphRequest -Uri 'security/attackSimulation/simulations' -ApiVersion v1.0)
        & $save @($sims | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = $_.displayName; Status = $_.status; AttackType = $_.attackType; AttackTechnique = $_.attackTechnique; LaunchDateTime = $_.launchDateTime; CompletionDateTime = $_.completionDateTime; IsAutomated = $_.isAutomated } }) 'exo-11-attack-simulations' $true
    } | Out-Null

    Invoke-PostureStep -Label 'Mail DNS' -Folder $Folder -Script {
        $domains = @(& $exo 'Get-AcceptedDomain' | Where-Object { [string]$_.DomainType -eq 'Authoritative' -and [string]$_.DomainName -notmatch '(?i)\.onmicrosoft\.com$' } | ForEach-Object { [string]$_.DomainName })
        # A lookup that fails (a timeout, a server failure) is recorded as failed, by record, in LookupFailed: the
        # checks then read that record as unknown for the domain, never as "not published".
        $rows = foreach ($d in $domains) {
            $failed = [System.Collections.Generic.List[string]]::new()
            $lookup = { param([string] $Record, [string] $Name, [string] $Type) try { @(Resolve-PostureDnsRecord -Name $Name -Type $Type) } catch { Write-Verbose $_.Exception.Message; $failed.Add($Record); @() } }
            $txt = @(& $lookup 'SPF' $d 'TXT')
            [ordered]@{
                Domain = $d
                MX     = (@(& $lookup 'MX' $d 'MX') -join ' | ')
                SPF    = (@($txt | Where-Object { $_ -match '^v=spf1' }) -join '')
                DMARC  = (@(& $lookup 'DMARC' "_dmarc.$d" 'TXT' | Where-Object { $_ -match '^v=DMARC1' }) -join '')
                MTASTS = (@(& $lookup 'MTASTS' "_mta-sts.$d" 'TXT' | Where-Object { $_ -match '^v=STSv1' }) -join '')
                TLSRPT = (@(& $lookup 'TLSRPT' "_smtp._tls.$d" 'TXT' | Where-Object { $_ -match '^v=TLSRPTv1' }) -join '')
                LookupFailed = ($failed -join ';')
            }
        }
        & $save @($rows) 'dns-01-mail-records' $true
    } | Out-Null

    $errorsPath = Join-Path (Get-PostureRunLayout -Folder $Folder).errors 'errors.txt'
    return @{ files = $files.ToArray(); errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath }) }
}
