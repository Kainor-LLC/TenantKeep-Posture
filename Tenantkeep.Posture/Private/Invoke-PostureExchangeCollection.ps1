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
        ('Org config', 'Get-OrganizationConfig', 'exo-01-orgconfig', $true, @('Name', 'OAuth2ClientProfileEnabled', 'DefaultAuthenticationPolicy', 'AuditDisabled', 'IsDehydrated', 'SendFromAliasEnabled', 'FocusedInboxOn', 'MailTipsAllTipsEnabled', 'EwsEnabled', 'EwsApplicationAccessPolicy', 'ActivityBasedAuthenticationTimeoutEnabled', 'ActivityBasedAuthenticationTimeoutInterval', 'ArcTrustedSealers', 'SmtpClientAuthenticationDisabled', 'CustomerLockboxEnabled')),
        ('Transport config', 'Get-TransportConfig', 'exo-01-transport-config', $true, @('SmtpClientAuthenticationDisabled', 'ExternalPostmasterAddress', 'MaxRecipientEnvelopeLimit', 'DSNConversionMode')),
        ('Authentication policies', 'Get-AuthenticationPolicy', 'exo-01-auth-policies', $false, $null),
        ('Audit config', 'Get-AdminAuditLogConfig', 'exo-01-audit-config', $true, @('UnifiedAuditLogIngestionEnabled', 'UnifiedAuditLogFirstOptInDate', 'AdminAuditLogEnabled')),
        ('Accepted domains', 'Get-AcceptedDomain', 'exo-02-accepted-domains', $false, @('DomainName', 'DomainType', 'Default', 'AuthenticationType', 'InitialDomain')),
        ('DKIM', 'Get-DkimSigningConfig', 'exo-02-dkim', $false, @('Domain', 'Enabled', 'Status', 'Selector1CNAME', 'Selector2CNAME', 'LastChecked', 'RotateOnDate')),
        ('Inbound connectors', 'Get-InboundConnector', 'exo-03-inbound-connectors', $false, @('Name', 'Enabled', 'ConnectorType', 'ConnectorSource', 'RestrictDomainsToIPAddresses', 'RestrictDomainsToCertificate', 'TreatMessagesAsInternal', 'EFSkipLastIP', 'EFSkipIPs', 'EFUsers', 'SenderIPAddresses', 'SenderDomains', 'TlsSenderCertificateName', 'WhenChanged')),
        ('Outbound connectors', 'Get-OutboundConnector', 'exo-03-outbound-connectors', $false, @('Name', 'Enabled', 'ConnectorType', 'UseMXRecord', 'SmartHosts', 'RecipientDomains', 'TlsSettings', 'TlsDomain', 'RouteAllMessagesViaOnPremises', 'WhenChanged')),
        ('Transport rules', 'Get-TransportRule', 'exo-03-transport-rules', $false, @('Name', 'State', 'Priority', 'Mode', 'SetSCL', 'SenderIpRanges', 'FromScope', 'SentToScope', 'HeaderContainsMessageHeader', 'Description', 'WhenChanged')),
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
        Invoke-PostureStep -Label 'Mailboxes' -Folder $Folder -Script {
            $mbx = & $exo 'Get-EXOMailbox' @{ ResultSize = 'Unlimited'; Properties = @('RecipientTypeDetails', 'LitigationHoldEnabled', 'InPlaceHolds', 'ArchiveStatus', 'ForwardingSmtpAddress', 'ForwardingAddress', 'DeliverToMailboxAndForward', 'AuditEnabled', 'WhenMailboxCreated', 'ExternalDirectoryObjectId') }
            $rows = @($mbx | ForEach-Object {
                    [ordered]@{
                        UserPrincipalName = [string]$_.UserPrincipalName; DisplayName = [string]$_.DisplayName; RecipientTypeDetails = [string]$_.RecipientTypeDetails; LitigationHoldEnabled = [bool]$_.LitigationHoldEnabled
                        InPlaceHoldCount = @($_.InPlaceHolds | Where-Object { $_ }).Count; ArchiveStatus = [string]$_.ArchiveStatus; ForwardingSmtpAddress = [string]$_.ForwardingSmtpAddress; ForwardingAddress = [string]$_.ForwardingAddress
                        DeliverToMailboxAndForward = [bool]$_.DeliverToMailboxAndForward; AuditEnabled = [bool]$_.AuditEnabled; WhenMailboxCreated = $_.WhenMailboxCreated; ExternalDirectoryObjectId = [string]$_.ExternalDirectoryObjectId
                    }
                })
            & $save $rows 'exo-09-mailboxes' $true
            & $save @($rows | Group-Object { $_.RecipientTypeDetails } | ForEach-Object { [ordered]@{ Name = $_.Name; Count = $_.Count } }) 'exo-09-mailboxes-by-type' $true
            & $save @($rows | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress }) 'exo-09-mailboxes-with-forwarding' $true
        } | Out-Null
        Invoke-PostureStep -Label 'CAS mailbox protocols' -Folder $Folder -Script {
            $cas = & $exo 'Get-EXOCASMailbox' @{ ResultSize = 'Unlimited'; Properties = @('ActiveSyncEnabled', 'ImapEnabled', 'PopEnabled', 'SmtpClientAuthenticationDisabled', 'OWAEnabled', 'MAPIEnabled', 'EwsEnabled') }
            $rows = @($cas | ForEach-Object { [ordered]@{ PrimarySmtpAddress = [string]$_.PrimarySmtpAddress; ActiveSyncEnabled = [bool]$_.ActiveSyncEnabled; ImapEnabled = [bool]$_.ImapEnabled; PopEnabled = [bool]$_.PopEnabled; SmtpClientAuthenticationDisabled = $_.SmtpClientAuthenticationDisabled; OWAEnabled = [bool]$_.OWAEnabled; MAPIEnabled = [bool]$_.MAPIEnabled; EwsEnabled = $_.EwsEnabled } })
            & $save $rows 'exo-10-cas-mailboxes' $true
            & $saveOne ([ordered]@{
                    Total = $rows.Count
                    ImapEnabled = @($rows | Where-Object { $_.ImapEnabled }).Count
                    PopEnabled = @($rows | Where-Object { $_.PopEnabled }).Count
                    ActiveSyncEnabled = @($rows | Where-Object { $_.ActiveSyncEnabled }).Count
                    SmtpAuthExplicitlyEnabled = @($rows | Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false }).Count
                }) 'exo-10-cas-summary'
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
        $rows = foreach ($d in $domains) {
            $txt = @(Resolve-PostureDnsRecord -Name $d -Type TXT)
            [ordered]@{
                Domain = $d
                MX     = (@(Resolve-PostureDnsRecord -Name $d -Type MX) -join ' | ')
                SPF    = (@($txt | Where-Object { $_ -match '^v=spf1' }) -join '')
                DMARC  = (@(Resolve-PostureDnsRecord -Name "_dmarc.$d" -Type TXT | Where-Object { $_ -match '^v=DMARC1' }) -join '')
                MTASTS = (@(Resolve-PostureDnsRecord -Name "_mta-sts.$d" -Type TXT | Where-Object { $_ -match '^v=STSv1' }) -join '')
                TLSRPT = (@(Resolve-PostureDnsRecord -Name "_smtp._tls.$d" -Type TXT | Where-Object { $_ -match '^v=TLSRPTv1' }) -join '')
            }
        }
        & $save @($rows) 'dns-01-mail-records' $true
    } | Out-Null

    $errorsPath = Join-Path $Folder 'errors.txt'
    return @{ files = $files.ToArray(); errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath }) }
}
