# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-ExchangeFixtureObject {
    <#
    .SYNOPSIS
        Synthetic Exchange Online cmdlet output by cmdlet name, for mocking Invoke-PostureExoCommand. Every value is made up.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name)

    $o = { param([hashtable] $h) [pscustomobject]$h }
    switch ($Name) {
        'Get-OrganizationConfig' { & $o @{ Name = 'contoso.example'; OAuth2ClientProfileEnabled = $true; DefaultAuthenticationPolicy = 'Block Basic'; AuditDisabled = $false; ArcTrustedSealers = @(); SmtpClientAuthenticationDisabled = $true; CustomerLockboxEnabled = $false; Identity = 'contoso.example' } }
        'Get-TransportConfig' { & $o @{ SmtpClientAuthenticationDisabled = $false; ExternalPostmasterAddress = $null; MaxRecipientEnvelopeLimit = 'Unlimited' } }
        'Get-AuthenticationPolicy' { & $o @{ Name = 'Block Basic'; AllowBasicAuthSmtp = $false; AllowBasicAuthImap = $false; AllowBasicAuthPop = $false } }
        'Get-AdminAuditLogConfig' { & $o @{ UnifiedAuditLogIngestionEnabled = $true; UnifiedAuditLogFirstOptInDate = [datetime]'2024-01-01'; AdminAuditLogEnabled = $true } }
        'Get-AcceptedDomain' {
            & $o @{ DomainName = 'contoso.example'; DomainType = 'Authoritative'; Default = $true; AuthenticationType = 'Managed'; InitialDomain = $false }
            & $o @{ DomainName = 'contoso.onmicrosoft.com'; DomainType = 'Authoritative'; Default = $false; AuthenticationType = 'Managed'; InitialDomain = $true }
            & $o @{ DomainName = 'legacy.example'; DomainType = 'Authoritative'; Default = $false; AuthenticationType = 'Managed'; InitialDomain = $false }
        }
        'Get-DkimSigningConfig' {
            & $o @{ Domain = 'contoso.example'; Enabled = $true; Status = 'Valid'; Selector1CNAME = 'selector1-contoso-example._domainkey.contoso.onmicrosoft.com'; Selector2CNAME = 's2'; LastChecked = [datetime]'2026-10-01'; RotateOnDate = [datetime]'2026-12-01' }
            & $o @{ Domain = 'contoso.onmicrosoft.com'; Enabled = $true; Status = 'Valid'; Selector1CNAME = 'a'; Selector2CNAME = 'b'; LastChecked = [datetime]'2026-10-01'; RotateOnDate = [datetime]'2026-12-01' }
            & $o @{ Domain = 'legacy.example'; Enabled = $false; Status = 'CnameMissing'; Selector1CNAME = 'a'; Selector2CNAME = 'b'; LastChecked = $null; RotateOnDate = $null }
        }
        'Get-InboundConnector' {
            & $o @{ Name = 'Gateway inbound'; Enabled = $true; ConnectorType = 'Partner'; ConnectorSource = 'Default'; RestrictDomainsToIPAddresses = $true; RestrictDomainsToCertificate = $false; TreatMessagesAsInternal = $false; EFSkipLastIP = $false; EFSkipIPs = @(); EFUsers = @(); SenderIPAddresses = @('203.0.113.10'); SenderDomains = @('smtp:*;1'); TlsSenderCertificateName = $null; WhenChanged = [datetime]'2026-01-01' }
            & $o @{ Name = 'Old gateway'; Enabled = $false; ConnectorType = 'Partner'; ConnectorSource = 'Default'; RestrictDomainsToIPAddresses = $true; RestrictDomainsToCertificate = $false; TreatMessagesAsInternal = $false; EFSkipLastIP = $false; EFSkipIPs = @(); EFUsers = @(); SenderIPAddresses = @('198.51.100.5'); SenderDomains = @(); TlsSenderCertificateName = $null; WhenChanged = [datetime]'2024-01-01' }
        }
        'Get-OutboundConnector' { & $o @{ Name = 'Gateway outbound'; Enabled = $true; ConnectorType = 'Partner'; UseMXRecord = $false; SmartHosts = @('relay.gateway.example'); RecipientDomains = @('*'); TlsSettings = 'EncryptionOnly'; TlsDomain = $null; RouteAllMessagesViaOnPremises = $false; WhenChanged = [datetime]'2026-01-01' } }
        'Get-TransportRule' {
            & $o @{ Name = 'Bypass spam for gateway'; State = 'Enabled'; Priority = 0; Mode = 'Enforce'; SetSCL = -1; SenderIpRanges = @('203.0.113.0/24'); FromScope = 'NotInOrganization'; SentToScope = $null; HeaderContainsMessageHeader = $null; Description = 'x'; WhenChanged = [datetime]'2026-01-01' }
            & $o @{ Name = 'Bypass spam for partner domain'; State = 'Enabled'; Priority = 1; Mode = 'Enforce'; SetSCL = -1; SenderIpRanges = @(); FromScope = 'NotInOrganization'; SentToScope = $null; HeaderContainsMessageHeader = $null; Description = 'x'; WhenChanged = [datetime]'2026-01-01' }
            & $o @{ Name = 'Disclaimer'; State = 'Enabled'; Priority = 2; Mode = 'Enforce'; SetSCL = $null; SenderIpRanges = @(); FromScope = $null; SentToScope = 'NotInOrganization'; HeaderContainsMessageHeader = $null; Description = 'x'; WhenChanged = [datetime]'2026-01-01' }
        }
        'Get-HostedContentFilterPolicy' {
            & $o @{ Name = 'Default'; IsDefault = $true; ZapEnabled = $true; SpamZapEnabled = $true; PhishZapEnabled = $true; HighConfidencePhishQuarantineTag = 'AdminOnlyAccessPolicy'; BulkThreshold = 6 }
            & $o @{ Name = 'Standard Preset Security Policy1234'; IsDefault = $false; ZapEnabled = $true; SpamZapEnabled = $true; PhishZapEnabled = $false; HighConfidencePhishQuarantineTag = 'DefaultFullAccessPolicy'; BulkThreshold = 6 }
        }
        'Get-HostedConnectionFilterPolicy' { & $o @{ Name = 'Default'; IPAllowList = @('198.51.100.0/24', '203.0.113.77'); IPBlockList = @(); EnableSafeList = $false } }
        'Get-MalwareFilterPolicy' { & $o @{ Name = 'Default'; ZapEnabled = $true; EnableFileFilter = $true; FileTypes = @('exe', 'js') } }
        'Get-AntiPhishPolicy' {
            & $o @{ Name = 'Office365 AntiPhish Default'; Enabled = $true; IsDefault = $true; EnableSpoofIntelligence = $true; HonorDmarcPolicy = $true; EnableTargetedUserProtection = $false; TargetedUsersToProtect = @(); EnableOrganizationDomainsProtection = $true; EnableMailboxIntelligence = $true; PhishThresholdLevel = 1 }
            & $o @{ Name = 'Execs'; Enabled = $true; IsDefault = $false; EnableSpoofIntelligence = $false; HonorDmarcPolicy = $true; EnableTargetedUserProtection = $true; TargetedUsersToProtect = @('CEO;ceo@contoso.example'); EnableOrganizationDomainsProtection = $true; EnableMailboxIntelligence = $true; PhishThresholdLevel = 3 }
        }
        'Get-HostedOutboundSpamFilterPolicy' {
            & $o @{ Name = 'Default'; AutoForwardingMode = 'Off'; RecipientLimitExternalPerHour = 500 }
            & $o @{ Name = 'Allow forward for finance'; AutoForwardingMode = 'On'; RecipientLimitExternalPerHour = 500 }
        }
        'Get-EOPProtectionPolicyRule' { & $o @{ Name = 'Standard Preset Security Policy'; State = 'Enabled'; Priority = 0; SentTo = @(); SentToMemberOf = @(); RecipientDomainIs = @(); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @(); ExceptIfRecipientDomainIs = @() } }
        'Get-ATPProtectionPolicyRule' { & $o @{ Name = 'Standard Preset Security Policy'; State = 'Enabled'; Priority = 0; SentTo = @(); SentToMemberOf = @('Pilot users'); RecipientDomainIs = @(); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @(); ExceptIfRecipientDomainIs = @() } }
        'Get-SafeLinksPolicy' { & $o @{ Name = 'Standard Preset Security Policy1234'; IsEnabled = $true; EnableSafeLinksForEmail = $true; EnableSafeLinksForTeams = $true; EnableSafeLinksForOffice = $true; ScanUrls = $true; DeliverMessageAfterScan = $true; TrackClicks = $true; AllowClickThrough = $false } }
        'Get-SafeAttachmentPolicy' { & $o @{ Name = 'Standard Preset Security Policy1234'; Enable = $true; Action = 'Block'; Redirect = $false; QuarantineTag = 'AdminOnlyAccessPolicy' } }
        'Get-AtpPolicyForO365' { & $o @{ Name = 'Default'; EnableATPForSPOTeamsODB = $true; EnableSafeDocs = $false; AllowSafeDocsOpen = $false } }
        'Get-QuarantinePolicy' {
            & $o @{ Name = 'AdminOnlyAccessPolicy'; EndUserQuarantinePermissions = 'none'; ESNEnabled = $false; QuarantinePolicyType = 'QuarantinePolicy'; EndUserQuarantinePermissionsValue = 0 }
            & $o @{ Name = 'DefaultFullAccessWithNotificationPolicy'; EndUserQuarantinePermissions = 'full'; ESNEnabled = $true; QuarantinePolicyType = 'QuarantinePolicy'; EndUserQuarantinePermissionsValue = 23 }
        }
        'Get-RemoteDomain' { & $o @{ Name = 'Default'; DomainName = '*'; AutoForwardEnabled = $true; AutoReplyEnabled = $true; AllowedOOFType = 'External'; TNEFEnabled = $null } }
        'Get-SharingPolicy' { & $o @{ Name = 'Default Sharing Policy'; Enabled = $true; Domains = @('Anonymous:CalendarSharingFreeBusySimple') } }
        'Get-OwaMailboxPolicy' { & $o @{ Name = 'OwaMailboxPolicy-Default'; IsDefault = $true; OfflineEnabledWin = $true; OfflineEnabledWeb = $true; ThirdPartyFileProvidersEnabled = $false; ConditionalAccessPolicy = 'Off'; LinkedInEnabled = $false } }
        'Get-ActiveSyncOrganizationSettings' { & $o @{ DefaultAccessLevel = 'Allow'; AdminMailRecipients = @() } }
        'Get-MobileDeviceMailboxPolicy' { & $o @{ Name = 'Default'; IsDefault = $true; PasswordEnabled = $false; RequireDeviceEncryption = $false } }
        'Get-RoleGroup' { & $o @{ Name = 'Organization Management'; Members = @('admin@contoso.example'); Roles = @('Mail Recipients', 'Transport Rules') } }
        'Get-EXOMailbox' {
            & $o @{ UserPrincipalName = 'admin1@contoso.example'; DisplayName = 'Admin One'; RecipientTypeDetails = 'UserMailbox'; LitigationHoldEnabled = $false; InPlaceHolds = @(); ArchiveStatus = 'None'; ForwardingSmtpAddress = 'smtp:someone@gmail.example'; ForwardingAddress = $null; DeliverToMailboxAndForward = $true; AuditEnabled = $true; WhenMailboxCreated = [datetime]'2024-01-01'; ExternalDirectoryObjectId = 'u1' }
            & $o @{ UserPrincipalName = 'admin3@contoso.example'; DisplayName = 'Admin Three'; RecipientTypeDetails = 'UserMailbox'; LitigationHoldEnabled = $true; InPlaceHolds = @('h1'); ArchiveStatus = 'Active'; ForwardingSmtpAddress = 'smtp:admin1@contoso.example'; ForwardingAddress = $null; DeliverToMailboxAndForward = $true; AuditEnabled = $true; WhenMailboxCreated = [datetime]'2024-01-01'; ExternalDirectoryObjectId = 'u3' }
            & $o @{ UserPrincipalName = 'billing@contoso.example'; DisplayName = 'Billing'; RecipientTypeDetails = 'SharedMailbox'; LitigationHoldEnabled = $false; InPlaceHolds = @(); ArchiveStatus = 'None'; ForwardingSmtpAddress = $null; ForwardingAddress = $null; DeliverToMailboxAndForward = $false; AuditEnabled = $true; WhenMailboxCreated = [datetime]'2024-01-01'; ExternalDirectoryObjectId = 'u2' }
            & $o @{ UserPrincipalName = 'support@contoso.example'; DisplayName = 'Support'; RecipientTypeDetails = 'SharedMailbox'; LitigationHoldEnabled = $false; InPlaceHolds = @(); ArchiveStatus = 'None'; ForwardingSmtpAddress = $null; ForwardingAddress = 'Vendor Contact'; DeliverToMailboxAndForward = $false; AuditEnabled = $true; WhenMailboxCreated = [datetime]'2024-01-01'; ExternalDirectoryObjectId = 'blocked-9' }
        }
        'Get-EXOCASMailbox' {
            & $o @{ PrimarySmtpAddress = 'admin1@contoso.example'; ActiveSyncEnabled = $true; ImapEnabled = $true; PopEnabled = $false; SmtpClientAuthenticationDisabled = $null; OWAEnabled = $true; MAPIEnabled = $true; EwsEnabled = $null }
            & $o @{ PrimarySmtpAddress = 'admin3@contoso.example'; ActiveSyncEnabled = $true; ImapEnabled = $false; PopEnabled = $false; SmtpClientAuthenticationDisabled = $false; OWAEnabled = $true; MAPIEnabled = $true; EwsEnabled = $null }
            & $o @{ PrimarySmtpAddress = 'billing@contoso.example'; ActiveSyncEnabled = $false; ImapEnabled = $false; PopEnabled = $false; SmtpClientAuthenticationDisabled = $null; OWAEnabled = $true; MAPIEnabled = $true; EwsEnabled = $null }
            & $o @{ PrimarySmtpAddress = 'support@contoso.example'; ActiveSyncEnabled = $false; ImapEnabled = $false; PopEnabled = $false; SmtpClientAuthenticationDisabled = $null; OWAEnabled = $true; MAPIEnabled = $true; EwsEnabled = $null }
        }
        default { throw "Fixture has no output for $Name" }
    }
}

function Get-ExchangeFixtureDnsRecord {
    <#
    .SYNOPSIS
        Synthetic DNS answers by name and type, for mocking Resolve-PostureDnsRecord.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name, [string] $Type = 'TXT')

    switch ("$Type $Name") {
        'MX contoso.example' { @('0 contoso-example.mail.protection.outlook.com') }
        'TXT contoso.example' { @('v=spf1 include:spf.protection.outlook.com include:_spf.gateway.example -all', 'MS=ms12345678') }
        'TXT _dmarc.contoso.example' { @('v=DMARC1; p=reject; rua=mailto:dmarc@contoso.example; pct=100') }
        'TXT _mta-sts.contoso.example' { @('v=STSv1; id=20260101') }
        'TXT _smtp._tls.contoso.example' { @('v=TLSRPTv1; rua=mailto:tlsrpt@contoso.example') }
        'MX legacy.example' { @('10 mail.legacy.example') }
        'TXT legacy.example' { @('v=spf1 a mx include:a.example include:b.example include:c.example include:d.example include:e.example include:f.example include:g.example include:h.example include:i.example ~all') }
        'TXT _dmarc.legacy.example' { @('v=DMARC1; p=none; rua=mailto:dmarc@legacy.example') }
        default { @() }
    }
}
