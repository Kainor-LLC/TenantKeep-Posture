# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PurviewFixtureObject {
    <#
    .SYNOPSIS
        Synthetic Security and Compliance cmdlet output by cmdlet name, for mocking Invoke-PostureExoCommand. Every value is made up.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name)

    $o = { param([hashtable] $h) [pscustomobject]$h }
    switch ($Name) {
        'Get-Label' {
            & $o @{ DisplayName = 'Confidential'; Name = 'confidential'; Guid = 'l1'; Priority = 2; ContentType = 'File, Email, Site, UnifiedGroup'; ParentId = $null; Disabled = $false; Tooltip = 'x'; EncryptionEnabled = $true; SiteAndGroupProtectionEnabled = $true }
            & $o @{ DisplayName = 'General'; Name = 'general'; Guid = 'l2'; Priority = 1; ContentType = 'File, Email'; ParentId = $null; Disabled = $false; Tooltip = 'x'; EncryptionEnabled = $false; SiteAndGroupProtectionEnabled = $false }
        }
        'Get-LabelPolicy' { & $o @{ Name = 'Global policy'; Enabled = $true; Mode = 'Enforce'; Type = 'PublishLabels'; Labels = @('l1', 'l2'); Workload = 'Exchange, SharePoint, OneDriveForBusiness, ModernGroup'; ExchangeLocation = @('All'); SharePointLocation = @('All'); OneDriveLocation = @('All'); ModernGroupLocation = @('All') } }
        'Get-AutoSensitivityLabelPolicy' { & $o @{ Name = 'Auto PII'; Enabled = $true; Mode = 'TestWithoutNotifications'; ApplySensitivityLabel = 'l1'; Workload = 'SharePoint' } }
        'Get-DlpCompliancePolicy' {
            & $o @{ Name = 'Credit cards'; Enabled = $true; Mode = 'Enable'; Priority = 0; Workload = 'Exchange, SharePoint, OneDriveForBusiness'; ExchangeLocation = @('All'); SharePointLocation = @('All'); OneDriveLocation = @('All'); TeamsLocation = @(); EndpointDlpLocation = @() }
            & $o @{ Name = 'Teams test'; Enabled = $true; Mode = 'TestWithNotifications'; Priority = 1; Workload = 'Teams'; TeamsLocation = @('All') }
        }
        'Get-DlpComplianceRule' { & $o @{ Name = 'Block CC external'; ParentPolicyName = 'Credit cards'; Disabled = $false; Priority = 0; ReportSeverityLevel = 'High'; BlockAccess = $true; NotifyUser = @('LastModifier') } }
        'Get-RetentionCompliancePolicy' { & $o @{ Name = 'Mail 7y'; Enabled = $true; Mode = 'Enforce'; Workload = 'Exchange'; DistributionStatus = 'Success'; ExchangeLocation = @('All'); SharePointLocation = @() } }
        'Get-RetentionComplianceRule' { & $o @{ Name = 'Mail 7y rule'; Policy = 'Mail 7y'; RetentionDuration = 2555; RetentionComplianceAction = 'Keep'; ExpirationDateOption = 'ModificationAgeInDays'; Disabled = $false } }
        'Get-ComplianceTag' { & $o @{ Name = 'Contract'; RetentionAction = 'KeepAndDelete'; RetentionDuration = 3650; RetentionType = 'ModificationAgeInDays'; IsRecordLabel = $true; IsRegulatoryRecord = $false } }
        'Get-InsiderRiskPolicy' { @() }
        'Get-SupervisoryReviewPolicyV2' { @() }
        'Get-InformationBarrierPolicy' { @() }
        'Get-UnifiedAuditLogRetentionPolicy' { & $o @{ Name = 'One year'; Priority = 1; RetentionDuration = 'TwelveMonths'; RecordTypes = @('ExchangeItem'); UserIds = @() } }
        'Get-ComplianceCase' { & $o @{ Name = 'HR-2026-01'; Status = 'Active'; CaseType = 'eDiscovery'; CreatedDateTime = [datetime]'2026-02-01' } }
        'Get-ProtectionAlert' { & $o @{ Name = 'Elevation of Exchange admin privilege'; Disabled = $false; Severity = 'Medium'; Category = 'AccessGovernance'; ThreatType = 'Activity'; IsSystemRule = $true } }
        'Get-RoleGroup' {
            & $o @{ Name = 'Compliance Administrator'; Members = @('admin1@contoso.example', 'admin2@contoso.example', 'admin3@contoso.example'); Roles = @('Compliance Administrator') }
            & $o @{ Name = 'Organization Management'; Members = @('admin1@contoso.example', 'admin4@contoso.example', 'admin5@contoso.example', 'admin6@contoso.example'); Roles = @('Organization Configuration') }
            & $o @{ Name = 'Reviewer'; Members = @('reviewer@contoso.example'); Roles = @('Review') }
        }
        default { throw "Fixture has no output for $Name" }
    }
}
