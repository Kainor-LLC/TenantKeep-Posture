# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PosturePurviewCollection {
    <#
    .SYNOPSIS
        The A.2 Purview collector through Security and Compliance PowerShell: sensitivity labels and policies,
        auto-labeling, DLP policies and rules, retention policies, rules and labels, insider risk, communication
        compliance, information barriers, audit retention policies, eDiscovery cases, alert policies, role groups.
    .DESCRIPTION
        Needs a Connect-IPPSSession session (ExchangeOnlineManagement 3.x; Compliance Administrator, or Global Reader
        for most reads, verify). Never connects. Purview and Exchange share cmdlet names such as Get-RoleGroup, so run
        this collector in a process of its own, after Connect-IPPSSession, with -Collector Purview. Every cmdlet goes
        through the Get-only entry point; rich objects are projected to scalars before they are written.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Folder)

    $ErrorActionPreference = 'Stop'
    $files = [System.Collections.Generic.List[string]]::new()
    $save = { param($Data, [string] $Name, [bool] $Csv = $false) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data -AsArray -Csv:$Csv)) }
    $exo = { param([string] $Name, [hashtable] $Params = @{}) @(Invoke-PostureExoCommand -Name $Name -Parameters $Params) }
    $flat = { param($Objects, [string[]] $Props) @($Objects | Where-Object { $_ } | ForEach-Object { if ($Props) { $_ | ConvertTo-PostureFlatObject -Property $Props } else { $_ | ConvertTo-PostureFlatObject } }) }

    $steps = @(
        ('Sensitivity labels', 'Get-Label', @{}, 'pv-01-sensitivity-labels', $true, @('DisplayName', 'Name', 'Guid', 'Priority', 'ContentType', 'ParentId', 'Disabled', 'Tooltip', 'EncryptionEnabled', 'EncryptionProtectionType', 'SiteAndGroupProtectionEnabled', 'SiteAndGroupProtectionPrivacy', 'Settings', 'WhenChanged')),
        ('Label policies', 'Get-LabelPolicy', @{}, 'pv-01-label-policies', $false, @('Name', 'Enabled', 'Mode', 'Type', 'Labels', 'Workload', 'ExchangeLocation', 'SharePointLocation', 'OneDriveLocation', 'ModernGroupLocation', 'WhenChanged')),
        ('Auto-labeling policies', 'Get-AutoSensitivityLabelPolicy', @{}, 'pv-01-autolabel-policies', $false, @('Name', 'Enabled', 'Mode', 'ApplySensitivityLabel', 'Workload', 'ExchangeLocation', 'SharePointLocation', 'OneDriveLocation', 'WhenChanged')),
        ('DLP policies', 'Get-DlpCompliancePolicy', @{}, 'pv-02-dlp-policies', $true, @('Name', 'Enabled', 'Mode', 'Priority', 'Workload', 'ExchangeLocation', 'SharePointLocation', 'OneDriveLocation', 'TeamsLocation', 'EndpointDlpLocation', 'WhenCreated', 'WhenChanged')),
        ('DLP rules', 'Get-DlpComplianceRule', @{}, 'pv-02-dlp-rules', $true, @('Name', 'ParentPolicyName', 'Disabled', 'Priority', 'ReportSeverityLevel', 'BlockAccess', 'BlockAccessScope', 'NotifyUser', 'Mode')),
        ('Retention policies', 'Get-RetentionCompliancePolicy', @{ DistributionDetail = $true }, 'pv-03-retention-policies', $false, @('Name', 'Enabled', 'Mode', 'Workload', 'DistributionStatus', 'RestrictiveRetention', 'ExchangeLocation', 'SharePointLocation', 'OneDriveLocation', 'TeamsChatLocation', 'TeamsChannelLocation', 'WhenChanged')),
        ('Retention rules', 'Get-RetentionComplianceRule', @{}, 'pv-03-retention-rules', $true, @('Name', 'Policy', 'RetentionDuration', 'RetentionComplianceAction', 'ExpirationDateOption', 'Disabled')),
        ('Retention labels', 'Get-ComplianceTag', @{}, 'pv-03-retention-labels', $true, @('Name', 'RetentionAction', 'RetentionDuration', 'RetentionType', 'IsRecordLabel', 'IsRegulatoryRecord')),
        ('Insider Risk policies', 'Get-InsiderRiskPolicy', @{}, 'pv-04-insider-risk-policies', $false, @('Name', 'Enabled', 'InsiderRiskScenario', 'WhenChanged')),
        ('Communication Compliance', 'Get-SupervisoryReviewPolicyV2', @{}, 'pv-04-communication-compliance', $false, @('Name', 'Enabled', 'WhenChanged')),
        ('Information barriers', 'Get-InformationBarrierPolicy', @{}, 'pv-04-information-barriers', $false, @('Name', 'State', 'AssignedSegment', 'SegmentsBlocked', 'SegmentsAllowed')),
        ('Audit retention policies', 'Get-UnifiedAuditLogRetentionPolicy', @{}, 'pv-05-audit-retention-policies', $false, @('Name', 'Priority', 'RetentionDuration', 'RecordTypes', 'UserIds')),
        ('eDiscovery cases', 'Get-ComplianceCase', @{}, 'pv-06-ediscovery-cases', $true, @('Name', 'Status', 'CaseType', 'CreatedDateTime')),
        ('Alert policies', 'Get-ProtectionAlert', @{}, 'pv-07-alert-policies', $true, @('Name', 'Disabled', 'Severity', 'Category', 'ThreatType', 'IsSystemRule')),
        ('Purview role groups', 'Get-RoleGroup', @{}, 'pv-08-role-groups', $false, @('Name', 'Members', 'Roles'))
    )
    foreach ($step in $steps) {
        $label, $cmd, $params, $name, $csv, $props = $step
        Invoke-PostureStep -Label $label -Folder $Folder -Script {
            $objects = & $exo $cmd $params
            & $save (& $flat $objects $props) $name $csv
        } | Out-Null
    }

    $errorsPath = Join-Path $Folder 'errors.txt'
    return @{ files = $files.ToArray(); errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath }) }
}
