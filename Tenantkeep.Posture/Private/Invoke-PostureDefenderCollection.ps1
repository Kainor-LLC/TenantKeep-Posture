# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureDefenderCollection {
    <#
    .SYNOPSIS
        The Defender effective-state collector (spec 4.11, Defender half, and the scores of 4.12) through Microsoft
        Graph: advanced hunting for device onboarding, sensor health, antivirus mode, secure configuration assessment
        and vulnerabilities; security incidents; Secure Score and its control profiles.
    .DESCRIPTION
        Everything is a Graph read on the signed-in session: advanced hunting is a query-style POST
        (security/runHuntingQuery) that changes nothing. Scopes: ThreatHunting.Read.All (hunting),
        SecurityIncident.Read.All (incidents), SecurityEvents.Read.All (Secure Score). Hunting answers at most 10,000
        rows per query, so the device tables are read in 16 shards by the first character of the device id.
        Licence: Defender for Endpoint P2 for the vulnerability and configuration tables (verify: P1 answers the
        DeviceInfo table only).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [datetime] $AsOf = [datetime]::UtcNow
    )

    $ErrorActionPreference = 'Stop'
    $files = [System.Collections.Generic.List[string]]::new()
    $save = { param($Data, [string] $Name, [bool] $Csv = $false) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data -AsArray -Csv:$Csv)) }
    $saveOne = { param($Data, [string] $Name) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data)) }
    $get = { param([string] $Uri, [string] $Api = 'v1.0') @(Invoke-PostureGraphRequest -Uri $Uri -ApiVersion $Api) }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $hunt = {
        param([string] $Query)
        # Advanced hunting: a query in the body, rows in the answer, nothing written.
        $r = Invoke-PostureGraphRequest -Uri 'security/runHuntingQuery' -Method 'POST' -Body @{ Query = $Query } -ApiVersion 'v1.0'   # posture:read-only-post
        @(& $v $r 'results')
    }
    $huntSharded = {
        param([string] $Table, [string] $Rest)
        # 16 shards by the first hex character of DeviceId keep each answer under the 10,000-row cap.
        $all = [System.Collections.Generic.List[object]]::new()
        foreach ($c in '0123456789abcdef'.ToCharArray()) { foreach ($row in @(& $hunt "$Table | where DeviceId startswith '$c' $Rest")) { $all.Add($row) } }
        $all.ToArray()
    }
    $group = { param($rows, [string[]] $keys) @(@($rows | ForEach-Object { [pscustomobject]$_ }) | Group-Object -Property $keys | ForEach-Object { [ordered]@{ Name = $_.Name; Count = $_.Count } } | Sort-Object { -$_.Count }) }

    Invoke-PostureStep -Label 'Defender devices' -Folder $Folder -Script {
        $rows = @(& $huntSharded 'DeviceInfo' '| where Timestamp > ago(7d) | summarize arg_max(Timestamp, *) by DeviceId | project DeviceId, DeviceName, OSPlatform, OSVersionInfo, OnboardingStatus, SensorHealthState, ExposureLevel, MachineGroup, JoinType, AadDeviceId, IsAzureADJoined, DeviceType, Timestamp')
        $flat = @($rows | ForEach-Object { [ordered]@{ DeviceId = (& $v $_ 'DeviceId'); DeviceName = (& $v $_ 'DeviceName'); OSPlatform = (& $v $_ 'OSPlatform'); OSVersionInfo = (& $v $_ 'OSVersionInfo'); OnboardingStatus = (& $v $_ 'OnboardingStatus'); SensorHealthState = (& $v $_ 'SensorHealthState'); ExposureLevel = (& $v $_ 'ExposureLevel'); MachineGroup = (& $v $_ 'MachineGroup'); JoinType = (& $v $_ 'JoinType'); AadDeviceId = (& $v $_ 'AadDeviceId'); IsAzureADJoined = (& $v $_ 'IsAzureADJoined'); DeviceType = (& $v $_ 'DeviceType'); LastSeen = (& $v $_ 'Timestamp') } })
        & $save $flat 'def-01-devices' $true
        & $saveOne ([ordered]@{
                Devices = $flat.Count
                Onboarded = @($flat | Where-Object { $_.OnboardingStatus -eq 'Onboarded' }).Count
                ByPlatformOnboarding = (& $group $flat @('OSPlatform', 'OnboardingStatus'))
                BySensorHealth = (& $group $flat @('SensorHealthState'))
                HighExposure = @($flat | Where-Object { $_.ExposureLevel -eq 'High' }).Count
            }) 'def-01-devices-summary'
    } | Out-Null

    Invoke-PostureStep -Label 'Defender antivirus state' -Folder $Folder -Script {
        # DeviceTvmInfoGathering carries the antivirus mode and signature state as AdditionalFields. (verify) field names and AvMode values: 0 active, 1 passive, 2 disabled, 4 EDR block mode
        $rows = @(& $huntSharded 'DeviceTvmInfoGathering' '| where Timestamp > ago(7d) | summarize arg_max(Timestamp, *) by DeviceId | extend AvMode = tostring(AdditionalFields.AvMode), AvIsSignatureUpToDate = tostring(AdditionalFields.AvIsSignatureUpToDate), AvIsEngineUpToDate = tostring(AdditionalFields.AvIsEngineUpToDate), AvIsPlatformUpToDate = tostring(AdditionalFields.AvIsPlatformUpToDate), AvSignatureVersion = tostring(AdditionalFields.AvSignatureVersion) | project DeviceId, DeviceName, OSPlatform, AvMode, AvIsSignatureUpToDate, AvIsEngineUpToDate, AvIsPlatformUpToDate, AvSignatureVersion, Timestamp')
        $flat = @($rows | ForEach-Object { [ordered]@{ DeviceId = (& $v $_ 'DeviceId'); DeviceName = (& $v $_ 'DeviceName'); OSPlatform = (& $v $_ 'OSPlatform'); AvMode = (& $v $_ 'AvMode'); AvIsSignatureUpToDate = (& $v $_ 'AvIsSignatureUpToDate'); AvIsEngineUpToDate = (& $v $_ 'AvIsEngineUpToDate'); AvIsPlatformUpToDate = (& $v $_ 'AvIsPlatformUpToDate'); AvSignatureVersion = (& $v $_ 'AvSignatureVersion'); LastSeen = (& $v $_ 'Timestamp') } })
        & $save $flat 'def-02-av-state' $true
        & $saveOne ([ordered]@{ Devices = $flat.Count; ByMode = (& $group $flat @('AvMode')); SignatureOutOfDate = @($flat | Where-Object { [string]$_.AvIsSignatureUpToDate -eq 'false' }).Count }) 'def-02-av-state-summary'
    } | Out-Null

    Invoke-PostureStep -Label 'Defender secure configuration assessment' -Folder $Folder -Script {
        # One row per configuration with applicable and compliant device counts, named from the KB table; the facts match on names and subcategory.
        $rows = @(& $hunt 'DeviceTvmSecureConfigurationAssessment | where IsApplicable == 1 | summarize Devices = dcount(DeviceId), Compliant = dcountif(DeviceId, IsCompliant == 1) by ConfigurationId | join kind=leftouter (DeviceTvmSecureConfigurationAssessmentKB | project ConfigurationId, ConfigurationName, ConfigurationCategory, ConfigurationSubcategory, ConfigurationImpact) on ConfigurationId | project ConfigurationId, ConfigurationName, ConfigurationCategory, ConfigurationSubcategory, ConfigurationImpact, Devices, Compliant')
        & $save @($rows | ForEach-Object { $d = [int](& $v $_ 'Devices'); $c = [int](& $v $_ 'Compliant'); [ordered]@{ ConfigurationId = (& $v $_ 'ConfigurationId'); ConfigurationName = (& $v $_ 'ConfigurationName'); Category = (& $v $_ 'ConfigurationCategory'); Subcategory = (& $v $_ 'ConfigurationSubcategory'); Impact = (& $v $_ 'ConfigurationImpact'); Devices = $d; Compliant = $c; CompliantPct = $(if ($d -gt 0) { [Math]::Round(100.0 * $c / $d, 1) } else { $null }) } }) 'def-03-secure-config' $true
    } | Out-Null

    Invoke-PostureStep -Label 'Defender vulnerabilities' -Folder $Folder -Script {
        $summary = @(& $hunt 'DeviceTvmSoftwareVulnerabilities | where VulnerabilitySeverityLevel == "Critical" | join kind=inner (DeviceTvmSoftwareVulnerabilitiesKB | project CveId, PublishedDate, CvssScore) on CveId | summarize Devices = dcount(DeviceId), Cves = dcount(CveId), CvesOver30d = dcountif(CveId, PublishedDate < ago(30d)), DevicesOver30d = dcountif(DeviceId, PublishedDate < ago(30d))')
        $s = $(if ($summary.Count -gt 0) { $summary[0] } else { @{} })
        & $saveOne ([ordered]@{ CriticalCves = [int](& $v $s 'Cves'); DevicesWithCriticalCves = [int](& $v $s 'Devices'); CriticalCvesOver30d = [int](& $v $s 'CvesOver30d'); DevicesWithCriticalCvesOver30d = [int](& $v $s 'DevicesOver30d') }) 'def-04-vulnerabilities-summary'
        $top = @(& $hunt 'DeviceTvmSoftwareVulnerabilities | where VulnerabilitySeverityLevel == "Critical" | join kind=inner (DeviceTvmSoftwareVulnerabilitiesKB | project CveId, PublishedDate, CvssScore) on CveId | summarize Devices = dcount(DeviceId), SoftwareName = any(SoftwareName), SoftwareVendor = any(SoftwareVendor), CvssScore = any(CvssScore), PublishedDate = any(PublishedDate) by CveId | top 50 by Devices desc')
        & $save @($top | ForEach-Object { [ordered]@{ CveId = (& $v $_ 'CveId'); SoftwareName = (& $v $_ 'SoftwareName'); SoftwareVendor = (& $v $_ 'SoftwareVendor'); CvssScore = (& $v $_ 'CvssScore'); PublishedDate = (& $v $_ 'PublishedDate'); Devices = (& $v $_ 'Devices') } }) 'def-04-vulnerabilities-top' $true
    } | Out-Null

    Invoke-PostureStep -Label 'Defender incidents' -Folder $Folder -Script {
        # SecurityIncident.Read.All; active incidents only.
        $incidents = & $get "security/incidents?`$filter=status eq 'active'&`$select=id,displayName,severity,status,assignedTo,createdDateTime,lastUpdateDateTime,classification,determination&`$top=50"
        $rows = @($incidents | ForEach-Object { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); Severity = (& $v $_ 'severity'); Status = (& $v $_ 'status'); AssignedTo = (& $v $_ 'assignedTo'); CreatedDateTime = (& $v $_ 'createdDateTime'); LastUpdateDateTime = (& $v $_ 'lastUpdateDateTime'); Classification = (& $v $_ 'classification') } })
        & $save $rows 'def-05-incidents' $true
        $week = $AsOf.AddDays(-7)
        & $saveOne ([ordered]@{ Active = $rows.Count; OpenOver7Days = @($rows | Where-Object { $d = ConvertTo-PostureUtcDateTime $_.CreatedDateTime; $d -and $d -lt $week }).Count; OpenOver7DaysUnassigned = @($rows | Where-Object { -not $_.AssignedTo } | Where-Object { $d = ConvertTo-PostureUtcDateTime $_.CreatedDateTime; $d -and $d -lt $week }).Count; BySeverity = (& $group $rows @('Severity')) }) 'def-05-incidents-summary'
    } | Out-Null

    Invoke-PostureStep -Label 'Secure Score' -Folder $Folder -Script {
        # SecurityEvents.Read.All. The latest score plus the control profiles (spec 4.12); Microsoft's numbers are reported, never the grade.
        $scores = @(& $get 'security/secureScores?$top=1')   # @( ) outside the call: a one-element array unrolls on return
        $s = $(if ($scores.Count -gt 0) { $scores[0] } else { $null })
        $byCategory = [ordered]@{}
        foreach ($c in @(& $v $s 'controlScores')) { $cat = [string](& $v $c 'controlCategory'); if ($cat) { $byCategory[$cat] = [double](& $v $c 'score') + $(if ($byCategory.Contains($cat)) { $byCategory[$cat] } else { 0 }) } }
        & $saveOne ([ordered]@{ Present = [bool]$s; CreatedDateTime = (& $v $s 'createdDateTime'); CurrentScore = (& $v $s 'currentScore'); MaxScore = (& $v $s 'maxScore'); LicensedUserCount = (& $v $s 'licensedUserCount'); ActiveUserCount = (& $v $s 'activeUserCount'); ByCategory = $byCategory; AverageComparativeScores = @(@(& $v $s 'averageComparativeScores') | ForEach-Object { [ordered]@{ Basis = (& $v $_ 'basis'); AverageScore = (& $v $_ 'averageScore') } }) }) 'def-06-secure-score'
        $profiles = & $get 'security/secureScoreControlProfiles?$select=id,title,controlCategory,implementationCost,userImpact,maxScore,actionType,tier,deprecated,controlStateUpdates,rank,remediation'
        & $save @($profiles | Where-Object { (& $v $_ 'deprecated') -ne $true } | ForEach-Object {
                $updates = @(& $v $_ 'controlStateUpdates'); $latest = $(if ($updates.Count -gt 0) { $updates[-1] } else { $null })
                [ordered]@{ Id = $_.id; Title = (& $v $_ 'title'); Category = (& $v $_ 'controlCategory'); MaxScore = (& $v $_ 'maxScore'); ImplementationCost = (& $v $_ 'implementationCost'); UserImpact = (& $v $_ 'userImpact'); ActionType = (& $v $_ 'actionType'); Tier = (& $v $_ 'tier'); Rank = (& $v $_ 'rank'); State = (& $v $latest 'state'); Remediation = (& $v $_ 'remediation') }
            }) 'def-06-secure-score-controls' $true
    } | Out-Null

    $errorsPath = Join-Path $Folder 'errors.txt'
    return @{ files = $files.ToArray(); errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath }) }
}
