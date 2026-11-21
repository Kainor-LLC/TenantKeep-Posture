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
    # What the last sharded read covered: rows the service says exist against rows it returned.
    $huntCoverage = @{ expected = [long]0; read = [long]0; shardsShort = 0 }
    $huntSharded = {
        param([string] $Table, [string] $Rest, [scriptblock] $OnRow)
        # 16 shards by the first hex character of DeviceId keep each answer under the row cap of one query. The cap is
        # the service's to change, so one query first asks how many rows each shard has: fewer rows back than that
        # (or rows under a first character no shard asks for) means the list is cut short, and the summary says so
        # instead of the checks reading a short list as whole.
        $huntCoverage.expected = 0; $huntCoverage.read = 0; $huntCoverage.shardsShort = 0
        $expected = @{}
        foreach ($row in @(& $hunt "$Table $Rest | summarize Count = count() by Shard = tolower(substring(DeviceId, 0, 1))")) {
            $expected[[string](& $v $row 'Shard')] = [long](& $v $row 'Count')
            $huntCoverage.expected += [long](& $v $row 'Count')
        }
        # One shard's rows are in memory at a time; each is handed to -OnRow, which writes it and counts it.
        $asked = @{}
        $hex = '0123456789abcdef'.ToCharArray()
        foreach ($c in $hex) {
            $prefix = [string]$c; $asked[$prefix] = $true
            $rows = @(& $hunt "$Table | where DeviceId startswith '$prefix' $Rest")
            $want = [long]$(if ($expected.ContainsKey($prefix)) { $expected[$prefix] } else { 0 })
            if ($rows.Count -lt $want) {
                # Fewer rows than the shard has: the answer met the row cap of one query. The shard is read again in
                # sixteen parts, by the second character of the id, and the fuller of the two answers is kept. A
                # shard that is still short leaves the list marked cut short.
                $parts = [System.Collections.Generic.List[object]]::new()
                foreach ($second in $hex) { foreach ($row in @(& $hunt "$Table | where DeviceId startswith '$prefix$second' $Rest")) { $parts.Add($row) } }
                if ($parts.Count -ge $rows.Count) { $rows = $parts.ToArray() }
            }
            $huntCoverage.read += $rows.Count
            if ($rows.Count -lt $want) { $huntCoverage.shardsShort++ }
            foreach ($row in $rows) { & $OnRow $row }
        }
        foreach ($k in $expected.get_Keys()) { if (-not $asked.ContainsKey($k) -and $expected[$k] -gt 0) { $huntCoverage.shardsShort++ } }
    }
    $coverage = { [ordered]@{ RowsExpected = $huntCoverage.expected; RowsRead = $huntCoverage.read; Truncated = ($huntCoverage.shardsShort -gt 0) } }
    # Counts by a key, as the summaries carry them: most first.
    $bump = { param($map, [string] $key) $map[$key] = 1 + $(if ($map.ContainsKey($key)) { $map[$key] } else { 0 }) }
    $counts = { param($map) @($map.get_Keys() | ForEach-Object { [ordered]@{ Name = $_; Count = $map[$_] } } | Sort-Object { -$_.Count }) }

    # The two device lists have a row per device. Each row is written as its shard arrives and counted into the
    # summary in the same pass; the list is never held whole.
    # Both are kept when they finished in this run and the run is resumed.
    $keepFiles = { param($kept) foreach ($f in @($kept.files)) { $files.Add((Join-Path $Folder "$([string]$f.name).json")) } }
    Invoke-PostureStep -Label 'Defender devices' -Folder $Folder -KeepDone -WhenKept $keepFiles -Script {
        $t = @{ n = 0; onboarded = 0; highExposure = 0; platform = @{}; sensor = @{} }
        $stream = Open-PostureEvidenceStream -Folder $Folder -Name 'def-01-devices' -Csv -Confirm:$false
        try {
            & $huntSharded 'DeviceInfo' '| where Timestamp > ago(7d) | summarize arg_max(Timestamp, *) by DeviceId | project DeviceId, DeviceName, OSPlatform, OSVersionInfo, OnboardingStatus, SensorHealthState, ExposureLevel, MachineGroup, JoinType, AadDeviceId, IsAzureADJoined, DeviceType, Timestamp' {
                param($r)
                $row = [ordered]@{ DeviceId = (& $v $r 'DeviceId'); DeviceName = (& $v $r 'DeviceName'); OSPlatform = (& $v $r 'OSPlatform'); OSVersionInfo = (& $v $r 'OSVersionInfo'); OnboardingStatus = (& $v $r 'OnboardingStatus'); SensorHealthState = (& $v $r 'SensorHealthState'); ExposureLevel = (& $v $r 'ExposureLevel'); MachineGroup = (& $v $r 'MachineGroup'); JoinType = (& $v $r 'JoinType'); AadDeviceId = (& $v $r 'AadDeviceId'); IsAzureADJoined = (& $v $r 'IsAzureADJoined'); DeviceType = (& $v $r 'DeviceType'); LastSeen = (& $v $r 'Timestamp') }
                Add-PostureEvidenceRow -Stream $stream -Row $row
                $t.n++
                if ($row.OnboardingStatus -eq 'Onboarded') { $t.onboarded++ }
                if ($row.ExposureLevel -eq 'High') { $t.highExposure++ }
                & $bump $t.platform "$($row.OSPlatform), $($row.OnboardingStatus)"; & $bump $t.sensor ([string]$row.SensorHealthState)
            }
            $files.Add((Close-PostureEvidenceStream -Stream $stream))
        }
        catch { Stop-PostureEvidenceStream -Stream $stream -Confirm:$false; throw }
        $cov = & $coverage
        & $saveOne ([ordered]@{
                Devices = $t.n
                RowsExpected = $cov.RowsExpected; RowsRead = $cov.RowsRead; Truncated = $cov.Truncated
                Onboarded = $t.onboarded
                ByPlatformOnboarding = (& $counts $t.platform)
                BySensorHealth = (& $counts $t.sensor)
                HighExposure = $t.highExposure
            }) 'def-01-devices-summary'
    } | Out-Null

    Invoke-PostureStep -Label 'Defender antivirus state' -Folder $Folder -KeepDone -WhenKept $keepFiles -Script {
        # DeviceTvmInfoGathering carries the antivirus mode and signature state as AdditionalFields. (verify) field names and AvMode values: 0 active, 1 passive, 2 disabled, 4 EDR block mode
        $t = @{ n = 0; signatureOld = 0; mode = @{} }
        $stream = Open-PostureEvidenceStream -Folder $Folder -Name 'def-02-av-state' -Csv -Confirm:$false
        try {
            & $huntSharded 'DeviceTvmInfoGathering' '| where Timestamp > ago(7d) | summarize arg_max(Timestamp, *) by DeviceId | extend AvMode = tostring(AdditionalFields.AvMode), AvIsSignatureUpToDate = tostring(AdditionalFields.AvIsSignatureUpToDate), AvIsEngineUpToDate = tostring(AdditionalFields.AvIsEngineUpToDate), AvIsPlatformUpToDate = tostring(AdditionalFields.AvIsPlatformUpToDate), AvSignatureVersion = tostring(AdditionalFields.AvSignatureVersion) | project DeviceId, DeviceName, OSPlatform, AvMode, AvIsSignatureUpToDate, AvIsEngineUpToDate, AvIsPlatformUpToDate, AvSignatureVersion, Timestamp' {
                param($r)
                $row = [ordered]@{ DeviceId = (& $v $r 'DeviceId'); DeviceName = (& $v $r 'DeviceName'); OSPlatform = (& $v $r 'OSPlatform'); AvMode = (& $v $r 'AvMode'); AvIsSignatureUpToDate = (& $v $r 'AvIsSignatureUpToDate'); AvIsEngineUpToDate = (& $v $r 'AvIsEngineUpToDate'); AvIsPlatformUpToDate = (& $v $r 'AvIsPlatformUpToDate'); AvSignatureVersion = (& $v $r 'AvSignatureVersion'); LastSeen = (& $v $r 'Timestamp') }
                Add-PostureEvidenceRow -Stream $stream -Row $row
                $t.n++
                if ([string]$row.AvIsSignatureUpToDate -eq 'false') { $t.signatureOld++ }
                & $bump $t.mode ([string]$row.AvMode)
            }
            $files.Add((Close-PostureEvidenceStream -Stream $stream))
        }
        catch { Stop-PostureEvidenceStream -Stream $stream -Confirm:$false; throw }
        $cov = & $coverage
        & $saveOne ([ordered]@{ Devices = $t.n; RowsExpected = $cov.RowsExpected; RowsRead = $cov.RowsRead; Truncated = $cov.Truncated; ByMode = (& $counts $t.mode); SignatureOutOfDate = $t.signatureOld }) 'def-02-av-state-summary'
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
        # Written and counted as the pages arrive.
        $week = $AsOf.AddDays(-7)
        $t = @{ active = 0; old = 0; oldUnassigned = 0; severity = @{} }
        $stream = Open-PostureEvidenceStream -Folder $Folder -Name 'def-05-incidents' -Csv -Confirm:$false
        try {
            $null = Invoke-PostureGraphRequest -Uri "security/incidents?`$filter=status eq 'active'&`$select=id,displayName,severity,status,assignedTo,createdDateTime,lastUpdateDateTime,classification,determination&`$top=50" -ApiVersion 'v1.0' -Label 'Defender incidents' -OnPage {
                param($page)
                foreach ($incident in $page) {
                    $row = ForEach-Object -InputObject $incident -Process { [ordered]@{ Id = $_.id; DisplayName = (& $v $_ 'displayName'); Severity = (& $v $_ 'severity'); Status = (& $v $_ 'status'); AssignedTo = (& $v $_ 'assignedTo'); CreatedDateTime = (& $v $_ 'createdDateTime'); LastUpdateDateTime = (& $v $_ 'lastUpdateDateTime'); Classification = (& $v $_ 'classification') } }
                    Add-PostureEvidenceRow -Stream $stream -Row $row
                    $t.active++
                    & $bump $t.severity ([string]$row.Severity)
                    $created = ConvertTo-PostureUtcDateTime $row.CreatedDateTime
                    if ($created -and $created -lt $week) { $t.old++; if (-not $row.AssignedTo) { $t.oldUnassigned++ } }
                }
            }
            $files.Add((Close-PostureEvidenceStream -Stream $stream))
        }
        catch { Stop-PostureEvidenceStream -Stream $stream -Confirm:$false; throw }
        & $saveOne ([ordered]@{ Active = $t.active; OpenOver7Days = $t.old; OpenOver7DaysUnassigned = $t.oldUnassigned; BySeverity = (& $counts $t.severity) }) 'def-05-incidents-summary'
    } | Out-Null

    Invoke-PostureStep -Label 'Defender incident trend' -Folder $Folder -Script {
        # Every incident created in the last 90 days, counted by week (starting Monday) and severity; only the two
        # fields the count needs are read, and nothing per incident is written.
        $since = $AsOf.ToUniversalTime().Date.AddDays(-90)
        $weeks = [ordered]@{}
        for ($d = $since.AddDays(-(([int]$since.DayOfWeek + 6) % 7)); $d -le $AsOf.ToUniversalTime(); $d = $d.AddDays(7)) { $weeks[$d.ToString('yyyy-MM-dd')] = [ordered]@{ WeekStart = $d.ToString('yyyy-MM-dd'); High = 0; Medium = 0; Low = 0; Informational = 0; Total = 0 } }
        # Counted as the pages arrive: a busy tenant has tens of thousands of incidents in ninety days.
        $seen = @{ n = 0 }
        $null = Invoke-PostureGraphRequest -Uri "security/incidents?`$filter=createdDateTime ge $($since.ToString('yyyy-MM-ddTHH:mm:ssZ'))&`$select=createdDateTime,severity&`$top=50" -ApiVersion 'v1.0' -Label 'Defender incident trend' -OnPage {
            param($page)
            foreach ($i in $page) {
                $seen.n++
                $c = ConvertTo-PostureUtcDateTime (& $v $i 'createdDateTime'); if (-not $c) { continue }
                $ws = $c.Date.AddDays(-(([int]$c.DayOfWeek + 6) % 7)).ToString('yyyy-MM-dd')
                if (-not $weeks.Contains($ws)) { continue }
                $sev = switch ([string](& $v $i 'severity')) { 'high' { 'High' } 'medium' { 'Medium' } 'low' { 'Low' } default { 'Informational' } }
                $weeks[$ws][$sev]++; $weeks[$ws].Total++
            }
        }
        & $saveOne ([ordered]@{ Days = 90; Incidents = $seen.n; Weeks = @($weeks.Values) }) 'def-05-incidents-weekly'
    } | Out-Null

    Invoke-PostureStep -Label 'Secure Score' -Folder $Folder -Script {
        # SecurityEvents.Read.All. The latest score plus the control profiles (spec 4.12); Microsoft's numbers are reported, never the grade.
        $scores = @(& $get 'security/secureScores?$top=1')   # @( ) outside the call: a one-element array unrolls on return
        $s = $(if ($scores.Count -gt 0) { $scores[0] } else { $null })
        $byCategory = [ordered]@{}
        $scoreOf = @{}
        foreach ($c in @(& $v $s 'controlScores')) {
            $cat = [string](& $v $c 'controlCategory'); if ($cat) { $byCategory[$cat] = [double](& $v $c 'score') + $(if ($byCategory.Contains($cat)) { $byCategory[$cat] } else { 0 }) }
            $scoreOf[[string](& $v $c 'controlName')] = [double](& $v $c 'score')
        }
        & $saveOne ([ordered]@{ Present = [bool]$s; CreatedDateTime = (& $v $s 'createdDateTime'); CurrentScore = (& $v $s 'currentScore'); MaxScore = (& $v $s 'maxScore'); LicensedUserCount = (& $v $s 'licensedUserCount'); ActiveUserCount = (& $v $s 'activeUserCount'); ByCategory = $byCategory; AverageComparativeScores = @(@(& $v $s 'averageComparativeScores') | ForEach-Object { [ordered]@{ Basis = (& $v $_ 'basis'); AverageScore = (& $v $_ 'averageScore') } }) }) 'def-06-secure-score'
        $profiles = & $get 'security/secureScoreControlProfiles?$select=id,title,controlCategory,implementationCost,userImpact,maxScore,actionType,tier,deprecated,controlStateUpdates,rank,remediation,actionUrl'
        & $save @($profiles | Where-Object { (& $v $_ 'deprecated') -ne $true } | ForEach-Object {
                $updates = @(& $v $_ 'controlStateUpdates'); $latest = $(if ($updates.Count -gt 0) { $updates[-1] } else { $null })
                [ordered]@{ Id = $_.id; Title = (& $v $_ 'title'); Category = (& $v $_ 'controlCategory'); MaxScore = (& $v $_ 'maxScore'); ImplementationCost = (& $v $_ 'implementationCost'); UserImpact = (& $v $_ 'userImpact'); ActionType = (& $v $_ 'actionType'); Tier = (& $v $_ 'tier'); Rank = (& $v $_ 'rank'); State = (& $v $latest 'state'); Remediation = (& $v $_ 'remediation')
                    # Points earned now, from the latest score, and Microsoft's own page for the action.
                    Score = $(if ($scoreOf.ContainsKey([string]$_.id)) { $scoreOf[[string]$_.id] } else { $null }); ActionUrl = (& $v $_ 'actionUrl')
                }
            }) 'def-06-secure-score-controls' $true
    } | Out-Null

    $errorsPath = Join-Path (Get-PostureRunLayout -Folder $Folder).errors 'errors.txt'
    return @{ files = $files.ToArray(); errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath }) }
}
