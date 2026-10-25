# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PosturePurviewFact {
    <#
    .SYNOPSIS
        Fact provider for the purview domain (spec 4.5): audit log and retention, sensitivity labels published,
        auto-labeling, container labels in use, DLP by workload, retention policies, insider risk, Purview role groups.
    .DESCRIPTION
        Reads exo-01-audit-config and the pv-* files, plus spo-sites-summary for labeled sites. Thresholds read:
        maxComplianceAdmins. Profile read: licenses (E5 makes Endpoint DLP and one-year audit retention expected).
        Endpoint DLP device onboarding and DSPM for AI have no collector yet.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [Parameter()] [System.Collections.IDictionary] $OrgProfile = @{},
        [Parameter()] [System.Collections.IDictionary] $Thresholds = @{}
    )

    $ErrorActionPreference = 'Stop'
    $t = @{ maxComplianceAdmins = 5 }
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
    # Callers wrap the result in @( ): a one-element array unrolls on return from a scriptblock.
    $list = { param($x) @($(if ($x -is [string]) { $x -split '[;|,]' } else { @($x) }) | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ }) }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    $missing = { param([string[]] $Ids, [string] $File) foreach ($id in $Ids) { $notEvaluated[$id] = "$File.json was not collected (Invoke-PostureCollection -Collector Purview; needs Connect-IPPSSession; check errors.txt)." } }

    if (@(Get-ChildItem -LiteralPath $Evidence -Filter 'pv-*.json' -ErrorAction SilentlyContinue).Count -eq 0) {
        return @{ available = $false; reason = 'No Purview evidence in the folder (Invoke-PostureCollection -Collector Purview needs a Connect-IPPSSession session).' }
    }
    $lic = @($OrgProfile['licenses'] | Where-Object { $_ })
    $e5 = [bool](@($lic | Where-Object { $_ -in @('E5', 'Purview') }).Count -gt 0)
    $facts.premiumAuditExpected = $e5

    # Audit (PV-001)
    $audit = & $load 'exo-01-audit-config'; $ret = & $load 'pv-05-audit-retention-policies'
    if ($null -eq $audit) { $notEvaluated['PV-001'] = 'exo-01-audit-config.json was not collected (Exchange collector).' }
    else {
        $facts.unifiedAuditLogEnabled = (& $v $audit 'UnifiedAuditLogIngestionEnabled') -eq $true
        $facts.auditRetentionPolicies = $(if ($null -ne $ret) { @(& $rows $ret).Count } else { 0 })
        $facts.auditRetentionOk = (-not $e5) -or $facts.auditRetentionPolicies -gt 0
    }

    # Sensitivity labels (PV-002), container labels (PV-004)
    $labels = & $load 'pv-01-sensitivity-labels'; $policies = & $load 'pv-01-label-policies'
    if ($null -eq $labels -or $null -eq $policies) { & $missing @('PV-002', 'PV-004') 'pv-01-sensitivity-labels' }
    else {
        $l = @(& $rows $labels | Where-Object { $_.Disabled -ne $true }); $p = @(& $rows $policies | Where-Object { $_.Enabled -ne $false })
        $facts.sensitivityLabels = $l.Count
        $facts.labelPoliciesEnabled = $p.Count
        $facts.labelPolicyToAllUsers = @($p | Where-Object { @(& $list $_.ExchangeLocation) -contains 'All' -or @(& $list $_.ModernGroupLocation) -contains 'All' }).Count -gt 0
        # Get-Label exposes the switches inside Settings as '[encryptionenabled, true]' strings on some tenants and as properties on others (confirmed 2026-10-15: properties null, Settings carries them).
        $settings = { param($x) (@(@(Get-PostureValue $x 'Settings') | ForEach-Object { [string]$_ }) -join ' ') }   # Settings is absent on older collections
        $facts.encryptingLabels = @($l | Where-Object { $_.EncryptionEnabled -eq $true -or (& $settings $_) -match '(?i)\[encryptionenabled, ?true\]' }).Count
        $facts.containerLabels = @($l | Where-Object { $_.SiteAndGroupProtectionEnabled -eq $true -or (& $settings $_) -match '(?i)\[siteandgroupprotectionenabled, ?true\]' -or [string](Get-PostureValue $_ 'ContentType') -match '(?i)Site|UnifiedGroup' }).Count
        $sites = & $load 'spo-sites-summary'
        $facts.labeledSites = $(if ($null -ne $sites) { [int](& $v $sites 'Labeled') } else { $null })
        if ($null -eq $sites) { $notEvaluated['PV-004'] = 'spo-sites-summary.json was not collected (SharePoint collector); labeled sites unknown.' }
    }

    # Auto-labeling (PV-003)
    $auto = & $load 'pv-01-autolabel-policies'
    if ($null -eq $auto) { & $missing @('PV-003') 'pv-01-autolabel-policies' }
    else { $facts.autoLabelPoliciesEnforced = @(& $rows $auto | Where-Object { $_.Enabled -ne $false -and [string]$_.Mode -match '(?i)^Enable' }).Count }

    # DLP by workload (PV-005)
    $dlp = & $load 'pv-02-dlp-policies'
    if ($null -eq $dlp) { & $missing @('PV-005') 'pv-02-dlp-policies' }
    else {
        $enforced = @(& $rows $dlp | Where-Object { $_.Enabled -ne $false -and [string]$_.Mode -match '(?i)^Enable' })
        $covered = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($d in $enforced) {
            foreach ($w in @(& $list $d.Workload)) { $null = $covered.Add($w.Trim()) }
            foreach ($pair in @(@('Exchange', $d.ExchangeLocation), @('SharePoint', $d.SharePointLocation), @('OneDriveForBusiness', $d.OneDriveLocation), @('Teams', $d.TeamsLocation), @('EndpointDevices', $d.EndpointDlpLocation))) { if (@(& $list $pair[1]).Count -gt 0) { $null = $covered.Add($pair[0]) } }
        }
        $required = @('Exchange', 'SharePoint', 'OneDriveForBusiness', 'Teams') + @($(if ($e5) { 'EndpointDevices' }))
        $facts.dlpPoliciesEnforced = $enforced.Count
        $facts.dlpWorkloadsCovered = @($covered | Sort-Object)
        $gaps = @($required | Where-Object { -not $covered.Contains($_) })
        $facts.dlpWorkloadsMissing = $gaps.Count
        $affected.dlpWorkloadsMissing = @($gaps | ForEach-Object { [ordered]@{ name = $_; detail = 'no enforced DLP policy covers this workload' } })
    }

    # Retention (PV-006)
    $rp = & $load 'pv-03-retention-policies'
    if ($null -eq $rp) { & $missing @('PV-006') 'pv-03-retention-policies' }
    else {
        $on = @(& $rows $rp | Where-Object { $_.Enabled -ne $false })
        $facts.retentionPoliciesEnabled = $on.Count
        $wl = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($r in $on) { foreach ($w in @(& $list $r.Workload)) { $null = $wl.Add($w.Trim()) }; if (@(& $list $r.ExchangeLocation).Count -gt 0) { $null = $wl.Add('Exchange') }; if (@(& $list $r.SharePointLocation).Count -gt 0) { $null = $wl.Add('SharePoint') } }
        $facts.retentionCoversExchangeAndSharePoint = $wl.Contains('Exchange') -and $wl.Contains('SharePoint')
    }

    # Insider risk (PV-007)
    $irm = & $load 'pv-04-insider-risk-policies'
    if ($null -eq $irm) { & $missing @('PV-007') 'pv-04-insider-risk-policies' }
    else { $facts.insiderRiskPoliciesEnabled = @(& $rows $irm | Where-Object { $_.Enabled -ne $false }).Count }

    # Purview role groups (PV-008)
    $rg = & $load 'pv-08-role-groups'
    if ($null -eq $rg) { & $missing @('PV-008') 'pv-08-role-groups' }
    else {
        # Purview names its role groups without spaces (ComplianceAdministrator, OrganizationManagement; confirmed 2026-10-15); Exchange uses spaces.
        $admin = @(& $rows $rg | Where-Object { [string]$_.Name -match '(?i)^(Compliance ?Administrator|Organization ?Management)$' })
        $members = @($admin | ForEach-Object { & $list $_.Members } | Sort-Object -Unique)
        $facts.complianceAdminMembers = $members.Count
        $affected.complianceAdminMembers = @($members | ForEach-Object { [ordered]@{ name = $_; detail = 'member of Compliance Administrator or Organization Management in Purview' } })
    }

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('pv-01-sensitivity-labels.json', 'pv-02-dlp-policies.json') }
}
