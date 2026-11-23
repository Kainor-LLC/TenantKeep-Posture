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
    # Where Premium Audit is expected, an unread retention list is not an empty one: Global Reader alone cannot read it.
    elseif ($e5 -and $null -eq $ret) { & $missing @('PV-001') 'pv-05-audit-retention-policies' }
    else {
        $facts.unifiedAuditLogEnabled = (& $v $audit 'UnifiedAuditLogIngestionEnabled') -eq $true
        $facts.auditRetentionPolicies = $(if ($null -ne $ret) { @(& $rows $ret).Count } else { 0 })
        $facts.auditRetentionOk = (-not $e5) -or $facts.auditRetentionPolicies -gt 0
    }

    # Sensitivity labels (PV-002), container labels (PV-004)
    $labels = & $load 'pv-01-sensitivity-labels'; $policies = & $load 'pv-01-label-policies'
    if ($null -eq $labels -or $null -eq $policies) { & $missing @('PV-002', 'PV-004') $(if ($null -eq $labels) { 'pv-01-sensitivity-labels' } else { 'pv-01-label-policies' }) }
    if ($null -eq $policies) { & $missing @('PV-009') 'pv-01-label-policies' }
    else {
        $l = @(& $rows $labels | Where-Object { $_.Disabled -ne $true }); $p = @(& $rows $policies | Where-Object { $_.Enabled -ne $false })
        $facts.sensitivityLabels = $l.Count
        $facts.labelPoliciesEnabled = $p.Count
        $facts.labelPolicyToAllUsers = @($p | Where-Object { @(& $list $_.ExchangeLocation) -contains 'All' -or @(& $list $_.ModernGroupLocation) -contains 'All' }).Count -gt 0
        # Get-Label exposes the switches inside Settings as '[encryptionenabled, true]' strings on some tenants and as properties on others (confirmed 2026-10-15: properties null, Settings carries them).
        $settings = { param($x) (@(@(Get-PostureValue $x 'Settings') | ForEach-Object { [string]$_ }) -join ' ') }   # Settings is absent on older collections
        $facts.encryptingLabels = @($l | Where-Object { $_.EncryptionEnabled -eq $true -or (& $settings $_) -match '(?i)\[encryptionenabled, ?true\]' }).Count
        $facts.containerLabels = @($l | Where-Object { $_.SiteAndGroupProtectionEnabled -eq $true -or (& $settings $_) -match '(?i)\[siteandgroupprotectionenabled, ?true\]' -or [string](Get-PostureValue $_ 'ContentType') -match '(?i)Site|UnifiedGroup' }).Count
        # PV-009: an email takes the label of its attachment. A label policy carries that as the setting attachmentaction
        # (Automatic or Recommended) among its Settings, which a collection before 2026-11-23 did not save: then the
        # policies are there and the answer is not, so the check has none.
        # Saved and empty is an answer (the policy has no such setting); not saved at all is not.
        $savedSettings = { param($x) if ($x -is [System.Collections.IDictionary]) { $x.Contains('Settings') } else { $null -ne $x.PSObject.Properties['Settings'] } }
        if ($p.Count -gt 0 -and @($p | Where-Object { & $savedSettings $_ }).Count -eq 0) {
            $notEvaluated['PV-009'] = 'pv-01-label-policies.json was collected before label policy settings were saved; collect Purview again.'
        }
        else {
            $inheriting = @($p | Where-Object { (& $settings $_) -match '(?i)\[attachmentaction, ?(automatic|recommended)\]' })
            $facts.labelPoliciesWithAttachmentInheritance = $inheriting.Count
            $facts.labelPoliciesWithoutAttachmentInheritance = $p.Count - $inheriting.Count
            $affected.labelPoliciesWithoutAttachmentInheritance = @($p | Where-Object { $_ -notin $inheriting } | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = 'an email does not take the label of its attachment' } })
        }
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

    # What an enforced DLP policy does when it matches (PV-010), and whether the person is told (PV-011). A policy
    # whose rules only report lets the message or the share through; a block with no policy tip leaves the person
    # guessing and calling the help desk. A rule belongs to its policy by ParentPolicyName.
    $saved = { param($x, [string] $Name) if ($x -is [System.Collections.IDictionary]) { $x.Contains($Name) } else { $null -ne $x.PSObject.Properties[$Name] } }
    $dlpRules = & $load 'pv-02-dlp-rules'
    if ($null -eq $dlp) { & $missing @('PV-010', 'PV-011') 'pv-02-dlp-policies' }
    elseif ($null -eq $dlpRules) { & $missing @('PV-010', 'PV-011') 'pv-02-dlp-rules' }
    else {
        $enforcedPolicies = @(& $rows $dlp | Where-Object { $_.Enabled -ne $false -and [string]$_.Mode -match '(?i)^Enable' })
        $liveRules = @(& $rows $dlpRules | Where-Object { $_.Disabled -ne $true })
        $rulesOf = { param([string] $Policy) @($liveRules | Where-Object { [string]$_.ParentPolicyName -eq $Policy }) }
        $before = 'pv-02-dlp-rules.json was collected before TenantKeep read what a rule does. Collect Purview again (Resume-PostureRun -Collector Purview).'
        $blocking = @()
        if ($liveRules.Count -gt 0 -and @($liveRules | Where-Object { & $saved $_ 'BlockAccess' }).Count -eq 0) { $notEvaluated['PV-010'] = $before; $notEvaluated['PV-011'] = $before }
        else {
            $blocking = @($enforcedPolicies | Where-Object { @(& $rulesOf ([string]$_.Name) | Where-Object { $_.BlockAccess -eq $true }).Count -gt 0 })
            $facts.dlpPoliciesBlocking = $blocking.Count
            $reportOnly = @($enforcedPolicies | Where-Object { $_ -notin $blocking })
            $facts.dlpPoliciesReportOnly = $reportOnly.Count
            $affected.dlpPoliciesReportOnly = @($reportOnly | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = 'no rule in this policy blocks: a match is reported and let through' } })
            # PV-011 judges the policies that block. With none, there is no block to explain, and that is PV-010's finding.
            if ($blocking.Count -eq 0) { $notEvaluated['PV-011'] = 'No enforced DLP policy blocks anything yet, so there is no block to explain. PV-010 comes first.' }
            elseif (@($liveRules | Where-Object { & $saved $_ 'NotifyUser' }).Count -eq 0) { $notEvaluated['PV-011'] = $before }
            else {
                $silent = @($blocking | Where-Object { @(& $rulesOf ([string]$_.Name) | Where-Object { $_.BlockAccess -eq $true -and @(& $list $_.NotifyUser).Count -eq 0 }).Count -gt 0 })
                $facts.dlpPoliciesBlockingSilently = $silent.Count
                $affected.dlpPoliciesBlockingSilently = @($silent | ForEach-Object { $name = [string]$_.Name; [ordered]@{ name = $name; detail = "blocks without telling the person: $(@(& $rulesOf $name | Where-Object { $_.BlockAccess -eq $true -and @(& $list $_.NotifyUser).Count -eq 0 } | ForEach-Object { [string]$_.Name }) -join ', ')" } })
            }
        }
    }

    # Alert policies (PV-012, PV-013): the six built-in policies CISA's baseline names, which tell an administrator
    # that the tenant is sending spam, that a connector or a forwarding rule looks hijacked, or that mail is held up.
    # A policy counts when it is in the list and not turned off. A tenant always has built-in policies, so an empty
    # list is a list that could not be read, not a tenant with none.
    $alerts = & $load 'pv-07-alert-policies'
    if ($null -eq $alerts) { & $missing @('PV-012', 'PV-013') 'pv-07-alert-policies' }
    elseif (@(& $rows $alerts).Count -eq 0) {
        foreach ($id in 'PV-012', 'PV-013') { $notEvaluated[$id] = 'The alert policy list came back empty. A tenant always has built-in alert policies, so the account that collected could not read them (Purview collector; check errors.txt).' }
    }
    else {
        $wanted = @('Suspicious email sending patterns detected', 'Suspicious connector activity', 'Suspicious email forwarding activity', 'Messages have been delayed', 'Tenant restricted from sending unprovisioned email', 'Tenant restricted from sending email')
        $byName = @{}
        foreach ($a in @(& $rows $alerts)) { $n = ([string]$a.Name).Trim(); if ($n) { $byName[$n.ToLowerInvariant()] = $a } }
        $off = [System.Collections.Generic.List[object]]::new(); $on = [System.Collections.Generic.List[object]]::new()
        foreach ($w in $wanted) {
            $a = $byName[$w.ToLowerInvariant()]
            if ($null -eq $a) { $off.Add([ordered]@{ name = $w; detail = 'not found among the alert policies' }) }
            elseif ($a.Disabled -eq $true) { $off.Add([ordered]@{ name = $w; detail = 'turned off' }) }
            else { $on.Add($a) }
        }
        $facts.alertPoliciesExpected = $wanted.Count
        $facts.alertPoliciesOff = $off.Count
        $affected.alertPoliciesOff = $off.ToArray()
        # PV-013: an alert that emails nobody is seen only by someone who opens the portal. The report can see that
        # an alert has a recipient, not that anybody reads the mailbox.
        if ($on.Count -eq 0) { $notEvaluated['PV-013'] = 'None of the six alert policies is on, so there is no recipient to judge. PV-012 comes first.' }
        elseif (@($on | Where-Object { & $saved $_ 'NotifyUser' }).Count -eq 0) { $notEvaluated['PV-013'] = 'pv-07-alert-policies.json was collected before TenantKeep read who an alert is sent to. Collect Purview again (Resume-PostureRun -Collector Purview).' }
        else {
            $quiet = @($on | Where-Object { @(& $list $_.NotifyUser).Count -eq 0 -or (Get-PostureValue $_ 'NotificationEnabled') -eq $false })
            $facts.alertPoliciesWithoutRecipient = $quiet.Count
            $affected.alertPoliciesWithoutRecipient = @($quiet | ForEach-Object { [ordered]@{ name = [string]$_.Name; detail = $(if ((Get-PostureValue $_ 'NotificationEnabled') -eq $false) { 'email notification is off' } else { 'no recipient' }) } })
        }
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
