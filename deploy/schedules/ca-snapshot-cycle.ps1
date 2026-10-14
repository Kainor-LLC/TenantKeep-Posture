#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    One Conditional Access monitoring cycle: snapshot, document, compare with the previous run, notify, prune.
.DESCRIPTION
    The shared body behind the three schedulers in deploy/schedules (Azure Automation runbook, GitHub Action, macOS
    launchd). Expects an existing Microsoft Graph session; each scheduler signs in its own way before calling this.

    Steps:
      1. Export-PostureCaSnapshot into <OutRoot>/<stamp>-ca
      2. New-PostureCaDocument for the new snapshot
      3. Compare-PostureCaSnapshot against the newest earlier <stamp>-ca folder, when one exists
      4. Notify, when there are risk-relevant changes (or always, with -EmailAlways):
           Teams Workflows webhook card, when -TeamsWebhookUrl is set
           email with ca-changes.html attached, when -EmailTo and -EmailFrom are set, through Graph sendMail
           (needs Mail.Send on the identity, opt-in) or an SMTP relay (-EmailMethod Smtp)
      5. Delete the oldest runs beyond -KeepRuns, when -KeepRuns is greater than 0

    Returns a summary object. With -FailOnRiskRelevantChange it throws at the end when the comparison found
    risk-relevant changes, so the scheduler's job fails and its own alerting fires too. Every send goes to the
    customer's own services; see ca-notifications.ps1.
.EXAMPLE
    Connect-MgGraph -Identity -NoWelcome
    ./ca-snapshot-cycle.ps1 -OutRoot /mnt/snapshots -TeamsWebhookUrl $env:TEAMS_WEBHOOK -FailOnRiskRelevantChange
.EXAMPLE
    ./ca-snapshot-cycle.ps1 -OutRoot ~/audit/evidence -EmailTo secops@contoso.example -EmailFrom ca-monitor@contoso.example

    Emails through Graph as ca-monitor@contoso.example when a risk-relevant change appears. The identity needs Mail.Send.
.EXAMPLE
    ./ca-snapshot-cycle.ps1 -OutRoot ~/audit/evidence -EmailTo secops@contoso.example -EmailFrom ca-monitor@contoso.example -EmailMethod Smtp -SmtpServer smtp.contoso.example -SmtpCredential $cred -EmailAlways

    Daily digest through the customer's SMTP relay, sent even when nothing is risk-relevant.
#>
[CmdletBinding()]
param(
    [string] $OutRoot = (Join-Path $HOME 'audit' 'evidence'),
    [string] $Brand,
    [string[]] $BreakGlass,
    [string] $NamePattern,
    [switch] $IncludeMembers,
    [string] $TeamsWebhookUrl,
    [string[]] $EmailTo,
    [string] $EmailFrom,
    [ValidateSet('Graph', 'Smtp')] [string] $EmailMethod = 'Graph',
    [string] $SmtpServer,
    [int] $SmtpPort = 587,
    [pscredential] $SmtpCredential,
    [bool] $SmtpUseTls = $true,
    [switch] $EmailAlways,
    [ValidateRange(0, 10000)] [int] $KeepRuns = 0,
    [switch] $FailOnRiskRelevantChange
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Get-Module -Name Tenantkeep.Posture)) { Import-Module Tenantkeep.Posture -ErrorAction Stop }
. (Join-Path $PSScriptRoot 'ca-notifications.ps1')
if ($EmailTo -and -not $EmailFrom) { throw '-EmailFrom is required with -EmailTo.' }

$optional = @{}
if ($Brand) { $optional.Brand = $Brand }

# 1. Snapshot
$snapshot = Export-PostureCaSnapshot -OutRoot $OutRoot -IncludeMembers:$IncludeMembers -PassThru
$newFolder = $snapshot.Folder
Write-Information "Snapshot: $newFolder ($($snapshot.PolicyCount) policies, $($snapshot.Errors) error(s))" -InformationAction Continue

# 2. Document
$docParams = @{ Snapshot = $newFolder } + $optional
if ($NamePattern) { $docParams.NamePattern = $NamePattern }
$documents = @(New-PostureCaDocument @docParams)

# 3. Compare with the previous run
$previous = Get-ChildItem -Path $OutRoot -Directory |
    Where-Object { $_.Name -match '^\d{8}-\d{4}-ca$' -and $_.FullName -ne $newFolder } |
    Sort-Object Name |
    Select-Object -Last 1
$comparison = $null
if ($previous) {
    $cmpParams = @{ Before = $previous.FullName; After = $newFolder; PassThru = $true } + $optional
    if ($BreakGlass) { $cmpParams.BreakGlass = $BreakGlass }
    $comparison = Compare-PostureCaSnapshot @cmpParams
    Write-Information "Compared with $($previous.Name): $($comparison.RiskRelevantCount) risk-relevant change(s)" -InformationAction Continue
}
else {
    Write-Information 'No earlier snapshot under OutRoot; nothing to compare. The next run will diff against this one.' -InformationAction Continue
}

# 4. Notify
$notified = @()
if ($comparison) {
    $risky = $comparison.HasRiskRelevantChanges
    $beforeName = $previous.Name
    $afterName = Split-Path $newFolder -Leaf
    if ($risky -and $TeamsWebhookUrl) {
        Send-CaTeamsCard -WebhookUrl $TeamsWebhookUrl -Comparison $comparison -BeforeName $beforeName -AfterName $afterName
        $notified += 'teams'
        Write-Information 'Posted the risk-relevant changes to Teams.' -InformationAction Continue
    }
    if ($EmailTo -and ($risky -or $EmailAlways)) {
        $tenantLabel = [string]$comparison.Diff.after.tenantId
        if ($Brand) { $clientName = (Get-Content -Raw -LiteralPath $Brand | ConvertFrom-Json).client.name; if ($clientName) { $tenantLabel = $clientName } }
        $content = Get-CaChangeNotificationContent -Comparison $comparison -BeforeName $beforeName -AfterName $afterName -TenantLabel $tenantLabel
        $html = @($comparison.Files | Where-Object { $_ -like '*.html' })
        $mailParams = @{ To = $EmailTo; From = $EmailFrom; Subject = $content.Subject; HtmlBody = $content.Body; AttachmentPath = $html; Method = $EmailMethod; SmtpUseTls = $SmtpUseTls; SmtpPort = $SmtpPort }
        if ($SmtpServer) { $mailParams.SmtpServer = $SmtpServer }
        if ($SmtpCredential) { $mailParams.SmtpCredential = $SmtpCredential }
        Send-CaChangeEmail @mailParams
        $notified += "email:$($EmailMethod.ToLowerInvariant())"
        Write-Information "Emailed $($EmailTo -join ', ') through $EmailMethod." -InformationAction Continue
    }
}

# 5. Prune
$pruned = @()
if ($KeepRuns -gt 0) {
    $runs = Get-ChildItem -Path $OutRoot -Directory | Where-Object { $_.Name -match '^\d{8}-\d{4}-ca$' } | Sort-Object Name
    $excess = $runs.Count - $KeepRuns
    if ($excess -gt 0) {
        foreach ($old in ($runs | Select-Object -First $excess)) {
            Remove-Item -LiteralPath $old.FullName -Recurse -Force
            $pruned += $old.Name
        }
    }
}

$result = [pscustomobject]@{
    Snapshot               = $newFolder
    Previous               = $(if ($previous) { $previous.FullName } else { $null })
    Documents              = $documents
    ChangeReports          = $(if ($comparison) { $comparison.Files } else { @() })
    RiskRelevantCount      = $(if ($comparison) { $comparison.RiskRelevantCount } else { 0 })
    HasRiskRelevantChanges = [bool]($comparison -and $comparison.HasRiskRelevantChanges)
    Notified               = $notified
    Pruned                 = $pruned
}
if ($FailOnRiskRelevantChange -and $result.HasRiskRelevantChanges) {
    $result | Format-List | Out-String | Write-Information -InformationAction Continue
    throw "$($result.RiskRelevantCount) risk-relevant Conditional Access change(s). See $($result.ChangeReports -join ', ')"
}
return $result
