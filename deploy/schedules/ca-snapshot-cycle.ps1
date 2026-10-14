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
      4. Post the risk-relevant changes to a Teams Workflows webhook, when -TeamsWebhookUrl is set and there are any
      5. Delete the oldest runs beyond -KeepRuns, when -KeepRuns is greater than 0

    Returns a summary object. With -FailOnRiskRelevantChange it throws at the end when the comparison found
    risk-relevant changes, so the scheduler's job fails and its own alerting fires. The module never sends mail:
    Mail.Send is a write scope and the module is read-only.
.EXAMPLE
    Connect-MgGraph -Identity -NoWelcome
    ./ca-snapshot-cycle.ps1 -OutRoot /mnt/snapshots -TeamsWebhookUrl $env:TEAMS_WEBHOOK -FailOnRiskRelevantChange
#>
[CmdletBinding()]
param(
    [string] $OutRoot = (Join-Path $HOME 'audit' 'evidence'),
    [string] $Brand,
    [string[]] $BreakGlass,
    [string] $NamePattern,
    [switch] $IncludeMembers,
    [string] $TeamsWebhookUrl,
    [ValidateRange(0, 10000)] [int] $KeepRuns = 0,
    [switch] $FailOnRiskRelevantChange
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Get-Module -Name Tenantkeep.Posture)) { Import-Module Tenantkeep.Posture -ErrorAction Stop }

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

# 4. Notify (Teams Workflows webhook, Adaptive Card payload) (verify: Workflows webhook accepts this shape; the
#    older Office 365 connector webhooks are retired)
if ($comparison -and $comparison.HasRiskRelevantChanges -and $TeamsWebhookUrl) {
    $facts = @($comparison.Diff.risk | Select-Object -First 15 | ForEach-Object { @{ title = $_.rule; value = "$($_.subject): $($_.detail)" } })
    $card = @{
        type        = 'message'
        attachments = @(@{
                contentType = 'application/vnd.microsoft.card.adaptive'
                content     = @{
                    '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
                    type      = 'AdaptiveCard'
                    version   = '1.4'
                    body      = @(
                        @{ type = 'TextBlock'; size = 'Large'; weight = 'Bolder'; text = "Conditional Access: $($comparison.RiskRelevantCount) risk-relevant change(s)" }
                        @{ type = 'TextBlock'; wrap = $true; text = "Between $($previous.Name) and $(Split-Path $newFolder -Leaf). Report: ca-changes.html in the snapshot folder." }
                        @{ type = 'FactSet'; facts = $facts }
                    )
                }
            })
    }
    $null = Invoke-RestMethod -Method Post -Uri $TeamsWebhookUrl -ContentType 'application/json' -Body ($card | ConvertTo-Json -Depth 12)
    Write-Information 'Posted the risk-relevant changes to Teams.' -InformationAction Continue
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
    Pruned                 = $pruned
}
if ($FailOnRiskRelevantChange -and $result.HasRiskRelevantChanges) {
    $result | Format-List | Out-String | Write-Information -InformationAction Continue
    throw "$($result.RiskRelevantCount) risk-relevant Conditional Access change(s). See $($result.ChangeReports -join ', ')"
}
return $result
