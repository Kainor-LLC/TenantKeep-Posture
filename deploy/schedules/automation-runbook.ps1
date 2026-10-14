#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Azure Automation runbook (PowerShell 7.4 runtime): nightly Conditional Access snapshot and diff with a managed identity.
.DESCRIPTION
    Sample for spec 5.4. Snapshots live on a storage account file share or blob container mounted or synced to the
    sandbox; the sandbox's own disk is wiped between jobs, so OutRoot must be durable storage.

    Setup, once:
      1. Automation account with a system-assigned managed identity.
      2. Grant the identity the Graph application permissions Policy.Read.All, Directory.Read.All, Group.Read.All
         (admin consent) (verify: app-only is required; a managed identity cannot use delegated scopes).
      3. Import the Tenantkeep.Posture module and Microsoft.Graph.Authentication into the account's PowerShell 7.4
         module list (verify: contentLink flow in Bicep, spec 6).
      4. Variables: TENANTKEEP_OUTROOT (durable path), optional TEAMS_WEBHOOK (encrypted), optional BREAK_GLASS
         (comma-separated UPNs), optional EMAIL_TO (comma-separated) and EMAIL_FROM (a mailbox in the tenant; grant
         the identity Mail.Send and restrict it to that mailbox with an Exchange application access policy).
      5. Schedule: daily. Add an alert rule on job failure; -FailOnRiskRelevantChange makes a risky night a failed job,
         which is how email alerting works without the module sending mail.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$outRoot = Get-AutomationVariable -Name 'TENANTKEEP_OUTROOT'
$webhook = try { Get-AutomationVariable -Name 'TEAMS_WEBHOOK' } catch { $null }
$breakGlass = try { (Get-AutomationVariable -Name 'BREAK_GLASS') -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } } catch { @() }
$emailTo = try { (Get-AutomationVariable -Name 'EMAIL_TO') -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } } catch { @() }
$emailFrom = try { Get-AutomationVariable -Name 'EMAIL_FROM' } catch { $null }

Connect-MgGraph -Identity -NoWelcome
Import-Module Tenantkeep.Posture

$cycle = Join-Path $PSScriptRoot 'ca-snapshot-cycle.ps1'
if (-not (Test-Path $cycle)) {
    # When the runbook is imported on its own, the cycle script ships inside the module's deploy folder.
    $cycle = Join-Path (Split-Path (Get-Module Tenantkeep.Posture).Path) 'deploy' 'schedules' 'ca-snapshot-cycle.ps1'
}

$params = @{ OutRoot = $outRoot; KeepRuns = 90; FailOnRiskRelevantChange = $true }
if ($webhook) { $params.TeamsWebhookUrl = $webhook }
if ($breakGlass) { $params.BreakGlass = $breakGlass }
if ($emailTo -and $emailFrom) { $params.EmailTo = $emailTo; $params.EmailFrom = $emailFrom }
& $cycle @params
