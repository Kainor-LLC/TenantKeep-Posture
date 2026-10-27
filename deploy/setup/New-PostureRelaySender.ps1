#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    One-time setup for relayed alerts to TenantKeep On-Call: a sender key for this tenant.
.DESCRIPTION
    Opt-in. Relayed alerts are the one exception to "nothing leaves the customer's environment": when a risk-relevant
    Conditional Access change is found, Watch encrypts an alert for each paired phone and sends it through Kainor's
    relay, which cannot read it and keeps nothing. See deploy/schedules/ca-relay.ps1 for exactly what crosses.

    This makes the sender key. With -AutomationAccountName it stores the key as the ENCRYPTED Automation variable
    RELAY_SENDER_KEY; without it, it prints the key once for you to store. Either way it prints the sender code to
    paste into TenantKeep On-Call on each phone (Settings, Relayed Alerts). The phones' pairing codes go into the
    Automation variable RELAY_PAIRING_CODES, comma separated.

    Relayed alerts need a TenantKeep On-Call Pro, MSP or enterprise licence for the tenant.
.EXAMPLE
    ./New-PostureRelaySender.ps1 -TenantId c0ffee00-1111-2222-3333-444455556666 -ResourceGroupName rg-tenantkeep -AutomationAccountName aa-tenantkeep
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [Guid] $TenantId,
    [string] $ResourceGroupName,
    [string] $AutomationAccountName
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..' 'schedules' 'ca-relay.ps1')

$senderKey = New-CaRelaySenderKey -TenantId $TenantId
if ($AutomationAccountName) {
    if (-not $ResourceGroupName) { throw '-ResourceGroupName is required with -AutomationAccountName.' }
    if ($PSCmdlet.ShouldProcess($AutomationAccountName, 'Store RELAY_SENDER_KEY as an encrypted Automation variable')) {
        $existing = Get-AzAutomationVariable -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name 'RELAY_SENDER_KEY' -ErrorAction SilentlyContinue
        if ($existing) {
            Remove-AzAutomationVariable -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name 'RELAY_SENDER_KEY'
        }
        $null = New-AzAutomationVariable -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name 'RELAY_SENDER_KEY' -Value $senderKey.PrivateKey -Encrypted $true
        Write-Information 'Stored RELAY_SENDER_KEY, encrypted. Phones paired with an earlier key must pin the new sender code.' -InformationAction Continue
    }
}
else {
    Write-Information 'Store this as the ENCRYPTED Automation variable RELAY_SENDER_KEY. It is shown once:' -InformationAction Continue
    Write-Information $senderKey.PrivateKey -InformationAction Continue
}
Write-Information '' -InformationAction Continue
Write-Information 'Paste this sender code into TenantKeep On-Call on each phone (Settings, Relayed Alerts):' -InformationAction Continue
Write-Information $senderKey.SenderCode -InformationAction Continue
