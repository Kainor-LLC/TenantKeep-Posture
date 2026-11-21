#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Checks the tenant's own audit logs for anything the run account changed while a TenantKeep Posture run was going
    on. Independent of the module: it does not load TenantKeep.Posture, and it only reads.
.DESCRIPTION
    For a security team that wants evidence from its own records rather than our word. It reads, for the account that
    ran the report and the window the run took:

      - the unified audit log (Search-UnifiedAuditLog, Exchange Online PowerShell): Exchange admin operations, which
        Exchange records only when something changes; Entra directory changes; SharePoint and OneDrive operations;
      - Entra's directory audit log (Graph auditLogs/directoryAudits), which holds changes only;
      - Entra's sign-in log for the account (Graph auditLogs/signIns), to show which apps it signed in to.

    A change is an Exchange admin record, an Entra directory change, or a SharePoint operation whose name says it
    changed something (added, removed, updated, shared and the like). Everything else is counted as a read. The
    expected answer is no changes. The audit log names the account, not the tool: run the report with an account that
    does nothing else in that window (a dedicated run account) or anything else it did shows up too.

    Audit records can take a few hours to arrive, Entra's within minutes, the unified audit log up to a day for some
    workloads. Run this the day after the run for the full picture.

    Needs, signed in as someone with audit log read access (Purview Audit Reader or View-Only Audit Logs, and Reports
    Reader or Security Reader in Entra):
      Connect-ExchangeOnline -UserPrincipalName <you>
      Connect-MgGraph -TenantId <tenant id> -Scopes AuditLog.Read.All, Directory.Read.All -NoWelcome
.PARAMETER TenantId
    The tenant. Both sessions must be in it.
.PARAMETER RunFolder
    A TenantKeep Posture run folder: the account and the window come from logs/run.json and the last file it wrote.
.PARAMETER Account
    The account that ran the report, when there is no run folder at hand.
.PARAMETER Start
    Start of the window (UTC), when there is no run folder.
.PARAMETER End
    End of the window (UTC), when there is no run folder.
.PARAMETER OutputPath
    Where the summary and the CSVs go. Default: .\readonly-check-<yyyyMMdd-HHmm>.
.EXAMPLE
    ./deploy/verify/Test-PostureReadOnly.ps1 -TenantId <tenant id> -RunFolder ~/tenantkeep/evidence/20261120-0957
.EXAMPLE
    ./deploy/verify/Test-PostureReadOnly.ps1 -TenantId <tenant id> -Account posture-run@contoso.com -Start '2026-11-20 14:00' -End '2026-11-20 15:30'
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive check; the console is the report.')]
param(
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $TenantId,
    [Parameter(Mandatory, ParameterSetName = 'Run')] [string] $RunFolder,
    [Parameter(Mandatory, ParameterSetName = 'Window')] [ValidatePattern('^[^@\s]+@[^@\s]+$')] [string] $Account,
    [Parameter(Mandatory, ParameterSetName = 'Window')] [datetime] $Start,
    [Parameter(Mandatory, ParameterSetName = 'Window')] [datetime] $End,
    [string] $OutputPath = (Join-Path (Get-Location) "readonly-check-$((Get-Date).ToString('yyyyMMdd-HHmm'))")
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# The window and the account, from the run folder when given.
if ($PSCmdlet.ParameterSetName -eq 'Run') {
    $root = (Resolve-Path -LiteralPath $RunFolder).Path
    if ((Split-Path $root -Leaf) -eq 'evidence') { $root = Split-Path $root -Parent }
    $plan = Get-Content -Raw -LiteralPath (Join-Path $root 'logs' 'run.json') | ConvertFrom-Json -AsHashtable
    if ([string]$plan['tenantId'] -ne $TenantId) { throw "The run folder is tenant $($plan['tenantId']), not $TenantId." }
    $Account = [string]$plan['runAs']['account']
    $Start = ([datetime]$plan['startedUtc']).ToUniversalTime().AddMinutes(-5)
    $last = @(Get-ChildItem -LiteralPath $root -Recurse -File | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1)
    $End = $last[0].LastWriteTimeUtc.AddMinutes(15)
}
else { $Start = $Start.ToUniversalTime(); $End = $End.ToUniversalTime() }
if (-not $Account) { throw 'No account to check: pass -Account, or a run folder whose run.json names it.' }
Write-Host "Checking $Account from $($Start.ToString('u')) to $($End.ToString('u'))."
if ($End -gt [datetime]::UtcNow.AddHours(-24)) { Write-Warning 'The window ended less than a day ago; some audit records may not have arrived yet. Run this again tomorrow for the full picture.' }

# The sessions, both in this tenant.
$ctx = Get-MgContext
if (-not $ctx -or [string]$ctx.TenantId -ne $TenantId) { throw "Connect-MgGraph -TenantId $TenantId -Scopes AuditLog.Read.All, Directory.Read.All first." }
$exo = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Connected' -and [string]$_.TenantID -eq $TenantId })
if ($exo.Count -eq 0) { throw 'Connect-ExchangeOnline to this tenant first (the unified audit log is read through it).' }

$changeOperation = '(Added|Removed|Deleted|Updated|Changed|Created|Modified|Renamed|Moved|Uploaded|Restored|Set|Granted|Revoked|Enabled|Disabled|Shared|Unshared|Reset|Applied)$|^Sharing|^AnonymousLink|^SiteCollectionAdmin|^Set-|^New-|^Remove-|^Add-|^Enable-|^Disable-'
$isChange = {
    param($r)
    $type = [string]$r.RecordType; $op = [string]$r.Operations
    if ($type -eq 'ExchangeAdmin') { return $true }
    if ($type -in 'AzureActiveDirectory', 'AzureActiveDirectoryStsLogon') { return $type -eq 'AzureActiveDirectory' -and $op -notmatch 'login|logon|sign-?in' }
    return $op -match $changeOperation
}

# 1. The unified audit log, page by page.
$records = [System.Collections.Generic.List[object]]::new()
$sessionId = [guid]::NewGuid().ToString()
while ($true) {
    $page = @(Search-UnifiedAuditLog -StartDate $Start -EndDate $End -UserIds $Account -SessionId $sessionId -SessionCommand ReturnLargeSet -ResultSize 5000)
    foreach ($r in $page) { $records.Add($r) }
    if ($page.Count -lt 5000) { break }
}

# 2. Entra directory changes and sign-ins, through Graph reads.
$graphAll = {
    param([string] $Uri)
    $out = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType HashTable
        foreach ($v in @($resp['value'])) { $out.Add($v) }
        $next = $(if ($resp.ContainsKey('@odata.nextLink')) { [string]$resp['@odata.nextLink'] } else { '' })
    }
    $out
}
$from = $Start.ToString('yyyy-MM-ddTHH:mm:ssZ'); $to = $End.ToString('yyyy-MM-ddTHH:mm:ssZ')
$who = [uri]::EscapeDataString($Account)
$directory = @(& $graphAll "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=initiatedBy/user/userPrincipalName eq '$who' and activityDateTime ge $from and activityDateTime le $to")
$signIns = @(& $graphAll "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=userPrincipalName eq '$who' and createdDateTime ge $from and createdDateTime le $to&`$select=appDisplayName,appId,createdDateTime,status")

# 3. The answer.
$changes = @($records | Where-Object { & $isChange $_ })
$byOperation = @($records | Group-Object RecordType, Operations | Sort-Object Count -Descending | ForEach-Object { [ordered]@{ recordType = $_.Group[0].RecordType; operation = $_.Group[0].Operations; count = $_.Count; change = [bool](& $isChange $_.Group[0]) } })
$apps = @($signIns | Group-Object { [string]$_['appDisplayName'] } | Sort-Object Count -Descending | ForEach-Object { [ordered]@{ app = $_.Name; appId = [string]$_.Group[0]['appId']; signIns = $_.Count } })

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$out = (Resolve-Path -LiteralPath $OutputPath).Path
$changes | Select-Object CreationDate, RecordType, Operations, UserIds, AuditData | Export-Csv -LiteralPath (Join-Path $out 'unified-audit-changes.csv') -NoTypeInformation
@($directory | ForEach-Object { [pscustomobject]@{ activityDateTime = $_['activityDateTime']; activity = $_['activityDisplayName']; category = $_['category']; result = $_['result'] } }) | Export-Csv -LiteralPath (Join-Path $out 'entra-directory-changes.csv') -NoTypeInformation
$summary = [ordered]@{
    tenantId = $TenantId; account = $Account; startUtc = $Start.ToString('o'); endUtc = $End.ToString('o'); checkedUtc = [datetime]::UtcNow.ToString('o')
    unifiedAuditRecords = $records.Count; unifiedAuditChanges = $changes.Count; entraDirectoryChanges = $directory.Count
    operations = $byOperation; signInsByApp = $apps
    verdict = $(if ($changes.Count -eq 0 -and $directory.Count -eq 0) { 'no changes' } else { 'changes found' })
}
[System.IO.File]::WriteAllText((Join-Path $out 'summary.json'), (ConvertTo-Json -InputObject $summary -Depth 6), [System.Text.UTF8Encoding]::new($false))

Write-Host ''
Write-Host "Unified audit log: $($records.Count) record(s) for $Account, $($changes.Count) of them change(s)."
Write-Host "Entra directory audit log: $($directory.Count) change(s) by $Account."
foreach ($a in $apps) { Write-Host ("  signed in to {0} ({1}) {2} time(s)" -f $a.app, $a.appId, $a.signIns) }
if ($summary.verdict -eq 'no changes') { Write-Host "No changes by $Account in the window. Details: $out" -ForegroundColor Green }
else { Write-Host "Changes found: see $out (unified-audit-changes.csv, entra-directory-changes.csv). If $Account did other admin work in the window, it is listed too." -ForegroundColor Yellow }
[pscustomobject]$summary
