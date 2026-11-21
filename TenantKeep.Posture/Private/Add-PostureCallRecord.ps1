# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# The call ledger: every request the module sends to the tenant, counted by service, method and target, so a run can
# show exactly what it did. Kept in memory per process and merged into logs/calls.json in the run folder.
$script:PostureCallLedger = [System.Collections.Generic.Dictionary[string, int]]::new()
# The last request sent, so a failed step can say which request it was (Invoke-PostureStep clears it per step).
$script:PostureLastCall = ''

function ConvertTo-PostureCallTarget {
    <#
    .SYNOPSIS
        A request target without the parts that name things in the tenant: no host or query string, ids and accounts
        replaced by placeholders. 'https://graph.microsoft.com/v1.0/users/0b1c.../memberOf?$select=id' becomes
        'v1.0/users/{id}/memberOf'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Target)

    $t = $Target -replace '^https?://[^/]+/', '' -replace '\?.*$', ''
    $t = $t -replace '[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}', '{id}'
    $t = $t -replace "[^/'()]+@[^/'()]+", '{user}'
    # A key segment in the OData form users('x') or Graph's ids that are not GUIDs (long base64 or hex).
    $t = $t -replace "\('[^']*'\)", '({id})' -replace '/[A-Za-z0-9_=-]{40,}(?=/|$)', '/{id}'
    return $t.TrimStart('/')
}

function Add-PostureCallRecord {
    <#
    .SYNOPSIS
        Counts one request in the ledger. The wrappers call it: Graph pages, Exchange and Purview, PnP and Teams
        commands, Azure requests and queries.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('graph', 'exchange', 'sharepoint', 'teams', 'azure')] [string] $Service,
        [Parameter(Mandatory)] [string] $Method,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Target
    )

    $clean = ConvertTo-PostureCallTarget -Target $Target
    $script:PostureLastCall = "$Service $($Method.ToUpperInvariant()) $clean"
    $key = "$Service`t$($Method.ToUpperInvariant())`t$clean"
    $current = 0
    $null = $script:PostureCallLedger.TryGetValue($key, [ref]$current)
    $script:PostureCallLedger[$key] = $current + 1
}

function Save-PostureCallLedger {
    <#
    .SYNOPSIS
        Adds this process's counts to logs/calls.json in the run folder and empties the ledger, so a second save in the
        same process does not count anything twice. The main process and the Exchange process each save their own.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Folder)

    $ErrorActionPreference = 'Stop'
    $ledgerPath = Join-Path (Get-PostureRunLayout -Folder $Folder).logs 'calls.json'
    if ($script:PostureCallLedger.Count -eq 0 -or -not $PSCmdlet.ShouldProcess($ledgerPath, 'Write the call ledger')) { return $ledgerPath }
    # The Exchange process and the main process can save at the same moment; the folder lock keeps one at a time.
    # Names here are unlike the lock function's own, which the script block would otherwise see first.
    $pendingCalls = $script:PostureCallLedger
    Invoke-PostureFolderLock -Folder $Folder -Script {
        $mergedCalls = [ordered]@{}
        if (Test-Path -LiteralPath $ledgerPath) {
            try { foreach ($e in @((Get-Content -Raw -LiteralPath $ledgerPath | ConvertFrom-Json -AsHashtable -Depth 6)['calls'])) { $mergedCalls["$($e['service'])`t$($e['method'])`t$($e['target'])"] = [int]$e['count'] } }
            catch { Write-Verbose "calls.json could not be read and is started again: $($_.Exception.Message)" }
        }
        foreach ($k in $pendingCalls.Keys) { $mergedCalls[$k] = $pendingCalls[$k] + $(if ($mergedCalls.Contains($k)) { [int]$mergedCalls[$k] } else { 0 }) }
        $callRows = @($mergedCalls.Keys | Sort-Object | ForEach-Object { $p = $_ -split "`t", 3; [ordered]@{ service = $p[0]; method = $p[1]; target = $p[2]; count = $mergedCalls[$_] } })
        New-Item -ItemType Directory -Path (Split-Path $ledgerPath -Parent) -Force | Out-Null
        $ledgerDoc = [ordered]@{ about = 'Every request this run sent to the tenant, by service, method and target, counted. Ids and accounts are replaced by placeholders. Written by TenantKeep Posture.'; updatedUtc = [datetime]::UtcNow.ToString('o'); calls = $callRows }
        [System.IO.File]::WriteAllText($ledgerPath, (ConvertTo-Json -InputObject $ledgerDoc -Depth 6), [System.Text.UTF8Encoding]::new($false))
    }
    $script:PostureCallLedger.Clear()
    return $ledgerPath
}

function Get-PostureCallSummary {
    <#
    .SYNOPSIS
        The run's call ledger for the report: totals by service and kind, and any call that is not a read. Reads are
        GET requests, Get- commands, Resource Graph queries, and the four POSTs that are reads with the question in the
        body (Graph batches of reads, advanced hunting queries, directory lookups by id, the Cost Management query),
        the same four the module test allows. Anything else is listed as unexpected; there should never be any.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([Parameter(Mandatory)] [string] $Folder)

    $ErrorActionPreference = 'Stop'
    $path = Join-Path (Get-PostureRunLayout -Folder $Folder).logs 'calls.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $calls = @((Get-Content -Raw -LiteralPath $path | ConvertFrom-Json -AsHashtable -Depth 6)['calls'] | Where-Object { $_ })
    $isRead = {
        param($c)
        $m = [string]$c['method']; $t = [string]$c['target']
        ($m -eq 'GET') -or ($m -eq 'CMDLET' -and $t -match '^Get-') -or ($m -eq 'QUERY') -or
        ($m -eq 'POST' -and [string]$c['service'] -eq 'graph' -and $t -match '^(v1\.0|beta)/(\$batch|security/runHuntingQuery|directoryObjects/getByIds)$') -or
        ($m -eq 'POST' -and [string]$c['service'] -eq 'azure' -and $t -match '/providers/Microsoft\.CostManagement/query$')
    }
    $label = @{ graph = 'Microsoft Graph'; exchange = 'Exchange Online and Purview'; sharepoint = 'SharePoint'; teams = 'Teams'; azure = 'Azure' }
    $services = foreach ($s in 'graph', 'exchange', 'sharepoint', 'teams', 'azure') {
        $mine = @($calls | Where-Object { $_['service'] -eq $s })
        if (-not $mine.Count) { continue }
        $top = @($mine | Sort-Object { - [int]$_['count'] }, { $_['target'] } | Select-Object -First 8 | ForEach-Object { [ordered]@{ method = [string]$_['method']; target = [string]$_['target']; count = [int]$_['count'] } })
        [ordered]@{ service = $s; label = $label[$s]; requests = [int](($mine | ForEach-Object { [int]$_['count'] } | Measure-Object -Sum).Sum); targets = $mine.Count; top = $top }
    }
    $unexpected = @($calls | Where-Object { -not (& $isRead $_) } | ForEach-Object { [ordered]@{ service = [string]$_['service']; method = [string]$_['method']; target = [string]$_['target']; count = [int]$_['count'] } })
    return [ordered]@{
        total      = [int](($calls | ForEach-Object { [int]$_['count'] } | Measure-Object -Sum).Sum)
        services   = @($services)
        unexpected = $unexpected
        file       = 'logs/calls.json'
    }
}
