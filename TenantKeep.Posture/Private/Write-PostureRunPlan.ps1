# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Write-PostureRunPlan {
    <#
    .SYNOPSIS
        Writes run.json in the run folder: the tenant, the client folder, the collectors the run set out to collect
        and the ones it skipped with why. Resume-PostureRun reads it to know what is still owed; a resume appends to
        its history instead of replacing the plan.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [string] $TenantId,
        [Parameter(Mandatory)] [string] $Client,
        [AllowEmptyCollection()] [string[]] $Collector = @(),
        [System.Collections.IDictionary] $Skipped = @{},
        [switch] $Resume
    )

    $ErrorActionPreference = 'Stop'
    $path = Join-Path $Folder 'run.json'
    $now = [datetime]::UtcNow.ToString('o')
    $doc = $null
    if ($Resume -and (Test-Path -LiteralPath $path)) { try { $doc = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json -AsHashtable -Depth 10 } catch { $doc = $null } }
    if ($doc) {
        $doc['resumes'] = @(@($(if ($doc.Contains('resumes')) { $doc['resumes'] })) + @([ordered]@{ startedUtc = $now; collectors = @($Collector) }) | Where-Object { $_ })
    }
    else {
        $doc = [ordered]@{ tenantId = $TenantId; client = $Client; startedUtc = $now; planned = @($Collector); skipped = [ordered]@{}; resumes = @() }
        foreach ($k in @($Skipped.Keys)) { $doc['skipped'][[string]$k] = [string]$Skipped[$k] }
    }
    if ($PSCmdlet.ShouldProcess($path, 'Write the run plan')) { Save-PostureJsonFile -Path $path -InputObject $doc -Confirm:$false }
}
