# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Initialize-ClientRunFixture {
    <#
    .SYNOPSIS
        A client folder and an output root with one evaluated run (the synthetic identity and auth evidence), for the
        cmdlets that change the client folder and rebuild the newest report. Every value is made up.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Root,
        [string] $TenantId = '11111111-2222-3333-4444-555555555555'
    )

    . (Join-Path $PSScriptRoot 'CollectionFixture.ps1')
    $client = Join-Path $Root 'clients' 'contoso'
    $outRoot = Join-Path $Root 'evidence'
    New-Item -ItemType Directory -Path $client, $outRoot -Force | Out-Null
    @{ version = 1; tenantId = $TenantId; clientName = 'Contoso'; licenses = @('P2') } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $client 'profile.json')
    $run = Initialize-CollectionFixture -Root (Join-Path $outRoot '20261101-1000')
    @{ tenantId = $TenantId; timestampUtc = '2026-11-01T10:00:00Z'; collectors = @('Entra') } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $run 'collection.json')
    $null = Invoke-PostureChecks -Evidence $run -Domain identity, auth -OutputPath $run
    return @{ Client = $client; OutRoot = $outRoot; Run = $run; TenantId = $TenantId; ClientsRoot = (Join-Path $Root 'clients') }
}
