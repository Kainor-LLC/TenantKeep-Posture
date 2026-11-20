# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureException {
    <#
    .SYNOPSIS
        Lists the accepted risks in a client folder's exceptions.json, with the check title and whether each has expired.
    .DESCRIPTION
        Reads the file only. An expired exception no longer counts: the check fails again on the next run until it is
        renewed with Add-PostureException or removed with Remove-PostureException.
    .PARAMETER TenantId
        The tenant id from the report header. Finds the client folder whose profile.json names it.
    .PARAMETER Client
        The client folder, instead of -TenantId.
    .PARAMETER Check
        Only the exceptions for this check.
    .PARAMETER Expired
        Only the expired ones.
    .EXAMPLE
        Get-PostureException -TenantId 00000000-0000-0000-0000-000000000000
    .EXAMPLE
        Get-PostureException -Client ~/tenantkeep/clients/contoso -Expired
    .OUTPUTS
        One object per exception: Check, Title, Object, Justification, Owner, Approver, Expires, Expired.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')] [string] $TenantId,
        [string] $Client,
        [string] $Check,
        [switch] $Expired
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $folder = Resolve-PostureClientFolder -Client $Client -TenantId $TenantId
    $titles = @{}; foreach ($c in (Import-PostureCheckCatalog).checks) { $titles[[string]$c['id']] = [string]$c['title'] }
    $today = [datetime]::UtcNow.Date
    foreach ($e in (Read-PostureExceptionFile -Path (Join-Path $folder 'exceptions.json'))) {
        $id = [string]$e['check']
        if ($Check -and $id -ne $Check) { continue }
        $expires = ConvertTo-PostureUtcDateTime (Get-PostureValue $e 'expires')
        $isExpired = [bool]($expires -and $expires.Date -lt $today)
        if ($Expired -and -not $isExpired) { continue }
        [pscustomobject]@{
            Check         = $id
            Title         = $(if ($titles.ContainsKey($id)) { $titles[$id] } else { '(not in the catalog)' })
            Object        = [string](Get-PostureValue $e 'object')
            Justification = [string](Get-PostureValue $e 'justification')
            Owner         = [string](Get-PostureValue $e 'owner')
            Approver      = [string](Get-PostureValue $e 'approver')
            Expires       = $(if ($expires) { $expires.ToString('yyyy-MM-dd') } else { 'no expiry' })
            Expired       = $isExpired
        }
    }
}
