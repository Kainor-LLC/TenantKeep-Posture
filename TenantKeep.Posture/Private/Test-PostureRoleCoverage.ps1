# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Test-PostureRoleCoverage {
    <#
    .SYNOPSIS
        Before collecting: does the signed-in account hold a role each collector needs? One row per collector:
        ok, missing (and what to grant), or unknown (an Exchange, Purview or Azure role Graph cannot see).
    .DESCRIPTION
        Reads the account's active directory roles (me/transitiveMemberOf, so roles through a group count too).
        PIM-eligible roles count only once activated, which is what the services check as well. The run goes on
        either way; the point is to say before a long run what will come back empty and what to grant.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string[]] $Collector
    )

    $ErrorActionPreference = 'Stop'
    $null = Assert-PostureGraphScope -AnyOfScope 'Directory.Read.All', 'RoleManagement.Read.Directory'
    $held = @(Invoke-PostureGraphRequest -ApiVersion v1.0 -Uri 'me/transitiveMemberOf/microsoft.graph.directoryRole?$select=displayName' | ForEach-Object { [string]$_['displayName'] } | Where-Object { $_ })
    $map = Get-PostureRequirementMap
    foreach ($c in $Collector) {
        if (-not $map['collectors'].Contains($c)) { continue }
        $need = @($map['collectors'][$c]['roles'])
        # Entra directory roles are plain names; role groups and Azure roles carry a qualifier in brackets.
        $entra = @($need | Where-Object { $_ -notmatch '\(' })
        $other = @($need | Where-Object { $_ -match '\(' })
        $have = @($held | Where-Object { $_ -in $entra -or $_ -eq 'Global Administrator' })
        $status = $(if ($have.Count -gt 0) { 'ok' } elseif ($other.Count -gt 0 -or $entra.Count -eq 0) { 'unknown' } else { 'missing' })
        [pscustomobject]@{
            Collector = $c
            Status    = $status
            Have      = ($have -join ', ')
            Needs     = ($need -join ' or ')
            Detail    = switch ($status) {
                'ok' { "covered by $($have -join ', ')" }
                'missing' { "needs $($need -join ' or '); you have $(if ($held.Count) { $held -join ', ' } else { 'no admin role' })" }
                default { "checked when it connects: needs $($need -join ' or ')" }
            }
        }
    }
}
