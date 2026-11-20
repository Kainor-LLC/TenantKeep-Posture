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
        [Parameter(Mandatory)] [string[]] $Collector,
        # The account's active roles, when the caller already read them (Get-PostureSignedInRole).
        [AllowEmptyCollection()] [string[]] $HeldRole
    )

    $ErrorActionPreference = 'Stop'
    $held = @(if ($PSBoundParameters.ContainsKey('HeldRole')) { $HeldRole } else { Get-PostureSignedInRole })
    $map = Get-PostureRequirementMap
    foreach ($c in $Collector) {
        if (-not $map['collectors'].Contains($c)) { continue }
        $need = @($map['collectors'][$c]['roles'])
        # Entra directory roles are plain names; role groups and Azure roles carry a qualifier in brackets.
        $entra = @($need | Where-Object { $_ -notmatch '\(' })
        $other = @($need | Where-Object { $_ -match '\(' })
        # Roles that work but grant more than this read-only run needs (Exchange Administrator, Global Administrator).
        $broader = @(@(if ($map['collectors'][$c].Contains('alsoWorks')) { $map['collectors'][$c]['alsoWorks'] }) + @('Global Administrator') | Sort-Object -Unique)
        $have = @($held | Where-Object { $_ -in $entra })
        $haveBroader = @($held | Where-Object { $_ -in $broader -and $_ -notin $entra })
        $status = $(if ($have.Count -gt 0 -or $haveBroader.Count -gt 0) { 'ok' } elseif ($other.Count -gt 0 -or $entra.Count -eq 0) { 'unknown' } else { 'missing' })
        [pscustomobject]@{
            Collector = $c
            Status    = $status
            Have      = ($have -join ', ')
            Needs     = ($need -join ' or ')
            Detail    = switch ($status) {
                'ok' { $(if ($have.Count -gt 0) { "covered by $($have -join ', ')" } else { "covered by $($haveBroader -join ', '), which is more than this run needs; $($need -join ' or ') is enough" }) }
                'missing' { "needs $($need -join ' or '); you have $(if ($held.Count) { $held -join ', ' } else { 'no admin role' })" }
                default { "checked when it connects: needs $($need -join ' or ')" }
            }
        }
    }
}

function Get-PostureSignedInRole {
    <#
    .SYNOPSIS
        The signed-in account's active directory roles, including those it holds through a group.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $ErrorActionPreference = 'Stop'
    $null = Assert-PostureGraphScope -AnyOfScope 'Directory.Read.All', 'RoleManagement.Read.Directory'
    return @(Invoke-PostureGraphRequest -ApiVersion v1.0 -Uri 'me/transitiveMemberOf/microsoft.graph.directoryRole?$select=displayName' | ForEach-Object { [string]$_['displayName'] } | Where-Object { $_ } | Sort-Object -Unique)
}
