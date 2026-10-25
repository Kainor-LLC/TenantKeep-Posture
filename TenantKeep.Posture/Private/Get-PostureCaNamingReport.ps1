# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureCaNamingReport {
    <#
    .SYNOPSIS
        Naming convention report (spec 5.2): the pattern, which policies conform, and a proposed name for each that does not.
    .DESCRIPTION
        The proposed name is a heuristic built from a format string. Tokens: {seq} (next free three-digit number,
        counting from the highest number found in conforming names), {persona} (Admins, Guests, WorkloadIDs or Users),
        {action} (the short control label), {name} (the current name). Default: CA-{seq}-{persona}-{action}.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Policy,
        [Parameter(Mandatory)] [string] $NamePattern,
        [string] $ProposedNameFormat = 'CA-{seq}-{persona}-{action}'
    )

    $ErrorActionPreference = 'Stop'

    $conforming = @($Policy | Where-Object { $_.name -match $NamePattern })
    $nonConforming = @($Policy | Where-Object { $_.name -notmatch $NamePattern })

    $maxSeq = 0
    foreach ($p in $conforming) {
        if ($p.name -match '(?<!\d)(\d{3})(?!\d)') { $n = [int]$Matches[1]; if ($n -gt $maxSeq) { $maxSeq = $n } }
    }

    $persona = {
        param($p)
        $a = $p.assignments
        if (@($a.includeRoles).Count -gt 0) { return 'Admins' }
        if (@($a.includeServicePrincipals).Count -gt 0) { return 'WorkloadIDs' }
        if ($a.includeGuestsOrExternal -or @($a.includeUsers | Where-Object { $_.id -eq 'GuestsOrExternalUsers' }).Count -gt 0) { return 'Guests' }
        return 'Users'
    }

    $proposals = foreach ($p in $nonConforming) {
        $maxSeq++
        $proposed = $ProposedNameFormat
        $proposed = $proposed.Replace('{seq}', $maxSeq.ToString('000'))
        $proposed = $proposed.Replace('{persona}', (& $persona $p))
        $proposed = $proposed.Replace('{action}', (Get-PostureCaControlLabel -Policy $p))
        $proposed = $proposed.Replace('{name}', $p.name)
        [ordered]@{ id = $p.id; name = $p.name; proposedName = $proposed; matchesAfterRename = [bool]($proposed -match $NamePattern) }
    }

    return [ordered]@{
        pattern       = $NamePattern
        format        = $ProposedNameFormat
        conforming    = @($conforming | ForEach-Object { $_.name })
        nonConforming = @($proposals)
    }
}
