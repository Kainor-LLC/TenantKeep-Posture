# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function ConvertTo-PostureUtcDateTime {
    <#
    .SYNOPSIS
        Normalises a Graph timestamp to a UTC DateTime, whatever shape it arrived in.
    .DESCRIPTION
        ConvertFrom-Json turns ISO 8601 strings into DateTime objects (Kind Local) before module code sees them,
        and raw Graph hashtables keep them as strings. Every date in a document goes through here so it is
        rendered in UTC regardless of the machine's time zone. Returns $null for empty input.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter()] [AllowNull()] [object] $Value
    )

    $ErrorActionPreference = 'Stop'
    if ($null -eq $Value -or $Value -eq '') { return $null }
    if ($Value -is [System.DateTimeOffset]) { return $Value.UtcDateTime }
    if ($Value -is [datetime]) {
        switch ($Value.Kind) {
            'Utc' { return $Value }
            'Local' { return $Value.ToUniversalTime() }
            default { return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) }
        }
    }
    return [System.DateTimeOffset]::Parse([string]$Value, [cultureinfo]::InvariantCulture).UtcDateTime
}
