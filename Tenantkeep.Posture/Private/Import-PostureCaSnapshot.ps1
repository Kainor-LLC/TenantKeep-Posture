# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Import-PostureCaSnapshot {
    <#
    .SYNOPSIS
        Loads an Export-PostureCaSnapshot folder into one object and validates it.
    .DESCRIPTION
        Shared by New-PostureCaDocument and Compare-PostureCaSnapshot. Reads the seven spec 5.1 files as hashtables
        (wire JSON casing), indexes group-scope by group id, and refuses a folder that is not a CA snapshot.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $Path
    )

    $ErrorActionPreference = 'Stop'

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Snapshot folder not found: $Path" }
    $folder = (Resolve-Path -LiteralPath $Path).Path

    $required = 'policies', 'named-locations', 'auth-strengths', 'auth-context', 'resolved-names', 'group-scope', 'metadata'
    $missing = @($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $folder "$_.json")) })
    if ($missing.Count -gt 0) {
        throw "Not a CA snapshot folder (missing $($missing -join '.json, ').json): $folder"
    }

    $read = {
        param([string] $Name)
        $text = Get-Content -LiteralPath (Join-Path $folder "$Name.json") -Raw
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }
        ConvertFrom-Json -InputObject $text -AsHashtable -Depth 30
    }

    $metadata = & $read 'metadata'
    if (-not $metadata -or (Get-PostureValue $metadata 'snapshotType') -ne 'conditional-access') {
        throw "metadata.json in $folder is not from Export-PostureCaSnapshot (snapshotType must be 'conditional-access')."
    }

    $groupScope = @{}
    foreach ($g in @(& $read 'group-scope')) { if ($g) { $groupScope[[string]$g.groupId] = $g } }

    $errorsPath = Join-Path $folder 'errors.txt'
    $errors = if (Test-Path -LiteralPath $errorsPath) { @(Get-Content -LiteralPath $errorsPath) } else { @() }

    $resolved = & $read 'resolved-names'
    if ($null -eq $resolved) { $resolved = @{} }

    return [ordered]@{
        Path           = $folder
        Metadata       = $metadata
        Policies       = @(& $read 'policies' | Where-Object { $null -ne $_ })
        NamedLocations = @(& $read 'named-locations' | Where-Object { $null -ne $_ })
        AuthStrengths  = @(& $read 'auth-strengths' | Where-Object { $null -ne $_ })
        AuthContexts   = @(& $read 'auth-context' | Where-Object { $null -ne $_ })
        ResolvedNames  = $resolved
        GroupScope     = $groupScope
        Errors         = $errors
    }
}
