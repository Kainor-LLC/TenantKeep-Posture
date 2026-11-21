# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function ConvertTo-PostureCsvSafeText {
    <#
    .SYNOPSIS
        Text for a cell of a CSV that people open in a spreadsheet: a value a spreadsheet would run as a formula
        gets a leading apostrophe, which makes it plain text.
    .DESCRIPTION
        The names in an affected list come from the tenant, and some from outside it: a guest chooses their own
        display name in their home tenant, a device its own name. A cell that starts with =, +, -, @, a tab or a
        carriage return is read as a formula by Excel and others. Used for the exports meant for people
        (affected/<check>.csv, findings.csv, the redaction key), never for the evidence CSVs the module reads back.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Position = 0)] [AllowNull()] [AllowEmptyString()] [string] $Text)

    if ($Text -and $Text -match '^[=+\-@\t\r]') { return "'" + $Text }
    return $Text
}

function ConvertTo-PostureCsvSafeRow {
    <#
    .SYNOPSIS
        A copy of an export row with every text cell made safe for a spreadsheet; numbers and dates as they are.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory, ValueFromPipeline)] [object] $InputObject)

    process {
        $safe = [ordered]@{}
        foreach ($p in $InputObject.PSObject.Properties) { $safe[$p.Name] = $(if ($p.Value -is [string]) { ConvertTo-PostureCsvSafeText $p.Value } else { $p.Value }) }
        [pscustomobject]$safe
    }
}
