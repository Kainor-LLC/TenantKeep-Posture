# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Test-PostureExoSession {
    <#
    .SYNOPSIS
        True when an Exchange Online PowerShell session (ExchangeOnlineManagement 3.x) is connected. Never connects.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $ErrorActionPreference = 'Stop'
    if (-not (Get-Command -Name Get-ConnectionInformation -ErrorAction SilentlyContinue)) { return $false }
    $info = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Connected' -and $_.ConnectionUri -notmatch 'compliance' })
    return $info.Count -gt 0
}

function Invoke-PostureExoCommand {
    <#
    .SYNOPSIS
        The single entry point for Exchange Online cmdlets: Get-* only, by name, so tests can mock one function.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [ValidatePattern('^Get-[A-Za-z0-9]+$')] [string] $Name,
        [hashtable] $Parameters = @{}
    )

    $ErrorActionPreference = 'Stop'
    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) { throw "$Name is not available; import ExchangeOnlineManagement and connect first." }
    return @(& $Name @Parameters)
}

function ConvertTo-PostureFlatObject {
    <#
    .SYNOPSIS
        Projects a rich cmdlet object to an ordered dictionary of scalar and scalar-list properties, so evidence stays
        small and predictable. -Property limits the set; otherwise every scalar property is kept.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] [object] $InputObject,
        [string[]] $Property
    )

    process {
        $ErrorActionPreference = 'Stop'
        $out = [ordered]@{}
        $names = if ($Property) { $Property } else { @($InputObject.PSObject.Properties | Where-Object { $_.MemberType -in 'Property', 'NoteProperty', 'AliasProperty' } | ForEach-Object { $_.Name }) }
        foreach ($n in $names) {
            $prop = $InputObject.PSObject.Properties[$n]
            if (-not $prop) { $out[$n] = $null; continue }
            $val = $prop.Value
            if ($null -eq $val) { $out[$n] = $null }
            elseif ($val -is [string] -or $val -is [bool] -or $val -is [int] -or $val -is [long] -or $val -is [double] -or $val -is [datetime] -or $val -is [enum] -or $val -is [guid]) { $out[$n] = $(if ($val -is [enum] -or $val -is [guid]) { [string]$val } else { $val }) }
            elseif ($val -is [System.Collections.IEnumerable] -and $val -isnot [System.Collections.IDictionary]) { $out[$n] = @($val | ForEach-Object { [string]$_ }) }
            else { $out[$n] = [string]$val }
        }
        $out
    }
}

function Resolve-PostureDnsRecord {
    <#
    .SYNOPSIS
        Returns the TXT or MX record strings for a name, through dig on macOS and Linux and Resolve-DnsName on Windows.
        Empty array when nothing is published. Tests mock this function.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [ValidateSet('TXT', 'MX')] [string] $Type = 'TXT'
    )

    $ErrorActionPreference = 'Stop'
    if ($IsWindows) {
        $r = @(Resolve-DnsName -Name $Name -Type $Type -ErrorAction SilentlyContinue)
        if ($Type -eq 'TXT') { return @($r | ForEach-Object { ($_.Strings -join '') } | Where-Object { $_ }) }
        return @($r | ForEach-Object { "$($_.Preference) $($_.NameExchange)" } | Where-Object { $_ })
    }
    $dig = Get-Command -Name dig -ErrorAction SilentlyContinue
    if (-not $dig) { throw 'dig is not available; install bind tools or run the DNS step on Windows.' }
    $lines = @(& $dig.Source +short +time=3 +tries=1 $Type $Name 2>$null | Where-Object { $_ })
    if ($Type -eq 'TXT') { return @($lines | ForEach-Object { ($_ -replace '"\s+"', '') -replace '^"|"$', '' }) }
    return @($lines | ForEach-Object { ($_ -replace '\.$', '').Trim() })
}
