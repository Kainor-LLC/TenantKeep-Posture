# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Test-PostureExoSession {
    <#
    .SYNOPSIS
        True when an Exchange Online PowerShell session (ExchangeOnlineManagement 3.x) is connected. Never connects.
        With -TenantId, only when every connected session is in that tenant: the commands go to whichever session the
        module picks, so a second one in another tenant could answer for the first.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string] $TenantId)

    $ErrorActionPreference = 'Stop'
    if (-not (Get-Command -Name Get-ConnectionInformation -ErrorAction SilentlyContinue)) { return $false }
    $info = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Connected' -and $_.ConnectionUri -notmatch 'compliance' })
    if ($TenantId -and @($info | Where-Object { [string]$_.TenantID -ne $TenantId }).Count) { return $false }
    return $info.Count -gt 0
}

function Test-PosturePurviewSession {
    <#
    .SYNOPSIS
        True when a Security and Compliance PowerShell session (Connect-IPPSSession) is connected. Never connects.
        With -TenantId, only when every connected session is in that tenant.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string] $TenantId)

    $ErrorActionPreference = 'Stop'
    if (-not (Get-Command -Name Get-ConnectionInformation -ErrorAction SilentlyContinue)) { return $false }
    $info = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Connected' -and $_.ConnectionUri -match 'compliance' })
    if ($TenantId -and @($info | Where-Object { [string]$_.TenantID -ne $TenantId }).Count) { return $false }
    return $info.Count -gt 0
}

function Invoke-PostureExoCommand {
    <#
    .SYNOPSIS
        The single entry point for Exchange Online and Security and Compliance cmdlets: Get-* only, by name, so tests can mock one function.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [ValidatePattern('^Get-[A-Za-z0-9]+$')] [string] $Name,
        [hashtable] $Parameters = @{},
        # Called with each object as the cmdlet emits it, instead of collecting them: large tenants stream to disk.
        [scriptblock] $OnItem
    )

    $ErrorActionPreference = 'Stop'
    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
        # A connected session loads only the cmdlets the signed-in roles and the tenant's licences expose (seen live on
        # Business Premium, 2026-10-23: no Get-AutoSensitivityLabelPolicy, no Get-InformationBarrierPolicy).
        if ((Test-PostureExoSession) -or (Test-PosturePurviewSession)) { throw "$Name is not in this session: the signed-in roles or the tenant's licences do not expose it." }
        throw "$Name is not available; import ExchangeOnlineManagement and connect first."
    }
    Add-PostureCallRecord -Service exchange -Method cmdlet -Target $Name
    if ($OnItem) { & $Name @Parameters | ForEach-Object { & $OnItem $_ }; return }
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
        Empty array when DNS answers that nothing is published. Throws when the lookup itself failed (a timeout, a
        server failure, no resolver reached): no answer is not the same as "no record". Tests mock this function.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [ValidateSet('TXT', 'MX')] [string] $Type = 'TXT'
    )

    $ErrorActionPreference = 'Stop'
    if ($IsWindows) {
        # The answer can carry extra records of other types (CNAME, A); only the requested type has the fields read below.
        try { $r = @(Resolve-DnsName -Name $Name -Type $Type -ErrorAction Stop | Where-Object { [string]$_.Type -eq $Type }) }
        catch {
            # "The name does not exist" and "no records of that type" are answers. Anything else is a failed lookup.
            # (verify on Windows: 9003 DNS_ERROR_RCODE_NAME_ERROR, 9501 DNS_INFO_NO_RECORDS)
            $code = $(if ($_.Exception.PSObject.Properties['NativeErrorCode']) { [int]$_.Exception.NativeErrorCode } else { 0 })
            if ($code -in 9003, 9501 -or [string]$_.Exception.Message -match '(?i)DNS name does not exist|no records|DNS_INFO_NO_RECORDS|DNS_ERROR_RCODE_NAME_ERROR') { return @() }
            throw "DNS lookup failed for $Type $($Name): $($_.Exception.Message)"
        }
        if ($Type -eq 'TXT') { return @($r | ForEach-Object { (@($_.Strings) -join '') } | Where-Object { $_ }) }
        return @($r | ForEach-Object { "$($_.Preference) $($_.NameExchange)" } | Where-Object { $_ })
    }
    $dig = Get-Command -Name dig -ErrorAction SilentlyContinue
    if (-not $dig) { throw 'dig is not available; install bind tools or run the DNS step on Windows.' }
    # The header says whether DNS answered: NOERROR and NXDOMAIN are answers, anything else (SERVFAIL, REFUSED) or no
    # header at all (timed out, no servers could be reached) is a failed lookup.
    $lines = @(& $dig.Source +time=3 +tries=2 +noall +comments +answer $Type $Name 2>$null)
    return (ConvertFrom-PostureDigAnswer -Line $lines -Name $Name -Type $Type)
}

function ConvertFrom-PostureDigAnswer {
    <#
    .SYNOPSIS
        Reads dig's "+noall +comments +answer" output: the record strings of the requested type, an empty array when
        DNS answered that there are none, an error when there was no answer to read.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [AllowEmptyCollection()] [AllowEmptyString()] [string[]] $Line = @(),
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [ValidateSet('TXT', 'MX')] [string] $Type
    )

    $ErrorActionPreference = 'Stop'
    $status = $null
    foreach ($l in $Line) { if ([string]$l -match 'status:\s*([A-Z]+)') { $status = $Matches[1]; break } }
    if ($status -notin 'NOERROR', 'NXDOMAIN') { throw "DNS lookup failed for $Type $($Name): $(if ($status) { "the server answered $status" } else { 'no answer (timed out, or no resolver reached)' })" }
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($l in $Line) {
        $text = [string]$l
        if (-not $text.Trim() -or $text.StartsWith(';')) { continue }
        # name, time to live, class, type, then the record data.
        $m = [regex]::Match($text, '^\S+\s+\d+\s+IN\s+(\S+)\s+(.+)$')
        if (-not $m.Success -or $m.Groups[1].Value -ne $Type) { continue }
        $data = $m.Groups[2].Value.Trim()
        if ($Type -eq 'TXT') { $out.Add(((($data -replace '"\s+"', '') -replace '^"|"$', '') -replace '\\"', '"')) }
        else { $out.Add(($data -replace '\.$', '').Trim()) }
    }
    return $out.ToArray()
}
