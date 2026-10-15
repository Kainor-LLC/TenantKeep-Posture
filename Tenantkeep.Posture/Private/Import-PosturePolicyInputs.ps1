# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Import-PostureBaseline {
    <#
    .SYNOPSIS
        Loads a baseline (spec 10.1) by name from baselines/ or by path: check selection, per-check thresholds, severity overrides.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $Baseline
    )

    $ErrorActionPreference = 'Stop'
    $file = if (Test-Path -LiteralPath $Baseline -PathType Leaf) { $Baseline } else { Join-Path (Get-PostureDataFolder -Name 'baselines') "$Baseline.json" }
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Baseline not found: $Baseline (looked for $file)" }
    $b = Get-Content -Raw -LiteralPath $file | ConvertFrom-Json -AsHashtable -Depth 20
    return [ordered]@{
        name        = [string]$(if ($b['name']) { $b['name'] } else { [System.IO.Path]::GetFileNameWithoutExtension($file) })
        description = [string]$b['description']
        checks      = @($(if ($b.Contains('checks')) { $b['checks'] } else { '*' }))
        exclude     = @($(if ($b.Contains('exclude')) { $b['exclude'] } else { @() }))
        thresholds  = $(if ($b['thresholds']) { $b['thresholds'] } else { @{} })
        severity    = $(if ($b['severity']) { $b['severity'] } else { @{} })
        frameworks  = @($(if ($b.Contains('frameworks')) { $b['frameworks'] } else { @() }))
        path        = (Resolve-Path -LiteralPath $file).Path
    }
}

function Import-PostureProfile {
    <#
    .SYNOPSIS
        Loads profile.json (spec 10.2) over defaults. Without a path, returns an "unknown" profile that gates nothing.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [string] $Path
    )

    $ErrorActionPreference = 'Stop'
    $model = [ordered]@{
        present               = $false
        clientName            = $null
        licenses              = @()
        platforms             = @()
        identityModel         = $null
        byod                  = $null
        externalCollaboration = $null
        copilot               = $null
        azure                 = $null
        thirdParty            = @{}
        frameworks            = @()
        thresholds            = @{}
        breakGlass            = @()
        audience              = 'technical'
        cadence               = $null
        tenantId              = $null
        sharePointClientId    = $null
        path                  = $null
    }
    if (-not $Path) { return $model }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "profile.json not found: $Path" }
    $p = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -AsHashtable -Depth 20
    foreach ($key in @($model.Keys)) {
        if ($key -in 'present', 'path') { continue }
        if ($p.Contains($key)) { $model[$key] = $(if ($model[$key] -is [array]) { @($p[$key]) } else { $p[$key] }) }
    }
    $model.present = $true
    $model.path = (Resolve-Path -LiteralPath $Path).Path
    return $model
}

function Import-PostureException {
    <#
    .SYNOPSIS
        Loads exceptions.json (spec 10.1): accepted risk per check or per object, with justification, owner, approver and expiry.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [string] $Path,
        [datetime] $AsOf = [datetime]::UtcNow
    )

    $ErrorActionPreference = 'Stop'
    if (-not $Path) { return @() }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "exceptions.json not found: $Path" }
    $doc = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -AsHashtable -Depth 10
    $list = if ($doc -is [System.Collections.IDictionary] -and $doc.Contains('exceptions')) { @($doc['exceptions']) } else { @($doc) }
    $out = foreach ($e in $list) {
        if (-not $e['check']) { throw 'An exception entry has no check id.' }
        $expires = ConvertTo-PostureUtcDateTime (Get-PostureValue $e 'expires')
        [ordered]@{
            check         = [string]$e['check']
            object        = $(if ($e['object']) { [string]$e['object'] } else { $null })
            justification = [string](Get-PostureValue $e 'justification')
            owner         = [string](Get-PostureValue $e 'owner')
            approver      = [string](Get-PostureValue $e 'approver')
            expires       = $expires
            expired       = [bool]($expires -and $expires -lt $AsOf)
        }
    }
    return @($out)
}
