# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# Why a collection step failed, in words an admin can act on: the cause read from the error text, and from
# requirements.json the role, scopes and licence the step needs.

$script:PostureRequirements = $null
$script:PostureCurrentCollector = $null

function Get-PostureRequirementMap {
    <#
    .SYNOPSIS
        requirements.json, loaded once.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    if (-not $script:PostureRequirements) { $script:PostureRequirements = Get-Content -Raw -LiteralPath (Join-Path $script:ModuleRoot 'requirements.json') | ConvertFrom-Json -AsHashtable -Depth 10 }
    return $script:PostureRequirements
}

function Resolve-PostureStepRequirement {
    <#
    .SYNOPSIS
        What a step needs: the step's own entry when one matches its label, else its collector's.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string] $Collector,
        [Parameter(Mandatory)] [string] $Label
    )
    $map = Get-PostureRequirementMap
    $base = $(if ($Collector -and $map['collectors'].Contains($Collector)) { $map['collectors'][$Collector] } else { @{} })
    $step = @($map['steps'] | Where-Object { (-not $Collector -or $_['collector'] -eq $Collector) -and $Label -match $_['match'] } | Select-Object -First 1)
    $pick = { param([string] $k) if ($step.Count -gt 0 -and $step[0].Contains($k)) { $step[0][$k] } elseif ($base.Contains($k)) { $base[$k] } else { $null } }
    return @{
        collector = $Collector
        service   = $(if ($base.Contains('service')) { [string]$base['service'] } else { $null })
        roles     = @(& $pick 'roles')
        scopes    = @(& $pick 'scopes')
        licence   = [string](& $pick 'licence')
        note      = [string](& $pick 'note')
    }
}

function Get-PostureFailureCause {
    <#
    .SYNOPSIS
        Classifies an error message: licence, token, module, permission, throttled, notProvisioned, network or unknown.
    .DESCRIPTION
        Licence comes before permission because Graph answers a missing licence with 403 too. The patterns are the
        error texts Graph, Exchange Online, Security & Compliance, PnP and Azure return (the ones seen on live runs
        are in the tests); an unknown text stays unknown rather than guessed. Security & Compliance hides a cmdlet
        from an account without the role, which the collectors report as "<cmdlet> is not available": a permission.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()] [string] $Message)

    $m = [string]$Message
    if ($m -match '(?i)(not licensed|licen[cs]e (is )?required|required licen[cs]e|requires? (a |an )?(premium|P1|P2|E5)|AadPremiumLicenseRequired|tenant does not have a (valid )?licen[cs]e|LicenseRequired|SubscriptionNotFound|InvalidLicense|feature is not (enabled|available)|not enabled for (this|the) tenant|Tenant is not onboarded|RequestFromNonPremiumTenantOrB2CTenant|premium licen[cs]e)') { return 'licence' }
    if ($m -match '(?i)(token.*(expired|lifetime)|InvalidAuthenticationToken|AADSTS700082|AADSTS50173|refresh token.*(expired|revoked)|CompactToken)') { return 'token' }
    if ($m -match '(?i)(module (is )?not (available|installed)|Install-Module |Add-WindowsCapability)') { return 'module' }
    if ($m -match '(?i)(\b403\b|Forbidden|Authorization_RequestDenied|Insufficient privileges|AccessDenied|Access (is )?denied|does not have (the )?(required )?permission|is not authorized|isn''t authorized|not within your (current )?(write |management )?scope|UnauthorizedAccess|\b401\b|Unauthorized|missing scope|RoleNotAssigned|-[A-Za-z]+ is not available; import|-[A-Za-z]+ is not in this session|The term ''[A-Za-z]+-[A-Za-z]+'' is not recognized)') { return 'permission' }
    if ($m -match '(?i)(\b429\b|TooManyRequests|throttl|rate limit)') { return 'throttled' }
    if ($m -match '(?i)(\b404\b|ResourceNotFound|Request_ResourceNotFound|not (yet )?provisioned|NotFound\b|could not be found|couldn''t be found|does not exist)') { return 'notProvisioned' }
    if ($m -match '(?i)(timed out|timeout|No such host|Name or service not known|nodename nor servname|connection (was )?(refused|reset|closed)|SSL|network is unreachable|\b50[234]\b|ServiceUnavailable|Bad Gateway)') { return 'network' }
    return 'unknown'
}

function Write-PostureStepFailure {
    <#
    .SYNOPSIS
        Appends one failure to errors.jsonl in the run folder: step, collector, cause, what it needs, the message.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [string] $Label,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Message,
        [string] $Collector = $script:PostureCurrentCollector
    )

    $ErrorActionPreference = 'Stop'
    $need = $(try { Resolve-PostureStepRequirement -Collector $Collector -Label $Label } catch { @{ roles = @(); scopes = @(); licence = ''; note = ''; service = $null } })
    $entry = [ordered]@{
        timeUtc = [datetime]::UtcNow.ToString('o'); collector = $Collector; step = $Label; cause = (Get-PostureFailureCause -Message $Message)
        roles = @($need.roles); scopes = @($need.scopes); licence = $need.licence; note = $need.note; message = $Message
    }
    if (-not $PSCmdlet.ShouldProcess((Join-Path $Folder 'errors.jsonl'), "Record the $Label failure")) { return }
    $line = $entry | ConvertTo-Json -Compress -Depth 5
    Invoke-PostureFolderLock -Folder $Folder -Script { Add-Content -Path (Join-Path $Folder 'errors.jsonl') -Value $line }
}

function Read-PostureRunFailure {
    <#
    .SYNOPSIS
        The failures recorded in a run folder: errors.jsonl, plus any errors.txt line it does not cover (runs made
        before errors.jsonl existed), classified the same way.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.IDictionary[]])]
    param([Parameter(Mandatory)] [string] $Folder)

    $ErrorActionPreference = 'Stop'
    $out = [System.Collections.Generic.List[System.Collections.IDictionary]]::new()
    $jsonl = Join-Path $Folder 'errors.jsonl'
    $covered = [System.Collections.Generic.HashSet[string]]::new()
    if (Test-Path -LiteralPath $jsonl) {
        foreach ($line in Get-Content -LiteralPath $jsonl) {
            if (-not $line.Trim()) { continue }
            try { $e = $line | ConvertFrom-Json -AsHashtable } catch { continue }
            $out.Add($e); $null = $covered.Add("$($e['step']) :: $($e['message'])")
        }
    }
    $txt = Join-Path $Folder 'errors.txt'
    if (Test-Path -LiteralPath $txt) {
        foreach ($line in Get-Content -LiteralPath $txt) {
            if (-not $line.Trim() -or $covered.Contains($line.Trim())) { continue }
            $label, $message = $line -split ' :: ', 2
            $collector = $(if ($label -match '^(\w+) collector$') { $Matches[1] } else { $null })
            $need = Resolve-PostureStepRequirement -Collector $collector -Label $label
            $out.Add([ordered]@{ collector = $collector; step = $label; cause = (Get-PostureFailureCause -Message $message); roles = @($need.roles); scopes = @($need.scopes); licence = $need.licence; note = $need.note; message = [string]$message })
        }
    }
    return $out.ToArray()
}

function Get-PostureFailureAdvice {
    <#
    .SYNOPSIS
        One plain sentence on what to do about a failure, the same in the report and at the console.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Failure)

    $roles = @($Failure['roles'] | Where-Object { $_ })
    $scopes = @($Failure['scopes'] | Where-Object { $_ })
    $licence = [string]$Failure['licence']
    switch ([string]$Failure['cause']) {
        'permission' {
            $t = $(if ($roles.Count) { "Give the account that runs the assessment one of: $($roles -join ', ')." } else { 'The account was refused; the message says by what.' })
            if ($scopes.Count) { $t += " The TenantKeep Posture app needs the delegated permission $($scopes -join ', ') too, which the tenant's consent grants." }
            if ($licence) { $t += " It also needs $licence." }
            return $t
        }
        'licence' { return $(if ($licence) { "Needs $licence. Without it the checks that read this stay not applicable; nothing to grant." } else { 'The tenant is not licensed for this; nothing to grant.' }) }
        'notProvisioned' { return 'Not set up in this tenant, so there was nothing to read. Nothing to grant.' }
        'throttled' { return 'Microsoft asked the run to slow down. Resume-PostureRun tries again.' }
        'network' { return 'A network or service error. Resume-PostureRun tries again.' }
        'token' { return 'The sign-in ran out before this step. Resume-PostureRun signs in again and collects it.' }
        'module' { return 'A PowerShell module is missing; the message says which and how to install it.' }
        default { return "Not a failure the module recognises; Microsoft's message is below.$(if ($roles.Count) { " The step normally needs: $($roles -join ', ')." })" }
    }
}
