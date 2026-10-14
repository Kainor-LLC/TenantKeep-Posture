# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function New-PostureProfile {
    <#
    .SYNOPSIS
        Writes profile.json, the org profile every check reads (spec 10.2): licenses, platforms, identity model,
        stance on BYOD, guests and Copilot, third-party controls, frameworks, thresholds, audience, cadence and
        break-glass accounts.
    .DESCRIPTION
        Interactive by default: about twelve questions, each with a default, the current value when the file
        already exists. Every answer is also a parameter, and -NonInteractive writes the profile from parameters and
        defaults without asking. Licenses are detected rather than typed: from 01-subscribed-skus.json in an
        evidence folder (-Evidence) or live from Graph (-FromGraph, read-only), then shown for confirmation.
    .PARAMETER Path
        Where to write. Default: ./profile.json. An existing file is read first and its answers become the defaults.
    .PARAMETER Evidence
        Evidence folder holding 01-subscribed-skus.json for license detection.
    .PARAMETER FromGraph
        Detect licenses from the signed-in Graph session (Organization.Read.All or Directory.Read.All).
    .PARAMETER NonInteractive
        Ask nothing; write parameters over existing values over defaults.
    .PARAMETER Force
        Overwrite without asking, in interactive mode, when the file exists.
    .PARAMETER PassThru
        Return the profile object instead of the path.
    .EXAMPLE
        Connect-MgGraph -Scopes Organization.Read.All -NoWelcome
        New-PostureProfile -Path ./clients/contoso/profile.json -FromGraph

        Detects licenses, then asks the questions.
    .EXAMPLE
        New-PostureProfile -Path ./profile.json -NonInteractive -Licenses P1, Intune -Platforms windows, macOS -IdentityModel cloud-only -BreakGlass bg01@contoso.example, bg02@contoso.example -Thresholds @{ namePattern = '^CA\d{3} - ' }

        Scripted, no prompts.
    .OUTPUTS
        System.String, the file path. With -PassThru, the profile object.
    .LINK
        docs/profile.md
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string], [System.Collections.Specialized.OrderedDictionary])]
    param(
        [string] $Path = './profile.json',
        [string] $Evidence,
        [switch] $FromGraph,
        [switch] $NonInteractive,
        [ValidateSet('E3', 'E5', 'BusinessPremium', 'P1', 'P2', 'Intune', 'IntuneSuite', 'EntraSuite', 'MDO1', 'MDO2', 'MDE1', 'MDE2', 'MDEBusiness', 'Purview', 'Copilot', 'SAM')]
        [string[]] $Licenses,
        [ValidateSet('windows', 'macOS', 'linux', 'iOS', 'android')] [string[]] $Platforms,
        [ValidateSet('cloud-only', 'hybrid-connect', 'hybrid-cloud-sync', 'hybrid-adfs')] [string] $IdentityModel,
        [ValidateSet('none', 'mam', 'mdm')] [string] $Byod,
        [ValidateSet('locked', 'governed', 'open')] [string] $ExternalCollaboration,
        [ValidateSet('none', 'pilot', 'deployed')] [string] $Copilot,
        [ValidateSet('none', 'platform', 'workloads')] [string] $Azure,
        [hashtable] $ThirdParty,
        [ValidateSet('none', 'hipaa', 'pci', 'cmmc', 'soc2', 'iso27001', 'nist-800-171', 'cisa-scuba')] [string[]] $Frameworks,
        [hashtable] $Thresholds,
        [string[]] $BreakGlass,
        [ValidateSet('executive', 'technical', 'auditor')] [string] $Audience,
        [ValidateSet('one-off', 'monthly', 'quarterly')] [string] $Cadence,
        [string] $ClientName,
        [switch] $Force,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $defaults = [ordered]@{
        clientName            = $null
        licenses              = @()
        platforms             = @('windows')
        identityModel         = 'cloud-only'
        byod                  = 'mam'
        externalCollaboration = 'governed'
        copilot               = 'none'
        azure                 = 'none'
        thirdParty            = [ordered]@{ email = 'none'; edr = 'none'; mfa = 'none'; mdm = 'none'; siem = 'none'; backup = 'none' }
        frameworks            = @()
        thresholds            = [ordered]@{ maxPermanentGlobalAdmins = 2; staleDeviceDays = 90; maxExclusionGroupMembers = 25; inactiveGuestDays = 90; reportOnlyMaxDays = 90; disabledMaxDays = 90; criticalCveMaxAgeDays = 14; namePattern = $null }
        audience              = 'technical'
        cadence               = 'quarterly'
        breakGlass            = @()
    }

    # Existing file: its answers become the defaults.
    $existing = $null
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $existing = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -AsHashtable -Depth 10
        foreach ($k in @($defaults.Keys)) {
            if (-not $existing.Contains($k)) { continue }
            if ($defaults[$k] -is [System.Collections.IDictionary]) { foreach ($sub in @($existing[$k].Keys)) { $defaults[$k][$sub] = $existing[$k][$sub] } }
            elseif ($defaults[$k] -is [array]) { $defaults[$k] = @($existing[$k]) }
            else { $defaults[$k] = $existing[$k] }
        }
    }

    # Parameters win over the file.
    if ($PSBoundParameters.ContainsKey('ClientName')) { $defaults.clientName = $ClientName }
    if ($PSBoundParameters.ContainsKey('Licenses')) { $defaults.licenses = @($Licenses) }
    if ($PSBoundParameters.ContainsKey('Platforms')) { $defaults.platforms = @($Platforms) }
    if ($IdentityModel) { $defaults.identityModel = $IdentityModel }
    if ($Byod) { $defaults.byod = $Byod }
    if ($ExternalCollaboration) { $defaults.externalCollaboration = $ExternalCollaboration }
    if ($Copilot) { $defaults.copilot = $Copilot }
    if ($Azure) { $defaults.azure = $Azure }
    if ($ThirdParty) { foreach ($k in $ThirdParty.Keys) { $defaults.thirdParty[[string]$k] = [string]$ThirdParty[$k] } }
    if ($PSBoundParameters.ContainsKey('Frameworks')) { $defaults.frameworks = @($Frameworks | Where-Object { $_ -ne 'none' }) }
    if ($Thresholds) { foreach ($k in $Thresholds.Keys) { $defaults.thresholds[[string]$k] = $Thresholds[$k] } }
    if ($PSBoundParameters.ContainsKey('BreakGlass')) { $defaults.breakGlass = @($BreakGlass) }
    if ($Audience) { $defaults.audience = $Audience }
    if ($Cadence) { $defaults.cadence = $Cadence }

    # Licenses: detected, then confirmed.
    $licenseSource = $(if ($existing -and $existing.Contains('licensesSource')) { $existing.licensesSource } else { 'manual' })
    $detected = $null
    if ($Evidence) {
        $skuFile = Join-Path $Evidence '01-subscribed-skus.json'
        if (-not (Test-Path -LiteralPath $skuFile)) { throw "No 01-subscribed-skus.json in $Evidence" }
        $detected = @(Get-PostureLicenseToken -Sku @(Get-Content -Raw -LiteralPath $skuFile | ConvertFrom-Json -AsHashtable -Depth 10))
        $licenseSource = "evidence:$skuFile"
    }
    elseif ($FromGraph) {
        $null = Assert-PostureGraphScope -AnyOfScope 'Organization.Read.All', 'Directory.Read.All'
        $detected = @(Get-PostureLicenseToken -Sku @(Invoke-PostureGraphRequest -Uri 'subscribedSkus' -ApiVersion 'v1.0'))
        $licenseSource = "graph:$((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd'))"
    }
    if ($null -ne $detected -and -not $PSBoundParameters.ContainsKey('Licenses')) { $defaults.licenses = $detected }

    $answers = $defaults
    if (-not $NonInteractive) {
        $ask = { param($q, $why, $choices, $default, [bool] $multi) Read-PostureAnswer -Question $q -Why $why -Choices $choices -Default $default -Multi:$multi }
        $answers.clientName = & $ask 'Client or tenant display name?' 'Shown on the report cover.' @() $answers.clientName $false
        $licenseWhy = if ($null -ne $detected) { "Detected from $licenseSource. Edit the list if it is wrong." } else { 'Tokens: E3, E5, BusinessPremium, P1, P2, Intune, IntuneSuite, EntraSuite, MDO1, MDO2, MDE1, MDE2, MDEBusiness, Purview, Copilot, SAM. Use -FromGraph or -Evidence to detect.' }
        $answers.licenses = @(& $ask 'Licenses present?' $licenseWhy @('E3', 'E5', 'BusinessPremium', 'P1', 'P2', 'Intune', 'IntuneSuite', 'EntraSuite', 'MDO1', 'MDO2', 'MDE1', 'MDE2', 'MDEBusiness', 'Purview', 'Copilot', 'SAM') $answers.licenses $true)
        $answers.platforms = @(& $ask 'Platforms in scope?' 'Decides which device and endpoint checks appear.' @('windows', 'macOS', 'linux', 'iOS', 'android') $answers.platforms $true)
        $answers.identityModel = & $ask 'Identity model?' 'Hybrid renders the AD domain; ADFS adds the federation checks.' @('cloud-only', 'hybrid-connect', 'hybrid-cloud-sync', 'hybrid-adfs') $answers.identityModel $false
        $answers.byod = & $ask 'BYOD stance for phones?' 'none: corporate devices only. mam: app protection without enrollment. mdm: enrolled.' @('none', 'mam', 'mdm') $answers.byod $false
        $answers.externalCollaboration = & $ask 'External collaboration stance?' 'locked: any guest is a finding. governed: guests with reviews pass. open: by policy.' @('locked', 'governed', 'open') $answers.externalCollaboration $false
        $answers.copilot = & $ask 'Copilot status?' 'Decides whether the readiness domain renders and how oversharing is scored.' @('none', 'pilot', 'deployed') $answers.copilot $false
        $answers.azure = & $ask 'Azure footprint?' 'none, platform only, or workloads. Decides whether the Azure domain renders.' @('none', 'platform', 'workloads') $answers.azure $false
        foreach ($cat in @($answers.thirdParty.Keys)) {
            $answers.thirdParty[$cat] = & $ask "Third-party $cat control? (vendor name, or none)" 'Checks it covers render as "Covered by <vendor>" instead of failing.' @() $answers.thirdParty[$cat] $false
        }
        $answers.frameworks = @(& $ask 'Regulated frameworks?' 'Adds the crosswalk appendix and severity lifts on mapped checks.' @('none', 'hipaa', 'pci', 'cmmc', 'soc2', 'iso27001', 'nist-800-171', 'cisa-scuba') $(if (@($answers.frameworks).Count -eq 0) { @('none') } else { $answers.frameworks }) $true | Where-Object { $_ -ne 'none' })
        foreach ($t in @($answers.thresholds.Keys)) {
            $v = & $ask "Threshold ${t}?" 'Product default shown; the appendix prints your override next to it.' @() $answers.thresholds[$t] $false
            $answers.thresholds[$t] = $(if ($t -eq 'namePattern') { $(if ($v) { [string]$v } else { $null }) } else { [int]$v })
        }
        $answers.breakGlass = @(& $ask 'Break-glass account UPNs?' 'Exclusion checks then know which accounts are supposed to be excluded.' @() $answers.breakGlass $true)
        $answers.audience = & $ask 'Primary audience?' 'executive: the 12-page view. technical: everything. auditor: crosswalk first.' @('executive', 'technical', 'auditor') $answers.audience $false
        $answers.cadence = & $ask 'Report cadence?' 'Sets the trend window and the "what changed" scope.' @('one-off', 'monthly', 'quarterly') $answers.cadence $false
    }

    $written = [ordered]@{ version = 1 }
    foreach ($k in $answers.Keys) { $written[$k] = $answers[$k] }
    $written.licensesSource = $licenseSource
    $written.createdUtc = $(if ($existing -and $existing.Contains('createdUtc')) { $existing.createdUtc } else { [datetime]::UtcNow.ToString('o') })
    $written.updatedUtc = [datetime]::UtcNow.ToString('o')

    if ($existing -and -not $NonInteractive -and -not $Force) {
        $ok = Read-PostureAnswer -Question "Overwrite ${Path}?" -Choices @('yes', 'no') -Default 'yes'
        if ($ok -ne 'yes') { Write-Warning 'Not written.'; if ($PassThru) { return $written }; return $null }
    }
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($PSCmdlet.ShouldProcess($full, 'Write profile.json')) {
        $dir = Split-Path $full -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        [System.IO.File]::WriteAllText($full, (ConvertTo-Json -InputObject $written -Depth 10), [System.Text.UTF8Encoding]::new($false))
    }
    if ($PassThru) { return $written }
    return $full
}
