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
    .PARAMETER Goal
        Security goals for the licensing advisor (licensing/goals.json ids, tab-completed), for example
        phishing-resistant-mfa, device-risk, copilot-data. The report's Licensing view says what the tenant's licences
        cover for them and the smallest addition that would. None: the advisor uses the core goals.
    .PARAMETER Path
        Where to write. Default: ./profile.json. An existing file is read first and its answers become the defaults.
    .PARAMETER Evidence
        Evidence folder from Invoke-PostureCollection. Discovery reads it for the licenses, platforms, identity model,
        BYOD stance, external collaboration, Copilot status, tenant id and display name, and the wizard then asks only
        what evidence cannot answer: third-party controls, thresholds, break-glass accounts, frameworks, audience,
        cadence. Each discovered value is printed with the file and rule it came from; a parameter still wins.
    .PARAMETER AskAll
        Ask the discovered questions too, with the discovered values as defaults.
    .PARAMETER FromGraph
        Detect licenses from the signed-in Graph session (Organization.Read.All or Directory.Read.All).
    .PARAMETER NonInteractive
        Ask nothing; write parameters over existing values over defaults.
    .PARAMETER TenantId
        The tenant this profile belongs to. Invoke-PostureCollection -ProfilePath refuses a session in any other tenant; -FromGraph records the signed-in one.
    .PARAMETER BreakGlassTestedUtc
        When the break-glass accounts were last signed in and verified (operations answer; OP-003).
    .PARAMETER MessageCenterOwner
        Who reads the Microsoft 365 Message Center and turns changes into tickets (operations answer; OP-004).
    .PARAMETER SharePointClientId
        Application (client) id of the Entra app the SharePoint and Teams collector signs in with; deploy/setup/New-PostureSharePointApp.ps1 writes it.
    .PARAMETER OutputRoot
        Where this client's run folders go (Start-PostureRun, and the exception cmdlets looking for the newest run).
        Default ~/tenantkeep/evidence. A -OutRoot given to a command wins over it.
    .PARAMETER Force
        Overwrite without asking, in interactive mode, when the file exists.
    .PARAMETER PassThru
        Return the profile object instead of the path.
    .EXAMPLE
        Connect-MgGraph -Scopes Organization.Read.All -NoWelcome
        New-PostureProfile -Path ~/tenantkeep/clients/contoso/profile.json -FromGraph

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
        [switch] $AskAll,
        [ValidateSet('E3', 'E5', 'BusinessPremium', 'P1', 'P2', 'Governance', 'EntraSuite', 'InternetAccess', 'PrivateAccess', 'WorkloadID', 'Intune', 'IntuneSuite', 'MDO1', 'MDO2', 'MDE1', 'MDE2', 'MDEBusiness', 'MDI', 'MDCA', 'IP1', 'Purview', 'EndpointDLP', 'TeamsDLP', 'AuditPremium', 'InsiderRisk', 'eDiscoveryPremium', 'CommsCompliance', 'InfoBarriers', 'Copilot', 'SAM')]
        [string[]] $Licenses,
        [ArgumentCompleter({ param($c, $p, $word) $f = @((Join-Path $PSScriptRoot '..' 'licensing' 'goals.json'), (Join-Path $PSScriptRoot '..' '..' 'licensing' 'goals.json')) | Where-Object { Test-Path $_ } | Select-Object -First 1; foreach ($g in @($(if ($f) { (Get-Content -Raw $f | ConvertFrom-Json).goals }))) { if ($g.id -like "$word*") { [System.Management.Automation.CompletionResult]::new($g.id, $g.id, 'ParameterValue', $g.name) } } })]
        [string[]] $Goal,
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
        [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $TenantId,
        [datetime] $BreakGlassTestedUtc,
        [string] $MessageCenterOwner,
        [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $SharePointClientId,
        [string] $OutputRoot,
        [switch] $Force,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $defaults = [ordered]@{
        clientName            = $null
        tenantId              = $null
        licenses              = @()
        platforms             = @('windows')
        identityModel         = 'cloud-only'
        byod                  = 'mam'
        externalCollaboration = 'governed'
        copilot               = 'none'
        azure                 = 'none'
        thirdParty            = [ordered]@{ email = 'none'; edr = 'none'; mfa = 'none'; mdm = 'none'; macMdm = 'none'; siem = 'none'; backup = 'none'; swg = 'none'; ztna = 'none'; training = 'none' }
        frameworks            = @()
        goals                 = @()
        thresholds            = [ordered]@{ maxPermanentGlobalAdmins = 2; staleDeviceDays = 90; maxExclusionGroupMembers = 25; inactiveGuestDays = 90; reportOnlyMaxDays = 90; disabledMaxDays = 90; criticalCveMaxAgeDays = 14; namePattern = $null }
        audience              = 'technical'
        cadence               = 'quarterly'
        breakGlass            = @()
        operations            = [ordered]@{ breakGlassTestedUtc = $null; messageCenterOwner = $null }
        sharePointClientId    = $null
        outputRoot            = $null
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
    if ($TenantId) { $defaults.tenantId = $TenantId }
    if ($PSBoundParameters.ContainsKey('Licenses')) { $defaults.licenses = @($Licenses) }
    if ($PSBoundParameters.ContainsKey('Platforms')) { $defaults.platforms = @($Platforms) }
    if ($IdentityModel) { $defaults.identityModel = $IdentityModel }
    if ($Byod) { $defaults.byod = $Byod }
    if ($ExternalCollaboration) { $defaults.externalCollaboration = $ExternalCollaboration }
    if ($Copilot) { $defaults.copilot = $Copilot }
    if ($Azure) { $defaults.azure = $Azure }
    if ($ThirdParty) { foreach ($k in $ThirdParty.Keys) { $defaults.thirdParty[[string]$k] = [string]$ThirdParty[$k] } }
    if ($PSBoundParameters.ContainsKey('Goal')) {
        $known = @((Get-PostureLicensingData).goals | ForEach-Object { $_.id })
        $bad = @($Goal | Where-Object { $_ -notin $known })
        if ($bad.Count) { throw "-Goal: $($bad -join ', ') is not a goal. Goals: $($known -join ', ')." }
        $defaults.goals = @($Goal)
    }
    if ($PSBoundParameters.ContainsKey('Frameworks')) { $defaults.frameworks = @($Frameworks | Where-Object { $_ -ne 'none' }) }
    if ($Thresholds) { foreach ($k in $Thresholds.Keys) { $defaults.thresholds[[string]$k] = $Thresholds[$k] } }
    if ($PSBoundParameters.ContainsKey('BreakGlass')) { $defaults.breakGlass = @($BreakGlass) }
    if ($PSBoundParameters.ContainsKey('BreakGlassTestedUtc')) { $defaults.operations.breakGlassTestedUtc = $BreakGlassTestedUtc.ToUniversalTime().ToString('o') }
    if ($PSBoundParameters.ContainsKey('MessageCenterOwner')) { $defaults.operations.messageCenterOwner = $MessageCenterOwner }
    if ($SharePointClientId) { $defaults.sharePointClientId = $SharePointClientId }
    if ($Audience) { $defaults.audience = $Audience }
    if ($Cadence) { $defaults.cadence = $Cadence }
    if ($OutputRoot) { $defaults.outputRoot = $OutputRoot }

    # Licenses: detected, then confirmed.
    $licenseSource = $(if ($existing -and $existing.Contains('licensesSource')) { $existing.licensesSource } else { 'manual' })
    $detected = $null
    $discovered = @()
    $discovery = $null
    if ($Evidence) {
        $discovery = Get-PostureProfileDiscovery -Evidence $Evidence
        $licenseSource = "evidence:$($discovery.evidence)"
        if ($discovery.facts.Contains('licenses')) { $detected = @($discovery.facts.licenses) }
        # Discovered values become the defaults unless the matching parameter was given.
        $paramFor = @{ platforms = 'Platforms'; identityModel = 'IdentityModel'; byod = 'Byod'; externalCollaboration = 'ExternalCollaboration'; copilot = 'Copilot'; tenantId = 'TenantId'; clientName = 'ClientName' }
        foreach ($k in @($discovery.facts.Keys | Where-Object { $_ -ne 'licenses' })) {
            # A discovered vendor (thirdParty.macMdm) fills one category, and only while it still says none.
            if ($k -like 'thirdParty.*') {
                $cat = $k.Substring(11)
                if ($ThirdParty -and $ThirdParty.Contains($cat)) { continue }
                if (-not $defaults.thirdParty.Contains($cat) -or [string]$defaults.thirdParty[$cat] -in '', 'none') { $defaults.thirdParty[$cat] = [string]$discovery.facts[$k]; $discovered += $k }
                continue
            }
            if ($paramFor.ContainsKey($k) -and $PSBoundParameters.ContainsKey($paramFor[$k])) { continue }
            $defaults[$k] = $discovery.facts[$k]
            $discovered += $k
        }
        if ($null -ne $detected -and -not $PSBoundParameters.ContainsKey('Licenses')) { $discovered += 'licenses' }
        Write-PostureDiscovery -Discovery $discovery -Keys $discovered
    }
    elseif ($FromGraph) {
        $null = Assert-PostureGraphScope -AnyOfScope 'Organization.Read.All', 'Directory.Read.All'
        $detected = @(Get-PostureLicenseToken -Sku @(Invoke-PostureGraphRequest -Uri 'subscribedSkus' -ApiVersion 'v1.0'))
        $licenseSource = "graph:$((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd'))"
        if (-not $TenantId) { $defaults.tenantId = [string](Get-MgContext).TenantId }
    }
    if ($null -ne $detected -and -not $PSBoundParameters.ContainsKey('Licenses')) { $defaults.licenses = $detected }

    $answers = $defaults
    if (-not $NonInteractive) {
        $ask = { param($q, $why, $choices, $default, [bool] $multi) Read-PostureAnswer -Question $q -Why $why -Choices $choices -Default $default -Multi:$multi }
        $skip = { param([string] $k) ($discovered -contains $k) -and -not $AskAll }
        if (-not (& $skip 'clientName')) { $answers.clientName = & $ask 'Client or tenant display name?' 'Shown on the report cover.' @() $answers.clientName $false }
        $licenseWhy = if ($null -ne $detected) { "Detected from $licenseSource. Edit the list if it is wrong." } else { 'Tokens: E3, E5, BusinessPremium, P1, P2, Governance, EntraSuite, Intune, IntuneSuite, MDO1, MDO2, MDE1, MDE2, MDEBusiness, MDI, MDCA, Purview, Copilot, SAM and the Purview add-ons (licensing/features.json lists them all). Use -FromGraph or -Evidence to detect.' }
        if (-not (& $skip 'licenses')) { $answers.licenses = @(& $ask 'Licenses present?' $licenseWhy @('E3', 'E5', 'BusinessPremium', 'P1', 'P2', 'Governance', 'EntraSuite', 'InternetAccess', 'PrivateAccess', 'WorkloadID', 'Intune', 'IntuneSuite', 'MDO1', 'MDO2', 'MDE1', 'MDE2', 'MDEBusiness', 'MDI', 'MDCA', 'IP1', 'Purview', 'EndpointDLP', 'TeamsDLP', 'AuditPremium', 'InsiderRisk', 'eDiscoveryPremium', 'CommsCompliance', 'InfoBarriers', 'Copilot', 'SAM') $answers.licenses $true) }
        if (-not (& $skip 'platforms')) { $answers.platforms = @(& $ask 'Platforms in scope?' 'Decides which device and endpoint checks appear.' @('windows', 'macOS', 'linux', 'iOS', 'android') $answers.platforms $true) }
        if (-not (& $skip 'identityModel')) { $answers.identityModel = & $ask 'Identity model?' 'Hybrid renders the AD domain; ADFS adds the federation checks.' @('cloud-only', 'hybrid-connect', 'hybrid-cloud-sync', 'hybrid-adfs') $answers.identityModel $false }
        if (-not (& $skip 'byod')) { $answers.byod = & $ask 'BYOD stance for phones?' 'none: corporate devices only. mam: app protection without enrollment. mdm: enrolled.' @('none', 'mam', 'mdm') $answers.byod $false }
        if (-not (& $skip 'externalCollaboration')) { $answers.externalCollaboration = & $ask 'External collaboration stance?' 'locked: any guest is a finding. governed: guests with reviews pass. open: by policy.' @('locked', 'governed', 'open') $answers.externalCollaboration $false }
        if (-not (& $skip 'copilot')) { $answers.copilot = & $ask 'Copilot status?' 'Decides whether the readiness domain renders and how oversharing is scored.' @('none', 'pilot', 'deployed') $answers.copilot $false }
        $answers.azure = & $ask 'Azure footprint?' 'none, platform only, or workloads. Decides whether the Azure domain renders.' @('none', 'platform', 'workloads') $answers.azure $false
        $vendorLabel = @{
            email = 'email security in front of Microsoft 365 (Proofpoint, Mimecast)'; edr = 'endpoint detection and response (CrowdStrike, SentinelOne)'
            mfa = 'MFA other than Microsoft (Duo, Okta)'; mdm = 'device management for every platform (Workspace ONE)'; macMdm = 'device management for Macs only (Jamf, Kandji, Mosyle)'
            siem = 'SIEM (Splunk, Sentinel in another tenant)'; backup = 'Microsoft 365 backup (Veeam, AvePoint)'; swg = 'secure web gateway (Zscaler, Netskope)'; ztna = 'private access or VPN replacement (Zscaler, Cloudflare)'
            training = 'phishing awareness training and simulation (KnowBe4, Proofpoint Security Awareness)'
        }
        foreach ($cat in @($answers.thirdParty.Keys)) {
            $label = $(if ($vendorLabel.ContainsKey($cat)) { $vendorLabel[$cat] } else { "$cat control" })
            $answers.thirdParty[$cat] = & $ask "Third-party $($label)? (vendor name, or none)" 'Checks it covers render as "Covered by <vendor>" instead of failing.' @() $answers.thirdParty[$cat] $false
        }
        $goalIds = @((Get-PostureLicensingData).goals | ForEach-Object { $_.id })
        $answers.goals = @(& $ask 'Security goals for the licensing advisor?' 'The report says what your licences cover for these and the smallest addition that would. Blank uses the core goals.' $goalIds $answers.goals $true | Where-Object { $_ })
        $answers.frameworks = @(& $ask 'Regulated frameworks?' 'Adds the crosswalk appendix and severity lifts on mapped checks.' @('none', 'hipaa', 'pci', 'cmmc', 'soc2', 'iso27001', 'nist-800-171', 'cisa-scuba') $(if (@($answers.frameworks).Count -eq 0) { @('none') } else { $answers.frameworks }) $true | Where-Object { $_ -ne 'none' })
        foreach ($t in @($answers.thresholds.Keys)) {
            $v = & $ask "Threshold ${t}?" 'Product default shown; the appendix prints your override next to it.' @() $answers.thresholds[$t] $false
            $answers.thresholds[$t] = $(if ($t -eq 'namePattern') { $(if ($v) { [string]$v } else { $null }) } else { [int]$v })
        }
        $answers.breakGlass = @(& $ask 'Break-glass account UPNs?' 'Exclusion checks then know which accounts are supposed to be excluded.' @() $answers.breakGlass $true)
        $testedAnswer = & $ask 'When were the break-glass accounts last tested (date, or blank)?' 'Sign in with each, confirm the exclusions and the alert; OP-003 wants it within six months.' @() $answers.operations.breakGlassTestedUtc $false
        $parsed = [datetime]::MinValue
        $answers.operations.breakGlassTestedUtc = $(if ($testedAnswer -and [datetime]::TryParse([string]$testedAnswer, [ref]$parsed)) { $parsed.ToUniversalTime().ToString('o') } else { if ($testedAnswer) { Write-Warning "Not a date: $testedAnswer; left blank." }; $null })
        $answers.operations.messageCenterOwner = & $ask 'Message Center triage owner (person or team, or blank)?' 'OP-004: who turns Microsoft 365 changes and retirements into tickets.' @() $answers.operations.messageCenterOwner $false
        $answers.audience = & $ask 'Primary audience?' 'executive: the 12-page view. technical: everything. auditor: crosswalk first.' @('executive', 'technical', 'auditor') $answers.audience $false
        $answers.cadence = & $ask 'Report cadence?' 'Sets the trend window and the "what changed" scope.' @('one-off', 'monthly', 'quarterly') $answers.cadence $false
        $root = & $ask 'Where should the run folders go?' 'Each run makes a dated folder here with the evidence and report.html. Blank keeps the current place.' @() $(if ($answers.outputRoot) { $answers.outputRoot } else { Join-Path '~' 'tenantkeep' 'evidence' }) $false
        $answers.outputRoot = $(if ($root -and $root -ne (Join-Path '~' 'tenantkeep' 'evidence')) { [string]$root } else { $null })
    }

    $written = [ordered]@{ version = 1 }
    foreach ($k in $answers.Keys) { $written[$k] = $answers[$k] }
    $written.licensesSource = $licenseSource
    if ($discovery) { $written.discovery = [ordered]@{ evidence = $discovery.evidence; timestampUtc = [datetime]::UtcNow.ToString('o'); keys = @($discovered | Sort-Object); sources = $discovery.sources } }
    $written.createdUtc = $(if ($existing -and $existing.Contains('createdUtc')) { $existing.createdUtc } else { [datetime]::UtcNow.ToString('o') })
    $written.updatedUtc = [datetime]::UtcNow.ToString('o')
    # Keys this cmdlet does not own (attestations from Set-PostureAttestation, anything added by hand) survive a rewrite.
    if ($existing) { foreach ($k in @($existing.Keys)) { if (-not $written.Contains($k)) { $written[$k] = $existing[$k] } } }

    if ($existing -and -not $NonInteractive -and -not $Force) {
        $ok = Read-PostureAnswer -Question "Overwrite ${Path}?" -Choices @('yes', 'no') -Default 'yes'
        if ($ok -ne 'yes') { Write-Warning 'Not written.'; if ($PassThru) { return $written }; return $null }
    }
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)   # expands ~ too
    if ($PSCmdlet.ShouldProcess($full, 'Write profile.json')) {
        $dir = Split-Path $full -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        # Through a temporary file: a run stopped mid-write must not leave half a profile for the next run to trip over.
        Save-PostureJsonFile -Path $full -InputObject $written -Confirm:$false
    }
    if ($PassThru) { return $written }
    return $full
}
