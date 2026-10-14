# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureEndpointFact {
    <#
    .SYNOPSIS
        Fact provider for the endpoint domain (spec 4.11), policy state from Intune: security baselines, BitLocker,
        firewall, LAPS, Defender Antivirus settings, tamper protection, network protection, ASR rules and exclusions,
        SmartScreen, Office macros, Windows Hello for Business, update rings, macOS FileVault and hardening, Platform
        SSO, mobile app protection and jailbreak detection.
    .DESCRIPTION
        Reads the settings catalog rows the Intune collector flattens (09-intune-policy-settings) and matches on the
        setting definition ids, which are self-describing. The ids and choice values used here are from the settings
        catalog as documented; each is tagged (verify) in the code until a live run confirms it. Effective state from
        Defender (what devices actually do) is a later collector; the gap between the two is the finding the spec
        asks for. Thresholds read: maxAsrRulesAudit, minOfficeMacroApps, maxQualityUpdateDeadlineDays.
        Profile read: platforms, identityModel, byod.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [Parameter()] [System.Collections.IDictionary] $OrgProfile = @{},
        [Parameter()] [System.Collections.IDictionary] $Thresholds = @{}
    )

    $ErrorActionPreference = 'Stop'
    $t = @{ maxAsrRulesAudit = 0; minOfficeMacroApps = 3; maxQualityUpdateDeadlineDays = 7 }
    foreach ($k in @($Thresholds.Keys)) { $t[$k] = $Thresholds[$k] }
    $load = {
        param([string] $Name)
        $f = Join-Path $Evidence "$Name.json"
        if (-not (Test-Path -LiteralPath $f)) { return $null }
        $text = Get-Content -Raw -LiteralPath $f
        if ([string]::IsNullOrWhiteSpace($text)) { return , @() }
        $parsed = ConvertFrom-Json -InputObject $text -AsHashtable -Depth 20
        if ($null -eq $parsed) { return , @() }
        return $parsed
    }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $rows = { param($o) @($o | Where-Object { $_ }) }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    $missing = { param([string[]] $Ids, [string] $File) foreach ($id in $Ids) { $notEvaluated[$id] = "$File.json was not collected (Invoke-PostureCollection -Collector Intune; check errors.txt and the scopes)." } }

    $catalog = & $load '09-intune-config-profiles-settings-catalog'
    if ($null -eq $catalog) { return @{ available = $false; reason = 'No Intune policy evidence in the folder (Invoke-PostureCollection -Collector Intune).' } }
    $assigned = @(& $rows $catalog | Where-Object { [int]$_.Assignments -gt 0 })

    # Security baselines (EP-001): settings catalog policies with the baseline template family. (verify) display names
    $baselines = @($assigned | Where-Object { [string]$_.TemplateFamily -eq 'baseline' })
    $facts.baselineWindows = @($baselines | Where-Object { [string]$_.TemplateDisplayName -match '(?i)security baseline for windows' }).Count -gt 0
    $facts.baselineDefender = @($baselines | Where-Object { [string]$_.TemplateDisplayName -match '(?i)defender for endpoint' }).Count -gt 0
    $facts.baselineEdge = @($baselines | Where-Object { [string]$_.TemplateDisplayName -match '(?i)edge' }).Count -gt 0
    $affected.baselinesMissing = @(@(@('Windows', $facts.baselineWindows), @('Defender for Endpoint', $facts.baselineDefender), @('Edge', $facts.baselineEdge)) | Where-Object { -not $_[1] } | ForEach-Object { [ordered]@{ name = "$($_[0]) baseline"; detail = 'no assigned security baseline of this type' } })

    # Settings catalog rows: every match is "some assigned policy sets this".
    $settings = & $load '09-intune-policy-settings'
    if ($null -eq $settings) { & $missing @('EP-002', 'EP-003', 'EP-004', 'EP-005', 'EP-006', 'EP-007', 'EP-008', 'EP-009', 'EP-010', 'EP-011', 'EP-012', 'EP-013', 'EP-015', 'EP-016', 'EP-017') '09-intune-policy-settings' }
    else {
        $all = @(& $rows $settings)
        $win = @($all | Where-Object { [string]$_.Platforms -match '(?i)windows' })
        $mac = @($all | Where-Object { [string]$_.Platforms -match '(?i)macos' })
        $hasWin = { param([string] $IdPattern, [string] $ValuePattern = '.') @($win | Where-Object { [string]$_.SettingDefinitionId -match $IdPattern -and [string]$_.Value -match $ValuePattern }).Count -gt 0 }
        $hasMac = { param([string] $IdPattern, [string] $ValuePattern = '.') @($mac | Where-Object { [string]$_.SettingDefinitionId -match $IdPattern -and [string]$_.Value -match $ValuePattern }).Count -gt 0 }

        # BitLocker (EP-002). (verify) child ids: encryptionmethodwithxts_ostype _7 is XTS-AES 256; osrequireactivedirectorybackup _1 escrows to Entra
        $facts.bitlockerPolicyAssigned = @($assigned | Where-Object { [string]$_.TemplateFamily -eq 'endpointSecurityDiskEncryption' }).Count -gt 0
        $facts.bitlockerRequireEncryption = & $hasWin 'bitlocker_requiredeviceencryption$' '_1$'
        $facts.bitlockerXtsAes256Os = & $hasWin 'encryptionmethodwithxts_?ostype' '_7$'
        $facts.bitlockerSilent = & $hasWin 'bitlocker_allowwarningforotherdiskencryption$' '_0$'
        $facts.bitlockerTpmStartup = & $hasWin 'systemdrivesrequirestartupauthentication$' '_1$'
        $facts.bitlockerEscrowRequired = & $hasWin 'osrequireactivedirectorybackup' '_1$'
        $affected.bitlockerGaps = @(@(@('require device encryption', $facts.bitlockerRequireEncryption), @('XTS-AES 256 for the OS drive', $facts.bitlockerXtsAes256Os), @('silent enablement', $facts.bitlockerSilent), @('TPM startup authentication', $facts.bitlockerTpmStartup), @('recovery key escrow required before enabling', $facts.bitlockerEscrowRequired)) | Where-Object { -not $_[1] } | ForEach-Object { [ordered]@{ name = $_[0]; detail = 'not set in any assigned Windows policy' } })

        # Firewall (EP-003). (verify) vendor_msft_firewall_mdmstore_<profile>profile_enablefirewall _true
        $facts.firewallDomain = & $hasWin 'firewall_mdmstore_domainprofile_enablefirewall$' '_true$'
        $facts.firewallPrivate = & $hasWin 'firewall_mdmstore_privateprofile_enablefirewall$' '_true$'
        $facts.firewallPublic = & $hasWin 'firewall_mdmstore_publicprofile_enablefirewall$' '_true$'
        $affected.firewallProfilesOff = @(@(@('domain', $facts.firewallDomain), @('private', $facts.firewallPrivate), @('public', $facts.firewallPublic)) | Where-Object { -not $_[1] } | ForEach-Object { [ordered]@{ name = "$($_[0]) profile"; detail = 'firewall not enabled by an assigned policy' } })

        # LAPS (EP-004). (verify) backupdirectory _1 is Entra; postauthenticationactions 1, 3, 5 include a password reset
        $facts.lapsBackupToEntra = & $hasWin 'laps_policies_backupdirectory$' '_1$'
        $facts.lapsResetAfterUse = & $hasWin 'laps_policies_postauthenticationactions$' '_(1|3|5)$'

        # Defender Antivirus (EP-005), tamper protection (EP-006), network protection (EP-007). (verify) ids and values
        $facts.avRealTime = & $hasWin 'defender_allowrealtimemonitoring$' '_1$'
        $facts.avCloudProtection = & $hasWin 'defender_allowcloudprotection$' '_1$'
        $facts.avPua = & $hasWin 'defender_puaprotection$' '_1$'
        $facts.avSampleSubmission = & $hasWin 'defender_submitsamplesconsent$' '_(1|3)$'
        $facts.avScheduledScan = & $hasWin 'defender_schedulescanday$' '_([1-8])$'
        $affected.avGaps = @(@(@('real-time protection', $facts.avRealTime), @('cloud-delivered protection', $facts.avCloudProtection), @('PUA protection block', $facts.avPua), @('automatic sample submission', $facts.avSampleSubmission), @('scheduled scan day', $facts.avScheduledScan)) | Where-Object { -not $_[1] } | ForEach-Object { [ordered]@{ name = $_[0]; detail = 'not set in any assigned antivirus policy' } })
        $facts.tamperProtection = & $hasWin 'tamperprotection' '_0$'
        $facts.networkProtectionBlock = & $hasWin 'defender_enablenetworkprotection$' '_1$'

        # ASR rules (EP-008) and exclusions (EP-009). (verify) the 19 rule ids as the settings catalog names them
        $asrRules = @('blockabuseofexploitedvulnerablesigneddrivers', 'blockadobereaderfromcreatingchildprocesses', 'blockallofficeapplicationsfromcreatingchildprocesses', 'blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem', 'blockexecutablecontentfromemailclientandwebmail', 'blockexecutablefilesrunningunlesstheymeetaprevalenceagetrustedlistcriterion', 'blockexecutionofpotentiallyobfuscatedscripts', 'blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent', 'blockofficeapplicationsfromcreatingexecutablecontent', 'blockofficeapplicationsfrominjectingcodeintootherprocesses', 'blockofficecommunicationappfromcreatingchildprocesses', 'blockpersistencethroughwmieventsubscription', 'blockprocesscreationsfrompsexecandwmicommands', 'blockrebootingmachineinsafemode', 'blockuntrustedunsignedprocessesthatrunfromusb', 'blockuseofcopiedorimpersonatedsystemtools', 'blockwebshellcreationforservers', 'blockwin32apicallsfromofficemacros', 'useadvancedprotectionagainstransomware')
        $asrRows = @($win | Where-Object { [string]$_.SettingDefinitionId -match 'attacksurfacereductionrules_' })
        $state = @{}
        foreach ($r in $asrRows) {
            $name = ([string]$r.SettingDefinitionId) -replace '^.*attacksurfacereductionrules_', ''
            $val = ([string]$r.Value) -replace '^.*_', ''
            $rank = @{ block = 3; warn = 2; audit = 1; off = 0 }
            if (-not $rank.ContainsKey($val)) { continue }
            if (-not $state.ContainsKey($name) -or $rank[$val] -gt $rank[$state[$name]]) { $state[$name] = $val }
        }
        $facts.asrRulesKnown = $asrRules.Count
        $facts.asrRulesBlock = @($asrRules | Where-Object { $state.ContainsKey($_) -and $state[$_] -in @('block', 'warn') }).Count
        $facts.asrRulesAudit = @($asrRules | Where-Object { $state.ContainsKey($_) -and $state[$_] -eq 'audit' }).Count
        $facts.asrRulesOff = @($asrRules | Where-Object { $state.ContainsKey($_) -and $state[$_] -eq 'off' }).Count
        $facts.asrRulesNotConfigured = @($asrRules | Where-Object { -not $state.ContainsKey($_) }).Count
        $affected.asrRulesNotBlocking = @($asrRules | Where-Object { -not $state.ContainsKey($_) -or $state[$_] -notin @('block', 'warn') } | ForEach-Object { [ordered]@{ name = $_; detail = $(if ($state.ContainsKey($_)) { $state[$_] } else { 'not configured' }) } })
        $exclusions = @($win | Where-Object { [string]$_.SettingDefinitionId -match 'attacksurfacereductiononlyexclusions$' } | ForEach-Object { ([string]$_.Value) -split '\|' } | Where-Object { $_ })
        $facts.asrExclusions = $exclusions.Count
        $affected.asrExclusions = @($exclusions | ForEach-Object { [ordered]@{ name = $_; detail = 'ASR-only exclusion' } })

        # SmartScreen (EP-010), Office macros (EP-011). (verify) ADMX-backed macro ids contain blockmacrosfrominternet per app
        $facts.smartScreenShell = & $hasWin 'smartscreen_enablesmartscreeninshell$' '_1$'
        $facts.smartScreenNoOverride = & $hasWin 'smartscreen_preventoverrideforfilesinshell$' '_1$'
        $macroApps = @($all | Where-Object { [string]$_.SettingDefinitionId -match 'blockmacrosfrominternet' -and [string]$_.Value -match '_1$' } | ForEach-Object { $m = [regex]::Match([string]$_.SettingDefinitionId, '(?i)(word|excel|powerpoint|access|visio|project|publisher|outlook)'); if ($m.Success) { $m.Value.ToLowerInvariant() } } | Sort-Object -Unique)
        $facts.officeMacroBlockApps = @($macroApps).Count

        # Windows Hello for Business (EP-012) and cloud Kerberos trust (EP-013). (verify) passportforwork ids
        $whfb = & $load '09-intune-windows-hello'
        $tenantWide = [bool]($null -ne $whfb -and (& $v $whfb 'Present') -eq $true -and [string](& $v $whfb 'State') -eq 'enabled')
        $facts.windowsHelloEnabled = $tenantWide -or (& $hasWin 'passportforwork_.*_usepassportforwork$' '_true$')
        $facts.windowsHelloCloudTrust = & $hasWin 'usecloudtrustforonpremauth$' '_true$'

        # macOS (EP-015 FileVault, EP-016 hardening, EP-017 Platform SSO). (verify) settings catalog ids for macOS
        $facts.macFileVaultPolicy = (& $hasMac 'com\.apple\.mcx\.filevault2_enable$' '_on$') -or (& $hasMac 'filevault2_enable$' '_on$')
        $facts.macFileVaultEscrow = & $hasMac 'fderecoverykeyescrow_location'
        $facts.macGatekeeper = & $hasMac 'com\.apple\.systempolicy\.control_enableassessment$' '_true$'
        $facts.macFirewall = & $hasMac 'com\.apple\.security\.firewall_enablefirewall$' '_true$'
        $facts.macPlatformSso = @($mac | Where-Object { [string]$_.SettingDefinitionId -match 'extensiblesso.*platformsso' }).Count -gt 0
    }

    # Compliance policies: SIP on macOS (EP-016), jailbreak and root detection (EP-018)
    $comp = & $load '09-intune-compliance-policy-settings'
    if ($null -eq $comp) { & $missing @('EP-018') '09-intune-compliance-policy-settings'; if (-not $facts.Contains('macSip')) { $facts.macSip = $false } }
    else {
        $c = @(& $rows $comp)
        $facts.macSip = @($c | Where-Object { [string]$_.Type -eq 'macOSCompliancePolicy' -and [string]$_.Setting -eq 'systemIntegrityProtectionEnabled' -and $_.Value -eq $true }).Count -gt 0
        $facts.iosJailbreakBlocked = @($c | Where-Object { [string]$_.Type -eq 'iosCompliancePolicy' -and [string]$_.Setting -eq 'securityBlockJailbrokenDevices' -and $_.Value -eq $true }).Count -gt 0
        $facts.androidRootBlocked = @($c | Where-Object { [string]$_.Type -match '^android' -and [string]$_.Setting -eq 'securityBlockJailbrokenDevices' -and $_.Value -eq $true }).Count -gt 0
    }
    $platforms = @($OrgProfile['platforms'] | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $facts.mobileJailbreakBlocked = (($platforms -notcontains 'ios') -or [bool]$facts.iosJailbreakBlocked) -and (($platforms -notcontains 'android') -or [bool]$facts.androidRootBlocked)
    $affected.mobilePlatformsWithoutJailbreakDetection = @(@(@('iOS', ($platforms -contains 'ios'), [bool]$facts.iosJailbreakBlocked), @('Android', ($platforms -contains 'android'), [bool]$facts.androidRootBlocked)) | Where-Object { $_[1] -and -not $_[2] } | ForEach-Object { [ordered]@{ name = $_[0]; detail = 'no assigned compliance policy blocks jailbroken or rooted devices' } })

    # App protection (EP-018, with byod mam or mdm)
    $app = & $load '09-intune-app-protection-policies'
    if ($null -eq $app) { & $missing @('EP-018') '09-intune-app-protection-policies' }
    else {
        $a = @(& $rows $app | Where-Object { $_.IsAssigned -eq $true })
        $facts.appProtectionIos = @($a | Where-Object { [string]$_.Type -match '^ios' }).Count -gt 0
        $facts.appProtectionAndroid = @($a | Where-Object { [string]$_.Type -match '^android' }).Count -gt 0
        $facts.mobileAppProtection = (($platforms -notcontains 'ios') -or $facts.appProtectionIos) -and (($platforms -notcontains 'android') -or $facts.appProtectionAndroid)
    }

    # Update rings and feature updates (EP-014)
    $cfg = & $load '09-intune-config-profile-settings'; $feature = & $load '09-intune-feature-update-profiles'
    if ($null -eq $cfg) { & $missing @('EP-014') '09-intune-config-profile-settings' }
    else {
        $rings = @(& $rows $cfg | Where-Object { [string]$_.Type -eq 'windowsUpdateForBusinessConfiguration' })
        $facts.updateRingsAssigned = @($rings | ForEach-Object { $_.PolicyId } | Sort-Object -Unique).Count
        $deadline = @($rings | Where-Object { [string]$_.Setting -eq 'deadlineForQualityUpdatesInDays' -and $null -ne $_.Value -and [int]$_.Value -le [int]$t.maxQualityUpdateDeadlineDays })
        $facts.updateQualityDeadlineSet = $deadline.Count -gt 0
        $facts.updateFeatureDeadlineSet = @($rings | Where-Object { [string]$_.Setting -eq 'deadlineForFeatureUpdatesInDays' -and $null -ne $_.Value }).Count -gt 0
        $facts.featureUpdateProfileAssigned = [bool]($null -ne $feature -and @(& $rows $feature | Where-Object { [int]$_.Assignments -gt 0 }).Count -gt 0)
    }

    return @{ available = $true; facts = $facts; affected = $affected; notEvaluated = $notEvaluated; evidence = @('09-intune-config-profiles-settings-catalog.json', '09-intune-policy-settings.json') }
}
